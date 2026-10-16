//! gRPC status codes and error types.
//!
//! Implements the gRPC status codes as defined in the gRPC specification.

use crate::bytes::Bytes;
use std::fmt;

/// gRPC status codes.
///
/// These codes follow the gRPC specification and map to HTTP/2 status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(i32)]
pub enum Code {
    /// Not an error; returned on success.
    Ok = 0,
    /// The operation was cancelled, typically by the caller.
    Cancelled = 1,
    /// Unknown error.
    #[default]
    Unknown = 2,
    /// The client specified an invalid argument.
    InvalidArgument = 3,
    /// The deadline expired before the operation could complete.
    DeadlineExceeded = 4,
    /// Some requested entity was not found.
    NotFound = 5,
    /// The entity that a client attempted to create already exists.
    AlreadyExists = 6,
    /// The caller does not have permission to execute the operation.
    PermissionDenied = 7,
    /// Some resource has been exhausted.
    ResourceExhausted = 8,
    /// The operation was rejected because the system is not in a state required for the operation's execution.
    FailedPrecondition = 9,
    /// The operation was aborted.
    Aborted = 10,
    /// The operation was attempted past the valid range.
    OutOfRange = 11,
    /// The operation is not implemented or not supported.
    Unimplemented = 12,
    /// Internal error.
    Internal = 13,
    /// The service is currently unavailable.
    Unavailable = 14,
    /// Unrecoverable data loss or corruption.
    DataLoss = 15,
    /// The request does not have valid authentication credentials.
    Unauthenticated = 16,
}

impl Code {
    /// Convert from an i32 value.
    #[must_use]
    pub fn from_i32(value: i32) -> Self {
        match value {
            0 => Self::Ok,
            1 => Self::Cancelled,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            // 2 is Unknown per gRPC spec; unmapped codes also return Unknown
            _ => Self::Unknown,
        }
    }

    /// Convert to i32 value.
    #[must_use]
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    /// Returns the canonical name for this code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// gRPC status with code, message, and optional details.
#[derive(Debug, Clone)]
pub struct Status {
    /// The status code.
    code: Code,
    /// A human-readable description of the error.
    message: String,
    /// Optional binary details for rich error models.
    details: Option<Bytes>,
}

/// Maximum length of a Status message in bytes (br-asupersync-uk2vsg).
///
/// Defense-in-depth cap to bound an attacker-influenced or operator-set
/// status message that would otherwise be propagated wholesale through
/// the gRPC trailer block (`grpc-message` is percent-encoded and capped
/// at the wire layer, but a `Status` object can be round-tripped through
/// in-process serializers — `Display`, JSON, observability — that have
/// no inherent cap). 8 KiB matches the typical HTTP/2 max header value
/// limits in the same codebase.
pub const MAX_STATUS_MESSAGE_LEN: usize = 8 * 1024;

/// Maximum length of Status details in bytes (br-asupersync-uk2vsg).
///
/// The gRPC spec recommends details be kept small; in practice google.rpc
/// Status details are protobuf and rarely exceed a few KiB. 64 KiB caps
/// pathological inputs without breaking realistic rich-error-model
/// payloads (rich-error UnaryAck, RetryInfo, BadRequest are <1 KiB; the
/// largest reasonable case — DebugInfo with a stack trace — fits easily
/// in 64 KiB).
pub const MAX_STATUS_DETAILS_LEN: usize = 64 * 1024;

/// Truncate a status message string to [`MAX_STATUS_MESSAGE_LEN`] bytes
/// at a UTF-8 boundary.
///
/// br-asupersync-uk2vsg: never panic on truncation — find the last char
/// boundary <= the cap and slice there. If the input is already short,
/// return the original String unchanged (no allocation).
fn cap_status_message(message: String) -> String {
    if message.len() <= MAX_STATUS_MESSAGE_LEN {
        return message;
    }
    let mut end = MAX_STATUS_MESSAGE_LEN;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_string()
}

/// Truncate status details `Bytes` to [`MAX_STATUS_DETAILS_LEN`].
fn cap_status_details(details: Bytes) -> Bytes {
    if details.len() <= MAX_STATUS_DETAILS_LEN {
        return details;
    }
    details.slice(..MAX_STATUS_DETAILS_LEN)
}

macro_rules! status_constructors {
    ($(
        $(#[$meta:meta])*
        $name:ident => $code:ident;
    )*) => {
        $(
            $(#[$meta])*
            #[must_use]
            pub fn $name(message: impl Into<String>) -> Self {
                Self::new(Code::$code, message)
            }
        )*
    };
}

impl Status {
    /// Create a new status with the given code and message.
    ///
    /// br-asupersync-uk2vsg: messages exceeding [`MAX_STATUS_MESSAGE_LEN`]
    /// are truncated at a UTF-8 boundary; this caps unbounded strings
    /// from leaking into wire frames or in-process serializers.
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: cap_status_message(message.into()),
            details: None,
        }
    }

    /// Create a status with details.
    ///
    /// br-asupersync-uk2vsg: messages exceeding [`MAX_STATUS_MESSAGE_LEN`]
    /// and details exceeding [`MAX_STATUS_DETAILS_LEN`] are truncated.
    #[must_use]
    pub fn with_details(code: Code, message: impl Into<String>, details: Bytes) -> Self {
        Self {
            code,
            message: cap_status_message(message.into()),
            details: Some(cap_status_details(details)),
        }
    }

    /// Create an OK status.
    #[must_use]
    pub fn ok() -> Self {
        Self::new(Code::Ok, "")
    }

    status_constructors! {
        /// Create a cancelled status.
        cancelled => Cancelled;
        /// Create an unknown error status.
        unknown => Unknown;
        /// Create an invalid argument status.
        invalid_argument => InvalidArgument;
        /// Create a deadline exceeded status.
        deadline_exceeded => DeadlineExceeded;
        /// Create a not found status.
        not_found => NotFound;
        /// Create an already exists status.
        already_exists => AlreadyExists;
        /// Create a permission denied status.
        permission_denied => PermissionDenied;
        /// Create a resource exhausted status.
        resource_exhausted => ResourceExhausted;
        /// Create a failed precondition status.
        failed_precondition => FailedPrecondition;
        /// Create an aborted status.
        aborted => Aborted;
        /// Create an out of range status.
        out_of_range => OutOfRange;
        /// Create an unimplemented status.
        unimplemented => Unimplemented;
        /// Create an internal error status.
        internal => Internal;
        /// Create an unavailable status.
        unavailable => Unavailable;
        /// Create a data loss status.
        data_loss => DataLoss;
        /// Create an unauthenticated status.
        unauthenticated => Unauthenticated;
    }

    /// Get the status code.
    #[must_use]
    pub fn code(&self) -> Code {
        self.code
    }

    /// Get the status message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the status details.
    #[must_use]
    pub fn details(&self) -> Option<&Bytes> {
        self.details.as_ref()
    }

    /// Returns true if this is an OK status.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.code == Code::Ok
    }

    /// Map an HTTP/2 `RST_STREAM` error code to a gRPC `Status` per the
    /// gRPC-over-HTTP/2 protocol specification.
    ///
    /// br-asupersync-q01vh5: the canonical 14-row mapping comes from
    /// <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>
    /// ("Responses (HTTP/2) ... RST_STREAM"). Pre-fix the only mapping in
    /// the codebase was the test helper `grpc_go_rst_stream_status` in
    /// `src/grpc/streaming.rs`, which omitted the spec-mandated
    /// `ENHANCE_YOUR_CALM → RESOURCE_EXHAUSTED` and
    /// `INADEQUATE_SECURITY → PERMISSION_DENIED` mappings.
    #[must_use]
    pub fn from_h2_rst_stream_code(code: crate::http::h2::error::ErrorCode) -> Self {
        use crate::http::h2::error::ErrorCode;
        let grpc_code = match code {
            ErrorCode::Cancel => Code::Cancelled,
            ErrorCode::RefusedStream => Code::Unavailable,
            ErrorCode::EnhanceYourCalm => Code::ResourceExhausted,
            ErrorCode::InadequateSecurity => Code::PermissionDenied,
            // Per gRPC spec, all other RST_STREAM codes map to INTERNAL.
            // STREAM_CLOSED has "no mapping" in the spec because the stream
            // is already gone, but if it surfaces to a caller we must still
            // produce a Status — INTERNAL is the safest non-retryable
            // signal that something framing-level went wrong.
            ErrorCode::NoError
            | ErrorCode::ProtocolError
            | ErrorCode::InternalError
            | ErrorCode::FlowControlError
            | ErrorCode::SettingsTimeout
            | ErrorCode::StreamClosed
            | ErrorCode::FrameSizeError
            | ErrorCode::CompressionError
            | ErrorCode::ConnectError
            | ErrorCode::Http11Required => Code::Internal,
        };
        Self::new(grpc_code, format!("Received RST_STREAM with code {code}"))
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gRPC status {}: {}", self.code, self.message)
    }
}

impl std::error::Error for Status {}

impl From<std::io::Error> for Status {
    fn from(err: std::io::Error) -> Self {
        Self::internal(err.to_string())
    }
}

/// Typed kind for transport-layer errors (br-asupersync-9gg21l).
///
/// Replaces the earlier substring-based classification that scanned
/// free-form error text for "timeout"/"timed out"/"deadline exceeded"/
/// "http 504" and routed to DeadlineExceeded vs Unavailable based on
/// what the OS errno or upstream proxy happened to spell. Peer-controlled
/// or os-controlled error strings could misclassify the status code,
/// changing client retry semantics (DeadlineExceeded is terminal,
/// Unavailable is retryable).
///
/// Callers at the codec/transport boundary classify the error explicitly
/// via [`GrpcError::transport_kind`]; the bare [`GrpcError::transport`]
/// constructor defaults to [`TransportErrorKind::Other`] which maps to
/// `Unavailable` (safe retryable default).
// br-asupersync-co6rye: #[non_exhaustive] so future taxonomy growth
// (e.g. TlsHandshakeFailed, LocalConfigError) is non-breaking for
// downstream callers that match on this enum.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransportErrorKind {
    /// Operation timed out (deadline elapsed). Maps to DeadlineExceeded.
    Timeout,
    /// Could not establish a connection (DNS failure, connect refused,
    /// loopback policy violation, etc.). Maps to Unavailable.
    ConnectFailed,
    /// Connection was reset or closed by the peer mid-flight.
    /// Maps to Unavailable.
    ResetByPeer,
    /// Wire-protocol violation (malformed frame, invalid HTTP/2 framing,
    /// schema mismatch). Maps to Internal — gRPC clients should not retry.
    ProtocolViolation,
    /// Unclassified transport error. Maps to Unavailable (safe default;
    /// retryable, matches the historical behavior for non-timeout errors).
    Other,
}

impl TransportErrorKind {
    /// Classify an [`std::io::ErrorKind`] into the gRPC transport taxonomy.
    ///
    /// Callers that need to preserve context around an `io::Error` should use
    /// this helper plus [`GrpcError::transport_kind`] rather than stringifying
    /// the error through [`GrpcError::transport`], which intentionally defaults
    /// to [`Self::Other`].
    #[must_use]
    pub fn from_io_error_kind(kind: std::io::ErrorKind) -> Self {
        use std::io::ErrorKind as Ek;
        match kind {
            Ek::TimedOut => Self::Timeout,
            Ek::ConnectionRefused
            | Ek::NotFound
            | Ek::AddrNotAvailable
            | Ek::NetworkDown
            | Ek::NetworkUnreachable
            | Ek::HostUnreachable => Self::ConnectFailed,
            // AddrInUse is a local bind/config failure, not peer reachability.
            Ek::AddrInUse => Self::ProtocolViolation,
            Ek::ConnectionReset
            | Ek::ConnectionAborted
            | Ek::BrokenPipe
            | Ek::NotConnected
            | Ek::UnexpectedEof => Self::ResetByPeer,
            Ek::InvalidData => Self::ProtocolViolation,
            _ => Self::Other,
        }
    }
}

impl From<std::io::ErrorKind> for TransportErrorKind {
    fn from(kind: std::io::ErrorKind) -> Self {
        Self::from_io_error_kind(kind)
    }
}

/// gRPC error type.
#[derive(Debug)]
pub enum GrpcError {
    /// A gRPC status error.
    Status(Status),
    /// Transport error with a typed kind that drives the Status mapping
    /// (br-asupersync-9gg21l). Previously `Transport(String)` with
    /// substring-driven classification.
    Transport(TransportErrorKind, String),
    /// Protocol error.
    Protocol(String),
    /// Message too large.
    MessageTooLarge,
    /// Invalid message.
    InvalidMessage(String),
    /// Compression error.
    Compression(String),
}

impl GrpcError {
    /// Create an unclassified transport error.
    ///
    /// Defaults to [`TransportErrorKind::Other`] which maps to
    /// `Unavailable` (retryable). For a typed classification (timeout,
    /// connect-failed, etc.), use [`Self::transport_kind`].
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(TransportErrorKind::Other, message.into())
    }

    /// Create a typed transport error (br-asupersync-9gg21l).
    ///
    /// Callers at the codec/transport boundary should use this to drive
    /// Status-code classification by the actual error type rather than by
    /// substring search of free-form text.
    #[must_use]
    pub fn transport_kind(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        Self::Transport(kind, message.into())
    }

    /// Create a protocol error.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::Protocol(message.into())
    }

    /// Create an invalid message error.
    #[must_use]
    pub fn invalid_message(message: impl Into<String>) -> Self {
        Self::InvalidMessage(message.into())
    }

    /// Create a compression error.
    #[must_use]
    pub fn compression(message: impl Into<String>) -> Self {
        Self::Compression(message.into())
    }

    /// Convert to a Status.
    #[must_use]
    pub fn into_status(self) -> Status {
        match self {
            Self::Status(s) => s,
            // br-asupersync-9gg21l: drive Status code from the typed
            // TransportErrorKind, not from a substring-search of msg.
            Self::Transport(kind, msg) => match kind {
                TransportErrorKind::Timeout => Status::deadline_exceeded(msg),
                TransportErrorKind::ProtocolViolation => Status::internal(msg),
                TransportErrorKind::ConnectFailed
                | TransportErrorKind::ResetByPeer
                | TransportErrorKind::Other => Status::unavailable(msg),
            },
            Self::Protocol(msg) => Status::internal(format!("protocol error: {msg}")),
            Self::MessageTooLarge => Status::resource_exhausted("message too large"),
            Self::InvalidMessage(msg) => Status::invalid_argument(msg),
            Self::Compression(msg) => Status::internal(format!("compression error: {msg}")),
        }
    }
}

impl fmt::Display for GrpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Status(s) => write!(f, "{s}"),
            Self::Transport(_kind, msg) => write!(f, "transport error: {msg}"),
            Self::Protocol(msg) => write!(f, "protocol error: {msg}"),
            Self::MessageTooLarge => write!(f, "message too large"),
            Self::InvalidMessage(msg) => write!(f, "invalid message: {msg}"),
            Self::Compression(msg) => write!(f, "compression error: {msg}"),
        }
    }
}

impl std::error::Error for GrpcError {}

impl From<Status> for GrpcError {
    fn from(status: Status) -> Self {
        Self::Status(status)
    }
}

impl From<std::io::Error> for GrpcError {
    fn from(err: std::io::Error) -> Self {
        let kind = TransportErrorKind::from_io_error_kind(err.kind());
        Self::Transport(kind, err.to_string())
    }
}

/// Percent-encode a `grpc-message` value for the HTTP/2 trailer wire format.
///
/// The gRPC wire grammar permits visible ASCII other than `%`; every other
/// UTF-8 byte is emitted as an uppercase percent escape. Internal spaces stay
/// literal, while leading and trailing spaces are escaped so intermediaries
/// cannot trim message content.
pub(crate) fn percent_encode_grpc_message(message: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let bytes = message.as_bytes();
    let mut encoded = String::with_capacity(bytes.len());

    for (index, &byte) in bytes.iter().enumerate() {
        let internal_space = byte == b' ' && index > 0 && index + 1 < bytes.len();
        let may_remain_literal = internal_space || matches!(byte, 0x21..=0x24 | 0x26..=0x7E);
        if may_remain_literal {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0F)]));
        }
    }

    encoded
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode one percent-encoded `grpc-message` trailer value.
pub(crate) fn percent_decode_grpc_message(value: &str) -> Result<String, GrpcError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let (Some(&high), Some(&low)) = (bytes.get(index + 1), bytes.get(index + 2)) else {
                return Err(GrpcError::protocol(
                    "incomplete percent escape in grpc-message trailer value",
                ));
            };
            let Some(high) = decode_hex_nibble(high) else {
                return Err(GrpcError::protocol(
                    "invalid percent escape in grpc-message trailer value",
                ));
            };
            let Some(low) = decode_hex_nibble(low) else {
                return Err(GrpcError::protocol(
                    "invalid percent escape in grpc-message trailer value",
                ));
            };
            decoded.push((high << 4) | low);
            index += 3;
            continue;
        }

        if matches!(byte, 0x20..=0x24 | 0x26..=0x7E) {
            decoded.push(byte);
            index += 1;
            continue;
        }

        return Err(GrpcError::protocol(format!(
            "invalid non-printable grpc-message in trailer block (length {})",
            value.len()
        )));
    }

    String::from_utf8(decoded)
        .map_err(|_| GrpcError::protocol("grpc-message percent escapes decode to invalid UTF-8"))
}

#[cfg(test)]
#[path = "status_inline_tests.rs"]
mod tests;
