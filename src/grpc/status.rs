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

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::web::response::StatusCode as HttpStatusCode;
    use base64::Engine as _;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_code_from_i32() {
        init_test("test_code_from_i32");
        crate::assert_with_log!(
            Code::from_i32(0) == Code::Ok,
            "0",
            Code::Ok,
            Code::from_i32(0)
        );
        crate::assert_with_log!(
            Code::from_i32(1) == Code::Cancelled,
            "1",
            Code::Cancelled,
            Code::from_i32(1)
        );
        crate::assert_with_log!(
            Code::from_i32(16) == Code::Unauthenticated,
            "16",
            Code::Unauthenticated,
            Code::from_i32(16)
        );
        crate::assert_with_log!(
            Code::from_i32(99) == Code::Unknown,
            "99",
            Code::Unknown,
            Code::from_i32(99)
        );
        crate::test_complete!("test_code_from_i32");
    }

    #[test]
    fn test_code_as_str() {
        init_test("test_code_as_str");
        let ok = Code::Ok.as_str();
        crate::assert_with_log!(ok == "OK", "OK", "OK", ok);
        let invalid = Code::InvalidArgument.as_str();
        crate::assert_with_log!(
            invalid == "INVALID_ARGUMENT",
            "INVALID_ARGUMENT",
            "INVALID_ARGUMENT",
            invalid
        );
        crate::test_complete!("test_code_as_str");
    }

    #[test]
    fn test_status_creation() {
        init_test("test_status_creation");
        let status = Status::new(Code::NotFound, "resource not found");
        let code = status.code();
        crate::assert_with_log!(code == Code::NotFound, "code", Code::NotFound, code);
        let message = status.message();
        crate::assert_with_log!(
            message == "resource not found",
            "message",
            "resource not found",
            message
        );
        let details = status.details();
        crate::assert_with_log!(details.is_none(), "details none", true, details.is_none());
        crate::test_complete!("test_status_creation");
    }

    #[test]
    fn test_status_ok() {
        init_test("test_status_ok");
        let status = Status::ok();
        let ok = status.is_ok();
        crate::assert_with_log!(ok, "is ok", true, ok);
        let code = status.code();
        crate::assert_with_log!(code == Code::Ok, "code", Code::Ok, code);
        crate::test_complete!("test_status_ok");
    }

    #[test]
    fn test_status_with_details() {
        init_test("test_status_with_details");
        let details = Bytes::from_static(b"detailed error info");
        let status = Status::with_details(Code::Internal, "error", details.clone());
        let got = status.details();
        crate::assert_with_log!(got == Some(&details), "details", Some(&details), got);
        crate::test_complete!("test_status_with_details");
    }

    /// br-asupersync-uk2vsg: Status::new and ::with_details cap the
    /// message at MAX_STATUS_MESSAGE_LEN and details at
    /// MAX_STATUS_DETAILS_LEN respectively. Truncation must not panic
    /// even on multi-byte UTF-8 input crossing the cap.
    #[test]
    fn uk2vsg_status_message_cap_truncates_long_input() {
        // Construct a message longer than the cap; verify truncation.
        let oversize = "a".repeat(MAX_STATUS_MESSAGE_LEN + 100);
        let status = Status::new(Code::Internal, oversize);
        assert_eq!(
            status.message().len(),
            MAX_STATUS_MESSAGE_LEN,
            "message should be truncated at the byte cap"
        );
    }

    #[test]
    fn uk2vsg_status_message_cap_preserves_short_input() {
        let normal = "ordinary error";
        let status = Status::new(Code::InvalidArgument, normal);
        assert_eq!(status.message(), normal);
    }

    #[test]
    fn uk2vsg_status_message_cap_preserves_utf8_boundary() {
        // Build a message that lands the cap mid-multibyte. Use a 4-byte
        // emoji (U+1F525 = "🔥" = 4 UTF-8 bytes) so we can land on every
        // boundary mod 4. We place fillers + emoji such that the natural
        // truncation point is mid-codepoint.
        let prefix_len = MAX_STATUS_MESSAGE_LEN - 2;
        let mut s = String::with_capacity(MAX_STATUS_MESSAGE_LEN + 10);
        s.push_str(&"a".repeat(prefix_len));
        s.push('🔥'); // 4 bytes, occupies positions [prefix_len .. prefix_len+4)
        s.push('🔥');
        let status = Status::new(Code::Internal, s);
        // Message must be valid UTF-8 (no panic on truncation) and must
        // be <= cap.
        let msg = status.message();
        assert!(msg.len() <= MAX_STATUS_MESSAGE_LEN);
        // Verify it round-trips through &str (would have panicked if we
        // sliced through a codepoint).
        assert_eq!(msg, status.message());
    }

    #[test]
    fn uk2vsg_status_details_cap_truncates_long_input() {
        let oversize = vec![0u8; MAX_STATUS_DETAILS_LEN + 1024];
        let status = Status::with_details(Code::Internal, "err", Bytes::from(oversize));
        assert_eq!(
            status.details().expect("details set").len(),
            MAX_STATUS_DETAILS_LEN,
            "details should be truncated at the byte cap"
        );
    }

    #[test]
    fn uk2vsg_status_details_cap_preserves_short_input() {
        let payload = b"small payload";
        let status = Status::with_details(Code::Internal, "err", Bytes::from_static(payload));
        assert_eq!(status.details().expect("details set").as_ref(), payload);
    }

    /// br-asupersync-9gg21l: Status mapping is now driven by the typed
    /// TransportErrorKind, not by substring search of free-form msg text.
    #[test]
    fn gg21l_typed_transport_kind_drives_status_code() {
        // Each kind round-trips to its expected Status code.
        let table = [
            (TransportErrorKind::Timeout, Code::DeadlineExceeded),
            (TransportErrorKind::ConnectFailed, Code::Unavailable),
            (TransportErrorKind::ResetByPeer, Code::Unavailable),
            (TransportErrorKind::ProtocolViolation, Code::Internal),
            (TransportErrorKind::Other, Code::Unavailable),
        ];
        for (kind, expected) in table {
            let s = GrpcError::transport_kind(kind, "msg with substring 'timeout'").into_status();
            assert_eq!(
                s.code(),
                expected,
                "kind {kind:?} must map to {expected:?}, got {:?}",
                s.code()
            );
        }
    }

    /// br-asupersync-9gg21l: bare GrpcError::transport(msg) defaults to
    /// Other → Unavailable, regardless of message text. The previous
    /// substring-classifier (timeout/timed out/deadline exceeded/http 504)
    /// is removed.
    #[test]
    fn gg21l_bare_transport_no_substring_classification() {
        for msg in [
            "request timeout",
            "deadline exceeded by 100ms",
            "http 504 gateway timeout",
            "operation timed out",
        ] {
            let s = GrpcError::transport(msg).into_status();
            assert_eq!(
                s.code(),
                Code::Unavailable,
                "bare transport must NOT classify by substring; \
                 expected Unavailable for {msg:?}, got {:?}",
                s.code()
            );
        }
    }

    /// br-asupersync-9gg21l: io::Error → GrpcError::Transport mapping
    /// preserves the relevant ErrorKind classification.
    #[test]
    fn gg21l_io_error_kind_maps_to_typed_transport_kind() {
        use std::io::ErrorKind as Ek;
        let mappings: &[(Ek, TransportErrorKind)] = &[
            (Ek::TimedOut, TransportErrorKind::Timeout),
            (Ek::ConnectionRefused, TransportErrorKind::ConnectFailed),
            (Ek::AddrNotAvailable, TransportErrorKind::ConnectFailed),
            (Ek::NetworkDown, TransportErrorKind::ConnectFailed),
            (Ek::NetworkUnreachable, TransportErrorKind::ConnectFailed),
            (Ek::HostUnreachable, TransportErrorKind::ConnectFailed),
            (Ek::ConnectionReset, TransportErrorKind::ResetByPeer),
            (Ek::ConnectionAborted, TransportErrorKind::ResetByPeer),
            (Ek::BrokenPipe, TransportErrorKind::ResetByPeer),
            (Ek::NotConnected, TransportErrorKind::ResetByPeer),
            (Ek::UnexpectedEof, TransportErrorKind::ResetByPeer),
            (Ek::InvalidData, TransportErrorKind::ProtocolViolation),
            // br-asupersync-co6rye: AddrInUse is a local bind failure
            // (not a peer problem), so it maps to ProtocolViolation
            // (→ Status::internal, non-retryable) NOT ConnectFailed.
            (Ek::AddrInUse, TransportErrorKind::ProtocolViolation),
            (Ek::Other, TransportErrorKind::Other),
        ];
        for (io_kind, expected) in mappings {
            let io_err = std::io::Error::new(*io_kind, "test");
            let grpc: GrpcError = io_err.into();
            let actual = match grpc {
                GrpcError::Transport(actual, _) => actual,
                other => {
                    crate::assert_with_log!(
                        false,
                        "io::Error converts to transport variant",
                        "Transport",
                        format!("{other:?}")
                    );
                    TransportErrorKind::Other
                }
            };
            assert_eq!(
                actual, *expected,
                "io::ErrorKind::{io_kind:?} must map to TransportErrorKind::{expected:?}, got {actual:?}"
            );
        }
    }

    #[test]
    fn io_error_kind_helper_matches_grpc_error_conversion() {
        use std::io::ErrorKind as Ek;
        for kind in [
            Ek::TimedOut,
            Ek::ConnectionRefused,
            Ek::AddrNotAvailable,
            Ek::NetworkDown,
            Ek::NetworkUnreachable,
            Ek::HostUnreachable,
            Ek::AddrInUse,
            Ek::ConnectionReset,
            Ek::ConnectionAborted,
            Ek::BrokenPipe,
            Ek::NotConnected,
            Ek::UnexpectedEof,
            Ek::InvalidData,
            Ek::Other,
        ] {
            let expected = TransportErrorKind::from_io_error_kind(kind);
            let grpc: GrpcError = std::io::Error::new(kind, "io failure").into();
            let actual = match grpc {
                GrpcError::Transport(actual, _) => actual,
                other => {
                    crate::assert_with_log!(
                        false,
                        "io::Error converts to transport variant",
                        "Transport",
                        format!("{other:?}")
                    );
                    TransportErrorKind::Other
                }
            };
            assert_eq!(
                actual, expected,
                "helper and GrpcError::from must classify {kind:?} identically"
            );
        }
    }

    #[test]
    fn test_grpc_error_into_status() {
        init_test("test_grpc_error_into_status");
        let error = GrpcError::MessageTooLarge;
        let status = error.into_status();
        let code = status.code();
        crate::assert_with_log!(
            code == Code::ResourceExhausted,
            "code",
            Code::ResourceExhausted,
            code
        );
        crate::test_complete!("test_grpc_error_into_status");
    }

    // Pure data-type tests (wave 13 – CyanBarn)

    #[test]
    fn code_display_all_variants() {
        assert_eq!(Code::Ok.to_string(), "OK");
        assert_eq!(Code::Cancelled.to_string(), "CANCELLED");
        assert_eq!(Code::Unknown.to_string(), "UNKNOWN");
        assert_eq!(Code::InvalidArgument.to_string(), "INVALID_ARGUMENT");
        assert_eq!(Code::DeadlineExceeded.to_string(), "DEADLINE_EXCEEDED");
        assert_eq!(Code::NotFound.to_string(), "NOT_FOUND");
        assert_eq!(Code::AlreadyExists.to_string(), "ALREADY_EXISTS");
        assert_eq!(Code::PermissionDenied.to_string(), "PERMISSION_DENIED");
        assert_eq!(Code::ResourceExhausted.to_string(), "RESOURCE_EXHAUSTED");
        assert_eq!(Code::FailedPrecondition.to_string(), "FAILED_PRECONDITION");
        assert_eq!(Code::Aborted.to_string(), "ABORTED");
        assert_eq!(Code::OutOfRange.to_string(), "OUT_OF_RANGE");
        assert_eq!(Code::Unimplemented.to_string(), "UNIMPLEMENTED");
        assert_eq!(Code::Internal.to_string(), "INTERNAL");
        assert_eq!(Code::Unavailable.to_string(), "UNAVAILABLE");
        assert_eq!(Code::DataLoss.to_string(), "DATA_LOSS");
        assert_eq!(Code::Unauthenticated.to_string(), "UNAUTHENTICATED");
    }

    #[test]
    fn code_default_is_unknown() {
        assert_eq!(Code::default(), Code::Unknown);
    }

    #[test]
    fn code_debug_clone_copy_eq_hash() {
        let code = Code::NotFound;
        let dbg = format!("{code:?}");
        assert!(dbg.contains("NotFound"));

        let cloned = code;
        assert_eq!(code, cloned);

        let mut set = std::collections::HashSet::new();
        set.insert(Code::Ok);
        set.insert(Code::Ok);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn code_as_i32_all_variants() {
        assert_eq!(Code::Ok.as_i32(), 0);
        assert_eq!(Code::Cancelled.as_i32(), 1);
        assert_eq!(Code::Unknown.as_i32(), 2);
        assert_eq!(Code::InvalidArgument.as_i32(), 3);
        assert_eq!(Code::DeadlineExceeded.as_i32(), 4);
        assert_eq!(Code::NotFound.as_i32(), 5);
        assert_eq!(Code::AlreadyExists.as_i32(), 6);
        assert_eq!(Code::PermissionDenied.as_i32(), 7);
        assert_eq!(Code::ResourceExhausted.as_i32(), 8);
        assert_eq!(Code::FailedPrecondition.as_i32(), 9);
        assert_eq!(Code::Aborted.as_i32(), 10);
        assert_eq!(Code::OutOfRange.as_i32(), 11);
        assert_eq!(Code::Unimplemented.as_i32(), 12);
        assert_eq!(Code::Internal.as_i32(), 13);
        assert_eq!(Code::Unavailable.as_i32(), 14);
        assert_eq!(Code::DataLoss.as_i32(), 15);
        assert_eq!(Code::Unauthenticated.as_i32(), 16);
    }

    #[test]
    fn code_from_i32_all_variants() {
        assert_eq!(Code::from_i32(0), Code::Ok);
        assert_eq!(Code::from_i32(1), Code::Cancelled);
        assert_eq!(Code::from_i32(2), Code::Unknown);
        assert_eq!(Code::from_i32(3), Code::InvalidArgument);
        assert_eq!(Code::from_i32(4), Code::DeadlineExceeded);
        assert_eq!(Code::from_i32(5), Code::NotFound);
        assert_eq!(Code::from_i32(6), Code::AlreadyExists);
        assert_eq!(Code::from_i32(7), Code::PermissionDenied);
        assert_eq!(Code::from_i32(8), Code::ResourceExhausted);
        assert_eq!(Code::from_i32(9), Code::FailedPrecondition);
        assert_eq!(Code::from_i32(10), Code::Aborted);
        assert_eq!(Code::from_i32(11), Code::OutOfRange);
        assert_eq!(Code::from_i32(12), Code::Unimplemented);
        assert_eq!(Code::from_i32(13), Code::Internal);
        assert_eq!(Code::from_i32(14), Code::Unavailable);
        assert_eq!(Code::from_i32(15), Code::DataLoss);
        assert_eq!(Code::from_i32(16), Code::Unauthenticated);
        assert_eq!(Code::from_i32(-1), Code::Unknown);
        assert_eq!(Code::from_i32(999), Code::Unknown);
    }

    #[test]
    fn code_as_str_all_variants() {
        assert_eq!(Code::Ok.as_str(), "OK");
        assert_eq!(Code::Cancelled.as_str(), "CANCELLED");
        assert_eq!(Code::Unknown.as_str(), "UNKNOWN");
        assert_eq!(Code::Aborted.as_str(), "ABORTED");
        assert_eq!(Code::DataLoss.as_str(), "DATA_LOSS");
        assert_eq!(Code::Unauthenticated.as_str(), "UNAUTHENTICATED");
    }

    #[test]
    fn status_debug_clone() {
        let status = Status::new(Code::NotFound, "missing");
        let dbg = format!("{status:?}");
        assert!(dbg.contains("NotFound"));
        assert!(dbg.contains("missing"));

        let cloned = status;
        assert_eq!(cloned.code(), Code::NotFound);
        assert_eq!(cloned.message(), "missing");
    }

    #[test]
    fn status_display_format() {
        let status = Status::new(Code::Internal, "something broke");
        let display = status.to_string();
        assert!(display.contains("INTERNAL"));
        assert!(display.contains("something broke"));
    }

    #[test]
    fn status_error_trait() {
        let status = Status::new(Code::Unavailable, "down");
        let err: &dyn std::error::Error = &status;
        assert!(!err.to_string().is_empty());
        assert!(err.source().is_none());
    }

    #[test]
    fn status_convenience_constructors() {
        assert_eq!(Status::cancelled("c").code(), Code::Cancelled);
        assert_eq!(Status::unknown("u").code(), Code::Unknown);
        assert_eq!(Status::invalid_argument("i").code(), Code::InvalidArgument);
        assert_eq!(
            Status::deadline_exceeded("d").code(),
            Code::DeadlineExceeded
        );
        assert_eq!(Status::not_found("n").code(), Code::NotFound);
        assert_eq!(Status::already_exists("a").code(), Code::AlreadyExists);
        assert_eq!(
            Status::permission_denied("p").code(),
            Code::PermissionDenied
        );
        assert_eq!(
            Status::resource_exhausted("r").code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            Status::failed_precondition("f").code(),
            Code::FailedPrecondition
        );
        assert_eq!(Status::aborted("a").code(), Code::Aborted);
        assert_eq!(Status::out_of_range("o").code(), Code::OutOfRange);
        assert_eq!(Status::unimplemented("u").code(), Code::Unimplemented);
        assert_eq!(Status::internal("i").code(), Code::Internal);
        assert_eq!(Status::unavailable("u").code(), Code::Unavailable);
        assert_eq!(Status::data_loss("d").code(), Code::DataLoss);
        assert_eq!(Status::unauthenticated("u").code(), Code::Unauthenticated);
    }

    #[test]
    fn status_is_ok_false_for_error() {
        let status = Status::new(Code::Internal, "bad");
        assert!(!status.is_ok());
    }

    #[test]
    fn status_from_io_error() {
        let io_err = std::io::Error::other("disk fail");
        let status: Status = Status::from(io_err);
        assert_eq!(status.code(), Code::Internal);
        assert!(status.message().contains("disk fail"));
    }

    #[test]
    fn grpc_error_display_all_variants() {
        let status_err = GrpcError::Status(Status::new(Code::NotFound, "gone"));
        assert!(status_err.to_string().contains("gone"));

        let transport_err = GrpcError::transport("conn refused");
        assert!(transport_err.to_string().contains("transport error"));

        let protocol_err = GrpcError::protocol("bad frame");
        assert!(protocol_err.to_string().contains("protocol error"));

        let msg_err = GrpcError::MessageTooLarge;
        assert!(msg_err.to_string().contains("message too large"));

        let invalid_err = GrpcError::invalid_message("corrupt");
        assert!(invalid_err.to_string().contains("invalid message"));

        let comp_err = GrpcError::compression("zlib fail");
        assert!(comp_err.to_string().contains("compression error"));
    }

    #[test]
    fn grpc_error_debug() {
        let err = GrpcError::MessageTooLarge;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("MessageTooLarge"));
    }

    #[test]
    fn grpc_error_error_trait() {
        let err = GrpcError::transport("t");
        let dyn_err: &dyn std::error::Error = &err;
        assert!(dyn_err.source().is_none());
    }

    #[test]
    fn grpc_error_into_status_all_variants() {
        let s = GrpcError::Status(Status::ok()).into_status();
        assert_eq!(s.code(), Code::Ok);

        let s = GrpcError::transport("down").into_status();
        assert_eq!(s.code(), Code::Unavailable);

        // br-asupersync-9gg21l: substring 'timed out' is no longer
        // classified as DeadlineExceeded by accident — callers must use
        // GrpcError::transport_kind(TransportErrorKind::Timeout, ...) to
        // request that classification.
        let s = GrpcError::transport_kind(TransportErrorKind::Timeout, "timed out").into_status();
        assert_eq!(s.code(), Code::DeadlineExceeded);

        // Bare unclassified transport defaults to Unavailable even if the
        // message text happens to contain 'timeout' (no substring magic).
        let s = GrpcError::transport("the message says timeout but kind is Other").into_status();
        assert_eq!(s.code(), Code::Unavailable);

        let s = GrpcError::protocol("bad").into_status();
        assert_eq!(s.code(), Code::Internal);

        let s = GrpcError::MessageTooLarge.into_status();
        assert_eq!(s.code(), Code::ResourceExhausted);

        let s = GrpcError::invalid_message("x").into_status();
        assert_eq!(s.code(), Code::InvalidArgument);

        let s = GrpcError::compression("z").into_status();
        assert_eq!(s.code(), Code::Internal);
    }

    #[test]
    fn grpc_error_from_status() {
        let status = Status::new(Code::Aborted, "abort");
        let err: GrpcError = GrpcError::from(status);
        assert!(matches!(err, GrpcError::Status(_)));
    }

    #[test]
    fn grpc_error_from_io_error() {
        let io_err = std::io::Error::other("net fail");
        let err: GrpcError = GrpcError::from(io_err);
        assert!(err.to_string().contains("net fail"));
    }

    // gRPC Status Codes and Trailers Round-trip Conformance Tests
    // Test all 17 canonical gRPC status codes per spec

    /// All 17 canonical gRPC status codes as defined by the gRPC specification.
    const CANONICAL_STATUS_CODES: &[(Code, i32, &str)] = &[
        (Code::Ok, 0, "OK"),
        (Code::Cancelled, 1, "CANCELLED"),
        (Code::Unknown, 2, "UNKNOWN"),
        (Code::InvalidArgument, 3, "INVALID_ARGUMENT"),
        (Code::DeadlineExceeded, 4, "DEADLINE_EXCEEDED"),
        (Code::NotFound, 5, "NOT_FOUND"),
        (Code::AlreadyExists, 6, "ALREADY_EXISTS"),
        (Code::PermissionDenied, 7, "PERMISSION_DENIED"),
        (Code::ResourceExhausted, 8, "RESOURCE_EXHAUSTED"),
        (Code::FailedPrecondition, 9, "FAILED_PRECONDITION"),
        (Code::Aborted, 10, "ABORTED"),
        (Code::OutOfRange, 11, "OUT_OF_RANGE"),
        (Code::Unimplemented, 12, "UNIMPLEMENTED"),
        (Code::Internal, 13, "INTERNAL"),
        (Code::Unavailable, 14, "UNAVAILABLE"),
        (Code::DataLoss, 15, "DATA_LOSS"),
        (Code::Unauthenticated, 16, "UNAUTHENTICATED"),
    ];

    /// Test data for UTF-8 message escaping scenarios.
    const UTF8_ESCAPE_TEST_CASES: &[(&str, &str)] = &[
        ("basic ascii", "basic ascii"),
        ("unicode: café", "unicode: café"),
        ("emoji: 🚀", "emoji: 🚀"),
        ("newlines:\ntest", "newlines:\\ntest"),
        ("tabs:\ttest", "tabs:\\ttest"),
        ("quotes: \"test\"", "quotes: \\\"test\\\""),
        ("backslash: \\", "backslash: \\\\"),
        ("mixed: 测试\n\"quote\\", "mixed: 测试\\n\\\"quote\\\\"),
    ];

    /// Escape grpc-message value for HTTP/2 header transmission.
    fn escape_grpc_message(message: &str) -> String {
        message
            .chars()
            .flat_map(|c| match c {
                '"' => vec!['\\', '"'],
                '\\' => vec!['\\', '\\'],
                '\n' => vec!['\\', 'n'],
                '\r' => vec!['\\', 'r'],
                '\t' => vec!['\\', 't'],
                c => vec![c],
            })
            .collect()
    }

    /// Unescape grpc-message value from HTTP/2 header.
    fn unescape_grpc_message(escaped: &str) -> String {
        let mut result = String::with_capacity(escaped.len());
        let mut chars = escaped.chars().peekable();

        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some('"') => result.push('"'),
                    Some('\\') => result.push('\\'),
                    Some('n') => result.push('\n'),
                    Some('r') => result.push('\r'),
                    Some('t') => result.push('\t'),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => result.push('\\'),
                }
            } else {
                result.push(c);
            }
        }

        result
    }

    fn status_wire_snapshot(status: &Status) -> serde_json::Value {
        serde_json::json!({
            "grpc-status": status.code().as_i32().to_string(),
            "grpc-message": escape_grpc_message(status.message()),
            "grpc-status-details-bin": status.details().map(|details| {
                base64::engine::general_purpose::STANDARD.encode(details)
            }),
        })
    }

    fn canonical_http_status_for_code(code: Code) -> HttpStatusCode {
        match code {
            Code::Ok => HttpStatusCode::OK,
            Code::Cancelled => HttpStatusCode::CLIENT_CLOSED_REQUEST,
            Code::Unknown => HttpStatusCode::INTERNAL_SERVER_ERROR,
            Code::InvalidArgument => HttpStatusCode::BAD_REQUEST,
            Code::DeadlineExceeded => HttpStatusCode::GATEWAY_TIMEOUT,
            Code::NotFound => HttpStatusCode::NOT_FOUND,
            Code::AlreadyExists => HttpStatusCode::CONFLICT,
            Code::PermissionDenied => HttpStatusCode::FORBIDDEN,
            Code::ResourceExhausted => HttpStatusCode::TOO_MANY_REQUESTS,
            Code::FailedPrecondition => HttpStatusCode::BAD_REQUEST,
            Code::Aborted => HttpStatusCode::CONFLICT,
            Code::OutOfRange => HttpStatusCode::BAD_REQUEST,
            Code::Unimplemented => HttpStatusCode::NOT_IMPLEMENTED,
            Code::Internal => HttpStatusCode::INTERNAL_SERVER_ERROR,
            Code::Unavailable => HttpStatusCode::SERVICE_UNAVAILABLE,
            Code::DataLoss => HttpStatusCode::INTERNAL_SERVER_ERROR,
            Code::Unauthenticated => HttpStatusCode::UNAUTHORIZED,
        }
    }

    fn scrub_status_mapping_snapshot(mut snapshot: serde_json::Value) -> serde_json::Value {
        fn scrub(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, entry) in map {
                        if key.contains("timestamp") {
                            *entry = serde_json::Value::String("<scrubbed-timestamp>".to_owned());
                        } else {
                            scrub(entry);
                        }
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        scrub(value);
                    }
                }
                _ => {}
            }
        }

        scrub(&mut snapshot);
        snapshot
    }

    fn status_http_mapping_snapshot() -> serde_json::Value {
        serde_json::Value::Array(
            CANONICAL_STATUS_CODES
                .iter()
                .map(|&(code, grpc_status, grpc_name)| {
                    let status = Status::new(code, grpc_name);
                    serde_json::json!({
                        "grpc_code": grpc_name,
                        "grpc_status": grpc_status,
                        "http_status": canonical_http_status_for_code(code).as_u16(),
                        "wire": status_wire_snapshot(&status),
                    })
                })
                .collect(),
        )
    }

    #[test]
    fn test_all_canonical_status_codes_encode_correctly() {
        init_test("test_all_canonical_status_codes_encode_correctly");

        for &(code, expected_int, expected_str) in CANONICAL_STATUS_CODES {
            let as_i32 = code.as_i32();
            crate::assert_with_log!(
                as_i32 == expected_int,
                format!("Code {:?} as_i32", code),
                expected_int,
                as_i32
            );

            let as_str = code.as_str();
            crate::assert_with_log!(
                as_str == expected_str,
                format!("Code {:?} as_str", code),
                expected_str,
                as_str
            );

            let display_str = code.to_string();
            crate::assert_with_log!(
                display_str == expected_str,
                format!("Code {:?} display", code),
                expected_str,
                display_str
            );
        }

        crate::test_complete!("test_all_canonical_status_codes_encode_correctly");
    }

    #[test]
    fn test_all_canonical_status_codes_decode_correctly() {
        init_test("test_all_canonical_status_codes_decode_correctly");

        for &(expected_code, code_int, _) in CANONICAL_STATUS_CODES {
            let decoded = Code::from_i32(code_int);
            crate::assert_with_log!(
                decoded == expected_code,
                format!("from_i32({})", code_int),
                expected_code,
                decoded
            );
        }

        crate::test_complete!("test_all_canonical_status_codes_decode_correctly");
    }

    #[test]
    fn test_invalid_status_codes_map_to_unknown() {
        init_test("test_invalid_status_codes_map_to_unknown");

        let invalid_codes = [-1, 17, 99, 255, 1000, i32::MAX, i32::MIN];

        for &invalid_code in &invalid_codes {
            let decoded = Code::from_i32(invalid_code);
            crate::assert_with_log!(
                decoded == Code::Unknown,
                format!("from_i32({})", invalid_code),
                Code::Unknown,
                decoded
            );
        }

        crate::test_complete!("test_invalid_status_codes_map_to_unknown");
    }

    #[test]
    fn test_grpc_message_utf8_escaping() {
        init_test("test_grpc_message_utf8_escaping");

        for &(original, expected_escaped) in UTF8_ESCAPE_TEST_CASES {
            let escaped = escape_grpc_message(original);
            crate::assert_with_log!(
                escaped == expected_escaped,
                format!("escape '{}'", original),
                expected_escaped,
                escaped
            );

            let unescaped = unescape_grpc_message(&escaped);
            crate::assert_with_log!(
                unescaped == original,
                format!("unescape '{}'", escaped),
                original,
                unescaped
            );
        }

        crate::test_complete!("test_grpc_message_utf8_escaping");
    }

    #[test]
    fn grpc_status_wire_format_snapshot() {
        let status = Status::with_details(
            Code::InvalidArgument,
            "field \"display_name\"\ncontains invalid UTF-8: 🚀",
            Bytes::from_static(b"\x00grpc-details\xff"),
        );

        insta::assert_json_snapshot!(
            "grpc_status_wire_format_invalid_argument",
            status_wire_snapshot(&status)
        );
    }

    #[test]
    fn grpc_status_http_mapping_snapshot() {
        insta::with_settings!({sort_maps => true}, {
            insta::assert_json_snapshot!(
                "grpc_status_http_mapping_all_codes",
                scrub_status_mapping_snapshot(status_http_mapping_snapshot())
            );
        });
    }

    #[test]
    fn test_comprehensive_status_trailer_conformance() {
        init_test("test_comprehensive_status_trailer_conformance");

        // Test all canonical codes with various message types
        let test_cases = vec![
            (Code::Ok, ""),
            (Code::Cancelled, "Request was cancelled"),
            (Code::Unknown, "Unknown error occurred"),
            (
                Code::InvalidArgument,
                "Invalid argument: field \"name\" is required",
            ),
            (Code::DeadlineExceeded, "Deadline exceeded after 30s"),
            (Code::NotFound, "Resource /api/v1/users/123 not found"),
            (
                Code::AlreadyExists,
                "User with email alice@example.com already exists",
            ),
            (
                Code::PermissionDenied,
                "Insufficient permissions for operation",
            ),
            (
                Code::ResourceExhausted,
                "Rate limit exceeded: 1000 requests/hour",
            ),
            (
                Code::FailedPrecondition,
                "Account must be verified before transfer",
            ),
            (Code::Aborted, "Transaction aborted due to conflict"),
            (Code::OutOfRange, "Index 42 is out of range [0, 10)"),
            (
                Code::Unimplemented,
                "Method FindUsersByLocation not implemented",
            ),
            (
                Code::Internal,
                "Internal server error: database connection failed",
            ),
            (Code::Unavailable, "Service temporarily unavailable"),
            (Code::DataLoss, "Data corruption detected in sector 7"),
            (
                Code::Unauthenticated,
                "Invalid or expired authentication token",
            ),
        ];

        for (code, message) in test_cases {
            // Create status
            let original_status = Status::new(code, message);

            // Test round-trip through integer encoding
            let encoded_int = original_status.code().as_i32();
            let decoded_code = Code::from_i32(encoded_int);

            crate::assert_with_log!(
                decoded_code == original_status.code(),
                format!("{:?} code round-trip", code),
                original_status.code(),
                decoded_code
            );

            // Test string representation
            let code_str = original_status.code().as_str();
            let display_str = original_status.code().to_string();

            crate::assert_with_log!(
                code_str == display_str,
                format!("{:?} string consistency", code),
                code_str,
                display_str
            );

            // Test message escaping round-trip
            if !message.is_empty() {
                let escaped = escape_grpc_message(original_status.message());
                let unescaped = unescape_grpc_message(&escaped);

                crate::assert_with_log!(
                    unescaped == original_status.message(),
                    format!("{:?} message escape round-trip", code),
                    original_status.message(),
                    unescaped
                );
            }
        }

        crate::test_complete!("test_comprehensive_status_trailer_conformance");
    }

    #[test]
    fn test_grpc_error_status_conversion() {
        init_test("test_grpc_error_status_conversion");

        let error_cases = vec![
            (GrpcError::MessageTooLarge, Code::ResourceExhausted),
            (
                GrpcError::transport_kind(TransportErrorKind::ConnectFailed, "Connection failed"),
                Code::Unavailable,
            ),
            (
                GrpcError::transport_kind(TransportErrorKind::Timeout, "request timeout"),
                Code::DeadlineExceeded,
            ),
            (GrpcError::protocol("Invalid frame"), Code::Internal),
            (
                GrpcError::invalid_message("Malformed"),
                Code::InvalidArgument,
            ),
            (
                GrpcError::compression("Decompression failed"),
                Code::Internal,
            ),
        ];

        for (error, expected_code) in error_cases {
            let status = error.into_status();
            crate::assert_with_log!(
                status.code() == expected_code,
                format!("GrpcError conversion to {:?}", expected_code),
                expected_code,
                status.code()
            );

            // Test integer encoding round-trip
            let encoded_int = status.code().as_i32();
            let decoded_code = Code::from_i32(encoded_int);

            crate::assert_with_log!(
                decoded_code == expected_code,
                format!("Round-trip {:?}", expected_code),
                expected_code,
                decoded_code
            );
        }

        crate::test_complete!("test_grpc_error_status_conversion");
    }

    /// br-asupersync-q01vh5 — full mapping table from the gRPC HTTP/2
    /// protocol spec. Every HTTP/2 RST_STREAM error code MUST produce
    /// the gRPC status code listed in
    /// <https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md>.
    ///
    /// Pre-fix the only mapping in the codebase was the 3-row test
    /// helper `grpc_go_rst_stream_status`, missing the spec-mandated
    /// rows for ENHANCE_YOUR_CALM and INADEQUATE_SECURITY.
    #[test]
    fn from_h2_rst_stream_code_matches_grpc_http2_spec() {
        use crate::http::h2::error::ErrorCode;

        // (rst_code, expected gRPC code, expected token in message)
        let cases: &[(ErrorCode, Code, &str)] = &[
            (ErrorCode::NoError, Code::Internal, "NO_ERROR"),
            (ErrorCode::ProtocolError, Code::Internal, "PROTOCOL_ERROR"),
            (ErrorCode::InternalError, Code::Internal, "INTERNAL_ERROR"),
            (
                ErrorCode::FlowControlError,
                Code::Internal,
                "FLOW_CONTROL_ERROR",
            ),
            (
                ErrorCode::SettingsTimeout,
                Code::Internal,
                "SETTINGS_TIMEOUT",
            ),
            (ErrorCode::StreamClosed, Code::Internal, "STREAM_CLOSED"),
            (
                ErrorCode::FrameSizeError,
                Code::Internal,
                "FRAME_SIZE_ERROR",
            ),
            (
                ErrorCode::RefusedStream,
                Code::Unavailable,
                "REFUSED_STREAM",
            ),
            (ErrorCode::Cancel, Code::Cancelled, "CANCEL"),
            (
                ErrorCode::CompressionError,
                Code::Internal,
                "COMPRESSION_ERROR",
            ),
            (ErrorCode::ConnectError, Code::Internal, "CONNECT_ERROR"),
            (
                ErrorCode::EnhanceYourCalm,
                Code::ResourceExhausted,
                "ENHANCE_YOUR_CALM",
            ),
            (
                ErrorCode::InadequateSecurity,
                Code::PermissionDenied,
                "INADEQUATE_SECURITY",
            ),
            (
                ErrorCode::Http11Required,
                Code::Internal,
                "HTTP_1_1_REQUIRED",
            ),
        ];

        for (rst_code, expected_code, expected_token) in cases.iter().copied() {
            let status = Status::from_h2_rst_stream_code(rst_code);
            assert_eq!(
                status.code(),
                expected_code,
                "RST_STREAM {} (0x{:x}) must map to gRPC code {:?}, got {:?}",
                expected_token,
                u32::from(rst_code),
                expected_code,
                status.code()
            );
            assert!(
                status.message().contains(expected_token),
                "Status message for RST_STREAM {} should mention the wire name; got {:?}",
                expected_token,
                status.message()
            );
        }
    }
}
