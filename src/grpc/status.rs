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

impl Status {
    /// Create a new status with the given code and message.
    #[must_use]
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    /// Create a status with details.
    #[must_use]
    pub fn with_details(code: Code, message: impl Into<String>, details: Bytes) -> Self {
        Self {
            code,
            message: message.into(),
            details: Some(details),
        }
    }

    /// Create an OK status.
    #[must_use]
    pub fn ok() -> Self {
        Self::new(Code::Ok, "")
    }

    /// Create a cancelled status.
    #[must_use]
    pub fn cancelled(message: impl Into<String>) -> Self {
        Self::new(Code::Cancelled, message)
    }

    /// Create an unknown error status.
    #[must_use]
    pub fn unknown(message: impl Into<String>) -> Self {
        Self::new(Code::Unknown, message)
    }

    /// Create an invalid argument status.
    #[must_use]
    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidArgument, message)
    }

    /// Create a deadline exceeded status.
    #[must_use]
    pub fn deadline_exceeded(message: impl Into<String>) -> Self {
        Self::new(Code::DeadlineExceeded, message)
    }

    /// Create a not found status.
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Code::NotFound, message)
    }

    /// Create an already exists status.
    #[must_use]
    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::new(Code::AlreadyExists, message)
    }

    /// Create a permission denied status.
    #[must_use]
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(Code::PermissionDenied, message)
    }

    /// Create a resource exhausted status.
    #[must_use]
    pub fn resource_exhausted(message: impl Into<String>) -> Self {
        Self::new(Code::ResourceExhausted, message)
    }

    /// Create a failed precondition status.
    #[must_use]
    pub fn failed_precondition(message: impl Into<String>) -> Self {
        Self::new(Code::FailedPrecondition, message)
    }

    /// Create an aborted status.
    #[must_use]
    pub fn aborted(message: impl Into<String>) -> Self {
        Self::new(Code::Aborted, message)
    }

    /// Create an out of range status.
    #[must_use]
    pub fn out_of_range(message: impl Into<String>) -> Self {
        Self::new(Code::OutOfRange, message)
    }

    /// Create an unimplemented status.
    #[must_use]
    pub fn unimplemented(message: impl Into<String>) -> Self {
        Self::new(Code::Unimplemented, message)
    }

    /// Create an internal error status.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Code::Internal, message)
    }

    /// Create an unavailable status.
    #[must_use]
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(Code::Unavailable, message)
    }

    /// Create a data loss status.
    #[must_use]
    pub fn data_loss(message: impl Into<String>) -> Self {
        Self::new(Code::DataLoss, message)
    }

    /// Create an unauthenticated status.
    #[must_use]
    pub fn unauthenticated(message: impl Into<String>) -> Self {
        Self::new(Code::Unauthenticated, message)
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

/// gRPC error type.
#[derive(Debug)]
pub enum GrpcError {
    /// A gRPC status error.
    Status(Status),
    /// Transport error.
    Transport(String),
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
    /// Create a transport error.
    #[must_use]
    pub fn transport(message: impl Into<String>) -> Self {
        Self::Transport(message.into())
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
            Self::Transport(msg) => Status::unavailable(msg),
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
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
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
        Self::Transport(err.to_string())
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

        let cloned = status.clone();
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
        assert_eq!(Status::deadline_exceeded("d").code(), Code::DeadlineExceeded);
        assert_eq!(Status::not_found("n").code(), Code::NotFound);
        assert_eq!(Status::already_exists("a").code(), Code::AlreadyExists);
        assert_eq!(Status::permission_denied("p").code(), Code::PermissionDenied);
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
}
