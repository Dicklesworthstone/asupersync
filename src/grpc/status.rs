//! gRPC status codes and error types.
//!
//! Implements the gRPC status codes as defined in the gRPC specification.

use crate::bytes::Bytes;
use std::fmt;

/// gRPC status codes.
///
/// These codes follow the gRPC specification and map to HTTP/2 status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Code {
    /// Not an error; returned on success.
    Ok = 0,
    /// The operation was cancelled, typically by the caller.
    Cancelled = 1,
    /// Unknown error.
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
            2 => Self::Unknown,
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

impl Default for Code {
    fn default() -> Self {
        Self::Unknown
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
}
