//! Error types and error handling strategy for Asupersync.
//!
//! This module defines the core error types used throughout the runtime.
//! Error handling follows these principles:
//!
//! - Errors are explicit and typed (no stringly-typed errors)
//! - Errors compose well with the Outcome severity lattice
//! - Panics are isolated and converted to `Outcome::Panicked`
//! - Errors are classified by recoverability for retry logic
//!
//! # Error Categories
//!
//! Errors are organized into categories:
//!
//! - **Cancellation**: Operation cancelled by request or timeout
//! - **Budgets**: Resource limits exceeded (deadlines, quotas)
//! - **Channels**: Communication primitive errors
//! - **Obligations**: Linear resource tracking violations
//! - **Regions**: Ownership and lifecycle errors
//! - **Encoding**: RaptorQ encoding pipeline errors
//! - **Decoding**: RaptorQ decoding pipeline errors
//! - **Transport**: Symbol routing and transmission errors
//! - **Distributed**: Distributed region coordination errors
//! - **Internal**: Runtime bugs and invalid states
//!
//! # Recovery Classification
//!
//! All errors can be classified by [`Recoverability`]:
//! - `Transient`: Temporary failure, safe to retry
//! - `Permanent`: Unrecoverable, do not retry
//! - `Unknown`: Recoverability depends on context

use core::fmt;
use std::sync::Arc;

use crate::types::symbol::{ObjectId, SymbolId};
use crate::types::{CancelReason, RegionId, TaskId};

pub mod recovery;

/// The kind of error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    // === Cancellation ===
    /// Operation was cancelled.
    Cancelled,
    /// Cancellation cleanup budget was exceeded.
    CancelTimeout,

    // === Budgets ===
    /// Deadline exceeded.
    DeadlineExceeded,
    /// Poll quota exhausted.
    PollQuotaExhausted,
    /// Cost quota exhausted.
    CostQuotaExhausted,

    // === Channels ===
    /// Channel is closed/disconnected.
    ChannelClosed,
    /// Channel is full (would block).
    ChannelFull,
    /// Channel is empty (would block).
    ChannelEmpty,

    // === Obligations ===
    /// Obligation was not resolved before close/completion.
    ObligationLeak,
    /// Tried to resolve an already-resolved obligation.
    ObligationAlreadyResolved,

    // === Regions / ownership ===
    /// Region is already closed.
    RegionClosed,
    /// Task not owned by region.
    TaskNotOwned,
    /// Region admission/backpressure limit reached.
    AdmissionDenied,

    // === Encoding (RaptorQ) ===
    /// Invalid encoding parameters (symbol size, block count, etc.).
    InvalidEncodingParams,
    /// Source data too large for configured parameters.
    DataTooLarge,
    /// Encoding operation failed.
    EncodingFailed,
    /// Symbol data is corrupted or invalid.
    CorruptedSymbol,

    // === Decoding (RaptorQ) ===
    /// Not enough symbols received to decode.
    InsufficientSymbols,
    /// Decoding operation failed (matrix singular, etc.).
    DecodingFailed,
    /// Symbol does not belong to the expected object.
    ObjectMismatch,
    /// Received duplicate symbol.
    DuplicateSymbol,
    /// Decoding threshold not met within timeout.
    ThresholdTimeout,

    // === Transport ===
    /// Symbol routing failed (no route to destination).
    RoutingFailed,
    /// Symbol dispatch failed.
    DispatchFailed,
    /// Symbol stream ended unexpectedly.
    StreamEnded,
    /// Symbol sink rejected the symbol.
    SinkRejected,
    /// Transport connection lost.
    ConnectionLost,
    /// Transport connection refused.
    ConnectionRefused,
    /// Transport protocol error.
    ProtocolError,

    // === Distributed Regions ===
    /// Region recovery failed.
    RecoveryFailed,
    /// Lease expired during operation.
    LeaseExpired,
    /// Lease renewal failed.
    LeaseRenewalFailed,
    /// Distributed coordination failed.
    CoordinationFailed,
    /// Quorum not reached.
    QuorumNotReached,
    /// Node is unavailable.
    NodeUnavailable,
    /// Partition detected (split brain).
    PartitionDetected,

    // === Internal / state machine ===
    /// Internal runtime error (bug).
    Internal,
    /// Invalid state transition.
    InvalidStateTransition,

    // === Configuration ===
    /// Configuration error (invalid env var, bad config file, etc.).
    ConfigError,

    // === User ===
    /// User-provided error.
    User,
}

impl ErrorKind {
    /// Returns the error category for this kind.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Cancelled | Self::CancelTimeout => ErrorCategory::Cancellation,
            Self::DeadlineExceeded | Self::PollQuotaExhausted | Self::CostQuotaExhausted => {
                ErrorCategory::Budget
            }
            Self::ChannelClosed | Self::ChannelFull | Self::ChannelEmpty => ErrorCategory::Channel,
            Self::ObligationLeak | Self::ObligationAlreadyResolved => ErrorCategory::Obligation,
            Self::RegionClosed | Self::TaskNotOwned | Self::AdmissionDenied => {
                ErrorCategory::Region
            }
            Self::InvalidEncodingParams
            | Self::DataTooLarge
            | Self::EncodingFailed
            | Self::CorruptedSymbol => ErrorCategory::Encoding,
            Self::InsufficientSymbols
            | Self::DecodingFailed
            | Self::ObjectMismatch
            | Self::DuplicateSymbol
            | Self::ThresholdTimeout => ErrorCategory::Decoding,
            Self::RoutingFailed
            | Self::DispatchFailed
            | Self::StreamEnded
            | Self::SinkRejected
            | Self::ConnectionLost
            | Self::ConnectionRefused
            | Self::ProtocolError => ErrorCategory::Transport,
            Self::RecoveryFailed
            | Self::LeaseExpired
            | Self::LeaseRenewalFailed
            | Self::CoordinationFailed
            | Self::QuorumNotReached
            | Self::NodeUnavailable
            | Self::PartitionDetected => ErrorCategory::Distributed,
            Self::Internal | Self::InvalidStateTransition => ErrorCategory::Internal,
            Self::ConfigError | Self::User => ErrorCategory::User,
        }
    }

    /// Returns the recoverability classification for this error kind.
    ///
    /// This helps retry logic decide whether to attempt recovery.
    #[must_use]
    pub const fn recoverability(&self) -> Recoverability {
        match self {
            // Transient errors - safe to retry
            Self::ChannelFull
            | Self::ChannelEmpty
            | Self::AdmissionDenied
            | Self::ConnectionLost
            | Self::NodeUnavailable
            | Self::QuorumNotReached
            | Self::ThresholdTimeout
            | Self::LeaseRenewalFailed => Recoverability::Transient,

            // Permanent errors - do not retry
            Self::Cancelled
            | Self::CancelTimeout
            | Self::ChannelClosed
            | Self::ObligationLeak
            | Self::ObligationAlreadyResolved
            | Self::RegionClosed
            | Self::InvalidEncodingParams
            | Self::DataTooLarge
            | Self::ObjectMismatch
            | Self::Internal
            | Self::InvalidStateTransition
            | Self::ProtocolError
            | Self::ConnectionRefused
            | Self::ConfigError => Recoverability::Permanent,

            // Context-dependent errors
            Self::DeadlineExceeded
            | Self::PollQuotaExhausted
            | Self::CostQuotaExhausted
            | Self::TaskNotOwned
            | Self::EncodingFailed
            | Self::CorruptedSymbol
            | Self::InsufficientSymbols
            | Self::DecodingFailed
            | Self::DuplicateSymbol
            | Self::RoutingFailed
            | Self::DispatchFailed
            | Self::StreamEnded
            | Self::SinkRejected
            | Self::RecoveryFailed
            | Self::LeaseExpired
            | Self::CoordinationFailed
            | Self::PartitionDetected
            | Self::User => Recoverability::Unknown,
        }
    }

    /// Returns true if this error is typically retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self.recoverability(), Recoverability::Transient)
    }

    /// Returns the recommended recovery action for this error kind.
    ///
    /// This provides more specific guidance than [`recoverability()`](Self::recoverability)
    /// about how to handle the error.
    #[must_use]
    pub const fn recovery_action(&self) -> RecoveryAction {
        match self {
            // Immediate retry - brief transient states
            Self::ChannelFull | Self::ChannelEmpty => RecoveryAction::RetryImmediately,

            // Backoff retry - transient but may need time to clear
            Self::AdmissionDenied
            | Self::ThresholdTimeout
            | Self::QuorumNotReached
            | Self::LeaseRenewalFailed => RecoveryAction::RetryWithBackoff(BackoffHint::DEFAULT),
            Self::NodeUnavailable => RecoveryAction::RetryWithBackoff(BackoffHint::AGGRESSIVE),

            // Reconnect - connection is likely broken
            Self::ConnectionLost | Self::StreamEnded => RecoveryAction::RetryWithNewConnection,

            // Propagate - let caller decide
            Self::Cancelled
            | Self::CancelTimeout
            | Self::DeadlineExceeded
            | Self::PollQuotaExhausted
            | Self::CostQuotaExhausted
            | Self::ChannelClosed
            | Self::RegionClosed
            | Self::InvalidEncodingParams
            | Self::DataTooLarge
            | Self::ObjectMismatch
            | Self::ConnectionRefused
            | Self::ProtocolError
            | Self::LeaseExpired
            | Self::PartitionDetected
            | Self::ConfigError => RecoveryAction::Propagate,

            // Escalate - serious problem, should cancel related work
            Self::ObligationLeak
            | Self::ObligationAlreadyResolved
            | Self::Internal
            | Self::InvalidStateTransition => RecoveryAction::Escalate,

            // Custom - depends on application context
            Self::TaskNotOwned
            | Self::EncodingFailed
            | Self::CorruptedSymbol
            | Self::InsufficientSymbols
            | Self::DecodingFailed
            | Self::DuplicateSymbol
            | Self::RoutingFailed
            | Self::DispatchFailed
            | Self::SinkRejected
            | Self::RecoveryFailed
            | Self::CoordinationFailed
            | Self::User => RecoveryAction::Custom,
        }
    }
}

/// Classification of error recoverability for retry logic.
///
/// This enum helps the retry combinator and error handling code
/// decide how to handle failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Recoverability {
    /// Temporary failure that may succeed on retry.
    Transient,
    /// Permanent failure that will not succeed on retry.
    Permanent,
    /// Recoverability depends on context and cannot be determined
    /// from the error kind alone.
    Unknown,
}

/// Recommended recovery action for an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryAction {
    /// Retry the operation immediately.
    RetryImmediately,
    /// Retry the operation with exponential backoff.
    RetryWithBackoff(BackoffHint),
    /// Retry after establishing a new connection.
    RetryWithNewConnection,
    /// Propagate the error to the caller without retry.
    Propagate,
    /// Escalate by requesting cancellation of the current operation tree.
    Escalate,
    /// Recovery action depends on application-specific context.
    Custom,
}

/// Hints for configuring exponential backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackoffHint {
    /// Suggested initial delay before first retry.
    pub initial_delay_ms: u32,
    /// Suggested maximum delay between retries.
    pub max_delay_ms: u32,
    /// Suggested maximum number of retry attempts.
    pub max_attempts: u8,
}

impl BackoffHint {
    /// Default backoff hint for transient errors.
    pub const DEFAULT: Self = Self {
        initial_delay_ms: 100,
        max_delay_ms: 30_000,
        max_attempts: 5,
    };

    /// Aggressive backoff for rate-limiting or overload scenarios.
    pub const AGGRESSIVE: Self = Self {
        initial_delay_ms: 1_000,
        max_delay_ms: 60_000,
        max_attempts: 10,
    };

    /// Quick backoff for brief transient failures.
    pub const QUICK: Self = Self {
        initial_delay_ms: 10,
        max_delay_ms: 1_000,
        max_attempts: 3,
    };
}

impl Default for BackoffHint {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Recoverability {
    /// Returns true if this error is safe to retry.
    #[must_use]
    pub const fn should_retry(&self) -> bool {
        matches!(self, Self::Transient)
    }

    /// Returns true if this error should never be retried.
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        matches!(self, Self::Permanent)
    }
}

/// High-level error category for grouping related errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// Cancellation-related failures.
    Cancellation,
    /// Budget/time/resource limit failures.
    Budget,
    /// Channel and messaging failures.
    Channel,
    /// Obligation lifecycle failures.
    Obligation,
    /// Region lifecycle failures.
    Region,
    /// Encoding failures.
    Encoding,
    /// Decoding failures.
    Decoding,
    /// Transport-layer failures.
    Transport,
    /// Distributed runtime failures.
    Distributed,
    /// Internal runtime errors.
    Internal,
    /// User-originated errors.
    User,
}

/// Diagnostic context for an error.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ErrorContext {
    /// The task where the error originated.
    pub task_id: Option<TaskId>,
    /// The region owning the task.
    pub region_id: Option<RegionId>,
    /// The object involved in the error (for distributed operations).
    pub object_id: Option<ObjectId>,
    /// The symbol involved in the error (for RaptorQ).
    pub symbol_id: Option<SymbolId>,
}

/// The main error type for Asupersync operations.
#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: Option<String>,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
    context: ErrorContext,
}

impl Error {
    /// Creates a new error with the given kind.
    #[must_use]
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            message: None,
            source: None,
            context: ErrorContext {
                task_id: None,
                region_id: None,
                object_id: None,
                symbol_id: None,
            },
        }
    }

    /// Returns the error kind.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns true if this error represents cancellation.
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self.kind, ErrorKind::Cancelled)
    }

    /// Returns true if this error is a timeout/deadline condition.
    #[must_use]
    pub const fn is_timeout(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::DeadlineExceeded | ErrorKind::CancelTimeout
        )
    }

    /// Adds a message description to the error.
    #[must_use]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Adds structured context to the error.
    #[must_use]
    pub fn with_context(mut self, ctx: ErrorContext) -> Self {
        self.context = ctx;
        self
    }

    /// Adds a source error to the chain.
    #[must_use]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Arc::new(source));
        self
    }

    /// Creates a cancellation error from a structured reason.
    #[must_use]
    pub fn cancelled(reason: &CancelReason) -> Self {
        Self::new(ErrorKind::Cancelled).with_message(reason.to_string())
    }

    /// Returns the error category.
    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        self.kind.category()
    }

    /// Returns the recoverability classification.
    #[must_use]
    pub const fn recoverability(&self) -> Recoverability {
        self.kind.recoverability()
    }

    /// Returns true if this error is typically retryable.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }

    /// Returns the recommended recovery action for this error.
    #[must_use]
    pub const fn recovery_action(&self) -> RecoveryAction {
        self.kind.recovery_action()
    }

    /// Returns the error message, if any.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Returns the error context.
    #[must_use]
    pub fn context(&self) -> &ErrorContext {
        &self.context
    }

    /// Returns true if this is an encoding-related error.
    #[must_use]
    pub const fn is_encoding_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Encoding)
    }

    /// Returns true if this is a decoding-related error.
    #[must_use]
    pub const fn is_decoding_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Decoding)
    }

    /// Returns true if this is a transport-related error.
    #[must_use]
    pub const fn is_transport_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Transport)
    }

    /// Returns true if this is a distributed coordination error.
    #[must_use]
    pub const fn is_distributed_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Distributed)
    }

    /// Returns true if this is a connection-related error.
    #[must_use]
    pub const fn is_connection_error(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::ConnectionLost | ErrorKind::ConnectionRefused
        )
    }

    /// Creates an encoding error with parameters context.
    #[must_use]
    pub fn invalid_encoding_params(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidEncodingParams).with_message(detail)
    }

    /// Creates a data too large error.
    #[must_use]
    pub fn data_too_large(actual: u64, max: u64) -> Self {
        Self::new(ErrorKind::DataTooLarge)
            .with_message(format!("data size {actual} exceeds maximum {max}"))
    }

    /// Creates an insufficient symbols error for decoding.
    #[must_use]
    pub fn insufficient_symbols(received: u32, needed: u32) -> Self {
        Self::new(ErrorKind::InsufficientSymbols).with_message(format!(
            "received {received} symbols, need at least {needed}"
        ))
    }

    /// Creates a decoding failed error.
    #[must_use]
    pub fn decoding_failed(reason: impl Into<String>) -> Self {
        Self::new(ErrorKind::DecodingFailed).with_message(reason)
    }

    /// Creates a routing failed error.
    #[must_use]
    pub fn routing_failed(destination: impl Into<String>) -> Self {
        Self::new(ErrorKind::RoutingFailed)
            .with_message(format!("no route to destination: {}", destination.into()))
    }

    /// Creates a lease expired error.
    #[must_use]
    pub fn lease_expired(lease_id: impl Into<String>) -> Self {
        Self::new(ErrorKind::LeaseExpired)
            .with_message(format!("lease expired: {}", lease_id.into()))
    }

    /// Creates a quorum not reached error.
    #[must_use]
    pub fn quorum_not_reached(achieved: u32, needed: u32) -> Self {
        Self::new(ErrorKind::QuorumNotReached)
            .with_message(format!("achieved {achieved} of {needed} required"))
    }

    /// Creates a node unavailable error.
    #[must_use]
    pub fn node_unavailable(node_id: impl Into<String>) -> Self {
        Self::new(ErrorKind::NodeUnavailable)
            .with_message(format!("node unavailable: {}", node_id.into()))
    }

    /// Creates an internal error (runtime bug).
    #[must_use]
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal).with_message(detail)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        if let Some(msg) = &self.message {
            write!(f, ": {msg}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

/// Marker type for cancellation, carrying a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cancelled {
    /// The reason for cancellation.
    pub reason: CancelReason,
}

impl From<Cancelled> for Error {
    fn from(c: Cancelled) -> Self {
        Self::cancelled(&c.reason)
    }
}

/// Error when sending on a channel.
#[derive(Debug)]
pub enum SendError<T> {
    /// Channel receiver was dropped.
    Disconnected(T),
    /// Would block (bounded channel is full).
    Full(T),
    /// The send operation was cancelled.
    Cancelled(T),
}

/// Error when receiving from a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// Channel sender was dropped.
    Disconnected,
    /// Would block (channel empty).
    Empty,
    /// The receive operation was cancelled.
    Cancelled,
}

/// Error when acquiring a semaphore-like permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcquireError {
    /// Semaphore/permit source closed.
    Closed,
}

impl From<RecvError> for Error {
    fn from(e: RecvError) -> Self {
        match e {
            RecvError::Disconnected => Self::new(ErrorKind::ChannelClosed),
            RecvError::Empty => Self::new(ErrorKind::ChannelEmpty),
            RecvError::Cancelled => Self::new(ErrorKind::Cancelled),
        }
    }
}

impl<T> From<SendError<T>> for Error {
    fn from(e: SendError<T>) -> Self {
        match e {
            SendError::Disconnected(_) => Self::new(ErrorKind::ChannelClosed),
            SendError::Full(_) => Self::new(ErrorKind::ChannelFull),
            SendError::Cancelled(_) => Self::new(ErrorKind::Cancelled),
        }
    }
}

/// Extension trait for adding context to Results.
#[allow(clippy::result_large_err)]
pub trait ResultExt<T> {
    /// Attach a context message on error.
    fn context(self, msg: impl Into<String>) -> Result<T>;
    /// Attach context message computed lazily on error.
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E: Into<Error>> ResultExt<T> for core::result::Result<T, E> {
    fn context(self, msg: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.into().with_message(msg))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| e.into().with_message(f()))
    }
}

/// A specialized Result type for Asupersync operations.
#[allow(clippy::result_large_err)]
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[derive(Debug)]
    struct Underlying;

    impl fmt::Display for Underlying {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "underlying")
        }
    }

    impl std::error::Error for Underlying {}

    #[test]
    fn display_without_message() {
        let err = Error::new(ErrorKind::Internal);
        assert_eq!(err.to_string(), "Internal");
    }

    #[test]
    fn display_with_message() {
        let err = Error::new(ErrorKind::ChannelEmpty).with_message("no messages");
        assert_eq!(err.to_string(), "ChannelEmpty: no messages");
    }

    #[test]
    fn source_chain_is_exposed() {
        let err = Error::new(ErrorKind::User)
            .with_message("outer")
            .with_source(Underlying);
        let source = err.source().expect("source missing");
        assert_eq!(source.to_string(), "underlying");
    }

    #[test]
    fn from_recv_error() {
        let disconnected: Error = RecvError::Disconnected.into();
        assert_eq!(disconnected.kind(), ErrorKind::ChannelClosed);

        let empty: Error = RecvError::Empty.into();
        assert_eq!(empty.kind(), ErrorKind::ChannelEmpty);
    }

    #[test]
    fn from_send_error() {
        let disconnected: Error = SendError::Disconnected(()).into();
        assert_eq!(disconnected.kind(), ErrorKind::ChannelClosed);

        let full: Error = SendError::Full(()).into();
        assert_eq!(full.kind(), ErrorKind::ChannelFull);
    }

    #[test]
    fn result_ext_adds_message() {
        let res: core::result::Result<(), RecvError> = Err(RecvError::Empty);
        let err = res.context("recv failed").expect_err("expected err");
        assert_eq!(err.kind(), ErrorKind::ChannelEmpty);
        assert_eq!(err.to_string(), "ChannelEmpty: recv failed");
    }

    #[test]
    fn predicates_match_kind() {
        let cancel = Error::new(ErrorKind::Cancelled);
        assert!(cancel.is_cancelled());
        assert!(!cancel.is_timeout());

        let timeout = Error::new(ErrorKind::DeadlineExceeded);
        assert!(!timeout.is_cancelled());
        assert!(timeout.is_timeout());
    }

    #[test]
    fn recovery_action_backoff() {
        let action = ErrorKind::ThresholdTimeout.recovery_action();
        assert!(matches!(action, RecoveryAction::RetryWithBackoff(_)));
    }

    #[test]
    fn error_context_default() {
        let err = Error::new(ErrorKind::Internal);
        assert!(err.context().task_id.is_none());
    }

    #[test]
    fn error_with_full_context() {
        use crate::util::ArenaIndex;

        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(2, 0));
        let object_id = ObjectId::new_for_test(123);
        let symbol_id = SymbolId::new_for_test(123, 0, 1);

        let ctx = ErrorContext {
            task_id: Some(task_id),
            region_id: Some(region_id),
            object_id: Some(object_id),
            symbol_id: Some(symbol_id),
        };

        let err = Error::new(ErrorKind::Internal).with_context(ctx);

        assert_eq!(err.context().task_id, Some(task_id));
        assert_eq!(err.context().region_id, Some(region_id));
        assert_eq!(err.context().object_id, Some(object_id));
        assert_eq!(err.context().symbol_id, Some(symbol_id));
    }

    // ---- ErrorKind category exhaustive coverage ----

    #[test]
    fn error_kind_category_coverage() {
        use ErrorCategory::*;
        let cases: &[(ErrorKind, ErrorCategory)] = &[
            (ErrorKind::Cancelled, Cancellation),
            (ErrorKind::CancelTimeout, Cancellation),
            (ErrorKind::DeadlineExceeded, Budget),
            (ErrorKind::PollQuotaExhausted, Budget),
            (ErrorKind::CostQuotaExhausted, Budget),
            (ErrorKind::ChannelClosed, Channel),
            (ErrorKind::ChannelFull, Channel),
            (ErrorKind::ChannelEmpty, Channel),
            (ErrorKind::ObligationLeak, Obligation),
            (ErrorKind::ObligationAlreadyResolved, Obligation),
            (ErrorKind::RegionClosed, Region),
            (ErrorKind::TaskNotOwned, Region),
            (ErrorKind::AdmissionDenied, Region),
            (ErrorKind::InvalidEncodingParams, Encoding),
            (ErrorKind::DataTooLarge, Encoding),
            (ErrorKind::EncodingFailed, Encoding),
            (ErrorKind::CorruptedSymbol, Encoding),
            (ErrorKind::InsufficientSymbols, Decoding),
            (ErrorKind::DecodingFailed, Decoding),
            (ErrorKind::ObjectMismatch, Decoding),
            (ErrorKind::DuplicateSymbol, Decoding),
            (ErrorKind::ThresholdTimeout, Decoding),
            (ErrorKind::RoutingFailed, Transport),
            (ErrorKind::DispatchFailed, Transport),
            (ErrorKind::StreamEnded, Transport),
            (ErrorKind::SinkRejected, Transport),
            (ErrorKind::ConnectionLost, Transport),
            (ErrorKind::ConnectionRefused, Transport),
            (ErrorKind::ProtocolError, Transport),
            (ErrorKind::RecoveryFailed, Distributed),
            (ErrorKind::LeaseExpired, Distributed),
            (ErrorKind::LeaseRenewalFailed, Distributed),
            (ErrorKind::CoordinationFailed, Distributed),
            (ErrorKind::QuorumNotReached, Distributed),
            (ErrorKind::NodeUnavailable, Distributed),
            (ErrorKind::PartitionDetected, Distributed),
            (ErrorKind::Internal, Internal),
            (ErrorKind::InvalidStateTransition, Internal),
            (ErrorKind::ConfigError, User),
            (ErrorKind::User, User),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.category(), *expected, "{kind:?}");
        }
    }

    #[test]
    fn error_kind_recoverability_classification() {
        // Transient
        for kind in [
            ErrorKind::ChannelFull,
            ErrorKind::ChannelEmpty,
            ErrorKind::AdmissionDenied,
            ErrorKind::ConnectionLost,
            ErrorKind::NodeUnavailable,
            ErrorKind::QuorumNotReached,
            ErrorKind::ThresholdTimeout,
            ErrorKind::LeaseRenewalFailed,
        ] {
            assert_eq!(kind.recoverability(), Recoverability::Transient, "{kind:?}");
            assert!(kind.is_retryable(), "{kind:?} should be retryable");
        }

        // Permanent
        for kind in [
            ErrorKind::Cancelled,
            ErrorKind::ChannelClosed,
            ErrorKind::ObligationLeak,
            ErrorKind::Internal,
            ErrorKind::ConnectionRefused,
            ErrorKind::ConfigError,
        ] {
            assert_eq!(kind.recoverability(), Recoverability::Permanent, "{kind:?}");
            assert!(!kind.is_retryable(), "{kind:?} should not be retryable");
        }

        // Unknown
        for kind in [
            ErrorKind::DeadlineExceeded,
            ErrorKind::EncodingFailed,
            ErrorKind::CorruptedSymbol,
            ErrorKind::User,
        ] {
            assert_eq!(kind.recoverability(), Recoverability::Unknown, "{kind:?}");
            assert!(!kind.is_retryable(), "{kind:?} Unknown is not retryable");
        }
    }

    #[test]
    fn recoverability_predicates() {
        assert!(Recoverability::Transient.should_retry());
        assert!(!Recoverability::Transient.is_permanent());

        assert!(!Recoverability::Permanent.should_retry());
        assert!(Recoverability::Permanent.is_permanent());

        assert!(!Recoverability::Unknown.should_retry());
        assert!(!Recoverability::Unknown.is_permanent());
    }

    #[test]
    fn recovery_action_variants() {
        assert!(matches!(
            ErrorKind::ChannelFull.recovery_action(),
            RecoveryAction::RetryImmediately
        ));
        assert!(matches!(
            ErrorKind::AdmissionDenied.recovery_action(),
            RecoveryAction::RetryWithBackoff(_)
        ));
        assert!(matches!(
            ErrorKind::NodeUnavailable.recovery_action(),
            RecoveryAction::RetryWithBackoff(_)
        ));
        assert!(matches!(
            ErrorKind::ConnectionLost.recovery_action(),
            RecoveryAction::RetryWithNewConnection
        ));
        assert!(matches!(
            ErrorKind::Cancelled.recovery_action(),
            RecoveryAction::Propagate
        ));
        assert!(matches!(
            ErrorKind::ObligationLeak.recovery_action(),
            RecoveryAction::Escalate
        ));
        assert!(matches!(
            ErrorKind::User.recovery_action(),
            RecoveryAction::Custom
        ));
    }

    #[test]
    fn backoff_hint_constants() {
        let d = BackoffHint::DEFAULT;
        assert_eq!(d.initial_delay_ms, 100);
        assert_eq!(d.max_delay_ms, 30_000);
        assert_eq!(d.max_attempts, 5);

        let a = BackoffHint::AGGRESSIVE;
        assert!(a.initial_delay_ms > d.initial_delay_ms);
        assert!(a.max_attempts > d.max_attempts);

        let q = BackoffHint::QUICK;
        assert!(q.initial_delay_ms < d.initial_delay_ms);
        assert!(q.max_attempts < d.max_attempts);

        assert_eq!(BackoffHint::default(), BackoffHint::DEFAULT);
    }

    // ---- Error convenience constructors ----

    #[test]
    fn error_data_too_large() {
        let err = Error::data_too_large(2000, 1000);
        assert_eq!(err.kind(), ErrorKind::DataTooLarge);
        let msg = err.to_string();
        assert!(msg.contains("2000"), "{msg}");
        assert!(msg.contains("1000"), "{msg}");
    }

    #[test]
    fn error_insufficient_symbols() {
        let err = Error::insufficient_symbols(5, 10);
        assert_eq!(err.kind(), ErrorKind::InsufficientSymbols);
        let msg = err.to_string();
        assert!(msg.contains('5'), "{msg}");
        assert!(msg.contains("10"), "{msg}");
    }

    #[test]
    fn error_routing_failed() {
        let err = Error::routing_failed("node-7");
        assert_eq!(err.kind(), ErrorKind::RoutingFailed);
        assert!(err.to_string().contains("node-7"));
    }

    #[test]
    fn error_lease_expired() {
        let err = Error::lease_expired("lease-42");
        assert_eq!(err.kind(), ErrorKind::LeaseExpired);
        assert!(err.to_string().contains("lease-42"));
    }

    #[test]
    fn error_quorum_not_reached() {
        let err = Error::quorum_not_reached(2, 3);
        assert_eq!(err.kind(), ErrorKind::QuorumNotReached);
        let msg = err.to_string();
        assert!(msg.contains('2'), "{msg}");
        assert!(msg.contains('3'), "{msg}");
    }

    #[test]
    fn error_node_unavailable() {
        let err = Error::node_unavailable("node-1");
        assert_eq!(err.kind(), ErrorKind::NodeUnavailable);
        assert!(err.to_string().contains("node-1"));
    }

    #[test]
    fn error_internal() {
        let err = Error::internal("bug found");
        assert_eq!(err.kind(), ErrorKind::Internal);
        assert!(err.to_string().contains("bug found"));
    }

    // ---- Error predicates ----

    #[test]
    fn error_is_predicates() {
        assert!(Error::new(ErrorKind::EncodingFailed).is_encoding_error());
        assert!(!Error::new(ErrorKind::DecodingFailed).is_encoding_error());

        assert!(Error::new(ErrorKind::InsufficientSymbols).is_decoding_error());
        assert!(!Error::new(ErrorKind::EncodingFailed).is_decoding_error());

        assert!(Error::new(ErrorKind::RoutingFailed).is_transport_error());
        assert!(!Error::new(ErrorKind::Internal).is_transport_error());

        assert!(Error::new(ErrorKind::QuorumNotReached).is_distributed_error());
        assert!(!Error::new(ErrorKind::ChannelFull).is_distributed_error());

        assert!(Error::new(ErrorKind::ConnectionLost).is_connection_error());
        assert!(Error::new(ErrorKind::ConnectionRefused).is_connection_error());
        assert!(!Error::new(ErrorKind::RoutingFailed).is_connection_error());
    }

    #[test]
    fn error_cancel_timeout_is_timeout() {
        assert!(Error::new(ErrorKind::CancelTimeout).is_timeout());
        assert!(!Error::new(ErrorKind::CancelTimeout).is_cancelled());
    }

    // ---- Conversion tests ----

    #[test]
    fn recv_error_cancelled_conversion() {
        let err: Error = RecvError::Cancelled.into();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn send_error_cancelled_conversion() {
        let err: Error = SendError::Cancelled(42u32).into();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
    }

    #[test]
    fn cancelled_struct_into_error() {
        let reason = CancelReason::user("test cancel");
        let cancelled = Cancelled { reason };
        let err: Error = cancelled.into();
        assert_eq!(err.kind(), ErrorKind::Cancelled);
        assert!(err.to_string().contains("Cancelled"));
    }

    #[test]
    fn result_ext_with_context_lazy() {
        let res: core::result::Result<(), RecvError> = Err(RecvError::Empty);
        let err = res
            .with_context(|| format!("lazy {}", "context"))
            .expect_err("expected err");
        assert_eq!(err.kind(), ErrorKind::ChannelEmpty);
        assert!(err.to_string().contains("lazy context"));
    }

    // ---- Debug/Clone ----

    #[test]
    fn error_category_debug() {
        for cat in [
            ErrorCategory::Cancellation,
            ErrorCategory::Budget,
            ErrorCategory::Channel,
            ErrorCategory::Obligation,
            ErrorCategory::Region,
            ErrorCategory::Encoding,
            ErrorCategory::Decoding,
            ErrorCategory::Transport,
            ErrorCategory::Distributed,
            ErrorCategory::Internal,
            ErrorCategory::User,
        ] {
            let dbg = format!("{cat:?}");
            assert!(!dbg.is_empty());
        }
    }

    #[test]
    fn acquire_error_debug_eq() {
        let err = AcquireError::Closed;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Closed"), "{dbg}");
        assert_eq!(err, AcquireError::Closed);
    }

    #[test]
    fn error_clone() {
        let err = Error::new(ErrorKind::Internal).with_message("clone me");
        let cloned = err.clone();
        assert_eq!(cloned.kind(), ErrorKind::Internal);
        assert_eq!(cloned.to_string(), err.to_string());
    }

    #[test]
    fn error_no_message() {
        let err = Error::new(ErrorKind::User);
        assert!(err.message().is_none());
    }

    #[test]
    fn error_source_none_without_with_source() {
        let err = Error::new(ErrorKind::User);
        assert!(err.source().is_none());
    }

    // Pure data-type tests (wave 39 – CyanBarn)

    #[test]
    fn error_kind_copy_hash() {
        use std::collections::HashSet;
        let kind = ErrorKind::Internal;
        let copied = kind;
        assert_eq!(copied, ErrorKind::Internal);

        let mut set = HashSet::new();
        set.insert(ErrorKind::Cancelled);
        set.insert(ErrorKind::DeadlineExceeded);
        set.insert(ErrorKind::Cancelled); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn recoverability_copy_hash_eq() {
        use std::collections::HashSet;
        let r = Recoverability::Transient;
        let copied = r;
        assert_eq!(copied, Recoverability::Transient);
        assert_ne!(r, Recoverability::Permanent);

        let mut set = HashSet::new();
        set.insert(Recoverability::Transient);
        set.insert(Recoverability::Permanent);
        set.insert(Recoverability::Unknown);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn recovery_action_copy_hash() {
        use std::collections::HashSet;
        let action = RecoveryAction::Propagate;
        let copied = action;
        assert_eq!(copied, RecoveryAction::Propagate);

        let mut set = HashSet::new();
        set.insert(RecoveryAction::RetryImmediately);
        set.insert(RecoveryAction::Propagate);
        set.insert(RecoveryAction::Escalate);
        set.insert(RecoveryAction::Custom);
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn error_category_copy_clone_hash() {
        use std::collections::HashSet;
        let cat = ErrorCategory::Transport;
        let copied = cat;
        let cloned = cat;
        assert_eq!(copied, cloned);

        let mut set = HashSet::new();
        set.insert(ErrorCategory::Cancellation);
        set.insert(ErrorCategory::Budget);
        set.insert(ErrorCategory::Channel);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn backoff_hint_copy_hash_eq() {
        use std::collections::HashSet;
        let hint = BackoffHint::DEFAULT;
        let copied = hint;
        assert_eq!(copied, BackoffHint::DEFAULT);
        assert_ne!(hint, BackoffHint::AGGRESSIVE);

        let mut set = HashSet::new();
        set.insert(BackoffHint::DEFAULT);
        set.insert(BackoffHint::AGGRESSIVE);
        set.insert(BackoffHint::QUICK);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn recv_error_debug_clone_copy() {
        let err = RecvError::Disconnected;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Disconnected"));

        let copied = err;
        assert_eq!(copied, RecvError::Disconnected);

        let cloned = err;
        assert_eq!(cloned, err);
    }

    #[test]
    fn cancelled_clone_eq() {
        let c = Cancelled {
            reason: CancelReason::user("test"),
        };
        let dbg = format!("{c:?}");
        assert!(dbg.contains("Cancelled"));

        let cloned = c.clone();
        assert_eq!(cloned, c);
    }
}
