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

use crate::types::CancelReason;

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
            Self::RegionClosed | Self::TaskNotOwned => ErrorCategory::Region,
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
            Self::User => ErrorCategory::User,
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
            | Self::ConnectionRefused => Recoverability::Permanent,

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
    /// This provides more specific guidance than [`recoverability()`]
    /// about how to handle the error.
    #[must_use]
    pub const fn recovery_action(&self) -> RecoveryAction {
        match self {
            // Immediate retry - brief transient states
            Self::ChannelFull | Self::ChannelEmpty => RecoveryAction::RetryImmediately,

            // Backoff retry - transient but may need time to clear
            Self::ThresholdTimeout | Self::QuorumNotReached | Self::LeaseRenewalFailed => {
                RecoveryAction::RetryWithBackoff(BackoffHint::DEFAULT)
            }
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
            | Self::PartitionDetected => RecoveryAction::Propagate,

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
    ///
    /// Examples: connection timeout, temporary resource exhaustion,
    /// transient network partition.
    Transient,

    /// Permanent failure that will not succeed on retry.
    ///
    /// Examples: invalid parameters, authentication failure,
    /// resource permanently gone.
    Permanent,

    /// Recoverability depends on context and cannot be determined
    /// from the error kind alone.
    ///
    /// The caller should examine the error context and source
    /// to make a retry decision.
    Unknown,
}

/// Recommended recovery action for an error.
///
/// This enum provides more specific guidance than [`Recoverability`]
/// about what steps to take when recovering from an error.
///
/// # Integration with Retry Combinator
///
/// The retry combinator uses this to determine whether and how to retry:
///
/// ```rust,ignore
/// match error.recovery_action() {
///     RecoveryAction::RetryImmediately => attempt_retry(ctx).await,
///     RecoveryAction::RetryWithBackoff(hint) => {
///         sleep(hint.initial_delay).await;
///         attempt_retry(ctx).await
///     }
///     RecoveryAction::RetryWithNewConnection => {
///         reconnect().await;
///         attempt_retry(ctx).await
///     }
///     RecoveryAction::Propagate => return Err(error),
///     RecoveryAction::Escalate => cx.request_cancel(CancelReason::fail_fast()).await,
///     RecoveryAction::Custom => { /* application-specific */ }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveryAction {
    /// Retry the operation immediately.
    ///
    /// Suitable for errors where the failure is expected to be
    /// very brief (e.g., channel momentarily full, brief lock contention).
    RetryImmediately,

    /// Retry the operation with exponential backoff.
    ///
    /// Suitable for transient failures that may take some time to clear
    /// (e.g., service temporarily unavailable, rate limiting).
    RetryWithBackoff(BackoffHint),

    /// Retry after establishing a new connection.
    ///
    /// Suitable for connection-related errors where the existing
    /// connection is likely corrupted or stale.
    RetryWithNewConnection,

    /// Propagate the error to the caller without retry.
    ///
    /// Suitable for permanent errors or errors that the current
    /// component cannot meaningfully handle.
    Propagate,

    /// Escalate by requesting cancellation of the current operation tree.
    ///
    /// Suitable for errors indicating a fundamental problem that
    /// should cancel related work (e.g., internal errors, invariant violations).
    Escalate,

    /// Recovery action depends on application-specific context.
    ///
    /// The error provides enough information for the application to
    /// decide, but no generic recovery strategy applies.
    Custom,
}

/// Hints for configuring exponential backoff.
///
/// These are suggestions; the actual backoff strategy is controlled
/// by the retry policy.
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
    /// Cancellation-related errors.
    Cancellation,
    /// Resource budget errors (deadlines, quotas).
    Budget,
    /// Channel communication errors.
    Channel,
    /// Linear obligation tracking errors.
    Obligation,
    /// Region ownership and lifecycle errors.
    Region,
    /// RaptorQ encoding pipeline errors.
    Encoding,
    /// RaptorQ decoding pipeline errors.
    Decoding,
    /// Symbol transport and routing errors.
    Transport,
    /// Distributed region coordination errors.
    Distributed,
    /// Internal runtime errors (bugs).
    Internal,
    /// User-defined errors.
    User,
}

impl fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Cancellation => "cancellation",
            Self::Budget => "budget",
            Self::Channel => "channel",
            Self::Obligation => "obligation",
            Self::Region => "region",
            Self::Encoding => "encoding",
            Self::Decoding => "decoding",
            Self::Transport => "transport",
            Self::Distributed => "distributed",
            Self::Internal => "internal",
            Self::User => "user",
        };
        write!(f, "{s}")
    }
}

/// The main error type for Asupersync operations.
#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    context: Option<String>,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl Error {
    /// Creates a new error with the given kind.
    #[must_use]
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            context: None,
            source: None,
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

    /// Adds deterministic context text to the error.
    #[must_use]
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = Some(ctx.into());
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
        Self::new(ErrorKind::Cancelled).with_context(format!("{reason}"))
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
        Self::new(ErrorKind::InvalidEncodingParams).with_context(detail)
    }

    /// Creates a data too large error.
    #[must_use]
    pub fn data_too_large(actual: u64, max: u64) -> Self {
        Self::new(ErrorKind::DataTooLarge)
            .with_context(format!("data size {actual} exceeds maximum {max}"))
    }

    /// Creates an insufficient symbols error for decoding.
    #[must_use]
    pub fn insufficient_symbols(received: u32, needed: u32) -> Self {
        Self::new(ErrorKind::InsufficientSymbols).with_context(format!(
            "received {received} symbols, need at least {needed}"
        ))
    }

    /// Creates a decoding failed error.
    #[must_use]
    pub fn decoding_failed(reason: impl Into<String>) -> Self {
        Self::new(ErrorKind::DecodingFailed).with_context(reason)
    }

    /// Creates a routing failed error.
    #[must_use]
    pub fn routing_failed(destination: impl Into<String>) -> Self {
        Self::new(ErrorKind::RoutingFailed)
            .with_context(format!("no route to destination: {}", destination.into()))
    }

    /// Creates a lease expired error.
    #[must_use]
    pub fn lease_expired(lease_id: impl Into<String>) -> Self {
        Self::new(ErrorKind::LeaseExpired)
            .with_context(format!("lease expired: {}", lease_id.into()))
    }

    /// Creates a quorum not reached error.
    #[must_use]
    pub fn quorum_not_reached(achieved: u32, needed: u32) -> Self {
        Self::new(ErrorKind::QuorumNotReached)
            .with_context(format!("achieved {achieved} of {needed} required"))
    }

    /// Creates a node unavailable error.
    #[must_use]
    pub fn node_unavailable(node_id: impl Into<String>) -> Self {
        Self::new(ErrorKind::NodeUnavailable)
            .with_context(format!("node unavailable: {}", node_id.into()))
    }

    /// Creates an internal error (runtime bug).
    #[must_use]
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal).with_context(detail)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.kind)?;
        if let Some(ctx) = &self.context {
            write!(f, ": {ctx}")?;
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
}

/// Error when receiving from a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// Channel sender was dropped.
    Disconnected,
    /// Would block (channel empty).
    Empty,
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
        }
    }
}

impl<T> From<SendError<T>> for Error {
    fn from(e: SendError<T>) -> Self {
        match e {
            SendError::Disconnected(_) => Self::new(ErrorKind::ChannelClosed),
            SendError::Full(_) => Self::new(ErrorKind::ChannelFull),
        }
    }
}

/// Extension trait for adding context to Results.
pub trait ResultExt<T> {
    /// Attach a context string on error.
    fn context(self, ctx: impl Into<String>) -> Result<T>;
    /// Attach context computed lazily on error.
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}

impl<T, E: Into<Error>> ResultExt<T> for core::result::Result<T, E> {
    fn context(self, ctx: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.into().with_context(ctx))
    }

    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| e.into().with_context(f()))
    }
}

/// A specialized Result type for Asupersync operations.
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
    fn display_without_context() {
        let err = Error::new(ErrorKind::Internal);
        assert_eq!(err.to_string(), "Internal");
    }

    #[test]
    fn display_with_context() {
        let err = Error::new(ErrorKind::ChannelEmpty).with_context("no messages");
        assert_eq!(err.to_string(), "ChannelEmpty: no messages");
    }

    #[test]
    fn source_chain_is_exposed() {
        let err = Error::new(ErrorKind::User)
            .with_context("outer")
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
    fn result_ext_adds_context() {
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
    fn error_categories_are_correct() {
        assert_eq!(ErrorKind::Cancelled.category(), ErrorCategory::Cancellation);
        assert_eq!(
            ErrorKind::DeadlineExceeded.category(),
            ErrorCategory::Budget
        );
        assert_eq!(ErrorKind::ChannelFull.category(), ErrorCategory::Channel);
        assert_eq!(
            ErrorKind::ObligationLeak.category(),
            ErrorCategory::Obligation
        );
        assert_eq!(ErrorKind::RegionClosed.category(), ErrorCategory::Region);
        assert_eq!(
            ErrorKind::InvalidEncodingParams.category(),
            ErrorCategory::Encoding
        );
        assert_eq!(
            ErrorKind::InsufficientSymbols.category(),
            ErrorCategory::Decoding
        );
        assert_eq!(
            ErrorKind::RoutingFailed.category(),
            ErrorCategory::Transport
        );
        assert_eq!(
            ErrorKind::LeaseExpired.category(),
            ErrorCategory::Distributed
        );
        assert_eq!(ErrorKind::Internal.category(), ErrorCategory::Internal);
        assert_eq!(ErrorKind::User.category(), ErrorCategory::User);
    }

    #[test]
    fn recoverability_classification() {
        // Transient errors are retryable
        assert_eq!(
            ErrorKind::ChannelFull.recoverability(),
            Recoverability::Transient
        );
        assert!(ErrorKind::ChannelFull.is_retryable());
        assert!(ErrorKind::ConnectionLost.is_retryable());
        assert!(ErrorKind::NodeUnavailable.is_retryable());
        assert!(ErrorKind::QuorumNotReached.is_retryable());

        // Permanent errors are not retryable
        assert_eq!(
            ErrorKind::Cancelled.recoverability(),
            Recoverability::Permanent
        );
        assert!(!ErrorKind::Cancelled.is_retryable());
        assert!(!ErrorKind::InvalidEncodingParams.is_retryable());
        assert!(!ErrorKind::ProtocolError.is_retryable());

        // Unknown recoverability errors
        assert_eq!(
            ErrorKind::DecodingFailed.recoverability(),
            Recoverability::Unknown
        );
    }

    #[test]
    fn recoverability_methods() {
        assert!(Recoverability::Transient.should_retry());
        assert!(!Recoverability::Transient.is_permanent());

        assert!(!Recoverability::Permanent.should_retry());
        assert!(Recoverability::Permanent.is_permanent());

        assert!(!Recoverability::Unknown.should_retry());
        assert!(!Recoverability::Unknown.is_permanent());
    }

    #[test]
    fn error_category_predicates() {
        let encoding_err = Error::new(ErrorKind::EncodingFailed);
        assert!(encoding_err.is_encoding_error());
        assert!(!encoding_err.is_decoding_error());

        let decoding_err = Error::new(ErrorKind::InsufficientSymbols);
        assert!(decoding_err.is_decoding_error());
        assert!(!decoding_err.is_encoding_error());

        let transport_err = Error::new(ErrorKind::ConnectionLost);
        assert!(transport_err.is_transport_error());
        assert!(transport_err.is_connection_error());

        let distributed_err = Error::new(ErrorKind::LeaseExpired);
        assert!(distributed_err.is_distributed_error());
    }

    #[test]
    fn specialized_constructors() {
        let err = Error::data_too_large(1000, 500);
        assert_eq!(err.kind(), ErrorKind::DataTooLarge);
        assert!(err.to_string().contains("1000"));
        assert!(err.to_string().contains("500"));

        let err = Error::insufficient_symbols(5, 10);
        assert_eq!(err.kind(), ErrorKind::InsufficientSymbols);
        assert!(err.to_string().contains('5'));
        assert!(err.to_string().contains("10"));

        let err = Error::routing_failed("node-42");
        assert_eq!(err.kind(), ErrorKind::RoutingFailed);
        assert!(err.to_string().contains("node-42"));

        let err = Error::quorum_not_reached(2, 3);
        assert_eq!(err.kind(), ErrorKind::QuorumNotReached);
        assert!(err.to_string().contains('2'));
        assert!(err.to_string().contains('3'));

        let err = Error::node_unavailable("peer-1");
        assert_eq!(err.kind(), ErrorKind::NodeUnavailable);
        assert!(err.to_string().contains("peer-1"));

        let err = Error::internal("unexpected state");
        assert_eq!(err.kind(), ErrorKind::Internal);
        assert!(err.to_string().contains("unexpected state"));
    }

    #[test]
    fn error_category_display() {
        assert_eq!(format!("{}", ErrorCategory::Encoding), "encoding");
        assert_eq!(format!("{}", ErrorCategory::Decoding), "decoding");
        assert_eq!(format!("{}", ErrorCategory::Transport), "transport");
        assert_eq!(format!("{}", ErrorCategory::Distributed), "distributed");
    }

    #[test]
    fn all_error_kinds_have_category() {
        // Test that every ErrorKind variant maps to a category
        let kinds = [
            ErrorKind::Cancelled,
            ErrorKind::CancelTimeout,
            ErrorKind::DeadlineExceeded,
            ErrorKind::PollQuotaExhausted,
            ErrorKind::CostQuotaExhausted,
            ErrorKind::ChannelClosed,
            ErrorKind::ChannelFull,
            ErrorKind::ChannelEmpty,
            ErrorKind::ObligationLeak,
            ErrorKind::ObligationAlreadyResolved,
            ErrorKind::RegionClosed,
            ErrorKind::TaskNotOwned,
            ErrorKind::InvalidEncodingParams,
            ErrorKind::DataTooLarge,
            ErrorKind::EncodingFailed,
            ErrorKind::CorruptedSymbol,
            ErrorKind::InsufficientSymbols,
            ErrorKind::DecodingFailed,
            ErrorKind::ObjectMismatch,
            ErrorKind::DuplicateSymbol,
            ErrorKind::ThresholdTimeout,
            ErrorKind::RoutingFailed,
            ErrorKind::DispatchFailed,
            ErrorKind::StreamEnded,
            ErrorKind::SinkRejected,
            ErrorKind::ConnectionLost,
            ErrorKind::ConnectionRefused,
            ErrorKind::ProtocolError,
            ErrorKind::RecoveryFailed,
            ErrorKind::LeaseExpired,
            ErrorKind::LeaseRenewalFailed,
            ErrorKind::CoordinationFailed,
            ErrorKind::QuorumNotReached,
            ErrorKind::NodeUnavailable,
            ErrorKind::PartitionDetected,
            ErrorKind::Internal,
            ErrorKind::InvalidStateTransition,
            ErrorKind::User,
        ];

        for kind in kinds {
            // Should not panic - category is defined for all variants
            let _ = kind.category();
            let _ = kind.recoverability();
            let _ = kind.recovery_action();
        }
    }

    #[test]
    fn recovery_action_immediate_retry() {
        assert_eq!(
            ErrorKind::ChannelFull.recovery_action(),
            RecoveryAction::RetryImmediately
        );
        assert_eq!(
            ErrorKind::ChannelEmpty.recovery_action(),
            RecoveryAction::RetryImmediately
        );
    }

    #[test]
    fn recovery_action_backoff() {
        let action = ErrorKind::ThresholdTimeout.recovery_action();
        assert!(matches!(action, RecoveryAction::RetryWithBackoff(_)));

        let action = ErrorKind::NodeUnavailable.recovery_action();
        if let RecoveryAction::RetryWithBackoff(hint) = action {
            assert_eq!(hint, BackoffHint::AGGRESSIVE);
        } else {
            panic!("Expected RetryWithBackoff for NodeUnavailable");
        }
    }

    #[test]
    fn recovery_action_reconnect() {
        assert_eq!(
            ErrorKind::ConnectionLost.recovery_action(),
            RecoveryAction::RetryWithNewConnection
        );
        assert_eq!(
            ErrorKind::StreamEnded.recovery_action(),
            RecoveryAction::RetryWithNewConnection
        );
    }

    #[test]
    fn recovery_action_propagate() {
        assert_eq!(
            ErrorKind::Cancelled.recovery_action(),
            RecoveryAction::Propagate
        );
        assert_eq!(
            ErrorKind::DeadlineExceeded.recovery_action(),
            RecoveryAction::Propagate
        );
        assert_eq!(
            ErrorKind::InvalidEncodingParams.recovery_action(),
            RecoveryAction::Propagate
        );
    }

    #[test]
    fn recovery_action_escalate() {
        assert_eq!(
            ErrorKind::ObligationLeak.recovery_action(),
            RecoveryAction::Escalate
        );
        assert_eq!(
            ErrorKind::Internal.recovery_action(),
            RecoveryAction::Escalate
        );
        assert_eq!(
            ErrorKind::InvalidStateTransition.recovery_action(),
            RecoveryAction::Escalate
        );
    }

    #[test]
    fn recovery_action_custom() {
        assert_eq!(
            ErrorKind::User.recovery_action(),
            RecoveryAction::Custom
        );
        assert_eq!(
            ErrorKind::DecodingFailed.recovery_action(),
            RecoveryAction::Custom
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)] // Testing const values is intentional
    fn backoff_hint_presets() {
        assert!(BackoffHint::DEFAULT.initial_delay_ms > 0);
        assert!(BackoffHint::AGGRESSIVE.initial_delay_ms > BackoffHint::DEFAULT.initial_delay_ms);
        assert!(BackoffHint::QUICK.initial_delay_ms < BackoffHint::DEFAULT.initial_delay_ms);

        // Default impl works
        let hint: BackoffHint = Default::default();
        assert_eq!(hint, BackoffHint::DEFAULT);
    }

    #[test]
    fn error_recovery_action_delegates() {
        let err = Error::new(ErrorKind::ConnectionLost);
        assert_eq!(err.recovery_action(), RecoveryAction::RetryWithNewConnection);

        let err = Error::new(ErrorKind::Internal);
        assert_eq!(err.recovery_action(), RecoveryAction::Escalate);
    }
}
