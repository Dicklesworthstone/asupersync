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
use std::sync::atomic::{AtomicU64, Ordering};

use crate::observability::SpanId;
use crate::sync::LockError;
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
    /// Tried to resolve an obligation after its region was finalized.
    RegionFinalized,

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
    /// Request rate limited by the remote endpoint.
    RateLimited,
    /// Invalid input provided to operation.
    InvalidInput,
    /// Operation failed to complete successfully.
    OperationFailed,

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
    /// Returns the stable ASUP error code for user-facing diagnostics.
    #[must_use]
    #[inline]
    pub const fn asup_code(&self) -> Option<&'static str> {
        match self {
            Self::ObligationLeak => Some("ASUP-E101"),
            Self::ObligationAlreadyResolved => Some("ASUP-E102"),
            Self::RegionClosed => Some("ASUP-E003"),
            Self::AdmissionDenied => Some("ASUP-E006"),
            Self::ChannelClosed => Some("ASUP-E201"),
            Self::CancelTimeout => Some("ASUP-E301"),
            Self::ConfigError => Some("ASUP-E901"),
            _ => None,
        }
    }

    /// Returns the error category for this kind.
    #[must_use]
    #[inline]
    pub const fn category(&self) -> ErrorCategory {
        match self {
            Self::Cancelled | Self::CancelTimeout => ErrorCategory::Cancellation,
            Self::DeadlineExceeded | Self::PollQuotaExhausted | Self::CostQuotaExhausted => {
                ErrorCategory::Budget
            }
            Self::ChannelClosed | Self::ChannelFull | Self::ChannelEmpty => ErrorCategory::Channel,
            Self::ObligationLeak | Self::ObligationAlreadyResolved | Self::RegionFinalized => {
                ErrorCategory::Obligation
            }
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
            | Self::ProtocolError
            | Self::RateLimited
            | Self::InvalidInput
            | Self::OperationFailed => ErrorCategory::Transport,
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
    #[inline]
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
            | Self::LeaseRenewalFailed
            | Self::RateLimited => Recoverability::Transient,

            // Permanent errors - do not retry
            Self::Cancelled
            | Self::CancelTimeout
            | Self::ChannelClosed
            | Self::ObligationLeak
            | Self::ObligationAlreadyResolved
            | Self::RegionFinalized
            | Self::RegionClosed
            | Self::InvalidEncodingParams
            | Self::DataTooLarge
            | Self::ObjectMismatch
            | Self::Internal
            | Self::InvalidStateTransition
            | Self::ProtocolError
            | Self::ConnectionRefused
            | Self::ConfigError
            | Self::InvalidInput => Recoverability::Permanent,

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
            | Self::OperationFailed
            | Self::User => Recoverability::Unknown,
        }
    }

    /// Returns true if this error is typically retryable.
    #[must_use]
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        matches!(self.recoverability(), Recoverability::Transient)
    }

    /// Returns the recommended recovery action for this error kind.
    ///
    /// This provides more specific guidance than [`recoverability()`](Self::recoverability)
    /// about how to handle the error.
    #[must_use]
    #[inline]
    pub const fn recovery_action(&self) -> RecoveryAction {
        match self {
            // Immediate retry - brief transient states
            Self::ChannelFull | Self::ChannelEmpty => RecoveryAction::RetryImmediately,

            // Backoff retry - transient but may need time to clear
            Self::AdmissionDenied
            | Self::ThresholdTimeout
            | Self::QuorumNotReached
            | Self::LeaseRenewalFailed
            | Self::RateLimited => RecoveryAction::RetryWithBackoff(BackoffHint::DEFAULT),
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
            | Self::ConfigError
            | Self::InvalidInput
            | Self::OperationFailed => RecoveryAction::Propagate,

            // Escalate - serious problem, should cancel related work
            Self::ObligationLeak
            | Self::ObligationAlreadyResolved
            | Self::RegionFinalized
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
    #[inline]
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl Recoverability {
    /// Returns true if this error is safe to retry.
    #[must_use]
    #[inline]
    pub const fn should_retry(&self) -> bool {
        matches!(self, Self::Transient)
    }

    /// Returns true if this error should never be retried.
    #[must_use]
    #[inline]
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
    /// Correlation ID for tracing error propagation across async boundaries.
    pub correlation_id: Option<u64>,
    /// Parent correlation IDs forming a causal chain.
    pub causal_chain: Vec<u64>,
    /// Span ID from the current tracing context.
    pub span_id: Option<crate::observability::SpanId>,
    /// Parent span ID for building async stack traces.
    pub parent_span_id: Option<crate::observability::SpanId>,
    /// Async stack trace showing error propagation path.
    pub async_stack: Vec<String>,
}

impl ErrorContext {
    /// Creates a new error context with automatic correlation ID generation.
    #[must_use]
    pub fn new() -> Self {
        static NEXT_CORRELATION_ID: AtomicU64 = AtomicU64::new(1);
        Self {
            correlation_id: Some(NEXT_CORRELATION_ID.fetch_add(1, Ordering::Relaxed)),
            ..Self::default()
        }
    }

    /// Creates an error context from the current Cx diagnostic context.
    #[must_use]
    pub fn from_diagnostic_context(ctx: &crate::observability::DiagnosticContext) -> Self {
        let mut error_ctx = Self::new();
        error_ctx.task_id = ctx.task_id();
        error_ctx.region_id = ctx.region_id();
        error_ctx.span_id = ctx.span_id();
        error_ctx.parent_span_id = ctx.parent_span_id();
        error_ctx
    }

    /// Derives a child error context preserving causal chain.
    #[must_use]
    pub fn derive_child(&self, operation: &str) -> Self {
        static NEXT_CORRELATION_ID: AtomicU64 = AtomicU64::new(1);
        let child_correlation_id = NEXT_CORRELATION_ID.fetch_add(1, Ordering::Relaxed);

        let mut causal_chain = self.causal_chain.clone();
        if let Some(parent_id) = self.correlation_id {
            causal_chain.push(parent_id);
        }

        let mut async_stack = self.async_stack.clone();
        async_stack.push(operation.to_string());

        Self {
            task_id: self.task_id,
            region_id: self.region_id,
            object_id: self.object_id,
            symbol_id: self.symbol_id,
            correlation_id: Some(child_correlation_id),
            causal_chain,
            span_id: Some(SpanId::new()), // New span for child operation
            parent_span_id: self.span_id,
            async_stack,
        }
    }

    /// Adds an operation to the async stack trace.
    #[must_use]
    pub fn with_operation(mut self, operation: &str) -> Self {
        self.async_stack.push(operation.to_string());
        self
    }

    /// Sets the span context from current tracing.
    #[must_use]
    pub fn with_span_context(mut self, span_id: SpanId, parent_span_id: Option<SpanId>) -> Self {
        self.span_id = Some(span_id);
        self.parent_span_id = parent_span_id;
        self
    }

    /// Returns the root correlation ID from the causal chain.
    #[must_use]
    pub fn root_correlation_id(&self) -> Option<u64> {
        self.causal_chain.first().copied().or(self.correlation_id)
    }

    /// Returns the full causal chain including current correlation ID.
    #[must_use]
    pub fn full_causal_chain(&self) -> Vec<u64> {
        let mut chain = self.causal_chain.clone();
        if let Some(id) = self.correlation_id {
            chain.push(id);
        }
        chain
    }

    /// Returns a human-readable async stack trace.
    #[must_use]
    pub fn format_async_stack(&self) -> String {
        if self.async_stack.is_empty() {
            "<no stack trace>".to_string()
        } else {
            self.async_stack.join(" -> ")
        }
    }
}

/// The main error type for Asupersync operations.
#[derive(Debug, Clone)]
pub struct Error {
    kind: ErrorKind,
    message: Option<String>,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
    context: ErrorContext,
    cancel_reason: Option<Box<CancelReason>>,
}

impl Error {
    /// Creates a new error with the given kind.
    #[must_use]
    #[inline]
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            message: None,
            source: None,
            context: ErrorContext::new(),
            cancel_reason: None,
        }
    }

    /// Returns the error kind.
    #[must_use]
    #[inline]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns true if this error represents cancellation.
    #[must_use]
    #[inline]
    pub const fn is_cancelled(&self) -> bool {
        matches!(self.kind, ErrorKind::Cancelled)
    }

    /// Returns true if this error is a timeout/deadline condition.
    #[must_use]
    #[inline]
    pub const fn is_timeout(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::DeadlineExceeded | ErrorKind::CancelTimeout
        )
    }

    /// Adds a message description to the error.
    #[must_use]
    #[inline]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    /// Adds structured context to the error.
    #[must_use]
    #[inline]
    pub fn with_context(mut self, ctx: ErrorContext) -> Self {
        self.context = ctx;
        self
    }

    /// Adds a source error to the chain.
    #[must_use]
    #[inline]
    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Arc::new(source));
        self
    }

    /// Creates an error with context derived from current Cx.
    #[must_use]
    pub fn from_cx(kind: ErrorKind, cx: &crate::cx::Cx) -> Self {
        let diag_ctx = cx.diagnostic_context();
        let error_ctx = ErrorContext::from_diagnostic_context(&diag_ctx)
            .with_operation(&format!("Error::{:?}", kind));

        Self::new(kind).with_context(error_ctx)
    }

    /// Propagates an error across an async boundary, preserving causal chain.
    #[must_use]
    pub fn propagate_across_async(mut self, operation: &str) -> Self {
        self.context = self.context.derive_child(operation);
        self
    }

    /// Adds an operation to the error's async stack trace.
    #[must_use]
    pub fn with_operation(mut self, operation: &str) -> Self {
        self.context = self.context.with_operation(operation);
        self
    }

    /// Returns the correlation ID for tracing this error.
    #[must_use]
    #[inline]
    pub fn correlation_id(&self) -> Option<u64> {
        self.context.correlation_id
    }

    /// Returns the root cause correlation ID.
    #[must_use]
    #[inline]
    pub fn root_correlation_id(&self) -> Option<u64> {
        self.context.root_correlation_id()
    }

    /// Returns the full causal chain for root cause analysis.
    #[must_use]
    #[inline]
    pub fn causal_chain(&self) -> Vec<u64> {
        self.context.full_causal_chain()
    }

    /// Returns a formatted async stack trace.
    #[must_use]
    #[inline]
    pub fn async_stack(&self) -> String {
        self.context.format_async_stack()
    }

    /// Creates a cancellation error from a structured reason.
    ///
    /// The reason is kept whole: [`Error::cancel_reason`] returns it.
    #[must_use]
    #[inline]
    pub fn cancelled(reason: &CancelReason) -> Self {
        Self::new(ErrorKind::Cancelled)
            .with_message(reason.to_string())
            .with_cancel_reason(reason.clone())
    }

    /// Attaches the structured reason for a cancellation, without changing
    /// the error's kind, message or `Display` text.
    #[must_use]
    #[inline]
    pub fn with_cancel_reason(mut self, reason: CancelReason) -> Self {
        self.cancel_reason = Some(Box::new(reason));
        self
    }

    /// [`Error::with_cancel_reason`] for a reason that may be absent.
    #[must_use]
    pub(crate) fn with_cancel_reason_from(mut self, reason: Option<&CancelReason>) -> Self {
        if let Some(reason) = reason {
            self.cancel_reason = Some(Box::new(reason.clone()));
        }
        self
    }

    /// Returns the structured cancellation reason this error carries: its
    /// kind, origin and cause chain.
    ///
    /// [`Cx::checkpoint`](crate::cx::Cx::checkpoint) and
    /// [`Error::cancelled`] attach it. This keeps the reason available to
    /// whoever receives the error, after the task's `Cx` is gone. A task that
    /// returns `cx.checkpoint()?`'s error joins as `Ok(Err(error))`, and this
    /// accessor recovers why it was cancelled. Returns `None` for other errors,
    /// and for cancellation errors built without a reason.
    #[must_use]
    #[inline]
    pub fn cancel_reason(&self) -> Option<&CancelReason> {
        self.cancel_reason.as_deref()
    }

    /// Returns the error category.
    #[must_use]
    #[inline]
    pub const fn category(&self) -> ErrorCategory {
        self.kind.category()
    }

    /// Returns the recoverability classification.
    #[must_use]
    #[inline]
    pub const fn recoverability(&self) -> Recoverability {
        self.kind.recoverability()
    }

    /// Returns true if this error is typically retryable.
    #[must_use]
    #[inline]
    pub const fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }

    /// Returns the recommended recovery action for this error.
    #[must_use]
    #[inline]
    pub const fn recovery_action(&self) -> RecoveryAction {
        self.kind.recovery_action()
    }

    /// Returns the error message, if any.
    #[must_use]
    #[inline]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Returns the error context.
    #[must_use]
    #[inline]
    pub fn context(&self) -> &ErrorContext {
        &self.context
    }

    /// Returns true if this is an encoding-related error.
    #[must_use]
    #[inline]
    pub const fn is_encoding_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Encoding)
    }

    /// Returns true if this is a decoding-related error.
    #[must_use]
    #[inline]
    pub const fn is_decoding_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Decoding)
    }

    /// Returns true if this is a transport-related error.
    #[must_use]
    #[inline]
    pub const fn is_transport_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Transport)
    }

    /// Returns true if this is a distributed coordination error.
    #[must_use]
    #[inline]
    pub const fn is_distributed_error(&self) -> bool {
        matches!(self.kind.category(), ErrorCategory::Distributed)
    }

    /// Returns true if this is a connection-related error.
    #[must_use]
    #[inline]
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
        if let Some(code) = self.kind.asup_code() {
            write!(f, "[{code}] ")?;
        }
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

impl From<LockError> for Error {
    fn from(e: LockError) -> Self {
        match e {
            LockError::Poisoned => Self::new(ErrorKind::InvalidStateTransition),
            LockError::Cancelled => Self::new(ErrorKind::Cancelled),
            LockError::TimedOut(_) => Self::new(ErrorKind::ThresholdTimeout),
            LockError::PolledAfterCompletion => Self::new(ErrorKind::InvalidStateTransition),
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
#[path = "error_inline_tests.rs"]
mod tests;
