//! Error types and error handling strategy for Asupersync.
//!
//! This module defines the core error types used throughout the runtime.
//! Error handling follows these principles:
//!
//! - Errors are explicit and typed (no stringly-typed errors)
//! - Errors compose well with the Outcome severity lattice
//! - Panics are isolated and converted to `Outcome::Panicked`

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

    // === Internal / state machine ===
    /// Internal runtime error (bug).
    Internal,
    /// Invalid state transition.
    InvalidStateTransition,

    // === User ===
    /// User-provided error.
    User,
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
}
