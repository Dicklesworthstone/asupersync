//! Transport layer errors.

use std::io;
use thiserror::Error;

/// Errors that can occur when receiving symbols from a stream.
#[derive(Debug, Error)]
pub enum StreamError {
    /// The connection was closed by the peer.
    #[error("Connection closed")]
    Closed,

    /// A stream helper future was polled again after it had already completed.
    #[error("stream future polled after completion")]
    PolledAfterCompletion,

    /// The connection was reset.
    #[error("Connection reset")]
    Reset,

    /// Timed out waiting for a symbol.
    #[error("Timeout waiting for symbol")]
    Timeout,

    /// Authentication failed for a symbol.
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed {
        /// The reason for authentication failure.
        reason: String,
    },

    /// Protocol violation or invalid data.
    #[error("Protocol error: {details}")]
    ProtocolError {
        /// Details about the protocol violation.
        details: String,
    },

    /// Underlying I/O error.
    #[error("I/O error: {source}")]
    Io {
        /// The source I/O error.
        #[from]
        source: io::Error,
    },

    /// Operation was cancelled.
    #[error("Cancelled")]
    Cancelled,
}

/// Errors that can occur when sending symbols to a sink.
#[derive(Debug, Error)]
pub enum SinkError {
    /// The connection was closed.
    #[error("Connection closed")]
    Closed,

    /// A sink helper future was polled again after it had already completed.
    #[error("sink future polled after completion")]
    PolledAfterCompletion,

    /// The internal buffer is full and cannot accept more items.
    #[error("Buffer full")]
    BufferFull,

    /// Failed to send the symbol.
    #[error("Send failed: {reason}")]
    SendFailed {
        /// The reason for the send failure.
        reason: String,
    },

    /// Underlying I/O error.
    #[error("I/O error: {source}")]
    Io {
        /// The source I/O error.
        #[from]
        source: io::Error,
    },

    /// Operation was cancelled.
    #[error("Cancelled")]
    Cancelled,
}

#[cfg(test)]
#[path = "error_inline_tests.rs"]
mod tests;
