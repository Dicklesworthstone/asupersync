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
mod tests {
    use super::*;

    // =========================================================================
    // Pure data-type tests (wave 41 – CyanBarn)
    // =========================================================================

    #[test]
    fn stream_error_debug_display() {
        let closed = StreamError::Closed;
        assert!(format!("{closed:?}").contains("Closed"));
        assert_eq!(format!("{closed}"), "Connection closed");

        let done = StreamError::PolledAfterCompletion;
        assert_eq!(format!("{done}"), "stream future polled after completion");

        let reset = StreamError::Reset;
        assert_eq!(format!("{reset}"), "Connection reset");

        let timeout = StreamError::Timeout;
        assert_eq!(format!("{timeout}"), "Timeout waiting for symbol");

        let cancelled = StreamError::Cancelled;
        assert_eq!(format!("{cancelled}"), "Cancelled");

        let auth = StreamError::AuthenticationFailed {
            reason: "bad token".into(),
        };
        assert!(format!("{auth}").contains("bad token"));

        let proto = StreamError::ProtocolError {
            details: "invalid frame".into(),
        };
        assert!(format!("{proto}").contains("invalid frame"));
    }

    #[test]
    fn stream_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::BrokenPipe, "pipe broken");
        let stream_err: StreamError = io_err.into();
        assert!(format!("{stream_err}").contains("pipe broken"));
        assert!(matches!(stream_err, StreamError::Io { .. }));
    }

    #[test]
    fn sink_error_debug_display() {
        let closed = SinkError::Closed;
        assert!(format!("{closed:?}").contains("Closed"));
        assert_eq!(format!("{closed}"), "Connection closed");

        let done = SinkError::PolledAfterCompletion;
        assert_eq!(format!("{done}"), "sink future polled after completion");

        let full = SinkError::BufferFull;
        assert_eq!(format!("{full}"), "Buffer full");

        let cancelled = SinkError::Cancelled;
        assert_eq!(format!("{cancelled}"), "Cancelled");

        let send_failed = SinkError::SendFailed {
            reason: "queue overflow".into(),
        };
        assert!(format!("{send_failed}").contains("queue overflow"));
    }

    #[test]
    fn sink_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let sink_err: SinkError = io_err.into();
        assert!(format!("{sink_err}").contains("refused"));
        assert!(matches!(sink_err, SinkError::Io { .. }));
    }
}
