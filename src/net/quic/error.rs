//! QUIC error types.
//!
//! Provides error handling for QUIC endpoint and connection operations.

use thiserror::Error;

/// Error type for QUIC operations.
#[derive(Debug, Error)]
pub enum QuicError {
    /// Connection error from the QUIC implementation.
    #[error("connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),

    /// Error during connection establishment.
    #[error("connect error: {0}")]
    Connect(#[from] quinn::ConnectError),

    /// Error writing to a stream.
    #[error("write error: {0}")]
    Write(#[from] quinn::WriteError),

    /// Error reading from a stream (exact read).
    #[error("read error: {0}")]
    Read(#[from] quinn::ReadExactError),

    /// Error reading from a stream.
    #[error("read error: {0}")]
    ReadStream(#[from] quinn::ReadError),

    /// Stream read finished unexpectedly.
    #[error("read to end error: {0}")]
    ReadToEnd(#[from] quinn::ReadToEndError),

    /// Error sending datagram.
    #[error("datagram send error: {0}")]
    Datagram(#[from] quinn::SendDatagramError),

    /// Stream was closed.
    #[error("stream closed")]
    StreamClosed,

    /// Endpoint was closed.
    #[error("endpoint closed")]
    EndpointClosed,

    /// Operation was cancelled via Cx cancellation.
    #[error("cancelled")]
    Cancelled,

    /// TLS configuration error.
    #[error("TLS config error: {0}")]
    TlsConfig(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Invalid configuration.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// Stream opening failed.
    #[error("failed to open stream")]
    OpenStream,
}

impl QuicError {
    /// Check if this error represents a cancellation.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// Check if this error is recoverable (connection can continue).
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::StreamClosed
                | Self::Read(_)
                | Self::ReadStream(_)
                | Self::ReadToEnd(_)
                | Self::Write(_)
        )
    }

    /// Check if this is a connection-level error.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::Connection(_) | Self::EndpointClosed)
    }
}

impl From<quinn::ClosedStream> for QuicError {
    fn from(_: quinn::ClosedStream) -> Self {
        Self::StreamClosed
    }
}

impl From<crate::error::Error> for QuicError {
    fn from(err: crate::error::Error) -> Self {
        // If it's a cancellation error, convert to Cancelled
        if err.is_cancelled() {
            Self::Cancelled
        } else {
            // For other errors, wrap as I/O error
            Self::Io(std::io::Error::other(err.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;

    #[test]
    fn cancelled_is_cancelled() {
        let err = QuicError::Cancelled;
        assert!(err.is_cancelled());
        assert!(!err.is_recoverable());
        assert!(!err.is_connection_error());
    }

    #[test]
    fn stream_closed_is_recoverable() {
        let err = QuicError::StreamClosed;
        assert!(err.is_recoverable());
        assert!(!err.is_cancelled());
        assert!(!err.is_connection_error());
    }

    #[test]
    fn endpoint_closed_is_connection_error() {
        let err = QuicError::EndpointClosed;
        assert!(err.is_connection_error());
        assert!(!err.is_cancelled());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn open_stream_not_recoverable() {
        let err = QuicError::OpenStream;
        assert!(!err.is_recoverable());
        assert!(!err.is_cancelled());
        assert!(!err.is_connection_error());
    }

    #[test]
    fn tls_config_error() {
        let err = QuicError::TlsConfig("bad cert".to_string());
        assert!(!err.is_cancelled());
        assert!(!err.is_recoverable());
        assert!(!err.is_connection_error());
    }

    #[test]
    fn config_error() {
        let err = QuicError::Config("invalid".to_string());
        assert!(!err.is_cancelled());
        assert!(!err.is_recoverable());
    }

    #[test]
    fn display_cancelled() {
        let err = QuicError::Cancelled;
        assert_eq!(format!("{err}"), "cancelled");
    }

    #[test]
    fn display_stream_closed() {
        let err = QuicError::StreamClosed;
        assert_eq!(format!("{err}"), "stream closed");
    }

    #[test]
    fn display_endpoint_closed() {
        let err = QuicError::EndpointClosed;
        assert_eq!(format!("{err}"), "endpoint closed");
    }

    #[test]
    fn display_open_stream() {
        let err = QuicError::OpenStream;
        assert_eq!(format!("{err}"), "failed to open stream");
    }

    #[test]
    fn display_tls_config() {
        let err = QuicError::TlsConfig("missing cert".to_string());
        assert!(format!("{err}").contains("missing cert"));
    }

    #[test]
    fn display_config() {
        let err = QuicError::Config("bad value".to_string());
        assert!(format!("{err}").contains("bad value"));
    }

    #[test]
    fn display_io() {
        let err = QuicError::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "pipe broken",
        ));
        assert!(format!("{err}").contains("pipe broken"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = QuicError::Io(io_err);
        assert!(matches!(err, QuicError::Io(_)));
    }

    #[test]
    fn from_framework_cancel_error() {
        let reason = crate::types::cancel::CancelReason::shutdown();
        let err = crate::error::Error::cancelled(&reason);
        let quic_err = QuicError::from(err);
        assert!(quic_err.is_cancelled());
    }

    #[test]
    fn from_framework_non_cancel_error() {
        let err = crate::error::Error::new(crate::error::ErrorKind::RegionClosed);
        let quic_err = QuicError::from(err);
        assert!(matches!(quic_err, QuicError::Io(_)));
    }

    #[test]
    fn debug_format() {
        let err = QuicError::Cancelled;
        let debug = format!("{err:?}");
        assert!(debug.contains("Cancelled"));
    }
}
