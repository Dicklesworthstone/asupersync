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

    /// Error reading from a stream.
    #[error("read error: {0}")]
    Read(#[from] quinn::ReadExactError),

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
        matches!(self, Self::StreamClosed | Self::Read(_) | Self::Write(_))
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
