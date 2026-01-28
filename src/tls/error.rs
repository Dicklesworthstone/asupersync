//! TLS error types.

use std::fmt;
use std::io;

/// Error type for TLS operations.
#[derive(Debug)]
pub enum TlsError {
    /// Invalid DNS name for SNI.
    InvalidDnsName(String),
    /// TLS handshake failure.
    Handshake(String),
    /// Certificate error.
    Certificate(String),
    /// Configuration error.
    Configuration(String),
    /// I/O error during TLS operations.
    Io(io::Error),
    /// Rustls-specific error.
    #[cfg(feature = "tls")]
    Rustls(rustls::Error),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDnsName(name) => write!(f, "invalid DNS name: {name}"),
            Self::Handshake(msg) => write!(f, "TLS handshake failed: {msg}"),
            Self::Certificate(msg) => write!(f, "certificate error: {msg}"),
            Self::Configuration(msg) => write!(f, "TLS configuration error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            #[cfg(feature = "tls")]
            Self::Rustls(err) => write!(f, "rustls error: {err}"),
        }
    }
}

impl std::error::Error for TlsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            #[cfg(feature = "tls")]
            Self::Rustls(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for TlsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(feature = "tls")]
impl From<rustls::Error> for TlsError {
    fn from(err: rustls::Error) -> Self {
        Self::Rustls(err)
    }
}
