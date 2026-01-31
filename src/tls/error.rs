//! TLS error types.

use std::fmt;
use std::io;
use std::time::Duration;

/// Error type for TLS operations.
#[derive(Debug)]
pub enum TlsError {
    /// Invalid DNS name for SNI.
    InvalidDnsName(String),
    /// TLS handshake failure.
    Handshake(String),
    /// Certificate error (generic).
    Certificate(String),
    /// Certificate has expired.
    CertificateExpired {
        /// The time the certificate expired (Unix timestamp in seconds).
        expired_at: i64,
        /// Description of the certificate.
        description: String,
    },
    /// Certificate is not yet valid.
    CertificateNotYetValid {
        /// The time the certificate becomes valid (Unix timestamp in seconds).
        valid_from: i64,
        /// Description of the certificate.
        description: String,
    },
    /// Certificate chain validation failed.
    ChainValidation(String),
    /// Certificate pin mismatch.
    PinMismatch {
        /// Expected pin(s).
        expected: Vec<String>,
        /// Actual pin found.
        actual: String,
    },
    /// Configuration error.
    Configuration(String),
    /// I/O error during TLS operations.
    Io(io::Error),
    /// TLS operation timed out.
    Timeout(Duration),
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
            Self::CertificateExpired {
                expired_at,
                description,
            } => write!(f, "certificate expired at {expired_at}: {description}"),
            Self::CertificateNotYetValid {
                valid_from,
                description,
            } => write!(f, "certificate not valid until {valid_from}: {description}"),
            Self::ChainValidation(msg) => write!(f, "certificate chain validation failed: {msg}"),
            Self::PinMismatch { expected, actual } => write!(
                f,
                "certificate pin mismatch: expected one of {expected:?}, got {actual}"
            ),
            Self::Configuration(msg) => write!(f, "TLS configuration error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Timeout(duration) => write!(f, "TLS operation timed out after {duration:?}"),
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
