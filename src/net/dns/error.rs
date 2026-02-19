//! DNS error types.
//!
//! This module defines errors that can occur during DNS resolution.

use std::fmt;
use std::io;

/// Error type for DNS operations.
#[derive(Debug, Clone)]
pub enum DnsError {
    /// No DNS records found for the host.
    NoRecords(String),
    /// DNS query timed out.
    Timeout,
    /// I/O error during DNS query.
    Io(String),
    /// Connection failed.
    Connection(String),
    /// Operation was cancelled.
    Cancelled,
    /// Invalid hostname.
    InvalidHost(String),
    /// DNS server returned an error.
    ServerError(String),
    /// Feature not implemented.
    NotImplemented(&'static str),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRecords(host) => write!(f, "no DNS records found for: {host}"),
            Self::Timeout => write!(f, "DNS query timed out"),
            Self::Io(msg) => write!(f, "DNS I/O error: {msg}"),
            Self::Connection(msg) => write!(f, "connection error: {msg}"),
            Self::Cancelled => write!(f, "DNS operation cancelled"),
            Self::InvalidHost(host) => write!(f, "invalid hostname: {host}"),
            Self::ServerError(msg) => write!(f, "DNS server error: {msg}"),
            Self::NotImplemented(feature) => write!(f, "not implemented: {feature}"),
        }
    }
}

impl std::error::Error for DnsError {}

impl From<io::Error> for DnsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // Wave 46 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn dns_error_debug_clone_display() {
        let errors: Vec<DnsError> = vec![
            DnsError::NoRecords("example.com".into()),
            DnsError::Timeout,
            DnsError::Io("broken pipe".into()),
            DnsError::Connection("refused".into()),
            DnsError::Cancelled,
            DnsError::InvalidHost("???".into()),
            DnsError::ServerError("SERVFAIL".into()),
            DnsError::NotImplemented("AAAA"),
        ];

        let expected_display = [
            "no DNS records found for: example.com",
            "DNS query timed out",
            "DNS I/O error: broken pipe",
            "connection error: refused",
            "DNS operation cancelled",
            "invalid hostname: ???",
            "DNS server error: SERVFAIL",
            "not implemented: AAAA",
        ];

        for (err, expected) in errors.iter().zip(expected_display.iter()) {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());
            let display = format!("{err}");
            assert_eq!(display, *expected);
            let cloned = err.clone();
            assert_eq!(format!("{cloned}"), display);
        }

        let e: &dyn std::error::Error = &errors[0];
        assert!(e.source().is_none());
    }

    #[test]
    fn dns_error_from_io() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionRefused, "test error");
        let dns_err: DnsError = io_err.into();
        let display = format!("{dns_err}");
        assert!(display.contains("DNS I/O error"), "{display}");
    }
}
