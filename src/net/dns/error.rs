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
    /// DNS lookup or connect operation timed out.
    Timeout,
    /// I/O error during DNS query.
    Io(String),
    /// DNS packet framing or parsing error.
    Protocol(String),
    /// Connection failed.
    Connection(String),
    /// Operation was cancelled.
    Cancelled,
    /// Invalid hostname.
    InvalidHost(String),
    /// DNS server returned an error.
    ServerError(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRecords(host) => write!(f, "no DNS records found for: {host}"),
            Self::Timeout => write!(f, "DNS operation timed out"),
            Self::Io(msg) => write!(f, "DNS I/O error: {msg}"),
            Self::Protocol(msg) => write!(f, "DNS protocol error: {msg}"),
            Self::Connection(msg) => write!(f, "connection error: {msg}"),
            Self::Cancelled => write!(f, "DNS operation cancelled"),
            Self::InvalidHost(host) => write!(f, "invalid hostname: {host}"),
            Self::ServerError(msg) => write!(f, "DNS server error: {msg}"),
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
#[path = "error_inline_tests.rs"]
mod tests;
