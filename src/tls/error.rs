//! TLS error types with security-hardened display formatting.
//!
//! This module provides comprehensive error types for TLS operations in the
//! asupersync runtime, with special attention to preventing log injection attacks
//! and information disclosure through error messages.
//!
//! # Security Design
//!
//! - **Log injection prevention**: Peer-controlled strings are sanitized before logging
//! - **Amplification protection**: Error messages are length-limited to prevent DoS
//! - **Information hiding**: Internal details are not exposed in error displays
//! - **Structured errors**: Errors are properly typed for programmatic handling
//!
//! # Error Categories
//!
//! - **Connection errors**: Handshake failures, protocol violations
//! - **Certificate errors**: Validation, parsing, and chain building failures
//! - **Configuration errors**: Invalid TLS settings or feature mismatches
//! - **I/O errors**: Network layer failures with TLS context

use std::fmt;
use std::io;
use std::time::Duration;

/// Maximum bytes a sanitized peer-controlled string may contribute to
/// a TLS error display. Larger strings are truncated with an ellipsis.
///
/// Defends against log-amplification (a peer could return a multi-KB
/// rustls error, which would explode log volume per failed handshake).
const MAX_SANITIZED_LEN: usize = 256;

/// Strip CR, LF, tab, NUL, and other ASCII control characters from a
/// peer-controlled string before rendering it to the log path.
///
/// br-asupersync-kxw8nx: rustls error strings, peer-supplied SNI values,
/// peer certificate subjects, etc. all flow through Display and end up
/// in structured logs. An attacker who controls these strings can inject
/// embedded `\n` to splice forged log lines (log injection / forgery).
///
/// Sanitization rules:
///   * `\r`, `\n`, `\t` → ASCII space (preserves field separation,
///     prevents line splitting)
///   * Any other ASCII control char (0x00..=0x1F, 0x7F) → replaced with
///     `?` (visible-but-not-special replacement marker)
///   * UTF-8 truncation at MAX_SANITIZED_LEN bytes, cut on a char
///     boundary to avoid invalid UTF-8 in the output, with `…` suffix
///     on truncation
fn sanitize_for_log(input: &str) -> String {
    let mut out = String::with_capacity(input.len().min(MAX_SANITIZED_LEN + 3));
    let mut byte_count = 0usize;
    let mut truncated = false;
    for ch in input.chars() {
        let mapped = match ch {
            '\r' | '\n' | '\t' => ' ',
            // ASCII control chars (excluding the three above already handled)
            c if (c as u32) < 0x20 || c == '\u{7f}' => '?',
            c => c,
        };
        let mapped_len = mapped.len_utf8();
        if byte_count + mapped_len > MAX_SANITIZED_LEN {
            truncated = true;
            break;
        }
        out.push(mapped);
        byte_count += mapped_len;
    }
    if truncated {
        out.push('…');
    }
    out
}

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
    /// TLS support was requested from a build compiled without the `tls` feature.
    FeatureDisabled {
        /// Operation that required TLS support.
        operation: &'static str,
        /// Operator-facing rebuild hint.
        hint: &'static str,
    },
    /// I/O error during TLS operations.
    Io(io::Error),
    /// TLS operation timed out.
    Timeout(Duration),
    /// ALPN negotiation failed or did not meet requirements.
    ///
    /// This is returned when ALPN was configured as required (e.g. HTTP/2-only)
    /// but the peer did not negotiate any protocol, or the negotiated protocol
    /// was not one of the expected values.
    AlpnNegotiationFailed {
        /// The set of acceptable ALPN protocols (in preference order).
        expected: Vec<Vec<u8>>,
        /// The protocol negotiated by the peer, if any.
        negotiated: Option<Vec<u8>>,
    },
    /// Rustls-specific error.
    #[cfg(feature = "tls")]
    Rustls(rustls::Error),
}

impl fmt::Display for TlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // br-asupersync-kxw8nx: every peer-controlled string is wrapped
        // in `sanitize_for_log` before formatting so an attacker cannot
        // inject CR/LF/tab to forge log lines, embed NULs to truncate
        // C-string consumers, or amplify log volume past 256 bytes per
        // error. Operator-controlled fields (Configuration) and
        // structured numeric fields (Timeout duration, expired_at
        // timestamp) are passed through verbatim.
        match self {
            Self::InvalidDnsName(name) => {
                write!(f, "invalid DNS name: {}", sanitize_for_log(name))
            }
            Self::Handshake(msg) => {
                write!(f, "TLS handshake failed: {}", sanitize_for_log(msg))
            }
            Self::Certificate(msg) => {
                write!(f, "certificate error: {}", sanitize_for_log(msg))
            }
            Self::CertificateExpired {
                expired_at,
                description,
            } => write!(
                f,
                "certificate expired at {expired_at}: {}",
                sanitize_for_log(description)
            ),
            Self::CertificateNotYetValid {
                valid_from,
                description,
            } => write!(
                f,
                "certificate not valid until {valid_from}: {}",
                sanitize_for_log(description)
            ),
            Self::ChainValidation(msg) => write!(
                f,
                "certificate chain validation failed: {}",
                sanitize_for_log(msg)
            ),
            Self::PinMismatch { expected, actual } => {
                // Pins are base64 — defensive sanitize anyway in case
                // a misconfigured caller passes raw subject strings.
                let expected_sanitized: Vec<String> =
                    expected.iter().map(|s| sanitize_for_log(s)).collect();
                write!(
                    f,
                    "certificate pin mismatch: expected one of {expected_sanitized:?}, got {}",
                    sanitize_for_log(actual)
                )
            }
            Self::Configuration(msg) => write!(f, "TLS configuration error: {msg}"),
            Self::FeatureDisabled { operation, hint } => {
                write!(f, "TLS feature disabled for {operation}: {hint}")
            }
            Self::Io(err) => {
                // io::Error Display can include peer-controlled paths
                // (e.g., file-not-found with attacker-supplied filename).
                write!(f, "I/O error: {}", sanitize_for_log(&err.to_string()))
            }
            Self::Timeout(duration) => write!(f, "TLS operation timed out after {duration:?}"),
            Self::AlpnNegotiationFailed {
                expected,
                negotiated,
            } => write!(
                f,
                "ALPN negotiation failed: expected one of {expected:?}, negotiated {negotiated:?}"
            ),
            #[cfg(feature = "tls")]
            Self::Rustls(err) => {
                // rustls error strings frequently include peer cert
                // subject CNs and other peer-controlled values.
                write!(f, "rustls error: {}", sanitize_for_log(&err.to_string()))
            }
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

#[cfg(test)]
#[path = "error_inline_tests.rs"]
mod tests;
