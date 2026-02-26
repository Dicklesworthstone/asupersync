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
            Self::AlpnNegotiationFailed {
                expected,
                negotiated,
            } => write!(
                f,
                "ALPN negotiation failed: expected one of {expected:?}, negotiated {negotiated:?}"
            ),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn test_display_invalid_dns_name() {
        init_test("test_display_invalid_dns_name");
        let err = TlsError::InvalidDnsName("bad.local".to_string());
        let rendered = format!("{err}");
        crate::assert_with_log!(
            rendered.contains("bad.local"),
            "display contains name",
            true,
            rendered.contains("bad.local")
        );
        crate::test_complete!("test_display_invalid_dns_name");
    }

    #[test]
    fn test_display_certificate_expired() {
        init_test("test_display_certificate_expired");
        let err = TlsError::CertificateExpired {
            expired_at: 123,
            description: "leaf".to_string(),
        };
        let rendered = format!("{err}");
        crate::assert_with_log!(
            rendered.contains("123") && rendered.contains("leaf"),
            "display expired",
            true,
            rendered.contains("123") && rendered.contains("leaf")
        );
        crate::test_complete!("test_display_certificate_expired");
    }

    #[test]
    fn test_display_pin_mismatch() {
        init_test("test_display_pin_mismatch");
        let err = TlsError::PinMismatch {
            expected: vec!["pinA".to_string(), "pinB".to_string()],
            actual: "pinC".to_string(),
        };
        let rendered = format!("{err}");
        crate::assert_with_log!(
            rendered.contains("pinC") && rendered.contains("pinA"),
            "display pin mismatch",
            true,
            rendered.contains("pinC") && rendered.contains("pinA")
        );
        crate::test_complete!("test_display_pin_mismatch");
    }

    #[test]
    fn test_io_error_source() {
        init_test("test_io_error_source");
        let io_err = io::Error::other("boom");
        let err = TlsError::from(io_err);
        crate::assert_with_log!(
            err.source().is_some(),
            "source",
            true,
            err.source().is_some()
        );
        let rendered = format!("{err}");
        crate::assert_with_log!(
            rendered.contains("I/O error"),
            "display io",
            true,
            rendered.contains("I/O error")
        );
        crate::test_complete!("test_io_error_source");
    }

    #[test]
    fn test_display_timeout() {
        init_test("test_display_timeout");
        let err = TlsError::Timeout(Duration::from_millis(250));
        let rendered = format!("{err}");
        crate::assert_with_log!(
            rendered.contains("250"),
            "display timeout",
            true,
            rendered.contains("250")
        );
        crate::test_complete!("test_display_timeout");
    }

    #[test]
    fn test_display_alpn_negotiation_failed() {
        init_test("test_display_alpn_negotiation_failed");
        let err = TlsError::AlpnNegotiationFailed {
            expected: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            negotiated: Some(b"http/1.1".to_vec()),
        };
        let rendered = format!("{err}");
        // ALPN protocol IDs are byte slices, so Debug format renders numeric bytes
        crate::assert_with_log!(
            rendered.contains("ALPN") && rendered.contains("negotiation failed"),
            "display alpn",
            true,
            rendered.contains("ALPN") && rendered.contains("negotiation failed")
        );
        crate::test_complete!("test_display_alpn_negotiation_failed");
    }

    // ---- remaining Display variants ----

    #[test]
    fn display_handshake() {
        let err = TlsError::Handshake("protocol version mismatch".into());
        let msg = err.to_string();
        assert!(msg.contains("handshake failed"), "{msg}");
        assert!(msg.contains("protocol version mismatch"), "{msg}");
    }

    #[test]
    fn display_certificate() {
        let err = TlsError::Certificate("self-signed".into());
        let msg = err.to_string();
        assert!(msg.contains("certificate error"), "{msg}");
        assert!(msg.contains("self-signed"), "{msg}");
    }

    #[test]
    fn display_certificate_not_yet_valid() {
        let err = TlsError::CertificateNotYetValid {
            valid_from: 9999999999,
            description: "leaf cert".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("not valid until"), "{msg}");
        assert!(msg.contains("9999999999"), "{msg}");
        assert!(msg.contains("leaf cert"), "{msg}");
    }

    #[test]
    fn display_chain_validation() {
        let err = TlsError::ChainValidation("missing intermediate".into());
        let msg = err.to_string();
        assert!(msg.contains("chain validation failed"), "{msg}");
        assert!(msg.contains("missing intermediate"), "{msg}");
    }

    #[test]
    fn display_configuration() {
        let err = TlsError::Configuration("no cipher suites".into());
        let msg = err.to_string();
        assert!(msg.contains("configuration error"), "{msg}");
        assert!(msg.contains("no cipher suites"), "{msg}");
    }

    #[test]
    fn display_alpn_no_negotiated() {
        let err = TlsError::AlpnNegotiationFailed {
            expected: vec![b"h2".to_vec()],
            negotiated: None,
        };
        let msg = err.to_string();
        assert!(msg.contains("None"), "{msg}");
    }

    // ---- source() for non-Io variants ----

    #[test]
    fn source_non_io_returns_none() {
        assert!(TlsError::InvalidDnsName("x".into()).source().is_none());
        assert!(TlsError::Handshake("x".into()).source().is_none());
        assert!(TlsError::Certificate("x".into()).source().is_none());
        assert!(TlsError::Configuration("x".into()).source().is_none());
        assert!(TlsError::ChainValidation("x".into()).source().is_none());
        assert!(
            TlsError::CertificateExpired {
                expired_at: 0,
                description: "x".into()
            }
            .source()
            .is_none()
        );
        assert!(
            TlsError::CertificateNotYetValid {
                valid_from: 0,
                description: "x".into()
            }
            .source()
            .is_none()
        );
        assert!(
            TlsError::PinMismatch {
                expected: vec![],
                actual: "x".into()
            }
            .source()
            .is_none()
        );
        assert!(TlsError::Timeout(Duration::ZERO).source().is_none());
        assert!(
            TlsError::AlpnNegotiationFailed {
                expected: vec![],
                negotiated: None
            }
            .source()
            .is_none()
        );
    }

    // ---- From<io::Error> ----

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::ConnectionReset, "reset");
        let tls_err: TlsError = io_err.into();
        assert!(matches!(tls_err, TlsError::Io(_)));
        assert!(tls_err.source().is_some());
    }
}
