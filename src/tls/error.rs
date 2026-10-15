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
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
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
            valid_from: 9_999_999_999,
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
    fn display_feature_disabled_includes_operation_and_hint() {
        let err = TlsError::FeatureDisabled {
            operation: "build TLS connector",
            hint: "rebuild with --features tls",
        };
        let msg = err.to_string();
        assert!(msg.contains("TLS feature disabled"), "{msg}");
        assert!(msg.contains("build TLS connector"), "{msg}");
        assert!(msg.contains("--features tls"), "{msg}");
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

    // ---- br-asupersync-kxw8nx: log injection sanitization ----

    #[test]
    fn sanitize_for_log_strips_crlf_to_space() {
        let raw = "line1\r\nline2";
        let sanitized = sanitize_for_log(raw);
        assert!(
            !sanitized.contains('\n') && !sanitized.contains('\r'),
            "CR/LF must be stripped, got {sanitized:?}"
        );
        assert_eq!(sanitized, "line1  line2");
    }

    #[test]
    fn sanitize_for_log_strips_tab_to_space() {
        let sanitized = sanitize_for_log("a\tb");
        assert_eq!(sanitized, "a b");
    }

    #[test]
    fn sanitize_for_log_replaces_other_control_with_question() {
        // NUL, BEL, ESC, DEL — all non-printable controls beyond CR/LF/tab.
        let raw = "x\x00y\x07z\x1bw\x7fv";
        let sanitized = sanitize_for_log(raw);
        assert_eq!(sanitized, "x?y?z?w?v");
    }

    #[test]
    fn sanitize_for_log_preserves_printable_ascii_and_unicode() {
        let raw = "hello, world! ✓ 漢字";
        let sanitized = sanitize_for_log(raw);
        assert_eq!(sanitized, raw);
    }

    #[test]
    fn sanitize_for_log_truncates_at_256_bytes_with_ellipsis() {
        let raw = "A".repeat(500);
        let sanitized = sanitize_for_log(&raw);
        // 256 bytes of 'A' (ASCII = 1 byte) plus '…' (3 bytes UTF-8).
        assert!(sanitized.starts_with(&"A".repeat(256)));
        assert!(sanitized.ends_with('…'));
        // Total UTF-8 length: 256 + 3 = 259 bytes.
        assert_eq!(sanitized.len(), 259);
    }

    #[test]
    fn sanitize_for_log_under_cap_does_not_append_ellipsis() {
        let raw = "short";
        let sanitized = sanitize_for_log(raw);
        assert!(!sanitized.ends_with('…'));
        assert_eq!(sanitized, "short");
    }

    #[test]
    fn sanitize_for_log_truncates_on_char_boundary_for_multibyte() {
        // Each '漢' is 3 UTF-8 bytes. 86 of them = 258 bytes (over cap).
        // Cap is 256 bytes; 85 chars = 255 bytes (fits); 86th char (3
        // bytes) would push to 258, so truncated at 85 chars + '…'.
        let raw = "漢".repeat(86);
        let sanitized = sanitize_for_log(&raw);
        assert!(sanitized.ends_with('…'));
        // 85 * 3 = 255 bytes of 漢, plus 3 bytes of '…' = 258 total.
        assert_eq!(sanitized.len(), 258);
        // Verify char boundary respected: must be valid UTF-8.
        assert!(std::str::from_utf8(sanitized.as_bytes()).is_ok());
    }

    #[test]
    fn sanitize_for_log_is_idempotent_after_replacement_and_truncation() {
        let cases = [
            "clean peer error",
            "line1\r\nline2\tfield",
            "nul\x00bell\x07escape\x1bdel\x7f",
            "A very long ASCII peer error: ",
            "unicode peer error ✓ 漢字",
        ];

        for raw in cases {
            let long_input;
            let input = if raw.starts_with('A') {
                long_input = raw.repeat(20);
                long_input.as_str()
            } else {
                raw
            };
            let once = sanitize_for_log(input);
            let twice = sanitize_for_log(&once);

            assert_eq!(twice, once, "sanitization must be idempotent for {raw:?}");
            assert!(
                !twice.contains('\r'),
                "sanitized output must not contain CR"
            );
            assert!(
                !twice.contains('\n'),
                "sanitized output must not contain LF"
            );
            assert!(
                !twice.contains('\t'),
                "sanitized output must not contain tab"
            );
            assert!(!twice.chars().any(|ch| ch < ' ' || ch == '\u{7f}'));
        }
    }

    #[test]
    fn display_sanitizes_peer_controlled_fields_across_variants() {
        let peer_text = "peer\r\nvalue\twith\x00controls\x7f";
        let cases = [
            TlsError::InvalidDnsName(peer_text.to_string()),
            TlsError::Handshake(peer_text.to_string()),
            TlsError::Certificate(peer_text.to_string()),
            TlsError::CertificateExpired {
                expired_at: 42,
                description: peer_text.to_string(),
            },
            TlsError::CertificateNotYetValid {
                valid_from: 43,
                description: peer_text.to_string(),
            },
            TlsError::ChainValidation(peer_text.to_string()),
            TlsError::PinMismatch {
                expected: vec![peer_text.to_string()],
                actual: peer_text.to_string(),
            },
            TlsError::Io(io::Error::other(peer_text)),
        ];

        for err in cases {
            let display = err.to_string();

            assert!(
                !display.contains('\r'),
                "Display must strip CR for {display:?}"
            );
            assert!(
                !display.contains('\n'),
                "Display must strip LF for {display:?}"
            );
            assert!(
                !display.contains('\t'),
                "Display must strip tabs for {display:?}"
            );
            assert!(
                !display.chars().any(|ch| ch < ' ' || ch == '\u{7f}'),
                "Display must strip remaining ASCII controls for {display:?}"
            );
            assert!(
                display.contains("peer  value with?controls?"),
                "sanitized peer text should remain visible in one log line: {display:?}"
            );
        }
    }

    #[test]
    fn display_handshake_with_log_injection_attempt_sanitized() {
        // Peer-controlled handshake error containing a forged log line
        // splice attempt. Post-fix Display must NOT contain the
        // injected newline.
        let err = TlsError::Handshake(
            "alert: bad_certificate\n[ERROR] FORGED LOG ENTRY: privilege escalation".to_string(),
        );
        let display = err.to_string();
        assert!(
            !display.contains('\n'),
            "Display MUST strip embedded newlines: {display:?}"
        );
        // The injected text becomes part of the same log line, prefixed
        // by the spaces that replaced \n — visible to operators but
        // unable to forge a separate log entry.
        assert!(display.contains("FORGED LOG ENTRY"));
        assert!(display.starts_with("TLS handshake failed: "));
    }

    #[test]
    fn display_invalid_dns_name_with_control_chars_sanitized() {
        let err = TlsError::InvalidDnsName("evil.com\r\n\x00\x07ROOT_PROMPT$".to_string());
        let display = err.to_string();
        assert!(!display.contains('\r'));
        assert!(!display.contains('\n'));
        assert!(!display.contains('\0'));
        assert!(!display.contains('\x07'));
        // The control chars get converted to ? or space; the trailing
        // text ROOT_PROMPT$ remains visible.
        assert!(display.contains("ROOT_PROMPT$"));
    }

    #[test]
    fn display_certificate_error_amplification_capped() {
        // Peer-controlled certificate error of 10 KB must be capped at
        // 256 bytes + ellipsis; total Display output stays bounded.
        let huge = "X".repeat(10_000);
        let err = TlsError::Certificate(huge);
        let display = err.to_string();
        // Display = "certificate error: " (19) + 256 'X' + '…' (3)
        // = 19 + 256 + 3 = 278 bytes max.
        assert!(
            display.len() < 300,
            "Display must be capped to ~256 bytes of payload, got {} bytes",
            display.len()
        );
        assert!(display.ends_with('…'));
    }
}
