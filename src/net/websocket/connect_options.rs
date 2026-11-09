//! Bounded request metadata for the additive native WebSocket connect APIs.

use super::{HandshakeError, WebSocketConfig, WsConnectError, WsError};
use std::fmt;
use std::io;

/// Validated configuration for a native WebSocket upgrade with custom headers.
///
/// Use this with [`super::WebSocket::connect_with_options`] or
/// `WebSocket::connect_tls_with_options` (with `tls`). Existing
/// [`WebSocketConfig`] literals and connection methods remain unchanged.
/// Header names are normalized to lowercase and are unique, including
/// `Authorization`, `Cookie`, `Origin`, and tracing fields. Combine list-valued
/// fields explicitly before adding them. Transport and WebSocket negotiation
/// headers are reserved; configure subprotocols through `WebSocketConfig` and
/// compression through `with_compression` (with `compression`).
///
/// Only the supplied origin receives these headers. The client does not follow
/// redirects. Use the TLS connection method when headers contain credentials.
/// Debug formatting reveals counts, never header names, values, or protocols.
///
/// ```no_run
/// use asupersync::net::websocket::{
///     WebSocket, WebSocketConfig, WebSocketConnectOptions,
/// };
/// # async fn example(cx: &asupersync::Cx) -> Result<(), Box<dyn std::error::Error>> {
/// let options = WebSocketConnectOptions::new(WebSocketConfig::default())
///     .try_header("Origin", "https://app.example")?
///     .try_header("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")?;
/// let socket = WebSocket::connect_with_options(cx, "ws://localhost/events", options).await?;
/// # drop(socket);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct WebSocketConnectOptions {
    config: WebSocketConfig,
    headers: Vec<(String, String)>,
    header_bytes: usize,
    compression: bool,
}

impl fmt::Debug for WebSocketConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WebSocketConnectOptions")
            .field("header_count", &self.headers.len())
            .field("header_bytes", &self.header_bytes)
            .field("compression", &self.compression)
            .finish_non_exhaustive()
    }
}

impl Default for WebSocketConnectOptions {
    fn default() -> Self {
        Self::new(WebSocketConfig::default())
    }
}

impl WebSocketConnectOptions {
    /// Maximum number of additional request headers.
    pub const MAX_HEADERS: usize = 32;
    /// Maximum serialized bytes for all additional headers, counting `: ` and
    /// the terminating CRLF for each field. Generated upgrade headers and the
    /// URL retain the existing connection API's separate behavior.
    pub const MAX_HEADER_BYTES: usize = 8 * 1024;
    /// Maximum bytes in one additional header name.
    pub const MAX_HEADER_NAME_BYTES: usize = 256;
    /// Maximum bytes in one additional header value.
    pub const MAX_HEADER_VALUE_BYTES: usize = 4096;

    /// Wrap existing message, timeout, subprotocol, and backpressure settings.
    #[must_use]
    pub fn new(config: WebSocketConfig) -> Self {
        Self {
            config,
            headers: Vec::new(),
            header_bytes: 0,
            compression: false,
        }
    }

    /// Add one validated request header without performing I/O.
    ///
    /// Names must be nonempty ASCII HTTP tokens. Values accept visible ASCII,
    /// space, and horizontal tab; CR, LF, other controls, and non-ASCII bytes
    /// are rejected. Duplicate names are rejected case-insensitively rather
    /// than replacing credentials or creating ambiguous authentication fields.
    /// Validation precedes allocation of the supplied strings.
    ///
    /// `Host`, `Connection`, `Upgrade`, every `Sec-WebSocket-*` name,
    /// `Content-Length`, `Transfer-Encoding`, `TE`, `Trailer`, `Expect`,
    /// `Keep-Alive`, `Proxy-Connection`, and `Proxy-Authorization` are reserved.
    /// Proxy credentials must not be sent as origin upgrade metadata.
    pub fn try_header(
        mut self,
        name: impl AsRef<str>,
        value: impl AsRef<str>,
    ) -> Result<Self, WebSocketConnectOptionsError> {
        let name = name.as_ref();
        let value = value.as_ref();
        if name.is_empty()
            || name.len() > Self::MAX_HEADER_NAME_BYTES
            || !name.bytes().all(is_token_byte)
        {
            return Err(WebSocketConnectOptionsError::InvalidHeaderName);
        }
        if reserved_header(name) {
            return Err(WebSocketConnectOptionsError::ReservedHeader);
        }
        if value.len() > Self::MAX_HEADER_VALUE_BYTES {
            return Err(WebSocketConnectOptionsError::HeaderBytesExceeded);
        }
        if !value
            .bytes()
            .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte))
        {
            return Err(WebSocketConnectOptionsError::InvalidHeaderValue);
        }
        if self
            .headers
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(name))
        {
            return Err(WebSocketConnectOptionsError::DuplicateHeader);
        }
        if self.headers.len() >= Self::MAX_HEADERS {
            return Err(WebSocketConnectOptionsError::TooManyHeaders);
        }
        let header_bytes = self
            .header_bytes
            .checked_add(name.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .and_then(|bytes| bytes.checked_add(4))
            .filter(|bytes| *bytes <= Self::MAX_HEADER_BYTES)
            .ok_or(WebSocketConnectOptionsError::HeaderBytesExceeded)?;
        self.headers
            .push((name.to_ascii_lowercase(), value.to_owned()));
        self.header_bytes = header_bytes;
        Ok(self)
    }

    /// Offer the same bounded permessage-deflate profile as
    /// [`super::WebSocket::connect_with_compression`]. The peer may decline it.
    #[cfg(feature = "compression")]
    #[must_use]
    pub fn with_compression(mut self) -> Self {
        self.compression = true;
        self
    }

    pub(super) fn into_parts(self) -> (WebSocketConfig, Vec<(String, String)>, bool) {
        (self.config, self.headers, self.compression)
    }
}

/// Value-redacted refusal of custom WebSocket request metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WebSocketConnectOptionsError {
    /// The name is empty, too long, or not an ASCII HTTP token.
    InvalidHeaderName,
    /// The handshake or transport owns this header.
    ReservedHeader,
    /// The value contains a forbidden control or non-ASCII byte.
    InvalidHeaderValue,
    /// A case-insensitively equal name was already added.
    DuplicateHeader,
    /// More than 32 additional fields were requested.
    TooManyHeaders,
    /// One value or the complete additional header list exceeds its byte bound.
    HeaderBytesExceeded,
}

impl fmt::Display for WebSocketConnectOptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidHeaderName => "invalid WebSocket request header name",
            Self::ReservedHeader => "WebSocket request header is reserved by the transport",
            Self::InvalidHeaderValue => "invalid WebSocket request header value",
            Self::DuplicateHeader => "duplicate WebSocket request header",
            Self::TooManyHeaders => "too many WebSocket request headers",
            Self::HeaderBytesExceeded => "WebSocket request headers exceed their byte limit",
        })
    }
}

impl std::error::Error for WebSocketConnectOptionsError {}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn reserved_header(name: &str) -> bool {
    name.get(..14)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sec-websocket-"))
        || [
            "host",
            "connection",
            "upgrade",
            "content-length",
            "transfer-encoding",
            "te",
            "trailer",
            "expect",
            "keep-alive",
            "proxy-connection",
            "proxy-authorization",
        ]
        .into_iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

// Custom metadata can be reflected by a hostile peer in its response fields.
// Redact only the additive options APIs; legacy error payloads stay unchanged.
pub(super) fn redact_connect_error(error: WsConnectError) -> WsConnectError {
    match error {
        WsConnectError::InvalidUrl(error) => {
            WsConnectError::InvalidUrl(redact_handshake_error(error))
        }
        WsConnectError::Handshake(error) => {
            WsConnectError::Handshake(redact_handshake_error(error))
        }
        WsConnectError::Io(error) => WsConnectError::Io(redact_io_error(error)),
        WsConnectError::Protocol(WsError::Io(error)) => {
            WsConnectError::Protocol(WsError::Io(redact_io_error(error)))
        }
        other => other,
    }
}

fn redact_io_error(error: io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || {
            io::Error::new(
                error.kind(),
                "WebSocket connection I/O failed (details redacted)",
            )
        },
        io::Error::from_raw_os_error,
    )
}

fn redact_handshake_error(error: HandshakeError) -> HandshakeError {
    const REDACTED: &str = "<redacted>";
    match error {
        HandshakeError::InvalidUrl(_) => HandshakeError::InvalidUrl(REDACTED.into()),
        HandshakeError::InvalidRequest(_) => HandshakeError::InvalidRequest(REDACTED.into()),
        HandshakeError::InvalidAccept { .. } => HandshakeError::InvalidAccept {
            expected: REDACTED.into(),
            actual: REDACTED.into(),
        },
        HandshakeError::UnsupportedVersion(_) => {
            HandshakeError::UnsupportedVersion(REDACTED.into())
        }
        HandshakeError::ProtocolMismatch { requested, offered } => {
            HandshakeError::ProtocolMismatch {
                requested: if requested.is_empty() {
                    Vec::new()
                } else {
                    vec![REDACTED.into()]
                },
                offered: offered.map(|_| REDACTED.into()),
            }
        }
        HandshakeError::ExtensionMismatch { requested, offered } => {
            HandshakeError::ExtensionMismatch {
                requested: if requested.is_empty() {
                    Vec::new()
                } else {
                    vec![REDACTED.into()]
                },
                offered: if offered.is_empty() {
                    Vec::new()
                } else {
                    vec![REDACTED.into()]
                },
            }
        }
        HandshakeError::Rejected { status, .. } => HandshakeError::Rejected {
            status,
            reason: REDACTED.into(),
        },
        HandshakeError::Io(error) => HandshakeError::Io(redact_io_error(error)),
        other => other,
    }
}
