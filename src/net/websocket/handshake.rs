//! WebSocket handshake implementation (RFC 6455 Section 4).
//!
//! Implements the HTTP upgrade handshake for both client and server roles.
//!
//! # Client Handshake
//!
//! ```http
//! GET /chat HTTP/1.1
//! Host: server.example.com
//! Upgrade: websocket
//! Connection: Upgrade
//! Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
//! Sec-WebSocket-Version: 13
//! ```
//!
//! # Server Response
//!
//! ```http
//! HTTP/1.1 101 Switching Protocols
//! Upgrade: websocket
//! Connection: Upgrade
//! Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
//! ```

use crate::util::EntropySource;
use base64::Engine;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, btree_map::Entry};
use std::fmt;

/// RFC 6455 GUID for Sec-WebSocket-Accept calculation.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the Sec-WebSocket-Accept value from a client key.
///
/// Per RFC 6455 Section 4.2.2:
/// 1. Concatenate the client's Sec-WebSocket-Key with the GUID
/// 2. Take the SHA-1 hash
/// 3. Base64 encode the result
///
/// # Example
///
/// ```
/// use asupersync::net::websocket::compute_accept_key;
///
/// let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
/// let accept = compute_accept_key(client_key);
/// assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
/// ```
#[must_use]
pub fn compute_accept_key(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Generate a random 16-byte key for the client handshake.
fn generate_client_key(entropy: &dyn EntropySource) -> String {
    let mut key = [0u8; 16];
    entropy.fill_bytes(&mut key);
    base64::engine::general_purpose::STANDARD.encode(key)
}

fn parse_extension_offers(header_value: &str) -> Vec<String> {
    header_value
        .split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn extension_token(offer: &str) -> &str {
    offer.split(';').next().unwrap_or("").trim()
}

fn header_has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|part| part.eq_ignore_ascii_case(token))
}

fn split_http_header_block(data: &[u8]) -> Result<(&[u8], &[u8]), HandshakeError> {
    let crlf_pos = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p.saturating_add(4));
    let lf_pos = data
        .windows(2)
        .position(|w| w == b"\n\n")
        .map(|p| p.saturating_add(2));

    let split_at = match (crlf_pos, lf_pos) {
        (Some(c), Some(l)) => Some(std::cmp::min(c, l)),
        (pos @ Some(_), None) | (None, pos @ Some(_)) => pos,
        (None, None) => None,
    };

    split_at.map_or_else(
        || {
            Err(HandshakeError::InvalidRequest(
                "incomplete HTTP headers".into(),
            ))
        },
        |pos| Ok((&data[..pos], &data[pos..])),
    )
}

#[inline]
fn is_http_header_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'
            | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
    )
}

/// Header names a handshake may carry only once. A second Host or
/// Sec-WebSocket-Version would make the request ambiguous, and RFC 6455
/// forbids repeating Sec-WebSocket-Key and Sec-WebSocket-Accept.
fn is_singleton_handshake_header(name: &str) -> bool {
    matches!(
        name,
        "host" | "sec-websocket-key" | "sec-websocket-accept" | "sec-websocket-version"
    )
}

/// Records one header line. A repeated header, other than a singleton, is
/// joined to the earlier value with ", " (RFC 9110 section 5.3). RFC 6455
/// allows repeating Sec-WebSocket-Protocol and Sec-WebSocket-Extensions, and
/// proxies and load balancers add their own repeated lines, such as Set-Cookie
/// or X-Forwarded-For.
fn insert_header(
    headers: &mut BTreeMap<String, String>,
    raw_name: &str,
    raw_value: &str,
) -> Result<(), HandshakeError> {
    if raw_name.is_empty() {
        return Err(HandshakeError::InvalidRequest(
            "empty HTTP header name".into(),
        ));
    }
    if !raw_name.bytes().all(is_http_header_name_byte) {
        return Err(HandshakeError::InvalidRequest(
            "invalid HTTP header name".into(),
        ));
    }
    let name = raw_name.to_ascii_lowercase();

    match headers.entry(name) {
        Entry::Vacant(entry) => {
            entry.insert(raw_value.trim().to_string());
            Ok(())
        }
        Entry::Occupied(entry) if is_singleton_handshake_header(entry.key()) => Err(
            HandshakeError::InvalidRequest(format!("duplicate HTTP header: {}", entry.key())),
        ),
        Entry::Occupied(mut entry) => {
            let joined = entry.get_mut();
            joined.push_str(", ");
            joined.push_str(raw_value.trim());
            Ok(())
        }
    }
}

fn validate_url_host(host: &str) -> Result<(), HandshakeError> {
    if host
        .bytes()
        .any(|b| matches!(b, 0..=32 | 127 | b'/' | b'?' | b'#' | b'@' | b'[' | b']'))
    {
        return Err(HandshakeError::InvalidUrl(
            "host contains an invalid HTTP authority byte".into(),
        ));
    }
    Ok(())
}

fn validate_url_request_target(path: &str) -> Result<(), HandshakeError> {
    if path.contains('#') {
        return Err(HandshakeError::InvalidUrl(
            "request target must not contain a URI fragment".into(),
        ));
    }
    if path.bytes().any(|b| matches!(b, 0..=32 | 127)) {
        return Err(HandshakeError::InvalidUrl(
            "request target contains an invalid HTTP request-line byte".into(),
        ));
    }
    Ok(())
}

fn split_url_authority_and_target(rest: &str) -> Result<(&str, String), HandshakeError> {
    if rest.contains('#') {
        return Err(HandshakeError::InvalidUrl(
            "WebSocket URL must not contain a fragment".into(),
        ));
    }

    let split_at = match (rest.find('/'), rest.find('?')) {
        (Some(slash), Some(query)) => Some(slash.min(query)),
        (Some(slash), None) => Some(slash),
        (None, Some(query)) => Some(query),
        (None, None) => None,
    };

    let Some(split_at) = split_at else {
        return Ok((rest, "/".to_string()));
    };

    let authority = &rest[..split_at];
    let target = &rest[split_at..];
    let target = if target.starts_with('?') {
        format!("/{target}")
    } else {
        target.to_string()
    };

    Ok((authority, target))
}

/// Parsed WebSocket URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsUrl {
    /// Host name or IP address.
    pub host: String,
    /// Port number (default: 80 for ws, 443 for wss).
    pub port: u16,
    /// Request path (default: "/").
    pub path: String,
    /// Whether TLS is required (wss://).
    pub tls: bool,
}

impl WsUrl {
    /// Parse a WebSocket URL (ws:// or wss://).
    ///
    /// # Errors
    ///
    /// Returns `HandshakeError::InvalidUrl` if the URL is malformed.
    pub fn parse(url: &str) -> Result<Self, HandshakeError> {
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| HandshakeError::InvalidUrl("missing scheme".into()))?;

        let tls = match scheme {
            "ws" => false,
            "wss" => true,
            _ => {
                return Err(HandshakeError::InvalidUrl(format!(
                    "unsupported scheme: {scheme}"
                )));
            }
        };

        let default_port = if tls { 443 } else { 80 };

        // Split authority from the HTTP request target. Query-only WebSocket
        // URLs use origin-form `/?query`; fragments are never sent on the wire.
        let (host_port, path) = split_url_authority_and_target(rest)?;

        // Parse host and port
        let (host, port) = if host_port.starts_with('[') {
            host_port.find(']').map_or_else(
                || {
                    Err(HandshakeError::InvalidUrl(
                        "missing closing bracket for IPv6 address".into(),
                    ))
                },
                |bracket_end| {
                    let host = &host_port[1..bracket_end];
                    let suffix = &host_port[bracket_end.saturating_add(1)..];
                    let port = if suffix.is_empty() {
                        default_port
                    } else if let Some(port_str) = suffix.strip_prefix(':') {
                        port_str
                            .parse()
                            .map_err(|_| HandshakeError::InvalidUrl("invalid port".into()))?
                    } else {
                        return Err(HandshakeError::InvalidUrl(
                            "unexpected data after bracketed IPv6 address".into(),
                        ));
                    };
                    Ok((host.to_string(), port))
                },
            )?
        } else if host_port.matches(':').count() > 1 {
            // Unbracketed IPv6 address - cannot safely have a port (ambiguous)
            (host_port.to_string(), default_port)
        } else if let Some(colon_idx) = host_port.rfind(':') {
            // host:port
            let host = &host_port[..colon_idx];
            let port = host_port[colon_idx.saturating_add(1)..]
                .parse()
                .map_err(|_| HandshakeError::InvalidUrl("invalid port".into()))?;
            (host.to_string(), port)
        } else {
            (host_port.to_string(), default_port)
        };

        if host.is_empty() {
            return Err(HandshakeError::InvalidUrl("empty host".into()));
        }
        validate_url_host(&host)?;
        validate_url_request_target(&path)?;

        Ok(Self {
            host,
            port,
            path,
            tls,
        })
    }

    /// Returns the Host header value.
    #[must_use]
    pub fn host_header(&self) -> String {
        let default_port = if self.tls { 443 } else { 80 };
        let host_str = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };

        if self.port == default_port {
            host_str
        } else {
            format!("{}:{}", host_str, self.port)
        }
    }
}

/// WebSocket handshake errors.
#[derive(Debug)]
pub enum HandshakeError {
    /// Invalid URL format.
    InvalidUrl(String),
    /// Invalid HTTP request.
    InvalidRequest(String),
    /// Missing required header.
    MissingHeader(&'static str),
    /// Invalid Sec-WebSocket-Key.
    InvalidKey,
    /// Invalid Sec-WebSocket-Accept (response validation).
    InvalidAccept {
        /// Expected accept value.
        expected: String,
        /// Actual accept value.
        actual: String,
    },
    /// Unsupported WebSocket version.
    UnsupportedVersion(String),
    /// Protocol negotiation failed.
    ProtocolMismatch {
        /// Requested protocols.
        requested: Vec<String>,
        /// Offered protocol (if any).
        offered: Option<String>,
    },
    /// Extension negotiation failed.
    ExtensionMismatch {
        /// Requested extensions.
        requested: Vec<String>,
        /// Offered extensions.
        offered: Vec<String>,
    },
    /// Server rejected upgrade with HTTP status.
    Rejected {
        /// HTTP status code.
        status: u16,
        /// Status reason phrase.
        reason: String,
    },
    /// HTTP response not 101 Switching Protocols.
    NotSwitchingProtocols(u16),
    /// I/O error.
    Io(std::io::Error),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(msg) => write!(f, "invalid URL: {msg}"),
            Self::InvalidRequest(msg) => write!(f, "invalid HTTP request: {msg}"),
            Self::MissingHeader(name) => write!(f, "missing required header: {name}"),
            Self::InvalidKey => write!(f, "invalid Sec-WebSocket-Key"),
            Self::InvalidAccept { expected, actual } => {
                write!(
                    f,
                    "invalid Sec-WebSocket-Accept: expected {expected}, got {actual}"
                )
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported WebSocket version: {v}"),
            Self::ProtocolMismatch { requested, offered } => {
                write!(
                    f,
                    "protocol mismatch: requested {requested:?}, offered {offered:?}"
                )
            }
            Self::ExtensionMismatch { requested, offered } => {
                write!(
                    f,
                    "extension mismatch: requested {requested:?}, offered {offered:?}"
                )
            }
            Self::Rejected { status, reason } => {
                write!(f, "server rejected upgrade: {status} {reason}")
            }
            Self::NotSwitchingProtocols(status) => {
                write!(f, "expected 101 Switching Protocols, got {status}")
            }
            Self::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for HandshakeError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Client-side WebSocket handshake configuration.
#[derive(Debug, Clone)]
pub struct ClientHandshake {
    /// Target URL.
    url: WsUrl,
    /// Random client key (base64 encoded).
    key: String,
    /// Requested subprotocols.
    protocols: Vec<String>,
    /// Requested extensions.
    extensions: Vec<String>,
    /// Additional headers.
    headers: BTreeMap<String, String>,
}

impl ClientHandshake {
    /// Internal constructor for deterministic testing.
    #[doc(hidden)]
    pub fn new_for_test(
        url: WsUrl,
        key: String,
        protocols: Vec<String>,
        extensions: Vec<String>,
        headers: BTreeMap<String, String>,
    ) -> Self {
        Self {
            url,
            key,
            protocols,
            extensions,
            headers,
        }
    }

    /// Initiates a new client handshake to the specified URL.
    ///
    /// # Errors
    ///
    /// Returns `HandshakeError::InvalidUrl` if the URL is malformed.
    pub fn new(url: &str, entropy: &dyn EntropySource) -> Result<Self, HandshakeError> {
        let parsed_url = WsUrl::parse(url)?;
        Ok(Self {
            url: parsed_url,
            key: generate_client_key(entropy),
            protocols: Vec::new(),
            extensions: Vec::new(),
            headers: BTreeMap::new(),
        })
    }

    /// Add a subprotocol to request.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.protocols.push(protocol.into());
        self
    }

    /// Add an extension to request.
    #[must_use]
    pub fn extension(mut self, extension: impl Into<String>) -> Self {
        self.extensions.push(extension.into());
        self
    }

    /// Add a custom header.
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Returns the parsed URL.
    #[must_use]
    pub fn url(&self) -> &WsUrl {
        &self.url
    }

    /// Returns the client key (for validation).
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Generate the HTTP upgrade request as bytes.
    #[must_use]
    pub fn request_bytes(&self) -> Vec<u8> {
        let mut request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n",
            self.url.path,
            self.url.host_header(),
            self.key
        );

        if !self.protocols.is_empty() {
            request.push_str("Sec-WebSocket-Protocol: ");
            let sanitized: Vec<String> = self
                .protocols
                .iter()
                .map(|p| p.replace(['\r', '\n'], ""))
                .collect();
            request.push_str(&sanitized.join(", "));
            request.push_str("\r\n");
        }

        if !self.extensions.is_empty() {
            request.push_str("Sec-WebSocket-Extensions: ");
            let sanitized: Vec<String> = self
                .extensions
                .iter()
                .map(|e| e.replace(['\r', '\n'], ""))
                .collect();
            request.push_str(&sanitized.join(", "));
            request.push_str("\r\n");
        }

        for (name, value) in &self.headers {
            // Sanitize CRLF to prevent HTTP header injection.
            let name = name.replace(['\r', '\n'], "");
            let value = value.replace(['\r', '\n'], "");
            request.push_str(&name);
            request.push_str(": ");
            request.push_str(&value);
            request.push_str("\r\n");
        }

        request.push_str("\r\n");
        request.into_bytes()
    }

    /// Validate the server's HTTP response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Status is not 101 Switching Protocols
    /// - Required headers are missing
    /// - Sec-WebSocket-Accept is invalid
    /// - Server-selected subprotocol was not requested by the client
    pub fn validate_response(&self, response: &HttpResponse) -> Result<(), HandshakeError> {
        // Check status code
        if response.status != 101 {
            return Err(HandshakeError::NotSwitchingProtocols(response.status));
        }

        // Check Upgrade header
        let upgrade = response
            .header("upgrade")
            .ok_or(HandshakeError::MissingHeader("Upgrade"))?;
        if !header_has_token(upgrade, "websocket") {
            return Err(HandshakeError::InvalidRequest(format!(
                "Upgrade header must contain 'websocket', got '{upgrade}'"
            )));
        }

        // Check Connection header
        let connection = response
            .header("connection")
            .ok_or(HandshakeError::MissingHeader("Connection"))?;
        if !header_has_token(connection, "upgrade") {
            return Err(HandshakeError::InvalidRequest(format!(
                "Connection header must contain 'Upgrade', got '{connection}'"
            )));
        }

        // Validate Sec-WebSocket-Accept
        let accept = response
            .header("sec-websocket-accept")
            .ok_or(HandshakeError::MissingHeader("Sec-WebSocket-Accept"))?;

        let expected = compute_accept_key(&self.key);
        if accept != expected {
            return Err(HandshakeError::InvalidAccept {
                expected,
                actual: accept.to_string(),
            });
        }

        // Validate subprotocol negotiation when server selected one.
        if let Some(offered_protocol) = response.header("sec-websocket-protocol") {
            let offered = offered_protocol.trim().to_string();
            if !self.protocols.iter().any(|requested| requested == &offered) {
                return Err(HandshakeError::ProtocolMismatch {
                    requested: self.protocols.clone(),
                    offered: Some(offered),
                });
            }
        }

        if let Some(offered_extensions) = response.header("sec-websocket-extensions") {
            let offered = parse_extension_offers(offered_extensions);
            let mut invalid = Vec::new();

            for extension in &offered {
                let token = extension_token(extension);
                if token.is_empty()
                    || !self
                        .extensions
                        .iter()
                        .any(|requested| extension_token(requested).eq_ignore_ascii_case(token))
                {
                    invalid.push(extension.clone());
                }
            }

            if !invalid.is_empty() {
                return Err(HandshakeError::ExtensionMismatch {
                    requested: self.extensions.clone(),
                    offered: invalid,
                });
            }
        }

        Ok(())
    }
}

/// Server-side WebSocket handshake configuration.
#[derive(Debug, Clone, Default)]
pub struct ServerHandshake {
    /// Supported subprotocols.
    supported_protocols: Vec<String>,
    /// Supported extensions.
    supported_extensions: Vec<String>,
}

impl ServerHandshake {
    /// Create a new server handshake configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a supported subprotocol.
    #[must_use]
    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.supported_protocols.push(protocol.into());
        self
    }

    /// Add a supported extension.
    #[must_use]
    pub fn extension(mut self, extension: impl Into<String>) -> Self {
        self.supported_extensions.push(extension.into());
        self
    }

    /// Validate client request and generate accept response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required headers are missing
    /// - WebSocket version is unsupported
    /// - Sec-WebSocket-Key is invalid
    pub fn accept(&self, request: &HttpRequest) -> Result<AcceptResponse, HandshakeError> {
        // Validate HTTP method
        if request.method != "GET" {
            return Err(HandshakeError::InvalidRequest(
                "method must be GET".to_string(),
            ));
        }

        // Check Upgrade header
        let upgrade = request
            .header("upgrade")
            .ok_or(HandshakeError::MissingHeader("Upgrade"))?;
        if !header_has_token(upgrade, "websocket") {
            return Err(HandshakeError::InvalidRequest(
                "Upgrade header must contain 'websocket'".to_string(),
            ));
        }

        // Check Connection header
        let connection = request
            .header("connection")
            .ok_or(HandshakeError::MissingHeader("Connection"))?;
        if !header_has_token(connection, "upgrade") {
            return Err(HandshakeError::InvalidRequest(
                "Connection header must contain 'Upgrade'".to_string(),
            ));
        }

        // Check WebSocket version
        let version = request
            .header("sec-websocket-version")
            .ok_or(HandshakeError::MissingHeader("Sec-WebSocket-Version"))?;
        if version != "13" {
            return Err(HandshakeError::UnsupportedVersion(
                "Unsupported WebSocket version".to_string(),
            ));
        }

        // Get and validate client key
        let client_key = request
            .header("sec-websocket-key")
            .ok_or(HandshakeError::MissingHeader("Sec-WebSocket-Key"))?;

        // Validate key is valid base64 of 16 bytes (24 chars with padding)
        match base64::engine::general_purpose::STANDARD.decode(client_key) {
            Ok(decoded) if decoded.len() == 16 => {}
            _ => return Err(HandshakeError::InvalidKey),
        }

        // Compute accept key
        let accept_key = compute_accept_key(client_key);

        // Negotiate subprotocol.
        //
        // RFC 6455 §4.2.2: the server selects one of the client-offered
        // subprotocols, honoring the client's preference order. Iterate the
        // client's list first and return the first entry the server supports.
        //
        // If no client-offered protocol is supported, omit
        // Sec-WebSocket-Protocol and still complete the opening handshake.
        let selected_protocol = if let Some(requested) = request.header("sec-websocket-protocol") {
            let offered: Vec<String> = requested
                .split(',')
                .map(str::trim)
                .filter(|candidate| !candidate.is_empty())
                .map(ToOwned::to_owned)
                .collect();
            let selected = offered.iter().find(|candidate| {
                self.supported_protocols
                    .iter()
                    .any(|supported| supported.as_str() == candidate.as_str())
            });
            selected.cloned()
        } else {
            None
        };

        let negotiated_extensions =
            request
                .header("sec-websocket-extensions")
                .map_or_else(Vec::new, |requested| {
                    let mut accepted = Vec::new();
                    let mut accepted_tokens = std::collections::BTreeSet::new();
                    for offer in parse_extension_offers(requested) {
                        let token = extension_token(&offer);
                        if token.is_empty() {
                            continue;
                        }
                        if self
                            .supported_extensions
                            .iter()
                            .any(|supported| supported.eq_ignore_ascii_case(token))
                        {
                            let normalized = token.to_ascii_lowercase();
                            if accepted_tokens.insert(normalized) {
                                // Sanitize: strip CR/LF to prevent HTTP response splitting.
                                let safe = offer.replace(['\r', '\n'], "");
                                accepted.push(safe);
                            }
                        }
                    }
                    accepted
                });

        Ok(AcceptResponse {
            accept_key,
            protocol: selected_protocol,
            extensions: negotiated_extensions,
        })
    }

    /// Generate a rejection response with the given HTTP status code.
    #[must_use]
    pub fn reject(status: u16, reason: &str) -> Vec<u8> {
        // Sanitize CRLF to prevent HTTP response header injection.
        let reason = reason.replace(['\r', '\n'], "");
        format!(
            "HTTP/1.1 {status} {reason}\r\n\
             Connection: close\r\n\
             \r\n"
        )
        .into_bytes()
    }
}

/// Result of accepting a WebSocket upgrade.
#[derive(Debug, Clone)]
pub struct AcceptResponse {
    /// Computed Sec-WebSocket-Accept value.
    pub accept_key: String,
    /// Negotiated subprotocol (if any).
    pub protocol: Option<String>,
    /// Negotiated extensions.
    pub extensions: Vec<String>,
}

impl AcceptResponse {
    /// Generate the HTTP 101 response as bytes.
    #[must_use]
    pub fn response_bytes(&self) -> Vec<u8> {
        let mut response = String::from(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n",
        );

        response.push_str("Sec-WebSocket-Accept: ");
        response.push_str(&self.accept_key);
        response.push_str("\r\n");

        if let Some(ref protocol) = self.protocol {
            response.push_str("Sec-WebSocket-Protocol: ");
            response.push_str(protocol);
            response.push_str("\r\n");
        }

        if !self.extensions.is_empty() {
            response.push_str("Sec-WebSocket-Extensions: ");
            response.push_str(&self.extensions.join(", "));
            response.push_str("\r\n");
        }

        response.push_str("\r\n");
        response.into_bytes()
    }
}

/// Minimal HTTP request representation for handshake.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method (should be GET for WebSocket).
    pub method: String,
    /// Request path.
    pub path: String,
    /// HTTP headers (lowercase keys).
    headers: BTreeMap<String, String>,
}

impl HttpRequest {
    /// Parse an HTTP request from bytes, returning the parsed request and any trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns `HandshakeError::InvalidRequest` if parsing fails.
    #[allow(clippy::option_if_let_else)]
    pub fn parse_with_trailing(data: &[u8]) -> Result<(Self, &[u8]), HandshakeError> {
        let (header_bytes, trailing) = split_http_header_block(data)?;

        let text = std::str::from_utf8(header_bytes)
            .map_err(|_| HandshakeError::InvalidRequest("invalid UTF-8".into()))?;

        let mut lines = text.lines();

        // Parse request line
        let request_line = lines
            .next()
            .ok_or_else(|| HandshakeError::InvalidRequest("empty request".into()))?;

        let mut parts = request_line.split_whitespace();
        let method = parts
            .next()
            .ok_or_else(|| HandshakeError::InvalidRequest("missing method".into()))?
            .to_string();
        let path = parts
            .next()
            .ok_or_else(|| HandshakeError::InvalidRequest("missing path".into()))?
            .to_string();

        // Parse headers
        let mut headers = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                insert_header(&mut headers, name, value)?;
            }
        }

        Ok((
            Self {
                method,
                path,
                headers,
            },
            trailing,
        ))
    }

    /// Parse an HTTP request from bytes.
    ///
    /// # Errors
    ///
    /// Returns `HandshakeError::InvalidRequest` if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, HandshakeError> {
        Self::parse_with_trailing(data).map(|(req, _)| req)
    }

    /// Get a header value by name (case-insensitive). The values of a
    /// repeated header are joined with ", ".
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// Minimal HTTP response representation for handshake.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Status reason phrase.
    pub reason: String,
    /// HTTP headers (lowercase keys).
    headers: BTreeMap<String, String>,
}

impl HttpResponse {
    /// Parse an HTTP response from bytes.
    ///
    /// # Errors
    ///
    /// Returns `HandshakeError::InvalidRequest` if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, HandshakeError> {
        let (header_bytes, _trailing) = split_http_header_block(data)?;
        let text = std::str::from_utf8(header_bytes)
            .map_err(|_| HandshakeError::InvalidRequest("invalid UTF-8".into()))?;

        let mut lines = text.lines();

        // Parse status line
        let status_line = lines
            .next()
            .ok_or_else(|| HandshakeError::InvalidRequest("empty response".into()))?;

        let mut parts = status_line.splitn(3, ' ');
        let _version = parts
            .next()
            .ok_or_else(|| HandshakeError::InvalidRequest("missing HTTP version".into()))?;
        let status: u16 = parts
            .next()
            .ok_or_else(|| HandshakeError::InvalidRequest("missing status code".into()))?
            .parse()
            .map_err(|_| HandshakeError::InvalidRequest("invalid status code".into()))?;
        let reason = parts.next().unwrap_or("").to_string();

        // Parse headers
        let mut headers = BTreeMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                insert_header(&mut headers, name, value)?;
            }
        }

        Ok(Self {
            status,
            reason,
            headers,
        })
    }

    /// Get a header value by name (case-insensitive). The values of a
    /// repeated header are joined with ", ".
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[cfg(test)]
#[path = "handshake_inline_tests.rs"]
mod tests;
