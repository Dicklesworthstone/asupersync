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
use std::collections::HashMap;
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
                )))
            }
        };

        let default_port = if tls { 443 } else { 80 };

        // Split host:port from path
        let (host_port, path) = rest
            .find('/')
            .map_or((rest, "/"), |idx| (&rest[..idx], &rest[idx..]));

        // Parse host and port
        let (host, port) = if let Some(bracket_end) = host_port.find(']') {
            // IPv6: [::1]:8080
            let host = &host_port[1..bracket_end];
            let port = if host_port.len() > bracket_end + 1
                && host_port.as_bytes()[bracket_end + 1] == b':'
            {
                host_port[bracket_end + 2..]
                    .parse()
                    .map_err(|_| HandshakeError::InvalidUrl("invalid port".into()))?
            } else {
                default_port
            };
            (host.to_string(), port)
        } else if let Some(colon_idx) = host_port.rfind(':') {
            // host:port
            let host = &host_port[..colon_idx];
            let port = host_port[colon_idx + 1..]
                .parse()
                .map_err(|_| HandshakeError::InvalidUrl("invalid port".into()))?;
            (host.to_string(), port)
        } else {
            (host_port.to_string(), default_port)
        };

        if host.is_empty() {
            return Err(HandshakeError::InvalidUrl("empty host".into()));
        }

        Ok(Self {
            host,
            port,
            path: path.to_string(),
            tls,
        })
    }

    /// Returns the Host header value.
    #[must_use]
    pub fn host_header(&self) -> String {
        let default_port = if self.tls { 443 } else { 80 };
        if self.port == default_port {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
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
    headers: HashMap<String, String>,
}

impl ClientHandshake {
    /// Create a new client handshake for the given URL.
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
            headers: HashMap::new(),
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
            request.push_str(&self.protocols.join(", "));
            request.push_str("\r\n");
        }

        if !self.extensions.is_empty() {
            request.push_str("Sec-WebSocket-Extensions: ");
            request.push_str(&self.extensions.join("; "));
            request.push_str("\r\n");
        }

        for (name, value) in &self.headers {
            request.push_str(name);
            request.push_str(": ");
            request.push_str(value);
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
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(HandshakeError::InvalidRequest(format!(
                "Upgrade header must be 'websocket', got '{upgrade}'"
            )));
        }

        // Check Connection header
        let connection = response
            .header("connection")
            .ok_or(HandshakeError::MissingHeader("Connection"))?;
        if !connection.to_ascii_lowercase().contains("upgrade") {
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
            return Err(HandshakeError::InvalidRequest(format!(
                "method must be GET, got '{}'",
                request.method
            )));
        }

        // Check Upgrade header
        let upgrade = request
            .header("upgrade")
            .ok_or(HandshakeError::MissingHeader("Upgrade"))?;
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(HandshakeError::InvalidRequest(format!(
                "Upgrade header must be 'websocket', got '{upgrade}'"
            )));
        }

        // Check Connection header
        let connection = request
            .header("connection")
            .ok_or(HandshakeError::MissingHeader("Connection"))?;
        if !connection.to_ascii_lowercase().contains("upgrade") {
            return Err(HandshakeError::InvalidRequest(format!(
                "Connection header must contain 'Upgrade', got '{connection}'"
            )));
        }

        // Check WebSocket version
        let version = request
            .header("sec-websocket-version")
            .ok_or(HandshakeError::MissingHeader("Sec-WebSocket-Version"))?;
        if version != "13" {
            return Err(HandshakeError::UnsupportedVersion(version.to_string()));
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

        // Negotiate subprotocol
        let selected_protocol = request
            .header("sec-websocket-protocol")
            .and_then(|requested| {
                let requested: Vec<&str> = requested.split(',').map(str::trim).collect();
                self.supported_protocols
                    .iter()
                    .find(|p| requested.contains(&p.as_str()))
                    .cloned()
            });

        Ok(AcceptResponse {
            accept_key,
            protocol: selected_protocol,
            extensions: Vec::new(), // TODO: Extension negotiation
        })
    }

    /// Generate a rejection response with the given HTTP status code.
    #[must_use]
    pub fn reject(status: u16, reason: &str) -> Vec<u8> {
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
            response.push_str(&self.extensions.join("; "));
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
    headers: HashMap<String, String>,
}

impl HttpRequest {
    /// Parse an HTTP request from bytes.
    ///
    /// # Errors
    ///
    /// Returns `HandshakeError::InvalidRequest` if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, HandshakeError> {
        let text = std::str::from_utf8(data)
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
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        Ok(Self {
            method,
            path,
            headers,
        })
    }

    /// Get a header value by name (case-insensitive).
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
    headers: HashMap<String, String>,
}

impl HttpResponse {
    /// Parse an HTTP response from bytes.
    ///
    /// # Errors
    ///
    /// Returns `HandshakeError::InvalidRequest` if parsing fails.
    pub fn parse(data: &[u8]) -> Result<Self, HandshakeError> {
        let text = std::str::from_utf8(data)
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
        let mut headers = HashMap::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
            }
        }

        Ok(Self {
            status,
            reason,
            headers,
        })
    }

    /// Get a header value by name (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::DetEntropy;

    #[test]
    fn test_compute_accept_key() {
        // RFC 6455 example
        let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = compute_accept_key(client_key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_ws_url_parse() {
        // Basic ws://
        let url = WsUrl::parse("ws://example.com/chat").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/chat");
        assert!(!url.tls);

        // wss:// with port
        let url = WsUrl::parse("wss://example.com:8443/ws").unwrap();
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 8443);
        assert_eq!(url.path, "/ws");
        assert!(url.tls);

        // No path
        let url = WsUrl::parse("ws://localhost:9000").unwrap();
        assert_eq!(url.host, "localhost");
        assert_eq!(url.port, 9000);
        assert_eq!(url.path, "/");

        // IPv6
        let url = WsUrl::parse("ws://[::1]:8080/test").unwrap();
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/test");
    }

    #[test]
    fn test_ws_url_host_header() {
        let url = WsUrl::parse("ws://example.com/chat").unwrap();
        assert_eq!(url.host_header(), "example.com");

        let url = WsUrl::parse("ws://example.com:8080/chat").unwrap();
        assert_eq!(url.host_header(), "example.com:8080");

        let url = WsUrl::parse("wss://example.com/chat").unwrap();
        assert_eq!(url.host_header(), "example.com");

        let url = WsUrl::parse("wss://example.com:443/chat").unwrap();
        assert_eq!(url.host_header(), "example.com");
    }

    #[test]
    fn test_client_handshake_request() {
        let entropy = DetEntropy::new(7);
        let handshake = ClientHandshake::new("ws://example.com/chat", &entropy)
            .unwrap()
            .protocol("chat");

        let request = handshake.request_bytes();
        let text = String::from_utf8(request).unwrap();

        assert!(text.starts_with("GET /chat HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));
        assert!(text.contains("Sec-WebSocket-Key: "));
        assert!(text.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(text.contains("Sec-WebSocket-Protocol: chat\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_client_validate_response() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: HashMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              \r\n",
        )
        .unwrap();

        assert!(handshake.validate_response(&response).is_ok());
    }

    #[test]
    fn test_client_validate_response_bad_accept() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").unwrap(),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: HashMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: wrong-accept-key\r\n\
              \r\n",
        )
        .unwrap();

        let err = handshake.validate_response(&response).unwrap_err();
        assert!(matches!(err, HandshakeError::InvalidAccept { .. }));
    }

    #[test]
    fn test_client_validate_response_unsolicited_protocol_rejected() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec![],
            extensions: vec![],
            headers: HashMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Protocol: chat\r\n\
              \r\n",
        )
        .expect("response must parse");

        let err = handshake
            .validate_response(&response)
            .expect_err("unsolicited protocol must be rejected");
        assert!(matches!(err, HandshakeError::ProtocolMismatch { .. }));
    }

    #[test]
    fn test_client_validate_response_unrequested_protocol_rejected() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec!["chat".to_string()],
            extensions: vec![],
            headers: HashMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Protocol: superchat\r\n\
              \r\n",
        )
        .expect("response must parse");

        let err = handshake
            .validate_response(&response)
            .expect_err("protocol not in request must be rejected");
        assert!(matches!(err, HandshakeError::ProtocolMismatch { .. }));
    }

    #[test]
    fn test_client_validate_response_requested_protocol_accepted() {
        let handshake = ClientHandshake {
            url: WsUrl::parse("ws://example.com/chat").expect("valid url"),
            key: "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            protocols: vec!["chat".to_string(), "superchat".to_string()],
            extensions: vec![],
            headers: HashMap::new(),
        };

        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\
              Sec-WebSocket-Protocol: superchat\r\n\
              \r\n",
        )
        .expect("response must parse");

        assert!(handshake.validate_response(&response).is_ok());
    }

    #[test]
    fn test_server_accept() {
        let server = ServerHandshake::new().protocol("chat");

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              Sec-WebSocket-Protocol: chat\r\n\
              \r\n",
        )
        .unwrap();

        let accept = server.accept(&request).unwrap();
        assert_eq!(accept.accept_key, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(accept.protocol, Some("chat".to_string()));
    }

    #[test]
    fn test_server_reject_bad_version() {
        let server = ServerHandshake::new();

        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 8\r\n\
              \r\n",
        )
        .unwrap();

        let err = server.accept(&request).unwrap_err();
        assert!(matches!(err, HandshakeError::UnsupportedVersion(_)));
    }

    #[test]
    fn test_accept_response_bytes() {
        let accept = AcceptResponse {
            accept_key: "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=".to_string(),
            protocol: Some("chat".to_string()),
            extensions: vec![],
        };

        let response = accept.response_bytes();
        let text = String::from_utf8(response).unwrap();

        assert!(text.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        assert!(text.contains("Upgrade: websocket\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));
        assert!(text.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert!(text.contains("Sec-WebSocket-Protocol: chat\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn test_http_request_parse() {
        let request = HttpRequest::parse(
            b"GET /chat HTTP/1.1\r\n\
              Host: example.com\r\n\
              Upgrade: WebSocket\r\n\
              Connection: Upgrade\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/chat");
        assert_eq!(request.header("host"), Some("example.com"));
        assert_eq!(request.header("upgrade"), Some("WebSocket"));
        assert_eq!(request.header("connection"), Some("Upgrade"));
    }

    #[test]
    fn test_http_response_parse() {
        let response = HttpResponse::parse(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: xyz\r\n\
              \r\n",
        )
        .unwrap();

        assert_eq!(response.status, 101);
        assert_eq!(response.reason, "Switching Protocols");
        assert_eq!(response.header("upgrade"), Some("websocket"));
        assert_eq!(response.header("sec-websocket-accept"), Some("xyz"));
    }

    #[test]
    fn test_generate_client_key() {
        let entropy = DetEntropy::new(42);
        let key = generate_client_key(&entropy);
        // Should be valid base64 of 16 bytes = 24 chars with padding
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&key)
            .unwrap();
        assert_eq!(decoded.len(), 16);
    }
}
