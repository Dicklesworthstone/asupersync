//! WebSocket HTTP upgrade handler for the web framework.
//!
//! Provides [`WebSocketUpgrade`] as an extractor that validates WebSocket
//! upgrade requests and produces the 101 Switching Protocols response.
//! After the upgrade, the connection transitions into a [`WebSocket`]
//! for bidirectional message exchange.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::websocket::{WebSocketUpgrade, WebSocket, Message};
//!
//! async fn ws_handler(upgrade: WebSocketUpgrade) -> Response {
//!     upgrade.protocols(["chat"]).into_response()
//! }
//!
//! // After upgrade, use the WebSocket:
//! // while let Some(msg) = ws.recv(&cx).await? { ... }
//! ```
//!
//! # Design
//!
//! The upgrade flow follows RFC 6455:
//!
//! 1. Client sends `GET` with `Upgrade: websocket` and `Sec-WebSocket-Key`
//! 2. [`WebSocketUpgrade::from_request`] validates the headers
//! 3. Handler calls [`WebSocketUpgrade::into_response`] to produce 101
//! 4. After 101 is written, the transport switches to WebSocket framing
//!
//! The actual bidirectional communication uses [`WebSocket`], which wraps
//! the existing `net::websocket::ServerWebSocket` with an ergonomic API.

use crate::net::websocket::{WebSocketAcceptor, compute_accept_key};

use super::extract::{ExtractionError, FromRequest, Request};
use super::response::{IntoResponse, Response, StatusCode};

// Re-export the key types users need for WebSocket communication.
pub use crate::net::websocket::{CloseReason, Message, ServerWebSocket};

/// WebSocket upgrade extractor.
///
/// Validates that an incoming HTTP request is a valid WebSocket upgrade
/// request per RFC 6455 Section 4.2.1. If validation succeeds, the
/// extractor holds the computed accept key and can produce the 101
/// Switching Protocols response.
///
/// # Validation
///
/// The extractor checks:
/// - HTTP method is GET
/// - `Upgrade` header contains "websocket" (case-insensitive)
/// - `Connection` header contains "Upgrade" (case-insensitive)
/// - `Sec-WebSocket-Version` is "13"
/// - `Sec-WebSocket-Key` is present and valid base64 of 16 bytes
///
/// # Rejection
///
/// Returns 400 Bad Request if any validation check fails.
#[derive(Debug, Clone)]
pub struct WebSocketUpgrade {
    /// Computed Sec-WebSocket-Accept value.
    accept_key: String,
    /// Client's requested subprotocols.
    requested_protocols: Vec<String>,
    /// Client's requested extensions.
    requested_extensions: Vec<String>,
    /// Selected subprotocol (set via `.protocols()`).
    selected_protocol: Option<String>,
    /// Selected extensions (set via `.extensions()`).
    selected_extensions: Vec<String>,
}

impl FromRequest for WebSocketUpgrade {
    fn from_request(req: Request) -> Result<Self, ExtractionError> {
        // Validate method is GET.
        if req.method != "GET" {
            return Err(ExtractionError::bad_request(format!(
                "method must be GET, got {}",
                req.method
            )));
        }

        // Validate Upgrade header.
        let upgrade = req
            .header("upgrade")
            .ok_or_else(|| ExtractionError::bad_request("missing Upgrade header"))?;
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(ExtractionError::bad_request(format!(
                "Upgrade header must be 'websocket', got '{upgrade}'"
            )));
        }

        // Validate Connection header contains "Upgrade".
        let connection = req
            .header("connection")
            .ok_or_else(|| ExtractionError::bad_request("missing Connection header"))?;
        if !header_has_token(connection, "upgrade") {
            return Err(ExtractionError::bad_request(format!(
                "Connection header must contain 'Upgrade', got '{connection}'"
            )));
        }

        // Validate Sec-WebSocket-Version.
        let version = req
            .header("sec-websocket-version")
            .ok_or_else(|| ExtractionError::bad_request("missing Sec-WebSocket-Version header"))?;
        if version != "13" {
            return Err(ExtractionError::bad_request(format!(
                "unsupported WebSocket version: {version}"
            )));
        }

        // Validate and extract Sec-WebSocket-Key.
        let key = req
            .header("sec-websocket-key")
            .ok_or_else(|| ExtractionError::bad_request("missing Sec-WebSocket-Key header"))?;

        // Validate key is valid base64 of 16 bytes.
        match base64::engine::general_purpose::STANDARD.decode(key) {
            Ok(bytes) if bytes.len() == 16 => {}
            _ => {
                return Err(ExtractionError::bad_request(
                    "Sec-WebSocket-Key must be 16 bytes of base64",
                ));
            }
        }

        let accept_key = compute_accept_key(key);

        // Parse requested protocols.
        let requested_protocols = req
            .header("sec-websocket-protocol")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        // Parse requested extensions.
        let requested_extensions = req
            .header("sec-websocket-extensions")
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            accept_key,
            requested_protocols,
            requested_extensions,
            selected_protocol: None,
            selected_extensions: Vec::new(),
        })
    }
}

use base64::Engine;

fn header_has_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .map(str::trim)
        .any(|part| part.eq_ignore_ascii_case(token))
}

impl WebSocketUpgrade {
    /// Select a subprotocol from the client's requested list.
    ///
    /// The server picks the first protocol from `supported` that appears
    /// in the client's `Sec-WebSocket-Protocol` header. If none match,
    /// no protocol is selected (which is valid per RFC 6455).
    #[must_use]
    pub fn protocols<I, S>(mut self, supported: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let supported: Vec<String> = supported
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();

        self.selected_protocol = self
            .requested_protocols
            .iter()
            .find(|requested| supported.iter().any(|s| s.eq_ignore_ascii_case(requested)))
            .cloned();

        self
    }

    /// Select extensions to accept from the client's requested list.
    #[must_use]
    pub fn extensions<I, S>(mut self, supported: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let supported: Vec<String> = supported
            .into_iter()
            .map(|s| s.as_ref().to_string())
            .collect();

        self.selected_extensions = self
            .requested_extensions
            .iter()
            .filter(|requested| {
                let token = requested.split(';').next().unwrap_or("").trim();
                supported.iter().any(|s| s.eq_ignore_ascii_case(token))
            })
            .cloned()
            .collect();

        self
    }

    /// Get the computed Sec-WebSocket-Accept key.
    #[must_use]
    pub fn accept_key(&self) -> &str {
        &self.accept_key
    }

    /// Get the client's requested protocols.
    #[must_use]
    pub fn requested_protocols(&self) -> &[String] {
        &self.requested_protocols
    }

    /// Get the client's requested extensions.
    #[must_use]
    pub fn requested_extensions(&self) -> &[String] {
        &self.requested_extensions
    }

    /// Get the selected protocol (if any).
    #[must_use]
    pub fn selected_protocol(&self) -> Option<&str> {
        self.selected_protocol.as_deref()
    }

    /// Build a [`WebSocketAcceptor`] configured with the negotiated
    /// protocols and extensions.
    #[must_use]
    pub fn acceptor(&self) -> WebSocketAcceptor {
        let mut acceptor = WebSocketAcceptor::new();
        if let Some(ref proto) = self.selected_protocol {
            acceptor = acceptor.protocol(proto.clone());
        }
        for ext in &self.selected_extensions {
            acceptor = acceptor.extension(ext.clone());
        }
        acceptor
    }
}

impl IntoResponse for WebSocketUpgrade {
    fn into_response(self) -> Response {
        let mut resp = Response::empty(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", &self.accept_key);

        if let Some(ref protocol) = self.selected_protocol {
            resp = resp.header("sec-websocket-protocol", protocol);
        }

        if !self.selected_extensions.is_empty() {
            resp = resp.header(
                "sec-websocket-extensions",
                self.selected_extensions.join(", "),
            );
        }

        resp
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytes::Bytes;
    use crate::net::websocket::ServerHandshake;

    /// Build a valid WebSocket upgrade request.
    fn ws_request() -> Request {
        Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
    }

    // ─── Extraction tests ─────────────────────────────────────────────

    #[test]
    fn valid_upgrade_request_extracts_successfully() {
        let req = ws_request();
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        // RFC 6455 example: dGhlIHNhbXBsZSBub25jZQ== → s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn valid_upgrade_request_accepts_mixed_case_header_names() {
        let req = Request::new("GET", "/ws")
            .with_header("UpGrAdE", "websocket")
            .with_header("cOnNeCtIoN", "Upgrade")
            .with_header("SeC-WebSocket-Version", "13")
            .with_header("sEc-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");

        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn rejects_non_get_method() {
        let req = Request::new("POST", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("GET"));
    }

    #[test]
    fn rejects_missing_upgrade_header() {
        let req = Request::new("GET", "/ws")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Upgrade"));
    }

    #[test]
    fn rejects_wrong_upgrade_value() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "h2c")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("websocket"));
    }

    #[test]
    fn rejects_missing_connection_header() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Connection"));
    }

    #[test]
    fn rejects_connection_without_upgrade() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "keep-alive")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Upgrade"));
    }

    #[test]
    fn rejects_connection_with_upgrade_only_as_substring() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "notupgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Upgrade"));
    }

    #[test]
    fn rejects_missing_version() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Version"));
    }

    #[test]
    fn rejects_unsupported_version() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "8")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("version"));
    }

    #[test]
    fn rejects_missing_key() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Key"));
    }

    #[test]
    fn rejects_invalid_key() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "not-valid-base64!!!");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Key"));
    }

    #[test]
    fn rejects_short_key() {
        // Valid base64 but only 8 bytes (need 16).
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "AAAAAAAAAAA=");

        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        assert!(err.message.contains("Key"));
    }

    // ─── Case insensitivity ───────────────────────────────────────────

    #[test]
    fn accepts_case_insensitive_upgrade_header() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "WebSocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        assert!(WebSocketUpgrade::from_request(req).is_ok());
    }

    #[test]
    fn accepts_connection_upgrade_mixed_case() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "keep-alive, Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        assert!(WebSocketUpgrade::from_request(req).is_ok());
    }

    // ─── Protocol negotiation ─────────────────────────────────────────

    #[test]
    fn protocol_negotiation_selects_first_match() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "chat, superchat");

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["superchat", "chat"]);

        // Client requested "chat" first, and we support both → "chat" wins.
        assert_eq!(upgrade.selected_protocol(), Some("chat"));
    }

    #[test]
    fn protocol_negotiation_no_match() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "mqtt");

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["chat"]);

        assert_eq!(upgrade.selected_protocol(), None);
    }

    #[test]
    fn no_protocol_requested() {
        let req = ws_request();
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        assert!(upgrade.requested_protocols().is_empty());
        assert_eq!(upgrade.selected_protocol(), None);
    }

    // ─── Extension negotiation ────────────────────────────────────────

    #[test]
    fn extension_negotiation_filters_supported() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header(
                "sec-websocket-extensions",
                "permessage-deflate; client_max_window_bits, x-unsupported",
            );

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .extensions(["permessage-deflate"]);

        assert_eq!(upgrade.selected_extensions.len(), 1);
        assert!(upgrade.selected_extensions[0].contains("permessage-deflate"));
    }

    // ─── IntoResponse ─────────────────────────────────────────────────

    #[test]
    fn into_response_produces_101() {
        let req = ws_request();
        let resp = WebSocketUpgrade::from_request(req).unwrap().into_response();

        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(resp.headers.get("upgrade").unwrap(), "websocket");
        assert_eq!(resp.headers.get("connection").unwrap(), "Upgrade");
        assert_eq!(
            resp.headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn into_response_includes_selected_protocol() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "graphql-ws, graphql-transport-ws");

        let resp = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["graphql-transport-ws"])
            .into_response();

        assert_eq!(
            resp.headers.get("sec-websocket-protocol").unwrap(),
            "graphql-transport-ws"
        );
    }

    #[test]
    fn into_response_omits_protocol_when_none_selected() {
        let req = ws_request();
        let resp = WebSocketUpgrade::from_request(req).unwrap().into_response();

        assert!(!resp.headers.contains_key("sec-websocket-protocol"));
    }

    #[test]
    fn into_response_includes_selected_extensions() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-extensions", "permessage-deflate");

        let resp = WebSocketUpgrade::from_request(req)
            .unwrap()
            .extensions(["permessage-deflate"])
            .into_response();

        assert!(
            resp.headers
                .get("sec-websocket-extensions")
                .unwrap()
                .contains("permessage-deflate")
        );
    }

    // ─── Rejection response ───────────────────────────────────────────

    #[test]
    fn extraction_error_produces_400() {
        use super::super::extract::ExtractionError;

        let err = ExtractionError::bad_request("test rejection");
        let resp = err.into_response();
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn non_ws_request_produces_400_via_extraction() {
        let req = Request::new("POST", "/ws");
        let err = WebSocketUpgrade::from_request(req).unwrap_err();
        let resp = err.into_response();
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    // ─── Acceptor builder ─────────────────────────────────────────────

    #[test]
    fn acceptor_built_with_negotiated_protocol() {
        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "chat");

        let upgrade = WebSocketUpgrade::from_request(req)
            .unwrap()
            .protocols(["chat"]);

        let acceptor = upgrade.acceptor();
        let dbg = format!("{acceptor:?}");
        assert!(dbg.contains("WebSocketAcceptor"));
    }

    // ─── Message re-exports ───────────────────────────────────────────

    #[test]
    fn message_text_construction() {
        let msg = Message::text("hello");
        assert!(matches!(msg, Message::Text(_)));
    }

    #[test]
    fn message_binary_construction() {
        let msg = Message::binary(vec![1, 2, 3]);
        assert!(matches!(msg, Message::Binary(_)));
    }

    #[test]
    fn message_close_construction() {
        let msg = Message::Close(Some(CloseReason::normal()));
        assert!(matches!(msg, Message::Close(Some(_))));
    }

    #[test]
    fn message_ping_pong() {
        let heartbeat_ping = Message::Ping(Bytes::from_static(b"ping"));
        assert!(matches!(heartbeat_ping, Message::Ping(_)));

        let control_reply = Message::Pong(Bytes::from_static(b"pong"));
        assert!(matches!(control_reply, Message::Pong(_)));
    }

    // ─── Data type trait coverage ─────────────────────────────────────

    #[test]
    fn websocket_upgrade_debug_clone() {
        let req = ws_request();
        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        let dbg = format!("{upgrade:?}");
        assert!(dbg.contains("WebSocketUpgrade"));
        assert!(dbg.contains("accept_key"));
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn extraction_error_debug_clone() {
        let err = ExtractionError::bad_request("test rejection");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("ExtractionError"));
        assert_eq!(err.message, "test rejection");
    }

    // ─── Accept key correctness ───────────────────────────────────────

    #[test]
    fn accept_key_rfc6455_vector() {
        // The canonical test vector from RFC 6455 Section 4.2.2.
        let req = Request::new("GET", "/chat")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==");

        let upgrade = WebSocketUpgrade::from_request(req).unwrap();
        assert_eq!(upgrade.accept_key(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn accept_key_different_keys_produce_different_accepts() {
        let key1 = ws_request();
        let key2 = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "AAAAAAAAAAAAAAAAAAAAAA==");

        let u1 = WebSocketUpgrade::from_request(key1).unwrap();
        let u2 = WebSocketUpgrade::from_request(key2).unwrap();
        assert_ne!(u1.accept_key(), u2.accept_key());
    }

    // ─── Full handler integration ─────────────────────────────────────

    #[test]
    fn handler_pattern_produces_correct_response() {
        // Simulate a handler that receives WebSocketUpgrade and returns Response.
        fn ws_handler(req: Request) -> Response {
            let upgrade = match WebSocketUpgrade::from_request(req) {
                Ok(u) => u,
                Err(rej) => return rej.into_response(),
            };
            upgrade.protocols(["chat"]).into_response()
        }

        let req = Request::new("GET", "/ws")
            .with_header("upgrade", "websocket")
            .with_header("connection", "Upgrade")
            .with_header("sec-websocket-version", "13")
            .with_header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .with_header("sec-websocket-protocol", "chat, superchat");

        let resp = ws_handler(req);
        assert_eq!(resp.status, StatusCode::SWITCHING_PROTOCOLS);
        assert_eq!(resp.headers.get("upgrade").unwrap(), "websocket");
        assert_eq!(resp.headers.get("connection").unwrap(), "Upgrade");
        assert_eq!(
            resp.headers.get("sec-websocket-accept").unwrap(),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        assert_eq!(resp.headers.get("sec-websocket-protocol").unwrap(), "chat");
    }

    #[test]
    fn handler_pattern_rejects_non_ws_request() {
        fn ws_handler(req: Request) -> Response {
            let upgrade = match WebSocketUpgrade::from_request(req) {
                Ok(u) => u,
                Err(rej) => return rej.into_response(),
            };
            upgrade.into_response()
        }

        // Normal HTTP request (not a WebSocket upgrade).
        let req = Request::new("GET", "/ws");
        let resp = ws_handler(req);
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }

    // ─── ServerHandshake compatibility ────────────────────────────────

    #[test]
    fn upgrade_accept_key_matches_server_handshake() {
        // Verify our accept key matches what the net::websocket layer computes.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let our_accept = compute_accept_key(key);

        let server = ServerHandshake::new();
        let http_req = crate::net::websocket::HttpRequest::parse(
            format!(
                "GET /ws HTTP/1.1\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {key}\r\n\
                 Sec-WebSocket-Version: 13\r\n\
                 \r\n"
            )
            .as_bytes(),
        )
        .unwrap();

        let accept_response = server.accept(&http_req).unwrap();
        assert_eq!(our_accept, accept_response.accept_key);
    }
}
