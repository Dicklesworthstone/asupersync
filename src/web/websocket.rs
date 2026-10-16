//! WebSocket HTTP upgrade handler for the web framework.
//!
//! Provides [`crate::web::websocket::WebSocketUpgrade`] as an extractor that
//! validates WebSocket upgrade requests and produces the 101 Switching Protocols response.
//! After the upgrade, the connection transitions into a `ServerWebSocket`
//! for bidirectional message exchange.
//!
//! # Example
//!
//! ```
//! use asupersync::web::Response;
//! use asupersync::web::websocket::{Message, WebSocketUpgrade};
//!
//! fn ws_handler(upgrade: WebSocketUpgrade) -> Response {
//!     // Answers 101; the callback runs once the response is flushed, with the
//!     // connection's `Cx` and a `ServerWebSocket`.
//!     upgrade.protocols(["chat"]).on_upgrade(|cx, mut ws| async move {
//!         while let Ok(Some(msg)) = ws.recv(&cx).await {
//!             match msg {
//!                 Message::Text(text) => {
//!                     if ws.send(&cx, Message::text(format!("echo: {text}"))).await.is_err() {
//!                         break;
//!                     }
//!                 }
//!                 Message::Close(_) => break,
//!                 _ => {}
//!             }
//!         }
//!     })
//! }
//! ```
//!
//! # Design
//!
//! The upgrade flow follows RFC 6455:
//!
//! 1. Client sends `GET` with `Upgrade: websocket` and `Sec-WebSocket-Key`
//! 2. [`FromRequest::from_request`] validates the headers
//! 3. Handler calls [`IntoResponse::into_response`] to produce 101
//! 4. After 101 is written, the transport switches to WebSocket framing
//!
//! The actual bidirectional communication uses `ServerWebSocket`.

#[cfg(not(target_arch = "wasm32"))]
use crate::net::websocket::AcceptResponse;
use crate::net::websocket::{WebSocketAcceptor, compute_accept_key};
#[cfg(not(target_arch = "wasm32"))]
use crate::{
    Cx,
    http::h1::{Http1Upgrade, Http1UpgradedIo},
    net::tcp::stream::TcpStream,
};
#[cfg(not(target_arch = "wasm32"))]
use std::future::Future;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;

use super::extract::{ExtractionError, FromRequest, Request};
use super::response::{IntoResponse, Response, StatusCode};

// Re-export the key types users need for WebSocket communication.
pub use crate::net::websocket::{CloseReason, Message, ServerWebSocket};

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Default)]
pub(crate) struct Http1UpgradeSlot {
    state: Arc<parking_lot::Mutex<Http1UpgradeSlotState>>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Default)]
enum Http1UpgradeSlotState {
    #[default]
    Empty,
    Registered(Http1Upgrade),
    Rejected,
}

#[cfg(not(target_arch = "wasm32"))]
impl std::fmt::Debug for Http1UpgradeSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http1UpgradeSlot")
            .field(
                "state",
                &match &*self.state.lock() {
                    Http1UpgradeSlotState::Empty => "empty",
                    Http1UpgradeSlotState::Registered(_) => "registered",
                    Http1UpgradeSlotState::Rejected => "rejected",
                },
            )
            .finish()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Http1UpgradeSlot {
    pub(crate) fn register(&self, action: Http1Upgrade) -> Result<(), Http1Upgrade> {
        let mut state = self.state.lock();
        if matches!(*state, Http1UpgradeSlotState::Empty) {
            *state = Http1UpgradeSlotState::Registered(action);
            Ok(())
        } else {
            // Poison the whole request on a duplicate attempt. Otherwise a
            // handler could ignore the second 500 and return the first 101,
            // accidentally committing a callback after violating one-shot
            // registration.
            *state = Http1UpgradeSlotState::Rejected;
            Err(action)
        }
    }

    pub(crate) fn take(&self) -> Result<Option<Http1Upgrade>, ()> {
        match std::mem::take(&mut *self.state.lock()) {
            Http1UpgradeSlotState::Empty => Ok(None),
            Http1UpgradeSlotState::Registered(action) => Ok(Some(action)),
            Http1UpgradeSlotState::Rejected => Err(()),
        }
    }
}

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
/// Origin-validation policy applied during the WebSocket upgrade response.
///
/// Defends against Cross-Site WebSocket Hijacking (CSWSH): browsers
/// initiate WebSocket handshakes under the same-origin policy of HTTP
/// (i.e. they don't enforce one), so without server-side `Origin`
/// validation an attacker page at `evil.example` can open a WebSocket
/// to `legit.example` from a victim's browser session.
/// (br-asupersync-o2t5gz)
#[derive(Debug, Clone, Default)]
pub enum OriginPolicy {
    /// Default. Reject the upgrade unless the request's `Origin` host:port
    /// matches its `Host` header (case-insensitive). Requests with NO
    /// `Origin` header are accepted on the assumption that they come
    /// from a non-browser client (browsers always emit `Origin` for
    /// WebSocket handshakes per RFC 6455 §10.2).
    #[default]
    SameOrigin,
    /// Accept the upgrade if the request's `Origin` value (full URL,
    /// case-insensitive) appears in the allowlist. An empty allowlist
    /// rejects every request that has an `Origin` header. Requests with
    /// no `Origin` header are accepted (non-browser clients).
    AllowList(Vec<String>),
    /// No `Origin` validation. Opt-in for tests and non-browser
    /// integrations that don't need CSWSH defense.
    Disabled,
}

/// Builder returned by the WebSocket extractor after validating an upgrade request.
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
    /// `Origin` header from the upgrade request (br-asupersync-o2t5gz).
    /// `None` if the client didn't send one (typically a non-browser
    /// client; browsers always send `Origin` per RFC 6455 §10.2).
    origin: Option<String>,
    /// `Host` header from the upgrade request, used to evaluate
    /// `OriginPolicy::SameOrigin`.
    host: Option<String>,
    /// Origin-validation policy applied at response time. Defaults to
    /// `SameOrigin` so any caller that forgets to call `.allow_origins()`
    /// or `.skip_origin_check()` still gets CSWSH defense.
    origin_policy: OriginPolicy,
    /// Decoded message limit for the accepted connection; `None` keeps the
    /// acceptor default.
    max_message_size: Option<usize>,
    /// Frame payload limit for the accepted connection; `None` keeps the
    /// acceptor default.
    max_frame_size: Option<usize>,
    #[cfg(not(target_arch = "wasm32"))]
    http1_upgrade_slot: Option<Http1UpgradeSlot>,
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
        if !header_has_token(upgrade, "websocket") {
            return Err(ExtractionError::bad_request(format!(
                "Upgrade header must contain 'websocket', got '{upgrade}'"
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

        // Capture Origin + Host for CSWSH defense (br-asupersync-o2t5gz).
        // The actual policy decision happens in `IntoResponse` so a caller
        // can override the default via `.allow_origins()` or
        // `.skip_origin_check()` before returning the upgrade.
        let origin = req.header("origin").map(ToOwned::to_owned);
        let host = req.header("host").map(ToOwned::to_owned);
        #[cfg(not(target_arch = "wasm32"))]
        let http1_upgrade_slot = req.extensions.get_typed_cloned::<Http1UpgradeSlot>();

        Ok(Self {
            accept_key,
            requested_protocols,
            requested_extensions,
            selected_protocol: None,
            selected_extensions: Vec::new(),
            origin,
            host,
            origin_policy: OriginPolicy::default(),
            max_message_size: None,
            max_frame_size: None,
            #[cfg(not(target_arch = "wasm32"))]
            http1_upgrade_slot,
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

/// Strip the `scheme://` prefix from an `Origin` value, returning the
/// authority component (`host[:port]`) for same-origin comparison against
/// the `Host` header. Falls back to the raw value if no scheme is found
/// (an invalid Origin would then fail the comparison, which is the
/// fail-closed behavior we want). (br-asupersync-o2t5gz)
fn strip_origin_scheme(origin: &str) -> &str {
    if let Some(idx) = origin.find("://") {
        // RFC 6454 origins must not have a path; if one is present we
        // truncate at the first '/' so a malformed Origin like
        // `https://victim.com/../attacker.com:443` cannot smuggle an
        // attacker host past the comparison.
        let after_scheme = &origin[idx + 3..];
        match after_scheme.find('/') {
            Some(slash) => &after_scheme[..slash],
            None => after_scheme,
        }
    } else {
        origin
    }
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

    /// Get the request's `Origin` header value, if present.
    /// (br-asupersync-o2t5gz)
    #[must_use]
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }

    /// Override the origin-validation policy with an explicit allowlist.
    /// Origins are matched case-insensitively against the request's full
    /// `Origin` value. (br-asupersync-o2t5gz)
    #[must_use]
    pub fn allow_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.origin_policy = OriginPolicy::AllowList(origins.into_iter().map(Into::into).collect());
        self
    }

    /// Disable origin validation entirely. Opt-in for tests and
    /// non-browser integrations that do not need CSWSH defense.
    /// (br-asupersync-o2t5gz)
    #[must_use]
    pub fn skip_origin_check(mut self) -> Self {
        self.origin_policy = OriginPolicy::Disabled;
        self
    }

    /// Bound each decoded message of the accepted connection, in bytes.
    ///
    /// Defaults to the acceptor's limit (64 MiB). With permessage-deflate a
    /// peer can send a few kilobytes that inflate up to this limit, so a
    /// server facing untrusted peers should set it to the largest message it
    /// actually expects (br-asupersync-ydis91).
    #[must_use]
    pub fn max_message_size(mut self, bytes: usize) -> Self {
        self.max_message_size = Some(bytes);
        self
    }

    /// Bound each frame payload of the accepted connection, in bytes.
    ///
    /// Defaults to the acceptor's limit.
    #[must_use]
    pub fn max_frame_size(mut self, bytes: usize) -> Self {
        self.max_frame_size = Some(bytes);
        self
    }

    /// Commit this handshake to a live HTTP/1 WebSocket session.
    ///
    /// The callback is registered in the current request's one-shot listener
    /// slot. It runs inline in the listener connection task only after the
    /// `101 Switching Protocols` response is completely flushed, with the
    /// listener-owned [`Cx`] and every codec-prefetched byte preserved.
    /// Calling this through a non-HTTP/1 router adapter fails closed with a
    /// `500` response because no transport slot exists.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn on_upgrade<F, Fut>(self, callback: F) -> Response
    where
        F: FnOnce(Cx, ServerWebSocket<TcpStream>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.commit_upgrade(|acceptor, accept_response| {
            Http1Upgrade::new(move |cx, io, read_ahead| async move {
                let websocket = acceptor.finish_upgrade(io, accept_response, &read_ahead);
                callback(cx, websocket).await;
            })
        })
    }

    /// [`Self::on_upgrade`] on any transport the HTTP/1 listener serves: its
    /// TCP connections, TLS (`wss://` through `Http1Listener::run_tls`), a
    /// Unix-domain socket, or a connection handed over by `HttpAutoListener`.
    ///
    /// `on_upgrade`'s callback receives the TCP stream, so those other
    /// transports refuse it; this callback receives the transport as an
    /// [`Http1UpgradedIo`]. Everything else (origin policy, negotiation, the
    /// `101`, read-ahead) is the same.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn on_upgrade_any<F, Fut>(self, callback: F) -> Response
    where
        F: FnOnce(Cx, ServerWebSocket<Http1UpgradedIo>) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.commit_upgrade(|acceptor, accept_response| {
            Http1Upgrade::new_any(move |cx, io, read_ahead| async move {
                let websocket = acceptor.finish_upgrade(io, accept_response, &read_ahead);
                callback(cx, websocket).await;
            })
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn commit_upgrade(
        mut self,
        action: impl FnOnce(WebSocketAcceptor, AcceptResponse) -> Http1Upgrade,
    ) -> Response {
        if let Err(reason) = self.evaluate_origin() {
            return Self::plain_response(StatusCode::FORBIDDEN, reason);
        }
        match crate::net::websocket::compression::negotiate(&self.selected_extensions) {
            Ok(selected) => self.selected_extensions = selected,
            Err(_) => return Self::plain_response(
                StatusCode::NOT_IMPLEMENTED,
                "selected WebSocket extension parameters are unsupported",
            ),
        }
        let Some(slot) = self.http1_upgrade_slot.clone() else {
            return Self::plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "HTTP/1 WebSocket upgrade transport unavailable",
            );
        };

        let response = self.switching_protocols_response();
        let accept_response = AcceptResponse {
            accept_key: self.accept_key.clone(),
            protocol: self.selected_protocol.clone(),
            extensions: self.selected_extensions.clone(),
        };
        let acceptor = self.acceptor();
        let action = action(acceptor, accept_response).with_websocket_negotiation(
            self.selected_protocol.clone(),
            self.selected_extensions.clone(),
        );
        if slot.register(action).is_err() {
            return Self::plain_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "HTTP/1 WebSocket upgrade callback already registered",
            );
        }
        response
    }

    fn plain_response(status: StatusCode, body: &'static str) -> Response {
        Response::new(status, crate::bytes::Bytes::from_static(body.as_bytes()))
            .header("content-type", "text/plain; charset=utf-8")
    }

    fn switching_protocols_response(&self) -> Response {
        let mut response = Response::empty(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", &self.accept_key);

        if let Some(ref protocol) = self.selected_protocol {
            response = response.header("sec-websocket-protocol", protocol);
        }

        if !self.selected_extensions.is_empty() {
            response = response.header(
                "sec-websocket-extensions",
                self.selected_extensions.join(", "),
            );
        }

        response
    }

    /// Evaluate the configured `OriginPolicy` against the captured
    /// `Origin` / `Host` headers. `Ok(())` means the upgrade may proceed;
    /// `Err(reason)` means the response must be a 403. Browsers always
    /// emit `Origin` for WebSocket handshakes per RFC 6455 §10.2, so a
    /// missing `Origin` is treated as a non-browser client and accepted.
    /// (br-asupersync-o2t5gz)
    fn evaluate_origin(&self) -> Result<(), &'static str> {
        match (&self.origin_policy, self.origin.as_deref()) {
            (OriginPolicy::Disabled, _) => Ok(()),
            (_, None) => Ok(()),
            (OriginPolicy::AllowList(list), Some(origin)) => {
                if list
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(origin))
                {
                    Ok(())
                } else {
                    Err("Origin not in allowlist")
                }
            }
            (OriginPolicy::SameOrigin, Some(origin)) => {
                let Some(host) = self.host.as_deref() else {
                    return Err("Origin present but no Host header to compare");
                };
                let origin_authority = strip_origin_scheme(origin);
                if origin_authority.eq_ignore_ascii_case(host) {
                    Ok(())
                } else {
                    Err("Origin does not match Host (cross-origin request rejected)")
                }
            }
        }
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
        if let Some(bytes) = self.max_message_size {
            acceptor = acceptor.max_message_size(bytes);
        }
        if let Some(bytes) = self.max_frame_size {
            acceptor = acceptor.max_frame_size(bytes);
        }
        acceptor
    }
}

impl IntoResponse for WebSocketUpgrade {
    fn into_response(self) -> Response {
        // Default-deny CSWSH defense (br-asupersync-o2t5gz). Rejected
        // origins get a 403 Forbidden instead of the 101 switch. Body is
        // a fixed string and the rejected Origin is NOT echoed back, so
        // the response is not itself a per-request oracle.
        if let Err(reason) = self.evaluate_origin() {
            return Self::plain_response(StatusCode::FORBIDDEN, reason);
        }
        self.switching_protocols_response()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "websocket_inline_tests.rs"]
mod tests;
