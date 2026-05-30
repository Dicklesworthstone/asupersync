//! NATS client with Cx integration.
//!
//! This module provides a pure Rust NATS client implementing the NATS
//! text protocol with Cx integration for cancel-correct publish/subscribe.
//!
//! # Protocol Reference
//! Based on NATS protocol: <https://docs.nats.io/reference/reference-protocols/nats-protocol>
//!
//! # Example
//! ```ignore
//! let client = NatsClient::connect(cx, "nats://localhost:4222").await?;
//! client.publish(cx, "foo.bar", b"hello").await?;
//! let mut sub = client.subscribe(cx, "foo.*").await?;
//! let msg = sub.next(cx).await?;
//! ```

use crate::channel::mpsc;
use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
#[cfg(feature = "tls")]
use crate::tls::{TlsConnector, TlsConnectorBuilder, TlsStream};
use crate::tracing_compat::warn;
use crate::types::Time;
use base64::{
    Engine as _,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use nkeys::{KeyPair, KeyPairType};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;
use subtle::ConstantTimeEq;

const REQUEST_TIMEOUT_MESSAGE: &str = "request timeout";

fn timeout_now(cx: &Cx) -> Time {
    cx.timer_driver()
        .map_or_else(crate::time::wall_now, |driver| driver.now())
}

fn request_timeout_error() -> NatsError {
    NatsError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        REQUEST_TIMEOUT_MESSAGE,
    ))
}

/// Error type for NATS operations.
#[derive(Debug)]
pub enum NatsError {
    /// I/O error during communication.
    Io(io::Error),
    /// Protocol error (malformed NATS message).
    Protocol(String),
    /// Invalid authentication configuration or malformed credentials.
    InvalidAuth(String),
    /// Server returned an error response (-ERR).
    Server(String),
    /// Invalid URL format.
    InvalidUrl(String),
    /// Operation cancelled.
    Cancelled,
    /// Connection closed.
    Closed,
    /// Subscription not found.
    SubscriptionNotFound(u64),
    /// Connection not established.
    NotConnected,
    /// TLS upgrade required by the server INFO frame OR mandated by
    /// the client config (`require_tls = true`), but the current
    /// build/config cannot create a TLS connector. The client fails
    /// closed before sending CONNECT to avoid leaking credentials in
    /// cleartext (br-asupersync-2kmc12).
    TlsRequired {
        /// True if the server's INFO frame set `tls_required`.
        server_required: bool,
        /// True if the client config set `require_tls`.
        client_required: bool,
    },
    /// TLS connector construction or handshake failure.
    Tls(crate::tls::TlsError),
}

impl fmt::Display for NatsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "NATS I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "NATS protocol error: {msg}"),
            Self::InvalidAuth(msg) => write!(f, "NATS invalid auth configuration: {msg}"),
            Self::Server(msg) => write!(f, "NATS server error: {msg}"),
            Self::InvalidUrl(url) => write!(f, "Invalid NATS URL: {url}"),
            Self::Cancelled => write!(f, "NATS operation cancelled"),
            Self::Closed => write!(f, "NATS connection closed"),
            Self::SubscriptionNotFound(sid) => write!(f, "NATS subscription not found: {sid}"),
            Self::NotConnected => write!(f, "NATS not connected"),
            Self::TlsRequired {
                server_required,
                client_required,
            } => write!(
                f,
                "NATS TLS upgrade required (server_required={server_required}, \
                 client_required={client_required}) but no usable TLS connector \
                 is configured for this build; refusing to send CONNECT in \
                 cleartext to avoid credential exposure (br-asupersync-2kmc12)"
            ),
            Self::Tls(err) => write!(f, "NATS TLS error: {err}"),
        }
    }
}

impl std::error::Error for NatsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Tls(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for NatsError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl NatsError {
    /// Whether this error is transient and may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Closed | Self::NotConnected)
    }

    /// Whether this error indicates a connection-level failure.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(self, Self::Io(_) | Self::Closed | Self::NotConnected)
    }

    /// Whether this error indicates resource/capacity exhaustion.
    #[must_use]
    pub fn is_capacity_error(&self) -> bool {
        false
    }

    /// Whether this error is a timeout.
    #[must_use]
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Io(e) if e.kind() == io::ErrorKind::TimedOut)
    }

    /// Whether the operation should be retried.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.is_transient()
    }
}

/// Configuration for NATS client.
///
/// br-asupersync-5in552: [`Debug`] is implemented MANUALLY (not
/// derived) to redact credential fields (`password`, `token`,
/// `user`). Pre-fix the derived Debug impl printed the cleartext
/// values verbatim — and a NatsConfig is routinely surfaced through
/// [`fmt::Debug`] by panic backtraces, structured-logging frameworks
/// that include `format!("{:?}", ...)` of context structs,
/// observability spans that capture connection state, and lab
/// crashpacks that serialize the runtime's connect history. Every
/// such surface leaked the password / token to whatever destination
/// the surface flowed into (logs, traces, panic backtraces shipped
/// to APM collectors). The redacted Debug impl substitutes the
/// sentinel `<redacted>` for any present credential and `None` for
/// absent ones.
/// # Auth-method support matrix (audit, 2026-04-29)
///
/// The asupersync NATS client supports the following auth methods:
///
/// | NATS auth method               | Supported here? | Notes |
/// | ------------------------------ | --------------- | ----- |
/// | None                           | ✅              | default |
/// | `user` + `pass`                | ✅              | requires TLS via `require_tls` or server INFO `tls_required` |
/// | `auth_token`                   | ✅              | same TLS gate as user/pass |
/// | nkey (nonce challenge, ed25519) | ✅              | requires INFO `nonce` and a user `nkey_seed` |
/// | JWT (decentralized auth, NGS)  | ✅              | requires INFO `nonce`, `user_jwt`, and matching user `nkey_seed` |
/// | `.creds` file contents         | ✅              | load via [`NatsConfig::apply_creds`] |
/// | sealing-key rotation           | delegated        | JWT verification remains server-side; client validates structure and subject match only |
///
/// Filed as `[security-audit-for-saas] nats client lacks nkey/JWT auth`.
/// Operators connecting to a server configured for nkey-only or JWT-only
/// auth (typical for NGS / Synadia Cloud) can now authenticate by
/// signing the INFO nonce before CONNECT without weakening the
/// existing legacy user/password/token path.
///
/// Subject-permission enforcement is correctly delegated to the
/// server; the client propagates server `-ERR 'Permissions Violation'`
/// as `NatsError::Server` (see test `server_err_propagates_as_nats_error`).
#[derive(Clone)]
pub struct NatsConfig {
    /// Host address.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Optional username for authentication.
    ///
    /// Wire format: emitted as the `user` field in CONNECT JSON. Sent
    /// in cleartext over the chosen transport — gated by
    /// [`Self::require_tls`] / server `tls_required` (br-asupersync-2kmc12).
    pub user: Option<String>,
    /// Optional password for authentication.
    ///
    /// Same TLS gate as [`Self::user`].
    pub password: Option<String>,
    /// Optional auth token (legacy single-token auth).
    ///
    /// Same TLS gate. Note: this is the static `auth_token` field, NOT
    /// a JWT. NATS-protocol JWT auth (CONNECT `jwt` + nonce-signed
    /// `sig`) uses [`Self::user_jwt`] plus [`Self::nkey_seed`].
    pub token: Option<String>,
    /// Optional user JWT for decentralized NATS auth.
    ///
    /// This mode MUST be paired with [`Self::nkey_seed`], and the JWT
    /// `sub` claim MUST match the public key derived from that seed.
    /// The client validates the token structure and claim shape, then
    /// signs the server INFO nonce and emits CONNECT `jwt` + `sig`.
    pub user_jwt: Option<String>,
    /// Optional user NKey seed used to sign the server INFO nonce.
    ///
    /// When set without [`Self::user_jwt`], the client emits CONNECT
    /// `nkey` + `sig` for nkey-only auth. When set with
    /// [`Self::user_jwt`], the client emits CONNECT `jwt` + `sig`.
    pub nkey_seed: Option<String>,
    /// Client name sent to server.
    pub name: Option<String>,
    /// Enable verbose mode (server echoes +OK for each command).
    pub verbose: bool,
    /// Enable pedantic mode (stricter protocol checking).
    pub pedantic: bool,
    /// Request timeout for request/reply pattern.
    pub request_timeout: Duration,
    /// Maximum payload size (default 1MB).
    pub max_payload: usize,
    /// Maximum read buffer size in bytes (default 8 MiB).
    ///
    /// Prevents unbounded memory growth if the server sends data faster
    /// than the client can consume. Also limits individual MSG payload size.
    pub max_read_buffer: usize,
    /// br-asupersync-2kmc12: client-side intent to require TLS before
    /// sending CONNECT. Default `false` for backward compatibility.
    ///
    /// When `true`, OR when the server's INFO frame sets
    /// `tls_required = true`, [`NatsClient::connect_with_config`]
    /// performs the NATS post-INFO TLS upgrade BEFORE sending CONNECT,
    /// preventing the client from transmitting `user`/`pass`/
    /// `auth_token` in cleartext over a plain TCP socket. Builds
    /// without TLS support, or TLS builds without roots/connector
    /// configuration, fail closed before CONNECT.
    pub require_tls: bool,
    /// TLS connector used when [`Self::require_tls`] is true or server
    /// INFO advertises `tls_required = true`.
    ///
    /// If omitted in a TLS build, the client attempts to build a
    /// default connector from enabled trust-root features:
    /// `tls-native-roots` first, then `tls-webpki-roots`.
    #[cfg(feature = "tls")]
    pub tls_connector: Option<TlsConnector>,
    /// Enable automatic reconnection on TCP failures.
    pub auto_reconnect: bool,
    /// Maximum number of reconnection attempts (0 = infinite).
    pub max_reconnect_attempts: u32,
    /// Initial reconnection delay.
    pub reconnect_delay: Duration,
    /// Maximum reconnection delay (with exponential backoff).
    pub max_reconnect_delay: Duration,
}

/// br-asupersync-5in552: redact credentials in Debug output.
/// Replaces every `Some(secret)` with `Some("<redacted>")` so panic
/// backtraces, structured logs, and trace spans that format the
/// config via `{:?}` cannot leak the cleartext password / token /
/// user to downstream destinations.
impl fmt::Debug for NatsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Helper: render Option<String> as Some("<redacted>") | None
        // without exposing the underlying value's length (a
        // length-leak side channel would be visible if we used
        // Some(value.len()) or similar).
        let user = self.user.as_deref().map(|_| "<redacted>");
        let password = self.password.as_deref().map(|_| "<redacted>");
        let token = self.token.as_deref().map(|_| "<redacted>");
        let user_jwt = self.user_jwt.as_deref().map(|_| "<redacted>");
        let nkey_seed = self.nkey_seed.as_deref().map(|_| "<redacted>");
        f.debug_struct("NatsConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &user)
            .field("password", &password)
            .field("token", &token)
            .field("user_jwt", &user_jwt)
            .field("nkey_seed", &nkey_seed)
            .field("name", &self.name)
            .field("verbose", &self.verbose)
            .field("pedantic", &self.pedantic)
            .field("request_timeout", &self.request_timeout)
            .field("max_payload", &self.max_payload)
            .field("max_read_buffer", &self.max_read_buffer)
            .field("require_tls", &self.require_tls)
            .field(
                "tls_connector",
                #[cfg(feature = "tls")]
                &self.tls_connector.as_ref().map(|_| "<configured>"),
                #[cfg(not(feature = "tls"))]
                &"<tls feature disabled>",
            )
            .finish()
    }
}

impl Default for NatsConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 4222,
            user: None,
            password: None,
            token: None,
            user_jwt: None,
            nkey_seed: None,
            name: None,
            verbose: false,
            pedantic: false,
            request_timeout: Duration::from_secs(10),
            max_payload: 1_048_576, // 1MB
            max_read_buffer: DEFAULT_MAX_READ_BUFFER,
            require_tls: false,
            #[cfg(feature = "tls")]
            tls_connector: None,
            auto_reconnect: true,
            max_reconnect_attempts: 10,
            reconnect_delay: Duration::from_millis(100),
            max_reconnect_delay: Duration::from_secs(30),
        }
    }
}

impl NatsConfig {
    /// Create config from a NATS URL.
    ///
    /// Format: `nats://[user:password@]host[:port]`
    ///
    /// `tls://[user:password@]host[:port]` is also accepted and sets
    /// [`Self::require_tls`] so the connection upgrades before
    /// CONNECT, matching the NATS TLS URL convention.
    ///
    /// Also supports bracketed IPv6 hosts, e.g. `nats://[::1]:4222`.
    pub fn from_url(url: &str) -> Result<Self, NatsError> {
        let (url, require_tls) = if let Some(url) = url.strip_prefix("nats://") {
            (url, false)
        } else if let Some(url) = url.strip_prefix("tls://") {
            (url, true)
        } else {
            return Err(NatsError::InvalidUrl(url.to_string()));
        };

        let mut config = Self::default();
        config.require_tls = require_tls;

        // Parse credentials if present
        let url = if let Some((creds, rest)) = url.rsplit_once('@') {
            if let Some((user, pass)) = creds.split_once(':') {
                config.user = Some(user.to_string());
                config.password = Some(pass.to_string());
            } else {
                // Token-based auth
                config.token = Some(creds.to_string());
            }
            rest
        } else {
            url
        };

        // Parse host:port
        if let Some(rest) = url.strip_prefix('[') {
            let (host_body, after_host) = rest
                .split_once(']')
                .ok_or_else(|| NatsError::InvalidUrl("invalid IPv6 host".to_string()))?;
            config.host = format!("[{host_body}]");
            if let Some(port) = after_host.strip_prefix(':') {
                config.port = port
                    .parse()
                    .map_err(|_| NatsError::InvalidUrl(format!("invalid port: {port}")))?;
            } else if !after_host.is_empty() {
                return Err(NatsError::InvalidUrl(format!("invalid host/port: {url}")));
            }
        } else if url.matches(':').count() <= 1 {
            if let Some((host, port)) = url.rsplit_once(':') {
                config.host = host.to_string();
                config.port = port
                    .parse()
                    .map_err(|_| NatsError::InvalidUrl(format!("invalid port: {port}")))?;
            } else if !url.is_empty() {
                config.host = url.to_string();
            }
        } else if !url.is_empty() {
            config.host = url.to_string();
        }

        if config.host.is_empty() {
            return Err(NatsError::InvalidUrl("host must not be empty".to_string()));
        }

        Ok(config)
    }

    /// Parse NATS `.creds` file contents into JWT + user seed fields.
    ///
    /// This only populates [`Self::user_jwt`] and [`Self::nkey_seed`].
    /// Mixed legacy auth (`user`/`password`/`token`) is rejected later
    /// by CONNECT validation so callers can decide whether to clear it.
    pub fn apply_creds(&mut self, creds: &str) -> Result<(), NatsError> {
        let (user_jwt, nkey_seed) = parse_nats_creds(creds)?;
        self.user_jwt = Some(user_jwt);
        self.nkey_seed = Some(nkey_seed);
        Ok(())
    }

    fn resolve_connect_auth(
        &self,
        server_info: Option<&ServerInfo>,
    ) -> Result<ConnectAuthPayload, NatsError> {
        let has_legacy_auth =
            self.user.is_some() || self.password.is_some() || self.token.is_some();
        let user_jwt = self.user_jwt.as_deref().map(str::trim);
        let nkey_seed = self.nkey_seed.as_deref().map(str::trim);
        let has_user_jwt = matches!(user_jwt, Some(jwt) if !jwt.is_empty());
        let has_nkey_seed = matches!(nkey_seed, Some(seed) if !seed.is_empty());

        if matches!(user_jwt, Some("")) {
            return Err(NatsError::InvalidAuth(
                "user_jwt must not be empty".to_string(),
            ));
        }
        if matches!(nkey_seed, Some("")) {
            return Err(NatsError::InvalidAuth(
                "nkey_seed must not be empty".to_string(),
            ));
        }
        if has_legacy_auth && (has_user_jwt || has_nkey_seed) {
            return Err(NatsError::InvalidAuth(
                "legacy NATS auth (user/password/token) cannot be combined with nkey/JWT auth"
                    .to_string(),
            ));
        }
        if has_user_jwt && !has_nkey_seed {
            return Err(NatsError::InvalidAuth(
                "JWT auth requires an nkey_seed to sign the server nonce".to_string(),
            ));
        }
        if !has_user_jwt && !has_nkey_seed {
            return Ok(ConnectAuthPayload::None);
        }

        let server_info = server_info.ok_or_else(|| {
            NatsError::InvalidAuth("server INFO missing before CONNECT auth resolution".to_string())
        })?;
        let nonce = server_info
            .nonce
            .as_deref()
            .filter(|nonce| !nonce.is_empty())
            .ok_or_else(|| {
                NatsError::InvalidAuth(
                    "server INFO nonce is required for nkey/JWT authentication".to_string(),
                )
            })?;

        // br-asupersync-0jcx5m: P2 MEDIUM security improvement - basic nonce validation
        // Add lightweight nonce validation to prevent obviously malicious or weak nonces.
        // Full replay protection requires server-side tracking, but we can validate
        // basic nonce quality to reduce attack surface.
        validate_nonce_quality(nonce)?;

        let key_pair = load_user_nkey(nkey_seed.expect("checked nkey_seed presence"))?;
        let signature = key_pair.sign(nonce.as_bytes()).map_err(|err| {
            NatsError::InvalidAuth(format!("failed to sign NATS server nonce: {err}"))
        })?;
        let signature_b64url = URL_SAFE_NO_PAD.encode(signature);

        if let Some(jwt) = user_jwt {
            let claims = parse_nats_jwt_claims(jwt)?;
            let public_key = key_pair.public_key();

            // br-asupersync-090on8: P1 HIGH security fix - prevent timing attacks on JWT subject comparison
            // Use constant-time comparison to prevent attackers from using timing side channels
            // to guess valid public keys by measuring response times of string comparisons.
            // Standard string comparison (!=) leaks timing information about where strings differ,
            // allowing attackers to iteratively guess correct public key characters.
            let subject_matches = claims.subject.as_bytes().ct_eq(public_key.as_bytes());
            if !bool::from(subject_matches) {
                return Err(NatsError::InvalidAuth(format!(
                    "JWT sub claim {} does not match seed public key {}",
                    claims.subject, public_key
                )));
            }
            return Ok(ConnectAuthPayload::Jwt {
                jwt: jwt.to_string(),
                signature_b64url,
                claims,
            });
        }

        Ok(ConnectAuthPayload::Nkey {
            public_key: key_pair.public_key(),
            signature_b64url,
        })
    }
}

/// A message received from NATS.
#[derive(Debug, Clone)]
pub struct Message {
    /// Subject the message was published to.
    pub subject: String,
    /// Subscription ID that received this message.
    pub sid: u64,
    /// Optional reply-to subject for request/reply pattern.
    pub reply_to: Option<String>,
    /// Optional raw NATS/1.0 header block for HMSG replies.
    pub headers: Option<Vec<u8>>,
    /// Message payload.
    pub payload: Vec<u8>,
}

/// Server INFO message parsed fields.
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    /// Server ID.
    pub server_id: String,
    /// Server name.
    pub server_name: String,
    /// Server version.
    pub version: String,
    /// Protocol version.
    pub proto: i32,
    /// Max payload size allowed.
    pub max_payload: usize,
    /// Whether TLS is required.
    pub tls_required: bool,
    /// Whether TLS is available.
    pub tls_available: bool,
    /// Whether the server supports the v1 NATS message-headers extension
    /// (HPUB / HMSG / HSUB). Negotiated at connect time; if false, the
    /// client MUST NOT emit HPUB frames or `Nats-Msg-Id`-style dedup
    /// headers on JetStream publishes (br-asupersync-byc2d1).
    pub headers: bool,
    /// Optional nonce used for nkey/JWT CONNECT challenge signing.
    pub nonce: Option<String>,
    /// Connected URL.
    pub connect_urls: Vec<String>,
}

impl ServerInfo {
    /// Parse INFO JSON payload, rejecting malformed or non-object frames.
    fn parse(json: &str) -> Result<Self, NatsError> {
        let value = serde_json::from_str::<serde_json::Value>(json).map_err(|err| {
            NatsError::Protocol(format!("malformed INFO JSON from server: {err}"))
        })?;
        if !value.is_object() {
            return Err(NatsError::Protocol(
                "malformed INFO JSON from server: expected object".to_string(),
            ));
        }

        let mut info = Self::default();

        // Simple JSON field extraction (no nested objects)
        if let Some(v) = extract_json_string(json, "server_id") {
            info.server_id = v;
        }
        if let Some(v) = extract_json_string(json, "server_name") {
            info.server_name = v;
        }
        if let Some(v) = extract_json_string(json, "version") {
            info.version = v;
        }
        if let Some(v) = extract_json_i64(json, "proto") {
            info.proto = v as i32;
        }
        if let Some(v) = extract_json_i64(json, "max_payload") {
            info.max_payload = usize::try_from(v).unwrap_or(0);
        }
        if let Some(v) = extract_json_bool(json, "tls_required") {
            info.tls_required = v;
        }
        if let Some(v) = extract_json_bool(json, "tls_available") {
            info.tls_available = v;
        }
        if let Some(v) = extract_json_bool(json, "headers") {
            info.headers = v;
        }
        if let Some(v) = extract_json_string(json, "nonce") {
            info.nonce = Some(v);
        }

        Ok(info)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct JwtClaimsSummary {
    subject: String,
    issuer: Option<String>,
    name: Option<String>,
    expires_at: Option<i64>,
}

impl JwtClaimsSummary {
    fn log_summary(&self) -> String {
        format!(
            "sub={} iss={} name={} exp={}",
            self.subject,
            self.issuer.as_deref().unwrap_or("<none>"),
            self.name.as_deref().unwrap_or("<none>"),
            self.expires_at
                .map_or_else(|| "<none>".to_string(), |exp| exp.to_string())
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectAuthPayload {
    None,
    Nkey {
        public_key: String,
        signature_b64url: String,
    },
    Jwt {
        jwt: String,
        signature_b64url: String,
        claims: JwtClaimsSummary,
    },
}

const NATS_CREDS_JWT_BEGIN: &str = "-----BEGIN NATS USER JWT-----";
const NATS_CREDS_JWT_END: &str = "------END NATS USER JWT------";
const NATS_CREDS_SEED_BEGIN: &str = "-----BEGIN USER NKEY SEED-----";
const NATS_CREDS_SEED_END: &str = "------END USER NKEY SEED------";

fn load_user_nkey(seed: &str) -> Result<KeyPair, NatsError> {
    let key_pair = KeyPair::from_seed(seed)
        .map_err(|err| NatsError::InvalidAuth(format!("invalid NKey seed: {err}")))?;
    if key_pair.key_pair_type() != KeyPairType::User {
        return Err(NatsError::InvalidAuth(format!(
            "nkey_seed must be a USER seed, got {:?}",
            key_pair.key_pair_type()
        )));
    }
    Ok(key_pair)
}

/// br-asupersync-0jcx5m: Validate basic nonce quality to reduce attack surface.
///
/// This provides lightweight protection against obviously weak or malicious nonces.
/// Full replay protection requires server-side nonce tracking and is outside the
/// scope of client-side validation.
///
/// Validation criteria:
/// - Minimum length to ensure sufficient entropy
/// - Maximum length to prevent DoS via oversized nonces
/// - Base64 character set validation to ensure well-formed nonces
/// - No obviously predictable patterns
fn validate_nonce_quality(nonce: &str) -> Result<(), NatsError> {
    // Minimum length: 16 characters (96 bits base64) for reasonable entropy
    if nonce.len() < 16 {
        return Err(NatsError::InvalidAuth(format!(
            "server nonce too short: {} chars (minimum 16 for security)",
            nonce.len()
        )));
    }

    // Maximum length: 256 characters to prevent DoS attacks via oversized nonces
    if nonce.len() > 256 {
        return Err(NatsError::InvalidAuth(format!(
            "server nonce too long: {} chars (maximum 256)",
            nonce.len()
        )));
    }

    // Ensure nonce contains only valid base64 characters (common NATS nonce format)
    // Allow base64 + base64url character sets: A-Za-z0-9+/=-_
    let is_valid_char = |c: char| c.is_ascii_alphanumeric() || "+=/-_".contains(c);
    if !nonce.chars().all(is_valid_char) {
        return Err(NatsError::InvalidAuth(
            "server nonce contains invalid characters (expected base64/base64url)".to_string(),
        ));
    }

    // Prevent obviously predictable nonces (all same character, simple sequences)
    let first_char = nonce.chars().next().unwrap(); // Safe: already checked non-empty
    if nonce.chars().all(|c| c == first_char) {
        return Err(NatsError::InvalidAuth(format!(
            "server nonce appears non-random (all '{}' characters)",
            first_char
        )));
    }

    // Check for simple incrementing pattern (like "012345...")
    let chars: Vec<char> = nonce.chars().collect();
    let mut is_sequential = true;
    for i in 1..chars.len().min(8) {
        // Check first 8 characters for sequence
        if chars[i] as u8 != (chars[i - 1] as u8).saturating_add(1) {
            is_sequential = false;
            break;
        }
    }
    if is_sequential {
        return Err(NatsError::InvalidAuth(
            "server nonce appears non-random (sequential pattern detected)".to_string(),
        ));
    }

    Ok(())
}

fn decode_base64_url(input: &str, field_name: &str) -> Result<Vec<u8>, NatsError> {
    URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| URL_SAFE.decode(input))
        .map_err(|err| NatsError::InvalidAuth(format!("invalid {field_name}: {err}")))
}

fn jwt_numeric_claim_to_i64(value: &serde_json::Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_u64().and_then(|value| i64::try_from(value).ok()))
}

fn parse_nats_jwt_claims(jwt: &str) -> Result<JwtClaimsSummary, NatsError> {
    let mut parts = jwt.split('.');
    let header_b64 = parts.next().unwrap_or_default();
    let payload_b64 = parts.next().unwrap_or_default();
    let signature_b64 = parts.next().unwrap_or_default();
    if header_b64.is_empty()
        || payload_b64.is_empty()
        || signature_b64.is_empty()
        || parts.next().is_some()
    {
        return Err(NatsError::InvalidAuth(
            "JWT auth expects a compact JWT with exactly 3 non-empty segments".to_string(),
        ));
    }

    let header = decode_base64_url(header_b64, "JWT header")?;
    let header: serde_json::Value = serde_json::from_slice(&header)
        .map_err(|err| NatsError::InvalidAuth(format!("JWT header is not valid JSON: {err}")))?;
    let header_obj = header.as_object().ok_or_else(|| {
        NatsError::InvalidAuth("JWT header must decode to a JSON object".to_string())
    })?;

    // Verify the algorithm is ed25519-nkey (required for NATS JWTs)
    let algorithm = header_obj
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            NatsError::InvalidAuth("JWT header must contain an 'alg' field".to_string())
        })?;
    if algorithm != "ed25519-nkey" {
        return Err(NatsError::InvalidAuth(format!(
            "unsupported JWT algorithm '{}', expected 'ed25519-nkey'",
            algorithm
        )));
    }

    let payload = decode_base64_url(payload_b64, "JWT payload")?;
    let payload: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|err| NatsError::InvalidAuth(format!("JWT payload is not valid JSON: {err}")))?;
    let payload_obj = payload.as_object().ok_or_else(|| {
        NatsError::InvalidAuth("JWT payload must decode to a JSON object".to_string())
    })?;
    let subject = payload_obj
        .get("sub")
        .and_then(serde_json::Value::as_str)
        .filter(|subject| !subject.is_empty())
        .ok_or_else(|| {
            NatsError::InvalidAuth(
                "JWT payload must contain a non-empty string sub claim".to_string(),
            )
        })?;
    let issuer = payload_obj
        .get("iss")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let name = payload_obj
        .get("name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let expires_at = payload_obj.get("exp").and_then(jwt_numeric_claim_to_i64);

    // br-asupersync-4h6ck7: CRITICAL security fix - verify JWT signature
    // For NATS JWTs, we need the issuer's public key to verify the signature.
    // In a production deployment, issuer keys should be pre-configured or
    // fetched from a trusted source. For now, we verify the signature if
    // the issuer claim is present and non-empty - the caller must ensure
    // proper issuer key validation.
    if let Some(issuer_str) = issuer.as_deref() {
        if !issuer_str.is_empty() {
            let signature = decode_base64_url(signature_b64, "JWT signature")?;
            let signed_data = format!("{}.{}", header_b64, payload_b64);

            // For NATS, the issuer field typically contains the issuer's public key
            // Attempt to verify signature using issuer as the public key
            match KeyPair::from_public_key(issuer_str) {
                Ok(issuer_keypair) => {
                    issuer_keypair
                        .verify(signed_data.as_bytes(), &signature)
                        .map_err(|err| {
                            NatsError::InvalidAuth(format!(
                                "JWT signature verification failed: {}",
                                err
                            ))
                        })?;
                }
                Err(_) => {
                    // If issuer is not a valid public key, we cannot verify the signature.
                    // In a production system, this should be a hard error or the issuer
                    // keys should be resolved from a different source.
                    return Err(NatsError::InvalidAuth(
                        "JWT issuer claim is not a valid NATS public key for signature verification".to_string(),
                    ));
                }
            }
        }
    } else {
        // No issuer claim means we cannot verify the JWT signature
        return Err(NatsError::InvalidAuth(
            "JWT missing issuer claim required for signature verification".to_string(),
        ));
    }

    // br-asupersync-w6pmc1: P1 HIGH security fix - validate JWT expiration
    // Prevent authentication with expired JWTs by checking exp claim against current time.
    // Include clock skew tolerance to handle network delays and minor time differences.
    if let Some(exp_timestamp) = expires_at {
        // Get current time as Unix timestamp (seconds since epoch)
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                NatsError::InvalidAuth(
                    "system clock error: cannot determine current time".to_string(),
                )
            })?
            .as_secs();
        let now = i64::try_from(now_secs).map_err(|_| {
            NatsError::InvalidAuth("system clock error: current time exceeds i64".to_string())
        })?;

        // Clock skew tolerance: allow 60 seconds of leeway for network delays
        // and minor time synchronization differences between client and server
        const CLOCK_SKEW_TOLERANCE_SECS: i64 = 60;
        let effective_now = now - CLOCK_SKEW_TOLERANCE_SECS;

        if exp_timestamp < effective_now {
            return Err(NatsError::InvalidAuth(format!(
                "JWT has expired: exp={} < current_time={} (with {}s tolerance)",
                exp_timestamp, now, CLOCK_SKEW_TOLERANCE_SECS
            )));
        }
    }

    Ok(JwtClaimsSummary {
        subject: subject.to_string(),
        issuer,
        name,
        expires_at,
    })
}

fn extract_credential_block(
    creds: &str,
    begin_marker: &str,
    end_marker: &str,
    label: &str,
) -> Result<String, NatsError> {
    let mut in_block = false;
    let mut found_end = false;
    let mut lines = Vec::new();

    for line in creds.lines() {
        let line = line.trim();
        if !in_block {
            if line == begin_marker {
                in_block = true;
            }
            continue;
        }
        if line == end_marker {
            found_end = true;
            break;
        }
        if !line.is_empty() {
            lines.push(line);
        }
    }

    if !in_block {
        return Err(NatsError::InvalidAuth(format!(
            "credentials are missing the {label} begin marker"
        )));
    }
    if !found_end {
        return Err(NatsError::InvalidAuth(format!(
            "credentials are missing the {label} end marker"
        )));
    }
    if lines.is_empty() {
        return Err(NatsError::InvalidAuth(format!(
            "credentials {label} block is empty"
        )));
    }

    Ok(lines.join(""))
}

fn parse_nats_creds(creds: &str) -> Result<(String, String), NatsError> {
    let user_jwt =
        extract_credential_block(creds, NATS_CREDS_JWT_BEGIN, NATS_CREDS_JWT_END, "JWT")?;
    let nkey_seed = extract_credential_block(
        creds,
        NATS_CREDS_SEED_BEGIN,
        NATS_CREDS_SEED_END,
        "USER NKEY SEED",
    )?;
    Ok((user_jwt, nkey_seed))
}

fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{key}\":\"");
    let start = json.find(&pattern)? + pattern.len();
    let slice = &json[start..];
    let mut out = String::with_capacity(slice.len());
    let mut chars = slice.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => {
                let next = chars.next()?;
                match next {
                    'b' => out.push('\x08'),
                    'f' => out.push('\x0C'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let mut hex = String::with_capacity(4);
                        for _ in 0..4 {
                            hex.push(chars.next()?);
                        }
                        if let Ok(val) = u32::from_str_radix(&hex, 16) {
                            if let Some(c) = char::from_u32(val) {
                                out.push(c);
                            }
                        }
                    }
                    other => out.push(other),
                }
            }
            c => out.push(c),
        }
    }
}

/// Encode a NATS v1 message-header block per
/// `https://docs.nats.io/reference/reference-protocols/nats-protocol#hpub`:
///
/// ```text
/// NATS/1.0\r\n<Key1>: <Value1>\r\n...<KeyN>: <ValueN>\r\n\r\n
/// ```
///
/// The trailing blank line (`\r\n\r\n`) is mandatory — it's the
/// header/payload separator the broker uses to split the HPUB body.
///
/// Header keys must be ASCII and contain no `:` `\r` `\n`. Values may
/// be arbitrary bytes but MUST NOT contain `\r` or `\n` (NATS does not
/// support multi-line header values).
///
/// `max_header_bytes` caps the fully encoded `NATS/1.0\r\n...\r\n\r\n`
/// block before allocation so oversized attacker-controlled header sets
/// fail closed before building a large intermediate buffer
/// (br-asupersync-uu9ayc).
fn encode_nats_headers(
    headers: &[(&str, &[u8])],
    max_header_bytes: usize,
) -> Result<Vec<u8>, NatsError> {
    let mut estimated = b"NATS/1.0\r\n\r\n".len();
    if estimated > max_header_bytes {
        return Err(NatsError::Protocol(format!(
            "NATS header block too large: {estimated} > {max_header_bytes}"
        )));
    }
    for (k, v) in headers {
        estimated = estimated
            .checked_add(k.len() + v.len() + 4)
            .ok_or_else(|| NatsError::Protocol("NATS header block length overflow".to_string()))?;
        if estimated > max_header_bytes {
            return Err(NatsError::Protocol(format!(
                "NATS header block too large: {estimated} > {max_header_bytes}"
            )));
        }
    }
    let mut out = Vec::with_capacity(estimated);
    out.extend_from_slice(b"NATS/1.0\r\n");
    for (k, v) in headers {
        if k.is_empty()
            || k.bytes()
                .any(|b| b == b':' || b == b'\r' || b == b'\n' || !b.is_ascii())
        {
            return Err(NatsError::Protocol(format!(
                "invalid NATS header key: {k:?}"
            )));
        }
        if v.iter().any(|&b| b == b'\r' || b == b'\n') {
            return Err(NatsError::Protocol(format!(
                "invalid NATS header value (contains CR/LF) for key {k:?}"
            )));
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// Escape a string for safe embedding in JSON values.
fn nats_json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                write!(&mut out, "\\u{:04x}", c as u32).expect("write to String");
            }
            c => out.push(c),
        }
    }
    out
}

fn extract_json_i64(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_json_bool(json: &str, key: &str) -> Option<bool> {
    let pattern = format!("\"{key}\":");
    let start = json.find(&pattern)? + pattern.len();
    let rest = json[start..].trim_start();
    if rest.starts_with("true") {
        Some(true)
    } else if rest.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn validate_nats_token(value: &str, field: &str) -> Result<(), NatsError> {
    if value.is_empty() {
        return Err(NatsError::Protocol(format!("{field} must not be empty")));
    }
    if value.len() > MAX_NATS_SUBJECT_BYTES {
        return Err(NatsError::Protocol(format!(
            "{field} exceeds the {MAX_NATS_SUBJECT_BYTES}-byte NATS subject bound"
        )));
    }
    if value
        .chars()
        .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    {
        return Err(NatsError::Protocol(format!(
            "{field} contains illegal whitespace/control characters"
        )));
    }
    Ok(())
}

/// Conservative per-subject bound aligned with the default NATS
/// `max_control_line` server limit (4KB). A subject longer than this
/// cannot fit on the default control line.
const MAX_NATS_SUBJECT_BYTES: usize = 4 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionPatternToken<'a> {
    Literal(&'a str),
    SingleWildcard,
    TailWildcard,
}

fn is_valid_nats_segment(token: &str) -> bool {
    !token.is_empty()
        && !token
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
}

fn parse_subscription_pattern(pattern: &str) -> Option<Vec<SubscriptionPatternToken<'_>>> {
    if pattern.is_empty() {
        return None;
    }

    let raw_tokens: Vec<_> = pattern.split('.').collect();
    let raw_len = raw_tokens.len();
    if raw_tokens.iter().any(|token| !is_valid_nats_segment(token)) {
        return None;
    }

    let mut parsed = Vec::with_capacity(raw_tokens.len());
    for (index, token) in raw_tokens.into_iter().enumerate() {
        match token {
            "*" => parsed.push(SubscriptionPatternToken::SingleWildcard),
            ">" if index + 1 == raw_len => {
                parsed.push(SubscriptionPatternToken::TailWildcard);
            }
            ">" => return None,
            _ if token.contains('*') || token.contains('>') => return None,
            _ => parsed.push(SubscriptionPatternToken::Literal(token)),
        }
    }

    Some(parsed)
}

fn parse_publish_subject(subject: &str) -> Option<Vec<&str>> {
    if subject.is_empty() || subject.len() > MAX_NATS_SUBJECT_BYTES {
        return None;
    }

    let tokens: Vec<_> = subject.split('.').collect();
    if tokens
        .iter()
        .any(|token| !is_valid_nats_segment(token) || token.contains('*') || token.contains('>'))
    {
        return None;
    }

    Some(tokens)
}

pub(crate) fn validate_nats_publish_subject(subject: &str, field: &str) -> Result<(), NatsError> {
    validate_nats_token(subject, field)?;
    if parse_publish_subject(subject).is_none() {
        return Err(NatsError::Protocol(format!(
            "{field} must be a fully specified NATS subject without wildcards or empty tokens"
        )));
    }
    Ok(())
}

pub(crate) fn validate_nats_subscription_pattern(
    pattern: &str,
    field: &str,
) -> Result<(), NatsError> {
    validate_nats_token(pattern, field)?;
    if parse_subscription_pattern(pattern).is_none() {
        return Err(NatsError::Protocol(format!(
            "{field} contains an invalid NATS wildcard placement or empty token"
        )));
    }
    Ok(())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_validate_nats_publish_subject(subject: &str) -> Result<(), String> {
    validate_nats_publish_subject(subject, "subject").map_err(|err| err.to_string())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_nats_publish_subject(subject: &str) -> Option<Vec<String>> {
    parse_publish_subject(subject).map(|tokens| tokens.into_iter().map(ToOwned::to_owned).collect())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_validate_nats_subscription_pattern(pattern: &str) -> Result<(), String> {
    validate_nats_subscription_pattern(pattern, "subject").map_err(|err| err.to_string())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_nats_jwt_claims(
    jwt: &str,
) -> Result<(String, Option<String>, Option<String>, Option<i64>), String> {
    parse_nats_jwt_claims(jwt)
        .map(|claims| {
            (
                claims.subject,
                claims.issuer,
                claims.name,
                claims.expires_at,
            )
        })
        .map_err(|err| err.to_string())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_nats_creds(creds: &str) -> Result<(String, String), String> {
    parse_nats_creds(creds).map_err(|err| err.to_string())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_load_nats_user_nkey(seed: &str) -> Result<String, String> {
    load_user_nkey(seed)
        .map(|key_pair| key_pair.public_key())
        .map_err(|err| err.to_string())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_deterministic_nats_user_seed(byte: u8) -> String {
    KeyPair::new_from_raw(KeyPairType::User, [byte; 32])
        .expect("deterministic user seed")
        .seed()
        .expect("seed encoding")
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub const fn fuzz_nats_subject_max_bytes() -> usize {
    MAX_NATS_SUBJECT_BYTES
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_encode_nats_headers(
    headers: &[(String, Vec<u8>)],
    max_header_bytes: usize,
) -> Result<Vec<u8>, String> {
    let borrowed = headers
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_slice()))
        .collect::<Vec<_>>();
    encode_nats_headers(&borrowed, max_header_bytes).map_err(|err| err.to_string())
}

#[cfg(any(test, feature = "test-internals"))]
fn subscription_matches_subject_impl(pattern: &str, subject: &str) -> bool {
    let Some(pattern_tokens) = parse_subscription_pattern(pattern) else {
        return false;
    };
    let Some(subject_tokens) = parse_publish_subject(subject) else {
        return false;
    };

    let mut subject_index = 0usize;
    for token in pattern_tokens {
        match token {
            SubscriptionPatternToken::Literal(literal) => {
                if subject_tokens.get(subject_index) != Some(&literal) {
                    return false;
                }
                subject_index += 1;
            }
            SubscriptionPatternToken::SingleWildcard => {
                if subject_tokens.get(subject_index).is_none() {
                    return false;
                }
                subject_index += 1;
            }
            SubscriptionPatternToken::TailWildcard => {
                return subject_index < subject_tokens.len();
            }
        }
    }

    subject_index == subject_tokens.len()
}

#[cfg(any(test, feature = "test-internals"))]
#[doc(hidden)]
pub fn subscription_matches_subject(pattern: &str, subject: &str) -> bool {
    subscription_matches_subject_impl(pattern, subject)
}

/// Generate a random suffix for unique inbox subjects using capability-based entropy.
fn random_suffix(cx: &Cx) -> String {
    let hi = cx.random_u64();
    let lo = cx.random_u64();
    format!("{:016x}", hi ^ lo)
}

/// Default maximum read buffer size (8 MiB). Prevents unbounded memory growth
/// if the server sends data faster than the client can consume.
const DEFAULT_MAX_READ_BUFFER: usize = 8 * 1024 * 1024;

/// Internal read buffer for NATS protocol parsing.
#[derive(Debug)]
struct NatsReadBuffer {
    buf: Vec<u8>,
    pos: usize,
    max_size: usize,
}

impl NatsReadBuffer {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_READ_BUFFER)
    }

    fn with_limit(max_size: usize) -> Self {
        Self {
            buf: Vec::new(),
            pos: 0,
            max_size,
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), NatsError> {
        if self.buf.len() + bytes.len() - self.pos > self.max_size {
            return Err(NatsError::Protocol(format!(
                "read buffer exceeds maximum size ({} bytes)",
                self.max_size
            )));
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.buf.len());
        // Compact buffer when we've consumed a lot
        if self.pos > 0 && (self.pos > 4096 && self.pos > (self.buf.len() / 2)) {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn find_crlf(&self) -> Option<usize> {
        let buf = self.available();
        (0..buf.len().saturating_sub(1)).find(|&i| buf[i] == b'\r' && buf[i + 1] == b'\n')
    }
}

/// NATS protocol message types.
#[derive(Debug)]
pub(crate) enum NatsMessage {
    /// Server INFO message.
    Info(ServerInfo),
    /// Server MSG message (subscription message).
    Msg(Message),
    /// Server +OK acknowledgement.
    Ok,
    /// Server -ERR error.
    Err(String),
    /// Server PING.
    Ping,
    /// Server PONG.
    Pong,
}

/// Internal subscription state.
struct SubscriptionState {
    #[allow(dead_code)] // read via tracing format strings
    subject: String,
    queue_group: Option<String>,
    sender: mpsc::Sender<Message>,
}

struct SubscriptionReplay {
    sid: u64,
    subject: String,
    queue_group: Option<String>,
}

/// Shared state between client and subscriptions.
struct SharedState {
    subscriptions: Mutex<HashMap<u64, SubscriptionState>>,
    server_info: Mutex<Option<ServerInfo>>,
    closed: std::sync::atomic::AtomicBool,
}

impl SharedState {
    fn new() -> Self {
        Self {
            subscriptions: Mutex::new(HashMap::new()),
            server_info: Mutex::new(None),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

struct SubscribeGuard<'a> {
    subs: &'a Mutex<HashMap<u64, SubscriptionState>>,
    sid: u64,
    defused: bool,
}

impl Drop for SubscribeGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            self.subs.lock().remove(&self.sid);
        }
    }
}

enum NatsStream {
    Plain(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<TlsStream<TcpStream>>),
    Closed,
}

impl NatsStream {
    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        match self {
            Self::Plain(stream) => stream.shutdown(how),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => stream.get_ref().shutdown(how),
            Self::Closed => Ok(()),
        }
    }
}

impl From<TcpStream> for NatsStream {
    fn from(stream: TcpStream) -> Self {
        Self::Plain(stream)
    }
}

impl AsyncRead for NatsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "NATS transport is closed",
            ))),
        }
    }
}

impl AsyncWrite for NatsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "NATS transport is closed",
            ))),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Closed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "NATS transport is closed",
            ))),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => stream.is_write_vectored(),
            Self::Closed => false,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
            Self::Closed => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Closed => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(feature = "tls")]
fn nats_tls_server_name(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

#[cfg(feature = "tls")]
fn build_default_nats_tls_connector() -> Result<TlsConnector, NatsError> {
    let builder = TlsConnectorBuilder::new();

    #[cfg(feature = "tls-native-roots")]
    {
        let builder = builder.with_native_roots().map_err(NatsError::Tls)?;
        return builder.build().map_err(NatsError::Tls);
    }

    #[cfg(all(not(feature = "tls-native-roots"), feature = "tls-webpki-roots"))]
    {
        return builder.with_webpki_roots().build().map_err(NatsError::Tls);
    }

    #[cfg(all(not(feature = "tls-native-roots"), not(feature = "tls-webpki-roots")))]
    {
        let _ = builder;
        Err(NatsError::Tls(crate::tls::TlsError::Configuration(
            "NATS TLS requires NatsConfig::tls_connector or a trust-root \
             feature (tls-native-roots or tls-webpki-roots)"
                .to_string(),
        )))
    }
}

/// NATS client with Cx integration.
pub struct NatsClient {
    config: NatsConfig,
    stream: NatsStream,
    read_buf: NatsReadBuffer,
    state: Arc<SharedState>,
    next_sid: AtomicU64,
    connected: bool,
    /// br-asupersync-8nx7g9: preserve TLS requirement established during
    /// initial connection to prevent TLS downgrade attacks during reconnection.
    /// Once TLS is determined to be required (by client config OR initial
    /// server INFO), it remains required for all subsequent reconnections.
    tls_required_on_connect: bool,
}

impl fmt::Debug for NatsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatsClient")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

impl NatsClient {
    /// Connect to a NATS server.
    pub async fn connect(cx: &Cx, url: &str) -> Result<Self, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let config = NatsConfig::from_url(url)?;
        Self::connect_with_config(cx, config).await
    }

    /// Connect with explicit configuration.
    pub async fn connect_with_config(cx: &Cx, config: NatsConfig) -> Result<Self, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
        cx.trace(&format!(
            "nats: connecting to {}:{}",
            config.host, config.port
        ));

        let addr = format!("{}:{}", config.host, config.port);
        let stream = TcpStream::connect(addr).await?;

        let read_buf_limit = config.max_read_buffer;
        let mut client = Self {
            config,
            stream: stream.into(),
            read_buf: NatsReadBuffer::with_limit(read_buf_limit),
            state: Arc::new(SharedState::new()),
            next_sid: AtomicU64::new(1),
            connected: false,
            tls_required_on_connect: false, // Will be set after TLS evaluation
        };

        // Read initial INFO from server
        let info = client.read_info(cx).await?;

        // br-asupersync-2kmc12: enforce TLS-required BEFORE sending
        // CONNECT (which may carry user/pass/token). NATS servers send
        // INFO first; when INFO advertises tls_required, or the client
        // config requires TLS, the client must perform the TLS handshake
        // on the same TCP connection before CONNECT.
        //
        // Two trigger sources:
        //   1. Client config require_tls = true → operator policy says
        //      "this connection must be TLS, period".
        //   2. Server INFO advertises tls_required = true → the server
        //      will reject (or worse, silently ignore) a plaintext
        //      CONNECT.
        // Either trigger upgrades the transport. If the build/config
        // cannot construct TLS, upgrade_to_tls fails closed before any
        // CONNECT bytes hit the wire.

        // br-asupersync-8nx7g9: preserve TLS requirement decision for reconnection
        let tls_required = info.tls_required || client.config.require_tls;
        client.tls_required_on_connect = tls_required;

        if tls_required {
            cx.trace(&format!(
                "nats: TLS required (server={}, client={}); upgrading before CONNECT",
                info.tls_required, client.config.require_tls
            ));
            client
                .upgrade_to_tls(cx, info.tls_required, client.config.require_tls)
                .await?;
        }

        // Enforce the server's max_payload if it is smaller than the client's.
        // This prevents the client from sending payloads that the server will reject.
        if info.max_payload > 0 && info.max_payload < client.config.max_payload {
            client.config.max_payload = info.max_payload;
        }

        *client.state.server_info.lock() = Some(info.clone());

        // Send CONNECT command. If TLS was required, the stream has
        // already been upgraded; otherwise this remains the legacy
        // cleartext NATS handshake.
        client.send_connect(cx).await?;
        client.connected = true;

        cx.trace("nats: connection established");
        Ok(client)
    }

    async fn upgrade_to_tls(
        &mut self,
        cx: &Cx,
        server_required: bool,
        client_required: bool,
    ) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        #[cfg(feature = "tls")]
        let _ = (server_required, client_required);

        #[cfg(not(feature = "tls"))]
        {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            self.stream = NatsStream::Closed;
            let _ = cx;
            Err(NatsError::TlsRequired {
                server_required,
                client_required,
            })
        }

        #[cfg(feature = "tls")]
        {
            let connector = self
                .config
                .tls_connector
                .clone()
                .map_or_else(build_default_nats_tls_connector, Ok)?;
            let server_name = nats_tls_server_name(&self.config.host).to_string();
            let tcp_stream = match std::mem::replace(&mut self.stream, NatsStream::Closed) {
                NatsStream::Plain(stream) => stream,
                NatsStream::Closed => {
                    return Err(NatsError::NotConnected);
                }
                NatsStream::Tls(stream) => {
                    self.stream = NatsStream::Tls(stream);
                    return Ok(());
                }
            };

            cx.trace(&format!("nats: starting TLS upgrade for {server_name}"));
            match connector.connect(&server_name, tcp_stream).await {
                Ok(tls_stream) => {
                    self.stream = NatsStream::Tls(Box::new(tls_stream));
                    cx.trace("nats: TLS upgrade complete");
                    Ok(())
                }
                Err(err) => {
                    self.stream = NatsStream::Closed;
                    Err(NatsError::Tls(err))
                }
            }
        }
    }

    /// Read the initial INFO message from server.
    async fn read_info(&mut self, cx: &Cx) -> Result<ServerInfo, NatsError> {
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            if let Some(msg) = self.try_parse_message()? {
                match msg {
                    NatsMessage::Info(info) => return Ok(info),
                    NatsMessage::Err(e) => return Err(NatsError::Server(e)),
                    _ => {
                        return Err(NatsError::Protocol(
                            "expected INFO message from server".to_string(),
                        ));
                    }
                }
            }

            self.read_more().await?;
        }
    }

    /// Send CONNECT command to server.
    async fn send_connect(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
        let server_info = self.state.server_info.lock().clone();
        let connect_auth = self.config.resolve_connect_auth(server_info.as_ref())?;
        let nonce_len = server_info
            .as_ref()
            .and_then(|info| info.nonce.as_ref())
            .map_or(0, String::len);

        match &connect_auth {
            ConnectAuthPayload::None => {}
            ConnectAuthPayload::Nkey { public_key, .. } => cx.trace(&format!(
                "nats: sending CONNECT with nkey auth public_key={public_key} nonce_len={nonce_len}"
            )),
            ConnectAuthPayload::Jwt { claims, .. } => cx.trace(&format!(
                "nats: sending CONNECT with jwt auth nonce_len={nonce_len} claims={}",
                claims.log_summary()
            )),
        }

        // Build CONNECT JSON
        let mut connect = String::from("{");
        connect.push_str("\"verbose\":");
        connect.push_str(if self.config.verbose { "true" } else { "false" });
        connect.push_str(",\"pedantic\":");
        connect.push_str(if self.config.pedantic {
            "true"
        } else {
            "false"
        });
        connect.push_str(",\"lang\":\"rust\"");
        connect.push_str(",\"version\":\"0.1.0\"");
        connect.push_str(",\"protocol\":1");
        if self.tls_required_on_connect {
            connect.push_str(",\"tls_required\":true");
        }
        // Advertise that we accept the NATS v1 message-headers extension
        // (HPUB / HMSG). The server's actual capability is reflected in
        // ServerInfo.headers, which we honour in
        // publish_request_with_headers (br-asupersync-byc2d1).
        connect.push_str(",\"headers\":true");
        // Required by the spec when headers:true is advertised so the
        // server can deliver "no responders" status frames via HMSG
        // rather than silently dropping them.
        connect.push_str(",\"no_responders\":true");

        if let Some(ref name) = self.config.name {
            connect.push_str(",\"name\":\"");
            connect.push_str(&nats_json_escape(name));
            connect.push('"');
        }

        if let Some(ref user) = self.config.user {
            connect.push_str(",\"user\":\"");
            connect.push_str(&nats_json_escape(user));
            connect.push('"');
        }

        if let Some(ref pass) = self.config.password {
            connect.push_str(",\"pass\":\"");
            connect.push_str(&nats_json_escape(pass));
            connect.push('"');
        }

        if let Some(ref token) = self.config.token {
            connect.push_str(",\"auth_token\":\"");
            connect.push_str(&nats_json_escape(token));
            connect.push('"');
        }

        match connect_auth {
            ConnectAuthPayload::None => {}
            ConnectAuthPayload::Nkey {
                public_key,
                signature_b64url,
            } => {
                connect.push_str(",\"nkey\":\"");
                connect.push_str(&nats_json_escape(&public_key));
                connect.push('"');
                connect.push_str(",\"sig\":\"");
                connect.push_str(&signature_b64url);
                connect.push('"');
            }
            ConnectAuthPayload::Jwt {
                jwt,
                signature_b64url,
                ..
            } => {
                connect.push_str(",\"jwt\":\"");
                connect.push_str(&nats_json_escape(&jwt));
                connect.push('"');
                connect.push_str(",\"sig\":\"");
                connect.push_str(&signature_b64url);
                connect.push('"');
            }
        }

        connect.push('}');

        let cmd = format!("CONNECT {connect}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;

        // If verbose mode, wait for +OK
        if self.config.verbose {
            self.expect_ok(cx).await?;
        }

        Ok(())
    }

    /// Attempt to reconnect when the TCP connection is lost.
    async fn try_reconnect(&mut self, cx: &Cx) -> Result<(), NatsError> {
        if !self.config.auto_reconnect {
            return Err(NatsError::NotConnected);
        }

        cx.trace("nats: connection lost, attempting to reconnect");

        let mut attempt = 0;
        let mut delay = self.config.reconnect_delay;

        loop {
            if self.config.max_reconnect_attempts > 0
                && attempt >= self.config.max_reconnect_attempts
            {
                cx.trace(&format!(
                    "nats: max reconnect attempts ({}) exceeded",
                    self.config.max_reconnect_attempts
                ));
                return Err(NatsError::NotConnected);
            }

            if attempt > 0 {
                cx.trace(&format!(
                    "nats: reconnect attempt {} after {}ms delay",
                    attempt + 1,
                    delay.as_millis()
                ));

                // Wait before retry
                crate::time::sleep(cx.now(), delay).await;

                // Exponential backoff with max cap
                delay = std::cmp::min(delay * 2, self.config.max_reconnect_delay);
            }

            attempt += 1;

            // Check for cancellation
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            // Attempt TCP reconnection
            let addr = format!("{}:{}", self.config.host, self.config.port);
            match TcpStream::connect(addr).await {
                Ok(new_stream) => {
                    cx.trace(&format!(
                        "nats: TCP reconnected to {}:{} (attempt {})",
                        self.config.host, self.config.port, attempt
                    ));

                    // Replace the stream and reset buffer
                    self.stream = new_stream.into();
                    self.read_buf = NatsReadBuffer::with_limit(self.config.max_read_buffer);
                    self.connected = false;

                    // Complete NATS handshake
                    match self.complete_reconnect_handshake(cx).await {
                        Ok(()) => {
                            cx.trace("nats: reconnection successful");
                            return Ok(());
                        }
                        Err(e) => {
                            cx.trace(&format!("nats: handshake failed during reconnect: {}", e));
                        }
                    }
                }
                Err(e) => {
                    cx.trace(&format!("nats: TCP reconnect failed: {}", e));
                }
            }
        }
    }

    /// Complete the NATS protocol handshake after TCP reconnection.
    async fn complete_reconnect_handshake(&mut self, cx: &Cx) -> Result<(), NatsError> {
        // Read initial INFO from server
        let info = self.read_info(cx).await?;

        // br-asupersync-8nx7g9: CRITICAL security fix - prevent TLS downgrade during reconnection.
        // Use the TLS requirement established during initial connection as a floor, then
        // OR in current client policy/server INFO. If TLS was ever required by the
        // original connection, every reconnect upgrades before replaying CONNECT/SUB.
        //
        // Original issue: Reconnection re-read server INFO and could be manipulated
        // by attackers to advertise tls_required=false, bypassing original security policy.
        //
        // Fix: Preserve the effective TLS requirement from initial connection, and upgrade
        // instead of aborting when TLS support is available.
        let tls_required =
            self.tls_required_on_connect || self.config.require_tls || info.tls_required;
        self.tls_required_on_connect = tls_required;
        if tls_required {
            cx.trace(&format!(
                "nats: reconnection TLS requirement preserved from initial connection \
                 (server_info_claims={}, client_config={}); upgrading before CONNECT replay",
                info.tls_required, self.config.require_tls
            ));
            self.upgrade_to_tls(cx, info.tls_required, self.config.require_tls)
                .await?;
        }

        // Update max_payload if server advertises a smaller limit
        if info.max_payload > 0 && info.max_payload < self.config.max_payload {
            self.config.max_payload = info.max_payload;
        }

        *self.state.server_info.lock() = Some(info);

        // Send CONNECT command
        self.send_connect(cx).await?;

        let replayed_subscriptions = self.replay_subscriptions_after_reconnect(cx).await?;
        self.connected = true;

        cx.trace(&format!(
            "nats: replayed {replayed_subscriptions} subscription(s) after reconnect"
        ));

        Ok(())
    }

    async fn replay_subscriptions_after_reconnect(&mut self, cx: &Cx) -> Result<usize, NatsError> {
        let mut subscriptions = {
            let subscriptions = self.state.subscriptions.lock();
            subscriptions
                .iter()
                .map(|(&sid, state)| SubscriptionReplay {
                    sid,
                    subject: state.subject.clone(),
                    queue_group: state.queue_group.clone(),
                })
                .collect::<Vec<_>>()
        };

        subscriptions.sort_by_key(|subscription| subscription.sid);
        if subscriptions.is_empty() {
            return Ok(0);
        }

        // A dropped or failed replay can leave the server with a partial SUB
        // transcript, so keep the connection unusable until every SUB is flushed.
        self.connected = false;
        for subscription in &subscriptions {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
            let cmd = if let Some(queue_group) = &subscription.queue_group {
                format!(
                    "SUB {} {} {}\r\n",
                    subscription.subject, queue_group, subscription.sid
                )
            } else {
                format!("SUB {} {}\r\n", subscription.subject, subscription.sid)
            };
            self.stream.write_all(cmd.as_bytes()).await?;
        }
        self.stream.flush().await?;

        Ok(subscriptions.len())
    }

    /// Wait for +OK response.
    async fn expect_ok(&mut self, cx: &Cx) -> Result<(), NatsError> {
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            if let Some(msg) = self.try_parse_message()? {
                match msg {
                    NatsMessage::Ok => return Ok(()),
                    NatsMessage::Err(e) => return Err(NatsError::Server(e)),
                    NatsMessage::Ping => {
                        // Respond to PING during handshake
                        self.send_server_pong().await?;
                    }
                    _ => {} // Ignore other messages during handshake
                }
            } else {
                self.read_more().await?;
            }
        }
    }

    /// Read more data from the stream.
    pub(crate) async fn read_more(&mut self) -> Result<(), NatsError> {
        let mut tmp = [0u8; 4096];
        let n = std::future::poll_fn(|task_cx| {
            if crate::cx::Cx::with_current(|c| c.checkpoint().is_err()).unwrap_or(false) {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "cancelled",
                )));
            }
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.stream).poll_read(task_cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        })
        .await?;

        if n == 0 {
            return Err(NatsError::Closed);
        }

        self.read_buf.extend(&tmp[..n])?;
        Ok(())
    }

    pub(crate) async fn read_more_until(
        &mut self,
        cx: &Cx,
        deadline: Time,
    ) -> Result<(), NatsError> {
        let now = timeout_now(cx);
        let remaining = Duration::from_nanos(deadline.duration_since(now));
        crate::time::timeout(now, remaining, self.read_more())
            .await
            .unwrap_or_else(|_| Err(request_timeout_error()))
    }

    async fn cleanup_request_subscription(&mut self, cx: &Cx, sid: u64, _reason: &str) {
        if let Err(_err) = self.unsubscribe(cx, sid).await {
            // tracing could go here, but for now we ignore
        }
    }

    /// Write a server-required `PONG` response.
    ///
    /// If the client is currently considered connected, fail closed around
    /// the write so a partial `PONG` cannot leave the connection reusable.
    pub(crate) async fn send_server_pong(&mut self) -> Result<(), NatsError> {
        let restore_connected = self.connected;
        if restore_connected {
            self.connected = false;
        }

        self.stream.write_all(b"PONG\r\n").await?;
        self.stream.flush().await?;

        if restore_connected {
            self.connected = true;
        }

        Ok(())
    }

    fn remove_local_subscription(&self, sid: u64) {
        let mut subs = self.state.subscriptions.lock();
        subs.remove(&sid);
    }

    /// Try to parse a complete message from the buffer.
    pub(crate) fn try_parse_message(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        if buf.is_empty() {
            return Ok(None);
        }

        // Check message type by prefix
        if buf.starts_with(b"INFO ") {
            return self.parse_info();
        } else if buf.starts_with(b"MSG ") {
            return self.parse_msg();
        } else if buf.starts_with(b"HMSG ") {
            return self.parse_hmsg();
        } else if buf.starts_with(b"+OK") {
            if buf.len() >= 5 && buf[3] == b'\r' && buf[4] == b'\n' {
                self.read_buf.consume(5);
                return Ok(Some(NatsMessage::Ok));
            } else if buf.len() < 5 {
                return Ok(None); // Need more data
            }
            return Err(NatsError::Protocol("malformed +OK frame".to_string()));
        } else if buf.starts_with(b"-ERR ") {
            return self.parse_err();
        } else if buf.starts_with(b"PING") {
            if buf.len() >= 6 && buf[4] == b'\r' && buf[5] == b'\n' {
                self.read_buf.consume(6);
                return Ok(Some(NatsMessage::Ping));
            } else if buf.len() < 6 {
                return Ok(None);
            }
            return Err(NatsError::Protocol("malformed PING frame".to_string()));
        } else if buf.starts_with(b"PONG") {
            if buf.len() >= 6 && buf[4] == b'\r' && buf[5] == b'\n' {
                self.read_buf.consume(6);
                return Ok(Some(NatsMessage::Pong));
            } else if buf.len() < 6 {
                return Ok(None);
            }
            return Err(NatsError::Protocol("malformed PONG frame".to_string()));
        }

        // Wait for more data or report unknown
        let Some(line_end) = self.read_buf.find_crlf() else {
            return Ok(None);
        };

        // Unknown message type
        let line = String::from_utf8_lossy(&self.read_buf.available()[..line_end]);
        Err(NatsError::Protocol(format!("unknown message: {line}")))
    }

    /// Parse INFO message.
    fn parse_info(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        let Some(end) = self.read_buf.find_crlf() else {
            return Ok(None);
        };

        let line = std::str::from_utf8(&buf[..end])
            .map_err(|_| NatsError::Protocol("invalid UTF-8 in INFO".to_string()))?;

        let json = line
            .strip_prefix("INFO ")
            .ok_or_else(|| NatsError::Protocol("malformed INFO".to_string()))?;

        let info = ServerInfo::parse(json)?;
        self.read_buf.consume(end + 2);
        Ok(Some(NatsMessage::Info(info)))
    }

    /// Parse MSG message.
    fn parse_msg(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        let Some(header_end) = self.read_buf.find_crlf() else {
            return Ok(None);
        };

        let header = std::str::from_utf8(&buf[..header_end])
            .map_err(|_| NatsError::Protocol("invalid UTF-8 in MSG header".to_string()))?;

        // MSG <subject> <sid> [reply-to] <#bytes>
        let mut parts = header.split_whitespace();
        let _msg = parts.next(); // "MSG"
        let subject_str = parts
            .next()
            .ok_or_else(|| NatsError::Protocol(format!("malformed MSG header: {header}")))?;
        let sid_str = parts
            .next()
            .ok_or_else(|| NatsError::Protocol(format!("malformed MSG header: {header}")))?;
        let third = parts
            .next()
            .ok_or_else(|| NatsError::Protocol(format!("malformed MSG header: {header}")))?;
        let fourth = parts.next();
        if parts.next().is_some() {
            return Err(NatsError::Protocol(format!(
                "malformed MSG header (too many fields): {header}"
            )));
        }

        let subject = subject_str.to_string();
        let sid: u64 = sid_str
            .parse()
            .map_err(|_| NatsError::Protocol(format!("invalid SID: {sid_str}")))?;

        let (reply_to, payload_len) = if let Some(len_str) = fourth {
            (
                Some(third.to_string()),
                len_str.parse::<usize>().map_err(|_| {
                    NatsError::Protocol(format!("invalid payload length: {len_str}"))
                })?,
            )
        } else {
            (
                None,
                third
                    .parse::<usize>()
                    .map_err(|_| NatsError::Protocol(format!("invalid payload length: {third}")))?,
            )
        };

        // Guard against oversized payloads from the server to prevent OOM.
        let max_buf = self.config.max_read_buffer;
        if payload_len > max_buf {
            return Err(NatsError::Protocol(format!(
                "MSG payload length {payload_len} exceeds maximum ({max_buf} bytes)"
            )));
        }

        // Check if we have the full payload + trailing CRLF
        let payload_start = header_end + 2;
        let payload_end = payload_start + payload_len;
        let total_len = payload_end + 2; // +2 for trailing CRLF

        if buf.len() < total_len {
            return Ok(None); // Need more data
        }
        if buf[payload_end] != b'\r' || buf[payload_end + 1] != b'\n' {
            return Err(NatsError::Protocol(
                "malformed MSG payload terminator".to_string(),
            ));
        }

        let payload = buf[payload_start..payload_end].to_vec();

        self.read_buf.consume(total_len);

        Ok(Some(NatsMessage::Msg(Message {
            subject,
            sid,
            reply_to,
            headers: None,
            payload,
        })))
    }

    /// Parse HMSG message.
    fn parse_hmsg(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let Some((message, total_frame_len)) =
            parse_hmsg_frame(self.read_buf.available(), self.config.max_read_buffer)?
        else {
            return Ok(None);
        };
        self.read_buf.consume(total_frame_len);
        Ok(Some(NatsMessage::Msg(message)))
    }

    /// Parse -ERR message.
    fn parse_err(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let buf = self.read_buf.available();
        let Some(end) = self.read_buf.find_crlf() else {
            return Ok(None);
        };

        let line = std::str::from_utf8(&buf[..end])
            .map_err(|_| NatsError::Protocol("invalid UTF-8 in -ERR".to_string()))?;

        let msg = line
            .strip_prefix("-ERR ")
            .unwrap_or(line)
            .trim_matches('\'')
            .to_string();

        self.read_buf.consume(end + 2);
        Ok(Some(NatsMessage::Err(msg)))
    }

    fn reply_status_error(message: &Message) -> Option<NatsError> {
        if !message.payload.is_empty() {
            return None;
        }

        let headers = message.headers.as_deref()?;
        let header_text = std::str::from_utf8(headers).ok()?;
        let mut lines = header_text.split("\r\n");
        let first_line = lines.next()?;
        if first_line != "NATS/1.0" && !first_line.starts_with("NATS/1.0 ") {
            return None;
        }

        let (mut status, mut description) =
            if let Some(status_line) = first_line.strip_prefix("NATS/1.0 ") {
                let status_line = status_line.trim();
                let mut parts = status_line.splitn(2, char::is_whitespace);
                (
                    parts.next().and_then(|value| value.parse::<u16>().ok()),
                    parts
                        .next()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned),
                )
            } else {
                (None, None)
            };

        for line in lines {
            if line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("Status") {
                status = value.parse::<u16>().ok();
            } else if name.eq_ignore_ascii_case("Description") {
                description = Some(value.to_string());
            }
        }

        let status = status?;
        if status < 300 {
            return None;
        }

        let detail = description.unwrap_or_else(|| format!("status {status}"));
        Some(NatsError::Server(format!("status {status}: {detail}")))
    }

    /// Publish a message to a subject.
    ///
    /// # At-most-once contract (br-asupersync-d49g0h)
    ///
    /// The previous order ran `handle_pending_messages` AFTER the PUB had
    /// already been flushed to the wire. If that read step erroreed (e.g.
    /// the server had emitted a `-ERR` between writes, or the inbox parser
    /// hit a transport failure), the function returned `Err(...)` even
    /// though the broker had definitively accepted the message. Callers
    /// would retry, producing duplicates on the broker — a silent NATS
    /// at-most-once violation.
    ///
    /// The fix: drain pending server messages BEFORE the wire write. If
    /// draining errors, no PUB has been sent yet so it's safe to surface
    /// the error to the caller. Once `flush().await?` returns `Ok`, the
    /// publish is definitive and the function commits to returning `Ok(())`
    /// — it does NOT perform any further wire reads that could fail and
    /// confuse the retry-vs-already-committed boundary.
    pub async fn publish(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            // Try to reconnect if auto-reconnect is enabled
            self.try_reconnect(cx).await?;
        }
        validate_nats_publish_subject(subject, "subject")?;

        if payload.len() > self.config.max_payload {
            return Err(NatsError::Protocol(format!(
                "payload too large: {} > {}",
                payload.len(),
                self.config.max_payload
            )));
        }

        // Drain pending server messages (PING → PONG, MSG → dispatch,
        // -ERR → typed error) BEFORE writing the PUB. Any error here
        // pre-dates the wire write, so failing the publish is safe — the
        // broker has not seen this PUB yet.
        self.handle_pending_messages(cx).await?;

        // Mark disconnected before the multi-part write so that if this
        // future is dropped mid-write, the connection is not reused in a
        // desynchronized state (partial PUB command on the wire).
        self.connected = false;

        let cmd = format!("PUB {subject} {}\r\n", payload.len());
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.write_all(payload).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;

        // PUB is now definitively on the wire. Commit to Ok — any post-flush
        // wire-read error must NOT roll the publish back via Err, or callers
        // will retry and the broker will see the message twice.
        self.connected = true;
        Ok(())
    }

    /// Publish a message with a reply-to subject.
    pub async fn publish_request(
        &mut self,
        cx: &Cx,
        subject: &str,
        reply_to: &str,
        payload: &[u8],
    ) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_publish_subject(subject, "subject")?;
        validate_nats_publish_subject(reply_to, "reply-to subject")?;

        if payload.len() > self.config.max_payload {
            return Err(NatsError::Protocol(format!(
                "payload too large: {} > {}",
                payload.len(),
                self.config.max_payload
            )));
        }

        // Mark disconnected before the multi-part write so that if this
        // future is dropped mid-write, the connection is not reused in a
        // desynchronized state (partial PUB command on the wire).
        self.connected = false;

        let cmd = format!("PUB {subject} {reply_to} {}\r\n", payload.len());
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.write_all(payload).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;

        self.connected = true;
        Ok(())
    }

    /// Publish a message with NATS v1 headers and a reply-to subject.
    ///
    /// Wire format (per https://docs.nats.io/reference/reference-protocols/nats-protocol#hpub):
    ///
    /// ```text
    /// HPUB <subject> [reply-to] <header-bytes> <total-bytes>\r\n
    /// NATS/1.0\r\n<Key1>: <Value1>\r\n...<KeyN>: <ValueN>\r\n\r\n
    /// <payload>\r\n
    /// ```
    ///
    /// `header-bytes` is the length of the header block (`NATS/1.0\r\n…\r\n\r\n`),
    /// `total-bytes` is `header-bytes + payload.len()`.
    ///
    /// Refuses to send if the server did not advertise `headers:true` in
    /// its INFO frame at connect time — older brokers will treat HPUB as
    /// a syntax error and close the connection.
    ///
    /// Used by JetStream `publish_with_id` to set `Nats-Msg-Id` for
    /// server-side dedup (br-asupersync-byc2d1).
    pub async fn publish_request_with_headers(
        &mut self,
        cx: &Cx,
        subject: &str,
        reply_to: &str,
        headers: &[(&str, &[u8])],
        payload: &[u8],
    ) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_publish_subject(subject, "subject")?;
        validate_nats_publish_subject(reply_to, "reply-to subject")?;
        let server_supports_headers = self
            .state
            .server_info
            .lock()
            .as_ref()
            .is_some_and(|info| info.headers);
        if !server_supports_headers {
            return Err(NatsError::Protocol(
                "server did not advertise headers:true in INFO; HPUB is not allowed".to_string(),
            ));
        }

        if payload.len() > self.config.max_payload {
            return Err(NatsError::Protocol(format!(
                "headers+payload too large: {} > {}",
                payload.len(),
                self.config.max_payload
            )));
        }
        let max_header_bytes = self.config.max_payload - payload.len();
        let header_block = encode_nats_headers(headers, max_header_bytes)?;
        let header_len = header_block.len();
        let total_len = header_len + payload.len();

        // Mark disconnected before the multi-part write so that if this
        // future is dropped mid-write, the connection is not reused in a
        // desynchronized state (partial HPUB command on the wire).
        self.connected = false;

        let cmd = format!("HPUB {subject} {reply_to} {header_len} {total_len}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.write_all(&header_block).await?;
        self.stream.write_all(payload).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;

        self.connected = true;
        Ok(())
    }

    /// Request/reply pattern with NATS v1 headers.
    ///
    /// Equivalent to [`request`](Self::request) but emits the request via
    /// HPUB carrying the given headers (e.g. `Nats-Msg-Id` for JetStream
    /// dedup). The reply path is identical: a unique inbox subject is
    /// subscribed before publishing and the first matching message is
    /// returned. Fails if the server does not support headers.
    pub async fn request_with_headers(
        &mut self,
        cx: &Cx,
        subject: &str,
        headers: &[(&str, &[u8])],
        payload: &[u8],
    ) -> Result<Message, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_publish_subject(subject, "subject")?;

        let inbox = format!(
            "_INBOX.{}.{}",
            self.next_sid.load(Ordering::Relaxed),
            random_suffix(cx)
        );

        let mut sub = self.subscribe(cx, &inbox).await?;

        if let Err(err) = self
            .publish_request_with_headers(cx, subject, &inbox, headers, payload)
            .await
        {
            self.cleanup_request_subscription(cx, sub.sid(), "publish_request_with_headers_failed")
                .await;
            return Err(err);
        }

        // Wait for response with timeout. Mirror of the loop in `request`;
        // a future refactor (br-asupersync-byc2d1 follow-up) should fold
        // both into a private await_request_reply helper.
        let deadline = timeout_now(cx) + self.config.request_timeout;

        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            let mut processed_any = false;
            loop {
                let message = match self.try_parse_message() {
                    Ok(message) => message,
                    Err(err) => {
                        self.cleanup_request_subscription(cx, sub.sid(), "parse_failed")
                            .await;
                        return Err(err);
                    }
                };

                match message {
                    Some(NatsMessage::Ping) => {
                        if let Err(err) = self.send_server_pong().await {
                            self.cleanup_request_subscription(
                                cx,
                                sub.sid(),
                                "server_ping_write_failed",
                            )
                            .await;
                            return Err(err);
                        }
                        processed_any = true;
                    }
                    Some(NatsMessage::Msg(m)) => {
                        if m.sid == sub.sid() {
                            self.unsubscribe(cx, sub.sid()).await?;
                            if let Some(err) = Self::reply_status_error(&m) {
                                return Err(err);
                            }
                            return Ok(m);
                        }
                        self.dispatch_message(m);
                        processed_any = true;
                    }
                    Some(NatsMessage::Err(e)) => {
                        self.cleanup_request_subscription(cx, sub.sid(), "server_error")
                            .await;
                        return Err(NatsError::Server(e));
                    }
                    Some(_) => {
                        processed_any = true;
                    }
                    None => {
                        if processed_any {
                            break;
                        }

                        if let Err(err) = self.read_more_until(cx, deadline).await {
                            self.cleanup_request_subscription(
                                cx,
                                sub.sid(),
                                REQUEST_TIMEOUT_MESSAGE,
                            )
                            .await;
                            return Err(err);
                        }
                        processed_any = true;
                    }
                }
            }

            if let Some(msg) = sub.try_next() {
                self.unsubscribe(cx, sub.sid()).await?;
                if let Some(err) = Self::reply_status_error(&msg) {
                    return Err(err);
                }
                return Ok(msg);
            }
        }
    }

    /// Request/reply pattern: publish and wait for a single response.
    ///
    /// This creates a unique inbox subject, subscribes to it, publishes
    /// the request, and waits for the first response (or timeout).
    pub async fn request(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<Message, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_publish_subject(subject, "subject")?;

        // Generate unique inbox subject
        let inbox = format!(
            "_INBOX.{}.{}",
            self.next_sid.load(Ordering::Relaxed),
            random_suffix(cx)
        );

        // Subscribe to inbox
        let mut sub = self.subscribe(cx, &inbox).await?;

        // Publish request with reply-to inbox
        if let Err(err) = self.publish_request(cx, subject, &inbox, payload).await {
            self.cleanup_request_subscription(cx, sub.sid(), "publish_request_failed")
                .await;
            return Err(err);
        }

        // Wait for response with timeout
        let deadline = timeout_now(cx) + self.config.request_timeout;

        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            let mut processed_any = false;
            // Process messages looking for our reply
            loop {
                let message = match self.try_parse_message() {
                    Ok(message) => message,
                    Err(err) => {
                        self.cleanup_request_subscription(cx, sub.sid(), "parse_failed")
                            .await;
                        return Err(err);
                    }
                };

                match message {
                    Some(NatsMessage::Ping) => {
                        if let Err(err) = self.send_server_pong().await {
                            self.cleanup_request_subscription(
                                cx,
                                sub.sid(),
                                "server_ping_write_failed",
                            )
                            .await;
                            return Err(err);
                        }
                        processed_any = true;
                    }
                    Some(NatsMessage::Msg(m)) => {
                        if m.sid == sub.sid() {
                            // This is our reply - clean up and return
                            self.unsubscribe(cx, sub.sid()).await?;
                            if let Some(err) = Self::reply_status_error(&m) {
                                return Err(err);
                            }
                            return Ok(m);
                        }
                        // Dispatch to other subscriptions
                        self.dispatch_message(m);
                        processed_any = true;
                    }
                    Some(NatsMessage::Err(e)) => {
                        self.cleanup_request_subscription(cx, sub.sid(), "server_error")
                            .await;
                        return Err(NatsError::Server(e));
                    }
                    Some(_) => {
                        processed_any = true;
                    }
                    None => {
                        if processed_any {
                            break;
                        }

                        if let Err(err) = self.read_more_until(cx, deadline).await {
                            self.cleanup_request_subscription(
                                cx,
                                sub.sid(),
                                REQUEST_TIMEOUT_MESSAGE,
                            )
                            .await;
                            return Err(err);
                        }
                        processed_any = true;
                    }
                }
            }

            // Also check the subscription channel in case message was already dispatched
            if let Some(msg) = sub.try_next() {
                self.unsubscribe(cx, sub.sid()).await?;
                if let Some(err) = Self::reply_status_error(&msg) {
                    return Err(err);
                }
                return Ok(msg);
            }
        }
    }

    /// Subscribe to a subject.
    ///
    /// Returns a `Subscription` that can be used to receive messages.
    pub async fn subscribe(&mut self, cx: &Cx, subject: &str) -> Result<Subscription, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_subscription_pattern(subject, "subject")?;

        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(256); // Bounded for backpressure

        // Register subscription
        {
            let mut subs = self.state.subscriptions.lock();
            subs.insert(
                sid,
                SubscriptionState {
                    subject: subject.to_string(),
                    queue_group: None,
                    sender: tx,
                },
            );
        }

        let mut guard = SubscribeGuard {
            subs: &self.state.subscriptions,
            sid,
            defused: false,
        };

        // Mark disconnected before write so partial command on cancellation
        // prevents further use of the desynchronized stream.
        self.connected = false;

        // Send SUB command. The guard prevents a leaked sender on write failure
        // or cancellation.
        let cmd = format!("SUB {subject} {sid}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;

        self.connected = true;
        guard.defused = true;

        cx.trace(&format!("nats: subscribed to {subject} (sid={sid})"));

        Ok(Subscription {
            sid,
            subject: subject.to_string(),
            rx,
            state: Arc::clone(&self.state),
        })
    }

    /// Subscribe with a queue group.
    pub async fn queue_subscribe(
        &mut self,
        cx: &Cx,
        subject: &str,
        queue_group: &str,
    ) -> Result<Subscription, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_subscription_pattern(subject, "subject")?;
        validate_nats_token(queue_group, "queue group")?;

        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(256);

        {
            let mut subs = self.state.subscriptions.lock();
            subs.insert(
                sid,
                SubscriptionState {
                    subject: subject.to_string(),
                    queue_group: Some(queue_group.to_string()),
                    sender: tx,
                },
            );
        }

        let mut guard = SubscribeGuard {
            subs: &self.state.subscriptions,
            sid,
            defused: false,
        };

        // Mark disconnected before write to prevent reuse on partial write.
        self.connected = false;

        // Send SUB command. Clean up the subscription entry on write failure
        // or cancellation (same as subscribe()).
        let cmd = format!("SUB {subject} {queue_group} {sid}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;

        self.connected = true;
        guard.defused = true;

        Ok(Subscription {
            sid,
            subject: subject.to_string(),
            rx,
            state: Arc::clone(&self.state),
        })
    }

    /// Unsubscribe from a subscription.
    pub async fn unsubscribe(&mut self, cx: &Cx, sid: u64) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // Remove from local state
        self.remove_local_subscription(sid);

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        // Send UNSUB command. Mark disconnected to prevent reuse on partial write.
        self.connected = false;
        let cmd = format!("UNSUB {sid}\r\n");
        self.stream.write_all(cmd.as_bytes()).await?;
        self.stream.flush().await?;
        self.connected = true;

        Ok(())
    }

    /// Send PING and wait for PONG.
    pub async fn ping(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        // Mark disconnected before write+read so that if this future is
        // dropped mid-exchange, the connection is not reused in a
        // desynchronized state.
        self.connected = false;

        self.stream.write_all(b"PING\r\n").await?;
        self.stream.flush().await?;

        // Wait for PONG
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            if let Some(msg) = self.try_parse_message()? {
                match msg {
                    NatsMessage::Pong => {
                        self.connected = true;
                        return Ok(());
                    }
                    NatsMessage::Err(e) => return Err(NatsError::Server(e)),
                    NatsMessage::Ping => {
                        self.send_server_pong().await?;
                    }
                    NatsMessage::Msg(m) => {
                        // Dispatch to subscription
                        self.dispatch_message(m);
                    }
                    _ => {}
                }
            } else {
                self.read_more().await?;
            }
        }
    }

    /// Handle any pending server messages (like PING).
    async fn handle_pending_messages(&mut self, _cx: &Cx) -> Result<(), NatsError> {
        // Non-blocking check for pending messages
        loop {
            match self.try_parse_message()? {
                Some(NatsMessage::Ping) => {
                    self.send_server_pong().await?;
                }
                Some(NatsMessage::Msg(m)) => {
                    self.dispatch_message(m);
                }
                Some(NatsMessage::Err(e)) => {
                    return Err(NatsError::Server(e));
                }
                Some(_) => {}
                None => break,
            }
        }
        Ok(())
    }

    /// Dispatch a message to the appropriate subscription.
    pub(crate) fn dispatch_message(&self, msg: Message) {
        let subs = self.state.subscriptions.lock();
        if let Some(sub) = subs.get(&msg.sid) {
            // Try to send; warn if channel is full (backpressure)
            if sub.sender.try_send(msg).is_err() {
                warn!(
                    subject = %sub.subject,
                    "NATS message dropped due to backpressure - consumer too slow"
                );
            }
        }
    }

    /// Process incoming messages and dispatch to subscriptions.
    /// Call this periodically if you have active subscriptions.
    pub async fn process(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        let mut processed_any = false;
        loop {
            match self.try_parse_message()? {
                Some(NatsMessage::Ping) => {
                    self.send_server_pong().await?;
                    processed_any = true;
                }
                Some(NatsMessage::Msg(m)) => {
                    self.dispatch_message(m);
                    processed_any = true;
                }
                Some(NatsMessage::Err(e)) => {
                    return Err(NatsError::Server(e));
                }
                Some(_) => {
                    processed_any = true;
                }
                None => {
                    if processed_any {
                        break;
                    }

                    self.read_more().await?;
                    // We read more data, but we only want to read once per `process` call
                    // if we are waiting for a partial message to complete.
                    processed_any = true;
                }
            }
        }

        Ok(())
    }

    /// Close the connection gracefully.
    ///
    /// Flushes pending writes before shutting down the TCP stream.
    pub async fn close(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        self.state.closed.store(true, Ordering::Release);

        // Clear all subscriptions
        {
            let mut subs = self.state.subscriptions.lock();
            subs.clear();
        }

        if self.connected {
            // Best-effort flush before shutdown
            let _ = self.stream.flush().await;
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
        self.connected = false;
        Ok(())
    }

    /// Get server info.
    pub fn server_info(&self) -> Option<ServerInfo> {
        self.state.server_info.lock().clone()
    }
}

fn parse_hmsg_frame(
    buf: &[u8],
    max_read_buffer: usize,
) -> Result<Option<(Message, usize)>, NatsError> {
    let Some(header_end) = find_crlf(buf) else {
        return Ok(None);
    };

    let header = std::str::from_utf8(&buf[..header_end])
        .map_err(|_| NatsError::Protocol("invalid UTF-8 in HMSG header".to_string()))?;

    // HMSG <subject> <sid> [reply-to] <#header bytes> <#total bytes>
    let mut parts = header.split_whitespace();
    if parts.next() != Some("HMSG") {
        return Err(NatsError::Protocol(format!(
            "malformed HMSG header: {header}"
        )));
    }
    let subject_str = parts
        .next()
        .ok_or_else(|| NatsError::Protocol(format!("malformed HMSG header: {header}")))?;
    let sid_str = parts
        .next()
        .ok_or_else(|| NatsError::Protocol(format!("malformed HMSG header: {header}")))?;
    let remaining: Vec<_> = parts.collect();

    let (reply_to, header_len_str, total_len_str) = match remaining.as_slice() {
        [header_len_str, total_len_str] => (None, *header_len_str, *total_len_str),
        [reply_to, header_len_str, total_len_str] => (
            Some((*reply_to).to_string()),
            *header_len_str,
            *total_len_str,
        ),
        _ => {
            return Err(NatsError::Protocol(format!(
                "malformed HMSG header: {header}"
            )));
        }
    };

    let subject = subject_str.to_string();
    let sid: u64 = sid_str
        .parse()
        .map_err(|_| NatsError::Protocol(format!("invalid SID: {sid_str}")))?;
    let header_len = header_len_str.parse::<usize>().map_err(|_| {
        NatsError::Protocol(format!("invalid HMSG header length: {header_len_str}"))
    })?;
    let total_len = total_len_str
        .parse::<usize>()
        .map_err(|_| NatsError::Protocol(format!("invalid HMSG total length: {total_len_str}")))?;

    if header_len == 0 || header_len > total_len {
        return Err(NatsError::Protocol(format!(
            "invalid HMSG lengths: header_len={header_len}, total_len={total_len}"
        )));
    }

    if total_len > max_read_buffer {
        return Err(NatsError::Protocol(format!(
            "HMSG total length {total_len} exceeds maximum ({max_read_buffer} bytes)"
        )));
    }

    let body_start = header_end + 2;
    let body_end = body_start
        .checked_add(total_len)
        .ok_or_else(|| NatsError::Protocol("HMSG body length overflow".to_string()))?;
    let total_frame_len = body_end
        .checked_add(2)
        .ok_or_else(|| NatsError::Protocol("HMSG frame length overflow".to_string()))?;

    if buf.len() < total_frame_len {
        return Ok(None);
    }
    if buf[body_end] != b'\r' || buf[body_end + 1] != b'\n' {
        return Err(NatsError::Protocol(
            "malformed HMSG payload terminator".to_string(),
        ));
    }

    let header_block_end = body_start + header_len;
    let header_block = buf[body_start..header_block_end].to_vec();
    if !is_valid_nats_header_block(&header_block) {
        return Err(NatsError::Protocol(
            "malformed HMSG header block".to_string(),
        ));
    }

    let payload = buf[header_block_end..body_end].to_vec();
    Ok(Some((
        Message {
            subject,
            sid,
            reply_to,
            headers: Some(header_block),
            payload,
        },
        total_frame_len,
    )))
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    (0..buf.len().saturating_sub(1)).find(|&i| buf[i] == b'\r' && buf[i + 1] == b'\n')
}

/// Parse a NATS server INFO payload through the production parser for fuzzing.
#[cfg(any(test, feature = "fuzz"))]
pub fn fuzz_parse_nats_server_info(json: &str) -> Result<ServerInfo, NatsError> {
    ServerInfo::parse(json)
}

/// Parse an HMSG frame through the production parser for fuzzing.
#[cfg(any(test, feature = "fuzz"))]
pub fn fuzz_parse_nats_hmsg_frame(
    frame: &[u8],
    max_read_buffer: usize,
) -> Result<Option<Message>, NatsError> {
    parse_hmsg_frame(frame, max_read_buffer).map(|parsed| parsed.map(|(message, _)| message))
}

fn is_valid_nats_header_block(header_block: &[u8]) -> bool {
    if !header_block.ends_with(b"\r\n\r\n") {
        return false;
    }

    let Some(first_line_end) = header_block.windows(2).position(|window| window == b"\r\n") else {
        return false;
    };
    let first_line = &header_block[..first_line_end];
    first_line == b"NATS/1.0" || first_line.starts_with(b"NATS/1.0 ")
}

/// A subscription to a NATS subject.
pub struct Subscription {
    sid: u64,
    subject: String,
    rx: mpsc::Receiver<Message>,
    state: Arc<SharedState>,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("sid", &self.sid)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl Subscription {
    /// Get the subscription ID.
    #[must_use]
    pub fn sid(&self) -> u64 {
        self.sid
    }

    /// Get the subject this subscription is for.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Receive the next message. Cancellation-safe.
    pub async fn next(&mut self, cx: &Cx) -> Result<Option<Message>, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // Drain any buffered messages before reporting closure so that
        // messages dispatched before close() are not silently lost.
        if let Ok(msg) = self.rx.try_recv() {
            return Ok(Some(msg));
        }

        if self.state.closed.load(Ordering::Acquire) {
            return Ok(None);
        }

        match self.rx.recv(cx).await {
            Ok(msg) => Ok(Some(msg)),
            Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Empty) => Ok(None),
            Err(mpsc::RecvError::Cancelled) => Err(NatsError::Cancelled),
        }
    }

    /// Try to receive a message without blocking.
    pub fn try_next(&mut self) -> Option<Message> {
        self.rx.try_recv().ok()
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        // Remove from shared state
        let mut subs = self.state.subscriptions.lock();
        subs.remove(&self.sid);
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
    use crate::test_utils::{assert_completes_within, run_test_with_cx};
    use serde_json::json;
    use socket2::SockRef;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::mpsc as std_mpsc;
    use std::thread::{self, JoinHandle};

    #[cfg(feature = "tls")]
    const NATS_TEST_CERT_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.crt");
    #[cfg(feature = "tls")]
    const NATS_TEST_KEY_PEM: &[u8] = include_bytes!("../../tests/fixtures/tls/server.key");

    fn scrub_reply_subject(reply_to: Option<&str>) -> Option<&str> {
        let value = reply_to?;
        Some(if value.starts_with("_INBOX.") {
            "_INBOX.[SCRUBBED]"
        } else {
            value
        })
    }

    fn message_event_snapshot(message: &Message) -> serde_json::Value {
        json!({
            "subject": message.subject,
            "sid": message.sid,
            "reply_to": scrub_reply_subject(message.reply_to.as_deref()),
            "payload_utf8": String::from_utf8_lossy(&message.payload),
            "payload_len": message.payload.len(),
        })
    }

    fn read_protocol_line(reader: &mut BufReader<std::net::TcpStream>) -> String {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).expect("read protocol line");
        assert!(bytes > 0, "peer closed before sending a full protocol line");
        line
    }

    fn parse_pub_payload_len(header: &str) -> usize {
        let parts: Vec<_> = header.split_whitespace().collect();
        assert_eq!(parts.first().copied(), Some("PUB"));
        assert_eq!(parts.len(), 4, "request publish must include reply-to");
        parts[3].parse().expect("parse PUB payload length")
    }

    #[test]
    fn encode_nats_headers_rejects_oversize_block_before_allocation_uu9ayc() {
        let err = encode_nats_headers(&[("Nats-Msg-Id", b"1234567890")], 16)
            .expect_err("oversize header block must fail closed");
        match err {
            NatsError::Protocol(msg) => {
                assert_eq!(msg, "NATS header block too large: 37 > 16");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn encode_nats_headers_rejects_empty_block_when_base_exceeds_cap() {
        let err = encode_nats_headers(&[], 0)
            .expect_err("mandatory empty header block must respect max_header_bytes");
        match err {
            NatsError::Protocol(msg) => {
                assert_eq!(msg, "NATS header block too large: 12 > 0");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    fn read_optional_protocol_line(reader: &mut BufReader<std::net::TcpStream>) -> Option<String> {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(line),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                None
            }
            Err(err) => panic!("read protocol line: {err}"),
        }
    }

    fn trim_protocol_line(line: String) -> String {
        line.trim_end_matches(['\r', '\n']).to_string()
    }

    fn parse_connect_json(connect_line: &str) -> serde_json::Value {
        let connect_json = connect_line
            .strip_prefix("CONNECT ")
            .expect("CONNECT prefix");
        serde_json::from_str(connect_json).expect("CONNECT JSON")
    }

    fn spawn_connect_recorder(
        info_json: &str,
        post_connect_line: Option<&str>,
    ) -> (SocketAddr, JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind connect test listener");
        let addr = listener.local_addr().expect("listener addr");
        let info_line = format!("INFO {info_json}\r\n");
        let post_connect_line = post_connect_line.map(|line| format!("{line}\r\n"));
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connect client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .write_all(info_line.as_bytes())
                .expect("write INFO line");
            stream.flush().expect("flush INFO line");

            let mut reader = BufReader::new(stream);
            let connect_line = trim_protocol_line(read_protocol_line(&mut reader));
            if let Some(post_connect_line) = post_connect_line {
                let stream = reader.get_mut();
                stream
                    .write_all(post_connect_line.as_bytes())
                    .expect("write post-CONNECT response");
                stream.flush().expect("flush post-CONNECT response");
            }
            connect_line
        });
        (addr, server)
    }

    fn deterministic_user_seed(byte: u8) -> String {
        KeyPair::new_from_raw(KeyPairType::User, [byte; 32])
            .expect("deterministic user seed")
            .seed()
            .expect("seed encoding")
    }

    fn deterministic_cluster_seed(byte: u8) -> String {
        KeyPair::new_from_raw(KeyPairType::Cluster, [byte; 32])
            .expect("deterministic cluster seed")
            .seed()
            .expect("seed encoding")
    }

    fn deterministic_valid_nonce(suffix: &str) -> String {
        format!("authNonceValid-{suffix}")
    }

    fn deterministic_operator_key(label: &str) -> KeyPair {
        let mut raw = [0u8; 32];
        for (index, byte) in label.bytes().enumerate() {
            let slot = index % raw.len();
            let offset = u8::try_from(index % 251).expect("bounded offset");
            raw[slot] = raw[slot].wrapping_add(byte).wrapping_add(offset);
        }
        if label.is_empty() {
            raw[0] = 1;
        }
        KeyPair::new_from_raw(KeyPairType::Operator, raw).expect("deterministic operator key")
    }

    fn test_user_jwt_for_seed(seed: &str, issuer: &str, name: &str) -> String {
        let public_key = KeyPair::from_seed(seed).expect("seed").public_key();
        let issuer_key = deterministic_operator_key(issuer);
        let issuer_public_key = issuer_key.public_key();
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"ed25519-nkey","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "sub": public_key,
                "iss": issuer_public_key,
                "name": name,
                "exp": 4_102_444_800_u64,
            })
            .to_string()
            .as_bytes(),
        );
        let signed_data = format!("{header}.{payload}");
        let signature = issuer_key
            .sign(signed_data.as_bytes())
            .expect("sign deterministic user JWT");
        let signature = URL_SAFE_NO_PAD.encode(signature);
        format!("{signed_data}.{signature}")
    }

    fn test_creds_document(jwt: &str, seed: &str) -> String {
        format!(
            "{jwt_begin}\n{jwt}\n{jwt_end}\n\n************************* IMPORTANT *************************\nNKEY Seed printed below can be used to sign and prove identity.\nNKEYs are sensitive and should be treated as secrets.\n\n{seed_begin}\n{seed}\n{seed_end}\n",
            jwt_begin = NATS_CREDS_JWT_BEGIN,
            jwt_end = NATS_CREDS_JWT_END,
            seed_begin = NATS_CREDS_SEED_BEGIN,
            seed_end = NATS_CREDS_SEED_END,
        )
    }

    fn spawn_reconnect_replay_recorder(
        expected_sub_count: usize,
    ) -> (SocketAddr, JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind reconnect test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept reconnect client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            stream
                .write_all(
                    b"INFO {\"server_id\":\"id\",\"server_name\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
                )
                .expect("write INFO");
            stream.flush().expect("flush INFO");

            let mut reader = BufReader::new(stream);
            let mut lines = Vec::with_capacity(expected_sub_count + 1);
            lines.push(trim_protocol_line(read_protocol_line(&mut reader)));
            for _ in 0..expected_sub_count {
                lines.push(trim_protocol_line(read_protocol_line(&mut reader)));
            }
            if let Some(extra) = read_optional_protocol_line(&mut reader) {
                lines.push(format!("EXTRA:{}", trim_protocol_line(extra)));
            }
            lines
        });
        (addr, server)
    }

    fn insert_replay_subscription(
        state: &Arc<SharedState>,
        sid: u64,
        subject: &str,
        queue_group: Option<&str>,
    ) {
        let (tx, _rx) = mpsc::channel(8);
        state.subscriptions.lock().insert(
            sid,
            SubscriptionState {
                subject: subject.to_string(),
                queue_group: queue_group.map(str::to_string),
                sender: tx,
            },
        );
    }

    #[test]
    fn reconnect_replay_zero_subscriptions_sends_no_sub_commands_jh9g1j() {
        let (addr, server) = spawn_reconnect_replay_recorder(0);

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect reconnect client");
            let state = Arc::new(SharedState::new());
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: false,
                tls_required_on_connect: false,
            };

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("zero-subscription reconnect must succeed");
            assert!(client.connected, "client should be connected after replay");
        });

        let lines = server.join().expect("server join");
        assert_eq!(lines.len(), 1, "zero replay must only send CONNECT");
        assert!(
            lines[0].starts_with("CONNECT "),
            "unexpected CONNECT line: {:?}",
            lines[0]
        );
        println!(
            "NATS_RECONNECT_REPLAY scenario=zero subscriptions=0 replay_count=0 exact_rch_command='rch exec -- env CARGO_TARGET_DIR=${{TMPDIR:-/tmp}}/rch_target_asupersync_jh9g1j_nats cargo test -p asupersync --lib reconnect_replay --features test-internals -- --nocapture' verdict=pass"
        );
    }

    #[test]
    fn reconnect_replays_existing_subscriptions_sorted_with_queue_groups_jh9g1j() {
        let (addr, server) = spawn_reconnect_replay_recorder(3);

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect reconnect client");
            let state = Arc::new(SharedState::new());
            insert_replay_subscription(&state, 7, "metrics.cpu", None);
            insert_replay_subscription(&state, 2, "orders.*", Some("workers"));
            insert_replay_subscription(&state, 5, "events.>", None);

            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state,
                next_sid: AtomicU64::new(8),
                connected: false,
                tls_required_on_connect: false,
            };

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("subscription replay must succeed");
            assert!(client.connected, "client should be connected after replay");
        });

        let lines = server.join().expect("server join");
        assert!(
            lines[0].starts_with("CONNECT "),
            "unexpected CONNECT line: {:?}",
            lines[0]
        );
        assert_eq!(
            &lines[1..],
            &[
                "SUB orders.* workers 2".to_string(),
                "SUB events.> 5".to_string(),
                "SUB metrics.cpu 7".to_string(),
            ],
            "subscriptions must replay once in deterministic SID order"
        );
        println!(
            "NATS_RECONNECT_REPLAY scenario=many_queue_wildcard subscription_ids=[2,5,7] queue_groups=1 replay_count=3 failure_point=none cancellation_state=active verdict=pass"
        );
    }

    #[test]
    fn repeated_reconnect_replays_each_subscription_once_per_connection_jh9g1j() {
        let (first_addr, first_server) = spawn_reconnect_replay_recorder(2);
        let (second_addr, second_server) = spawn_reconnect_replay_recorder(2);

        run_test_with_cx(|cx| async move {
            let state = Arc::new(SharedState::new());
            insert_replay_subscription(&state, 11, "alpha", None);
            insert_replay_subscription(&state, 12, "beta", Some("queue"));

            let first_stream = TcpStream::connect(format!("{first_addr}"))
                .await
                .expect("connect first reconnect client");
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: first_stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(13),
                connected: false,
                tls_required_on_connect: false,
            };

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("first replay must succeed");

            client.stream = TcpStream::connect(format!("{second_addr}"))
                .await
                .expect("connect second reconnect client")
                .into();
            client.read_buf = NatsReadBuffer::new();
            client.connected = false;

            client
                .complete_reconnect_handshake(&cx)
                .await
                .expect("second replay must succeed");
        });

        for (label, server) in [("first", first_server), ("second", second_server)] {
            let lines = server.join().expect("server join");
            assert_eq!(
                &lines[1..],
                &["SUB alpha 11".to_string(), "SUB beta queue 12".to_string()],
                "{label} reconnect must replay each active subscription exactly once"
            );
        }
        println!(
            "NATS_RECONNECT_REPLAY scenario=repeated subscription_ids=[11,12] replay_count_per_connection=2 duplicate_sub_commands=0 verdict=pass"
        );
    }

    #[test]
    fn reconnect_replay_failure_keeps_subscription_state_and_disconnects_jh9g1j() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind replay failure listener");
        let addr = listener.local_addr().expect("listener addr");
        let (closed_tx, closed_rx) = std_mpsc::channel();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept replay failure client");
            SockRef::from(&stream)
                .set_linger(Some(Duration::ZERO))
                .expect("force reset on close");
            drop(stream);
            closed_tx.send(()).expect("closed ack");
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect replay failure client");
            closed_rx.recv().expect("server closed");

            let state = Arc::new(SharedState::new());
            insert_replay_subscription(&state, 42, "svc.echo", None);
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(43),
                connected: true,
                tls_required_on_connect: false,
            };

            let err = client
                .replay_subscriptions_after_reconnect(&cx)
                .await
                .expect_err("replay write to reset peer must fail");
            assert!(
                matches!(err, NatsError::Io(_)),
                "expected I/O replay failure, got {err:?}"
            );
            assert!(
                !client.connected,
                "failed replay must leave connection marked unusable"
            );
            assert!(
                state.subscriptions.lock().contains_key(&42),
                "local subscription must survive failed replay for next reconnect"
            );
        });

        server.join().expect("server join");
        println!(
            "NATS_RECONNECT_REPLAY scenario=replay_failure subscription_ids=[42] replay_count=0 failure_point=write cancellation_state=active local_state_preserved=true verdict=pass"
        );
    }

    #[test]
    fn test_config_from_url_simple() {
        let config = NatsConfig::from_url("nats://localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert!(config.user.is_none());
        assert!(config.password.is_none());
    }

    #[test]
    fn test_config_from_url_with_auth() {
        let config = NatsConfig::from_url("nats://user:pass@localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert_eq!(config.user, Some("user".to_string()));
        assert_eq!(config.password, Some("pass".to_string()));
    }

    // br-asupersync-5in552: NatsConfig's Debug output MUST NOT
    // contain cleartext credentials. The manual Debug impl
    // substitutes "<redacted>" for any present user / password /
    // token. This test pins the redaction so a future refactor
    // that re-derives Debug (or adds a new credential field
    // without updating the manual impl) is caught immediately.
    #[test]
    fn test_natsconfig_debug_redacts_credentials_5in552() {
        let config =
            NatsConfig::from_url("nats://alice:supersecret123@nats.internal:4222").unwrap();
        let debug_output = format!("{config:?}");

        // Cleartext credential strings MUST NOT appear anywhere in
        // the Debug output.
        assert!(
            !debug_output.contains("supersecret123"),
            "Debug output leaked password: {debug_output}"
        );
        assert!(
            !debug_output.contains("alice"),
            "Debug output leaked username: {debug_output}"
        );

        // The redaction sentinel SHOULD appear for the present fields
        // so operators reading logs can see that credentials WERE
        // configured (not silently absent).
        assert!(
            debug_output.contains("<redacted>"),
            "Debug output should mark redacted credentials with sentinel: {debug_output}"
        );

        // Non-sensitive fields (host, port) are still visible.
        assert!(debug_output.contains("nats.internal"));
        assert!(debug_output.contains("4222"));
    }

    #[test]
    fn test_natsconfig_debug_redacts_token_5in552() {
        let mut config = NatsConfig::default();
        config.token = Some("eyJhbGciOiJIUzI1NiJ9.payload.signature".to_string());
        let debug_output = format!("{config:?}");

        assert!(
            !debug_output.contains("eyJhbGciOiJIUzI1NiJ9"),
            "Debug output leaked token: {debug_output}"
        );
        assert!(
            !debug_output.contains("signature"),
            "Debug output leaked token tail: {debug_output}"
        );
        assert!(
            debug_output.contains("<redacted>"),
            "Debug output should mark redacted token: {debug_output}"
        );
    }

    #[test]
    fn test_natsconfig_debug_redacts_jwt_and_nkey_seed_h1gf40() {
        let seed = deterministic_user_seed(7);
        let jwt = test_user_jwt_for_seed(&seed, "issuer", "operator");
        let mut config = NatsConfig::default();
        config.user_jwt = Some(jwt.clone());
        config.nkey_seed = Some(seed.clone());
        let debug_output = format!("{config:?}");

        assert!(
            !debug_output.contains(&jwt),
            "Debug output leaked JWT: {debug_output}"
        );
        assert!(
            !debug_output.contains(&seed),
            "Debug output leaked seed: {debug_output}"
        );
        assert!(
            debug_output.contains("user_jwt: Some(\"<redacted>\")"),
            "JWT field must be redacted: {debug_output}"
        );
        assert!(
            debug_output.contains("nkey_seed: Some(\"<redacted>\")"),
            "seed field must be redacted: {debug_output}"
        );
    }

    #[test]
    fn test_natsconfig_debug_unset_credentials_show_none_5in552() {
        let config = NatsConfig::default();
        let debug_output = format!("{config:?}");

        // Default config has None for user/password/token. Debug
        // output should show None for those fields, NOT <redacted>
        // (so operators can distinguish 'no credential configured'
        // from 'credential configured but redacted').
        assert!(
            !debug_output.contains("<redacted>"),
            "Default config should not show <redacted>; got: {debug_output}"
        );
        // The fields must still appear in the output as None for
        // diagnostic clarity.
        assert!(debug_output.contains("user: None"));
        assert!(debug_output.contains("password: None"));
        assert!(debug_output.contains("token: None"));
        assert!(debug_output.contains("user_jwt: None"));
        assert!(debug_output.contains("nkey_seed: None"));
    }

    #[test]
    fn nats_config_apply_creds_extracts_jwt_and_seed_h1gf40() {
        let seed = deterministic_user_seed(5);
        let jwt = test_user_jwt_for_seed(&seed, "issuer-A", "operator-A");
        let creds = test_creds_document(&jwt, &seed);
        let mut config = NatsConfig::default();
        config.apply_creds(&creds).expect("parse creds");

        assert_eq!(config.user_jwt.as_deref(), Some(jwt.as_str()));
        assert_eq!(config.nkey_seed.as_deref(), Some(seed.as_str()));
    }

    #[test]
    fn nats_config_apply_creds_rejects_missing_seed_block_h1gf40() {
        let seed = deterministic_user_seed(6);
        let jwt = test_user_jwt_for_seed(&seed, "issuer-B", "operator-B");
        let creds = format!("{NATS_CREDS_JWT_BEGIN}\n{jwt}\n{NATS_CREDS_JWT_END}\n");
        let mut config = NatsConfig::default();
        let err = config
            .apply_creds(&creds)
            .expect_err("missing seed block must fail closed");

        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("USER NKEY SEED")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_jwt_without_seed_h1gf40() {
        let mut config = NatsConfig::default();
        config.user_jwt = Some("a.b.c".to_string());
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("jwt-no-seed")),
                ..ServerInfo::default()
            }))
            .expect_err("JWT without seed must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("requires an nkey_seed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_non_user_seed_h1gf40() {
        let mut config = NatsConfig::default();
        config.nkey_seed = Some(deterministic_cluster_seed(4));
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("cluster-seed")),
                ..ServerInfo::default()
            }))
            .expect_err("non-user seed must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("USER seed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_malformed_seed_h1gf40() {
        let mut config = NatsConfig::default();
        config.nkey_seed = Some("not-a-valid-seed".to_string());
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("malformed-seed")),
                ..ServerInfo::default()
            }))
            .expect_err("malformed seed must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("invalid NKey seed")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn resolve_connect_auth_rejects_malformed_jwt_h1gf40() {
        let mut config = NatsConfig::default();
        config.user_jwt = Some("not-a-jwt".to_string());
        config.nkey_seed = Some(deterministic_user_seed(12));
        let err = config
            .resolve_connect_auth(Some(&ServerInfo {
                nonce: Some(deterministic_valid_nonce("malformed-jwt")),
                ..ServerInfo::default()
            }))
            .expect_err("malformed JWT must fail closed");
        assert!(
            matches!(err, NatsError::InvalidAuth(ref msg) if msg.contains("compact JWT")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn connect_user_password_auth_fields_unchanged_h1gf40() {
        let (addr, server) = spawn_connect_recorder(
            r#"{"server_id":"id","server_name":"test","version":"2.10.0","proto":1,"max_payload":1048576}"#,
            None,
        );

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                ..Default::default()
            };
            let _client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("legacy user/password connect should still succeed");
        });

        let connect_line = server.join().expect("server join");
        let connect = parse_connect_json(&connect_line);
        assert_eq!(connect["user"], "alice");
        assert_eq!(connect["pass"], "secret");
        assert!(connect.get("jwt").is_none());
        assert!(connect.get("nkey").is_none());
        assert!(connect.get("sig").is_none());
    }

    #[test]
    fn connect_nkey_auth_emits_signed_nonce_fields_h1gf40() {
        let seed = deterministic_user_seed(9);
        let nonce = "nkey-challenge-12345";
        let (addr, server) = spawn_connect_recorder(
            &format!(
                r#"{{"server_id":"id","server_name":"test","version":"2.10.0","proto":1,"max_payload":1048576,"nonce":"{nonce}"}}"#
            ),
            None,
        );
        let seed_for_client = seed.clone();

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                nkey_seed: Some(seed_for_client),
                ..Default::default()
            };
            let _client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("nkey auth connect should succeed");
        });

        let connect_line = server.join().expect("server join");
        let connect = parse_connect_json(&connect_line);
        let public_key = KeyPair::from_seed(&seed).expect("seed").public_key();
        let sig = connect["sig"].as_str().expect("sig field");
        let sig = decode_base64_url(sig, "CONNECT sig").expect("decode sig");
        KeyPair::from_public_key(&public_key)
            .expect("public key")
            .verify(nonce.as_bytes(), &sig)
            .expect("signature verification");
        assert_eq!(connect["nkey"], public_key);
        assert!(connect.get("jwt").is_none());
        assert!(connect.get("auth_token").is_none());
        println!(
            "NATS_AUTH_HANDSHAKE scenario=nkey_connect mode=nkey nonce_len={} signature_verified=true jwt_claims=none server_response=connect_ok reconnect_behavior=not_exercised verdict=pass",
            nonce.len()
        );
    }

    #[test]
    fn connect_jwt_auth_signs_nonce_and_maps_auth_error_h1gf40() {
        let seed = deterministic_user_seed(11);
        let jwt = test_user_jwt_for_seed(&seed, "issuer-C", "operator-C");
        let nonce = "jwt-challenge-abcdef";
        let (addr, server) = spawn_connect_recorder(
            &format!(
                r#"{{"server_id":"id","server_name":"test","version":"2.10.0","proto":1,"max_payload":1048576,"nonce":"{nonce}"}}"#
            ),
            Some("-ERR 'Authorization Violation'"),
        );
        let seed_for_client = seed.clone();
        let jwt_for_client = jwt.clone();

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user_jwt: Some(jwt_for_client),
                nkey_seed: Some(seed_for_client),
                verbose: true,
                ..Default::default()
            };
            let err = NatsClient::connect_with_config(&cx, config)
                .await
                .expect_err("server auth violation must map to NatsError::Server");
            assert!(
                matches!(err, NatsError::Server(ref msg) if msg.contains("Authorization Violation")),
                "unexpected error: {err:?}"
            );
        });

        let connect_line = server.join().expect("server join");
        let connect = parse_connect_json(&connect_line);
        let claims = parse_nats_jwt_claims(&jwt).expect("claims summary");
        let public_key = KeyPair::from_seed(&seed).expect("seed").public_key();
        let sig = connect["sig"].as_str().expect("sig field");
        let sig = decode_base64_url(sig, "CONNECT sig").expect("decode sig");
        KeyPair::from_public_key(&public_key)
            .expect("public key")
            .verify(nonce.as_bytes(), &sig)
            .expect("signature verification");
        assert_eq!(connect["jwt"], jwt);
        assert!(connect.get("nkey").is_none());
        println!(
            "NATS_AUTH_HANDSHAKE scenario=jwt_connect mode=jwt nonce_len={} signature_verified=true jwt_claims=\"{}\" server_response=authorization_violation reconnect_behavior=not_exercised verdict=pass",
            nonce.len(),
            claims.log_summary()
        );
    }

    #[test]
    fn test_config_from_url_with_token() {
        let config = NatsConfig::from_url("nats://mytoken@localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert_eq!(config.token, Some("mytoken".to_string()));
    }

    #[test]
    fn test_config_from_url_default_port() {
        let config = NatsConfig::from_url("nats://localhost").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222); // Default port
    }

    #[test]
    fn test_config_from_tls_url_sets_require_tls() {
        let config = NatsConfig::from_url("tls://localhost:4222").unwrap();
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
        assert!(config.require_tls);
    }

    #[test]
    fn test_config_from_url_ipv6() {
        let config = NatsConfig::from_url("nats://[::1]:4333").unwrap();
        assert_eq!(config.host, "[::1]");
        assert_eq!(config.port, 4333);
    }

    #[test]
    fn test_config_from_url_password_with_at_sign() {
        let config = NatsConfig::from_url("nats://user:pa@ss@localhost:4222").unwrap();
        assert_eq!(config.user.as_deref(), Some("user"));
        assert_eq!(config.password.as_deref(), Some("pa@ss"));
        assert_eq!(config.host, "localhost");
        assert_eq!(config.port, 4222);
    }

    /// br-asupersync-2kmc12: when the server's INFO frame advertises
    /// `tls_required = true`, NatsClient::connect_with_config MUST
    /// upgrade to TLS BEFORE sending the CONNECT command. In builds
    /// that cannot construct TLS, it must still fail closed before
    /// plaintext CONNECT. This is the credential-leak defense: the
    /// previous implementation read tls_required into ServerInfo but
    /// never consulted it, sending CONNECT (with user/pass/token in
    /// cleartext) to a server that claimed to require TLS.
    ///
    /// The test server scripts the wire exchange:
    ///   1. Accept the TCP connection.
    ///   2. Write an INFO frame with tls_required = true.
    ///   3. Read whatever the client sends. Plaintext CONNECT is
    ///      forbidden; TLS ClientHello bytes are acceptable in TLS
    ///      builds and prove the upgrade happens before credentials.
    #[test]
    fn connect_aborts_without_sending_connect_when_server_requires_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept test client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            // 1. Send INFO with tls_required=true.
            let info = b"INFO {\"server_id\":\"test\",\"server_name\":\"test\",\"version\":\"2.9.0\",\"proto\":1,\"max_payload\":1048576,\"tls_required\":true}\r\n";
            stream.write_all(info).expect("write INFO");
            stream.flush().expect("flush INFO");

            // 2. Read whatever the client sends. The client MUST NOT
            //    send plaintext CONNECT. TLS-enabled builds may send a
            //    ClientHello here; this plaintext test server then
            //    closes and the client surfaces a handshake error.
            let mut buf = [0u8; 1024];
            match stream.read(&mut buf) {
                Ok(0) => {
                    // Clean EOF — TLS unavailable/configured fail-closed.
                }
                Ok(n) => {
                    let leaked = String::from_utf8_lossy(&buf[..n]);
                    assert!(
                        !leaked.starts_with("CONNECT "),
                        "br-asupersync-2kmc12 REGRESSION: plaintext CONNECT \
                         sent after server INFO advertised tls_required=true; \
                         payload starts with: {leaked:?}"
                    );
                    assert!(
                        !leaked.contains("secret"),
                        "br-asupersync-2kmc12 REGRESSION: credentials leaked \
                         before TLS handshake; payload starts with: {leaked:?}"
                    );
                    // Non-CONNECT bytes are expected TLS handshake bytes.
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!(
                        "client neither closed nor attempted TLS after server \
                         signalled tls_required"
                    );
                }
                Err(_) => {
                    // Connection-reset / broken pipe — also acceptable;
                    // the client closed its side, OS reports the reset.
                }
            }
        });

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                ..Default::default()
            };
            let result = NatsClient::connect_with_config(&cx, config).await;
            result.expect_err(
                "plaintext test server cannot complete TLS, but client must never send plaintext CONNECT",
            );
        });

        server.join().expect("server thread join");
    }

    /// br-asupersync-2kmc12: when the client config sets require_tls =
    /// true, the same pre-CONNECT TLS gate fires regardless of what
    /// the server advertises.
    #[test]
    fn connect_aborts_without_sending_connect_when_client_requires_tls() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut stream, _) = listener.accept().expect("accept test client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            // Server advertises tls_required=false (legacy plaintext NATS).
            // Client config still mandates TLS so the gate must fire.
            let info = b"INFO {\"server_id\":\"test\",\"server_name\":\"test\",\"version\":\"2.9.0\",\"proto\":1,\"max_payload\":1048576,\"tls_required\":false}\r\n";
            stream.write_all(info).expect("write INFO");
            stream.flush().expect("flush INFO");

            let mut buf = [0u8; 1024];
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let leaked = String::from_utf8_lossy(&buf[..n]);
                    assert!(
                        !leaked.starts_with("CONNECT "),
                        "br-asupersync-2kmc12 REGRESSION: plaintext CONNECT \
                         sent despite client require_tls=true; payload: {leaked:?}"
                    );
                    assert!(
                        !leaked.contains("secret"),
                        "br-asupersync-2kmc12 REGRESSION: credentials leaked \
                         before TLS handshake; payload: {leaked:?}"
                    );
                }
            }
        });

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                require_tls: true,
                ..Default::default()
            };
            let result = NatsClient::connect_with_config(&cx, config).await;
            result.expect_err(
                "plaintext test server cannot complete TLS, but client must never send plaintext CONNECT",
            );
        });

        server.join().expect("server thread join");
    }

    #[cfg(feature = "tls")]
    #[test]
    fn connect_upgrades_to_tls_before_connect_when_server_requires_tls() {
        use crate::io::AsyncReadExt;
        use crate::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptorBuilder};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind TLS test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept TLS client");
            stream
                .write_all(
                    b"INFO {\"server_id\":\"test\",\"server_name\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576,\"tls_required\":true}\r\n",
                )
                .expect("write INFO");
            stream.flush().expect("flush INFO");

            let async_stream = TcpStream::from_std(stream).expect("wrap accepted TCP stream");
            let chain = CertificateChain::from_pem(NATS_TEST_CERT_PEM).expect("test cert chain");
            let key = PrivateKey::from_pem(NATS_TEST_KEY_PEM).expect("test private key");
            let acceptor = TlsAcceptorBuilder::new(chain, key)
                .build()
                .expect("build test acceptor");

            futures_lite::future::block_on(async move {
                let mut tls_stream = acceptor.accept(async_stream).await.expect("accept TLS");
                let mut buf = [0_u8; 4096];
                let n = tls_stream.read(&mut buf).await.expect("read TLS CONNECT");
                assert!(n > 0, "client must send CONNECT over TLS");
                let connect = String::from_utf8_lossy(&buf[..n]);
                assert!(
                    connect.starts_with("CONNECT "),
                    "expected CONNECT over TLS, got {connect:?}"
                );
                assert!(
                    connect.contains("\"tls_required\":true"),
                    "CONNECT should advertise TLS requirement, got {connect:?}"
                );
                assert!(
                    connect.contains("\"user\":\"alice\"")
                        && connect.contains("\"pass\":\"secret\""),
                    "credentials should be present only inside TLS, got {connect:?}"
                );
            });
        });

        run_test_with_cx(|cx| async move {
            let certs = Certificate::from_pem(NATS_TEST_CERT_PEM).expect("parse test cert");
            let connector = TlsConnectorBuilder::new()
                .insecure_add_root_certificate(&certs[0])
                .handshake_timeout(Duration::from_secs(2))
                .build()
                .expect("build test connector");
            let config = NatsConfig {
                host: "localhost".to_string(),
                port: addr.port(),
                user: Some("alice".into()),
                password: Some("secret".into()),
                tls_connector: Some(connector),
                ..Default::default()
            };

            let client = NatsClient::connect_with_config(&cx, config)
                .await
                .expect("TLS NATS handshake should succeed");
            assert!(
                client.tls_required_on_connect,
                "TLS requirement must be preserved for reconnect downgrade defense"
            );
        });

        server.join().expect("TLS server thread join");
    }

    #[test]
    fn test_server_info_parse() {
        let json = r#"{"server_id":"id123","server_name":"test","version":"2.9.0","proto":1,"max_payload":1048576,"tls_required":false,"nonce":"abc123"}"#;
        let info = ServerInfo::parse(json).expect("valid INFO JSON");
        assert_eq!(info.server_id, "id123");
        assert_eq!(info.server_name, "test");
        assert_eq!(info.version, "2.9.0");
        assert_eq!(info.proto, 1);
        assert_eq!(info.max_payload, 1_048_576);
        assert!(!info.tls_required);
        assert_eq!(info.nonce.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_extract_json_string() {
        let json = r#"{"name":"value","other":123}"#;
        assert_eq!(extract_json_string(json, "name"), Some("value".to_string()));
        assert_eq!(extract_json_string(json, "missing"), None);
    }

    #[test]
    fn test_extract_json_i64() {
        let json = r#"{"count":42,"neg":-5}"#;
        assert_eq!(extract_json_i64(json, "count"), Some(42));
        assert_eq!(extract_json_i64(json, "neg"), Some(-5));
        assert_eq!(extract_json_i64(json, "missing"), None);
    }

    #[test]
    fn test_extract_json_bool() {
        let json = r#"{"enabled":true,"disabled":false}"#;
        assert_eq!(extract_json_bool(json, "enabled"), Some(true));
        assert_eq!(extract_json_bool(json, "disabled"), Some(false));
        assert_eq!(extract_json_bool(json, "missing"), None);
    }

    #[test]
    fn test_config_invalid_url() {
        let result = NatsConfig::from_url("http://localhost:4222");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_config_invalid_port() {
        let result = NatsConfig::from_url("nats://localhost:notaport");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_config_invalid_empty_host() {
        let result = NatsConfig::from_url("nats://:4222");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn test_nats_error_display() {
        assert_eq!(
            format!("{}", NatsError::Cancelled),
            "NATS operation cancelled"
        );
        assert_eq!(format!("{}", NatsError::Closed), "NATS connection closed");
        assert_eq!(format!("{}", NatsError::NotConnected), "NATS not connected");
        assert_eq!(
            format!("{}", NatsError::SubscriptionNotFound(42)),
            "NATS subscription not found: 42"
        );
        assert_eq!(
            format!("{}", NatsError::Server("auth error".to_string())),
            "NATS server error: auth error"
        );
        assert_eq!(
            format!("{}", NatsError::Protocol("parse error".to_string())),
            "NATS protocol error: parse error"
        );
        assert_eq!(
            format!("{}", NatsError::InvalidUrl("bad".to_string())),
            "Invalid NATS URL: bad"
        );
        assert_eq!(
            format!("{}", NatsError::InvalidAuth("bad auth".to_string())),
            "NATS invalid auth configuration: bad auth"
        );
    }

    #[test]
    fn test_validate_nats_token_rejects_whitespace_and_controls() {
        assert!(validate_nats_token("foo.bar", "subject").is_ok());
        assert!(validate_nats_token("", "subject").is_err());
        assert!(validate_nats_token("foo bar", "subject").is_err());
        assert!(validate_nats_token("foo\r\nPUB x 1\r\nx", "subject").is_err());
        assert!(validate_nats_token("queue\tgroup", "queue group").is_err());
    }

    #[test]
    fn test_validate_nats_publish_subject_rejects_wildcards_and_empty_tokens() {
        assert!(validate_nats_publish_subject("foo.bar", "subject").is_ok());
        assert!(validate_nats_publish_subject("_INBOX.123.abc", "subject").is_ok());
        assert!(validate_nats_publish_subject("foo.bar.>", "subject").is_err());
        assert!(validate_nats_publish_subject("*", "subject").is_err());
        assert!(validate_nats_publish_subject("foo.*", "subject").is_err());
        assert!(validate_nats_publish_subject("foo..bar", "subject").is_err());
    }

    #[test]
    fn test_validate_nats_subscription_pattern_enforces_wildcard_grammar() {
        assert!(validate_nats_subscription_pattern("foo.bar", "subject").is_ok());
        assert!(validate_nats_subscription_pattern("foo.*", "subject").is_ok());
        assert!(validate_nats_subscription_pattern("foo.>", "subject").is_ok());
        assert!(validate_nats_subscription_pattern(">", "subject").is_ok());
        assert!(validate_nats_subscription_pattern("foo.>.bar", "subject").is_err());
        assert!(validate_nats_subscription_pattern("foo*>", "subject").is_err());
        assert!(validate_nats_subscription_pattern("foo..bar", "subject").is_err());
        assert!(validate_nats_subscription_pattern("foo.*.>.bar", "subject").is_err());
    }

    #[test]
    fn test_subscription_matches_subject_exact_and_single_wildcard() {
        assert!(subscription_matches_subject("time.us.east", "time.us.east"));
        assert!(subscription_matches_subject("time.*.east", "time.us.east"));
        assert!(!subscription_matches_subject(
            "time.*.east",
            "time.us.east.atlanta"
        ));
        assert!(!subscription_matches_subject("time.*.east", "time.east"));
    }

    #[test]
    fn test_subscription_matches_subject_tail_wildcard_requires_trailing_tokens() {
        assert!(subscription_matches_subject("time.>", "time.us"));
        assert!(subscription_matches_subject(
            "time.>",
            "time.us.east.atlanta"
        ));
        assert!(!subscription_matches_subject("time.>", "time"));
        assert!(subscription_matches_subject(">", "time.us"));
    }

    #[test]
    fn test_subscription_matches_subject_rejects_invalid_wildcard_placements() {
        assert!(!subscription_matches_subject("time>.east", "time.us.east"));
        assert!(!subscription_matches_subject("time.>.east", "time.us.east"));
        assert!(!subscription_matches_subject("time.*east", "time.us.east"));
        assert!(!subscription_matches_subject("time.east", "time.*"));
    }

    #[test]
    fn test_subscription_matches_subject_rejects_empty_tokens() {
        assert!(!subscription_matches_subject("time..east", "time.us.east"));
        assert!(!subscription_matches_subject(".time.east", "time.us.east"));
        assert!(!subscription_matches_subject("time.east", "time..east"));
        assert!(!subscription_matches_subject("time.east", "time.east."));
    }

    #[test]
    fn test_random_suffix_format() {
        let cx: Cx = Cx::for_testing();
        let s1 = random_suffix(&cx);
        let s2 = random_suffix(&cx);
        // Verify format is correct (16 hex chars)
        assert_eq!(s1.len(), 16);
        assert!(s1.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(s2.len(), 16);
        assert!(s2.chars().all(|c| c.is_ascii_hexdigit()));
        // With deterministic entropy, successive calls should differ
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_server_info_parse_minimal() {
        let json = "{}";
        let info = ServerInfo::parse(json).expect("valid empty INFO JSON");
        assert_eq!(info.server_id, "");
        assert_eq!(info.max_payload, 0);
        assert!(!info.tls_required);
    }

    #[test]
    fn test_server_info_parse_with_tls() {
        let json = r#"{"tls_required":true,"tls_available":true}"#;
        let info = ServerInfo::parse(json).expect("valid TLS INFO JSON");
        assert!(info.tls_required);
        assert!(info.tls_available);
    }

    #[test]
    fn test_nats_config_default() {
        let config = NatsConfig::default();
        assert_eq!(config.host, "127.0.0.1");
        assert_eq!(config.port, 4222);
        assert!(config.user.is_none());
        assert!(config.password.is_none());
        assert!(config.token.is_none());
        assert!(config.user_jwt.is_none());
        assert!(config.nkey_seed.is_none());
        assert!(!config.verbose);
        assert!(!config.pedantic);
        assert_eq!(config.max_payload, 1_048_576);
        assert_eq!(config.request_timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_read_buffer_operations() {
        let mut buf = NatsReadBuffer::new();
        assert!(buf.available().is_empty());

        buf.extend(b"hello\r\n").unwrap();
        assert_eq!(buf.available(), b"hello\r\n");
        assert_eq!(buf.find_crlf(), Some(5));

        buf.consume(7);
        assert!(buf.available().is_empty());
    }

    #[test]
    fn test_read_buffer_partial_crlf() {
        let mut buf = NatsReadBuffer::new();
        buf.extend(b"hello\r").unwrap();
        assert_eq!(buf.find_crlf(), None); // Incomplete CRLF

        buf.extend(b"\n").unwrap();
        assert_eq!(buf.find_crlf(), Some(5));
    }

    #[test]
    fn test_nats_json_escape_c1_control() {
        // C1 control U+0080 is 2 bytes in UTF-8 (0xC2, 0x80).
        // Must emit a single \u0080 escape, not per-byte \u00c2\u0080.
        let input = "\u{0080}";
        let escaped = nats_json_escape(input);
        assert_eq!(escaped, "\\u0080");
    }

    #[test]
    fn test_nats_json_escape_c0_control() {
        // C0 control U+0001 (SOH) is 1 byte in UTF-8.
        let escaped = nats_json_escape("\u{0001}");
        assert_eq!(escaped, "\\u0001");
    }

    #[test]
    fn test_nats_json_escape_common_chars() {
        assert_eq!(nats_json_escape(r#"hello"world"#), r#"hello\"world"#);
        assert_eq!(nats_json_escape("back\\slash"), "back\\\\slash");
        assert_eq!(nats_json_escape("new\nline"), "new\\nline");
        assert_eq!(nats_json_escape("plain"), "plain");
    }

    // Pure data-type tests (wave 14 – CyanBarn)

    #[test]
    fn nats_error_display_all_variants() {
        assert!(
            NatsError::Io(io::Error::other("e"))
                .to_string()
                .contains("I/O error")
        );
        assert!(
            NatsError::Protocol("p".into())
                .to_string()
                .contains("protocol error")
        );
        assert!(
            NatsError::Server("s".into())
                .to_string()
                .contains("server error")
        );
        assert!(
            NatsError::InvalidUrl("bad://".into())
                .to_string()
                .contains("bad://")
        );
        assert!(
            NatsError::InvalidAuth("bad auth".into())
                .to_string()
                .contains("bad auth")
        );
        assert!(NatsError::Cancelled.to_string().contains("cancelled"));
        assert!(NatsError::Closed.to_string().contains("closed"));
        assert!(
            NatsError::SubscriptionNotFound(42)
                .to_string()
                .contains("42")
        );
        assert!(
            NatsError::NotConnected
                .to_string()
                .contains("not connected")
        );
    }

    #[test]
    fn nats_error_debug() {
        let err = NatsError::Closed;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("Closed"));
    }

    #[test]
    fn nats_error_source_io() {
        let err = NatsError::Io(io::Error::other("disk"));
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn nats_request_timeout_error_is_classified_as_timeout() {
        assert!(request_timeout_error().is_timeout());
    }

    #[test]
    fn request_enforces_timeout_while_socket_reads_are_pending() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .write_all(
                    b"INFO {\"server_id\":\"id\",\"server_name\":\"test\",\"version\":\"2.10.0\",\"proto\":1,\"max_payload\":1048576}\r\n",
                )
                .expect("write INFO");
            stream.flush().expect("flush INFO");

            let mut reader = BufReader::new(stream);
            let connect = read_protocol_line(&mut reader);
            assert!(
                connect.starts_with("CONNECT "),
                "unexpected CONNECT: {connect:?}"
            );

            let subscribe = read_protocol_line(&mut reader);
            assert!(
                subscribe.starts_with("SUB _INBOX."),
                "unexpected SUB: {subscribe:?}"
            );

            let publish = read_protocol_line(&mut reader);
            assert!(
                publish.starts_with("PUB svc.echo _INBOX."),
                "unexpected PUB: {publish:?}"
            );

            let payload_len = parse_pub_payload_len(&publish);
            let mut payload = vec![0_u8; payload_len + 2];
            reader
                .read_exact(&mut payload)
                .expect("read request payload");
            assert_eq!(&payload[..payload_len], b"ping");
            assert_eq!(&payload[payload_len..], b"\r\n");

            read_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let config = NatsConfig {
                host: addr.ip().to_string(),
                port: addr.port(),
                request_timeout: Duration::from_millis(100),
                ..Default::default()
            };

            assert_completes_within(
                Duration::from_secs(2),
                "nats request timeout enforcement",
                move || {
                    let config = config.clone();
                    Box::pin(async move {
                        let mut client = NatsClient::connect_with_config(&cx, config)
                            .await
                            .expect("connect to test server");
                        let err = client
                            .request(&cx, "svc.echo", b"ping")
                            .await
                            .expect_err("request must time out");
                        assert!(
                            matches!(err, NatsError::Io(ref io_err) if io_err.kind() == io::ErrorKind::TimedOut),
                            "expected timed out I/O error, got {err:?}"
                        );
                        assert!(err.is_timeout(), "expected timeout classification");
                    })
                },
            )
            .await;
        });

        let unsubscribe = server.join().expect("server join");
        assert!(
            unsubscribe.starts_with("UNSUB "),
            "timeout cleanup must unsubscribe, got {unsubscribe:?}"
        );
    }

    #[test]
    fn publish_request_with_headers_rejects_oversize_headers_before_wire_write_uu9ayc() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            read_optional_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            *state.server_info.lock() = Some(ServerInfo {
                headers: true,
                max_payload: 32,
                ..ServerInfo::default()
            });
            let mut client = NatsClient {
                config: NatsConfig {
                    max_payload: 32,
                    ..Default::default()
                },
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state,
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            let err = client
                .publish_request_with_headers(
                    &cx,
                    "svc.echo",
                    "_INBOX.reply",
                    &[("Nats-Msg-Id", b"1234567890abcdef")],
                    b"",
                )
                .await
                .expect_err("oversize headers must fail closed");
            match err {
                NatsError::Protocol(msg) => {
                    assert_eq!(msg, "NATS header block too large: 43 > 32");
                }
                other => panic!("expected Protocol error, got {other:?}"),
            }
        });

        let wire = server.join().expect("server join");
        assert!(
            wire.is_none(),
            "oversize headers must not emit HPUB bytes, got {wire:?}"
        );
    }

    #[test]
    fn unsubscribe_on_disconnected_client_skips_wire_write() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            read_optional_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            let sid = 41;
            let (tx, _rx) = mpsc::channel(8);
            state.subscriptions.lock().insert(
                sid,
                SubscriptionState {
                    subject: "svc.echo".to_string(),
                    queue_group: None,
                    sender: tx,
                },
            );

            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: false,
                tls_required_on_connect: false,
            };

            let err = client
                .unsubscribe(&cx, sid)
                .await
                .expect_err("disconnected unsubscribe must fail closed");
            assert!(matches!(err, NatsError::NotConnected));
            assert!(
                !state.subscriptions.lock().contains_key(&sid),
                "local subscription must still be removed"
            );
        });

        let line = server.join().expect("server join");
        assert!(
            line.is_none(),
            "disconnected unsubscribe must not emit UNSUB, got {line:?}"
        );
    }

    #[test]
    fn ping_on_disconnected_client_skips_wire_write() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .expect("set read timeout");
            let mut reader = BufReader::new(stream);
            read_optional_protocol_line(&mut reader)
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: false,
                tls_required_on_connect: false,
            };

            let err = client
                .ping(&cx)
                .await
                .expect_err("disconnected ping must fail closed");
            assert!(matches!(err, NatsError::NotConnected));
        });

        let line = server.join().expect("server join");
        assert!(
            line.is_none(),
            "disconnected ping must not emit wire bytes, got {line:?}"
        );
    }

    #[test]
    fn process_ping_write_failure_marks_client_disconnected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let (close_tx, close_rx) = std_mpsc::channel();
        let (closed_tx, closed_rx) = std_mpsc::channel();

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            close_rx.recv().expect("close signal");
            SockRef::from(&stream)
                .set_linger(Some(Duration::ZERO))
                .expect("force reset on close");
            drop(stream);
            closed_tx.send(()).expect("closed ack");
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            client.read_buf.extend(b"PING\r\n").expect("buffer ping");
            close_tx.send(()).expect("signal close");
            closed_rx.recv().expect("server closed");
            thread::sleep(Duration::from_millis(20));

            let err = client
                .process(&cx)
                .await
                .expect_err("PONG write must fail against reset peer");
            assert!(
                matches!(err, NatsError::Io(_)),
                "expected I/O error, got {err:?}"
            );
            assert!(
                !client.connected,
                "client must remain disconnected after failed PONG write"
            );

            let follow_up = client
                .publish(&cx, "svc.echo", b"ping")
                .await
                .expect_err("fail-closed client must reject follow-up publish");
            assert!(matches!(follow_up, NatsError::NotConnected));
        });

        server.join().expect("server join");
    }

    #[test]
    fn request_ping_write_failure_cleans_up_temporary_subscription() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let mut reader = BufReader::new(stream);

            let subscribe = read_protocol_line(&mut reader);
            assert!(
                subscribe.starts_with("SUB _INBOX."),
                "unexpected SUB: {subscribe:?}"
            );

            let publish = read_protocol_line(&mut reader);
            assert!(
                publish.starts_with("PUB svc.echo _INBOX."),
                "unexpected PUB: {publish:?}"
            );

            let payload_len = parse_pub_payload_len(&publish);
            let mut payload = vec![0_u8; payload_len + 2];
            reader
                .read_exact(&mut payload)
                .expect("read request payload");
            assert_eq!(&payload[..payload_len], b"ping");
            assert_eq!(&payload[payload_len..], b"\r\n");

            let stream = reader.into_inner();
            SockRef::from(&stream)
                .set_linger(Some(Duration::ZERO))
                .expect("force reset on close");
            drop(stream);
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let state = Arc::new(SharedState::new());
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::clone(&state),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            client.read_buf.extend(b"PING\r\n").expect("buffer ping");

            let err = client
                .request(&cx, "svc.echo", b"ping")
                .await
                .expect_err("request must fail when PONG write fails");
            assert!(
                matches!(err, NatsError::Io(_)),
                "expected I/O error, got {err:?}"
            );
            assert!(
                state.subscriptions.lock().is_empty(),
                "temporary request inbox subscription must be cleaned up after PONG write failure"
            );
            assert!(
                !client.connected,
                "client must remain disconnected after failed PONG write"
            );
        });

        server.join().expect("server join");
    }

    #[test]
    fn nats_error_source_none_for_others() {
        assert!(std::error::Error::source(&NatsError::Cancelled).is_none());
        assert!(std::error::Error::source(&NatsError::Closed).is_none());
        assert!(std::error::Error::source(&NatsError::NotConnected).is_none());
    }

    #[test]
    fn nats_error_from_io() {
        let io_err = io::Error::other("net");
        let err: NatsError = NatsError::from(io_err);
        assert!(matches!(err, NatsError::Io(_)));
    }

    #[test]
    fn nats_config_debug_clone() {
        let cfg = NatsConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("NatsConfig"));

        let cloned = cfg;
        assert_eq!(cloned.host, "127.0.0.1");
        assert_eq!(cloned.port, 4222);
    }

    #[test]
    fn nats_config_from_url_with_creds() {
        let cfg = NatsConfig::from_url("nats://user:pass@myhost:4223").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 4223);
        assert_eq!(cfg.user, Some("user".into()));
        assert_eq!(cfg.password, Some("pass".into()));
    }

    #[test]
    fn nats_config_from_url_with_token() {
        let cfg = NatsConfig::from_url("nats://mytoken@server:4222").unwrap();
        assert_eq!(cfg.token, Some("mytoken".into()));
        assert!(cfg.user.is_none());
    }

    #[test]
    fn nats_config_from_url_host_only() {
        let cfg = NatsConfig::from_url("nats://myhost").unwrap();
        assert_eq!(cfg.host, "myhost");
        assert_eq!(cfg.port, 4222); // default
    }

    #[test]
    fn nats_config_from_url_invalid_scheme() {
        assert!(NatsConfig::from_url("http://localhost").is_err());
    }

    #[test]
    fn message_debug_clone() {
        let msg = Message {
            subject: "foo.bar".into(),
            sid: 1,
            reply_to: Some("_INBOX.123".into()),
            headers: None,
            payload: b"hello".to_vec(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("foo.bar"));
        assert!(dbg.contains("_INBOX"));

        let cloned = msg;
        assert_eq!(cloned.subject, "foo.bar");
        assert_eq!(cloned.sid, 1);
        assert_eq!(cloned.payload, b"hello");
    }

    #[test]
    fn message_no_reply() {
        let msg = Message {
            subject: "test".into(),
            sid: 0,
            reply_to: None,
            headers: None,
            payload: vec![],
        };
        assert!(msg.reply_to.is_none());
        assert!(msg.payload.is_empty());
    }

    #[test]
    fn nats_pubsub_event_snapshot_scrubbed() {
        let msg = Message {
            subject: "svc.echo".into(),
            sid: 7,
            reply_to: Some("_INBOX.42.reply".into()),
            headers: None,
            payload: b"{\"event\":\"published\",\"seq\":12}".to_vec(),
        };

        insta::assert_json_snapshot!("nats_pubsub_event_scrubbed", message_event_snapshot(&msg));
    }

    #[test]
    fn parse_hmsg_preserves_header_block_and_payload_72u8k4() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            drop(stream);
        });

        run_test_with_cx(|_cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            let headers = b"NATS/1.0\r\nFoo: bar\r\n\r\n";
            let payload = b"hello";
            let frame = format!(
                "HMSG headers.test 789 {} {}\r\n",
                headers.len(),
                headers.len() + payload.len()
            );
            client
                .read_buf
                .extend(frame.as_bytes())
                .expect("buffer HMSG header");
            client.read_buf.extend(headers).expect("buffer headers");
            client.read_buf.extend(payload).expect("buffer payload");
            client.read_buf.extend(b"\r\n").expect("buffer terminator");

            let parsed = client
                .try_parse_message()
                .expect("parse HMSG")
                .expect("complete HMSG frame");
            let NatsMessage::Msg(message) = parsed else {
                panic!("expected HMSG to parse as Msg");
            };

            assert_eq!(message.subject, "headers.test");
            assert_eq!(message.sid, 789);
            assert!(message.reply_to.is_none());
            assert_eq!(message.headers.as_deref(), Some(headers.as_slice()));
            assert_eq!(message.payload, payload);
        });

        server.join().expect("server join");
    }

    #[test]
    fn reply_status_error_surfaces_no_responders_hmsg_72u8k4() {
        let message = Message {
            subject: "_INBOX.1".into(),
            sid: 1,
            reply_to: None,
            headers: Some(
                b"NATS/1.0\r\nStatus: 503\r\nDescription: No Responders\r\n\r\n".to_vec(),
            ),
            payload: Vec::new(),
        };

        let err = NatsClient::reply_status_error(&message)
            .expect("empty status-only HMSG reply must surface as error");
        match err {
            NatsError::Server(message) => {
                assert!(
                    message.contains("503"),
                    "expected status code, got {message}"
                );
                assert!(
                    message.contains("No Responders"),
                    "expected server description, got {message}"
                );
            }
            other => panic!("expected server error, got {other:?}"),
        }
    }

    #[test]
    fn parse_hmsg_accepts_nats_status_line_header_block_6xjxd7() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            drop(stream);
        });

        run_test_with_cx(|_cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            let headers = b"NATS/1.0 408 Request Timeout\r\n\r\n";
            let frame = format!("HMSG _INBOX.1 42 {} {}\r\n", headers.len(), headers.len());
            client
                .read_buf
                .extend(frame.as_bytes())
                .expect("buffer HMSG status header");
            client.read_buf.extend(headers).expect("buffer headers");
            client.read_buf.extend(b"\r\n").expect("buffer terminator");

            let parsed = client
                .try_parse_message()
                .expect("parse status HMSG")
                .expect("complete status HMSG frame");
            let NatsMessage::Msg(message) = parsed else {
                panic!("expected status HMSG to parse as Msg");
            };

            assert_eq!(message.subject, "_INBOX.1");
            assert_eq!(message.sid, 42);
            assert!(message.payload.is_empty());
            assert_eq!(message.headers.as_deref(), Some(headers.as_slice()));

            let err = NatsClient::reply_status_error(&message)
                .expect("status-line HMSG reply must surface as server error");
            match err {
                NatsError::Server(message) => {
                    assert!(
                        message.contains("408"),
                        "expected status code, got {message}"
                    );
                    assert!(
                        message.contains("Request Timeout"),
                        "expected status description, got {message}"
                    );
                }
                other => panic!("expected server error, got {other:?}"),
            }
        });

        server.join().expect("server join");
    }

    #[test]
    fn server_info_default() {
        let info = ServerInfo::default();
        assert!(info.server_id.is_empty());
        assert!(info.server_name.is_empty());
        assert!(info.version.is_empty());
        assert_eq!(info.proto, 0);
        assert_eq!(info.max_payload, 0);
        assert!(!info.tls_required);
        assert!(!info.tls_available);
        assert!(info.connect_urls.is_empty());
    }

    #[test]
    fn server_info_debug_clone() {
        let info = ServerInfo {
            server_id: "test-id".into(),
            ..Default::default()
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ServerInfo"));

        let cloned = info;
        assert_eq!(cloned.server_id, "test-id");
    }

    #[test]
    fn server_info_parse_full() {
        let json = r#"{"server_id":"abc","server_name":"srv","version":"2.10","proto":1,"max_payload":1048576}"#;
        let info = ServerInfo::parse(json).expect("valid INFO JSON");
        assert_eq!(info.server_id, "abc");
        assert_eq!(info.server_name, "srv");
        assert_eq!(info.version, "2.10");
        assert_eq!(info.proto, 1);
        assert_eq!(info.max_payload, 1_048_576);
    }

    #[test]
    fn server_info_parse_empty() {
        let info = ServerInfo::parse("{}").expect("valid empty INFO JSON");
        assert!(info.server_id.is_empty());
        assert_eq!(info.proto, 0);
    }

    #[test]
    fn server_info_parse_rejects_malformed_json() {
        let err = ServerInfo::parse(r#"{"server_id":"abc""#)
            .expect_err("malformed INFO JSON must fail closed");
        assert!(
            matches!(err, NatsError::Protocol(ref message) if message.contains("malformed INFO JSON")),
            "expected malformed INFO protocol error, got {err:?}"
        );
    }

    #[test]
    fn server_info_parse_rejects_non_object_json() {
        let err = ServerInfo::parse("[]").expect_err("INFO JSON must be an object");
        assert!(
            matches!(err, NatsError::Protocol(ref message) if message.contains("expected object")),
            "expected non-object INFO protocol error, got {err:?}"
        );
    }

    #[test]
    fn nats_config_debug_clone_default() {
        let cfg = NatsConfig::default();
        let cloned = cfg.clone();
        assert_eq!(cloned.host, "127.0.0.1");
        assert_eq!(cloned.port, 4222);
        assert!(!cloned.verbose);
        assert!(!cloned.pedantic);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("NatsConfig"));
    }

    #[test]
    fn server_info_debug_clone_default() {
        let info = ServerInfo::default();
        assert!(info.server_id.is_empty());
        assert_eq!(info.proto, 0);
        assert!(!info.tls_required);
        let cloned = info.clone();
        assert_eq!(cloned.max_payload, 0);
        let dbg = format!("{info:?}");
        assert!(dbg.contains("ServerInfo"));
    }

    // ====================================================================
    // T6.7 Hardening tests
    // ====================================================================

    #[test]
    fn test_max_read_buffer_constant() {
        assert_eq!(DEFAULT_MAX_READ_BUFFER, 8 * 1024 * 1024);
    }

    #[test]
    fn test_read_buffer_rejects_oversized() {
        let mut buf = NatsReadBuffer::new();
        let big = vec![0u8; DEFAULT_MAX_READ_BUFFER + 1];
        let err = buf.extend(&big).unwrap_err();
        assert!(matches!(err, NatsError::Protocol(_)));
    }

    #[test]
    fn test_read_buffer_accepts_max() {
        let mut buf = NatsReadBuffer::new();
        let data = vec![0u8; DEFAULT_MAX_READ_BUFFER];
        buf.extend(&data).unwrap();
        assert_eq!(buf.available().len(), DEFAULT_MAX_READ_BUFFER);
    }

    #[test]
    fn test_read_buffer_consumed_data_not_counted() {
        let mut buf = NatsReadBuffer::new();
        // Fill to near max
        let data = vec![0u8; DEFAULT_MAX_READ_BUFFER - 100];
        buf.extend(&data).unwrap();
        // Consume most of it
        buf.consume(DEFAULT_MAX_READ_BUFFER - 200);
        // Now should be able to add more
        let more = vec![0u8; 200];
        buf.extend(&more).unwrap();
    }

    #[test]
    fn test_read_buffer_consume_clamps_when_over_consumed() {
        let mut buf = NatsReadBuffer::new();
        buf.extend(b"abc").unwrap();
        buf.consume(usize::MAX);
        assert!(buf.available().is_empty());

        // Buffer remains usable after an oversized consume request.
        buf.extend(b"xy").unwrap();
        assert_eq!(buf.available(), b"xy");
    }

    #[test]
    fn test_config_max_payload_default() {
        let config = NatsConfig::default();
        assert_eq!(config.max_payload, 1_048_576);
    }

    #[test]
    fn test_server_info_parse_max_payload() {
        let json = r#"{"max_payload":524288}"#;
        let info = ServerInfo::parse(json).expect("valid max_payload INFO JSON");
        assert_eq!(info.max_payload, 524_288);
    }

    #[test]
    fn test_validate_nats_token_accepts_valid_queue_group_token() {
        assert!(validate_nats_token("workers.v1", "queue group").is_ok());
    }

    #[test]
    fn test_validate_nats_token_rejects_empty() {
        assert!(validate_nats_token("", "subject").is_err());
    }

    #[test]
    fn test_validate_nats_token_rejects_newline_injection() {
        // A subject with \r\nPUB would inject a second command
        assert!(validate_nats_token("foo\r\nPUB evil 0\r\n", "subject").is_err());
    }

    #[test]
    fn test_validate_nats_token_rejects_oversized_subject() {
        let oversized = "a".repeat(MAX_NATS_SUBJECT_BYTES + 1);
        let err = validate_nats_token(&oversized, "subject").unwrap_err();
        match err {
            NatsError::Protocol(message) => {
                assert!(message.contains("exceeds"));
                assert!(message.contains("4096-byte"));
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_nats_token_rejects_tab() {
        assert!(validate_nats_token("foo\tbar", "queue").is_err());
    }

    #[test]
    fn test_parse_publish_subject_rejects_oversized_subject() {
        let oversized = "a".repeat(MAX_NATS_SUBJECT_BYTES + 1);
        assert!(parse_publish_subject(&oversized).is_none());
    }

    #[test]
    fn test_nats_json_escape_empty() {
        assert_eq!(nats_json_escape(""), "");
    }

    #[test]
    fn test_nats_json_escape_tab_and_cr() {
        assert_eq!(nats_json_escape("\t"), "\\t");
        assert_eq!(nats_json_escape("\r"), "\\r");
    }

    #[test]
    fn test_extract_json_string_with_escape() {
        let json = r#"{"key":"val\"ue"}"#;
        assert_eq!(
            extract_json_string(json, "key"),
            Some("val\"ue".to_string())
        );
    }

    #[test]
    fn test_extract_json_i64_negative() {
        let json = r#"{"val":-42}"#;
        assert_eq!(extract_json_i64(json, "val"), Some(-42));
    }

    #[test]
    fn test_extract_json_bool_missing() {
        let json = r#"{"other":42}"#;
        assert_eq!(extract_json_bool(json, "missing"), None);
    }

    #[test]
    fn test_config_from_url_ipv6_default_port() {
        let config = NatsConfig::from_url("nats://[::1]").unwrap();
        assert_eq!(config.host, "[::1]");
        assert_eq!(config.port, 4222);
    }

    #[test]
    fn test_config_from_url_ipv6_invalid() {
        let result = NatsConfig::from_url("nats://[::1");
        assert!(matches!(result, Err(NatsError::InvalidUrl(_))));
    }

    #[test]
    fn handle_pending_messages_propagates_server_error() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            drop(stream);
        });

        run_test_with_cx(|cx| async move {
            let stream = TcpStream::connect(format!("{addr}"))
                .await
                .expect("connect client");
            let mut client = NatsClient {
                config: NatsConfig::default(),
                stream: stream.into(),
                read_buf: NatsReadBuffer::new(),
                state: Arc::new(SharedState::new()),
                next_sid: AtomicU64::new(1),
                connected: true,
                tls_required_on_connect: false,
            };

            client
                .read_buf
                .extend(b"-ERR 'Permissions Violation'\r\n")
                .expect("buffer server error");

            let err = client
                .handle_pending_messages(&cx)
                .await
                .expect_err("server -ERR must propagate as error");
            assert!(
                matches!(&err, NatsError::Server(msg) if msg.contains("Permissions Violation")),
                "expected server error with permissions message, got {err:?}"
            );
        });

        server.join().expect("server join");
    }
}
