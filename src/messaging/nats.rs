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

use crate::channel::{mpsc, oneshot};
use crate::combinator::select::{Either, Select};
use crate::cx::{CancelWakerToken, Cx};
use crate::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use crate::net::TcpStream;
use crate::runtime::TaskHandle;
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
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Poll, Waker};
use std::time::Duration;
use subtle::ConstantTimeEq;

const REQUEST_TIMEOUT_MESSAGE: &str = "request timeout";
const CONNECT_TIMEOUT_MESSAGE: &str = "connection attempt timed out";

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
/// server; an operation that waits on the server returns its
/// `-ERR 'Permissions Violation ...'` as `NatsError::Server` (see test
/// `handle_pending_messages_propagates_server_error`). The server keeps the
/// connection open after such an error, and so does a supervised client.
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
    ///
    /// A supervised client keeps counting across reconnections that the server
    /// refuses with an error before they have stayed up for
    /// `max_reconnect_delay`, so a server that accepts the handshake and then
    /// refuses the client is not retried forever.
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

        // Top-level fields from the parsed object. Matching `"key":` in the
        // text read `"tls_required" : true` (valid JSON) as absent, skipping
        // the TLS upgrade, and let a nested key shadow a top-level one
        // (br-asupersync-pm29wb).
        let string = |key: &str| value.get(key).and_then(serde_json::Value::as_str);
        let integer = |key: &str| value.get(key).and_then(serde_json::Value::as_i64);
        let flag = |key: &str| value.get(key).and_then(serde_json::Value::as_bool);
        if let Some(v) = string("server_id") {
            info.server_id = v.to_string();
        }
        if let Some(v) = string("server_name") {
            info.server_name = v.to_string();
        }
        if let Some(v) = string("version") {
            info.version = v.to_string();
        }
        if let Some(v) = integer("proto") {
            info.proto = v as i32;
        }
        if let Some(v) = integer("max_payload") {
            info.max_payload = usize::try_from(v).unwrap_or(0);
        }
        if let Some(v) = flag("tls_required") {
            info.tls_required = v;
        }
        if let Some(v) = flag("tls_available") {
            info.tls_available = v;
        }
        if let Some(v) = flag("headers") {
            info.headers = v;
        }
        if let Some(v) = string("nonce") {
            info.nonce = Some(v.to_string());
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
    // Sanity floor only — reject empty/obviously-truncated nonces. A stock
    // nats-server nonce is 11 random bytes base64url-encoded to 15 chars, so a
    // `< 16` minimum rejected EVERY real server nonce and broke all nkey/JWT
    // auth. The client cannot police server-side nonce entropy anyway: a MITM
    // is free to forge a nonce of any length, so a length floor provides no
    // security, only interop breakage. Keep a small floor to catch a truncated
    // or empty handshake.
    const NONCE_MIN_LEN: usize = 8;
    if nonce.len() < NONCE_MIN_LEN {
        return Err(NatsError::InvalidAuth(format!(
            "server nonce too short: {} chars (minimum {NONCE_MIN_LEN})",
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
    if let Some(issuer_str) = issuer.as_deref().filter(|iss| !iss.is_empty()) {
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
                    "JWT issuer claim is not a valid NATS public key for signature verification"
                        .to_string(),
                ));
            }
        }
    } else {
        // A missing OR empty issuer claim means the JWT signature cannot be
        // verified. The empty case (`iss: ""`) must be rejected here rather
        // than silently skipped: the previous `if !is_empty()` guard left an
        // empty issuer to fall through with NO signature check, so a forged
        // JWT carrying `iss: ""` (and any signature) was accepted — an auth
        // bypass. Both cases now fail closed.
        return Err(NatsError::InvalidAuth(
            "JWT missing or empty issuer claim required for signature verification".to_string(),
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
    loss: Arc<SubscriptionLoss>,
}

#[derive(Default)]
struct SubscriptionLoss {
    count: AtomicU64,
    changed: crate::sync::Notify,
}

impl SubscriptionLoss {
    fn record_drop(&self) {
        let mut previous = self.count.load(Ordering::Relaxed);
        while previous != u64::MAX {
            match self.count.compare_exchange_weak(
                previous,
                previous + 1,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    // The counter is the durable condition. Broadcast avoids
                    // accumulating one stored notify permit per dropped message.
                    self.changed.notify_waiters();
                    return;
                }
                Err(actual) => previous = actual,
            }
        }
    }
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
    connected: std::sync::atomic::AtomicBool,
    processed_epoch: AtomicU64,
    /// PINGs written on the current connection, keepalive and
    /// [`NatsClient::ping`] alike. The server answers in order, so
    /// `pings_sent - pongs` are still unanswered. Both reset on reconnect.
    pings_sent: AtomicU64,
    /// `PONG` frames parsed on the current connection, whichever read
    /// consumed them.
    pongs: AtomicU64,
    /// Set once a supervisor owns the connection. Only a supervised client
    /// unsubscribes dropped subscriptions.
    supervised: std::sync::atomic::AtomicBool,
    /// SIDs of subscriptions dropped without an unsubscribe, awaiting their
    /// UNSUB. Lock order: `subscriptions`, then `dropped_sids`.
    dropped_sids: Mutex<Vec<u64>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            subscriptions: Mutex::new(HashMap::new()),
            server_info: Mutex::new(None),
            closed: std::sync::atomic::AtomicBool::new(false),
            connected: std::sync::atomic::AtomicBool::new(false),
            processed_epoch: AtomicU64::new(0),
            pings_sent: AtomicU64::new(0),
            pongs: AtomicU64::new(0),
            supervised: std::sync::atomic::AtomicBool::new(false),
            dropped_sids: Mutex::new(Vec::new()),
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
        builder.build().map_err(NatsError::Tls)
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

/// The single-owner NATS protocol engine.
///
/// Runtime-wired clients move this value into the connection supervisor. A
/// direct mode remains available for contexts without a spawn gateway so the
/// v0.4.3 test-internals surface keeps its established behavior.
struct NatsConnection {
    config: NatsConfig,
    connect_policy: NatsConnectPolicy,
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

/// Reconnect progress a supervised client carries from one recovery to the
/// next.
///
/// A connection that fails before it has stayed up for `max_reconnect_delay`
/// waits `reconnect_delay` before the next attempt instead of reconnecting at
/// once. When the server refused it with an `-ERR` (an authorization
/// violation, for example), the backoff keeps growing and the attempts count
/// toward `max_reconnect_attempts`. Without this, a server that completed the
/// handshake and then refused the client was reconnected at once,
/// indefinitely.
#[derive(Debug, Default)]
struct ReconnectStreak {
    attempts: u32,
    next_delay: Option<Duration>,
    reconnected_at: Option<Time>,
}

impl fmt::Debug for NatsConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NatsClient")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("connected", &self.connected)
            .finish_non_exhaustive()
    }
}

/// Owns one cancellation registration for a transport wait. The command's
/// caller can differ from the task polling the connection supervisor, so the
/// explicit owner must not be replaced with `Cx::current()`.
struct NatsCancelWakerGuard {
    cx: Cx,
    token: Option<CancelWakerToken>,
}

impl NatsCancelWakerGuard {
    fn new(cx: &Cx) -> Self {
        Self {
            cx: cx.clone(),
            token: None,
        }
    }

    fn refresh(&mut self, waker: &Waker) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, waker));
    }
}

impl Drop for NatsCancelWakerGuard {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

/// Poll transport work under both its explicit command owner and the task
/// driving it. No ambient context is replaced: capability restrictions and
/// supervisor shutdown remain effective while caller cancellation can wake a
/// silent read, blocked write, connection attempt, or TLS handshake.
///
/// A budget deadline on either context is a cancellation source too, but
/// `Cx::checkpoint` only notices an expired deadline when something polls.
/// A timer for each deadline re-polls work parked on a silent server, so it
/// fails with `Cancelled` at the deadline, as `redis_io` does.
async fn nats_io<T, E>(cx: &Cx, future: impl Future<Output = Result<T, E>>) -> Result<T, NatsError>
where
    NatsError: From<E>,
{
    let mut owner_cancel = NatsCancelWakerGuard::new(cx);
    let mut driver_cancel = Cx::current().as_ref().map(NatsCancelWakerGuard::new);
    let mut deadlines: Vec<_> = [
        cx.budget().deadline,
        driver_cancel
            .as_ref()
            .and_then(|driver| driver.cx.budget().deadline),
    ]
    .into_iter()
    .flatten()
    .collect();
    deadlines.sort_unstable();
    // Latest first, so `pop` yields the next deadline to arm.
    deadlines.reverse();
    let mut deadline_timer = deadlines
        .pop()
        .map(|at| Box::pin(crate::time::sleep_until(at)));
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|task_cx| {
        // Registration precedes the checkpoint: cancellation published while
        // a Waker is being cloned must be observed even if its wake snapshot
        // ran before the new registration became visible.
        owner_cancel.refresh(task_cx.waker());
        if let Some(driver) = driver_cancel.as_mut() {
            driver.refresh(task_cx.waker());
        }
        // Arm (or re-arm) the deadline wakeup. A fired timer is replaced by
        // the next deadline: the earlier one may not end the call (for
        // example, the driving task is inside a masked section).
        while deadline_timer
            .as_mut()
            .is_some_and(|timer| timer.as_mut().poll(task_cx).is_ready())
        {
            deadline_timer = deadlines
                .pop()
                .map(|at| Box::pin(crate::time::sleep_until(at)));
        }
        if cx.checkpoint().is_err()
            || driver_cancel
                .as_ref()
                .is_some_and(|driver| driver.cx.checkpoint().is_err())
        {
            return Poll::Ready(Err(NatsError::Cancelled));
        }
        future.as_mut().poll(task_cx).map_err(Into::into)
    })
    .await
}

/// One timer covers an entire connection attempt. Bind it to the explicit
/// owner's driver so a supervisor with a different clock cannot expire it
/// early or leave it parked. `nats_io` checks both owners before this timer,
/// preserving cancellation attribution when cancellation races the timeout.
/// Erase this cold-path future so reconnecting inside a JetStream operation
/// does not deepen its already long `Send` proof chain.
fn nats_connect_attempt<'a, T: Send + 'a>(
    cx: &'a Cx,
    timeout: Option<Duration>,
    future: impl Future<Output = Result<T, NatsError>> + Send + 'a,
) -> Pin<Box<dyn Future<Output = Result<T, NatsError>> + Send + 'a>> {
    Box::pin(async move {
        let timer = timeout.map(|duration| {
            let driver = cx
                .timer_driver()
                .or_else(|| Cx::current().and_then(|current| current.timer_driver()));
            match driver {
                Some(driver) => {
                    crate::time::Sleep::with_timer_driver(driver.now() + duration, driver)
                }
                None => crate::time::Sleep::after(crate::time::wall_now(), duration),
            }
        });
        nats_io(cx, async {
            let Some(timer) = timer else {
                return future.await;
            };
            let mut timer = std::pin::pin!(timer);
            let mut future = std::pin::pin!(future);
            std::future::poll_fn(|task_cx| {
                if timer.as_mut().poll_deadline(task_cx).is_ready() {
                    return Poll::Ready(Err(NatsError::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        CONNECT_TIMEOUT_MESSAGE,
                    ))));
                }
                future.as_mut().poll(task_cx)
            })
            .await
        })
        .await
    })
}

impl NatsConnection {
    /// Connect with explicit configuration.
    async fn connect_with_policy(
        cx: &Cx,
        config: NatsConfig,
        connect_policy: NatsConnectPolicy,
    ) -> Result<Self, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
        cx.trace(&format!(
            "nats: connecting to {}:{}",
            config.host, config.port
        ));

        let addr = format!("{}:{}", config.host, config.port);
        let stream = nats_io(cx, TcpStream::connect(addr)).await?;

        let read_buf_limit = config.max_read_buffer;
        let mut client = Self {
            config,
            connect_policy,
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
        if connect_policy.confirm_connect {
            client.confirm_connect(cx).await?;
        }
        client.connected = true;
        client.state.connected.store(true, Ordering::Release);

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
            match nats_io(cx, async {
                connector
                    .connect(&server_name, tcp_stream)
                    .await
                    .map_err(NatsError::Tls)
            })
            .await
            {
                Ok(tls_stream) => {
                    self.stream = NatsStream::Tls(Box::new(tls_stream));
                    cx.trace("nats: TLS upgrade complete");
                    Ok(())
                }
                Err(err) => {
                    self.stream = NatsStream::Closed;
                    Err(err)
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

            self.read_more(cx).await?;
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
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.flush()).await?;

        // If verbose mode, wait for +OK
        if self.config.verbose {
            self.expect_ok(cx).await?;
        }

        Ok(())
    }

    /// Confirm that the server processed CONNECT before exposing a usable
    /// connection. Every handshake error is terminal, including a permission
    /// error: no application command has been sent on this connection yet.
    async fn confirm_connect(&mut self, cx: &Cx) -> Result<(), NatsError> {
        self.send_keepalive_ping(cx).await?;
        let answered_at = self.state.pings_sent.load(Ordering::Acquire);
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
            match self.try_parse_message()? {
                Some(NatsMessage::Pong)
                    if self.state.pongs.load(Ordering::Acquire) >= answered_at =>
                {
                    return Ok(());
                }
                Some(NatsMessage::Err(error)) => return Err(NatsError::Server(error)),
                Some(NatsMessage::Ping) => self.send_server_pong(cx).await?,
                Some(NatsMessage::Info(info)) => {
                    *self.state.server_info.lock() = Some(info);
                }
                Some(NatsMessage::Msg(message)) => self.dispatch_message(message),
                Some(NatsMessage::Ok | NatsMessage::Pong) => {}
                None => self.read_more(cx).await?,
            }
        }
    }

    /// Attempt to reconnect when the TCP connection is lost, continuing
    /// `streak` when the connection it last produced failed before it was
    /// stable. `refused` says the server ended that connection with an
    /// `-ERR`. A caller outside the supervisor passes a fresh streak.
    ///
    /// This stays a single async fn on purpose: every wrapper layer deepens
    /// the future type that callers' `Send` checks walk, and JetStream's
    /// futures already sit near the compiler's recursion limit.
    async fn try_reconnect(
        &mut self,
        cx: &Cx,
        streak: &mut ReconnectStreak,
        refused: bool,
    ) -> Result<(), NatsError> {
        if !self.config.auto_reconnect {
            return Err(NatsError::NotConnected);
        }

        cx.trace("nats: connection lost, attempting to reconnect");

        let stable_after = self.config.max_reconnect_delay;
        let failed_quickly = streak.reconnected_at.is_some_and(|reconnected_at| {
            Duration::from_nanos(timeout_now(cx).duration_since(reconnected_at)) < stable_after
        });
        let (mut attempt, mut delay) = if failed_quickly && refused {
            (
                streak.attempts,
                streak.next_delay.unwrap_or(self.config.reconnect_delay),
            )
        } else {
            (0, self.config.reconnect_delay)
        };
        let mut wait_first = failed_quickly;

        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
            if self.config.max_reconnect_attempts > 0
                && attempt >= self.config.max_reconnect_attempts
            {
                cx.trace(&format!(
                    "nats: max reconnect attempts ({}) exceeded",
                    self.config.max_reconnect_attempts
                ));
                return Err(NatsError::NotConnected);
            }

            if attempt > 0 || wait_first {
                wait_first = false;
                cx.trace(&format!(
                    "nats: reconnect attempt {} after {}ms delay",
                    attempt + 1,
                    delay.as_millis()
                ));

                // Wait before retry
                nats_io(cx, async {
                    crate::time::sleep(cx.now(), delay).await;
                    Ok::<(), NatsError>(())
                })
                .await?;

                // Exponential backoff with max cap
                delay = std::cmp::min(delay.saturating_mul(2), self.config.max_reconnect_delay);
            }

            attempt += 1;

            // Check for cancellation
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            // One bound spans TCP and the entire handshake, including replay.
            // Failed attempts consume the existing attempt/backoff budget;
            // a peer withholding INFO must not hold the supervisor forever.
            let addr = format!("{}:{}", self.config.host, self.config.port);
            let timeout = self.connect_policy.timeout;
            let result = nats_connect_attempt(cx, timeout, async {
                let new_stream = nats_io(cx, TcpStream::connect(addr)).await?;
                cx.trace(&format!(
                    "nats: TCP reconnected to {}:{} (attempt {})",
                    self.config.host, self.config.port, attempt
                ));

                self.stream = new_stream.into();
                self.read_buf = NatsReadBuffer::with_limit(self.config.max_read_buffer);
                self.connected = false;
                // The old connection's unanswered PINGs never get a PONG.
                self.state.pings_sent.store(0, Ordering::Release);
                self.state.pongs.store(0, Ordering::Release);
                self.complete_reconnect_handshake(cx).await
            })
            .await;
            match result {
                Ok(()) => {
                    cx.trace("nats: reconnection successful");
                    *streak = ReconnectStreak {
                        attempts: attempt,
                        next_delay: Some(delay),
                        reconnected_at: Some(timeout_now(cx)),
                    };
                    return Ok(());
                }
                Err(error) => {
                    self.connected = false;
                    self.state.connected.store(false, Ordering::Release);
                    let _ = self.stream.shutdown(std::net::Shutdown::Both);
                    self.stream = NatsStream::Closed;
                    self.read_buf = NatsReadBuffer::with_limit(self.config.max_read_buffer);
                    if matches!(error, NatsError::Cancelled) {
                        return Err(NatsError::Cancelled);
                    }
                    cx.trace(&format!(
                        "nats: connection attempt failed during reconnect: {error}"
                    ));
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
        if self.connect_policy.confirm_connect {
            self.confirm_connect(cx).await?;
        }

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
            // The new connection carries none of the dropped subscriptions.
            self.state.dropped_sids.lock().clear();
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
            nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        }
        nats_io(cx, self.stream.flush()).await?;

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
                        self.send_server_pong(cx).await?;
                    }
                    _ => {} // Ignore other messages during handshake
                }
            } else {
                self.read_more(cx).await?;
            }
        }
    }

    /// Read more data from the stream.
    pub(crate) async fn read_more(&mut self, cx: &Cx) -> Result<(), NatsError> {
        let mut tmp = [0u8; 4096];
        let read = std::future::poll_fn(|task_cx| {
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.stream).poll_read(task_cx, &mut read_buf) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            }
        });
        let n = nats_io(cx, read).await?;

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
        crate::time::timeout(now, remaining, self.read_more(cx))
            .await
            .unwrap_or_else(|_| Err(request_timeout_error()))
    }

    async fn cleanup_request_subscription(&mut self, cx: &Cx, sid: u64, _reason: &str) {
        if let Err(_err) = self.unsubscribe(cx, sid).await {
            // tracing could go here, but for now we ignore
        }
    }

    /// Commit a received request reply before best-effort subscription cleanup.
    ///
    /// Once the reply is parsed, an UNSUB write failure must not replace it
    /// with an error: callers could retry an operation that already completed
    /// at the service. The failed write still leaves the client disconnected
    /// through `unsubscribe`'s fail-closed transport state.
    async fn finalize_request_reply(
        &mut self,
        cx: &Cx,
        sid: u64,
        message: Message,
    ) -> Result<Message, NatsError> {
        self.cleanup_request_subscription(cx, sid, "reply_received")
            .await;
        if let Some(err) = Self::reply_status_error(&message) {
            Err(err)
        } else {
            Ok(message)
        }
    }

    /// Write a server-required `PONG` response.
    ///
    /// If the client is currently considered connected, fail closed around
    /// the write so a partial `PONG` cannot leave the connection reusable.
    pub(crate) async fn send_server_pong(&mut self, cx: &Cx) -> Result<(), NatsError> {
        let restore_connected = self.connected;
        if restore_connected {
            self.connected = false;
        }

        nats_io(cx, self.stream.write_all(b"PONG\r\n")).await?;
        nats_io(cx, self.stream.flush()).await?;

        if restore_connected {
            self.connected = true;
        }

        Ok(())
    }

    /// Write a client keepalive `PING`. Its `PONG` is not awaited here:
    /// whichever read parses it counts it (see [`NatsKeepalive`]). Fails
    /// closed around the write like [`Self::send_server_pong`].
    async fn send_keepalive_ping(&mut self, cx: &Cx) -> Result<(), NatsError> {
        let restore_connected = self.connected;
        if restore_connected {
            self.connected = false;
        }

        nats_io(cx, self.stream.write_all(b"PING\r\n")).await?;
        nats_io(cx, self.stream.flush()).await?;
        self.state.pings_sent.fetch_add(1, Ordering::AcqRel);

        if restore_connected {
            self.connected = true;
        }

        Ok(())
    }

    /// PINGs written on this connection that no parsed `PONG` has answered.
    fn unanswered_pings(&self) -> u64 {
        let sent = self.state.pings_sent.load(Ordering::Acquire);
        sent.saturating_sub(self.state.pongs.load(Ordering::Acquire))
    }

    /// Send UNSUB for subscriptions dropped without an unsubscribe.
    ///
    /// Like every multi-part write, the connection stays marked unusable
    /// until the whole batch is flushed.
    async fn flush_dropped_subscriptions(&mut self, cx: &Cx) -> Result<(), NatsError> {
        let sids = std::mem::take(&mut *self.state.dropped_sids.lock());
        if sids.is_empty() || !self.connected {
            return Ok(());
        }
        let mut cmd = String::new();
        for sid in sids {
            cmd.push_str(&format!("UNSUB {sid}\r\n"));
        }
        self.connected = false;
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.flush()).await?;
        self.connected = true;
        Ok(())
    }

    fn remove_local_subscription(&self, sid: u64) {
        let mut subs = self.state.subscriptions.lock();
        subs.remove(&sid);
    }

    /// Try to parse a complete message from the buffer.
    pub(crate) fn try_parse_message(&mut self) -> Result<Option<NatsMessage>, NatsError> {
        let result = self.try_parse_message_inner();
        if result.is_err() {
            // A malformed server frame leaves the byte stream desynchronized:
            // retaining the same transport would make every later operation
            // observe the same invalid prefix. Fail closed and let the normal
            // reconnect path replace both the transport and read buffer.
            self.connected = false;
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
        result
    }

    fn try_parse_message_inner(&mut self) -> Result<Option<NatsMessage>, NatsError> {
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
                self.state.pongs.fetch_add(1, Ordering::AcqRel);
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

        // Check if we have the full payload + trailing CRLF. Use checked
        // arithmetic like the HMSG parser: `max_read_buffer` is
        // caller-configurable, so these sums must not be able to wrap.
        // (`header_end` indexes into `buf`, so `+ 2` cannot overflow.)
        let payload_start = header_end + 2;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| NatsError::Protocol("MSG payload bounds overflow".to_string()))?;
        let total_len = payload_end
            .checked_add(2) // +2 for trailing CRLF
            .ok_or_else(|| NatsError::Protocol("MSG payload bounds overflow".to_string()))?;

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
        status_reply(message).map(|(_, error)| error)
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
            self.try_reconnect(cx, &mut ReconnectStreak::default(), false)
                .await?;
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
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.write_all(payload)).await?;
        nats_io(cx, self.stream.write_all(b"\r\n")).await?;
        nats_io(cx, self.stream.flush()).await?;

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
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.write_all(payload)).await?;
        nats_io(cx, self.stream.write_all(b"\r\n")).await?;
        nats_io(cx, self.stream.flush()).await?;

        self.connected = true;
        Ok(())
    }

    /// Publish a message with NATS v1 headers and a reply-to subject.
    ///
    /// Wire format (per <https://docs.nats.io/reference/reference-protocols/nats-protocol#hpub>):
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
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.write_all(&header_block)).await?;
        nats_io(cx, self.stream.write_all(payload)).await?;
        nats_io(cx, self.stream.write_all(b"\r\n")).await?;
        nats_io(cx, self.stream.flush()).await?;

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
                        if let Err(err) = self.send_server_pong(cx).await {
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
                            return self.finalize_request_reply(cx, sub.sid(), m).await;
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
                return self.finalize_request_reply(cx, sub.sid(), msg).await;
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
                        if let Err(err) = self.send_server_pong(cx).await {
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
                            return self.finalize_request_reply(cx, sub.sid(), m).await;
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
                return self.finalize_request_reply(cx, sub.sid(), msg).await;
            }
        }
    }

    /// Subscribe to a subject.
    ///
    /// Returns a `Subscription` that can be used to receive messages.
    pub async fn subscribe(&mut self, cx: &Cx, subject: &str) -> Result<Subscription, NatsError> {
        self.subscribe_with_capacity(cx, subject, DEFAULT_SUBSCRIPTION_CAPACITY)
            .await
    }

    /// Subscribe to a subject, buffering up to `capacity` messages (at least 1).
    pub async fn subscribe_with_capacity(
        &mut self,
        cx: &Cx,
        subject: &str,
        capacity: usize,
    ) -> Result<Subscription, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_subscription_pattern(subject, "subject")?;

        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        // Bounded: a message that arrives while the buffer is full is dropped.
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let loss = Arc::new(SubscriptionLoss::default());

        // Register subscription
        {
            let mut subs = self.state.subscriptions.lock();
            subs.insert(
                sid,
                SubscriptionState {
                    subject: subject.to_string(),
                    queue_group: None,
                    sender: tx,
                    loss: Arc::clone(&loss),
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
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.flush()).await?;

        self.connected = true;
        guard.defused = true;

        cx.trace(&format!("nats: subscribed to {subject} (sid={sid})"));

        Ok(Subscription {
            sid,
            subject: subject.to_string(),
            rx,
            state: Arc::clone(&self.state),
            loss,
            reported_dropped_messages: 0,
        })
    }

    /// Subscribe with a queue group and an explicit local buffer capacity.
    async fn queue_subscribe_with_capacity(
        &mut self,
        cx: &Cx,
        subject: &str,
        queue_group: &str,
        capacity: usize,
    ) -> Result<Subscription, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }
        validate_nats_subscription_pattern(subject, "subject")?;
        validate_nats_token(queue_group, "queue group")?;

        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(capacity.max(1));
        let loss = Arc::new(SubscriptionLoss::default());

        {
            let mut subs = self.state.subscriptions.lock();
            subs.insert(
                sid,
                SubscriptionState {
                    subject: subject.to_string(),
                    queue_group: Some(queue_group.to_string()),
                    sender: tx,
                    loss: Arc::clone(&loss),
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
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.flush()).await?;

        self.connected = true;
        guard.defused = true;

        Ok(Subscription {
            sid,
            subject: subject.to_string(),
            rx,
            state: Arc::clone(&self.state),
            loss,
            reported_dropped_messages: 0,
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
        nats_io(cx, self.stream.write_all(cmd.as_bytes())).await?;
        nats_io(cx, self.stream.flush()).await?;
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

        nats_io(cx, self.stream.write_all(b"PING\r\n")).await?;
        nats_io(cx, self.stream.flush()).await?;
        // The server answers PINGs in order. A PONG for an earlier keepalive
        // PING is not this one's: the commands written before this PING may
        // still be unprocessed when it arrives.
        let answered_at = self.state.pings_sent.fetch_add(1, Ordering::AcqRel) + 1;

        // Wait for PONG
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

            if let Some(msg) = self.try_parse_message()? {
                match msg {
                    NatsMessage::Pong => {
                        if self.state.pongs.load(Ordering::Acquire) >= answered_at {
                            self.connected = true;
                            return Ok(());
                        }
                    }
                    // The server keeps the connection after a permissions
                    // violation and sends the PONG next. Failing here broke
                    // the publish-then-ping flush idiom and reconnected,
                    // dropping in-flight messages.
                    NatsMessage::Err(e) if server_error_keeps_connection(&e) => {
                        cx.trace(&format!(
                            "nats: server reported {e:?} before PONG; the connection stays open"
                        ));
                    }
                    NatsMessage::Err(e) => return Err(NatsError::Server(e)),
                    NatsMessage::Ping => {
                        self.send_server_pong(cx).await?;
                    }
                    NatsMessage::Msg(m) => {
                        // Dispatch to subscription
                        self.dispatch_message(m);
                    }
                    _ => {}
                }
            } else {
                self.read_more(cx).await?;
            }
        }
    }

    /// Handle any pending server messages (like PING).
    async fn handle_pending_messages(&mut self, cx: &Cx) -> Result<(), NatsError> {
        // Non-blocking check for pending messages
        loop {
            match self.try_parse_message()? {
                Some(NatsMessage::Ping) => {
                    self.send_server_pong(cx).await?;
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
        let delivery = self
            .state
            .subscriptions
            .lock()
            .get(&msg.sid)
            .map(|sub| (sub.sender.clone(), Arc::clone(&sub.loss)));
        let Some((sender, loss)) = delivery else {
            return;
        };
        // Both channel delivery and overflow notification can wake arbitrary
        // user code. Run them after releasing the subscription-map lock. The
        // temporary sender also keeps a concurrent close from hiding an
        // already admitted dispatch from a loss-aware receiver.
        if let Err(mpsc::SendError::Full(message)) = sender.try_send(msg) {
            loss.record_drop();
            warn!(
                subject = %message.subject,
                "NATS message dropped because the subscription buffer is full"
            );
        }
    }

    /// Process incoming messages and dispatch to subscriptions.
    /// Call this periodically if you have active subscriptions.
    pub async fn process(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        if !self.connected {
            return Err(NatsError::NotConnected);
        }

        let mut processed_any = false;
        loop {
            match self.try_parse_message()? {
                Some(NatsMessage::Ping) => {
                    self.send_server_pong(cx).await?;
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

                    self.read_more(cx).await?;
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
            let _ = nats_io(cx, self.stream.flush()).await;
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
        self.connected = false;
        self.state.connected.store(false, Ordering::Release);
        Ok(())
    }
}

impl Drop for NatsConnection {
    fn drop(&mut self) {
        // `close()` is the graceful path, but dropping the owner must still
        // terminate subscription receivers and make the transport unusable.
        self.state.closed.store(true, Ordering::Release);
        self.state.subscriptions.lock().clear();
        self.connected = false;
        self.state.connected.store(false, Ordering::Release);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

const NATS_SUPERVISOR_COMMAND_CAPACITY: usize = 64;

/// Client-side keepalive of a supervised [`NatsClient`].
///
/// A half-open TCP connection (the server or a middlebox gone without a FIN
/// or RST) accepts writes into the socket buffer for many minutes: publishes
/// return `Ok` and subscriptions go quiet. The supervisor therefore sends a
/// `PING` every interval; the server answers each with a `PONG`, in order.
/// When `max_pings_out` PINGs are still unanswered at a tick, the connection
/// is stale and the supervisor replaces it as it does after a transport
/// error: it reconnects within [`NatsConfig`]'s reconnect limits and replays
/// the subscriptions. [`NatsClient::ping`] still waits for its own `PONG`,
/// not one answering an earlier keepalive `PING`, but no longer than
/// `interval × max_pings_out`: past that it fails and the connection is
/// replaced.
///
/// [`NatsClient::connect`] and [`NatsClient::connect_with_config`] use
/// [`NatsKeepalive::default`], the nats.go defaults: a `PING` every two
/// minutes, stale with two unanswered, so a dead connection is replaced
/// within about six minutes. [`NatsClient::connect_with_keepalive`] changes
/// or disables it.
///
/// A client without a supervisor (its `Cx` has no spawn gateway) reads only
/// while one of its calls runs, so it has no keepalive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NatsKeepalive {
    interval: Option<Duration>,
    max_pings_out: u32,
}

impl NatsKeepalive {
    /// The default `PING` interval (nats.go's `DefaultPingInterval`).
    pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(120);
    /// The default limit of unanswered PINGs (nats.go's `DefaultMaxPingOut`).
    pub const DEFAULT_MAX_PINGS_OUT: u32 = 2;

    /// Sends a `PING` every `interval` (at least 1 ms) and declares the
    /// connection stale when `max_pings_out` (at least 1) are unanswered at
    /// the next tick.
    #[must_use]
    pub fn new(interval: Duration, max_pings_out: u32) -> Self {
        Self {
            interval: Some(interval.max(Duration::from_millis(1))),
            max_pings_out: max_pings_out.max(1),
        }
    }

    /// No client keepalive, as in v0.4.3. The supervisor still answers the
    /// server's PINGs.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            interval: None,
            max_pings_out: Self::DEFAULT_MAX_PINGS_OUT,
        }
    }

    /// The `PING` interval, or `None` when the keepalive is disabled.
    #[must_use]
    pub const fn interval(&self) -> Option<Duration> {
        self.interval
    }

    /// How many unanswered PINGs make the connection stale.
    #[must_use]
    pub const fn max_pings_out(&self) -> u32 {
        self.max_pings_out
    }
}

impl Default for NatsKeepalive {
    fn default() -> Self {
        Self::new(Self::DEFAULT_INTERVAL, Self::DEFAULT_MAX_PINGS_OUT)
    }
}

/// Connection-attempt policy for [`NatsClient::connect_with_policy`].
///
/// The default preserves [`NatsClient::connect_with_config`]: no additional
/// connection timeout, no PING/PONG confirmation of CONNECT, and the default
/// client keepalive. The caller's cancellation and budget still apply.
/// This separate type keeps the exhaustively constructible [`NatsConfig`]
/// compatible with existing callers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NatsConnectPolicy {
    timeout: Option<Duration>,
    confirm_connect: bool,
    keepalive: NatsKeepalive,
}

impl NatsConnectPolicy {
    /// Create a policy with the existing connection behavior.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Bound each complete connection attempt, including name resolution,
    /// TCP, INFO, TLS, CONNECT, the verbose acknowledgement and optional
    /// PING/PONG confirmation. Reconnection also includes subscription replay.
    ///
    /// A fresh timeout starts for each reconnect attempt, after its backoff;
    /// progress within an attempt never resets it. A zero timeout refuses the
    /// attempt before opening a socket. During initial connection establishment,
    /// expiry returns [`NatsError::Io`] with [`io::ErrorKind::TimedOut`];
    /// cancellation remains [`NatsError::Cancelled`]. During reconnection,
    /// an expired attempt fails that individual attempt and enters backoff/retry
    /// under the reconnect policy.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Wait for a PONG after CONNECT before reporting success or replaying
    /// subscriptions. During initial connection establishment, this surfaces a
    /// server's authentication refusal directly even when [`NatsConfig::verbose`]
    /// is false. During reconnection, an unconfirmed or refused attempt fails that
    /// individual reconnect attempt and enters the retry/backoff loop; callers
    /// observing the client see disconnection if reconnect attempts are exhausted.
    /// Pair this with [`Self::with_timeout`] to bound an unresponsive peer.
    #[must_use]
    pub const fn with_connect_confirmation(mut self, enabled: bool) -> Self {
        self.confirm_connect = enabled;
        self
    }

    /// Choose the keepalive used after establishment. As with
    /// [`NatsClient::connect_with_keepalive`], it runs only in supervised mode.
    #[must_use]
    pub const fn with_keepalive(mut self, keepalive: NatsKeepalive) -> Self {
        self.keepalive = keepalive;
        self
    }

    /// The complete-attempt timeout, or `None` for the existing unbounded policy.
    #[must_use]
    pub const fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Whether CONNECT is confirmed with a PING/PONG exchange.
    #[must_use]
    pub const fn confirms_connect(&self) -> bool {
        self.confirm_connect
    }

    /// The client keepalive used after the connection is established.
    #[must_use]
    pub const fn keepalive(&self) -> NatsKeepalive {
        self.keepalive
    }
}

/// When the supervisor's next keepalive `PING` is due.
struct KeepaliveClock {
    interval: Duration,
    max_pings_out: u32,
    next_ping: Time,
}

/// What a keepalive tick asks the supervisor to do.
enum KeepaliveTick {
    /// Send a `PING`, bounding the write by the interval.
    Ping(Duration),
    /// `max_pings_out` PINGs are unanswered: replace the connection.
    Stale,
}

impl KeepaliveClock {
    /// `None` when the keepalive is disabled.
    fn new(cx: &Cx, keepalive: NatsKeepalive) -> Option<Self> {
        let interval = keepalive.interval?;
        Some(Self {
            interval,
            max_pings_out: keepalive.max_pings_out,
            next_ping: timeout_now(cx) + interval,
        })
    }

    /// A fresh connection waits a whole interval for its first `PING`.
    fn restart(&mut self, cx: &Cx) {
        self.next_ping = timeout_now(cx) + self.interval;
    }

    /// How long a `PING` may go unanswered before the keepalive would call the
    /// connection stale. A supervised [`NatsClient::ping`] waits no longer:
    /// while it waits, the supervisor cannot tick.
    fn stale_window(&self) -> Duration {
        self.interval.saturating_mul(self.max_pings_out)
    }

    /// Handles a due tick: with `max_pings_out` PINGs still unanswered the
    /// connection is stale; otherwise one more is sent.
    fn tick(&mut self, cx: &Cx, unanswered: u64) -> KeepaliveTick {
        if unanswered >= u64::from(self.max_pings_out) {
            return KeepaliveTick::Stale;
        }
        self.next_ping = timeout_now(cx) + self.interval;
        KeepaliveTick::Ping(self.interval)
    }
}

/// Messages a subscription buffers before further ones are dropped; see
/// [`NatsClient::subscribe_with_capacity`].
const DEFAULT_SUBSCRIPTION_CAPACITY: usize = 256;

/// NATS client with Cx integration.
///
/// When the supplied [`Cx`] is backed by an asupersync runtime, the client
/// starts one region-owned connection supervisor. That task is the exclusive
/// owner of socket reads and writes, so it can answer server `PING` frames and
/// dispatch subscription messages even while the caller is otherwise idle.
/// It also sends keepalive PINGs and replaces a connection that stops
/// answering them; see [`NatsKeepalive`]. Contexts without a spawn gateway
/// retain the cooperative v0.4.3 transport behavior for compatibility with
/// lightweight test harnesses.
pub struct NatsClient {
    config: NatsConfig,
    state: Arc<SharedState>,
    mode: NatsClientMode,
}

enum NatsClientMode {
    Direct(NatsConnection),
    Supervised(NatsSupervisor),
}

struct NatsSupervisor {
    commands: mpsc::Sender<NatsSupervisorCommand>,
    task: Option<TaskHandle<()>>,
}

enum NatsSupervisorCommand {
    Publish {
        cx: Cx,
        subject: String,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), NatsError>>,
    },
    PublishRequest {
        cx: Cx,
        subject: String,
        reply_to: String,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), NatsError>>,
    },
    PublishRequestWithHeaders {
        cx: Cx,
        subject: String,
        reply_to: String,
        headers: Vec<(String, Vec<u8>)>,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<(), NatsError>>,
    },
    RequestWithHeaders {
        cx: Cx,
        subject: String,
        headers: Vec<(String, Vec<u8>)>,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Message, NatsError>>,
    },
    Request {
        cx: Cx,
        subject: String,
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<Message, NatsError>>,
    },
    Subscribe {
        cx: Cx,
        subject: String,
        queue_group: Option<String>,
        capacity: usize,
        reply: oneshot::Sender<Result<Subscription, NatsError>>,
    },
    Unsubscribe {
        cx: Cx,
        sid: u64,
        reply: oneshot::Sender<Result<(), NatsError>>,
    },
    Ping {
        cx: Cx,
        reply: oneshot::Sender<Result<(), NatsError>>,
    },
    Process {
        after_epoch: u64,
        reply: oneshot::Sender<Result<(), NatsError>>,
    },
    Close {
        cx: Cx,
        reply: oneshot::Sender<Result<(), NatsError>>,
    },
}

impl NatsSupervisorCommand {
    /// Whether the caller stopped waiting before the supervisor reached this
    /// command, for example because a timeout dropped its future. Such a
    /// command is skipped, so a publish the caller saw fail is not sent later.
    /// Unsubscribe and close still run: they release server state.
    fn caller_gave_up(&self) -> bool {
        match self {
            Self::Publish { reply, .. }
            | Self::PublishRequest { reply, .. }
            | Self::PublishRequestWithHeaders { reply, .. }
            | Self::Ping { reply, .. }
            | Self::Process { reply, .. } => reply.is_closed(),
            Self::Request { reply, .. } | Self::RequestWithHeaders { reply, .. } => {
                reply.is_closed()
            }
            Self::Subscribe { reply, .. } => reply.is_closed(),
            Self::Unsubscribe { .. } | Self::Close { .. } => false,
        }
    }
}

impl fmt::Debug for NatsClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let connected = match &self.mode {
            NatsClientMode::Direct(connection) => connection.connected,
            NatsClientMode::Supervised(_) => self.state.connected.load(Ordering::Acquire),
        };
        f.debug_struct("NatsClient")
            .field("host", &self.config.host)
            .field("port", &self.config.port)
            .field("connected", &connected)
            .finish_non_exhaustive()
    }
}

impl NatsSupervisor {
    async fn request<T>(
        &self,
        cx: &Cx,
        build: impl FnOnce(Cx, oneshot::Sender<Result<T, NatsError>>) -> NatsSupervisorCommand,
    ) -> Result<T, NatsError> {
        let (reply, mut response) = oneshot::channel();
        self.commands
            .send(cx, build(cx.clone(), reply))
            .await
            .map_err(|error| match error {
                mpsc::SendError::Cancelled(_) => NatsError::Cancelled,
                mpsc::SendError::Disconnected(_) | mpsc::SendError::Full(_) => NatsError::Closed,
            })?;
        response.recv(cx).await.map_err(|error| match error {
            oneshot::RecvError::Cancelled => NatsError::Cancelled,
            oneshot::RecvError::Closed | oneshot::RecvError::PolledAfterCompletion => {
                NatsError::Closed
            }
        })?
    }
}

impl NatsClient {
    /// Connect to a NATS server.
    pub async fn connect(cx: &Cx, url: &str) -> Result<Self, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
        let config = NatsConfig::from_url(url)?;
        Self::connect_with_config(cx, config).await
    }

    /// Connect with explicit configuration and the default keepalive
    /// ([`NatsKeepalive::default`]).
    pub async fn connect_with_config(cx: &Cx, config: NatsConfig) -> Result<Self, NatsError> {
        Self::connect_with_keepalive(cx, config, NatsKeepalive::default()).await
    }

    /// Connect with explicit configuration and client keepalive.
    ///
    /// The keepalive runs in the connection supervisor, so it applies only
    /// when `cx` has a spawn gateway; see [`NatsKeepalive`].
    pub async fn connect_with_keepalive(
        cx: &Cx,
        config: NatsConfig,
        keepalive: NatsKeepalive,
    ) -> Result<Self, NatsError> {
        Self::connect_with_policy(
            cx,
            config,
            NatsConnectPolicy::new().with_keepalive(keepalive),
        )
        .await
    }

    /// Connect with explicit establishment and keepalive policy.
    ///
    /// [`NatsConnectPolicy::with_timeout`] bounds the entire attempt instead
    /// of independently granting each handshake stage a fresh timeout. Every
    /// subsequent reconnect uses the same policy and the existing
    /// [`NatsConfig`] attempt limit and backoff. A failed or timed-out attempt
    /// closes its transport before any retry; no partial handshake is reused.
    ///
    /// ```no_run
    /// # async fn connect(cx: &asupersync::Cx) -> Result<(), asupersync::messaging::nats::NatsError> {
    /// use asupersync::messaging::nats::{NatsClient, NatsConfig, NatsConnectPolicy};
    /// use std::time::Duration;
    ///
    /// let config = NatsConfig::from_url("nats://127.0.0.1:4222")?;
    /// let policy = NatsConnectPolicy::new()
    ///     .with_timeout(Duration::from_secs(5))
    ///     .with_connect_confirmation(true);
    /// let mut client = NatsClient::connect_with_policy(cx, config, policy).await?;
    /// client.close(cx).await
    /// # }
    /// ```
    pub async fn connect_with_policy(
        cx: &Cx,
        config: NatsConfig,
        policy: NatsConnectPolicy,
    ) -> Result<Self, NatsError> {
        let connection = nats_connect_attempt(
            cx,
            policy.timeout,
            NatsConnection::connect_with_policy(cx, config, policy),
        )
        .await?;
        let config = connection.config.clone();
        let state = Arc::clone(&connection.state);

        if cx.spawn_gateway_handle().is_none() || cx.pending_spawn_counter_handle().is_none() {
            return Ok(Self {
                config,
                state,
                mode: NatsClientMode::Direct(connection),
            });
        }

        let (commands, receiver) = mpsc::channel(NATS_SUPERVISOR_COMMAND_CAPACITY);
        let task = cx
            .spawn(move |supervisor_cx| async move {
                run_nats_supervisor(&supervisor_cx, connection, receiver, policy.keepalive).await;
            })
            .map_err(|_| NatsError::NotConnected)?;

        Ok(Self {
            config,
            state,
            mode: NatsClientMode::Supervised(NatsSupervisor {
                commands,
                task: Some(task),
            }),
        })
    }

    /// Publish a message to a subject.
    pub async fn publish(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<(), NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => connection.publish(cx, subject, payload).await,
            NatsClientMode::Supervised(supervisor) => {
                let subject = subject.to_string();
                let payload = payload.to_vec();
                supervisor
                    .request(cx, move |cx, reply| NatsSupervisorCommand::Publish {
                        cx,
                        subject,
                        payload,
                        reply,
                    })
                    .await
            }
        }
    }

    /// Publish a message with a reply-to subject.
    pub async fn publish_request(
        &mut self,
        cx: &Cx,
        subject: &str,
        reply_to: &str,
        payload: &[u8],
    ) -> Result<(), NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => {
                connection
                    .publish_request(cx, subject, reply_to, payload)
                    .await
            }
            NatsClientMode::Supervised(supervisor) => {
                let subject = subject.to_string();
                let reply_to = reply_to.to_string();
                let payload = payload.to_vec();
                supervisor
                    .request(cx, move |cx, reply| NatsSupervisorCommand::PublishRequest {
                        cx,
                        subject,
                        reply_to,
                        payload,
                        reply,
                    })
                    .await
            }
        }
    }

    /// Publish a message with NATS v1 headers and a reply-to subject.
    pub async fn publish_request_with_headers(
        &mut self,
        cx: &Cx,
        subject: &str,
        reply_to: &str,
        headers: &[(&str, &[u8])],
        payload: &[u8],
    ) -> Result<(), NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => {
                connection
                    .publish_request_with_headers(cx, subject, reply_to, headers, payload)
                    .await
            }
            NatsClientMode::Supervised(supervisor) => {
                let subject = subject.to_string();
                let reply_to = reply_to.to_string();
                let headers = headers
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), (*value).to_vec()))
                    .collect();
                let payload = payload.to_vec();
                supervisor
                    .request(cx, move |cx, reply| {
                        NatsSupervisorCommand::PublishRequestWithHeaders {
                            cx,
                            subject,
                            reply_to,
                            headers,
                            payload,
                            reply,
                        }
                    })
                    .await
            }
        }
    }

    /// Request/reply pattern with NATS v1 headers.
    pub async fn request_with_headers(
        &mut self,
        cx: &Cx,
        subject: &str,
        headers: &[(&str, &[u8])],
        payload: &[u8],
    ) -> Result<Message, NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => {
                connection
                    .request_with_headers(cx, subject, headers, payload)
                    .await
            }
            NatsClientMode::Supervised(supervisor) => {
                let subject = subject.to_string();
                let headers = headers
                    .iter()
                    .map(|(name, value)| ((*name).to_string(), (*value).to_vec()))
                    .collect();
                let payload = payload.to_vec();
                supervisor
                    .request(cx, move |cx, reply| {
                        NatsSupervisorCommand::RequestWithHeaders {
                            cx,
                            subject,
                            headers,
                            payload,
                            reply,
                        }
                    })
                    .await
            }
        }
    }

    /// Request/reply pattern: publish and wait for a single response.
    pub async fn request(
        &mut self,
        cx: &Cx,
        subject: &str,
        payload: &[u8],
    ) -> Result<Message, NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => connection.request(cx, subject, payload).await,
            NatsClientMode::Supervised(supervisor) => {
                let subject = subject.to_string();
                let payload = payload.to_vec();
                supervisor
                    .request(cx, move |cx, reply| NatsSupervisorCommand::Request {
                        cx,
                        subject,
                        payload,
                        reply,
                    })
                    .await
            }
        }
    }

    /// Subscribe to a subject.
    ///
    /// The subscription buffers up to 256 messages; one that arrives while the
    /// buffer is full is dropped with a warning. Use
    /// [`Self::subscribe_with_capacity`] for a larger buffer and
    /// [`Subscription::next_event`] to observe local message loss.
    pub async fn subscribe(&mut self, cx: &Cx, subject: &str) -> Result<Subscription, NatsError> {
        self.subscribe_with_capacity(cx, subject, DEFAULT_SUBSCRIPTION_CAPACITY)
            .await
    }

    /// Subscribe to a subject, buffering up to `capacity` messages (at least
    /// 1) until they are received.
    ///
    /// A message that arrives while the buffer is full is dropped with a
    /// warning, so size the buffer to the largest burst the subscriber must
    /// absorb between receives, such as a request expecting that many replies.
    /// [`Subscription::dropped_messages`] counts these losses, and
    /// [`Subscription::next_event`] reports them alongside received messages.
    pub async fn subscribe_with_capacity(
        &mut self,
        cx: &Cx,
        subject: &str,
        capacity: usize,
    ) -> Result<Subscription, NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => {
                connection
                    .subscribe_with_capacity(cx, subject, capacity)
                    .await
            }
            NatsClientMode::Supervised(supervisor) => {
                let subject = subject.to_string();
                supervisor
                    .request(cx, move |cx, reply| NatsSupervisorCommand::Subscribe {
                        cx,
                        subject,
                        queue_group: None,
                        capacity,
                        reply,
                    })
                    .await
            }
        }
    }

    /// Subscribe with a queue group.
    pub async fn queue_subscribe(
        &mut self,
        cx: &Cx,
        subject: &str,
        queue_group: &str,
    ) -> Result<Subscription, NatsError> {
        self.queue_subscribe_with_capacity(cx, subject, queue_group, DEFAULT_SUBSCRIPTION_CAPACITY)
            .await
    }

    /// Subscribe with a queue group and an explicit local buffer capacity.
    ///
    /// The capacity is at least one message and has the same overflow
    /// semantics as [`Self::subscribe_with_capacity`]. Queue-group delivery
    /// does not provide local backpressure: an overflowing message is lost to
    /// this subscriber, so use [`Subscription::next_event`] to observe loss.
    pub async fn queue_subscribe_with_capacity(
        &mut self,
        cx: &Cx,
        subject: &str,
        queue_group: &str,
        capacity: usize,
    ) -> Result<Subscription, NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => {
                connection
                    .queue_subscribe_with_capacity(cx, subject, queue_group, capacity)
                    .await
            }
            NatsClientMode::Supervised(supervisor) => {
                let subject = subject.to_string();
                let queue_group = Some(queue_group.to_string());
                supervisor
                    .request(cx, move |cx, reply| NatsSupervisorCommand::Subscribe {
                        cx,
                        subject,
                        queue_group,
                        capacity,
                        reply,
                    })
                    .await
            }
        }
    }

    /// Unsubscribe from a subscription.
    pub async fn unsubscribe(&mut self, cx: &Cx, sid: u64) -> Result<(), NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => connection.unsubscribe(cx, sid).await,
            NatsClientMode::Supervised(supervisor) => {
                supervisor
                    .request(cx, move |cx, reply| NatsSupervisorCommand::Unsubscribe {
                        cx,
                        sid,
                        reply,
                    })
                    .await
            }
        }
    }

    /// Send PING and wait for PONG.
    pub async fn ping(&mut self, cx: &Cx) -> Result<(), NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => connection.ping(cx).await,
            NatsClientMode::Supervised(supervisor) => {
                supervisor
                    .request(cx, |cx, reply| NatsSupervisorCommand::Ping { cx, reply })
                    .await
            }
        }
    }

    /// Wait until the supervisor has processed at least one incoming frame.
    ///
    /// The method remains a compatibility surface for callers that explicitly
    /// pump subscriptions. Supervised clients already process continuously; an
    /// epoch captured before command enqueue prevents a race from waiting for a
    /// second frame when the supervisor handled the first one concurrently.
    pub async fn process(&mut self, cx: &Cx) -> Result<(), NatsError> {
        match &mut self.mode {
            NatsClientMode::Direct(connection) => connection.process(cx).await,
            NatsClientMode::Supervised(supervisor) => {
                let after_epoch = self.state.processed_epoch.load(Ordering::Acquire);
                supervisor
                    .request(cx, move |_, reply| NatsSupervisorCommand::Process {
                        after_epoch,
                        reply,
                    })
                    .await
            }
        }
    }

    /// Close the connection gracefully and drain its supervisor task.
    pub async fn close(&mut self, cx: &Cx) -> Result<(), NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
        match &mut self.mode {
            NatsClientMode::Direct(connection) => connection.close(cx).await,
            NatsClientMode::Supervised(supervisor) => {
                if !self.state.connected.load(Ordering::Acquire) {
                    self.state.closed.store(true, Ordering::Release);
                    self.state.subscriptions.lock().clear();
                    if let Some(mut task) = supervisor.task.take() {
                        task.abort();
                        let _ = task.join(cx).await;
                    }
                    return Ok(());
                }
                let result = supervisor
                    .request(cx, |cx, reply| NatsSupervisorCommand::Close { cx, reply })
                    .await;
                if result.is_ok()
                    && let Some(mut task) = supervisor.task.take()
                {
                    task.join(cx).await.map_err(|_| NatsError::Closed)?;
                }
                result
            }
        }
    }

    /// Get server info.
    pub fn server_info(&self) -> Option<ServerInfo> {
        self.state.server_info.lock().clone()
    }
}

impl Drop for NatsClient {
    fn drop(&mut self) {
        self.state.closed.store(true, Ordering::Release);
        self.state.subscriptions.lock().clear();
        if let NatsClientMode::Supervised(supervisor) = &self.mode
            && let Some(task) = &supervisor.task
        {
            task.abort();
        }
    }
}

async fn run_nats_supervisor(
    supervisor_cx: &Cx,
    mut connection: NatsConnection,
    mut commands: mpsc::Receiver<NatsSupervisorCommand>,
    keepalive: NatsKeepalive,
) {
    let mut streak = ReconnectStreak::default();
    let mut process_waiters = Vec::new();
    let mut keepalive = KeepaliveClock::new(supervisor_cx, keepalive);
    // Kept across iterations: a frame loop turn must not re-arm the timer.
    let mut ping_timer: Option<(Time, Pin<Box<crate::time::Sleep>>)> = None;
    connection.state.supervised.store(true, Ordering::Release);
    loop {
        let pumped = match connection.flush_dropped_subscriptions(supervisor_cx).await {
            Ok(()) => drain_supervisor_frames(supervisor_cx, &mut connection).await,
            Err(error) => Err(error),
        };
        match pumped {
            Ok(processed) => {
                if processed > 0 {
                    let epoch = connection
                        .state
                        .processed_epoch
                        .fetch_add(processed, Ordering::AcqRel)
                        .saturating_add(processed);
                    answer_process_waiters(&mut process_waiters, epoch);
                    continue;
                }
            }
            Err(error) => {
                fail_process_waiters(&mut process_waiters);
                if !recover_supervisor_connection(
                    supervisor_cx,
                    &mut connection,
                    &mut streak,
                    &mut keepalive,
                    error,
                )
                .await
                {
                    break;
                }
                continue;
            }
        }

        let due = keepalive.as_ref().map(|clock| clock.next_ping);
        if ping_timer.as_ref().map(|(at, _)| *at) != due {
            ping_timer = due.map(|at| (at, Box::pin(crate::time::sleep_until(at))));
        }

        // All three operations are drop-cancel-safe: mpsc recv leaves the
        // queued command untouched, poll_read commits no bytes while pending,
        // and the keepalive timer outlives the select. A selected command
        // therefore cannot steal socket bytes, and a selected read cannot
        // lose a command reservation. The socket is always polled before the
        // timer (`Select` alternates its sides), so a PONG that has arrived
        // is parsed before a keepalive tick judges the connection.
        let selected = {
            let mut read = Box::pin(connection.read_more(supervisor_cx));
            let timer = &mut ping_timer;
            let io = Box::pin(std::future::poll_fn(move |task| {
                if let Poll::Ready(result) = read.as_mut().poll(task) {
                    return Poll::Ready(Either::Left(result));
                }
                match timer.as_mut() {
                    Some((_, sleep)) => sleep.as_mut().poll(task).map(Either::Right),
                    None => Poll::Pending,
                }
            }));
            let command = Box::pin(commands.recv(supervisor_cx));
            Select::new(io, command).await
        };

        match selected {
            Ok(Either::Left(Either::Left(Ok(())))) => {}
            Ok(Either::Left(Either::Left(Err(error)))) => {
                fail_process_waiters(&mut process_waiters);
                if !recover_supervisor_connection(
                    supervisor_cx,
                    &mut connection,
                    &mut streak,
                    &mut keepalive,
                    error,
                )
                .await
                {
                    break;
                }
            }
            Ok(Either::Left(Either::Right(()))) => {
                // A finished Sleep must not be polled again; the next turn
                // arms one for the new deadline.
                ping_timer = None;
                let Some(clock) = keepalive.as_mut() else {
                    continue;
                };
                let failure = match clock.tick(supervisor_cx, connection.unanswered_pings()) {
                    KeepaliveTick::Ping(bound) => {
                        // A dead peer's full send buffer must not park the
                        // supervisor: the PING write gets one interval.
                        let now = timeout_now(supervisor_cx);
                        let ping = connection.send_keepalive_ping(supervisor_cx);
                        match crate::time::timeout(now, bound, ping).await {
                            Ok(Ok(())) => None,
                            Ok(Err(error)) => Some(error),
                            Err(_) => Some(stale_connection_error()),
                        }
                    }
                    KeepaliveTick::Stale => Some(stale_connection_error()),
                };
                if let Some(error) = failure {
                    fail_process_waiters(&mut process_waiters);
                    if !recover_supervisor_connection(
                        supervisor_cx,
                        &mut connection,
                        &mut streak,
                        &mut keepalive,
                        error,
                    )
                    .await
                    {
                        break;
                    }
                }
            }
            Ok(Either::Right(Ok(command))) => {
                // A subscription dropped while the supervisor waited is
                // unsubscribed before the command writes anything.
                if let Err(error) = connection.flush_dropped_subscriptions(supervisor_cx).await {
                    fail_process_waiters(&mut process_waiters);
                    if !recover_supervisor_connection(
                        supervisor_cx,
                        &mut connection,
                        &mut streak,
                        &mut keepalive,
                        error,
                    )
                    .await
                    {
                        break;
                    }
                }
                let ping_bound = keepalive.as_ref().map(KeepaliveClock::stale_window);
                if !handle_supervisor_command(
                    &mut connection,
                    command,
                    &mut process_waiters,
                    ping_bound,
                )
                .await
                {
                    break;
                }
                // A command cut off mid-exchange (a cancelled or failed write,
                // or a PING whose PONG never came) leaves the connection marked
                // unusable. The stream may end in a partial frame that the next
                // PONG would complete, so replace it instead of reading on.
                if !connection.connected {
                    fail_process_waiters(&mut process_waiters);
                    if !recover_supervisor_connection(
                        supervisor_cx,
                        &mut connection,
                        &mut streak,
                        &mut keepalive,
                        NatsError::NotConnected,
                    )
                    .await
                    {
                        break;
                    }
                }
            }
            Ok(Either::Right(Err(_))) | Err(_) => break,
        }
    }

    connection.state.closed.store(true, Ordering::Release);
    connection.state.connected.store(false, Ordering::Release);
    connection.state.subscriptions.lock().clear();
    connection.connected = false;
    let _ = connection.stream.shutdown(std::net::Shutdown::Both);
}

async fn drain_supervisor_frames(
    cx: &Cx,
    connection: &mut NatsConnection,
) -> Result<u64, NatsError> {
    let mut processed = 0_u64;
    loop {
        match connection.try_parse_message()? {
            Some(NatsMessage::Ping) => connection.send_server_pong(cx).await?,
            Some(NatsMessage::Msg(message)) => connection.dispatch_message(message),
            Some(NatsMessage::Err(error)) if server_error_keeps_connection(&error) => {
                cx.trace(&format!(
                    "nats: server reported {error:?}; the connection stays open"
                ));
            }
            Some(NatsMessage::Err(error)) => return Err(NatsError::Server(error)),
            Some(NatsMessage::Info(info)) => {
                *connection.state.server_info.lock() = Some(info);
            }
            Some(NatsMessage::Ok | NatsMessage::Pong) => {}
            None => return Ok(processed),
        }
        processed = processed.saturating_add(1);
    }
}

/// Whether the server keeps the connection open after sending `error`.
///
/// The server keeps it after a permissions violation, an invalid subject or
/// the subscription limit, and closes it after every other `-ERR`
/// (<https://docs.nats.io/reference/reference-protocols/nats-protocol#-err>).
/// Any other message is treated as fatal.
fn server_error_keeps_connection(error: &str) -> bool {
    let error = error.to_ascii_lowercase();
    error.starts_with("permissions violation for ")
        || error.starts_with("maximum subscriptions exceeded")
        || error == "invalid subject"
        || error == "invalid publish subject"
}

async fn recover_supervisor_connection(
    cx: &Cx,
    connection: &mut NatsConnection,
    streak: &mut ReconnectStreak,
    keepalive: &mut Option<KeepaliveClock>,
    error: NatsError,
) -> bool {
    cx.trace(&format!(
        "nats: supervisor transport error ({error}); entering reconnect lifecycle"
    ));
    connection.connected = false;
    connection.state.connected.store(false, Ordering::Release);
    let _ = connection.stream.shutdown(std::net::Shutdown::Both);
    let refused = matches!(error, NatsError::Server(_));
    let reconnected = connection.try_reconnect(cx, streak, refused).await.is_ok();
    connection
        .state
        .connected
        .store(reconnected, Ordering::Release);
    if reconnected && let Some(clock) = keepalive.as_mut() {
        clock.restart(cx);
    }
    reconnected
}

/// Why the supervisor replaces a connection that stopped answering its
/// keepalive (nats.go's `ErrStaleConnection`).
fn stale_connection_error() -> NatsError {
    NatsError::Io(io::Error::new(
        io::ErrorKind::TimedOut,
        "nats: stale connection: keepalive PINGs went unanswered",
    ))
}

/// A parked supervised `process()` call: the epoch it saw, and its reply.
type ProcessWaiter = (u64, oneshot::Sender<Result<(), NatsError>>);

/// Answers each parked `process()` call once the supervisor has handled a
/// frame after the epoch the call saw, and forgets callers that stopped
/// waiting.
fn answer_process_waiters(waiters: &mut Vec<ProcessWaiter>, epoch: u64) {
    let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(waiters)
        .into_iter()
        .filter(|(_, reply)| !reply.is_closed())
        .partition(|(after_epoch, _)| epoch > *after_epoch);
    *waiters = waiting;
    for (_, reply) in ready {
        let _ = reply.send_blocking(Ok(()));
    }
}

/// Fails every parked `process()` call when the connection breaks, as the
/// read it used to make would have.
fn fail_process_waiters(waiters: &mut Vec<ProcessWaiter>) {
    for (_, reply) in waiters.drain(..) {
        let _ = reply.send_blocking(Err(NatsError::NotConnected));
    }
}

/// Keep an in-flight command owned by the future waiting for its reply.
/// A timeout can drop that future without cancelling its Cx. Registering the
/// receiver-close wake before polling the operation lets a silent transport
/// release the supervisor immediately when its caller stops waiting.
///
/// Dropping the operation preserves the connection's existing cancellation
/// fences: a partial write or unfinished PING leaves it unusable, while a
/// request waiting for a reply drops its inbox and queues the required UNSUB.
/// Unsubscribe and Close bypass this helper because their cleanup must finish
/// even after the caller has stopped waiting.
async fn complete_supervisor_command<T>(
    mut reply: oneshot::Sender<Result<T, NatsError>>,
    operation: impl Future<Output = Result<T, NatsError>>,
) {
    let mut operation = std::pin::pin!(operation);
    let result = std::future::poll_fn(|task_cx| {
        if reply.poll_closed(task_cx).is_ready() {
            return Poll::Ready(None);
        }
        operation.as_mut().poll(task_cx).map(Some)
    })
    .await;
    if let Some(result) = result {
        let _ = reply.send_blocking(result);
    }
}

async fn handle_supervisor_command(
    connection: &mut NatsConnection,
    command: NatsSupervisorCommand,
    process_waiters: &mut Vec<ProcessWaiter>,
    ping_bound: Option<Duration>,
) -> bool {
    if command.caller_gave_up() {
        return true;
    }
    match command {
        NatsSupervisorCommand::Publish {
            cx,
            subject,
            payload,
            reply,
        } => {
            complete_supervisor_command(reply, connection.publish(&cx, &subject, &payload)).await;
        }
        NatsSupervisorCommand::PublishRequest {
            cx,
            subject,
            reply_to,
            payload,
            reply,
        } => {
            complete_supervisor_command(
                reply,
                connection.publish_request(&cx, &subject, &reply_to, &payload),
            )
            .await;
        }
        NatsSupervisorCommand::PublishRequestWithHeaders {
            cx,
            subject,
            reply_to,
            headers,
            payload,
            reply,
        } => {
            let headers = headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_slice()))
                .collect::<Vec<_>>();
            complete_supervisor_command(
                reply,
                connection.publish_request_with_headers(
                    &cx, &subject, &reply_to, &headers, &payload,
                ),
            )
            .await;
        }
        NatsSupervisorCommand::RequestWithHeaders {
            cx,
            subject,
            headers,
            payload,
            reply,
        } => {
            let headers = headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_slice()))
                .collect::<Vec<_>>();
            complete_supervisor_command(
                reply,
                connection.request_with_headers(&cx, &subject, &headers, &payload),
            )
            .await;
        }
        NatsSupervisorCommand::Request {
            cx,
            subject,
            payload,
            reply,
        } => {
            complete_supervisor_command(reply, connection.request(&cx, &subject, &payload)).await;
        }
        NatsSupervisorCommand::Subscribe {
            cx,
            subject,
            queue_group,
            capacity,
            reply,
        } => {
            complete_supervisor_command(reply, async {
                if let Some(queue_group) = queue_group {
                    connection
                        .queue_subscribe_with_capacity(&cx, &subject, &queue_group, capacity)
                        .await
                } else {
                    connection
                        .subscribe_with_capacity(&cx, &subject, capacity)
                        .await
                }
            })
            .await;
        }
        NatsSupervisorCommand::Unsubscribe { cx, sid, reply } => {
            let _ = reply.send_blocking(connection.unsubscribe(&cx, sid).await);
        }
        NatsSupervisorCommand::Ping { cx, reply } => {
            // With a keepalive, a PONG that has not come within its stale
            // window never will: the PING leaves the connection unusable and
            // the supervisor replaces it, rather than waiting (and keeping
            // the keepalive from ticking) until TCP gives up.
            complete_supervisor_command(reply, async {
                match ping_bound {
                    Some(bound) => {
                        let ping = connection.ping(&cx);
                        crate::time::timeout(timeout_now(&cx), bound, ping)
                            .await
                            .unwrap_or_else(|_| Err(stale_connection_error()))
                    }
                    None => connection.ping(&cx).await,
                }
            })
            .await;
        }
        NatsSupervisorCommand::Process { after_epoch, reply } => {
            // The supervisor's own frame loop answers it. Reading the socket
            // here held the supervisor until the next inbound frame even when
            // the caller had stopped waiting (a timeout drops the future and
            // does not cancel its Cx): for a JetStream pull, until the
            // server's next PING, minutes later, with every command queued.
            if !connection.connected {
                let _ = reply.send_blocking(Err(NatsError::NotConnected));
            } else if connection.state.processed_epoch.load(Ordering::Acquire) > after_epoch {
                let _ = reply.send_blocking(Ok(()));
            } else {
                process_waiters.retain(|(_, waiting)| !waiting.is_closed());
                process_waiters.push((after_epoch, reply));
            }
        }
        NatsSupervisorCommand::Close { cx, reply } => {
            let result = connection.close(&cx).await;
            let _ = reply.send_blocking(result);
            return false;
        }
    }
    connection
        .state
        .connected
        .store(connection.connected, Ordering::Release);
    true
}

/// The server status carried by a message that is only a `NATS/1.0` header
/// block (`NATS/1.0 503`, `NATS/1.0 409 Consumer Deleted`): its code and the
/// error it means. `None` for an ordinary message or a status below 300.
pub(crate) fn status_reply(message: &Message) -> Option<(u16, NatsError)> {
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

    // nats-server answers a request with no subscribers with a bare
    // `NATS/1.0 503` header and no Description line (real-server suite,
    // nats:2.10). Supply the protocol's well-known wording for that code
    // so callers can recognise the condition the way other clients
    // (`ErrNoResponders`) surface it; unknown bare codes keep the numeric
    // fallback.
    let detail = description.unwrap_or_else(|| match status {
        503 => "No Responders".to_string(),
        _ => format!("status {status}"),
    });
    Some((
        status,
        NatsError::Server(format!("status {status}: {detail}")),
    ))
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

/// A received message or a notification of local subscription-buffer loss.
///
/// Loss notifications aggregate dropped incoming messages. They are delivered
/// before the next receive when already known, but do not identify an exact
/// position among buffered messages. They do not report server-side loss or
/// messages missed while a connection was unavailable.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SubscriptionEvent {
    /// A message accepted into the subscription's local buffer.
    Message(Message),
    /// Incoming messages discarded because the local buffer was full.
    Lagged {
        /// Newly observed drops since the last loss notification.
        dropped: u64,
    },
}

/// A subscription to a NATS subject.
///
/// [`Self::next`] and [`Self::try_next`] preserve the message-only API. Use
/// [`Self::next_event`] or [`Self::try_next_event`] when local overflow must
/// be observable, or inspect [`Self::dropped_messages`] for cumulative loss.
pub struct Subscription {
    sid: u64,
    subject: String,
    rx: mpsc::Receiver<Message>,
    state: Arc<SharedState>,
    loss: Arc<SubscriptionLoss>,
    reported_dropped_messages: u64,
}

impl fmt::Debug for Subscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Subscription")
            .field("sid", &self.sid)
            .field("subject", &self.subject)
            .field("dropped_messages", &self.dropped_messages())
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

    /// Total messages discarded because this subscription's buffer was full.
    ///
    /// The count survives reconnects, unsubscribe, and connection closure,
    /// saturates at [`u64::MAX`], and is not reset by any receive method. It
    /// excludes deliveries to an already removed or dropped subscription.
    #[must_use]
    pub fn dropped_messages(&self) -> u64 {
        self.loss.count.load(Ordering::Acquire)
    }

    fn take_lagged_event(&mut self) -> Option<SubscriptionEvent> {
        let total = self.dropped_messages();
        let dropped = total - self.reported_dropped_messages;
        if dropped == 0 {
            return None;
        }
        self.reported_dropped_messages = total;
        Some(SubscriptionEvent::Lagged { dropped })
    }

    /// Receive a message or a notification of local buffer overflow.
    ///
    /// Cancellation-safe: a cancelled or dropped pending receive does not
    /// consume a message or loss notification. Loss already observed by the
    /// dispatcher is reported before receiving another message; loss that
    /// races a receive can be reported by the following call. Buffered
    /// messages and pending loss remain observable after unsubscribe or close.
    /// Returns `None` once the subscription is closed and both are drained.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<Option<SubscriptionEvent>, NatsError> {
        let loss = Arc::clone(&self.loss);
        loop {
            cx.checkpoint().map_err(|_| NatsError::Cancelled)?;
            if let Some(event) = self.take_lagged_event() {
                return Ok(Some(event));
            }

            let reported = self.reported_dropped_messages;
            let received = {
                let mut changed = std::pin::pin!(loss.changed.notified());
                let mut receive = std::pin::pin!(self.rx.recv(cx));
                std::future::poll_fn(|task_cx| {
                    if cx.checkpoint().is_err() {
                        return Poll::Ready(Some(Err(mpsc::RecvError::Cancelled)));
                    }
                    // Arm before checking the counter. A receiver may drain
                    // the last buffered message after try_send reports Full
                    // but before dispatch publishes that loss, so the message
                    // channel alone cannot provide the required wakeup.
                    let notified = changed.as_mut().poll(task_cx);
                    if loss.count.load(Ordering::Acquire) != reported || notified.is_ready() {
                        return Poll::Ready(None);
                    }
                    receive.as_mut().poll(task_cx).map(Some)
                })
                .await
            };

            match received {
                // A notification can race a count report. Re-arm and check
                // again; no message was consumed when this leg won.
                None => {}
                Some(Ok(message)) => return Ok(Some(SubscriptionEvent::Message(message))),
                Some(Err(mpsc::RecvError::Cancelled)) => return Err(NatsError::Cancelled),
                Some(Err(mpsc::RecvError::Disconnected | mpsc::RecvError::Empty)) => {
                    // Sender closure is authoritative here. In-flight
                    // dispatches retain a sender until their loss is published.
                    return Ok(self.take_lagged_event());
                }
            }
        }
    }

    /// Try to receive a message or local-overflow notification without waiting.
    ///
    /// Returns `None` when neither is currently available. Like
    /// [`Self::try_next`], this does not distinguish an empty buffer from a
    /// closed subscription. A loss notification consumes only its report,
    /// never a buffered message or the cumulative drop count.
    pub fn try_next_event(&mut self) -> Option<SubscriptionEvent> {
        self.take_lagged_event()
            .or_else(|| self.try_next().map(SubscriptionEvent::Message))
    }

    /// Receive the next message. Cancellation-safe.
    ///
    /// Local overflow is available through [`Self::dropped_messages`] or the
    /// event receive methods; this compatibility method returns messages only.
    pub async fn next(&mut self, cx: &Cx) -> Result<Option<Message>, NatsError> {
        cx.checkpoint().map_err(|_| NatsError::Cancelled)?;

        // Drain any buffered messages before reporting closure so that
        // messages dispatched before close() are not silently lost.
        if let Ok(msg) = self.rx.try_recv() {
            return Ok(Some(msg));
        }

        // Every connection-close path retires the registered senders, but a
        // dispatch admitted before close can still hold a temporary sender.
        // Wait for that sender too, so the global closed flag cannot hide its
        // final accepted message from the message-only receive API.
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
        // Remove from shared state. A subscription still registered here was
        // never unsubscribed, and the server keeps routing to it until told
        // otherwise, so a supervised client queues its UNSUB.
        let mut subs = self.state.subscriptions.lock();
        if subs.remove(&self.sid).is_some()
            && self.state.supervised.load(Ordering::Acquire)
            && !self.state.closed.load(Ordering::Acquire)
        {
            self.state.dropped_sids.lock().push(self.sid);
        }
    }
}

#[cfg(test)]
#[path = "nats_inline_tests.rs"]
mod tests;
