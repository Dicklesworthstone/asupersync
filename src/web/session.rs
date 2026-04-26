//! Session middleware with pluggable storage backends.
//!
//! Provides HTTP session management via cookies. Sessions are identified by
//! a random session ID stored in a configurable cookie. Session data is
//! stored in a pluggable backend (in-memory by default).
//!
//! # Example
//!
//! ```ignore
//! use asupersync::web::session::{SessionLayer, MemoryStore};
//! use asupersync::web::{Router, get};
//!
//! let store = MemoryStore::new();
//! let app = SessionLayer::new(store)
//!     .cookie_name("sid")
//!     .wrap(my_handler);
//! ```

use parking_lot::Mutex;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::extract::Request;
use super::handler::Handler;
use super::response::{Response, StatusCode};

/// Default session cookie name.
const DEFAULT_COOKIE_NAME: &str = "session_id";

/// Session ID length in hex characters (16 bytes = 32 hex chars).
const SESSION_ID_HEX_LEN: usize = 32;

/// Reserved key under which the per-session CSRF token is stored inside
/// `SessionData`. Stored alongside user data so the existing
/// `SessionStore::save` / `load` contracts don't need a schema change
/// (br-asupersync-7udumi).
const CSRF_TOKEN_KEY: &str = "__asupersync.csrf_token";

/// Reserved key under which the last-accessed unix timestamp (seconds)
/// is stored inside `SessionData`. Used by the server-side idle-TTL
/// expiration check (br-asupersync-7udumi).
const LAST_ACCESSED_KEY: &str = "__asupersync.last_accessed_unix_secs";

/// br-asupersync-hifab2 — Reserved key set by [`Session::regenerate`] to
/// signal the middleware that the session ID must be rotated at response
/// time. The middleware deletes the old store entry, mints a fresh ID,
/// saves the data under the new ID, and emits a new Set-Cookie. This
/// prevents session fixation: if an attacker primes the victim's browser
/// with a known session ID and then waits for the victim to authenticate,
/// rotating on auth boundary makes the captured ID worthless.
const REGENERATE_FLAG_KEY: &str = "__asupersync.regenerate";

/// HTTP request methods that mutate server-side state. CSRF validation
/// is required on these methods only — safe methods (GET/HEAD/OPTIONS)
/// are exempt per the OWASP CSRF Prevention Cheat Sheet.
fn is_state_changing_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH" | "DELETE"
    )
}

/// Returns the current unix-epoch time in seconds. Used for idle-TTL
/// bookkeeping. Falls back to 0 if the system clock is somehow before
/// the epoch (defensive — production clocks always exceed 1970).
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ─── SessionStore trait ─────────────────────────────────────────────────────

/// Storage backend for session data.
///
/// Implementations must be `Send + Sync` for use across threads.
pub trait SessionStore: Send + Sync + 'static {
    /// Load session data by ID. Returns `None` if the session doesn't exist.
    fn load(&self, id: &str) -> Option<SessionData>;

    /// Save session data. Called after each request.
    fn save(&self, id: &str, data: &SessionData);

    /// Delete a session by ID.
    fn delete(&self, id: &str);
}

// ─── SessionData ────────────────────────────────────────────────────────────

/// Session key-value data.
#[derive(Debug, Clone, Default)]
pub struct SessionData {
    values: HashMap<String, String>,
    modified: bool,
}

impl SessionData {
    /// Create empty session data.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }

    /// Insert a key-value pair. Returns the previous value if any.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) -> Option<String> {
        self.modified = true;
        self.values.insert(key.into(), value.into())
    }

    /// Remove a key. Returns the previous value if any.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.modified = true;
        self.values.remove(key)
    }

    /// Returns `true` if the session data was modified.
    #[must_use]
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// Returns `true` if the session has no data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// All keys.
    #[must_use]
    pub fn keys(&self) -> Vec<&str> {
        self.values.keys().map(String::as_str).collect()
    }

    /// Clear all data.
    pub fn clear(&mut self) {
        self.modified = true;
        self.values.clear();
    }
}

// ─── MemoryStore ────────────────────────────────────────────────────────────

/// In-memory session store. Data is lost on process restart.
///
/// Suitable for development and single-process deployments.
#[derive(Clone, Default)]
pub struct MemoryStore {
    sessions: Arc<Mutex<HashMap<String, SessionData>>>,
}

impl MemoryStore {
    /// Create a new empty memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Number of active sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.lock().len()
    }

    /// Returns `true` if there are no sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.lock().is_empty()
    }
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.sessions.lock().len();
        f.debug_struct("MemoryStore")
            .field("sessions", &count)
            .finish()
    }
}

impl SessionStore for MemoryStore {
    fn load(&self, id: &str) -> Option<SessionData> {
        self.sessions.lock().get(id).cloned()
    }

    fn save(&self, id: &str, data: &SessionData) {
        let mut stored = data.clone();
        // Reset modified flag so reloaded sessions don't appear pre-modified,
        // which would cause unnecessary re-saves and Set-Cookie headers.
        stored.modified = false;
        self.sessions.lock().insert(id.to_string(), stored);
    }

    fn delete(&self, id: &str) {
        self.sessions.lock().remove(id);
    }
}

// ─── Session ID generation ──────────────────────────────────────────────────

/// Generate a cryptographically random session ID (16 random bytes as hex).
fn generate_session_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS entropy source unavailable");
    let mut hex = String::with_capacity(32);
    for b in &buf {
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Validate that a session ID looks legitimate (hex, correct length).
fn is_valid_session_id(id: &str) -> bool {
    id.len() == SESSION_ID_HEX_LEN && id.bytes().all(|b| b.is_ascii_hexdigit())
}

// ─── Cookie parsing helpers ─────────────────────────────────────────────────

/// Extract a cookie value from the Cookie header.
fn get_cookie(req: &Request, name: &str) -> Option<String> {
    let header = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .map(|(_, v)| v)?;
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// br-asupersync-uz7oxb — true if `s` is safe to interpolate into a
/// `Set-Cookie` header field as a name, value, or attribute value.
/// Rejects any byte that would terminate the current attribute or split
/// the header: `;`, `,`, `=` for names, control chars (< 0x20), `\r`,
/// `\n`, and DEL (0x7f).
fn is_cookie_token_safe(s: &str, allow_eq: bool) -> bool {
    s.bytes().all(|b| {
        b >= 0x20
            && b != 0x7f
            && b != b';'
            && b != b','
            && b != b'\r'
            && b != b'\n'
            && (allow_eq || b != b'=')
    })
}

/// Build a Set-Cookie header value.
///
/// br-asupersync-uz7oxb — sanitises the cookie `name`, `value`, and the
/// configured `cookie_path`: any byte that would let a caller escape its
/// attribute (`;`, `,`, control chars, CR/LF, DEL) panics. The current
/// internal callers all pass either the configured cookie name (set at
/// startup) or hex session IDs (caller-built), but the helper is a
/// general-purpose API and a future caller passing user-controlled input
/// is one refactor away from header injection / cookie scope escape.
/// Names additionally reject `=` since the format is `name=value`.
fn set_cookie_header(name: &str, value: &str, config: &SessionConfig) -> String {
    assert!(
        is_cookie_token_safe(name, false),
        "br-asupersync-uz7oxb: cookie name contains forbidden byte (;,=,CR,LF,control,DEL)"
    );
    assert!(
        is_cookie_token_safe(value, true),
        "br-asupersync-uz7oxb: cookie value contains forbidden byte (;,,CR,LF,control,DEL)"
    );
    assert!(
        is_cookie_token_safe(&config.cookie_path, true),
        "br-asupersync-uz7oxb: cookie_path contains forbidden byte (;,,CR,LF,control,DEL)"
    );
    let mut cookie = format!("{name}={value}; Path={}", config.cookie_path);
    if config.http_only {
        cookie.push_str("; HttpOnly");
    }
    if config.secure {
        cookie.push_str("; Secure");
    }
    match config.same_site {
        SameSite::Strict => cookie.push_str("; SameSite=Strict"),
        SameSite::Lax => cookie.push_str("; SameSite=Lax"),
        SameSite::None => cookie.push_str("; SameSite=None"),
    }
    if let Some(max_age) = config.max_age {
        let _ = write!(cookie, "; Max-Age={max_age}");
    }
    cookie
}

// ─── SessionConfig ──────────────────────────────────────────────────────────

/// SameSite cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    /// Always send cookie in same-site requests only.
    Strict,
    /// Send cookie in same-site requests and top-level navigations.
    Lax,
    /// Send cookie in all contexts (requires `Secure` in modern browsers).
    None,
}

/// Configuration error produced by [`SessionConfig::validate`].
/// (br-asupersync-7udumi)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionConfigError {
    /// `SameSite::None` was set without `secure = true`. Modern browsers
    /// silently drop such cookies; we reject the configuration loudly so
    /// the misconfiguration is visible at startup, not at the first
    /// inexplicable session loss.
    SameSiteNoneWithoutSecure,
}

impl fmt::Display for SessionConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SameSiteNoneWithoutSecure => write!(
                f,
                "session: SameSite=None requires Secure (browsers reject cross-site cookies otherwise)"
            ),
        }
    }
}

impl std::error::Error for SessionConfigError {}

/// Session cookie configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Name of the session cookie.
    pub cookie_name: String,
    /// Cookie `Path` attribute.
    pub cookie_path: String,
    /// Cookie `HttpOnly` attribute.
    pub http_only: bool,
    /// Cookie `Secure` attribute. **Default: `true`.** Production sites
    /// MUST serve over HTTPS; flipping this to `false` is only sane in
    /// dev. (br-asupersync-7udumi)
    pub secure: bool,
    /// Cookie `SameSite` attribute.
    pub same_site: SameSite,
    /// Optional cookie `Max-Age` in seconds.
    pub max_age: Option<u64>,
    /// Server-side idle timeout in seconds. When `Some(n)` and a session
    /// has not been accessed for more than `n` seconds, the next request
    /// treats it as expired (server-side delete + new session id) even if
    /// the client cookie is still valid. `None` disables the idle check.
    /// (br-asupersync-7udumi)
    pub idle_ttl_seconds: Option<u64>,
    /// Whether to require a CSRF token on state-changing requests
    /// (POST / PUT / PATCH / DELETE). The token is bound to the session,
    /// stored under [`CSRF_TOKEN_KEY`] inside `SessionData`, and must be
    /// supplied by the client as the `X-CSRF-Token` request header.
    /// **Default: `true`.** (br-asupersync-7udumi)
    pub csrf_protection: bool,
    /// br-asupersync-czbj90 — Allowed `Origin` values for state-changing
    /// requests. Each entry is a scheme+host[+port] string matched
    /// case-insensitively against the request `Origin` header (with
    /// `Referer` as a fallback when `Origin` is absent — older clients).
    /// Per OWASP CSRF Prevention Cheat Sheet, this is the second layer
    /// of defense alongside the synchronizer-token check.
    ///
    /// **When empty** (default), origin checking is disabled and only
    /// the X-CSRF-Token check fires. **When non-empty**, state-changing
    /// requests must carry an `Origin` (or `Referer`) header whose
    /// origin matches one of these entries; otherwise the request is
    /// rejected with 403 even before the X-CSRF-Token check.
    ///
    /// Modern browsers always send `Origin` on state-changing requests,
    /// so populating this is essentially free at runtime and adds
    /// significant defense against header-stripping intermediaries that
    /// drop `X-CSRF-Token` but preserve `Origin` (forms posted from same
    /// site without JS).
    pub allowed_origins: Vec<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            cookie_path: "/".to_string(),
            http_only: true,
            // br-asupersync-7udumi: default-secure. Anything else is a
            // dev convenience that should require an explicit opt-out.
            secure: true,
            same_site: SameSite::Lax,
            max_age: None,
            idle_ttl_seconds: None,
            csrf_protection: true,
            allowed_origins: Vec::new(),
        }
    }
}

impl SessionConfig {
    /// Validate the configuration. Currently rejects the
    /// `SameSite::None && !secure` combination, which browsers silently
    /// drop. Called from [`SessionLayer::new`] (where it panics on
    /// failure) and available for explicit pre-flight checks.
    /// (br-asupersync-7udumi)
    pub fn validate(&self) -> Result<(), SessionConfigError> {
        if self.same_site == SameSite::None && !self.secure {
            return Err(SessionConfigError::SameSiteNoneWithoutSecure);
        }
        Ok(())
    }
}

// ─── SessionLayer ───────────────────────────────────────────────────────────

/// Session middleware layer.
///
/// Wraps a handler, loading/saving session data from the configured store
/// on each request. The session ID is managed via a cookie.
pub struct SessionLayer<S: SessionStore> {
    store: Arc<S>,
    config: SessionConfig,
}

impl<S: SessionStore> SessionLayer<S> {
    /// Create a new session layer with the given store.
    ///
    /// The default configuration is production-safe: `HttpOnly`, `Secure`,
    /// `SameSite=Lax`, CSRF protection enabled. Customise via the builder
    /// methods. (br-asupersync-7udumi)
    pub fn new(store: S) -> Self {
        let config = SessionConfig::default();
        // Default config is always valid; this expect() is a guard for
        // future maintainers who change the default — they'll see the
        // panic at startup rather than discovering broken cookies in
        // prod.
        config
            .validate()
            .expect("default SessionConfig must validate");
        Self {
            store: Arc::new(store),
            config,
        }
    }

    /// Set the session cookie name.
    #[must_use]
    pub fn cookie_name(mut self, name: impl Into<String>) -> Self {
        self.config.cookie_name = name.into();
        self
    }

    /// Set the cookie path.
    #[must_use]
    pub fn cookie_path(mut self, path: impl Into<String>) -> Self {
        self.config.cookie_path = path.into();
        self
    }

    /// br-asupersync-czbj90 — Set the allow-list of expected origins for
    /// state-changing requests. See [`SessionConfig::allowed_origins`].
    /// Each entry should be a scheme+host[+port] string such as
    /// `"https://app.example.com"` or `"https://app.example.com:8443"`.
    #[must_use]
    pub fn allowed_origins<I, S2>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S2>,
        S2: Into<String>,
    {
        self.config.allowed_origins = origins.into_iter().map(Into::into).collect();
        self
    }

    /// Set the HttpOnly flag.
    #[must_use]
    pub fn http_only(mut self, value: bool) -> Self {
        self.config.http_only = value;
        self
    }

    /// Set the Secure flag.
    #[must_use]
    pub fn secure(mut self, value: bool) -> Self {
        self.config.secure = value;
        self
    }

    /// Set the SameSite attribute.
    ///
    /// **Panics** if `SameSite::None` is set while `secure = false` —
    /// browsers silently drop such cookies, so we surface the
    /// misconfiguration loudly. (br-asupersync-7udumi)
    #[must_use]
    pub fn same_site(mut self, value: SameSite) -> Self {
        self.config.same_site = value;
        self.config
            .validate()
            .expect("SessionConfig validation failed (SameSite=None requires Secure)");
        self
    }

    /// Set Max-Age in seconds.
    #[must_use]
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.config.max_age = Some(seconds);
        self
    }

    /// Set the server-side idle TTL (seconds). Sessions older than this
    /// since their last access are treated as expired on the next
    /// request. (br-asupersync-7udumi)
    #[must_use]
    pub fn idle_ttl_seconds(mut self, seconds: u64) -> Self {
        self.config.idle_ttl_seconds = Some(seconds);
        self
    }

    /// Toggle CSRF protection. Default is enabled — disable only for
    /// API-only endpoints that authenticate every request via a bearer
    /// token unrelated to the session cookie. (br-asupersync-7udumi)
    #[must_use]
    pub fn csrf_protection(mut self, enabled: bool) -> Self {
        self.config.csrf_protection = enabled;
        self
    }

    /// Wrap a handler with session management.
    pub fn wrap<H: Handler>(self, inner: H) -> SessionMiddleware<S, H> {
        // Final validation gate — catches manual mutations to
        // self.config that bypassed the builder's setters.
        self.config
            .validate()
            .expect("SessionConfig validation failed before wrap");
        SessionMiddleware {
            inner,
            store: self.store,
            config: self.config,
        }
    }
}

impl<S: SessionStore> fmt::Debug for SessionLayer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionLayer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// ─── SessionMiddleware ──────────────────────────────────────────────────────

/// The actual middleware that wraps a handler.
pub struct SessionMiddleware<S: SessionStore, H: Handler> {
    inner: H,
    store: Arc<S>,
    config: SessionConfig,
}

impl<S: SessionStore, H: Handler> Handler for SessionMiddleware<S, H> {
    fn call(&self, mut req: Request) -> Response {
        // 1. Extract or generate session ID.
        //    If the client-supplied ID is syntactically valid but absent from the
        //    store, regenerate to prevent session-fixation attacks (an attacker
        //    could plant a chosen ID and later hijack it).
        let (mut session_id, mut is_new) = match get_cookie(&req, &self.config.cookie_name) {
            Some(id) if is_valid_session_id(&id) => (id, false),
            _ => (generate_session_id(), true),
        };

        // 2. Load existing session data.
        //    If the client-supplied ID is not in the store, regenerate to
        //    prevent session-fixation attacks. Also: if an idle TTL is
        //    configured and the session's last_accessed is too old,
        //    server-side delete + new id (br-asupersync-7udumi).
        let mut session_data = if is_new {
            SessionData::new()
        } else if let Some(data) = self.store.load(&session_id) {
            if self.is_idle_expired(&data) {
                self.store.delete(&session_id);
                session_id = generate_session_id();
                is_new = true;
                SessionData::new()
            } else {
                data
            }
        } else {
            session_id = generate_session_id();
            is_new = true;
            SessionData::new()
        };

        // 2b. Touch the session (refresh last-accessed timestamp). Marks
        //     the session as modified so the touch is persisted to the
        //     store on this request. (br-asupersync-7udumi)
        session_data.insert(LAST_ACCESSED_KEY, now_unix_secs().to_string());

        // 2c. Ensure a CSRF token exists. New sessions get one on first
        //     touch; existing sessions that pre-date this commit get one
        //     lazily on first access. (br-asupersync-7udumi)
        if self.config.csrf_protection && session_data.get(CSRF_TOKEN_KEY).is_none() {
            session_data.insert(CSRF_TOKEN_KEY, generate_session_id());
        }

        // 2d. CSRF validation — state-changing requests must present the
        //     X-CSRF-Token header matching the session's stored token.
        //     Constant-time comparison prevents timing oracles.
        //     (br-asupersync-7udumi)
        //
        //     br-asupersync-czbj90 — defense in depth: when allowed_origins
        //     is non-empty, also validate the request Origin (or Referer
        //     fallback) against the allow-list. Modern browsers always
        //     send Origin on state-changing requests, so this check is
        //     essentially free at runtime. Header-stripping intermediaries
        //     that drop X-CSRF-Token but preserve Origin still get
        //     stopped here; a forged Origin would fail this check before
        //     the X-CSRF-Token check has a chance to compensate. If both
        //     Origin and Referer are absent on a state-changing request
        //     and origin checking is configured, reject as 403.
        if self.config.csrf_protection
            && is_state_changing_method(&req.method)
            && !self.config.allowed_origins.is_empty()
        {
            match request_origin(&req) {
                None => {
                    return Response::new(
                        StatusCode::FORBIDDEN,
                        crate::bytes::Bytes::from_static(
                            b"CSRF: missing Origin/Referer header on state-changing request",
                        ),
                    )
                    .header("content-type", "text/plain; charset=utf-8");
                }
                Some(origin) => {
                    if !origin_is_allowed(&origin, &self.config.allowed_origins) {
                        return Response::new(
                            StatusCode::FORBIDDEN,
                            crate::bytes::Bytes::from_static(
                                b"CSRF: Origin/Referer not in allow-list",
                            ),
                        )
                        .header("content-type", "text/plain; charset=utf-8");
                    }
                }
            }
        }

        if self.config.csrf_protection && is_state_changing_method(&req.method) {
            // Brand-new sessions on the first request can't have shipped
            // a token to the client yet, so we don't reject them — but
            // they have no authenticated state either, so the CSRF
            // window is empty anyway. Reject only when the session was
            // loaded from storage (i.e. the client should know the
            // token).
            if !is_new {
                let header_token = req
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("x-csrf-token"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or("");
                let session_token = session_data.get(CSRF_TOKEN_KEY).unwrap_or("");
                if !constant_time_eq_str(header_token, session_token) || session_token.is_empty() {
                    return Response::new(
                        StatusCode::FORBIDDEN,
                        crate::bytes::Bytes::from_static(b"CSRF token missing or invalid"),
                    )
                    .header("content-type", "text/plain; charset=utf-8");
                }
            }
        }

        // 3. Inject session data into request extensions.
        //    We use a shared Arc<Mutex<SessionData>> so the handler can modify it.
        let session_handle = Arc::new(Mutex::new(session_data));
        req.extensions
            .insert_typed(Session(Arc::clone(&session_handle)));

        // 4. Call inner handler.
        let mut resp = self.inner.call(req);

        // 5. Extract (possibly modified) session data.
        session_data = {
            let guard = session_handle.lock();
            guard.clone()
        };

        // 5b. br-asupersync-hifab2 — handle session-ID regeneration. If the
        //     handler called Session::regenerate(), the data carries a
        //     REGENERATE_FLAG_KEY marker. Delete the old store entry, mint
        //     a fresh ID, strip the marker, and proceed with the new ID
        //     for the save+cookie steps below. The CSRF token was already
        //     rotated inside Session::regenerate(); we strip the marker
        //     here so it doesn't persist into the saved data.
        let regenerate_requested = session_data.get(REGENERATE_FLAG_KEY).is_some();
        if regenerate_requested {
            session_data.remove(REGENERATE_FLAG_KEY);
            if !is_new {
                self.store.delete(&session_id);
            }
            session_id = generate_session_id();
            // Treat as a freshly-issued cookie (must be Set-Cookie'd to
            // the client); the old client cookie is implicitly replaced
            // by the new one in the response.
            is_new = true;
            // Force the modified flag so the save+cookie branches fire.
            session_data.insert(LAST_ACCESSED_KEY, now_unix_secs().to_string());
        }

        // 6. Save if modified. Untouched new sessions are NOT saved to prevent DoS.
        let session_cleared = session_data.is_empty() && session_data.is_modified();

        if session_cleared {
            if !is_new {
                // Session cleared → delete server-side data and expire the cookie.
                self.store.delete(&session_id);
            }
        } else if session_data.is_modified() || regenerate_requested {
            self.store.save(&session_id, &session_data);
        }

        // 7. Set cookie on modified sessions, or expire if cleared.
        if session_cleared {
            if !is_new {
                // Expire the cookie so the browser deletes it.
                // Reuse set_cookie_header to ensure all configured attributes
                // (Secure, SameSite, HttpOnly) are included — omitting them
                // could leave a stale session cookie in the browser.
                let mut expire_config = self.config.clone();
                expire_config.max_age = Some(0);
                let cookie_val = set_cookie_header(&self.config.cookie_name, "", &expire_config);
                resp.set_header("set-cookie", cookie_val);
            }
        } else if session_data.is_modified() || regenerate_requested {
            let cookie_val = set_cookie_header(&self.config.cookie_name, &session_id, &self.config);
            resp.set_header("set-cookie", cookie_val);
        }

        resp
    }
}

impl<S: SessionStore, H: Handler> SessionMiddleware<S, H> {
    /// Returns true if the configured idle TTL has elapsed since the
    /// session's `LAST_ACCESSED_KEY` timestamp. Sessions without the
    /// timestamp (pre-7udumi sessions) are treated as fresh on the
    /// first access; the next request will populate the timestamp.
    fn is_idle_expired(&self, data: &SessionData) -> bool {
        let Some(ttl) = self.config.idle_ttl_seconds else {
            return false;
        };
        let Some(last_str) = data.get(LAST_ACCESSED_KEY) else {
            return false;
        };
        let Ok(last) = last_str.parse::<u64>() else {
            return false;
        };
        let now = now_unix_secs();
        now.saturating_sub(last) > ttl
    }
}

/// br-asupersync-czbj90 — Extract the `Origin` header verbatim, falling
/// back to the scheme+host+port portion of `Referer` if Origin is
/// absent. Returns `None` if neither header is present or the Referer
/// fails to parse far enough to derive an origin. Comparison against
/// `allowed_origins` is case-insensitive.
fn request_origin(req: &Request) -> Option<String> {
    if let Some((_, origin)) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("origin"))
    {
        let trimmed = origin.trim();
        if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("null") {
            return Some(trimmed.to_string());
        }
    }
    if let Some((_, referer)) = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("referer"))
    {
        // Extract the scheme+authority prefix: scheme://host[:port]
        // (everything up to the first '/' after the "://").
        let r = referer.trim();
        let scheme_end = r.find("://")?;
        let after_scheme_idx = scheme_end + 3;
        let rest = &r[after_scheme_idx..];
        let path_start = rest.find('/').unwrap_or(rest.len());
        return Some(r[..after_scheme_idx + path_start].to_string());
    }
    None
}

/// br-asupersync-czbj90 — true if `origin` matches at least one entry of
/// `allowed`. Comparison is case-insensitive on the scheme+host[+port]
/// portion only; trailing slashes / paths are stripped from candidates
/// to make `https://app.example.com/` and `https://app.example.com`
/// equivalent.
fn origin_is_allowed(origin: &str, allowed: &[String]) -> bool {
    fn normalise(s: &str) -> String {
        let trimmed = s.trim().trim_end_matches('/');
        trimmed.to_ascii_lowercase()
    }
    let want = normalise(origin);
    allowed.iter().any(|a| normalise(a) == want)
}

/// Constant-time string equality. Used for CSRF-token comparison so a
/// per-byte timing oracle cannot leak the session's token. Falls back
/// to `false` immediately on length mismatch — the length is not
/// secret, so this is acceptable.
fn constant_time_eq_str(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    if ab.len() != bb.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in ab.iter().zip(bb.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ─── Session handle ─────────────────────────────────────────────────────────

/// Handle to the current session, stored in request extensions.
///
/// Extract this from the request to read/write session data within a handler.
#[derive(Clone)]
pub struct Session(Arc<Mutex<SessionData>>);

impl Session {
    /// Get a value from the session.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<String> {
        self.0.lock().get(key).map(ToString::to_string)
    }

    /// Insert a value into the session.
    pub fn insert(&self, key: impl Into<String>, value: impl Into<String>) {
        self.0.lock().insert(key, value);
    }

    /// Remove a value from the session.
    #[must_use]
    pub fn remove(&self, key: &str) -> Option<String> {
        self.0.lock().remove(key)
    }

    /// Clear all session data.
    pub fn clear(&self) {
        self.0.lock().clear();
    }

    /// Check if a key exists.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.0.lock().get(key).is_some()
    }

    /// Returns the per-session CSRF token if one is set. Handlers should
    /// echo this into response payloads (HTML form fields, response
    /// headers, JSON envelopes) so JS clients can replay it as the
    /// `X-CSRF-Token` header on state-changing requests.
    /// (br-asupersync-7udumi)
    #[must_use]
    pub fn csrf_token(&self) -> Option<String> {
        self.0.lock().get(CSRF_TOKEN_KEY).map(ToString::to_string)
    }

    /// br-asupersync-hifab2 — Request a session-ID rotation at the end of
    /// this request. The middleware deletes the old server-side entry,
    /// mints a fresh cryptographic ID, saves the (carried-over) data
    /// under the new ID, rotates the CSRF token, and issues a new
    /// Set-Cookie header. Idiomatic call sites: directly after a
    /// successful login, on MFA verification, on role-elevation, on
    /// logout (followed by `clear()`).
    ///
    /// User data is preserved — only the ID and CSRF token change.
    /// To clear data, call [`Self::clear`] before or after
    /// `regenerate()`.
    pub fn regenerate(&self) {
        let mut guard = self.0.lock();
        guard.insert(REGENERATE_FLAG_KEY, "1");
        // Rotate CSRF token alongside ID — a session ID rotation that
        // doesn't rotate the bound CSRF token leaves a trust-boundary
        // hole. (br-asupersync-3cvnmo)
        guard.insert(CSRF_TOKEN_KEY, generate_session_id());
    }

    /// br-asupersync-3cvnmo — Mint a fresh CSRF token for this session
    /// without rotating the session ID. Use this for periodic in-session
    /// rotation (e.g. on a per-N-request or per-time-window policy)
    /// where a full ID rotation is not warranted. The new token is
    /// returned to the caller so the response can echo it to the client
    /// before the old one becomes invalid.
    ///
    /// Most callers should prefer [`Self::regenerate`], which rotates
    /// both ID and CSRF in lockstep.
    pub fn rotate_csrf_token(&self) -> String {
        let token = generate_session_id();
        self.0.lock().insert(CSRF_TOKEN_KEY, token.clone());
        token
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.0.lock();
        f.debug_struct("Session")
            .field("len", &data.len())
            .field("modified", &data.is_modified())
            .finish()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

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
    use super::super::handler::Handler;
    use super::super::response::StatusCode;
    use super::*;

    // ================================================================
    // SessionData
    // ================================================================

    #[test]
    fn session_data_insert_get() {
        let mut data = SessionData::new();
        assert!(data.is_empty());
        assert_eq!(data.len(), 0);

        data.insert("user", "alice");
        assert_eq!(data.get("user"), Some("alice"));
        assert_eq!(data.len(), 1);
        assert!(!data.is_empty());
        assert!(data.is_modified());
    }

    #[test]
    fn session_data_remove() {
        let mut data = SessionData::new();
        data.insert("key", "val");
        let removed = data.remove("key");
        assert_eq!(removed.as_deref(), Some("val"));
        assert!(data.is_empty());
    }

    #[test]
    fn session_data_clear() {
        let mut data = SessionData::new();
        data.insert("a", "1");
        data.insert("b", "2");
        data.clear();
        assert!(data.is_empty());
        assert!(data.is_modified());
    }

    #[test]
    fn session_data_keys() {
        let mut data = SessionData::new();
        data.insert("x", "1");
        data.insert("y", "2");
        let mut keys = data.keys();
        keys.sort_unstable();
        assert_eq!(keys, vec!["x", "y"]);
    }

    #[test]
    fn session_data_not_modified_initially() {
        let data = SessionData::new();
        assert!(!data.is_modified());
    }

    #[test]
    fn session_data_debug_clone() {
        let mut data = SessionData::new();
        data.insert("k", "v");
        let dbg = format!("{data:?}");
        assert!(dbg.contains("SessionData"));
        let cloned = data.clone();
        assert_eq!(cloned.get("k"), Some("v"));
    }

    // ================================================================
    // MemoryStore
    // ================================================================

    #[test]
    fn memory_store_save_load() {
        let store = MemoryStore::new();
        let mut data = SessionData::new();
        data.insert("user", "bob");

        store.save("sess1", &data);
        assert_eq!(store.len(), 1);

        let loaded = store.load("sess1").unwrap();
        assert_eq!(loaded.get("user"), Some("bob"));
    }

    #[test]
    fn memory_store_delete() {
        let store = MemoryStore::new();
        store.save("sess1", &SessionData::new());
        assert_eq!(store.len(), 1);

        store.delete("sess1");
        assert!(store.is_empty());
        assert!(store.load("sess1").is_none());
    }

    #[test]
    fn memory_store_load_missing() {
        let store = MemoryStore::new();
        assert!(store.load("nonexistent").is_none());
    }

    #[test]
    fn memory_store_debug_clone() {
        let store = MemoryStore::new();
        let dbg = format!("{store:?}");
        assert!(dbg.contains("MemoryStore"));
    }

    #[test]
    fn memory_store_default() {
        let store = MemoryStore::default();
        assert!(store.is_empty());
    }

    // ================================================================
    // Session ID
    // ================================================================

    #[test]
    fn generate_id_is_valid() {
        let id = generate_session_id();
        assert!(is_valid_session_id(&id));
        assert_eq!(id.len(), SESSION_ID_HEX_LEN);
    }

    #[test]
    fn generate_id_uniqueness() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, id2);
    }

    #[test]
    fn validate_session_id() {
        assert!(is_valid_session_id("0123456789abcdef0123456789abcdef"));
        assert!(!is_valid_session_id("short"));
        assert!(!is_valid_session_id("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
        assert!(!is_valid_session_id(""));
    }

    // ================================================================
    // Cookie parsing
    // ================================================================

    #[test]
    fn get_cookie_basic() {
        let mut req = Request::new("GET", "/");
        req.headers
            .insert("cookie".to_string(), "session_id=abc123".to_string());
        assert_eq!(get_cookie(&req, "session_id"), Some("abc123".to_string()));
    }

    #[test]
    fn get_cookie_multiple() {
        let mut req = Request::new("GET", "/");
        req.headers.insert(
            "cookie".to_string(),
            "foo=bar; session_id=xyz; other=val".to_string(),
        );
        assert_eq!(get_cookie(&req, "session_id"), Some("xyz".to_string()));
    }

    #[test]
    fn get_cookie_missing() {
        let req = Request::new("GET", "/");
        assert!(get_cookie(&req, "session_id").is_none());
    }

    // ================================================================
    // Set-Cookie header
    // ================================================================

    #[test]
    fn set_cookie_default_config() {
        let config = SessionConfig::default();
        let header = set_cookie_header("sid", "val123", &config);
        assert!(header.contains("sid=val123"));
        assert!(header.contains("Path=/"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("SameSite=Lax"));
        assert!(!header.contains("Secure"));
    }

    #[test]
    fn set_cookie_secure_strict() {
        let config = SessionConfig {
            secure: true,
            same_site: SameSite::Strict,
            max_age: Some(3600),
            ..Default::default()
        };
        let header = set_cookie_header("sid", "val", &config);
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Max-Age=3600"));
    }

    // ================================================================
    // SessionLayer builder
    // ================================================================

    #[test]
    fn session_layer_builder() {
        let layer = SessionLayer::new(MemoryStore::new())
            .cookie_name("my_session")
            .cookie_path("/app")
            .http_only(false)
            .secure(true)
            .same_site(SameSite::None)
            .max_age(7200);

        assert_eq!(layer.config.cookie_name, "my_session");
        assert_eq!(layer.config.cookie_path, "/app");
        assert!(!layer.config.http_only);
        assert!(layer.config.secure);
        assert_eq!(layer.config.same_site, SameSite::None);
        assert_eq!(layer.config.max_age, Some(7200));
    }

    #[test]
    fn session_layer_debug() {
        let layer = SessionLayer::new(MemoryStore::new());
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("SessionLayer"));
    }

    // ================================================================
    // Middleware integration
    // ================================================================

    /// A simple echo handler that reads/writes session data.
    struct TestHandler;

    impl Handler for TestHandler {
        fn call(&self, req: Request) -> Response {
            // Try to get session from extensions.
            req.extensions.get_typed::<Session>().map_or_else(
                || Response::new(StatusCode::OK, b"no session".to_vec()),
                |session| {
                    let count = session
                        .get("count")
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(0);
                    session.insert("count", (count + 1).to_string());
                    let body = format!("count={}", count + 1);
                    Response::new(StatusCode::OK, body.into_bytes())
                },
            )
        }
    }

    #[test]
    fn middleware_creates_session_on_first_request() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(TestHandler);

        let req = Request::new("GET", "/");
        let resp = handler.call(req);

        assert_eq!(resp.status, StatusCode::OK);
        assert!(resp.headers.contains_key("set-cookie"));
        let cookie = resp.headers.get("set-cookie").unwrap();
        assert!(cookie.contains("session_id="));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn middleware_loads_existing_session() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store);
        let handler = layer.wrap(TestHandler);

        // First request — creates session.
        let req1 = Request::new("GET", "/");
        let resp1 = handler.call(req1);
        let cookie_header = resp1.headers.get("set-cookie").unwrap().clone();

        // Extract session ID from Set-Cookie.
        let session_id = cookie_header
            .split('=')
            .nth(1)
            .unwrap()
            .split(';')
            .next()
            .unwrap();

        // Second request with session cookie.
        let mut req2 = Request::new("GET", "/");
        req2.headers
            .insert("cookie".to_string(), format!("session_id={session_id}"));
        let resp2 = handler.call(req2);
        let body2 = std::str::from_utf8(&resp2.body).unwrap();
        assert_eq!(body2, "count=2");
    }

    #[test]
    fn middleware_invalid_session_id_creates_new() {
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(TestHandler);

        let mut req = Request::new("GET", "/");
        req.headers
            .insert("cookie".to_string(), "session_id=bad!".to_string());
        let resp = handler.call(req);

        assert!(resp.headers.contains_key("set-cookie"));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn middleware_fixation_unknown_id_regenerated() {
        // Regression: an attacker-supplied valid-format ID that is not in the
        // store must NOT be accepted — a fresh ID must be generated.
        let store = MemoryStore::new();
        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(TestHandler);

        let fake_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"; // valid format, not in store
        let mut req = Request::new("GET", "/");
        req.headers
            .insert("cookie".to_string(), format!("session_id={fake_id}"));
        let resp = handler.call(req);

        // The response must set a NEW session cookie, not reuse the attacker's ID.
        let cookie = resp.headers.get("set-cookie").unwrap();
        assert!(
            !cookie.contains(fake_id),
            "must not reuse attacker-supplied ID"
        );
        assert_eq!(store.len(), 1);
    }

    /// br-asupersync-hifab2: end-to-end session-fixation defence.
    ///
    /// A handler that calls `Session::regenerate()` (the OWASP-mandated
    /// post-login action) MUST cause the middleware to:
    ///   1. issue a NEW session ID in Set-Cookie (different from the
    ///      inbound cookie),
    ///   2. DELETE the old server-side store entry (so the
    ///      pre-authentication ID an attacker might have planted via
    ///      session-fixation can't be replayed), and
    ///   3. PRESERVE the user's session data under the new ID (so the
    ///      authenticated state survives the rotation).
    ///
    /// Without these three properties, an attacker can plant a chosen
    /// session ID on a victim, wait for them to log in, and then hijack
    /// the now-authenticated session by reusing the planted ID.
    #[test]
    fn middleware_regenerate_rotates_id_and_preserves_data() {
        struct LoginHandler;
        impl Handler for LoginHandler {
            fn call(&self, req: Request) -> Response {
                if let Some(session) = req.extensions.get_typed::<Session>() {
                    // Simulate a successful login: stash an authenticated
                    // user_id and rotate the session ID.
                    session.insert("user_id", "alice");
                    session.regenerate();
                }
                Response::new(StatusCode::OK, b"logged in".to_vec())
            }
        }

        let store = MemoryStore::new();
        // Seed a pre-auth session that the attacker might have planted.
        let attacker_planted_id = "1234567890abcdef1234567890abcdef";
        let mut pre_auth = SessionData::new();
        pre_auth.insert("pre_auth_marker", "still here");
        store.save(attacker_planted_id, &pre_auth);

        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(LoginHandler);

        // Victim arrives with the attacker's planted cookie and "logs in".
        let mut req = Request::new("POST", "/login");
        req.headers.insert(
            "cookie".to_string(),
            format!("session_id={attacker_planted_id}"),
        );
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);

        // Property 1: response carries a NEW session-id cookie that is
        // NOT the attacker-planted one.
        let cookie = resp
            .headers
            .get("set-cookie")
            .expect("middleware must issue Set-Cookie after regenerate");
        assert!(
            !cookie.contains(attacker_planted_id),
            "middleware reused the attacker's planted ID after regenerate(); fixation is OPEN. Set-Cookie: {cookie}"
        );
        let new_id = cookie
            .split('=')
            .nth(1)
            .expect("malformed Set-Cookie")
            .split(';')
            .next()
            .expect("missing cookie value")
            .to_string();
        assert_ne!(
            new_id, attacker_planted_id,
            "regenerate() did not actually rotate the ID"
        );
        assert_eq!(new_id.len(), 32, "new ID must be 32-char hex");

        // Property 2: old server-side store entry is GONE.
        assert!(
            store.load(attacker_planted_id).is_none(),
            "old session id must be deleted from store after regenerate()"
        );

        // Property 3: session data was PRESERVED under the new ID.
        let migrated = store
            .load(&new_id)
            .expect("new session id must be persisted");
        assert_eq!(
            migrated.get("user_id"),
            Some("alice"),
            "post-login user_id was not preserved across regenerate()"
        );

        // Defense in depth: the regenerate flag must NOT have leaked
        // into the saved session data (it's an internal marker).
        assert!(
            migrated.get(REGENERATE_FLAG_KEY).is_none(),
            "REGENERATE_FLAG_KEY leaked into persisted session data"
        );
    }

    #[test]
    fn middleware_clear_session_expires_cookie() {
        // Regression: clearing a session must expire the cookie (Max-Age=0),
        // not re-set it with the same ID.
        struct ClearHandler;
        impl Handler for ClearHandler {
            fn call(&self, req: Request) -> Response {
                if let Some(session) = req.extensions.get_typed::<Session>() {
                    session.insert("data", "value"); // ensure non-empty first
                    session.clear();
                }
                Response::new(StatusCode::OK, b"cleared".to_vec())
            }
        }

        let store = MemoryStore::new();
        // Seed a session in the store.
        let mut seed = SessionData::new();
        seed.insert("data", "value");
        store.save("abcdef01234567890abcdef012345678", &seed);

        let layer = SessionLayer::new(store.clone());
        let handler = layer.wrap(ClearHandler);

        let mut req = Request::new("GET", "/");
        req.headers.insert(
            "cookie".to_string(),
            "session_id=abcdef01234567890abcdef012345678".to_string(),
        );
        let resp = handler.call(req);
        let cookie = resp.headers.get("set-cookie").unwrap();
        assert!(
            cookie.contains("Max-Age=0"),
            "cookie must be expired on clear"
        );
        assert!(store.is_empty(), "server-side data must be deleted");
    }

    #[test]
    fn generate_id_uses_crypto_randomness() {
        // Verify 16 bytes of entropy → 32 hex chars, all unique.
        let ids: Vec<String> = (0..100).map(|_| generate_session_id()).collect();
        for id in &ids {
            assert!(is_valid_session_id(id));
        }
        // All 100 must be unique (probability of collision is negligible).
        let set: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(set.len(), 100);
    }

    // ================================================================
    // Session handle
    // ================================================================

    #[test]
    fn session_handle_operations() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        session.insert("key", "value");
        assert!(session.contains("key"));
        assert_eq!(session.get("key"), Some("value".to_string()));

        let _ = session.remove("key");
        assert!(!session.contains("key"));
    }

    #[test]
    fn session_handle_clear() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        session.insert("a", "1");
        session.insert("b", "2");
        session.clear();
        assert!(!session.contains("a"));
    }

    #[test]
    fn session_handle_debug() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        let dbg = format!("{session:?}");
        assert!(dbg.contains("Session"));
    }

    // ================================================================
    // SameSite
    // ================================================================

    #[test]
    fn same_site_variants() {
        let config_none = SessionConfig {
            same_site: SameSite::None,
            ..Default::default()
        };
        let header = set_cookie_header("s", "v", &config_none);
        assert!(header.contains("SameSite=None"));
    }

    // ================================================================
    // br-asupersync-uz7oxb — set_cookie_header injection guard
    // ================================================================

    #[test]
    #[should_panic(expected = "br-asupersync-uz7oxb")]
    fn cookie_name_with_semicolon_panics() {
        let cfg = SessionConfig::default();
        let _ = set_cookie_header("evil; HttpOnly=false; X", "v", &cfg);
    }

    #[test]
    #[should_panic(expected = "br-asupersync-uz7oxb")]
    fn cookie_value_with_semicolon_panics() {
        let cfg = SessionConfig::default();
        let _ = set_cookie_header("s", "v; Domain=attacker.com", &cfg);
    }

    #[test]
    #[should_panic(expected = "br-asupersync-uz7oxb")]
    fn cookie_path_with_crlf_panics() {
        let cfg = SessionConfig {
            cookie_path: "/foo\r\nX-Injected: 1".to_string(),
            ..Default::default()
        };
        let _ = set_cookie_header("s", "v", &cfg);
    }

    #[test]
    fn cookie_helper_accepts_safe_inputs() {
        let cfg = SessionConfig::default();
        let h = set_cookie_header("session", "abcd1234", &cfg);
        assert!(h.starts_with("session=abcd1234; Path=/"));
    }

    // ================================================================
    // br-asupersync-3cvnmo — CSRF token rotation
    // ================================================================

    #[test]
    fn rotate_csrf_token_changes_token() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        // Seed an initial token.
        session.insert(CSRF_TOKEN_KEY, "old-token");
        let new = session.rotate_csrf_token();
        assert_ne!(new, "old-token");
        assert_eq!(session.csrf_token().as_deref(), Some(new.as_str()));
    }

    #[test]
    fn regenerate_rotates_csrf_and_sets_flag() {
        let session = Session(Arc::new(Mutex::new(SessionData::new())));
        session.insert(CSRF_TOKEN_KEY, "old-token");
        session.regenerate();
        let inner = session.0.lock();
        assert!(inner.get(REGENERATE_FLAG_KEY).is_some());
        let new_csrf = inner.get(CSRF_TOKEN_KEY).unwrap();
        assert_ne!(new_csrf, "old-token");
    }

    // ================================================================
    // br-asupersync-czbj90 — Origin/Referer extraction + allow-list
    // ================================================================

    #[test]
    fn referer_origin_strips_path() {
        // Origin absent; Referer present with path component.
        let req = Request {
            method: crate::http::Method::POST,
            uri: "/api/x".to_string(),
            version: crate::http::Version::HTTP_1_1,
            headers: vec![(
                "Referer".to_string(),
                "https://app.example.com/foo/bar?q=1".to_string(),
            )],
            body: crate::bytes::Bytes::new(),
            extensions: crate::web::Extensions::new(),
        };
        let origin = request_origin(&req);
        assert_eq!(origin.as_deref(), Some("https://app.example.com"));
    }

    #[test]
    fn origin_allow_list_match_is_case_insensitive_and_trim_slash() {
        let allowed = vec!["https://App.Example.Com/".to_string()];
        assert!(origin_is_allowed("https://app.example.com", &allowed));
        assert!(origin_is_allowed("HTTPS://APP.EXAMPLE.COM", &allowed));
        assert!(!origin_is_allowed("https://attacker.com", &allowed));
    }

    #[test]
    fn origin_header_takes_precedence_over_referer() {
        let req = Request {
            method: crate::http::Method::POST,
            uri: "/api/x".to_string(),
            version: crate::http::Version::HTTP_1_1,
            headers: vec![
                ("Origin".to_string(), "https://app.example.com".to_string()),
                (
                    "Referer".to_string(),
                    "https://other.example.com/".to_string(),
                ),
            ],
            body: crate::bytes::Bytes::new(),
            extensions: crate::web::Extensions::new(),
        };
        assert_eq!(
            request_origin(&req).as_deref(),
            Some("https://app.example.com")
        );
    }

    #[test]
    fn null_origin_falls_back_to_referer() {
        let req = Request {
            method: crate::http::Method::POST,
            uri: "/api/x".to_string(),
            version: crate::http::Version::HTTP_1_1,
            headers: vec![
                ("Origin".to_string(), "null".to_string()),
                (
                    "Referer".to_string(),
                    "https://app.example.com/foo".to_string(),
                ),
            ],
            body: crate::bytes::Bytes::new(),
            extensions: crate::web::Extensions::new(),
        };
        assert_eq!(
            request_origin(&req).as_deref(),
            Some("https://app.example.com")
        );
    }
}
