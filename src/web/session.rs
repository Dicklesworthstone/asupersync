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
use std::collections::{BTreeSet, HashMap};
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

/// Reserved key under which the session's original creation time is stored.
/// Unlike [`LAST_ACCESSED_KEY`], this timestamp is preserved across ordinary
/// requests and ID regeneration so an absolute server-side TTL cannot be
/// extended indefinitely by activity.
const CREATED_AT_KEY: &str = "__asupersync.created_at_unix_secs";

/// br-asupersync-hifab2 — Reserved key set by [`Session::regenerate`] to
/// signal the middleware that the session ID must be rotated at response
/// time. The middleware deletes the old store entry, mints a fresh ID,
/// saves the data under the new ID, and emits a new Set-Cookie. This
/// prevents session fixation: if an attacker primes the victim's browser
/// with a known session ID and then waits for the victim to authenticate,
/// rotating on auth boundary makes the captured ID worthless.
const REGENERATE_FLAG_KEY: &str = "__asupersync.regenerate";
/// The `REGENERATE_FLAG_KEY` value `SessionData::clear` leaves behind.
const REGENERATE_AFTER_CLEAR: &str = "cleared";

/// br-asupersync-qokau8 / br-asupersync-z74jcy — fail-closed finalizer
/// for session-ID rotation that runs on the cancel/panic path.
///
/// The hifab2 regenerate protocol relies on the middleware reading
/// `REGENERATE_FLAG_KEY` back from the shared session_data AFTER the
/// handler returns and then deleting the OLD store entry + minting a
/// fresh ID. If the handler unwinds (panics, or — in a future async
/// extension of this Handler trait — is cancelled) between calling
/// `Session::regenerate()` and returning, the middleware never
/// executes that step. The OLD session ID stays live in the store,
/// defeating the session-fixation defense the rotation was supposed
/// to provide.
///
/// `RegenerateGuard` captures the store reference, the OLD session
/// ID, and a handle on the shared `SessionData`. On the happy path
/// the middleware reaches the explicit regenerate-processing block
/// and `disarm()`s the guard; the `Drop` impl then becomes a no-op.
/// On any unwinding path the guard's `Drop` runs, inspects the
/// shared `SessionData` under lock for `REGENERATE_FLAG_KEY`, and
/// if the flag is set it FAILS CLOSED: the OLD store entry is
/// deleted, invalidating the session server-side. The client's
/// cookie still references the OLD ID but the store no longer
/// recognises it, so the next request mints a fresh session and any
/// session-fixation attempt is foiled.
///
/// `parking_lot::Mutex` is used here (matching the rest of the file),
/// which does NOT poison on panic, so the lock acquisition inside
/// the Drop impl is safe even when the panic happened while the
/// handler held the lock.
struct RegenerateGuard<'a, S: SessionStore + ?Sized> {
    /// `true` until the middleware reaches its happy-path regenerate
    /// processing and calls [`Self::disarm`]. While armed, `Drop`
    /// runs the fail-closed path.
    armed: bool,
    /// Borrow of the configured session store. The lifetime ties the
    /// guard to the middleware's `&self` borrow, which outlives the
    /// inner handler call.
    store: &'a S,
    /// Shared session data (also seen by the handler). Inspected
    /// under lock during fail-closed processing to detect a pending
    /// `REGENERATE_FLAG_KEY`.
    session_handle: Arc<Mutex<SessionData>>,
    /// The session ID that was passed to the handler. If the handler
    /// requested rotation and then unwound, this is the ID that
    /// must be invalidated server-side.
    session_id: String,
    /// `true` if the session was newly minted on this request (no
    /// existing store entry to delete on the fail-closed path).
    is_new: bool,
}

impl<S: SessionStore + ?Sized> RegenerateGuard<'_, S> {
    /// Disarm the guard. Called from the happy-path branch of the
    /// middleware AFTER the handler has returned and the explicit
    /// regenerate processing has taken responsibility for the
    /// rotation. Once disarmed, `Drop` is a no-op.
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<S: SessionStore + ?Sized> Drop for RegenerateGuard<'_, S> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Cancel/panic path: the handler did not give the middleware
        // a chance to rotate. Fail closed by invalidating the OLD
        // session server-side if a rotation was in fact requested.
        let regenerate_requested = {
            let guard = self.session_handle.lock();
            guard.get(REGENERATE_FLAG_KEY).is_some()
        };
        if regenerate_requested && !self.is_new {
            if std::thread::panicking() {
                // Avoid aborting the process with a double panic while preserving
                // the original handler failure. Outside unwind, let store.delete
                // panics surface: hiding a normal-path invalidation failure would
                // make session rotation look safer than it was.
                let _delete_outcome =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        self.store.delete(&self.session_id);
                    }));
            } else {
                self.store.delete(&self.session_id);
            }
        }
    }
}

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
        .map_or(0, |d| d.as_secs())
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
    ///
    /// A pending [`Session::regenerate`] request survives, marked as
    /// followed by a clear: it is the middleware's rotation state, not
    /// session data. `regenerate()` followed by `clear()`, the documented
    /// logout sequence, used to drop it, so a handler that then panicked or
    /// was cancelled left the old, logged-in entry valid in the store
    /// (br-asupersync-a1q12q). On the normal path such a session still ends
    /// like any cleared one: its entry is deleted and its cookie expired.
    pub fn clear(&mut self) {
        self.modified = true;
        let regenerate = self.values.remove(REGENERATE_FLAG_KEY).is_some();
        self.values.clear();
        if regenerate {
            self.values.insert(
                REGENERATE_FLAG_KEY.to_string(),
                REGENERATE_AFTER_CLEAR.to_string(),
            );
        }
    }
}

// ─── MemoryStore ────────────────────────────────────────────────────────────

/// In-memory session store. Data is lost on process restart.
///
/// Suitable for development and single-process deployments. [`Self::new`]
/// remains unbounded for backwards compatibility; use
/// [`Self::with_max_sessions`] when memory residency must be capped.
#[derive(Clone, Default)]
pub struct MemoryStore {
    state: Arc<Mutex<MemoryStoreState>>,
}

#[derive(Default)]
struct MemoryStoreState {
    sessions: HashMap<String, SessionData>,
    access_order: BTreeSet<(u64, String)>,
    max_sessions: Option<usize>,
}

impl MemoryStore {
    /// Create a new empty memory store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MemoryStoreState::default())),
        }
    }

    /// Create an empty memory store capped at `max_sessions` entries.
    ///
    /// Saving a new session at capacity evicts the least recently accessed
    /// entry according to the middleware's server-side timestamp, with the
    /// session ID as a deterministic tie-breaker. Updating an existing entry
    /// never evicts another session.
    ///
    /// # Panics
    ///
    /// Panics when `max_sessions` is zero.
    #[must_use]
    pub fn with_max_sessions(max_sessions: usize) -> Self {
        assert!(max_sessions > 0, "max_sessions must be greater than zero");
        Self {
            state: Arc::new(Mutex::new(MemoryStoreState {
                sessions: HashMap::new(),
                access_order: BTreeSet::new(),
                max_sessions: Some(max_sessions),
            })),
        }
    }

    /// Number of active sessions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.state.lock().sessions.len()
    }

    /// Returns `true` if there are no sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.state.lock().sessions.is_empty()
    }
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        let mut debug = f.debug_struct("MemoryStore");
        debug.field("sessions", &state.sessions.len());
        if let Some(max_sessions) = state.max_sessions {
            debug.field("max_sessions", &max_sessions);
        }
        debug.finish()
    }
}

impl SessionStore for MemoryStore {
    fn load(&self, id: &str) -> Option<SessionData> {
        self.state.lock().sessions.get(id).cloned()
    }

    fn save(&self, id: &str, data: &SessionData) {
        let mut stored = data.clone();
        // Reset modified flag so reloaded sessions don't appear pre-modified,
        // which would cause unnecessary re-saves and Set-Cookie headers.
        stored.modified = false;
        let mut state = self.state.lock();
        if state.max_sessions.is_some() {
            let old_ts = state.sessions.get(id).map(session_last_accessed);
            if let Some(old_ts) = old_ts {
                state.access_order.remove(&(old_ts, id.to_string()));
            } else if state
                .max_sessions
                .is_some_and(|max_sessions| state.sessions.len() >= max_sessions)
            {
                if let Some((_, evicted_id)) = state.access_order.pop_first() {
                    state.sessions.remove(&evicted_id);
                }
            }
            let ts = session_last_accessed(&stored);
            state.access_order.insert((ts, id.to_string()));
        }
        state.sessions.insert(id.to_string(), stored);
    }

    fn delete(&self, id: &str) {
        let mut state = self.state.lock();
        if let Some(data) = state.sessions.remove(id) {
            if state.max_sessions.is_some() {
                state
                    .access_order
                    .remove(&(session_last_accessed(&data), id.to_string()));
            }
        }
    }
}

fn session_last_accessed(data: &SessionData) -> u64 {
    data.get(LAST_ACCESSED_KEY)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

// ─── Session ID generation ──────────────────────────────────────────────────

/// Generate a cryptographically random session ID (16 random bytes as hex).
/// Returns `None` if OS entropy source is unavailable.
fn generate_session_id() -> Option<String> {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).ok()?;
    let mut hex = String::with_capacity(32);
    for b in &buf {
        let _ = write!(hex, "{b:02x}");
    }
    Some(hex)
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
    /// stored under `CSRF_TOKEN_KEY` inside `SessionData`, and must be
    /// supplied by the client as the `X-CSRF-Token` request header.
    /// **Default: `true`.** (br-asupersync-7udumi)
    ///
    /// The token is checked only for requests that carry a stored session.
    /// A state-changing request without one (a login form posted
    /// cross-site) is not checked; set [`Self::allowed_origins`] so its
    /// `Origin` is (br-asupersync-a1q12q).
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
    absolute_ttl_seconds: Option<u64>,
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
            absolute_ttl_seconds: None,
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

    /// Set the absolute server-side session TTL in seconds.
    ///
    /// Unlike [`Self::idle_ttl_seconds`], activity does not extend this
    /// lifetime. ID regeneration also preserves the original creation time.
    #[must_use]
    pub const fn absolute_ttl_seconds(mut self, seconds: u64) -> Self {
        self.absolute_ttl_seconds = Some(seconds);
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
            absolute_ttl_seconds: self.absolute_ttl_seconds,
        }
    }
}

// Unified layering (br-asupersync-server-stack-hardening-eeexl1.3): the
// session layer composes through the same `service::Layer` trait as the rest
// of the web middleware, so it works with `Router::layer` and
// `MiddlewareStack::layer`. The store is `Arc`-shared, so one layer value
// applied across a router's routes shares ONE session store — exactly the
// semantics sessions need.
impl<S: SessionStore, H: Handler> crate::service::Layer<H> for SessionLayer<S> {
    type Service = SessionMiddleware<S, H>;

    fn layer(&self, inner: H) -> Self::Service {
        // Same validation gate as `wrap`.
        self.config
            .validate()
            .expect("SessionConfig validation failed before wrap");
        SessionMiddleware {
            inner,
            store: Arc::clone(&self.store),
            config: self.config.clone(),
            absolute_ttl_seconds: self.absolute_ttl_seconds,
        }
    }
}

impl<S: SessionStore> fmt::Debug for SessionLayer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionLayer")
            .field("config", &self.config)
            .field("absolute_ttl_seconds", &self.absolute_ttl_seconds)
            .finish_non_exhaustive()
    }
}

// ─── SessionMiddleware ──────────────────────────────────────────────────────

/// The actual middleware that wraps a handler.
pub struct SessionMiddleware<S: SessionStore, H: Handler> {
    inner: H,
    store: Arc<S>,
    config: SessionConfig,
    absolute_ttl_seconds: Option<u64>,
}

impl<S: SessionStore, H: Handler> Handler for SessionMiddleware<S, H> {
    fn call(
        &self,
        cx: &crate::Cx,
        mut req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        Box::pin(async move {
            // 1. Extract or generate session ID.
            //    If the client-supplied ID is syntactically valid but absent from the
            //    store, regenerate to prevent session-fixation attacks (an attacker
            //    could plant a chosen ID and later hijack it).
            let (mut session_id, mut is_new) = match get_cookie(&req, &self.config.cookie_name) {
                Some(id) if is_valid_session_id(&id) => (id, false),
                _ => {
                    let Some(id) = generate_session_id() else {
                        return Response::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Session initialization failed: OS entropy unavailable".to_string(),
                        );
                    };
                    (id, true)
                }
            };

            // 2. Load existing session data.
            //    If the client-supplied ID is not in the store, regenerate to
            //    prevent session-fixation attacks. Also: if an idle or
            //    absolute TTL is configured and elapsed, server-side delete
            //    + new id (br-asupersync-7udumi, br-asupersync-ne8jdw).
            let mut session_data = if is_new {
                SessionData::new()
            } else if let Some(data) = self.store.load(&session_id) {
                if self.is_idle_expired(&data) || self.is_absolute_expired(&data) {
                    self.store.delete(&session_id);
                    let Some(new_id) = generate_session_id() else {
                        return Response::new(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Session renewal failed: OS entropy unavailable".to_string(),
                        );
                    };
                    session_id = new_id;
                    is_new = true;
                    SessionData::new()
                } else {
                    data
                }
            } else {
                let Some(new_id) = generate_session_id() else {
                    return Response::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Session creation failed: OS entropy unavailable".to_string(),
                    );
                };
                session_id = new_id;
                is_new = true;
                SessionData::new()
            };

            // 2b. Touch existing sessions only. Brand-new, otherwise
            //     untouched safe requests must not allocate a backing store
            //     entry or emit a cookie; handlers that actually use the
            //     session will mark it modified below. (br-asupersync-7udumi)
            if !is_new {
                session_data.insert(LAST_ACCESSED_KEY, now_unix_secs().to_string());
            }

            // 2c. Ensure existing sessions have a CSRF token. New sessions
            //     mint one lazily from Session::csrf_token() or
            //     rotate_csrf_token(), avoiding empty-request allocation.
            //     (br-asupersync-7udumi)
            if !is_new && self.config.csrf_protection && session_data.get(CSRF_TOKEN_KEY).is_none()
            {
                let Some(csrf_token) = generate_session_id() else {
                    return Response::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "CSRF token generation failed: OS entropy unavailable".to_string(),
                    );
                };
                session_data.insert(CSRF_TOKEN_KEY, csrf_token);
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
                        .map_or("", |(_, v)| v.as_str());
                    let session_token = session_data.get(CSRF_TOKEN_KEY).unwrap_or("");
                    if !constant_time_eq_str(header_token, session_token)
                        || session_token.is_empty()
                    {
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

            // br-asupersync-qokau8 / br-asupersync-z74jcy — install a
            // fail-closed regenerate finalizer BEFORE the handler runs.
            // If the handler unwinds (panic, or future async cancel)
            // before we reach step 5b, the guard's `Drop` deletes the
            // OLD store entry whenever `REGENERATE_FLAG_KEY` is set,
            // preserving the session-fixation defense even on the
            // cancel path. On the happy path we `disarm()` the guard
            // once the explicit rotation logic has run.
            let mut regenerate_guard = RegenerateGuard {
                armed: true,
                store: self.store.as_ref(),
                session_handle: Arc::clone(&session_handle),
                session_id: session_id.clone(),
                is_new,
            };

            // 4. Call inner handler.
            let mut resp = self.inner.call(&cx, req).await;

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
            let marker = session_data.get(REGENERATE_FLAG_KEY).map(str::to_owned);
            let regenerate_requested = marker.is_some();
            if regenerate_requested {
                // remove() marks the data modified; only a marked session is.
                session_data.remove(REGENERATE_FLAG_KEY);
            }
            // regenerate() then clear(), the documented logout, leaves the
            // marker as REGENERATE_AFTER_CLEAR so the failure guard can still
            // delete the old entry. With nothing stored after the clear, the
            // session ends like any cleared one below (entry deleted, cookie
            // expired) instead of rotating into a fresh, empty session.
            let logout =
                marker.as_deref() == Some(REGENERATE_AFTER_CLEAR) && session_data.is_empty();
            if regenerate_requested && !logout {
                if !is_new {
                    self.store.delete(&session_id);
                }
                let Some(new_id) = generate_session_id() else {
                    return Response::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Session regeneration failed: OS entropy unavailable".to_string(),
                    );
                };
                session_id = new_id;
                // Treat as a freshly-issued cookie (must be Set-Cookie'd to
                // the client); the old client cookie is implicitly replaced
                // by the new one in the response.
                is_new = true;
                // Force the modified flag so the save+cookie branches fire.
                session_data.insert(LAST_ACCESSED_KEY, now_unix_secs().to_string());
            }
            // br-asupersync-qokau8: explicit rotation path has now taken
            // responsibility for the regenerate flag. Disarm the
            // fail-closed finalizer so its Drop is a no-op.
            regenerate_guard.disarm();

            // 6. Save if modified. Untouched new sessions are NOT saved to prevent DoS.
            let session_cleared = session_data.is_empty() && session_data.is_modified();
            let should_save_session =
                !session_cleared && (session_data.is_modified() || regenerate_requested);

            if session_cleared {
                if !is_new {
                    // Session cleared → delete server-side data and expire the cookie.
                    self.store.delete(&session_id);
                }
            } else if should_save_session {
                if session_data.get(CREATED_AT_KEY).is_none() {
                    session_data.insert(CREATED_AT_KEY, now_unix_secs().to_string());
                }
                session_data.insert(LAST_ACCESSED_KEY, now_unix_secs().to_string());
                self.store.save(&session_id, &session_data);
            }

            // 7. Set cookie on modified sessions, or expire if cleared.
            //    br-asupersync-ehtkns: append rather than set so any
            //    Set-Cookie the inner handler emitted (CSRF cookie,
            //    remember-me, post-login flash) survives the middleware
            //    layer instead of being overwritten by the session cookie.
            if session_cleared {
                if !is_new {
                    // Expire the cookie so the browser deletes it.
                    // Reuse set_cookie_header to ensure all configured attributes
                    // (Secure, SameSite, HttpOnly) are included — omitting them
                    // could leave a stale session cookie in the browser.
                    let mut expire_config = self.config.clone();
                    expire_config.max_age = Some(0);
                    let cookie_val =
                        set_cookie_header(&self.config.cookie_name, "", &expire_config);
                    resp.append_set_cookie(cookie_val);
                }
            } else if should_save_session {
                let cookie_val =
                    set_cookie_header(&self.config.cookie_name, &session_id, &self.config);
                resp.append_set_cookie(cookie_val);
            }

            resp
        })
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

    /// Returns true if the configured absolute TTL has elapsed since the
    /// session's original creation timestamp. Pre-ne8jdw sessions without the
    /// timestamp are admitted once and stamped on the following save.
    fn is_absolute_expired(&self, data: &SessionData) -> bool {
        let Some(ttl) = self.absolute_ttl_seconds else {
            return false;
        };
        let Some(created_at) = data
            .get(CREATED_AT_KEY)
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return false;
        };
        now_unix_secs().saturating_sub(created_at) > ttl
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
        let mut guard = self.0.lock();
        if let Some(token) = guard.get(CSRF_TOKEN_KEY) {
            return Some(token.to_string());
        }
        let token = generate_session_id()?;
        guard.insert(CSRF_TOKEN_KEY, token.clone());
        Some(token)
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
    /// `regenerate()`. Returns `None` if OS entropy is unavailable.
    pub fn regenerate(&self) -> Option<()> {
        let mut guard = self.0.lock();
        guard.insert(REGENERATE_FLAG_KEY, "1");
        // Rotate CSRF token alongside ID — a session ID rotation that
        // doesn't rotate the bound CSRF token leaves a trust-boundary
        // hole. (br-asupersync-3cvnmo)
        let csrf_token = generate_session_id()?;
        guard.insert(CSRF_TOKEN_KEY, csrf_token);
        Some(())
    }

    /// br-asupersync-3cvnmo — Mint a fresh CSRF token for this session
    /// without rotating the session ID. Use this for periodic in-session
    /// rotation (e.g. on a per-N-request or per-time-window policy)
    /// where a full ID rotation is not warranted. The new token is
    /// returned to the caller so the response can echo it to the client
    /// before the old one becomes invalid.
    ///
    /// Most callers should prefer [`Self::regenerate`], which rotates
    /// both ID and CSRF in lockstep. Returns `None` if OS entropy is unavailable.
    pub fn rotate_csrf_token(&self) -> Option<String> {
        let token = generate_session_id()?;
        self.0.lock().insert(CSRF_TOKEN_KEY, token.clone());
        Some(token)
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
#[path = "session_inline_tests.rs"]
mod tests;
