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

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use super::extract::Request;
use super::handler::Handler;
use super::response::Response;

/// Default session cookie name.
const DEFAULT_COOKIE_NAME: &str = "session_id";

/// Session ID length in hex characters (16 bytes = 32 hex chars).
const SESSION_ID_HEX_LEN: usize = 32;

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
#[derive(Clone)]
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
        self.sessions.lock().unwrap().len()
    }

    /// Returns `true` if there are no sessions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.lock().unwrap().is_empty()
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let count = self.sessions.lock().unwrap().len();
        f.debug_struct("MemoryStore")
            .field("sessions", &count)
            .finish()
    }
}

impl SessionStore for MemoryStore {
    fn load(&self, id: &str) -> Option<SessionData> {
        self.sessions.lock().unwrap().get(id).cloned()
    }

    fn save(&self, id: &str, data: &SessionData) {
        self.sessions
            .lock()
            .unwrap()
            .insert(id.to_string(), data.clone());
    }

    fn delete(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }
}

// ─── Session ID generation ──────────────────────────────────────────────────

/// Generate a random session ID (16 random bytes as hex).
fn generate_session_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::UNIX_EPOCH
            .elapsed()
            .unwrap_or_default()
            .as_nanos() as u64,
    );
    let h1 = hasher.finish();

    let state2 = RandomState::new();
    let mut hasher2 = state2.build_hasher();
    hasher2.write_u64(h1.wrapping_mul(6_364_136_223_846_793_005));
    let h2 = hasher2.finish();

    format!("{h1:016x}{h2:016x}")
}

/// Validate that a session ID looks legitimate (hex, correct length).
fn is_valid_session_id(id: &str) -> bool {
    id.len() == SESSION_ID_HEX_LEN && id.bytes().all(|b| b.is_ascii_hexdigit())
}

// ─── Cookie parsing helpers ─────────────────────────────────────────────────

/// Extract a cookie value from the Cookie header.
fn get_cookie(req: &Request, name: &str) -> Option<String> {
    let header = req.headers.get("cookie")?;
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

/// Build a Set-Cookie header value.
fn set_cookie_header(name: &str, value: &str, config: &SessionConfig) -> String {
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

/// Session cookie configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Name of the session cookie.
    pub cookie_name: String,
    /// Cookie `Path` attribute.
    pub cookie_path: String,
    /// Cookie `HttpOnly` attribute.
    pub http_only: bool,
    /// Cookie `Secure` attribute.
    pub secure: bool,
    /// Cookie `SameSite` attribute.
    pub same_site: SameSite,
    /// Optional cookie `Max-Age` in seconds.
    pub max_age: Option<u64>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            cookie_name: DEFAULT_COOKIE_NAME.to_string(),
            cookie_path: "/".to_string(),
            http_only: true,
            secure: false,
            same_site: SameSite::Lax,
            max_age: None,
        }
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
    pub fn new(store: S) -> Self {
        Self {
            store: Arc::new(store),
            config: SessionConfig::default(),
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
    #[must_use]
    pub fn same_site(mut self, value: SameSite) -> Self {
        self.config.same_site = value;
        self
    }

    /// Set Max-Age in seconds.
    #[must_use]
    pub fn max_age(mut self, seconds: u64) -> Self {
        self.config.max_age = Some(seconds);
        self
    }

    /// Wrap a handler with session management.
    pub fn wrap<H: Handler>(self, inner: H) -> SessionMiddleware<S, H> {
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
        let (session_id, is_new) = match get_cookie(&req, &self.config.cookie_name) {
            Some(id) if is_valid_session_id(&id) => (id, false),
            _ => (generate_session_id(), true),
        };

        // 2. Load existing session data.
        let mut session_data = if is_new {
            SessionData::new()
        } else {
            self.store.load(&session_id).unwrap_or_default()
        };

        // 3. Inject session data into request extensions.
        //    We use a shared Arc<Mutex<SessionData>> so the handler can modify it.
        let session_handle = Arc::new(Mutex::new(session_data.clone()));
        req.extensions
            .insert_typed(Session(Arc::clone(&session_handle)));

        // 4. Call inner handler.
        let mut resp = self.inner.call(req);

        // 5. Extract (possibly modified) session data.
        session_data = {
            let guard = session_handle.lock().unwrap();
            guard.clone()
        };

        // 6. Save if modified or new.
        if session_data.is_modified() || is_new {
            if session_data.is_empty() && !is_new {
                // Session cleared → delete.
                self.store.delete(&session_id);
            } else {
                self.store.save(&session_id, &session_data);
            }
        }

        // 7. Set cookie on new sessions or modified sessions.
        if is_new || session_data.is_modified() {
            let cookie_val = set_cookie_header(&self.config.cookie_name, &session_id, &self.config);
            resp.headers.insert("set-cookie".to_string(), cookie_val);
        }

        resp
    }
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
        self.0.lock().unwrap().get(key).map(ToString::to_string)
    }

    /// Insert a value into the session.
    pub fn insert(&self, key: impl Into<String>, value: impl Into<String>) {
        self.0.lock().unwrap().insert(key, value);
    }

    /// Remove a value from the session.
    #[must_use]
    pub fn remove(&self, key: &str) -> Option<String> {
        self.0.lock().unwrap().remove(key)
    }

    /// Clear all session data.
    pub fn clear(&self) {
        self.0.lock().unwrap().clear();
    }

    /// Check if a key exists.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.0.lock().unwrap().get(key).is_some()
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.0.lock().unwrap();
        f.debug_struct("Session")
            .field("len", &data.len())
            .field("modified", &data.is_modified())
            .finish()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
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
        keys.sort();
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
        let _cloned = store.clone();
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
            if let Some(session) = req.extensions.get_typed::<Session>() {
                let count = session
                    .get("count")
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                session.insert("count", (count + 1).to_string());
                let body = format!("count={}", count + 1);
                Response::new(StatusCode::OK, body.into_bytes())
            } else {
                Response::new(StatusCode::OK, b"no session".to_vec())
            }
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
        let layer = SessionLayer::new(store.clone());
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
}
