//! Audit + regression test for CSRF token validation.
//!
//! NOTE: the operator's audit pointer was `src/web/security.rs`,
//! but that file is the security HEADERS middleware (HSTS, CSP,
//! X-Frame-Options) — NOT CSRF. The actual CSRF validation logic
//! lives in `src/web/session.rs` (SessionMiddleware + SessionLayer
//! + Session). This test audits the correct file.
//!
//! Audit scope:
//!   (1) Token rotation on session-id change.
//!   (2) Constant-time comparison (NOT bytewise `==`).
//!   (3) Origin header checking when Referer absent (per OWASP
//!       2023 update: validate Origin first, fall back to Referer,
//!       reject if BOTH absent on state-changing requests).
//!
//! Audit verdict: **SOUND** on all three concerns.
//!
//!   (1) `Session::regenerate()` (session.rs:998-1005,
//!       br-asupersync-3cvnmo) rotates BOTH the session ID AND
//!       the bound CSRF token in lockstep. `Session::
//!       rotate_csrf_token()` (session.rs:1016-1020) mints a
//!       fresh token without an ID rotation for periodic
//!       in-session rotation. The doc-comment on `regenerate`
//!       explicitly notes "a session ID rotation that doesn't
//!       rotate the bound CSRF token leaves a trust-boundary
//!       hole."
//!
//!   (2) `constant_time_eq_str` (session.rs:927-938) uses an
//!       XOR accumulator pattern — the per-byte XOR is OR'd
//!       into a single `diff: u8` and the final equality is
//!       `diff == 0`. This is the standard CT-equality pattern;
//!       no early-return on first differing byte. Length
//!       mismatch returns false immediately because the length
//!       is non-secret per OWASP guidance.
//!
//!   (3) `request_origin` (session.rs:881-907,
//!       br-asupersync-czbj90) extracts the Origin header
//!       verbatim, falling back to Referer's scheme+host[+port]
//!       prefix when Origin is absent. The CSRF middleware at
//!       session.rs:714-740 checks the result against
//!       `allowed_origins`: when BOTH Origin and Referer are
//!       absent on a state-changing request and origin checking
//!       is configured, the request is REJECTED with 403 BEFORE
//!       the X-CSRF-Token check runs. This matches the OWASP
//!       2023 update.
//!
//! Regression tests below pin (1)+(2)+(3).

use asupersync::Cx;
use asupersync::web::extract::Request;
use asupersync::web::handler::FnHandler;
use asupersync::web::response::{Response, StatusCode};
use asupersync::web::session::{MemoryStore, Session, SessionLayer};
use std::future::Future;
use std::pin::Pin;

fn ok_handler() -> StatusCode {
    StatusCode::OK
}

fn csrf_cookie_handler(session: &Session) -> StatusCode {
    assert!(
        session.csrf_token().is_some(),
        "test fixture must mint a CSRF token before extracting Set-Cookie",
    );
    StatusCode::OK
}

struct SessionStatusHandler<F>(F);

impl<F> asupersync::web::handler::Handler for SessionStatusHandler<F>
where
    F: Fn(&Session) -> StatusCode + Send + Sync + 'static,
{
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let session = req
                .extensions
                .get_typed::<Session>()
                .expect("session middleware injects Session");
            Response::new((self.0)(session), Vec::<u8>::new())
        })
    }
}

trait TestHandlerSyncExt: asupersync::web::handler::Handler {
    fn call(&self, req: Request) -> Response {
        futures_lite::future::block_on(asupersync::web::handler::Handler::call(
            self,
            &Cx::for_testing(),
            req,
        ))
    }
}

impl<T> TestHandlerSyncExt for T where T: asupersync::web::handler::Handler + ?Sized {}

// ── (1) Token rotation on session-id change ──────────────────────

#[test]
fn regenerate_rotates_csrf_token_alongside_session_id() {
    // Pin (1): `Session::regenerate()` flips the CSRF token AND
    // marks the session for ID rotation in a single atomic call.
    // A regression that rotated only one of the two would leave
    // the trust-boundary hole the doc comment warns about.
    use std::sync::Arc;
    use std::sync::Mutex;

    let captured: Arc<Mutex<Option<(String, String, bool)>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();
    let layer = SessionLayer::new(MemoryStore::new())
        .secure(false)
        .csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(move |session: &Session| {
        let token_before = session
            .csrf_token()
            .expect("session middleware minted a CSRF token");
        session.regenerate();
        let token_after = session
            .csrf_token()
            .expect("regenerate writes a fresh token");
        let regenerate_requested = session.contains("__asupersync.regenerate");
        *captured_clone.lock().unwrap() = Some((token_before, token_after, regenerate_requested));
        StatusCode::OK
    }));

    let resp = mw.call(Request::new("GET", "/login"));
    assert_eq!(resp.status, StatusCode::OK);

    let (token_before, token_after, regenerate_requested) = captured
        .lock()
        .unwrap()
        .clone()
        .expect("handler captured token rotation");
    assert_ne!(
        token_after, token_before,
        "regenerate MUST mint a fresh CSRF token (br-asupersync-3cvnmo) — \
         a session-ID rotation that doesn't rotate the CSRF token leaves \
         a trust-boundary hole",
    );
    // Also: a regenerate flag is recorded internally.
    assert!(
        regenerate_requested,
        "regenerate must mark the session for ID rotation",
    );
}

#[test]
fn rotate_csrf_token_returns_fresh_value_distinct_from_old() {
    // Pin (1) extension: `Session::rotate_csrf_token()` mints a
    // fresh token without an ID rotation — used for periodic
    // in-session rotation. Returns the new token to the caller.
    use std::sync::Arc;
    use std::sync::Mutex;

    let captured: Arc<Mutex<Option<(String, String, String)>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();
    let layer = SessionLayer::new(MemoryStore::new())
        .secure(false)
        .csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(move |session: &Session| {
        let old_token = session
            .csrf_token()
            .expect("session middleware minted a CSRF token");
        let new_token = session
            .rotate_csrf_token()
            .expect("rotate_csrf_token returns the freshly minted token");
        let stored_token = session
            .csrf_token()
            .expect("rotate_csrf_token stores the new token");
        *captured_clone.lock().unwrap() = Some((old_token, new_token, stored_token));
        StatusCode::OK
    }));

    let resp = mw.call(Request::new("GET", "/rotate"));
    assert_eq!(resp.status, StatusCode::OK);

    let (old_token, new_token, stored_token) = captured
        .lock()
        .unwrap()
        .clone()
        .expect("handler captured token rotation");
    assert_ne!(
        new_token, old_token,
        "rotate_csrf_token returns a fresh value distinct from the old",
    );
    // The session itself now holds the new value too.
    assert_eq!(stored_token, new_token);
}

#[test]
fn two_rotations_produce_distinct_tokens() {
    // Pin (1): consecutive rotations produce DISTINCT tokens —
    // no caching, no deterministic generator. Pinned because a
    // regression to a counter-based generator would let an
    // attacker predict future tokens.
    use std::sync::Arc;
    use std::sync::Mutex;

    let captured: Arc<Mutex<Option<(String, String, String)>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();
    let layer = SessionLayer::new(MemoryStore::new())
        .secure(false)
        .csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(move |session: &Session| {
        let t1 = session
            .rotate_csrf_token()
            .expect("first rotation mints a token");
        let t2 = session
            .rotate_csrf_token()
            .expect("second rotation mints a token");
        let t3 = session
            .rotate_csrf_token()
            .expect("third rotation mints a token");
        *captured_clone.lock().unwrap() = Some((t1, t2, t3));
        StatusCode::OK
    }));

    let resp = mw.call(Request::new("GET", "/rotate-many"));
    assert_eq!(resp.status, StatusCode::OK);

    let (t1, t2, t3) = captured
        .lock()
        .unwrap()
        .clone()
        .expect("handler captured token rotations");

    assert_ne!(t1, t2, "rotation 1 != rotation 2");
    assert_ne!(t2, t3, "rotation 2 != rotation 3");
    assert_ne!(t1, t3, "rotation 1 != rotation 3");
    // Each token is non-empty and reasonably long (entropy
    // sanity check — generate_session_id uses crypto RNG).
    assert!(t1.len() >= 16, "token has non-trivial entropy; got {t1:?}");
}

// ── (2) Constant-time comparison ────────────────────────────────

#[test]
fn csrf_validation_uses_constant_time_for_token_compare_via_session_middleware() {
    // Pin (2) end-to-end: the SessionMiddleware uses
    // constant_time_eq_str (session.rs:756) to compare the
    // X-CSRF-Token header against the session's stored token.
    // Mismatched tokens reject with 403 regardless of how many
    // matching bytes are at the prefix — pinned by submitting
    // a token with matching prefix that diverges late.
    //
    // The spec we're enforcing: a peer with a "shared prefix"
    // X-CSRF-Token cannot use timing differences to recover
    // the rest of the token byte-by-byte. We can't directly
    // measure timing in a unit test, but we CAN verify the
    // function returns the same boolean (false) for both an
    // early-divergent and a late-divergent mismatch — and
    // that the secret-correct token does match.
    use std::sync::Arc;
    use std::sync::Mutex;

    let captured_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured_token.clone();
    let layer = SessionLayer::new(MemoryStore::new())
        .secure(false)
        .csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(move |session: &Session| {
        *captured_clone.lock().unwrap() = session.csrf_token();
        StatusCode::OK
    }));

    let get_resp = mw.call(Request::new("GET", "/test"));
    assert_eq!(get_resp.status, StatusCode::OK);
    let cookie = extract_set_cookie_value(&get_resp);
    let real_token = captured_token
        .lock()
        .unwrap()
        .clone()
        .expect("session minted a CSRF token on first GET");
    assert!(
        !real_token.is_empty(),
        "fresh session has a non-empty CSRF token",
    );

    let early_mismatch = token_with_byte_changed(&real_token, 0);
    let late_mismatch = token_with_byte_changed(&real_token, real_token.len() - 1);
    for wrong_token in [early_mismatch, late_mismatch] {
        let post = Request::new("POST", "/test")
            .with_header("cookie", &cookie)
            .with_header("x-csrf-token", &wrong_token);
        let post_resp = mw.call(post);
        assert_eq!(
            post_resp.status,
            StatusCode::FORBIDDEN,
            "wrong CSRF token MUST reject independently of mismatch position",
        );
    }
}

#[test]
fn constant_time_compare_helper_returns_false_for_length_mismatch() {
    // Pin (2): the CT-compare helper is called via the public
    // `Session::csrf_token()` + middleware path. We can also
    // verify the helper's contract behaviorally: a session
    // whose stored token has length N rejects an X-CSRF-Token
    // of length M ≠ N.
    //
    // (Length mismatch returns false immediately per
    // session.rs:930-932; length is non-secret.)
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store).secure(false).csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);
    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("x-csrf-token", "x");
    let post_resp = mw.call(post);
    assert_eq!(
        post_resp.status,
        StatusCode::FORBIDDEN,
        "tokens of different lengths never compare equal",
    );
}

#[test]
fn csrf_token_with_wrong_value_rejects_with_403() {
    // Pin (2) integration: a state-changing request with an
    // incorrect X-CSRF-Token (any value other than the one in
    // the session) gets rejected with 403. The middleware uses
    // constant_time_eq_str (no early-return on prefix match),
    // so timing-based recovery is structurally infeasible.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store).secure(false).csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    // First, GET to seed a session.
    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    // Second, POST with a WRONG X-CSRF-Token.
    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("x-csrf-token", "wrong-token-value");
    let post_resp = mw.call(post);
    assert_eq!(
        post_resp.status,
        StatusCode::FORBIDDEN,
        "wrong CSRF token MUST surface 403; got {:?}",
        post_resp.status,
    );
    let body = std::str::from_utf8(post_resp.body.as_ref()).unwrap_or("");
    assert!(
        body.contains("CSRF"),
        "rejection body mentions CSRF; got {body:?}",
    );
}

#[test]
fn csrf_token_with_wrong_length_rejects_with_403() {
    // Pin (2): length-mismatch rejection — proves the
    // length-check guard at session.rs:930-932 fires before the
    // XOR loop.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store).secure(false).csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    // Token with very wrong length (1 char vs ~32-char token).
    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("x-csrf-token", "x");
    let post_resp = mw.call(post);
    assert_eq!(post_resp.status, StatusCode::FORBIDDEN);
}

#[test]
fn csrf_token_missing_header_rejects_with_403() {
    // Pin (2): a state-changing request with NO X-CSRF-Token
    // header at all rejects (the empty string is treated as
    // not-equal to the session's non-empty token; the empty-
    // check at session.rs:756 also fires).
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store).secure(false).csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    let post = Request::new("POST", "/test").with_header("cookie", &cookie);
    let post_resp = mw.call(post);
    assert_eq!(post_resp.status, StatusCode::FORBIDDEN);
}

#[test]
fn csrf_token_correct_value_succeeds() {
    // Pin (2) positive case: a state-changing request with the
    // correct X-CSRF-Token DOES succeed. Sanity check that the
    // CT-compare returns true on equality.
    use std::sync::{Arc, Mutex};

    let captured_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured_token.clone();
    let capture_handler = move |session: &Session| -> StatusCode {
        *captured_clone.lock().unwrap() = session.csrf_token();
        StatusCode::OK
    };
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store).secure(false).csrf_protection(true);
    let mw = layer.wrap(SessionStatusHandler(capture_handler));

    // First GET: seed session + capture token.
    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);
    let token = captured_token
        .lock()
        .unwrap()
        .clone()
        .expect("session minted CSRF token");

    // Second POST: include the correct token.
    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("x-csrf-token", &token);
    let post_resp = mw.call(post);
    assert_eq!(
        post_resp.status,
        StatusCode::OK,
        "correct CSRF token MUST succeed",
    );
}

// ── (3) Origin / Referer checking (OWASP 2023 update) ──────────

#[test]
fn state_changing_request_without_origin_or_referer_rejects() {
    // Pin (3) audit-critical: when `allowed_origins` is
    // configured AND the state-changing request has BOTH
    // Origin AND Referer absent, the middleware rejects with
    // 403 BEFORE the X-CSRF-Token check runs (session.rs:
    // 718-727). This matches the OWASP 2023 update.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .secure(false)
        .csrf_protection(true)
        .allowed_origins(["https://app.example.com"]);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    // POST with NO Origin and NO Referer — must reject.
    let post = Request::new("POST", "/test").with_header("cookie", &cookie);
    let post_resp = mw.call(post);
    assert_eq!(
        post_resp.status,
        StatusCode::FORBIDDEN,
        "state-changing request with neither Origin nor Referer MUST \
         reject when origin checking is configured",
    );
    let body = std::str::from_utf8(post_resp.body.as_ref()).unwrap_or("");
    assert!(
        body.contains("Origin"),
        "rejection body identifies the missing-Origin/Referer class; \
         got {body:?}",
    );
}

#[test]
fn state_changing_request_with_disallowed_origin_rejects() {
    // Pin (3): an Origin header that doesn't match the allow-list
    // rejects with 403.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .secure(false)
        .csrf_protection(true)
        .allowed_origins(["https://app.example.com"]);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("origin", "https://attacker.example.com");
    let post_resp = mw.call(post);
    assert_eq!(post_resp.status, StatusCode::FORBIDDEN);
}

#[test]
fn state_changing_request_with_origin_allowed_passes_origin_check() {
    // Pin (3): an Origin matching the allow-list passes the
    // Origin gate. (Still has to pass the X-CSRF-Token check
    // afterward — we expect 403 from that, NOT from origin.)
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .secure(false)
        .csrf_protection(true)
        .allowed_origins(["https://app.example.com"]);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    // Allowed Origin + WRONG token → still 403, but from the
    // CSRF-token check (NOT from Origin).
    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("origin", "https://app.example.com")
        .with_header("x-csrf-token", "wrong");
    let post_resp = mw.call(post);
    assert_eq!(post_resp.status, StatusCode::FORBIDDEN);
    let body = std::str::from_utf8(post_resp.body.as_ref()).unwrap_or("");
    // The rejection should be the token error, NOT the
    // origin error.
    assert!(
        body.contains("CSRF token") && !body.contains("Origin"),
        "passing Origin allow-list reaches the X-CSRF-Token check; \
         rejection body: {body:?}",
    );
}

#[test]
fn referer_fallback_when_origin_absent() {
    // Pin (3): when Origin header is absent but Referer is
    // present, the middleware extracts scheme+host[+port]
    // from Referer and validates against allowed_origins.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .secure(false)
        .csrf_protection(true)
        .allowed_origins(["https://app.example.com"]);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    // No Origin, but Referer set to allowed origin (with path).
    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("referer", "https://app.example.com/some/path?q=1")
        .with_header("x-csrf-token", "wrong");
    let post_resp = mw.call(post);
    // Should pass the origin check (scheme+host extracted from
    // Referer matches the allow-list). Then fails on token.
    assert_eq!(post_resp.status, StatusCode::FORBIDDEN);
    let body = std::str::from_utf8(post_resp.body.as_ref()).unwrap_or("");
    assert!(
        body.contains("CSRF token"),
        "Referer fallback passes origin check; rejection comes from \
         token check: {body:?}",
    );
}

#[test]
fn referer_with_disallowed_origin_rejects_at_origin_check() {
    // Pin (3): Referer fallback also rejects unallowed origins.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .secure(false)
        .csrf_protection(true)
        .allowed_origins(["https://app.example.com"]);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("referer", "https://attacker.example.com/path");
    let post_resp = mw.call(post);
    assert_eq!(post_resp.status, StatusCode::FORBIDDEN);
}

#[test]
fn safe_methods_do_not_require_origin_or_csrf() {
    // Pin (3): GET/HEAD/OPTIONS are NOT state-changing per
    // OWASP CSRF Prevention Cheat Sheet. The middleware skips
    // both the origin check AND the X-CSRF-Token check on
    // these methods.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .secure(false)
        .csrf_protection(true)
        .allowed_origins(["https://app.example.com"]);
    let mw = layer.wrap(FnHandler::new(ok_handler));

    // GET with no Origin, no Referer, no X-CSRF-Token — OK.
    let get_resp = mw.call(Request::new("GET", "/test"));
    assert_eq!(get_resp.status, StatusCode::OK);

    // HEAD with same — OK.
    let head_resp = mw.call(Request::new("HEAD", "/test"));
    assert_eq!(head_resp.status, StatusCode::OK);
}

#[test]
fn empty_allowed_origins_disables_origin_check() {
    // Pin (3): when allowed_origins is empty (default), the
    // origin check is SKIPPED — only the X-CSRF-Token check
    // fires (session.rs:716). A request with no Origin / no
    // Referer reaches the token check and rejects there.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store).secure(false).csrf_protection(true);
    // No .allowed_origins(...) call.
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    let post = Request::new("POST", "/test").with_header("cookie", &cookie);
    let post_resp = mw.call(post);
    assert_eq!(post_resp.status, StatusCode::FORBIDDEN);
    let body = std::str::from_utf8(post_resp.body.as_ref()).unwrap_or("");
    // Rejection comes from the token check, NOT the origin
    // check (since allowed_origins was empty).
    assert!(
        body.contains("CSRF token"),
        "empty allowed_origins → only X-CSRF-Token check fires; got {body:?}",
    );
}

#[test]
fn null_origin_treated_as_absent() {
    // Pin (3): per session.rs:888, an Origin value of literal
    // "null" is treated as absent — same as no header. This
    // matches the browser behavior where sandboxed iframes
    // and file:// pages send `Origin: null`. A regression
    // that allowed `null` through would silently authorize
    // sandboxed contexts.
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store)
        .secure(false)
        .csrf_protection(true)
        .allowed_origins(["https://app.example.com"]);
    let mw = layer.wrap(SessionStatusHandler(csrf_cookie_handler));

    let get_resp = mw.call(Request::new("GET", "/test"));
    let cookie = extract_set_cookie_value(&get_resp);

    let post = Request::new("POST", "/test")
        .with_header("cookie", &cookie)
        .with_header("origin", "null");
    let post_resp = mw.call(post);
    assert_eq!(
        post_resp.status,
        StatusCode::FORBIDDEN,
        "Origin: null MUST be treated as absent → falls through to \
         the missing-Origin/Referer rejection",
    );
}

// ── Helpers ──────────────────────────────────────────────────────

/// Extract the cookie value from a Set-Cookie response header.
/// Returns the `name=value` portion suitable for use in a
/// subsequent request's `cookie` header.
fn extract_set_cookie_value(resp: &Response) -> String {
    let set_cookie = resp
        .set_cookies
        .first()
        .cloned()
        .expect("set-cookie header present after first request");
    // Strip attributes after the first `;` — we only need
    // `name=value` for the next request's Cookie header.
    set_cookie
        .split(';')
        .next()
        .unwrap_or(&set_cookie)
        .trim()
        .to_string()
}

fn token_with_byte_changed(token: &str, index: usize) -> String {
    let mut bytes = token.as_bytes().to_vec();
    bytes[index] = if bytes[index] == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).expect("CSRF tokens are ASCII hex")
}
