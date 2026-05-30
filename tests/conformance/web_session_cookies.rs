//! Active RFC 6265-oriented session cookie conformance tests.
//!
//! The previous file was a permanently disabled simulator. These tests now use
//! the real `SessionLayer`, `MemoryStore`, and `Session` middleware path.

use asupersync::Cx;
use asupersync::web::extract::Request;
use asupersync::web::session::{
    MemoryStore, SameSite, Session, SessionConfig, SessionLayer, SessionStore,
};
use asupersync::web::{Handler, Response, StatusCode};
use std::future::Future;
use std::pin::Pin;

fn call_sync<H: Handler + ?Sized>(handler: &H, req: Request) -> Response {
    futures_lite::future::block_on(handler.call(&Cx::for_testing(), req))
}

fn session_id_from_set_cookie<'a>(set_cookie: &'a str, cookie_name: &str) -> &'a str {
    let prefix = format!("{cookie_name}=");
    set_cookie
        .split(';')
        .find_map(|part| part.trim().strip_prefix(&prefix))
        .expect("Set-Cookie should contain the configured session cookie")
}

struct MutatingSessionHandler;

impl Handler for MutatingSessionHandler {
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let session = req
                .extensions
                .get_typed::<Session>()
                .expect("session middleware should inject Session");
            let visits = session
                .get("visits")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(0)
                + 1;
            session.insert("visits", visits.to_string());
            Response::new(StatusCode::OK, format!("visits={visits}").into_bytes())
        })
    }
}

struct CsrfEchoHandler;

impl Handler for CsrfEchoHandler {
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            let method = req.method.clone();
            let session = req
                .extensions
                .get_typed::<Session>()
                .expect("session middleware should inject Session");
            let token = session
                .csrf_token()
                .expect("session middleware should mint a CSRF token");
            if method.eq_ignore_ascii_case("POST") {
                session.insert("mutated", "yes");
            }
            Response::new(StatusCode::OK, token.into_bytes())
        })
    }
}

#[test]
fn session_cookie_config_defaults_are_secure_and_validated() {
    let default_config = SessionConfig::default();
    assert!(default_config.http_only);
    assert!(default_config.secure);
    assert_eq!(default_config.same_site, SameSite::Lax);
    assert!(default_config.csrf_protection);
    assert!(default_config.validate().is_ok());

    let invalid_cross_site_config = SessionConfig {
        secure: false,
        same_site: SameSite::None,
        ..SessionConfig::default()
    };
    assert!(invalid_cross_site_config.validate().is_err());
}

#[test]
fn session_middleware_emits_configured_rfc6265_cookie_attributes() {
    let store = MemoryStore::new();
    let middleware = SessionLayer::new(store.clone())
        .cookie_name("sid")
        .cookie_path("/app")
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(120)
        .csrf_protection(false)
        .wrap(MutatingSessionHandler);

    let response = call_sync(&middleware, Request::new("GET", "/app/home"));
    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(std::str::from_utf8(&response.body).unwrap(), "visits=1");
    assert_eq!(store.len(), 1);

    let cookie = response
        .set_cookies
        .first()
        .expect("mutated session should set a cookie");
    let session_id = session_id_from_set_cookie(cookie, "sid");
    assert_eq!(session_id.len(), 32);
    assert!(session_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(cookie.contains("Path=/app"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Max-Age=120"));

    let stored = store.load(session_id).expect("session should be persisted");
    assert_eq!(stored.get("visits"), Some("1"));
}

#[test]
fn session_middleware_enforces_origin_and_csrf_token_for_existing_sessions() {
    let store = MemoryStore::new();
    let middleware = SessionLayer::new(store.clone())
        .allowed_origins(["https://app.example"])
        .wrap(CsrfEchoHandler);

    let first = call_sync(&middleware, Request::new("GET", "/form"));
    assert_eq!(first.status, StatusCode::OK);
    let cookie = first
        .set_cookies
        .first()
        .expect("first request should issue a session cookie")
        .clone();
    let session_id = session_id_from_set_cookie(&cookie, "session_id").to_string();
    let csrf_token = std::str::from_utf8(&first.body).unwrap().to_string();
    assert_eq!(csrf_token.len(), 32);

    let missing_token = call_sync(
        &middleware,
        Request::new("POST", "/form")
            .with_header("Cookie", format!("session_id={session_id}"))
            .with_header("Origin", "https://app.example"),
    );
    assert_eq!(missing_token.status, StatusCode::FORBIDDEN);
    assert_eq!(store.load(&session_id).unwrap().get("mutated"), None);

    let bad_origin = call_sync(
        &middleware,
        Request::new("POST", "/form")
            .with_header("Cookie", format!("session_id={session_id}"))
            .with_header("Origin", "https://evil.example")
            .with_header("X-CSRF-Token", csrf_token.clone()),
    );
    assert_eq!(bad_origin.status, StatusCode::FORBIDDEN);
    assert_eq!(store.load(&session_id).unwrap().get("mutated"), None);

    let accepted = call_sync(
        &middleware,
        Request::new("POST", "/form")
            .with_header("Cookie", format!("session_id={session_id}"))
            .with_header("Origin", "https://app.example")
            .with_header("X-CSRF-Token", csrf_token),
    );
    assert_eq!(accepted.status, StatusCode::OK);
    assert_eq!(store.load(&session_id).unwrap().get("mutated"), Some("yes"));
}
