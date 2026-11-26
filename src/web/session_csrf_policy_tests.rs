//! Public middleware journeys for opt-in pre-session CSRF enforcement.
//! Serves asupersync-a1q12q (login CSRF without a stored session).

use super::{
    CREATED_AT_KEY, CSRF_TOKEN_KEY, Handler, MemoryStore, Request, Response, Session, SessionData,
    SessionLayer, SessionStore, StatusCode,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn call<H: Handler>(handler: &H, request: Request) -> Response {
    futures_lite::future::block_on(handler.call(&crate::Cx::for_testing(), request))
}

fn request(method: &str, session_id: Option<&str>, token: Option<&str>) -> Request {
    let mut request = Request::new(method, "/login");
    if let Some(id) = session_id {
        request
            .headers
            .insert("cookie".to_owned(), format!("session_id={id}"));
    }
    if let Some(token) = token {
        request
            .headers
            .insert("x-csrf-token".to_owned(), token.to_owned());
    }
    request
}

fn cookie_id(response: &Response) -> &str {
    response.set_cookies[0]
        .split(';')
        .next()
        .expect("cookie name/value")
        .split_once('=')
        .expect("session cookie")
        .1
}

struct CountCalls(Arc<AtomicUsize>);

impl Handler for CountCalls {
    fn call(
        &self,
        _cx: &crate::Cx,
        _request: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Response::new(StatusCode::OK, "handled")
        })
    }
}

struct Login(Arc<AtomicUsize>);

impl Handler for Login {
    fn call(
        &self,
        _cx: &crate::Cx,
        request: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            let session = request.extensions.get_typed::<Session>().expect("session");
            if request.method == "GET" {
                Response::new(StatusCode::OK, session.csrf_token().expect("CSRF token"))
            } else {
                session.insert("user", "alice");
                session.regenerate().expect("session ID rotation");
                Response::new(StatusCode::OK, "signed in")
            }
        })
    }
}

#[test]
fn strict_csrf_refuses_first_unsafe_requests_without_calling_the_handler() {
    let store = MemoryStore::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = SessionLayer::new(store.clone())
        .require_existing_session_for_csrf(true)
        .wrap(Login(Arc::clone(&calls)));

    for method in [
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "PROPPATCH",
        "custom",
        "get",
        "Get",
        "head",
        "options",
        "Trace",
        "trace",
    ] {
        for id in [
            None,
            Some("invalid"),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ] {
            let response = call(&handler, request(method, id, Some("forged-token")));
            assert_eq!(response.status, StatusCode::FORBIDDEN, "{method} {id:?}");
            assert!(response.set_cookies.is_empty(), "{method} {id:?}");
            assert!(store.is_empty(), "refusal must not allocate a session");
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn strict_csrf_keeps_safe_methods_available_without_allocating_sessions() {
    let store = MemoryStore::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = SessionLayer::new(store.clone())
        .require_existing_session_for_csrf(true)
        .wrap(CountCalls(Arc::clone(&calls)));

    for method in ["GET", "HEAD", "OPTIONS", "TRACE"] {
        let response = call(&handler, request(method, None, None));
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.set_cookies.is_empty());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(store.is_empty());
}

#[test]
fn strict_csrf_login_journey_requires_token_and_rotates_the_authenticated_session() {
    let store = MemoryStore::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = SessionLayer::new(store.clone())
        .try_concurrency_protection()
        .expect("MemoryStore supports atomic sessions")
        .require_existing_session_for_csrf(true)
        .wrap(Login(Arc::clone(&calls)));

    let form = call(&handler, request("GET", None, None));
    assert_eq!(form.status, StatusCode::OK);
    let original_id = cookie_id(&form).to_owned();
    let original_token = std::str::from_utf8(&form.body).expect("token").to_owned();
    assert_eq!(store.len(), 1);

    for token in [None, Some("wrong-token")] {
        let denied = call(&handler, request("POST", Some(&original_id), token));
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        assert!(denied.set_cookies.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            store.load(&original_id).expect("pre-session").get("user"),
            None
        );
    }

    let signed_in = call(
        &handler,
        request("POST", Some(&original_id), Some(&original_token)),
    );
    assert_eq!(signed_in.status, StatusCode::OK);
    let new_id = cookie_id(&signed_in).to_owned();
    assert_ne!(new_id, original_id);
    assert!(store.load(&original_id).is_none());
    let authenticated = store.load(&new_id).expect("authenticated session");
    assert_eq!(authenticated.get("user"), Some("alice"));
    let new_token = authenticated.get(CSRF_TOKEN_KEY).expect("rotated token");
    assert_ne!(new_token, original_token);
    assert_eq!(store.len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    for id in [&original_id, &new_id] {
        let denied = call(&handler, request("POST", Some(id), Some(&original_token)));
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        assert!(denied.set_cookies.is_empty());
    }
    let extension = call(&handler, request("custom", Some(&new_id), Some(new_token)));
    assert_eq!(extension.status, StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(store.len(), 1);
}

#[test]
fn strict_csrf_rejects_expired_sessions_instead_of_treating_them_as_login_authority() {
    let store = MemoryStore::new();
    let id = "11111111111111111111111111111111";
    let mut data = SessionData::new();
    data.insert(CREATED_AT_KEY, "1");
    data.insert(CSRF_TOKEN_KEY, "expired-token");
    store.save(id, &data);
    let calls = Arc::new(AtomicUsize::new(0));
    let handler = SessionLayer::new(store.clone())
        .absolute_ttl_seconds(1)
        .require_existing_session_for_csrf(true)
        .wrap(CountCalls(Arc::clone(&calls)));

    let response = call(&handler, request("POST", Some(id), Some("expired-token")));
    assert_eq!(response.status, StatusCode::FORBIDDEN);
    assert!(response.set_cookies.is_empty());
    assert!(store.is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn strict_csrf_applies_origin_and_token_checks_to_extension_methods_through_layer() {
    let store = MemoryStore::new();
    let id = "22222222222222222222222222222222";
    let mut data = SessionData::new();
    data.insert(CSRF_TOKEN_KEY, "stored-token");
    store.save(id, &data);
    let calls = Arc::new(AtomicUsize::new(0));
    let layer = SessionLayer::new(store)
        .require_existing_session_for_csrf(true)
        .allowed_origins(["https://app.example"]);
    let handler = crate::service::Layer::layer(&layer, CountCalls(Arc::clone(&calls)));

    for (origin, token, expected) in [
        (
            "https://attacker.example",
            Some("stored-token"),
            StatusCode::FORBIDDEN,
        ),
        ("https://app.example", None, StatusCode::FORBIDDEN),
        (
            "https://app.example",
            Some("wrong-token"),
            StatusCode::FORBIDDEN,
        ),
        ("https://app.example", Some("stored-token"), StatusCode::OK),
    ] {
        let mut input = request("custom", Some(id), token);
        input.headers.insert("origin".to_owned(), origin.to_owned());
        let response = call(&handler, input);
        assert_eq!(response.status, expected);
        if expected == StatusCode::FORBIDDEN {
            assert!(response.set_cookies.is_empty());
        }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn strict_csrf_preserves_legacy_default_and_explicit_protection_opt_out() {
    // Default policy, disabled CSRF protection, and an explicitly disabled
    // strict policy must each retain the legacy first-request behavior.
    for strict in [None, Some(true), Some(false)] {
        let store = MemoryStore::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let layer = SessionLayer::new(store.clone());
        let layer = if let Some(required) = strict {
            layer
                .require_existing_session_for_csrf(true)
                .require_existing_session_for_csrf(required)
                .csrf_protection(!required)
        } else {
            layer
        };
        let handler = layer.wrap(Login(Arc::clone(&calls)));
        let response = call(&handler, request("POST", None, None));
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.len(), 1);
        assert_eq!(
            store
                .load(cookie_id(&response))
                .expect("session")
                .get("user"),
            Some("alice")
        );
    }
}
