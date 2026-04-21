#![allow(clippy::all)]
//! Integration coverage for empty-session middleware behavior.

use asupersync::web::extract::Request;
use asupersync::web::handler::Handler;
use asupersync::web::response::{Response, StatusCode};
use asupersync::web::session::{MemoryStore, SessionLayer};

struct EmptyHandler;

impl Handler for EmptyHandler {
    fn call(&self, _req: Request) -> Response {
        Response::new(StatusCode::OK, "")
    }
}

#[test]
fn test_dos_empty_session() {
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store.clone());
    let middleware = layer.wrap(EmptyHandler);

    let req = Request::new("GET", "/");
    let resp = middleware.call(req);

    assert_eq!(
        store.len(),
        0,
        "Store should not save empty untouched sessions"
    );
    assert!(
        !resp.headers.contains_key("set-cookie"),
        "Should not set cookie for empty untouched sessions"
    );
}
