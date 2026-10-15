//! Integration coverage for empty-session middleware behavior.

use asupersync::Cx;
use asupersync::web::extract::Request;
use asupersync::web::handler::Handler;
use asupersync::web::response::{Response, StatusCode};
use asupersync::web::session::{MemoryStore, SessionLayer};
use std::future::Future;
use std::pin::Pin;

struct EmptyHandler;

impl Handler for EmptyHandler {
    fn call(&self, _cx: &Cx, _req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        Box::pin(async move { Response::new(StatusCode::OK, "") })
    }
}

trait SyncHandlerExt {
    fn call_sync(&self, req: Request) -> Response;
}

impl<H: Handler> SyncHandlerExt for H {
    fn call_sync(&self, req: Request) -> Response {
        futures_lite::future::block_on(Handler::call(self, &Cx::for_testing(), req))
    }
}

#[test]
fn empty_untouched_session_does_not_allocate_or_set_cookie() {
    let store = MemoryStore::new();
    let layer = SessionLayer::new(store.clone());
    let middleware = layer.wrap(EmptyHandler);

    let req = Request::new("GET", "/");
    let resp = middleware.call_sync(req);

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(
        store.len(),
        0,
        "Store should not save empty untouched sessions"
    );
    assert!(
        resp.header_value("set-cookie").is_none(),
        "Should not set cookie for empty untouched sessions"
    );
}
