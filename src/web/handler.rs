//! Handler trait and implementations.
//!
//! Handlers are async functions that take extractors as parameters and return
//! a type implementing [`IntoResponse`]. The [`Handler`] trait provides the
//! abstraction that the router uses to invoke handlers.

use super::extract::{FromRequest, FromRequestParts, Request};
use super::response::{IntoResponse, Response};

/// A request handler.
///
/// This trait is implemented for async functions with up to 4 extractor
/// parameters. The last parameter may consume the request body.
pub trait Handler: Send + Sync + 'static {
    /// Handle the request and produce a response.
    fn call(&self, req: Request) -> Response;
}

// ─── Handler Implementations ─────────────────────────────────────────────────
//
// We implement Handler for synchronous closures returning IntoResponse.
// Async support requires runtime integration (Phase 1). For Phase 0, we
// provide synchronous handlers which cover the routing and extraction logic.

/// Wrapper that turns a function into a [`Handler`].
pub struct FnHandler<F> {
    func: F,
}

impl<F> FnHandler<F> {
    /// Wrap a function as a handler.
    pub fn new(func: F) -> Self {
        Self { func }
    }
}

// 0 extractors
impl<F, Res> Handler for FnHandler<F>
where
    F: Fn() -> Res + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, _req: Request) -> Response {
        (self.func)().into_response()
    }
}

/// Wrapper for handlers with 1 extractor.
pub struct FnHandler1<F, T1> {
    func: F,
    _marker: std::marker::PhantomData<T1>,
}

impl<F, T1> FnHandler1<F, T1> {
    /// Wrap a function with 1 extractor.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, Res> Handler for FnHandler1<F, T1>
where
    F: Fn(T1) -> Res + Send + Sync + 'static,
    T1: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        match T1::from_request(req) {
            Ok(t1) => (self.func)(t1).into_response(),
            Err(e) => e.into_response(),
        }
    }
}

/// Wrapper for handlers with 2 extractors.
pub struct FnHandler2<F, T1, T2> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2)>,
}

impl<F, T1, T2> FnHandler2<F, T1, T2> {
    /// Wrap a function with 2 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, T2, Res> Handler for FnHandler2<F, T1, T2>
where
    F: Fn(T1, T2) -> Res + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        let t1 = match T1::from_request_parts(&req) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
        let t2 = match T2::from_request(req) {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
        (self.func)(t1, t2).into_response()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::extract::Path;
    use crate::web::response::StatusCode;

    #[test]
    fn handler_no_extractors() {
        fn index() -> &'static str {
            "hello"
        }

        let handler = FnHandler::new(index);
        let req = Request::new("GET", "/");
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn handler_one_extractor() {
        fn get_user(Path(id): Path<String>) -> String {
            format!("user:{id}")
        }

        let handler = FnHandler1::<_, Path<String>>::new(get_user);
        let mut params = std::collections::HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        let req = Request::new("GET", "/users/42").with_path_params(params);
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn handler_extraction_failure_returns_error() {
        fn get_user(Path(_id): Path<String>) -> &'static str {
            "ok"
        }

        let handler = FnHandler1::<_, Path<String>>::new(get_user);
        let req = Request::new("GET", "/"); // no path params
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::BAD_REQUEST);
    }
}
