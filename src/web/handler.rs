//! Handler trait and implementations.
//!
//! Handlers are async functions that take extractors as parameters and return
//! a type implementing [`IntoResponse`]. The [`Handler`] trait provides the
//! abstraction that the router uses to invoke handlers.

use std::future::Future;
use std::sync::OnceLock;

use crate::Cx;
use crate::runtime::{Runtime, RuntimeBuilder};

use super::extract::{FromRequest, FromRequestParts, Request};
use super::response::{IntoResponse, Response, StatusCode};

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

// ─── Async Cx-aware Handler Implementations ─────────────────────────────────

#[inline]
fn extract_arg_1<T1>(req: Request) -> Result<T1, Response>
where
    T1: FromRequest,
{
    T1::from_request(req).map_err(IntoResponse::into_response)
}

#[inline]
fn extract_arg_2<T1, T2>(req: Request) -> Result<(T1, T2), Response>
where
    T1: FromRequestParts,
    T2: FromRequest,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request(req).map_err(IntoResponse::into_response)?;
    Ok((t1, t2))
}

#[inline]
fn extract_arg_3<T1, T2, T3>(req: Request) -> Result<(T1, T2, T3), Response>
where
    T1: FromRequestParts,
    T2: FromRequestParts,
    T3: FromRequest,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request(req).map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3))
}

#[inline]
fn extract_arg_4<T1, T2, T3, T4>(req: Request) -> Result<(T1, T2, T3, T4), Response>
where
    T1: FromRequestParts,
    T2: FromRequestParts,
    T3: FromRequestParts,
    T4: FromRequest,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request(req).map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4))
}

#[inline]
fn run_async_handler<F, Res>(future: F) -> Response
where
    F: Future<Output = Res>,
    Res: IntoResponse,
{
    static HANDLER_RUNTIME: OnceLock<Option<Runtime>> = OnceLock::new();
    let runtime = HANDLER_RUNTIME.get_or_init(|| RuntimeBuilder::current_thread().build().ok());
    runtime.as_ref().map_or_else(
        || Response::empty(StatusCode::INTERNAL_SERVER_ERROR),
        |rt| rt.block_on(future).into_response(),
    )
}

/// Wrapper for async handlers that receive a [`Cx`] and no extractors.
pub struct AsyncCxFnHandler<F> {
    func: F,
}

impl<F> AsyncCxFnHandler<F> {
    /// Wrap an async Cx-aware function as a handler.
    pub fn new(func: F) -> Self {
        Self { func }
    }
}

impl<F, Fut, Res> Handler for AsyncCxFnHandler<F>
where
    F: Fn(Cx) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Res>,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, _req: Request) -> Response {
        run_async_handler((self.func)(Cx::for_request()))
    }
}

/// Wrapper for async handlers with 1 extractor.
pub struct AsyncCxFnHandler1<F, T1> {
    func: F,
    _marker: std::marker::PhantomData<T1>,
}

impl<F, T1> AsyncCxFnHandler1<F, T1> {
    /// Wrap an async Cx-aware function with 1 extractor.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1> Handler for AsyncCxFnHandler1<F, T1>
where
    F: Fn(Cx, T1) -> Fut + Send + Sync + 'static,
    T1: FromRequest + Send + Sync + 'static,
    Fut: Future<Output = Res>,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        let t1 = match extract_arg_1::<T1>(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        run_async_handler((self.func)(Cx::for_request(), t1))
    }
}

/// Wrapper for async handlers with 2 extractors.
pub struct AsyncCxFnHandler2<F, T1, T2> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2)>,
}

impl<F, T1, T2> AsyncCxFnHandler2<F, T1, T2> {
    /// Wrap an async Cx-aware function with 2 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1, T2> Handler for AsyncCxFnHandler2<F, T1, T2>
where
    F: Fn(Cx, T1, T2) -> Fut + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequest + Send + Sync + 'static,
    Fut: Future<Output = Res>,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        let (t1, t2) = match extract_arg_2::<T1, T2>(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        run_async_handler((self.func)(Cx::for_request(), t1, t2))
    }
}

/// Wrapper for async handlers with 3 extractors.
pub struct AsyncCxFnHandler3<F, T1, T2, T3> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3)>,
}

impl<F, T1, T2, T3> AsyncCxFnHandler3<F, T1, T2, T3> {
    /// Wrap an async Cx-aware function with 3 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1, T2, T3> Handler for AsyncCxFnHandler3<F, T1, T2, T3>
where
    F: Fn(Cx, T1, T2, T3) -> Fut + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequest + Send + Sync + 'static,
    Fut: Future<Output = Res>,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        let (t1, t2, t3) = match extract_arg_3::<T1, T2, T3>(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        run_async_handler((self.func)(Cx::for_request(), t1, t2, t3))
    }
}

/// Wrapper for async handlers with 4 extractors.
pub struct AsyncCxFnHandler4<F, T1, T2, T3, T4> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3, T4)>,
}

impl<F, T1, T2, T3, T4> AsyncCxFnHandler4<F, T1, T2, T3, T4> {
    /// Wrap an async Cx-aware function with 4 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1, T2, T3, T4> Handler for AsyncCxFnHandler4<F, T1, T2, T3, T4>
where
    F: Fn(Cx, T1, T2, T3, T4) -> Fut + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequest + Send + Sync + 'static,
    Fut: Future<Output = Res>,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        let (t1, t2, t3, t4) = match extract_arg_4::<T1, T2, T3, T4>(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        run_async_handler((self.func)(Cx::for_request(), t1, t2, t3, t4))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::bytes::Bytes;
    use crate::web::extract::{Json, Path, Query};
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

    #[test]
    fn async_cx_handler_no_extractors() {
        async fn index(cx: Cx) -> &'static str {
            cx.checkpoint().expect("checkpoint");
            "async-hello"
        }

        let handler = AsyncCxFnHandler::new(index);
        let resp = handler.call(Request::new("GET", "/"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(&resp.body).expect("utf8"),
            "async-hello"
        );
    }

    #[test]
    fn async_cx_handler_one_extractor() {
        async fn get_user(cx: Cx, Path(id): Path<String>) -> String {
            cx.checkpoint().expect("checkpoint");
            format!("async-user:{id}")
        }

        let handler = AsyncCxFnHandler1::<_, Path<String>>::new(get_user);
        let mut params = HashMap::new();
        params.insert("id".to_string(), "7".to_string());
        let req = Request::new("GET", "/users/7").with_path_params(params);
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(&resp.body).expect("utf8"),
            "async-user:7"
        );
    }

    #[test]
    fn async_cx_handler_two_extractors() {
        async fn save(
            cx: Cx,
            Query(query): Query<HashMap<String, String>>,
            Json(payload): Json<HashMap<String, String>>,
        ) -> StatusCode {
            cx.checkpoint().expect("checkpoint");
            assert_eq!(query.get("tenant"), Some(&"blue".to_string()));
            assert_eq!(payload.get("name"), Some(&"alice".to_string()));
            StatusCode::CREATED
        }

        let handler = AsyncCxFnHandler2::<
            _,
            Query<HashMap<String, String>>,
            Json<HashMap<String, String>>,
        >::new(save);
        let req = Request::new("POST", "/users")
            .with_query("tenant=blue")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(br#"{"name":"alice"}"#));
        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::CREATED);
    }

    #[test]
    fn async_cx_handler_four_extractors() {
        async fn audit(
            cx: Cx,
            Path(id): Path<String>,
            Query(query): Query<HashMap<String, String>>,
            headers: HashMap<String, String>,
            Json(payload): Json<HashMap<String, String>>,
        ) -> String {
            cx.checkpoint().expect("checkpoint");
            let req_id = headers
                .get("x-request-id")
                .expect("x-request-id header present");
            let tenant = query.get("tenant").expect("tenant query");
            let event = payload.get("event").expect("event key");
            format!("{req_id}:{tenant}:{id}:{event}")
        }

        let handler = AsyncCxFnHandler4::<
            _,
            Path<String>,
            Query<HashMap<String, String>>,
            HashMap<String, String>,
            Json<HashMap<String, String>>,
        >::new(audit);

        let mut params = HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        let req = Request::new("POST", "/users/42/audit")
            .with_path_params(params)
            .with_query("tenant=green")
            .with_header("x-request-id", "req-123")
            .with_header("content-type", "application/json")
            .with_body(Bytes::from_static(br#"{"event":"created"}"#));

        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(&resp.body).expect("utf8"),
            "req-123:green:42:created"
        );
    }
}
