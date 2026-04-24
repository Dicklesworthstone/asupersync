//! Handler trait and implementations.
//!
//! Handlers are async functions that take extractors as parameters and return
//! a type implementing [`IntoResponse`]. The [`Handler`] trait provides the
//! abstraction that the router uses to invoke handlers.

use std::future::Future;
use std::sync::OnceLock;

use crate::Cx;
use crate::runtime::{Runtime, RuntimeBuilder};
use crate::types::Budget;

use super::extract::{FromRequest, FromRequestParts, Request};
use super::response::{IntoResponse, Response, StatusCode};

thread_local! {
    static HANDLER_RUNTIME: OnceLock<Runtime> = const { OnceLock::new() };
}

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

/// Wrapper for handlers with 3 extractors.
pub struct FnHandler3<F, T1, T2, T3> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3)>,
}

impl<F, T1, T2, T3> FnHandler3<F, T1, T2, T3> {
    /// Wrap a function with 3 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, T2, T3, Res> Handler for FnHandler3<F, T1, T2, T3>
where
    F: Fn(T1, T2, T3) -> Res + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        let (t1, t2, t3) = match extract_arg_3::<T1, T2, T3>(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        (self.func)(t1, t2, t3).into_response()
    }
}

/// Wrapper for handlers with 4 extractors.
pub struct FnHandler4<F, T1, T2, T3, T4> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3, T4)>,
}

impl<F, T1, T2, T3, T4> FnHandler4<F, T1, T2, T3, T4> {
    /// Wrap a function with 4 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, T2, T3, T4, Res> Handler for FnHandler4<F, T1, T2, T3, T4>
where
    F: Fn(T1, T2, T3, T4) -> Res + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, req: Request) -> Response {
        let (t1, t2, t3, t4) = match extract_arg_4::<T1, T2, T3, T4>(req) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        (self.func)(t1, t2, t3, t4).into_response()
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
pub(crate) fn run_async_handler_with_runtime_cx<F, Fut, Res>(f: F) -> Response
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = Res>,
    Res: IntoResponse,
{
    let ambient_cx = Cx::current();
    let runtime_cx = ambient_cx
        .clone()
        .filter(|_| Runtime::current_handle().is_some())
        .or_else(|| Runtime::current_request_cx_with_budget(Budget::INFINITE));
    if let Some(runtime_cx) = runtime_cx {
        return Runtime::block_on_current_with_cx(runtime_cx.clone(), f(runtime_cx)).map_or_else(
            || Response::empty(StatusCode::INTERNAL_SERVER_ERROR),
            IntoResponse::into_response,
        );
    }

    HANDLER_RUNTIME.with(|runtime| {
        let rt = if let Some(rt) = runtime.get() {
            rt
        } else {
            match RuntimeBuilder::current_thread().build() {
                Ok(rt) => {
                    let _ = runtime.set(rt);
                    runtime
                        .get()
                        .expect("handler runtime should be initialized after set")
                }
                Err(_) => return Response::empty(StatusCode::INTERNAL_SERVER_ERROR),
            }
        };

        let cx = ambient_cx.unwrap_or_else(|| rt.request_cx_with_budget(Budget::INFINITE));
        rt.block_on_with_cx(cx.clone(), f(cx)).into_response()
    })
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
        run_async_handler_with_runtime_cx(|cx| (self.func)(cx))
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
        run_async_handler_with_runtime_cx(|cx| (self.func)(cx, t1))
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
        run_async_handler_with_runtime_cx(|cx| (self.func)(cx, t1, t2))
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
        run_async_handler_with_runtime_cx(|cx| (self.func)(cx, t1, t2, t3))
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
        run_async_handler_with_runtime_cx(|cx| (self.func)(cx, t1, t2, t3, t4))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::pedantic, clippy::nursery, clippy::expect_fun_call, clippy::map_unwrap_or, clippy::cast_possible_wrap, clippy::future_not_send)]
    use super::*;
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::thread;

    use crate::bytes::Bytes;
    use crate::time::TimerDriverHandle;
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
    fn handler_three_extractors() {
        #[allow(clippy::needless_pass_by_value)]
        fn audit(
            Path(id): Path<String>,
            Query(query): Query<HashMap<String, String>>,
            mut headers: HashMap<String, String>,
        ) -> String {
            let req_id = headers
                .remove("x-request-id")
                .expect("x-request-id header present");
            let tenant = query.get("tenant").expect("tenant query");
            format!("{req_id}:{tenant}:{id}")
        }

        let handler = FnHandler3::<
            _,
            Path<String>,
            Query<HashMap<String, String>>,
            HashMap<String, String>,
        >::new(audit);

        let mut params = HashMap::new();
        params.insert("id".to_string(), "42".to_string());
        let req = Request::new("GET", "/users/42/audit")
            .with_path_params(params)
            .with_query("tenant=green")
            .with_header("x-request-id", "req-123");

        let resp = handler.call(req);
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(
            std::str::from_utf8(&resp.body).expect("utf8"),
            "req-123:green:42"
        );
    }

    #[test]
    fn handler_four_extractors() {
        #[allow(clippy::needless_pass_by_value)]
        fn audit(
            Path(id): Path<String>,
            Query(query): Query<HashMap<String, String>>,
            mut headers: HashMap<String, String>,
            Json(payload): Json<HashMap<String, String>>,
        ) -> String {
            let req_id = headers
                .remove("x-request-id")
                .expect("x-request-id header present");
            let tenant = query.get("tenant").expect("tenant query");
            let event = payload.get("event").expect("event key");
            format!("{req_id}:{tenant}:{id}:{event}")
        }

        let handler = FnHandler4::<
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
    fn async_cx_handler_installs_runtime_backed_current_cx() {
        async fn inspect(cx: Cx) -> &'static str {
            assert!(
                cx.timer_driver().is_some(),
                "async handler should receive the runtime timer driver"
            );
            let current = Cx::current().expect("async handler should install CURRENT_CX");
            assert_eq!(current.region_id(), cx.region_id());
            assert_eq!(current.task_id(), cx.task_id());
            assert!(
                current.timer_driver().is_some(),
                "ambient CURRENT_CX should expose the runtime timer driver"
            );
            "ok"
        }

        let handler = AsyncCxFnHandler::new(inspect);
        let resp = handler.call(Request::new("GET", "/inspect"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&resp.body).expect("utf8"), "ok");
    }

    #[test]
    fn async_cx_handler_reuses_ambient_request_cx() {
        async fn inspect(cx: Cx) -> &'static str {
            let current = Cx::current().expect("ambient CURRENT_CX should be preserved");
            assert_eq!(
                cx.task_id(),
                current.task_id(),
                "async web handler should reuse the ambient request task"
            );
            assert_eq!(
                cx.region_id(),
                current.region_id(),
                "async web handler should stay in the ambient request region"
            );
            assert_eq!(
                cx.budget().deadline,
                current.budget().deadline,
                "async web handler should inherit the ambient request deadline"
            );
            "ok"
        }

        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("build current-thread runtime");
        let deadline_budget = Budget::with_deadline_secs(7);
        let request_cx = runtime.request_cx_with_budget(deadline_budget);
        let expected_task = request_cx.task_id();
        let expected_region = request_cx.region_id();
        let expected_deadline = request_cx.budget().deadline;

        runtime.block_on_with_cx(request_cx, async move {
            let handler = AsyncCxFnHandler::new(inspect);
            let resp = handler.call(Request::new("GET", "/ambient"));
            assert_eq!(resp.status, StatusCode::OK);
            assert_eq!(std::str::from_utf8(&resp.body).expect("utf8"), "ok");

            let after = Cx::current().expect("ambient CURRENT_CX should still be installed");
            assert_eq!(after.task_id(), expected_task);
            assert_eq!(after.region_id(), expected_region);
            assert_eq!(after.budget().deadline, expected_deadline);
        });
    }

    #[test]
    fn async_cx_handler_runtime_cache_is_thread_local() {
        let (tx, rx) = mpsc::channel::<TimerDriverHandle>();

        let spawn_handler_thread = |tx: mpsc::Sender<TimerDriverHandle>| {
            thread::spawn(move || {
                let handler = AsyncCxFnHandler::new(move |cx: Cx| {
                    let tx = tx.clone();
                    async move {
                        let timer = cx
                            .timer_driver()
                            .expect("async handler should receive a timer driver")
                            .clone();
                        tx.send(timer).expect("send timer handle");
                        "ok"
                    }
                });

                let resp = handler.call(Request::new("GET", "/thread-local-runtime"));
                assert_eq!(resp.status, StatusCode::OK);
            })
        };

        let first = spawn_handler_thread(tx.clone());
        let second = spawn_handler_thread(tx);

        first.join().expect("first handler thread should complete");
        second
            .join()
            .expect("second handler thread should complete");

        let timer_a = rx.recv().expect("first timer handle");
        let timer_b = rx.recv().expect("second timer handle");
        assert!(
            !timer_a.ptr_eq(&timer_b),
            "different caller threads must not share the same cached current-thread runtime"
        );
    }

    #[test]
    fn async_cx_handler_falls_back_to_helper_runtime_with_ambient_nonruntime_cx() {
        let ambient = Cx::for_testing();
        let expected_task = ambient.task_id();
        let expected_region = ambient.region_id();
        let _guard = Cx::set_current(Some(ambient));

        let handler = AsyncCxFnHandler::new(move |cx: Cx| async move {
            assert_eq!(cx.task_id(), expected_task);
            assert_eq!(cx.region_id(), expected_region);
            let current = Cx::current().expect("helper runtime should preserve CURRENT_CX");
            assert_eq!(current.task_id(), expected_task);
            assert_eq!(current.region_id(), expected_region);
            "ok"
        });

        let resp = handler.call(Request::new("GET", "/ambient-no-runtime"));
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(std::str::from_utf8(&resp.body).expect("utf8"), "ok");

        let restored = Cx::current().expect("ambient CURRENT_CX should still be installed");
        assert_eq!(restored.task_id(), expected_task);
        assert_eq!(restored.region_id(), expected_region);
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
