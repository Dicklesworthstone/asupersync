//! Handler trait and implementations.
//!
//! Handlers are async functions that take extractors as parameters and return
//! a type implementing [`IntoResponse`]. The [`Handler`] trait provides the
//! abstraction that the router uses to invoke handlers.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::Cx;
use crate::runtime::{Runtime, RuntimeBuilder};

use super::extract::{FromRequest, FromRequestParts, Request};
use super::response::{IntoResponse, Response};

/// A request handler.
///
/// This trait is implemented for functions with up to 8 extractor
/// parameters. The last parameter may consume the request body.
///
/// Phase 1: Now supports async handlers with asupersync runtime integration.
pub trait Handler: Send + Sync + 'static {
    /// Handle the request and produce a response.
    ///
    /// Async handlers receive a `Cx` for structured concurrency and runtime integration.
    fn call(
        &self,
        cx: &Cx,
        req: Request,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send + '_>>;

    /// Return a stable diagnostic name for route introspection.
    #[must_use]
    fn handler_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }
}

// Type-erased handlers remain handlers, so middleware layers can re-wrap the
// `Box<dyn Handler>` values the router stores (br-asupersync-server-stack-hardening-eeexl1.3).
impl<H: Handler + ?Sized> Handler for Box<H> {
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        (**self).call(cx, req)
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        (**self).handler_name()
    }
}

impl<H: Handler + ?Sized> Handler for std::sync::Arc<H> {
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        (**self).call(cx, req)
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        (**self).handler_name()
    }
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
    fn call(&self, _cx: &Cx, _req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move { (func)().into_response() })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler"
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
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            match T1::from_request(req) {
                Ok(t1) => (func)(t1).into_response(),
                Err(e) => e.into_response(),
            }
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler1"
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
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            let t1 = match T1::from_request_parts(&req) {
                Ok(v) => v,
                Err(e) => return e.into_response(),
            };
            let t2 = match T2::from_request(req) {
                Ok(v) => v,
                Err(e) => return e.into_response(),
            };
            (func)(t1, t2).into_response()
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler2"
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
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3) = match extract_arg_3::<T1, T2, T3>(req) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            (func)(t1, t2, t3).into_response()
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler3"
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
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4) = match extract_arg_4::<T1, T2, T3, T4>(req) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            (func)(t1, t2, t3, t4).into_response()
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler4"
    }
}

/// Wrapper for handlers with 5 extractors.
pub struct FnHandler5<F, T1, T2, T3, T4, T5> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3, T4, T5)>,
}

impl<F, T1, T2, T3, T4, T5> FnHandler5<F, T1, T2, T3, T4, T5> {
    /// Wrap a function with 5 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, T2, T3, T4, T5, Res> Handler for FnHandler5<F, T1, T2, T3, T4, T5>
where
    F: Fn(T1, T2, T3, T4, T5) -> Res + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5) = match extract_arg_5::<T1, T2, T3, T4, T5>(req) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            (func)(t1, t2, t3, t4, t5).into_response()
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler5"
    }
}

/// Wrapper for handlers with 6 extractors.
pub struct FnHandler6<F, T1, T2, T3, T4, T5, T6> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3, T4, T5, T6)>,
}

impl<F, T1, T2, T3, T4, T5, T6> FnHandler6<F, T1, T2, T3, T4, T5, T6> {
    /// Wrap a function with 6 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, T2, T3, T4, T5, T6, Res> Handler for FnHandler6<F, T1, T2, T3, T4, T5, T6>
where
    F: Fn(T1, T2, T3, T4, T5, T6) -> Res + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequestParts + Send + Sync + 'static,
    T6: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5, t6) = match extract_arg_6::<T1, T2, T3, T4, T5, T6>(req) {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            (func)(t1, t2, t3, t4, t5, t6).into_response()
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler6"
    }
}

/// Wrapper for handlers with 7 extractors.
pub struct FnHandler7<F, T1, T2, T3, T4, T5, T6, T7> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3, T4, T5, T6, T7)>,
}

impl<F, T1, T2, T3, T4, T5, T6, T7> FnHandler7<F, T1, T2, T3, T4, T5, T6, T7> {
    /// Wrap a function with 7 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, T2, T3, T4, T5, T6, T7, Res> Handler for FnHandler7<F, T1, T2, T3, T4, T5, T6, T7>
where
    F: Fn(T1, T2, T3, T4, T5, T6, T7) -> Res + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequestParts + Send + Sync + 'static,
    T6: FromRequestParts + Send + Sync + 'static,
    T7: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5, t6, t7) =
                match extract_arg_7::<T1, T2, T3, T4, T5, T6, T7>(req) {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
            (func)(t1, t2, t3, t4, t5, t6, t7).into_response()
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler7"
    }
}

/// Wrapper for handlers with 8 extractors.
pub struct FnHandler8<F, T1, T2, T3, T4, T5, T6, T7, T8> {
    func: F,
    _marker: std::marker::PhantomData<(T1, T2, T3, T4, T5, T6, T7, T8)>,
}

impl<F, T1, T2, T3, T4, T5, T6, T7, T8> FnHandler8<F, T1, T2, T3, T4, T5, T6, T7, T8> {
    /// Wrap a function with 8 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, T1, T2, T3, T4, T5, T6, T7, T8, Res> Handler
    for FnHandler8<F, T1, T2, T3, T4, T5, T6, T7, T8>
where
    F: Fn(T1, T2, T3, T4, T5, T6, T7, T8) -> Res + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequestParts + Send + Sync + 'static,
    T6: FromRequestParts + Send + Sync + 'static,
    T7: FromRequestParts + Send + Sync + 'static,
    T8: FromRequest + Send + Sync + 'static,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, _cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5, t6, t7, t8) =
                match extract_arg_8::<T1, T2, T3, T4, T5, T6, T7, T8>(req) {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
            (func)(t1, t2, t3, t4, t5, t6, t7, t8).into_response()
        })
    }

    #[inline]
    fn handler_name(&self) -> &'static str {
        "FnHandler8"
    }
}

#[doc(hidden)]
pub trait HandlerArityExceeded<F> {}

#[doc(hidden)]
pub struct HandlersSupportAtMostEightExtractorsGroupAdditionalInputsIntoARequestStruct;

#[doc(hidden)]
pub struct FnHandler9<F, T1, T2, T3, T4, T5, T6, T7, T8, T9> {
    _marker: std::marker::PhantomData<(F, T1, T2, T3, T4, T5, T6, T7, T8, T9)>,
}

impl<F, T1, T2, T3, T4, T5, T6, T7, T8, T9> FnHandler9<F, T1, T2, T3, T4, T5, T6, T7, T8, T9> {
    #[doc(hidden)]
    pub fn new(_func: F) -> Self
    where
        HandlersSupportAtMostEightExtractorsGroupAdditionalInputsIntoARequestStruct:
            HandlerArityExceeded<F>,
    {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

// ─── Async Cx-aware Handler Implementations ─────────────────────────────────

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
fn extract_arg_5<T1, T2, T3, T4, T5>(req: Request) -> Result<(T1, T2, T3, T4, T5), Response>
where
    T1: FromRequestParts,
    T2: FromRequestParts,
    T3: FromRequestParts,
    T4: FromRequestParts,
    T5: FromRequest,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request(req).map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5))
}

#[inline]
fn extract_arg_6<T1, T2, T3, T4, T5, T6>(req: Request) -> Result<(T1, T2, T3, T4, T5, T6), Response>
where
    T1: FromRequestParts,
    T2: FromRequestParts,
    T3: FromRequestParts,
    T4: FromRequestParts,
    T5: FromRequestParts,
    T6: FromRequest,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t6 = T6::from_request(req).map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5, t6))
}

#[inline]
fn extract_arg_7<T1, T2, T3, T4, T5, T6, T7>(
    req: Request,
) -> Result<(T1, T2, T3, T4, T5, T6, T7), Response>
where
    T1: FromRequestParts,
    T2: FromRequestParts,
    T3: FromRequestParts,
    T4: FromRequestParts,
    T5: FromRequestParts,
    T6: FromRequestParts,
    T7: FromRequest,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t6 = T6::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t7 = T7::from_request(req).map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5, t6, t7))
}

#[inline]
fn extract_arg_8<T1, T2, T3, T4, T5, T6, T7, T8>(
    req: Request,
) -> Result<(T1, T2, T3, T4, T5, T6, T7, T8), Response>
where
    T1: FromRequestParts,
    T2: FromRequestParts,
    T3: FromRequestParts,
    T4: FromRequestParts,
    T5: FromRequestParts,
    T6: FromRequestParts,
    T7: FromRequestParts,
    T8: FromRequest,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t6 = T6::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t7 = T7::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t8 = T8::from_request(req).map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5, t6, t7, t8))
}

#[inline]
async fn extract_async_arg_1<T1>(cx: &Cx, req: Request) -> Result<T1, Response>
where
    T1: FromRequest + Send,
{
    T1::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)
}

#[inline]
async fn extract_async_arg_2<T1, T2>(cx: &Cx, req: Request) -> Result<(T1, T2), Response>
where
    T1: FromRequestParts + Send,
    T2: FromRequest + Send,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((t1, t2))
}

#[inline]
async fn extract_async_arg_3<T1, T2, T3>(cx: &Cx, req: Request) -> Result<(T1, T2, T3), Response>
where
    T1: FromRequestParts + Send,
    T2: FromRequestParts + Send,
    T3: FromRequest + Send,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3))
}

#[inline]
async fn extract_async_arg_4<T1, T2, T3, T4>(
    cx: &Cx,
    req: Request,
) -> Result<(T1, T2, T3, T4), Response>
where
    T1: FromRequestParts + Send,
    T2: FromRequestParts + Send,
    T3: FromRequestParts + Send,
    T4: FromRequest + Send,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4))
}

#[inline]
async fn extract_async_arg_5<T1, T2, T3, T4, T5>(
    cx: &Cx,
    req: Request,
) -> Result<(T1, T2, T3, T4, T5), Response>
where
    T1: FromRequestParts + Send,
    T2: FromRequestParts + Send,
    T3: FromRequestParts + Send,
    T4: FromRequestParts + Send,
    T5: FromRequest + Send,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5))
}

#[inline]
async fn extract_async_arg_6<T1, T2, T3, T4, T5, T6>(
    cx: &Cx,
    req: Request,
) -> Result<(T1, T2, T3, T4, T5, T6), Response>
where
    T1: FromRequestParts + Send,
    T2: FromRequestParts + Send,
    T3: FromRequestParts + Send,
    T4: FromRequestParts + Send,
    T5: FromRequestParts + Send,
    T6: FromRequest + Send,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t6 = T6::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5, t6))
}

#[inline]
async fn extract_async_arg_7<T1, T2, T3, T4, T5, T6, T7>(
    cx: &Cx,
    req: Request,
) -> Result<(T1, T2, T3, T4, T5, T6, T7), Response>
where
    T1: FromRequestParts + Send,
    T2: FromRequestParts + Send,
    T3: FromRequestParts + Send,
    T4: FromRequestParts + Send,
    T5: FromRequestParts + Send,
    T6: FromRequestParts + Send,
    T7: FromRequest + Send,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t6 = T6::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t7 = T7::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5, t6, t7))
}

#[inline]
async fn extract_async_arg_8<T1, T2, T3, T4, T5, T6, T7, T8>(
    cx: &Cx,
    req: Request,
) -> Result<(T1, T2, T3, T4, T5, T6, T7, T8), Response>
where
    T1: FromRequestParts + Send,
    T2: FromRequestParts + Send,
    T3: FromRequestParts + Send,
    T4: FromRequestParts + Send,
    T5: FromRequestParts + Send,
    T6: FromRequestParts + Send,
    T7: FromRequestParts + Send,
    T8: FromRequest + Send,
{
    let t1 = T1::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t2 = T2::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t3 = T3::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t4 = T4::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t5 = T5::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t6 = T6::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t7 = T7::from_request_parts(&req).map_err(IntoResponse::into_response)?;
    let t8 = T8::from_request_with_cx(cx, req)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((t1, t2, t3, t4, t5, t6, t7, t8))
}

/// Wrapper for async handlers that receive a [`Cx`] and no extractors.
pub struct AsyncCxFnHandler<F> {
    func: F,
}

thread_local! {
    static ASYNC_HANDLER_HELPER_RUNTIME: Runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("async handler helper runtime should build");
}

#[pin_project::pin_project]
struct CurrentCxFuture<Fut> {
    cx: Cx,
    #[pin]
    future: Fut,
}

impl<Fut: Future> Future for CurrentCxFuture<Fut> {
    type Output = Fut::Output;

    fn poll(self: Pin<&mut Self>, task_cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let _guard = Cx::set_current(Some(this.cx.clone()));
        this.future.poll(task_cx)
    }
}

/// Whether `cx` runs with less than full runtime authority (any of spawn,
/// time, entropy, io or remote masked off).
fn runtime_authority_is_narrowed(cx: &Cx) -> bool {
    let granted = cx.capabilities().runtime;
    !(granted.spawn && granted.time && granted.entropy && granted.io && granted.remote)
}

async fn run_async_cx_handler<F, Fut, Res>(caller_cx: Cx, func: F) -> Response
where
    F: FnOnce(Cx) -> Fut,
    Fut: Future<Output = Res>,
    Res: IntoResponse,
{
    let ambient_cx = Cx::current();
    // A caller whose runtime authority was narrowed keeps its own context,
    // even without a timer. Swapping in a runtime request context would
    // silently grant every capability the caller was denied
    // (asupersync-bi2462.46). A narrowed ambient context (for example under
    // Cx::push_restriction) is kept for the same reason (asupersync-mkybj0).
    let handler_cx = if caller_cx.timer_driver().is_some()
        || runtime_authority_is_narrowed(&caller_cx)
    {
        caller_cx
    } else if let Some(current) = ambient_cx
        && (current.timer_driver().is_some()
            || runtime_authority_is_narrowed(&current)
            || Runtime::current_handle().is_none())
    {
        current
    } else if let Some(runtime_cx) = Runtime::current_request_cx_with_budget(caller_cx.budget()) {
        runtime_cx
    } else {
        return ASYNC_HANDLER_HELPER_RUNTIME.with(|runtime| {
            let runtime_cx = runtime.request_cx_with_budget(caller_cx.budget());
            runtime.block_on_with_cx(runtime_cx.clone(), async move {
                func(runtime_cx).await.into_response()
            })
        });
    };

    let future_cx = handler_cx.clone();
    CurrentCxFuture {
        cx: handler_cx,
        future: async move { func(future_cx).await.into_response() },
    }
    .await
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
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, _req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move { run_async_cx_handler(cx, func).await })
    }
}

/// Wrapper for async handlers with 1 extractor.
pub struct AsyncCxFnHandler1<F, T1> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> T1>,
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
    T1: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let t1 = match extract_async_arg_1::<T1>(&cx, req).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            run_async_cx_handler(cx, |handler_cx| func(handler_cx, t1)).await
        })
    }
}

/// Wrapper for async handlers with 2 extractors.
pub struct AsyncCxFnHandler2<F, T1, T2> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> (T1, T2)>,
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
    T2: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2) = match extract_async_arg_2::<T1, T2>(&cx, req).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            run_async_cx_handler(cx, |handler_cx| func(handler_cx, t1, t2)).await
        })
    }
}

/// Wrapper for async handlers with 3 extractors.
pub struct AsyncCxFnHandler3<F, T1, T2, T3> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> (T1, T2, T3)>,
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
    T3: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3) = match extract_async_arg_3::<T1, T2, T3>(&cx, req).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            run_async_cx_handler(cx, |handler_cx| func(handler_cx, t1, t2, t3)).await
        })
    }
}

/// Wrapper for async handlers with 4 extractors.
pub struct AsyncCxFnHandler4<F, T1, T2, T3, T4> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> (T1, T2, T3, T4)>,
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
    T4: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4) = match extract_async_arg_4::<T1, T2, T3, T4>(&cx, req).await {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            run_async_cx_handler(cx, |handler_cx| func(handler_cx, t1, t2, t3, t4)).await
        })
    }
}

/// Wrapper for async handlers with 5 extractors.
pub struct AsyncCxFnHandler5<F, T1, T2, T3, T4, T5> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> (T1, T2, T3, T4, T5)>,
}

impl<F, T1, T2, T3, T4, T5> AsyncCxFnHandler5<F, T1, T2, T3, T4, T5> {
    /// Wrap an async Cx-aware function with 5 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1, T2, T3, T4, T5> Handler for AsyncCxFnHandler5<F, T1, T2, T3, T4, T5>
where
    F: Fn(Cx, T1, T2, T3, T4, T5) -> Fut + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5) =
                match extract_async_arg_5::<T1, T2, T3, T4, T5>(&cx, req).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
            run_async_cx_handler(cx, |handler_cx| func(handler_cx, t1, t2, t3, t4, t5)).await
        })
    }
}

/// Wrapper for async handlers with 6 extractors.
pub struct AsyncCxFnHandler6<F, T1, T2, T3, T4, T5, T6> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> (T1, T2, T3, T4, T5, T6)>,
}

impl<F, T1, T2, T3, T4, T5, T6> AsyncCxFnHandler6<F, T1, T2, T3, T4, T5, T6> {
    /// Wrap an async Cx-aware function with 6 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1, T2, T3, T4, T5, T6> Handler for AsyncCxFnHandler6<F, T1, T2, T3, T4, T5, T6>
where
    F: Fn(Cx, T1, T2, T3, T4, T5, T6) -> Fut + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequestParts + Send + Sync + 'static,
    T6: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5, t6) =
                match extract_async_arg_6::<T1, T2, T3, T4, T5, T6>(&cx, req).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
            run_async_cx_handler(cx, |handler_cx| func(handler_cx, t1, t2, t3, t4, t5, t6)).await
        })
    }
}

/// Wrapper for async handlers with 7 extractors.
pub struct AsyncCxFnHandler7<F, T1, T2, T3, T4, T5, T6, T7> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> (T1, T2, T3, T4, T5, T6, T7)>,
}

impl<F, T1, T2, T3, T4, T5, T6, T7> AsyncCxFnHandler7<F, T1, T2, T3, T4, T5, T6, T7> {
    /// Wrap an async Cx-aware function with 7 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1, T2, T3, T4, T5, T6, T7> Handler
    for AsyncCxFnHandler7<F, T1, T2, T3, T4, T5, T6, T7>
where
    F: Fn(Cx, T1, T2, T3, T4, T5, T6, T7) -> Fut + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequestParts + Send + Sync + 'static,
    T6: FromRequestParts + Send + Sync + 'static,
    T7: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5, t6, t7) =
                match extract_async_arg_7::<T1, T2, T3, T4, T5, T6, T7>(&cx, req).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
            run_async_cx_handler(cx, |handler_cx| {
                func(handler_cx, t1, t2, t3, t4, t5, t6, t7)
            })
            .await
        })
    }
}

/// Wrapper for async handlers with 8 extractors.
pub struct AsyncCxFnHandler8<F, T1, T2, T3, T4, T5, T6, T7, T8> {
    func: F,
    _marker: std::marker::PhantomData<fn() -> (T1, T2, T3, T4, T5, T6, T7, T8)>,
}

impl<F, T1, T2, T3, T4, T5, T6, T7, T8> AsyncCxFnHandler8<F, T1, T2, T3, T4, T5, T6, T7, T8> {
    /// Wrap an async Cx-aware function with 8 extractors.
    pub fn new(func: F) -> Self {
        Self {
            func,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<F, Fut, Res, T1, T2, T3, T4, T5, T6, T7, T8> Handler
    for AsyncCxFnHandler8<F, T1, T2, T3, T4, T5, T6, T7, T8>
where
    F: Fn(Cx, T1, T2, T3, T4, T5, T6, T7, T8) -> Fut + Send + Sync + 'static,
    T1: FromRequestParts + Send + Sync + 'static,
    T2: FromRequestParts + Send + Sync + 'static,
    T3: FromRequestParts + Send + Sync + 'static,
    T4: FromRequestParts + Send + Sync + 'static,
    T5: FromRequestParts + Send + Sync + 'static,
    T6: FromRequestParts + Send + Sync + 'static,
    T7: FromRequestParts + Send + Sync + 'static,
    T8: FromRequest + Send + 'static,
    Fut: Future<Output = Res> + Send,
    Res: IntoResponse,
{
    #[inline]
    fn call(&self, cx: &Cx, req: Request) -> Pin<Box<dyn Future<Output = Response> + Send + '_>> {
        let cx = cx.clone();
        let func = &self.func;
        Box::pin(async move {
            let (t1, t2, t3, t4, t5, t6, t7, t8) =
                match extract_async_arg_8::<T1, T2, T3, T4, T5, T6, T7, T8>(&cx, req).await {
                    Ok(v) => v,
                    Err(resp) => return resp,
                };
            run_async_cx_handler(cx, |handler_cx| {
                func(handler_cx, t1, t2, t3, t4, t5, t6, t7, t8)
            })
            .await
        })
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "handler_inline_tests.rs"]
mod tests;
