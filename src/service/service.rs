//! Service trait and utility combinators.

use crate::cx::Cx;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

/// A composable async service.
///
/// Services are request/response handlers that can be composed with middleware
/// layers. The `poll_ready` method lets a service apply backpressure before
/// accepting work.
pub trait Service<Request> {
    /// Response type produced by this service.
    type Response;
    /// Error type produced by this service.
    type Error;
    /// Future returned by [`Service::call`].
    type Future: Future<Output = Result<Self::Response, Self::Error>>;

    /// Polls readiness to accept a request.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;

    /// Dispatches a request to the service.
    fn call(&mut self, req: Request) -> Self::Future;
}

/// Extension trait providing convenience adapters for services.
pub trait ServiceExt<Request>: Service<Request> {
    /// Waits until the service is ready to accept a request.
    fn ready(&mut self) -> Ready<'_, Self, Request>
    where
        Self: Sized,
    {
        Ready::new(self)
    }

    /// Executes a single request on this service.
    ///
    /// # Note
    ///
    /// This adapter requires `Self` and `Request` to be `Unpin` so we can safely
    /// move the service and request through the internal state machine without
    /// unsafe code.
    fn oneshot(self, req: Request) -> Oneshot<Self, Request>
    where
        Self: Sized + Unpin,
        Request: Unpin,
        Self::Future: Unpin,
    {
        Oneshot::new(self, req)
    }
}

impl<T, Request> ServiceExt<Request> for T where T: Service<Request> + ?Sized {}

/// A service that executes within an Asupersync [`Cx`].
///
/// Unlike [`Service`], this trait is async-native and does not expose readiness
/// polling. Callers supply a `Cx` so cancellation, budgets, and capabilities
/// are explicitly threaded through the call.
#[allow(async_fn_in_trait)]
pub trait AsupersyncService<Request>: Send + Sync {
    /// Response type returned by the service.
    type Response;
    /// Error type returned by the service.
    type Error;

    /// Dispatches a request within the given context.
    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error>;
}

/// Extension helpers for [`AsupersyncService`].
pub trait AsupersyncServiceExt<Request>: AsupersyncService<Request> {
    /// Map the response type.
    fn map_response<F, NewResponse>(self, f: F) -> MapResponse<Self, F>
    where
        Self: Sized,
        F: Fn(Self::Response) -> NewResponse + Send + Sync,
    {
        MapResponse::new(self, f)
    }

    /// Map the error type.
    fn map_err<F, NewError>(self, f: F) -> MapErr<Self, F>
    where
        Self: Sized,
        F: Fn(Self::Error) -> NewError + Send + Sync,
    {
        MapErr::new(self, f)
    }

    /// Convert this service into a Tower-compatible adapter.
    #[cfg(feature = "tower")]
    fn into_tower(self) -> TowerAdapter<Self>
    where
        Self: Sized,
    {
        TowerAdapter::new(self)
    }
}

impl<T, Request> AsupersyncServiceExt<Request> for T where T: AsupersyncService<Request> + ?Sized {}

/// Adapter that maps the response type of an [`AsupersyncService`].
pub struct MapResponse<S, F> {
    service: S,
    map: F,
}

impl<S, F> MapResponse<S, F> {
    fn new(service: S, map: F) -> Self {
        Self { service, map }
    }
}

impl<S, F, Request, NewResponse> AsupersyncService<Request> for MapResponse<S, F>
where
    S: AsupersyncService<Request>,
    F: Fn(S::Response) -> NewResponse + Send + Sync,
{
    type Response = NewResponse;
    type Error = S::Error;

    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        let response = self.service.call(cx, request).await?;
        Ok((self.map)(response))
    }
}

/// Adapter that maps the error type of an [`AsupersyncService`].
pub struct MapErr<S, F> {
    service: S,
    map: F,
}

impl<S, F> MapErr<S, F> {
    fn new(service: S, map: F) -> Self {
        Self { service, map }
    }
}

impl<S, F, Request, NewError> AsupersyncService<Request> for MapErr<S, F>
where
    S: AsupersyncService<Request>,
    F: Fn(S::Error) -> NewError + Send + Sync,
{
    type Response = S::Response;
    type Error = NewError;

    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        self.service.call(cx, request).await.map_err(&self.map)
    }
}

/// Blanket implementation for async functions and closures.
impl<F, Fut, Request, Response, Error> AsupersyncService<Request> for F
where
    F: Fn(&Cx, Request) -> Fut + Send + Sync,
    Fut: Future<Output = Result<Response, Error>> + Send,
{
    type Response = Response;
    type Error = Error;

    async fn call(&self, cx: &Cx, request: Request) -> Result<Self::Response, Self::Error> {
        (self)(cx, request).await
    }
}

#[cfg(feature = "tower")]
pub struct TowerAdapter<S> {
    service: std::sync::Arc<S>,
}

#[cfg(feature = "tower")]
impl<S> TowerAdapter<S> {
    fn new(service: S) -> Self {
        Self {
            service: std::sync::Arc::new(service),
        }
    }
}

#[cfg(feature = "tower")]
impl<S, Request> tower::Service<(Cx, Request)> for TowerAdapter<S>
where
    S: AsupersyncService<Request> + Send + Sync + 'static,
    Request: Send + 'static,
    S::Response: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, (cx, request): (Cx, Request)) -> Self::Future {
        let service = std::sync::Arc::clone(&self.service);
        Box::pin(async move { service.call(&cx, request).await })
    }
}

/// Future returned by [`ServiceExt::ready`].
#[derive(Debug)]
pub struct Ready<'a, S: ?Sized, Request> {
    service: &'a mut S,
    _marker: PhantomData<fn(Request)>,
}

impl<'a, S: ?Sized, Request> Ready<'a, S, Request> {
    fn new(service: &'a mut S) -> Self {
        Self {
            service,
            _marker: PhantomData,
        }
    }
}

impl<S, Request> Future for Ready<'_, S, Request>
where
    S: Service<Request> + ?Sized,
{
    type Output = Result<(), S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        this.service.poll_ready(cx)
    }
}

/// Future returned by [`ServiceExt::oneshot`].
pub struct Oneshot<S, Request>
where
    S: Service<Request>,
{
    state: OneshotState<S, Request>,
}

enum OneshotState<S, Request>
where
    S: Service<Request>,
{
    Ready {
        service: S,
        request: Option<Request>,
    },
    Calling {
        future: S::Future,
    },
    Done,
}

impl<S, Request> Oneshot<S, Request>
where
    S: Service<Request>,
{
    /// Creates a new oneshot future.
    pub fn new(service: S, request: Request) -> Self {
        Self {
            state: OneshotState::Ready {
                service,
                request: Some(request),
            },
        }
    }
}

impl<S, Request> Future for Oneshot<S, Request>
where
    S: Service<Request> + Unpin,
    Request: Unpin,
    S::Future: Unpin,
{
    type Output = Result<S::Response, S::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            match &mut this.state {
                OneshotState::Ready { service, request } => match service.poll_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        this.state = OneshotState::Done;
                        return Poll::Ready(Err(err));
                    }
                    Poll::Ready(Ok(())) => {
                        let req = request.take().expect("Oneshot polled after request taken");
                        let fut = service.call(req);
                        this.state = OneshotState::Calling { future: fut };
                    }
                },
                OneshotState::Calling { future } => {
                    let result = Pin::new(future).poll(cx);
                    if result.is_ready() {
                        this.state = OneshotState::Done;
                    }
                    return result;
                }
                OneshotState::Done => {
                    panic!("Oneshot polled after completion");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{AsupersyncService, AsupersyncServiceExt};
    use crate::test_utils::run_test_with_cx;

    #[test]
    fn function_service_call_works() {
        run_test_with_cx(|cx| async move {
            let svc = |_: &crate::cx::Cx, req: i32| async move { Ok::<_, ()>(req + 1) };
            let result = AsupersyncService::call(&svc, &cx, 41).await.unwrap();
            assert_eq!(result, 42);
        });
    }

    #[test]
    fn map_response_and_map_err() {
        run_test_with_cx(|cx| async move {
            let svc = |_: &crate::cx::Cx, req: i32| async move { Ok::<_, &str>(req) };
            let svc = svc.map_response(|v| v + 1).map_err(|e| format!("err:{e}"));
            let result = AsupersyncService::call(&svc, &cx, 41).await.unwrap();
            assert_eq!(result, 42);

            let fail = |_: &crate::cx::Cx, _: i32| async move { Err::<i32, &str>("nope") };
            let fail = fail.map_err(|e| format!("err:{e}"));
            let err = AsupersyncService::call(&fail, &cx, 0).await.unwrap_err();
            assert_eq!(err, "err:nope");
        });
    }
}
