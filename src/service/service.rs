//! Service trait and utility combinators.

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
                OneshotState::Ready { service, request } => {
                    match service.poll_ready(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(err)) => {
                            this.state = OneshotState::Done;
                            return Poll::Ready(Err(err));
                        }
                        Poll::Ready(Ok(())) => {
                            let req = request
                                .take()
                                .expect("Oneshot polled after request taken");
                            let fut = service.call(req);
                            this.state = OneshotState::Calling { future: fut };
                        }
                    }
                }
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
