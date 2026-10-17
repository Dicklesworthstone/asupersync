//! Load shedding middleware layer.
//!
//! The [`LoadShedLayer`] wraps a service and sheds load when the inner service
//! signals backpressure. If the inner service returns `Poll::Pending` from
//! `poll_ready`, the load shedder marks itself as overloaded and immediately
//! rejects subsequent requests until the inner service becomes ready again.

use super::{Layer, Service};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Waker;
use std::task::{Context, Poll};

fn tracked_probe_waker(delegate: &Waker) -> (Waker, Arc<AtomicBool>) {
    struct TrackWaker {
        woke: Arc<AtomicBool>,
        delegate: Waker,
    }

    use std::task::Wake;
    impl Wake for TrackWaker {
        fn wake(self: Arc<Self>) {
            self.woke.store(true, Ordering::SeqCst);
            self.delegate.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.woke.store(true, Ordering::SeqCst);
            self.delegate.wake_by_ref();
        }
    }

    let woke = Arc::new(AtomicBool::new(false));
    let waker = Waker::from(Arc::new(TrackWaker {
        woke: Arc::clone(&woke),
        delegate: delegate.clone(),
    }));
    (waker, woke)
}

/// The probe waker a [`LoadShed`] polls its inner service with, kept across
/// `poll_ready` calls while the task's waker stays the same. A fresh probe per
/// poll would look like a new task to an inner service that de-duplicates
/// wakers with `will_wake` (`Buffer`), which then queues one more waker for
/// every shed request.
#[derive(Debug)]
struct ReadinessProbe {
    waker: Waker,
    woke: Arc<AtomicBool>,
    delegate: Waker,
}

fn poll_ready_preserving_self_wake<S, Request>(
    service: &mut S,
    probe: &mut Option<ReadinessProbe>,
    cx: &mut Context<'_>,
) -> Poll<Result<(), S::Error>>
where
    S: Service<Request>,
{
    if !probe
        .as_ref()
        .is_some_and(|probe| probe.delegate.will_wake(cx.waker()))
    {
        let (waker, woke) = tracked_probe_waker(cx.waker());
        *probe = Some(ReadinessProbe {
            waker,
            woke,
            delegate: cx.waker().clone(),
        });
    }
    let probe = probe.as_ref().expect("probe installed above");
    // Only a wake during this poll counts as a self-wake.
    probe.woke.store(false, Ordering::SeqCst);
    let mut probe_cx = Context::from_waker(&probe.waker);
    let mut readiness = service.poll_ready(&mut probe_cx);
    if matches!(readiness, Poll::Pending) && probe.woke.load(Ordering::SeqCst) {
        readiness = service.poll_ready(cx);
    }
    readiness
}

/// A layer that sheds load when the inner service is not ready.
///
/// This is useful for protecting services from being overwhelmed. When the
/// inner service signals backpressure via `poll_ready`, the load shedder
/// will immediately fail new requests instead of queueing them.
///
/// # Example
///
/// ```ignore
/// use asupersync::service::{ServiceBuilder, ServiceExt};
/// use asupersync::service::load_shed::LoadShedLayer;
///
/// let svc = ServiceBuilder::new()
///     .layer(LoadShedLayer::new())
///     .service(my_service);
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadShedLayer;

impl LoadShedLayer {
    /// Creates a new load shedding layer.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for LoadShedLayer {
    type Service = LoadShed<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoadShed::new(inner)
    }
}

/// A service that sheds load when the inner service is not ready.
///
/// The load shedder checks the inner service's readiness in `poll_ready`.
/// If the inner service returns `Poll::Pending`, the load shedder marks
/// itself as overloaded and will reject the next `call` with an [`Overloaded`]
/// error instead of processing it.
///
/// Each successful `poll_ready` authorizes exactly one subsequent `call`.
/// Calling without first observing readiness fails closed with
/// [`LoadShedError::NotReady`].
#[derive(Debug)]
pub struct LoadShed<S> {
    inner: S,
    overloaded: bool,
    ready_observed: bool,
    probe: Option<ReadinessProbe>,
}

impl<S: Clone> Clone for LoadShed<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            overloaded: self.overloaded,
            // Readiness is handle-local and must not be duplicated across clones.
            ready_observed: false,
            probe: None,
        }
    }
}

impl<S> LoadShed<S> {
    /// Creates a new load shedding service.
    #[must_use]
    pub const fn new(inner: S) -> Self {
        Self {
            inner,
            overloaded: false,
            ready_observed: false,
            probe: None,
        }
    }

    /// Returns whether the service is currently overloaded.
    #[must_use]
    pub const fn is_overloaded(&self) -> bool {
        self.overloaded
    }

    /// Returns a reference to the inner service.
    #[must_use]
    pub const fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns a mutable reference to the inner service.
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Consumes the load shedder, returning the inner service.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

/// Error returned when a request is shed due to overload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Overloaded(());

impl Overloaded {
    /// Creates a new overloaded error.
    #[must_use]
    pub const fn new() -> Self {
        Self(())
    }
}

impl std::fmt::Display for Overloaded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "service overloaded")
    }
}

impl std::error::Error for Overloaded {}

/// Error returned by the load shedding service.
#[derive(Debug)]
pub enum LoadShedError<E> {
    /// The caller attempted `call()` without a preceding successful `poll_ready()`.
    NotReady,
    /// The load-shed future was polled after it had already completed.
    PolledAfterCompletion,
    /// The service is overloaded and the request was shed.
    Overloaded(Overloaded),
    /// The inner service returned an error.
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for LoadShedError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotReady => write!(f, "poll_ready required before call"),
            Self::PolledAfterCompletion => write!(f, "load shed future polled after completion"),
            Self::Overloaded(e) => write!(f, "{e}"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for LoadShedError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NotReady | Self::PolledAfterCompletion => None,
            Self::Overloaded(e) => Some(e),
            Self::Inner(e) => Some(e),
        }
    }
}

impl<S, Request> Service<Request> for LoadShed<S>
where
    S: Service<Request>,
    S::Future: Unpin,
{
    type Response = S::Response;
    type Error = LoadShedError<S::Error>;
    type Future = LoadShedFuture<S::Future>;

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        self.ready_observed = false;
        self.inner.release_readiness()
    }

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match poll_ready_preserving_self_wake::<S, Request>(&mut self.inner, &mut self.probe, cx) {
            Poll::Ready(Ok(())) => {
                self.overloaded = false;
                self.ready_observed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => {
                self.overloaded = false;
                self.ready_observed = false;
                drop(self.inner.release_readiness());
                Poll::Ready(Err(LoadShedError::Inner(e)))
            }
            Poll::Pending => {
                // Inner service is not ready; mark as overloaded but return Ready
                // so the caller can call us immediately (and we'll shed).
                // Release the inner wait now, not in `call`: a handle that is
                // never called would otherwise keep it, e.g. a queued
                // ConcurrencyLimit acquire at the head of its FIFO semaphore,
                // blocking every later acquirer (br-asupersync-wfch0u).
                self.overloaded = true;
                self.ready_observed = true;
                drop(self.inner.release_readiness());
                Poll::Ready(Ok(()))
            }
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if !std::mem::replace(&mut self.ready_observed, false) {
            return LoadShedFuture::not_ready();
        }

        if self.overloaded {
            // Stay overloaded until `poll_ready` observes the inner service as
            // ready. `poll_ready` already released the inner wait.
            LoadShedFuture::overloaded()
        } else {
            LoadShedFuture::inner(self.inner.call(req))
        }
    }
}

/// Future returned by the [`LoadShed`] service.
pub struct LoadShedFuture<F> {
    state: LoadShedState<F>,
}

enum LoadShedState<F> {
    /// Caller skipped `poll_ready` or reused a consumed readiness window.
    NotReady,
    /// Request was shed due to overload.
    Overloaded,
    /// Request is being processed by the inner service.
    Inner(F),
    /// Future has completed.
    Done,
}

impl<F> LoadShedFuture<F> {
    /// Creates a future that immediately returns a readiness misuse error.
    #[must_use]
    pub fn not_ready() -> Self {
        Self {
            state: LoadShedState::NotReady,
        }
    }

    /// Creates a future that immediately returns an overloaded error.
    #[must_use]
    pub fn overloaded() -> Self {
        Self {
            state: LoadShedState::Overloaded,
        }
    }

    /// Creates a future that wraps the inner service's future.
    #[must_use]
    pub fn inner(future: F) -> Self {
        Self {
            state: LoadShedState::Inner(future),
        }
    }
}

impl<F, T, E> Future for LoadShedFuture<F>
where
    F: Future<Output = Result<T, E>> + Unpin,
{
    type Output = Result<T, LoadShedError<E>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match std::mem::replace(&mut this.state, LoadShedState::Done) {
            LoadShedState::NotReady => Poll::Ready(Err(LoadShedError::NotReady)),
            LoadShedState::Overloaded => {
                Poll::Ready(Err(LoadShedError::Overloaded(Overloaded::new())))
            }
            LoadShedState::Inner(mut future) => match Pin::new(&mut future).poll(cx) {
                Poll::Ready(Ok(response)) => Poll::Ready(Ok(response)),
                Poll::Ready(Err(e)) => Poll::Ready(Err(LoadShedError::Inner(e))),
                Poll::Pending => {
                    this.state = LoadShedState::Inner(future);
                    Poll::Pending
                }
            },
            LoadShedState::Done => Poll::Ready(Err(LoadShedError::PolledAfterCompletion)),
        }
    }
}

impl<F: std::fmt::Debug> std::fmt::Debug for LoadShedFuture<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadShedFuture").finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "load_shed_inline_tests.rs"]
mod tests;
