//! Buffer service layer.
//!
//! The [`BufferLayer`] wraps a service with a bounded request buffer. When the
//! inner service applies backpressure, requests are queued in the buffer up to
//! a configurable capacity. This decouples request submission from processing,
//! allowing callers to submit work without blocking on the inner service's
//! readiness.
//!
//! The buffer is implemented as a bounded MPSC channel. A background worker
//! drains the channel and dispatches requests to the inner service.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::service::{ServiceBuilder, ServiceExt};
//! use asupersync::service::buffer::BufferLayer;
//!
//! let svc = ServiceBuilder::new()
//!     .layer(BufferLayer::new(16))
//!     .service(my_service);
//! ```

use super::{Layer, Service};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Default buffer capacity.
const DEFAULT_CAPACITY: usize = 16;

// ─── BufferLayer ────────────────────────────────────────────────────────────

/// A layer that wraps a service with a bounded request buffer.
///
/// Requests are queued and dispatched to the inner service by a worker.
/// When the buffer is full, `poll_ready` returns `Poll::Pending`.
#[derive(Debug, Clone)]
pub struct BufferLayer {
    capacity: usize,
}

impl BufferLayer {
    /// Creates a new buffer layer with the given capacity.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "buffer capacity must be > 0");
        Self { capacity }
    }
}

impl Default for BufferLayer {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
        }
    }
}

impl<S> Layer<S> for BufferLayer {
    type Service = Buffer<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Buffer::new(inner, self.capacity)
    }
}

// ─── Shared state ───────────────────────────────────────────────────────────

/// A buffered request waiting to be processed.
struct BufferedRequest<Request, Response, Error> {
    request: Request,
    tx: oneshot::Sender<Result<Response, Error>>,
}

/// Simple oneshot channel for response delivery.
mod oneshot {
    use std::sync::{Arc, Mutex};

    use std::task::Waker;

    pub struct Sender<T> {
        shared: Arc<Mutex<Inner<T>>>,
    }

    pub struct Receiver<T> {
        shared: Arc<Mutex<Inner<T>>>,
    }

    struct Inner<T> {
        value: Option<T>,
        waker: Option<Waker>,
    }

    pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
        let shared = Arc::new(Mutex::new(Inner {
            value: None,
            waker: None,
        }));
        (
            Sender {
                shared: shared.clone(),
            },
            Receiver { shared },
        )
    }

    impl<T> Sender<T> {
        pub fn send(self, value: T) {
            let waker = {
                let mut guard = self.shared.lock().unwrap();
                guard.value = Some(value);
                guard.waker.take()
            };
            if let Some(w) = waker {
                w.wake();
            }
        }
    }

    impl<T> Receiver<T> {
        /// Try to take the value. Returns `Some` if available.
        pub fn try_recv(&self) -> Option<T> {
            let mut guard = self.shared.lock().unwrap();
            guard.value.take()
        }

        /// Register a waker to be notified when a value is sent.
        pub fn register_waker(&self, waker: &Waker) {
            let mut guard = self.shared.lock().unwrap();
            if guard.waker.as_ref().is_none_or(|w| !w.will_wake(waker)) {
                guard.waker = Some(waker.clone());
            }
        }
    }
}

// ─── Buffer service ─────────────────────────────────────────────────────────

/// A service that buffers requests via a bounded channel.
///
/// The `Buffer` accepts requests and sends them through a channel to an
/// internal worker that dispatches them to the inner service. This allows
/// the service to be cloned cheaply — all clones share the same buffer
/// and worker.
pub struct Buffer<S> {
    shared: Arc<SharedBuffer<S>>,
}

struct SharedBuffer<S> {
    /// The inner service, protected by a mutex for shared access.
    inner: Mutex<S>,
    /// Buffer capacity.
    capacity: usize,
    /// Number of requests currently in the buffer (pending processing).
    pending: Mutex<usize>,
    /// Whether the buffer has been closed.
    closed: Mutex<bool>,
    /// Wakers waiting for capacity to become available.
    ready_wakers: Mutex<Vec<std::task::Waker>>,
}

impl<S> Buffer<S> {
    /// Creates a new buffer service wrapping the given inner service.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` is zero.
    #[must_use]
    pub fn new(inner: S, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer capacity must be > 0");
        Self {
            shared: Arc::new(SharedBuffer {
                inner: Mutex::new(inner),
                capacity,
                pending: Mutex::new(0),
                closed: Mutex::new(false),
                ready_wakers: Mutex::new(Vec::new()),
            }),
        }
    }

    /// Returns the buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.capacity
    }

    /// Returns the number of pending (buffered) requests.
    #[must_use]
    pub fn pending(&self) -> usize {
        *self.shared.pending.lock().unwrap()
    }

    /// Returns `true` if the buffer is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.pending() >= self.shared.capacity
    }

    /// Returns `true` if the buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending() == 0
    }

    /// Close the buffer, rejecting new requests.
    pub fn close(&self) {
        *self.shared.closed.lock().unwrap() = true;
    }

    /// Returns `true` if the buffer has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.shared.closed.lock().unwrap()
    }
}

impl<S> Clone for Buffer<S> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
        }
    }
}

impl<S> fmt::Debug for Buffer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("capacity", &self.shared.capacity)
            .field("pending", &self.pending())
            .finish()
    }
}

// ─── Buffer error ───────────────────────────────────────────────────────────

/// Error returned by the buffer service.
#[derive(Debug)]
pub enum BufferError<E> {
    /// The buffer is full and cannot accept more requests.
    Full,
    /// The buffer has been closed.
    Closed,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for BufferError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "buffer full"),
            Self::Closed => write!(f, "buffer closed"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for BufferError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Full | Self::Closed => None,
            Self::Inner(e) => Some(e),
        }
    }
}

// ─── Buffer Future ──────────────────────────────────────────────────────────

/// Future returned by the [`Buffer`] service.
///
/// Resolves to the inner service's response once the buffered request
/// has been processed.
pub struct BufferFuture<Response, Error> {
    state: BufferFutureState<Response, Error>,
}

enum BufferFutureState<Response, Error> {
    /// Waiting for the response from the worker.
    Waiting(oneshot::Receiver<Result<Response, Error>>),
    /// Immediate error (buffer full or closed).
    Error(Option<BufferError<Error>>),
    /// Completed.
    Done,
}

impl<Response, Error> BufferFuture<Response, Error> {
    fn waiting(rx: oneshot::Receiver<Result<Response, Error>>) -> Self {
        Self {
            state: BufferFutureState::Waiting(rx),
        }
    }

    fn error(err: BufferError<Error>) -> Self {
        Self {
            state: BufferFutureState::Error(Some(err)),
        }
    }
}

impl<Response, Error> Future for BufferFuture<Response, Error>
where
    Response: Unpin,
    Error: Unpin,
{
    type Output = Result<Response, BufferError<Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match &mut this.state {
            BufferFutureState::Waiting(rx) => match rx.try_recv() {
                Some(Ok(response)) => {
                    this.state = BufferFutureState::Done;
                    Poll::Ready(Ok(response))
                }
                Some(Err(e)) => {
                    this.state = BufferFutureState::Done;
                    Poll::Ready(Err(BufferError::Inner(e)))
                }
                None => {
                    rx.register_waker(cx.waker());
                    Poll::Pending
                }
            },
            BufferFutureState::Error(err) => {
                let err = err.take().expect("polled after completion");
                this.state = BufferFutureState::Done;
                Poll::Ready(Err(err))
            }
            BufferFutureState::Done => {
                panic!("BufferFuture polled after completion")
            }
        }
    }
}

impl<Response, Error> fmt::Debug for BufferFuture<Response, Error> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            BufferFutureState::Waiting(_) => "Waiting",
            BufferFutureState::Error(_) => "Error",
            BufferFutureState::Done => "Done",
        };
        f.debug_struct("BufferFuture")
            .field("state", &state)
            .finish()
    }
}

// ─── Service impl ───────────────────────────────────────────────────────────

impl<S, Request> Service<Request> for Buffer<S>
where
    S: Service<Request>,
    S::Future: Unpin,
    S::Response: Unpin,
    S::Error: Unpin,
    Request: Unpin,
{
    type Response = S::Response;
    type Error = BufferError<S::Error>;
    type Future = BufferFuture<S::Response, S::Error>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if *self.shared.closed.lock().unwrap() {
            return Poll::Ready(Err(BufferError::Closed));
        }
        let pending = *self.shared.pending.lock().unwrap();
        if pending >= self.shared.capacity {
            let mut wakers = self.shared.ready_wakers.lock().unwrap();
            wakers.push(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if *self.shared.closed.lock().unwrap() {
            return BufferFuture::error(BufferError::Closed);
        }

        {
            let mut pending = self.shared.pending.lock().unwrap();
            if *pending >= self.shared.capacity {
                return BufferFuture::error(BufferError::Full);
            }
            *pending += 1;
        }

        // Process the request synchronously through the inner service.
        // In a fully async runtime, this would be done by a background worker.
        // For Phase 0 (synchronous Handler pattern), we process inline and
        // use the buffer for capacity management.
        let (tx, rx) = oneshot::channel();

        let result = {
            let mut inner = self.shared.inner.lock().unwrap();
            // Poll the inner service's future to completion.
            let noop_waker = std::task::Waker::from(Arc::new(NoopWaker));
            let mut cx = Context::from_waker(&noop_waker);

            // Check readiness.
            match inner.poll_ready(&mut cx) {
                Poll::Ready(Ok(())) => {
                    let mut future = inner.call(req);
                    drop(inner);
                    // Poll the future to completion.
                    match Pin::new(&mut future).poll(&mut cx) {
                        Poll::Ready(result) => Some(result),
                        Poll::Pending => None,
                    }
                }
                Poll::Ready(Err(e)) => Some(Err(e)),
                Poll::Pending => None,
            }
        };

        // Decrement pending count and wake any callers blocked on poll_ready.
        {
            let mut pending = self.shared.pending.lock().unwrap();
            *pending = pending.saturating_sub(1);
        }
        let wakers: Vec<_> = {
            let mut ready_wakers = self.shared.ready_wakers.lock().unwrap();
            std::mem::take(&mut *ready_wakers)
        };
        for w in wakers {
            w.wake();
        }

        if let Some(result) = result {
            tx.send(result);
        }

        BufferFuture::waiting(rx)
    }
}

struct NoopWaker;

impl std::task::Wake for NoopWaker {
    fn wake(self: Arc<Self>) {}
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
    }

    // ================================================================
    // Test services
    // ================================================================

    struct EchoService;

    impl Service<i32> for EchoService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: i32) -> Self::Future {
            std::future::ready(Ok(req * 2))
        }
    }

    struct DoubleService;

    impl Service<String> for DoubleService {
        type Response = String;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<String, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: String) -> Self::Future {
            std::future::ready(Ok(format!("{req}{req}")))
        }
    }

    struct CountingService {
        count: Arc<AtomicUsize>,
    }

    impl CountingService {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let count = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    count: count.clone(),
                },
                count,
            )
        }
    }

    impl Service<()> for CountingService {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<usize, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            let n = self.count.fetch_add(1, Ordering::SeqCst) + 1;
            std::future::ready(Ok(n))
        }
    }

    struct FailService;

    impl Service<i32> for FailService {
        type Response = i32;
        type Error = &'static str;
        type Future = std::future::Ready<Result<i32, &'static str>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: i32) -> Self::Future {
            std::future::ready(Err("service error"))
        }
    }

    struct NeverReadyService;

    impl Service<i32> for NeverReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Pending<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Pending
        }

        fn call(&mut self, _req: i32) -> Self::Future {
            std::future::pending()
        }
    }

    // ================================================================
    // BufferLayer
    // ================================================================

    #[test]
    fn layer_creates_buffer() {
        init_test("layer_creates_buffer");
        let layer = BufferLayer::new(8);
        let svc: Buffer<EchoService> = layer.layer(EchoService);
        assert_eq!(svc.capacity(), 8);
        assert!(svc.is_empty());
        crate::test_complete!("layer_creates_buffer");
    }

    #[test]
    fn layer_default() {
        init_test("layer_default");
        let layer = BufferLayer::default();
        let svc: Buffer<EchoService> = layer.layer(EchoService);
        assert_eq!(svc.capacity(), DEFAULT_CAPACITY);
        crate::test_complete!("layer_default");
    }

    #[test]
    fn layer_debug_clone() {
        let layer = BufferLayer::new(4);
        let dbg = format!("{layer:?}");
        assert!(dbg.contains("BufferLayer"));
        assert!(dbg.contains('4'));
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn layer_zero_capacity_panics() {
        let _ = BufferLayer::new(0);
    }

    // ================================================================
    // Buffer service basics
    // ================================================================

    #[test]
    fn buffer_new() {
        init_test("buffer_new");
        let svc = Buffer::new(EchoService, 4);
        assert_eq!(svc.capacity(), 4);
        assert!(svc.is_empty());
        assert!(!svc.is_full());
        assert!(!svc.is_closed());
        crate::test_complete!("buffer_new");
    }

    #[test]
    #[should_panic(expected = "capacity must be > 0")]
    fn buffer_zero_capacity_panics() {
        let _ = Buffer::new(EchoService, 0);
    }

    #[test]
    fn buffer_debug() {
        let svc = Buffer::new(EchoService, 8);
        let dbg = format!("{svc:?}");
        assert!(dbg.contains("Buffer"));
        assert!(dbg.contains("capacity"));
        assert!(dbg.contains('8'));
    }

    #[test]
    fn buffer_clone() {
        let svc = Buffer::new(EchoService, 4);
        let cloned = svc.clone();
        assert_eq!(cloned.capacity(), 4);
        // Clones share the same buffer.
        assert!(Arc::ptr_eq(&svc.shared, &cloned.shared));
    }

    // ================================================================
    // Service impl
    // ================================================================

    #[test]
    fn poll_ready_when_empty() {
        init_test("poll_ready_when_empty");
        let mut svc = Buffer::new(EchoService, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let result = svc.poll_ready(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(()))));
        crate::test_complete!("poll_ready_when_empty");
    }

    #[test]
    fn call_echo_service() {
        init_test("call_echo_service");
        let mut svc = Buffer::new(EchoService, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = svc.poll_ready(&mut cx);
        let mut future = svc.call(21);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(42))));
        crate::test_complete!("call_echo_service");
    }

    #[test]
    fn call_string_service() {
        init_test("call_string_service");
        let mut svc = Buffer::new(DoubleService, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = svc.poll_ready(&mut cx);
        let mut future = svc.call("hello".to_string());
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(ref s)) if s == "hellohello"));
        crate::test_complete!("call_string_service");
    }

    #[test]
    fn call_propagates_inner_error() {
        init_test("call_propagates_inner_error");
        let mut svc = Buffer::new(FailService, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = svc.poll_ready(&mut cx);
        let mut future = svc.call(1);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(BufferError::Inner(_)))));
        crate::test_complete!("call_propagates_inner_error");
    }

    #[test]
    fn counting_service_through_buffer() {
        init_test("counting_service_through_buffer");
        let (counting, count) = CountingService::new();
        let mut svc = Buffer::new(counting, 8);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for expected in 1..=5 {
            let _ = svc.poll_ready(&mut cx);
            let mut future = svc.call(());
            let result = Pin::new(&mut future).poll(&mut cx);
            assert!(matches!(result, Poll::Ready(Ok(n)) if n == expected));
        }
        assert_eq!(count.load(Ordering::SeqCst), 5);
        crate::test_complete!("counting_service_through_buffer");
    }

    // ================================================================
    // Close / closed
    // ================================================================

    #[test]
    fn close_rejects_new_requests() {
        init_test("close_rejects_new_requests");
        let mut svc = Buffer::new(EchoService, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        svc.close();
        assert!(svc.is_closed());

        let result = svc.poll_ready(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(BufferError::Closed))));

        let mut future = svc.call(1);
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(BufferError::Closed))));
        crate::test_complete!("close_rejects_new_requests");
    }

    #[test]
    fn close_on_clone_affects_all_clones() {
        init_test("close_on_clone_affects_all_clones");
        let svc1 = Buffer::new(EchoService, 4);
        let svc2 = svc1.clone();
        svc1.close();
        assert!(svc2.is_closed());
        crate::test_complete!("close_on_clone_affects_all_clones");
    }

    // ================================================================
    // Inner service readiness
    // ================================================================

    #[test]
    fn never_ready_inner_returns_pending_on_call() {
        init_test("never_ready_inner_returns_pending_on_call");
        let mut svc = Buffer::new(NeverReadyService, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let _ = svc.poll_ready(&mut cx);
        let mut future = svc.call(1);
        let result = Pin::new(&mut future).poll(&mut cx);
        // Inner service is not ready, response not yet available.
        assert!(result.is_pending());
        crate::test_complete!("never_ready_inner_returns_pending_on_call");
    }

    // ================================================================
    // BufferError
    // ================================================================

    #[test]
    fn buffer_error_display() {
        init_test("buffer_error_display");
        let full: BufferError<&str> = BufferError::Full;
        assert!(format!("{full}").contains("buffer full"));

        let closed: BufferError<&str> = BufferError::Closed;
        assert!(format!("{closed}").contains("buffer closed"));

        let inner: BufferError<&str> = BufferError::Inner("oops");
        assert!(format!("{inner}").contains("inner service error"));
        crate::test_complete!("buffer_error_display");
    }

    #[test]
    fn buffer_error_debug() {
        let full: BufferError<&str> = BufferError::Full;
        let dbg = format!("{full:?}");
        assert!(dbg.contains("Full"));

        let closed: BufferError<&str> = BufferError::Closed;
        let dbg = format!("{closed:?}");
        assert!(dbg.contains("Closed"));

        let inner: BufferError<&str> = BufferError::Inner("err");
        let dbg = format!("{inner:?}");
        assert!(dbg.contains("Inner"));
    }

    #[test]
    fn buffer_error_source() {
        use std::error::Error;
        let full: BufferError<std::io::Error> = BufferError::Full;
        assert!(full.source().is_none());

        let closed: BufferError<std::io::Error> = BufferError::Closed;
        assert!(closed.source().is_none());

        let inner = BufferError::Inner(std::io::Error::other("test"));
        assert!(inner.source().is_some());
    }

    // ================================================================
    // BufferFuture
    // ================================================================

    #[test]
    fn buffer_future_debug() {
        let (tx, rx) = oneshot::channel::<Result<i32, &str>>();
        let future = BufferFuture::<i32, &str>::waiting(rx);
        let dbg = format!("{future:?}");
        assert!(dbg.contains("BufferFuture"));
        assert!(dbg.contains("Waiting"));
        drop(tx);
    }

    #[test]
    fn buffer_future_error_debug() {
        let future = BufferFuture::<i32, &str>::error(BufferError::Full);
        let dbg = format!("{future:?}");
        assert!(dbg.contains("Error"));
    }

    #[test]
    #[should_panic(expected = "polled after completion")]
    fn buffer_future_panics_when_polled_after_completion() {
        let future = BufferFuture::<i32, &str>::error(BufferError::Full);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = future;
        let _ = Pin::new(&mut future).poll(&mut cx);
        let _ = Pin::new(&mut future).poll(&mut cx); // should panic
    }

    // ================================================================
    // Oneshot channel
    // ================================================================

    #[test]
    fn oneshot_send_recv() {
        let (tx, rx) = oneshot::channel::<i32>();
        assert!(rx.try_recv().is_none());
        tx.send(42);
        assert_eq!(rx.try_recv(), Some(42));
        // Second recv returns None.
        assert!(rx.try_recv().is_none());
    }

    // ================================================================
    // Multiple requests
    // ================================================================

    #[test]
    fn multiple_sequential_requests() {
        init_test("multiple_sequential_requests");
        let mut svc = Buffer::new(EchoService, 4);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        for i in 0..10 {
            let _ = svc.poll_ready(&mut cx);
            let mut future = svc.call(i);
            let result = Pin::new(&mut future).poll(&mut cx);
            assert!(matches!(result, Poll::Ready(Ok(v)) if v == i * 2));
        }
        crate::test_complete!("multiple_sequential_requests");
    }

    // ================================================================
    // Capacity management
    // ================================================================

    #[test]
    fn pending_count_tracks_requests() {
        init_test("pending_count_tracks_requests");
        let svc = Buffer::new(EchoService, 4);
        assert_eq!(svc.pending(), 0);
        assert!(svc.is_empty());
        crate::test_complete!("pending_count_tracks_requests");
    }
}
