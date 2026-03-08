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
use parking_lot::Mutex;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
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

// ─── Buffer service ─────────────────────────────────────────────────────────

/// A service that buffers requests via a bounded channel.
///
/// The `Buffer` accepts requests and sends them through a channel to an
/// internal worker that dispatches them to the inner service. This allows
/// the service to be cloned cheaply — all clones share the same buffer
/// and worker.
pub struct Buffer<S> {
    shared: Arc<SharedBuffer<S>>,
    /// Tracks whether this clone is holding a slot reserved by `poll_ready`.
    ready_slot_reserved: bool,
}

struct InnerWakers {
    wakers: Mutex<Vec<std::task::Waker>>,
}

impl std::task::Wake for InnerWakers {
    fn wake(self: Arc<Self>) {
        let wakers = std::mem::take(&mut *self.wakers.lock());
        for w in wakers {
            w.wake();
        }
    }
}

struct SharedBuffer<S> {
    /// The inner service, protected by a mutex for shared access.
    inner: Mutex<S>,
    /// Buffer capacity.
    capacity: usize,
    /// Number of claimed request slots across requests and ready reservations.
    pending: Mutex<usize>,
    /// Whether the buffer has been closed.
    closed: Mutex<bool>,
    /// Wakers waiting for capacity to become available.
    ready_wakers: Mutex<Vec<std::task::Waker>>,
    /// Wakers waiting for the inner service to become ready.
    inner_wakers: Arc<InnerWakers>,
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
                inner_wakers: Arc::new(InnerWakers {
                    wakers: Mutex::new(Vec::new()),
                }),
            }),
            ready_slot_reserved: false,
        }
    }

    /// Returns the buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.capacity
    }

    /// Returns the number of claimed request slots.
    ///
    /// This includes requests already in flight plus any slot reserved by a
    /// successful `poll_ready` that has not yet been consumed by `call`.
    #[must_use]
    pub fn pending(&self) -> usize {
        *self.shared.pending.lock()
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
    ///
    /// Wakes all tasks waiting for capacity or inner-service readiness so they
    /// can observe the closed state and return `BufferError::Closed`.
    pub fn close(&self) {
        *self.shared.closed.lock() = true;
        let ready_wakers = std::mem::take(&mut *self.shared.ready_wakers.lock());
        let inner_wakers = std::mem::take(&mut *self.shared.inner_wakers.wakers.lock());
        for w in ready_wakers {
            w.wake();
        }
        for w in inner_wakers {
            w.wake();
        }
    }

    /// Returns `true` if the buffer has been closed.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        *self.shared.closed.lock()
    }
}

impl<S> Clone for Buffer<S> {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.clone(),
            // Reservations are specific to a single handle; a freshly cloned
            // handle must not inherit a readiness claim from the source clone.
            ready_slot_reserved: false,
        }
    }
}

impl<S> Drop for Buffer<S> {
    fn drop(&mut self) {
        if self.ready_slot_reserved {
            self.ready_slot_reserved = false;
            release_capacity_claim(&self.shared);
        }
    }
}

impl<S> fmt::Debug for Buffer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("capacity", &self.shared.capacity)
            .field("pending", &self.pending())
            .field("ready_slot_reserved", &self.ready_slot_reserved)
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

// ─── Pending guard ──────────────────────────────────────────────────────────

/// RAII guard that decrements `pending` and wakes waiters on drop.
///
/// Used to prevent pending-count leaks when a panic occurs during the
/// `BufferFuture` state machine transitions (where `mem::replace` has
/// already set the state to `Done`).
struct PendingGuard<S> {
    shared: Option<Arc<SharedBuffer<S>>>,
}

fn release_capacity_claim<S>(shared: &SharedBuffer<S>) {
    let mut pending = shared.pending.lock();
    *pending = pending.saturating_sub(1);
    let wakers = std::mem::take(&mut *shared.ready_wakers.lock());
    drop(pending);
    for w in wakers {
        w.wake();
    }
    let inner_wakers = std::mem::take(&mut *shared.inner_wakers.wakers.lock());
    for w in inner_wakers {
        w.wake();
    }
}

impl<S> PendingGuard<S> {
    fn new(shared: Arc<SharedBuffer<S>>) -> Self {
        Self {
            shared: Some(shared),
        }
    }

    /// Defuse the guard, preventing the pending-count decrement on drop.
    ///
    /// Call this after successfully restoring the `BufferFutureState` so
    /// the normal decrement path handles cleanup instead.
    fn defuse(mut self) -> Arc<SharedBuffer<S>> {
        self.shared.take().expect("guard already defused")
    }
}

impl<S> Drop for PendingGuard<S> {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            release_capacity_claim(&shared);
        }
    }
}

// ─── Buffer Future ──────────────────────────────────────────────────────────

/// Future returned by the [`Buffer`] service.
///
/// Resolves to the inner service's response.
pub struct BufferFuture<F, E, S, R> {
    state: BufferFutureState<F, E, S, R>,
}

enum BufferFutureState<F, E, S, R> {
    /// Waiting for the inner service to be ready.
    WaitingForReady {
        request: Option<R>,
        shared: Arc<SharedBuffer<S>>,
    },
    /// Waiting for the inner future.
    Active {
        future: F,
        shared: Arc<SharedBuffer<S>>,
    },
    /// Immediate error (buffer full or closed).
    Error(Option<BufferError<E>>),
    /// Completed.
    Done,
}

impl<F, E, S, R> BufferFuture<F, E, S, R> {
    fn waiting(request: R, shared: Arc<SharedBuffer<S>>) -> Self {
        Self {
            state: BufferFutureState::WaitingForReady {
                request: Some(request),
                shared,
            },
        }
    }

    fn error(err: BufferError<E>) -> Self {
        Self {
            state: BufferFutureState::Error(Some(err)),
        }
    }
}

impl<F, Response, Error, S, R> Future for BufferFuture<F, Error, S, R>
where
    F: Future<Output = Result<Response, Error>> + Unpin,
    S: Service<R, Response = Response, Error = Error, Future = F>,
    Error: Unpin,
    R: Unpin,
{
    type Output = Result<Response, BufferError<Error>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let this = self.as_mut().get_mut();

            let state = std::mem::replace(&mut this.state, BufferFutureState::Done);

            match state {
                BufferFutureState::WaitingForReady {
                    mut request,
                    shared,
                } => {
                    // Guard ensures pending count is decremented even if a
                    // panic occurs during poll_ready / call below.
                    let guard = PendingGuard::new(Arc::clone(&shared));

                    if *shared.closed.lock() {
                        // Guard will handle the decrement + wakeups on drop.
                        drop(guard);
                        return Poll::Ready(Err(BufferError::Closed));
                    }

                    {
                        // Register the caller before polling the inner service with the
                        // fanout waker. Otherwise a readiness edge can race with this
                        // task's registration and be lost.
                        let mut wakers = shared.inner_wakers.wakers.lock();
                        if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
                            wakers.push(cx.waker().clone());
                        }
                    }

                    let mut inner = shared.inner.lock();
                    let waker = std::task::Waker::from(Arc::clone(&shared.inner_wakers));
                    let mut inner_cx = std::task::Context::from_waker(&waker);
                    match inner.poll_ready(&mut inner_cx) {
                        Poll::Ready(Ok(())) => {
                            let req = request.take().unwrap();
                            let future = inner.call(req);
                            drop(inner);

                            let wakers = std::mem::take(&mut *shared.inner_wakers.wakers.lock());
                            for w in wakers {
                                w.wake();
                            }

                            // Defuse: state restored with shared still tracked.
                            let shared = guard.defuse();
                            this.state = BufferFutureState::Active { future, shared };
                            // Loop around to poll Active
                        }
                        Poll::Ready(Err(e)) => {
                            drop(inner);
                            // Guard will handle the decrement + wakeups on drop.
                            drop(guard);
                            this.state = BufferFutureState::Error(Some(BufferError::Inner(e)));
                            // Loop around to poll Error
                        }
                        Poll::Pending => {
                            drop(inner);
                            // Defuse: state restored with shared still tracked.
                            let shared = guard.defuse();
                            this.state = BufferFutureState::WaitingForReady { request, shared };
                            return Poll::Pending;
                        }
                    }
                }
                BufferFutureState::Active { mut future, shared } => {
                    // Guard ensures pending count is decremented even if the
                    // inner future's poll panics.
                    let guard = PendingGuard::new(Arc::clone(&shared));

                    match Pin::new(&mut future).poll(cx) {
                        Poll::Ready(result) => {
                            // Guard will handle the decrement + wakeups on drop.
                            drop(guard);
                            match result {
                                Ok(v) => return Poll::Ready(Ok(v)),
                                Err(e) => return Poll::Ready(Err(BufferError::Inner(e))),
                            }
                        }
                        Poll::Pending => {
                            // Defuse: state restored with shared still tracked.
                            let shared = guard.defuse();
                            this.state = BufferFutureState::Active { future, shared };
                            return Poll::Pending;
                        }
                    }
                }
                BufferFutureState::Error(mut err) => {
                    let err = err.take().expect("polled after completion");
                    return Poll::Ready(Err(err));
                }
                BufferFutureState::Done => {
                    panic!("BufferFuture polled after completion")
                }
            }
        }
    }
}

impl<F, E, S, R> Drop for BufferFuture<F, E, S, R> {
    fn drop(&mut self) {
        match &mut self.state {
            BufferFutureState::WaitingForReady { shared, .. }
            | BufferFutureState::Active { shared, .. } => {
                release_capacity_claim(shared);
            }
            _ => {}
        }
    }
}

impl<F, E, S, R> fmt::Debug for BufferFuture<F, E, S, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = match &self.state {
            BufferFutureState::WaitingForReady { .. } => "WaitingForReady",
            BufferFutureState::Active { .. } => "Active",
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
    type Future = BufferFuture<S::Future, S::Error, S, Request>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if *self.shared.closed.lock() {
            return Poll::Ready(Err(BufferError::Closed));
        }
        if self.ready_slot_reserved {
            return Poll::Ready(Ok(()));
        }
        // Lock ordering is pending -> ready_wakers everywhere to avoid inversion
        // with completion/drop paths that decrement pending then wake waiters.
        let mut pending = self.shared.pending.lock();
        if *pending >= self.shared.capacity {
            let mut wakers = self.shared.ready_wakers.lock();
            if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
                wakers.push(cx.waker().clone());
            }
            drop(wakers);
            drop(pending);
            Poll::Pending
        } else {
            *pending += 1;
            drop(pending);
            self.ready_slot_reserved = true;
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if *self.shared.closed.lock() {
            if self.ready_slot_reserved {
                self.ready_slot_reserved = false;
                release_capacity_claim(&self.shared);
            }
            return BufferFuture::error(BufferError::Closed);
        }

        if self.ready_slot_reserved {
            self.ready_slot_reserved = false;
            return BufferFuture::waiting(req, self.shared.clone());
        }

        {
            let mut pending = self.shared.pending.lock();
            if *pending >= self.shared.capacity {
                return BufferFuture::error(BufferError::Full);
            }
            *pending += 1;
        }

        BufferFuture::waiting(req, self.shared.clone())
    }
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

    struct NoopWaker;

    impl std::task::Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
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
        let err = BufferFuture::<
            std::future::Ready<Result<i32, std::convert::Infallible>>,
            std::convert::Infallible,
            EchoService,
            i32,
        >::error(BufferError::Full);
        let dbg = format!("{err:?}");
        assert!(dbg.contains("BufferFuture"));
        assert!(dbg.contains("Error"));
    }

    #[test]
    fn buffer_future_error_debug() {
        let future = BufferFuture::<
            std::future::Ready<Result<i32, std::convert::Infallible>>,
            std::convert::Infallible,
            EchoService,
            i32,
        >::error(BufferError::Full);
        let dbg = format!("{future:?}");
        assert!(dbg.contains("Error"));
    }

    #[test]
    #[should_panic(expected = "polled after completion")]
    fn buffer_future_panics_when_polled_after_completion() {
        let future = BufferFuture::<
            std::future::Ready<Result<i32, std::convert::Infallible>>,
            std::convert::Infallible,
            EchoService,
            i32,
        >::error(BufferError::Full);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut future = future;
        let _ = Pin::new(&mut future).poll(&mut cx);
        let _ = Pin::new(&mut future).poll(&mut cx); // should panic
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

    #[test]
    fn poll_ready_deduplicates_waker_when_full() {
        init_test("poll_ready_deduplicates_waker_when_full");
        let mut svc = Buffer::new(EchoService, 1);
        *svc.shared.pending.lock() = 1;

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(svc.poll_ready(&mut cx).is_pending());
        assert_eq!(svc.shared.ready_wakers.lock().len(), 1);

        assert!(svc.poll_ready(&mut cx).is_pending());
        assert_eq!(svc.shared.ready_wakers.lock().len(), 1);
        crate::test_complete!("poll_ready_deduplicates_waker_when_full");
    }

    #[test]
    fn poll_ready_reserves_slot_until_call() {
        init_test("poll_ready_reserves_slot_until_call");
        let mut svc = Buffer::new(EchoService, 1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(svc.pending(), 1);

        // Re-polling the same handle must not consume another slot.
        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(svc.pending(), 1);

        let mut future = svc.call(5);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(10))
        ));
        assert_eq!(svc.pending(), 0);
        crate::test_complete!("poll_ready_reserves_slot_until_call");
    }

    #[test]
    fn poll_ready_reservation_blocks_other_clones() {
        init_test("poll_ready_reservation_blocks_other_clones");
        let mut holder = Buffer::new(EchoService, 1);
        let mut waiter = holder.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(holder.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(holder.pending(), 1);
        assert!(waiter.poll_ready(&mut cx).is_pending());

        let mut future = holder.call(11);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(22))
        ));
        assert_eq!(waiter.pending(), 0);
        crate::test_complete!("poll_ready_reservation_blocks_other_clones");
    }

    #[test]
    fn reserved_slot_prevents_clone_from_stealing_capacity() {
        init_test("reserved_slot_prevents_clone_from_stealing_capacity");
        let mut ready_holder = Buffer::new(EchoService, 1);
        let mut thief = ready_holder.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            ready_holder.poll_ready(&mut cx),
            Poll::Ready(Ok(()))
        ));

        let mut stolen = thief.call(9);
        assert!(matches!(
            Pin::new(&mut stolen).poll(&mut cx),
            Poll::Ready(Err(BufferError::Full))
        ));

        let mut reserved = ready_holder.call(9);
        assert!(matches!(
            Pin::new(&mut reserved).poll(&mut cx),
            Poll::Ready(Ok(18))
        ));
        crate::test_complete!("reserved_slot_prevents_clone_from_stealing_capacity");
    }

    #[test]
    fn dropping_reserved_clone_releases_capacity() {
        init_test("dropping_reserved_clone_releases_capacity");
        let mut holder = Buffer::new(EchoService, 1);
        let mut waiter = holder.clone();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(holder.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(holder.pending(), 1);

        drop(holder);

        assert!(matches!(waiter.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        let mut future = waiter.call(3);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Ok(6))
        ));
        crate::test_complete!("dropping_reserved_clone_releases_capacity");
    }

    #[test]
    fn call_after_close_releases_reserved_slot() {
        init_test("call_after_close_releases_reserved_slot");
        let mut svc = Buffer::new(EchoService, 1);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(svc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(svc.pending(), 1);

        svc.close();

        let mut future = svc.call(7);
        assert!(matches!(
            Pin::new(&mut future).poll(&mut cx),
            Poll::Ready(Err(BufferError::Closed))
        ));
        assert_eq!(svc.pending(), 0);
        crate::test_complete!("call_after_close_releases_reserved_slot");
    }

    // ================================================================
    // Waker accumulation regression (Bug: last-only dedup)
    // ================================================================

    struct FlagWaker {
        flag: Arc<std::sync::atomic::AtomicBool>,
    }

    impl std::task::Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.flag.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn flag_waker() -> (Waker, Arc<std::sync::atomic::AtomicBool>) {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let waker = Waker::from(Arc::new(FlagWaker { flag: flag.clone() }));
        (waker, flag)
    }

    #[test]
    fn poll_ready_dedup_with_alternating_tasks() {
        init_test("poll_ready_dedup_with_alternating_tasks");
        let mut svc = Buffer::new(EchoService, 1);
        *svc.shared.pending.lock() = 1;

        let (waker_a, _flag_a) = flag_waker();
        let (waker_b, _flag_b) = flag_waker();
        let mut cx_a = Context::from_waker(&waker_a);
        let mut cx_b = Context::from_waker(&waker_b);

        // Two different tasks alternate polling. Waker list should stay at
        // most 2 entries (one per distinct waker), never grow unboundedly.
        for _ in 0..10 {
            assert!(svc.poll_ready(&mut cx_a).is_pending());
            assert!(svc.poll_ready(&mut cx_b).is_pending());
        }
        let waker_count = svc.shared.ready_wakers.lock().len();
        assert!(
            waker_count <= 2,
            "waker list grew to {waker_count}, expected at most 2"
        );
        crate::test_complete!("poll_ready_dedup_with_alternating_tasks");
    }

    // ================================================================
    // Close wakes waiting tasks (Bug: close without wake)
    // ================================================================

    #[test]
    fn close_wakes_tasks_waiting_for_capacity() {
        init_test("close_wakes_tasks_waiting_for_capacity");
        let mut svc = Buffer::new(EchoService, 1);
        *svc.shared.pending.lock() = 1;

        let (waker, flag) = flag_waker();
        let mut cx = Context::from_waker(&waker);

        // Task parks waiting for capacity
        assert!(svc.poll_ready(&mut cx).is_pending());
        assert!(!flag.load(std::sync::atomic::Ordering::SeqCst));

        // Close should wake the parked task
        svc.close();
        assert!(
            flag.load(std::sync::atomic::Ordering::SeqCst),
            "close() must wake tasks waiting for capacity"
        );

        // Re-poll should get Closed error
        let result = svc.poll_ready(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(BufferError::Closed))));
        crate::test_complete!("close_wakes_tasks_waiting_for_capacity");
    }

    #[test]
    fn close_wakes_tasks_waiting_for_inner_ready() {
        init_test("close_wakes_tasks_waiting_for_inner_ready");
        let mut svc = Buffer::new(NeverReadyService, 4);

        let (waker, flag) = flag_waker();
        let mut cx = Context::from_waker(&waker);

        // Submit a request and poll the future, causing it to park in
        // WaitingForReady because NeverReadyService returns Pending.
        let _ = svc.poll_ready(&mut cx);
        let mut future = svc.call(1);
        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert!(!flag.load(std::sync::atomic::Ordering::SeqCst));

        // Close should wake the future
        svc.close();
        assert!(
            flag.load(std::sync::atomic::Ordering::SeqCst),
            "close() must wake tasks waiting for inner readiness"
        );

        // Re-poll should get Closed error
        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Err(BufferError::Closed))));
        crate::test_complete!("close_wakes_tasks_waiting_for_inner_ready");
    }

    struct SingleWakerService {
        waker: Mutex<Option<std::task::Waker>>,
        ready: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Service<i32> for SingleWakerService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.ready.load(std::sync::atomic::Ordering::SeqCst) {
                Poll::Ready(Ok(()))
            } else {
                *self.waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            }
        }

        fn call(&mut self, req: i32) -> Self::Future {
            std::future::ready(Ok(req))
        }
    }

    struct WakeDuringPollReadyService {
        woke_once: bool,
    }

    impl Service<i32> for WakeDuringPollReadyService {
        type Response = i32;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<i32, std::convert::Infallible>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.woke_once {
                Poll::Ready(Ok(()))
            } else {
                self.woke_once = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }

        fn call(&mut self, req: i32) -> Self::Future {
            std::future::ready(Ok(req))
        }
    }

    #[test]
    fn buffer_lost_wakeup() {
        init_test("buffer_lost_wakeup");
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let inner = SingleWakerService {
            waker: Mutex::new(None),
            ready: ready.clone(),
        };

        let mut svc = Buffer::new(inner, 10);
        let dummy_waker = noop_waker();
        let mut cx_dummy = Context::from_waker(&dummy_waker);
        let _ = svc.poll_ready(&mut cx_dummy);

        let mut fut1 = svc.call(1);
        let mut fut2 = svc.call(2);

        let (waker1, flag1) = flag_waker();
        let mut cx1 = Context::from_waker(&waker1);

        let (waker2, _flag2) = flag_waker();
        let mut cx2 = Context::from_waker(&waker2);

        // fut1 polls, registers waker1 with inner service
        assert!(Pin::new(&mut fut1).poll(&mut cx1).is_pending());

        // fut2 polls, overwrites waker in inner service with waker2
        assert!(Pin::new(&mut fut2).poll(&mut cx2).is_pending());

        // fut2 is dropped!
        drop(fut2);

        // inner service becomes ready and wakes the registered waker (waker2)
        ready.store(true, std::sync::atomic::Ordering::SeqCst);
        let guard = svc.shared.inner.lock();
        let waker = guard.waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
        drop(guard);

        // Now, is fut1 woken?
        assert!(
            flag1.load(std::sync::atomic::Ordering::SeqCst),
            "LOST WAKEUP! fut1 was not woken when fut2 was dropped"
        );

        crate::test_complete!("buffer_lost_wakeup");
    }

    #[test]
    fn buffer_wake_during_poll_ready_is_not_lost() {
        init_test("buffer_wake_during_poll_ready_is_not_lost");

        let mut svc = Buffer::new(WakeDuringPollReadyService { woke_once: false }, 4);
        let dummy_waker = noop_waker();
        let mut dummy_cx = Context::from_waker(&dummy_waker);
        assert!(matches!(svc.poll_ready(&mut dummy_cx), Poll::Ready(Ok(()))));

        let mut future = svc.call(7);
        let (waker, flag) = flag_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
        assert!(
            flag.load(std::sync::atomic::Ordering::SeqCst),
            "wake emitted during inner poll_ready must reach the waiting buffer future"
        );

        let result = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(result, Poll::Ready(Ok(7))));

        crate::test_complete!("buffer_wake_during_poll_ready_is_not_lost");
    }
}
