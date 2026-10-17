//! Buffer service layer.
//!
//! The [`BufferLayer`] wraps a service with bounded concurrent in-flight capacity.
//! When the buffer capacity is reached, `poll_ready` returns `Poll::Pending` until
//! active requests complete and release their slots.
//!
//! Unlike Tower's MPSC-channel worker design, this layer uses a slot-counted
//! coordinator with direct polling on the inner service, retaining slots until
//! response completion to bound in-flight load without detached worker threads.
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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

/// Default buffer capacity.
const DEFAULT_CAPACITY: usize = 16;

// ─── BufferLayer ────────────────────────────────────────────────────────────

/// A layer that wraps a service with a bounded request buffer.
///
/// Bounded slots are acquired on readiness and held until the request completes.
/// When all slots are in use, `poll_ready` returns `Poll::Pending`.
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
    ready_reserved: bool,
    ready_waiting: bool,
    readiness_owner: Arc<()>,
}

struct SharedBuffer<S> {
    /// The inner service, protected by a mutex for shared access.
    inner: Mutex<S>,
    /// Buffer capacity.
    capacity: usize,
    /// Occupied capacity. `pending` tracks admitted requests; `reserved` tracks
    /// readiness windows that have been granted but not yet consumed by `call`.
    slots: Mutex<SlotCounts>,
    /// Whether the buffer has been closed.
    closed: Mutex<bool>,
    /// Wakers waiting for capacity to become available.
    ready_wakers: Mutex<Vec<CapacityWaiter>>,
    /// Wakers waiting for the inner service to become ready.
    inner_wakers: Mutex<Vec<std::task::Waker>>,
    /// Admitted futures that have not dispatched to the shared inner service.
    waiting_for_ready: AtomicUsize,
}

#[derive(Default)]
struct SlotCounts {
    pending: usize,
    reserved: usize,
}

struct CapacityWaiter {
    waker: Waker,
    owners: Vec<Arc<()>>,
}

fn register_capacity_waiter(waiters: &mut Vec<CapacityWaiter>, owner: &Arc<()>, waker: &Waker) {
    if let Some(waiter) = waiters
        .iter_mut()
        .find(|waiter| waiter.waker.will_wake(waker))
    {
        if !waiter
            .owners
            .iter()
            .any(|existing| Arc::ptr_eq(existing, owner))
        {
            waiter.owners.push(Arc::clone(owner));
        }
    } else {
        waiters.push(CapacityWaiter {
            waker: waker.clone(),
            owners: vec![Arc::clone(owner)],
        });
    }
}

fn remove_capacity_waiter(waiters: &mut Vec<CapacityWaiter>, owner: &Arc<()>) -> Vec<Waker> {
    let mut retired = Vec::new();
    let mut index = 0;
    while index < waiters.len() {
        waiters[index]
            .owners
            .retain(|existing| !Arc::ptr_eq(existing, owner));
        if waiters[index].owners.is_empty() {
            retired.push(waiters.swap_remove(index).waker);
        } else {
            index += 1;
        }
    }
    retired
}

impl SlotCounts {
    fn occupied(&self) -> usize {
        self.pending + self.reserved
    }
}

fn push_waker_if_new(wakers: &mut Vec<Waker>, waker: &Waker) {
    if wakers.iter().all(|existing| !existing.will_wake(waker)) {
        wakers.push(waker.clone());
    }
}

fn release_pending_capacity<S>(shared: &SharedBuffer<S>) {
    let mut slots = shared.slots.lock();
    slots.pending = slots.pending.saturating_sub(1);
    let ready_wakers = std::mem::take(&mut *shared.ready_wakers.lock());
    let inner_wakers = std::mem::take(&mut *shared.inner_wakers.lock());
    drop(slots);
    for waiter in ready_wakers {
        waiter.waker.wake();
    }
    for waker in inner_wakers {
        waker.wake();
    }
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
                slots: Mutex::new(SlotCounts::default()),
                closed: Mutex::new(false),
                ready_wakers: Mutex::new(Vec::new()),
                inner_wakers: Mutex::new(Vec::new()),
                waiting_for_ready: AtomicUsize::new(0),
            }),
            ready_reserved: false,
            ready_waiting: false,
            readiness_owner: Arc::new(()),
        }
    }

    fn detach_readiness(&mut self) -> super::ReadinessRelease {
        let reserved = std::mem::replace(&mut self.ready_reserved, false);
        let waiting = std::mem::replace(&mut self.ready_waiting, false);
        if !reserved && !waiting {
            return super::ReadinessRelease::default();
        }
        let wakers = {
            let mut slots = self.shared.slots.lock();
            let mut waiters = self.shared.ready_wakers.lock();
            if reserved {
                slots.reserved = slots.reserved.saturating_sub(1);
                std::mem::take(&mut *waiters)
                    .into_iter()
                    .map(|waiter| waiter.waker)
                    .collect()
            } else {
                remove_capacity_waiter(&mut waiters, &self.readiness_owner)
            }
        };
        // An unused slot wakes peers; an abandoned wait only drops its own
        // detached wakers. Neither callback runs under a coordinator lock.
        super::ReadinessRelease::new(move || {
            if reserved {
                for waker in wakers {
                    waker.wake();
                }
            } else {
                drop(wakers);
            }
        })
    }

    /// Returns the buffer capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.shared.capacity
    }

    /// Returns the number of pending (buffered) requests.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.shared.slots.lock().pending
    }

    /// Returns `true` if the buffer is full.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.shared.slots.lock().occupied() >= self.shared.capacity
    }

    /// Returns `true` if the buffer has no admitted requests or reserved
    /// readiness windows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shared.slots.lock().occupied() == 0
    }

    /// Close the buffer, rejecting new requests.
    ///
    /// Wakes all tasks currently parked in `poll_ready` so they observe the
    /// closed state and return `BufferError::Closed`.
    pub fn close(&self) {
        *self.shared.closed.lock() = true;
        let waiters = std::mem::take(&mut *self.shared.ready_wakers.lock());
        for waiter in waiters {
            waiter.waker.wake();
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
            ready_reserved: false,
            ready_waiting: false,
            readiness_owner: Arc::new(()),
        }
    }
}

impl<S> Drop for Buffer<S> {
    fn drop(&mut self) {
        drop(self.detach_readiness());
    }
}

impl<S> fmt::Debug for Buffer<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("capacity", &self.shared.capacity)
            .field("pending", &self.pending())
            .field("ready_reserved", &self.ready_reserved)
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
    /// The future was polled after it had already completed.
    PolledAfterCompletion,
    /// The inner service returned an error.
    Inner(E),
}

impl<E: fmt::Display> fmt::Display for BufferError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "buffer full"),
            Self::Closed => write!(f, "buffer closed"),
            Self::PolledAfterCompletion => write!(f, "buffer future polled after completion"),
            Self::Inner(e) => write!(f, "inner service error: {e}"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for BufferError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Full | Self::Closed | Self::PolledAfterCompletion => None,
            Self::Inner(e) => Some(e),
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
        readiness: InnerReadiness<S>,
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
    fn waiting(request: R, shared: Arc<SharedBuffer<S>>) -> Self
    where
        S: Service<R>,
    {
        shared.waiting_for_ready.fetch_add(1, Ordering::AcqRel);
        let readiness = InnerReadiness {
            shared: Arc::clone(&shared),
            release: <S as Service<R>>::release_readiness,
            waiting: true,
        };
        Self {
            state: BufferFutureState::WaitingForReady {
                request: Some(request),
                shared,
                readiness,
            },
        }
    }

    fn error(err: BufferError<E>) -> Self {
        Self {
            state: BufferFutureState::Error(Some(err)),
        }
    }

    fn release_pending_slot(shared: &SharedBuffer<S>) {
        release_pending_capacity(shared);
    }
}

/// The shared service's readiness belongs to its waiting requests collectively.
/// Retiring one caller must not revoke a surviving caller's FIFO place.
struct InnerReadiness<S> {
    shared: Arc<SharedBuffer<S>>,
    release: fn(&mut S) -> super::ReadinessRelease,
    waiting: bool,
}

impl<S> InnerReadiness<S> {
    fn dispatched(&mut self) {
        self.waiting = false;
        self.shared.waiting_for_ready.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<S> Drop for InnerReadiness<S> {
    fn drop(&mut self) {
        if self.waiting {
            let _release_scope = super::service::ReadinessReleaseScope::new();
            // Serialize the final-owner decision with poll_ready/call. The
            // detached action is deliberately dropped AFTER the service lock.
            let release = {
                let mut inner = self.shared.inner.lock();
                (self.shared.waiting_for_ready.fetch_sub(1, Ordering::AcqRel) == 1)
                    .then(|| (self.release)(&mut inner))
            };
            drop(release);
        }
    }
}

struct BufferTransitionGuard<'a, F, E, S, R> {
    marker: std::marker::PhantomData<&'a mut BufferFuture<F, E, S, R>>,
    shared: Arc<SharedBuffer<S>>,
    armed: bool,
}

impl<F, E, S, R> Drop for BufferTransitionGuard<'_, F, E, S, R> {
    fn drop(&mut self) {
        if self.armed {
            BufferFuture::<F, E, S, R>::release_pending_slot(self.shared.as_ref());
        }
    }
}

impl<F, Response, Error, S, R> BufferFuture<F, Error, S, R>
where
    F: Future<Output = Result<Response, Error>> + Unpin,
    S: Service<R, Response = Response, Error = Error, Future = F>,
    Error: Unpin,
    R: Unpin,
{
    fn poll_waiting_for_ready(
        &mut self,
        cx: &mut Context<'_>,
        mut request: Option<R>,
        shared: Arc<SharedBuffer<S>>,
        mut readiness: InnerReadiness<S>,
    ) -> Option<Poll<Result<Response, BufferError<Error>>>> {
        let _release_scope = super::service::ReadinessReleaseScope::new();
        let mut transition_guard: BufferTransitionGuard<'_, F, Error, S, R> =
            BufferTransitionGuard {
                marker: std::marker::PhantomData,
                shared: Arc::clone(&shared),
                armed: true,
            };
        let mut inner = shared.inner.lock();
        match inner.poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let req = request.take().expect("request missing");
                let future = inner.call(req);
                readiness.dispatched();
                drop(inner);

                let wakers = std::mem::take(&mut *shared.inner_wakers.lock());
                for waker in wakers {
                    waker.wake();
                }

                self.state = BufferFutureState::Active { future, shared };
                transition_guard.armed = false;
                None
            }
            Poll::Ready(Err(e)) => {
                drop(inner);
                drop(readiness);
                transition_guard.armed = false;
                self.state = BufferFutureState::Error(Some(BufferError::Inner(e)));
                Self::release_pending_slot(shared.as_ref());
                None
            }
            Poll::Pending => {
                drop(inner);
                {
                    let mut wakers = shared.inner_wakers.lock();
                    push_waker_if_new(&mut wakers, cx.waker());
                }
                self.state = BufferFutureState::WaitingForReady {
                    request,
                    shared,
                    readiness,
                };
                transition_guard.armed = false;
                Some(Poll::Pending)
            }
        }
    }

    fn poll_active(
        &mut self,
        cx: &mut Context<'_>,
        mut future: F,
        shared: Arc<SharedBuffer<S>>,
    ) -> Poll<Result<Response, BufferError<Error>>> {
        let mut transition_guard: BufferTransitionGuard<'_, F, Error, S, R> =
            BufferTransitionGuard {
                marker: std::marker::PhantomData,
                shared: Arc::clone(&shared),
                armed: true,
            };
        match Pin::new(&mut future).poll(cx) {
            Poll::Ready(result) => {
                transition_guard.armed = false;
                self.state = BufferFutureState::Done;
                Self::release_pending_slot(shared.as_ref());
                Poll::Ready(match result {
                    Ok(v) => Ok(v),
                    Err(e) => Err(BufferError::Inner(e)),
                })
            }
            Poll::Pending => {
                self.state = BufferFutureState::Active { future, shared };
                transition_guard.armed = false;
                Poll::Pending
            }
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
            let poll = match state {
                BufferFutureState::WaitingForReady {
                    request,
                    shared,
                    readiness,
                } => this.poll_waiting_for_ready(cx, request, shared, readiness),
                BufferFutureState::Active { future, shared } => {
                    Some(this.poll_active(cx, future, shared))
                }
                BufferFutureState::Error(mut err) => {
                    let err = err.take().expect("polled after completion");
                    this.state = BufferFutureState::Done;
                    Some(Poll::Ready(Err(err)))
                }
                BufferFutureState::Done => {
                    this.state = BufferFutureState::Done;
                    Some(Poll::Ready(Err(BufferError::PolledAfterCompletion)))
                }
            };

            if let Some(poll) = poll {
                return poll;
            }
        }
    }
}

impl<F, E, S, R> Drop for BufferFuture<F, E, S, R> {
    fn drop(&mut self) {
        match &mut self.state {
            BufferFutureState::WaitingForReady { shared, .. }
            | BufferFutureState::Active { shared, .. } => {
                Self::release_pending_slot(shared.as_ref());
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

    fn release_readiness(&mut self) -> super::ReadinessRelease {
        // Requests already passed to call own the shared inner readiness; a
        // handle's unused outer slot must not cancel those requests.
        self.detach_readiness()
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.ready_reserved {
            return Poll::Ready(Ok(()));
        }
        if *self.shared.closed.lock() {
            return Poll::Ready(Err(BufferError::Closed));
        }
        // Lock ordering is slots -> ready_wakers everywhere to avoid inversion
        // with completion/drop paths that release capacity then wake waiters.
        let mut slots = self.shared.slots.lock();
        if slots.occupied() >= self.shared.capacity {
            let mut wakers = self.shared.ready_wakers.lock();
            register_capacity_waiter(&mut wakers, &self.readiness_owner, cx.waker());
            self.ready_waiting = true;
            Poll::Pending
        } else {
            slots.reserved += 1;
            self.ready_reserved = true;
            self.ready_waiting = false;
            let retired = remove_capacity_waiter(
                &mut self.shared.ready_wakers.lock(),
                &self.readiness_owner,
            );
            drop(slots);
            if !retired.is_empty() {
                drop(super::ReadinessRelease::new(move || drop(retired)));
            }
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, req: Request) -> Self::Future {
        if self.ready_reserved {
            self.ready_reserved = false;
            let mut slots = self.shared.slots.lock();
            slots.reserved = slots.reserved.saturating_sub(1);
            slots.pending += 1;
            return BufferFuture::waiting(req, self.shared.clone());
        }

        drop(self.detach_readiness());

        if *self.shared.closed.lock() {
            return BufferFuture::error(BufferError::Closed);
        }

        {
            let mut slots = self.shared.slots.lock();
            if slots.occupied() >= self.shared.capacity {
                return BufferFuture::error(BufferError::Full);
            }
            slots.pending += 1;
        }

        BufferFuture::waiting(req, self.shared.clone())
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "buffer_inline_tests.rs"]
mod tests;
