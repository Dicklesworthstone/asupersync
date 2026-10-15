//! Steer combinator: routes requests to one of several services.
//!
//! [`Steer`] dispatches each request to one of N inner services based on
//! a user-supplied routing function. This enables content-based routing,
//! A/B testing, and service selection patterns.

use super::Service;
use parking_lot::{Mutex, MutexGuard};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

// ─── Steer ────────────────────────────────────────────────────────────────

/// Wakers of the steer futures waiting for one backend's `poll_ready`.
///
/// Most services keep only the latest waker passed to `poll_ready`
/// (`RateLimit`, the semaphore behind `ConcurrencyLimit`), so with two
/// futures waiting on one backend only the later one would be woken. A
/// future that stops waiting (dispatched, failed or dropped) therefore wakes
/// the others, which re-poll and register their own wakers again.
#[derive(Default)]
struct ReadinessWaiters {
    next_id: u64,
    wakers: Vec<(u64, Waker)>,
    owners: usize,
}

impl ReadinessWaiters {
    fn register(waiters: &Mutex<Self>, id: &mut Option<u64>, waker: &Waker) {
        let mut guard = waiters.lock();
        let key = *id.get_or_insert_with(|| {
            guard.next_id = guard.next_id.wrapping_add(1);
            guard.next_id
        });
        match guard.wakers.iter_mut().find(|(entry, _)| *entry == key) {
            Some((_, stored)) if stored.will_wake(waker) => {}
            Some((_, stored)) => stored.clone_from(waker),
            None => guard.wakers.push((key, waker.clone())),
        }
    }

    fn release(waiters: &Mutex<Self>, id: Option<u64>) {
        let retired = {
            let mut guard = waiters.lock();
            std::mem::take(&mut guard.wakers)
        };
        // The excluded caller's Waker may run user code when dropped too.
        // Move every entry out before filtering or dispatching any callback.
        for (entry, waker) in retired {
            if Some(entry) != id {
                waker.wake();
            }
        }
    }
}

/// A service that routes requests to one of several inner services.
///
/// The `picker` function is called with the request to select which
/// backend receives it (by index into the `services` vec). Out-of-range
/// indexes fail closed instead of being silently wrapped.
pub struct Steer<S, F> {
    services: Vec<Arc<Mutex<S>>>,
    /// Per backend, shared by clones like the backend itself.
    waiters: Vec<Arc<Mutex<ReadinessWaiters>>>,
    picker: F,
}

impl<S, F> Steer<S, F> {
    /// Create a new steer combinator.
    ///
    /// `picker` is called with a reference to the request and must return
    /// an index into `services`. Returning an out-of-range index causes
    /// [`SteerError::InvalidRoute`] when the returned future is polled.
    ///
    /// # Panics
    ///
    /// Panics if `services` is empty.
    #[must_use]
    pub fn new(services: Vec<S>, picker: F) -> Self {
        assert!(!services.is_empty(), "steer requires at least one service");
        let waiters = services.iter().map(|_| Arc::default()).collect();
        Self {
            services: services
                .into_iter()
                .map(|service| Arc::new(Mutex::new(service)))
                .collect(),
            waiters,
            picker,
        }
    }

    /// Get the number of inner services.
    #[must_use]
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Returns false (at least one service is always present).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Snapshot the current inner services by cloning them.
    ///
    /// This is intended for inspection and tests.
    #[must_use]
    pub fn services(&self) -> Vec<S>
    where
        S: Clone,
    {
        self.services
            .iter()
            .map(|service| service.lock().clone())
            .collect()
    }

    /// Acquire mutable guards for the inner services.
    ///
    /// This is intended for tests and synchronous maintenance operations.
    pub fn services_mut(&self) -> Vec<MutexGuard<'_, S>> {
        self.services.iter().map(|service| service.lock()).collect()
    }
}

impl<S, F: Clone> Clone for Steer<S, F> {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            waiters: self.waiters.clone(),
            picker: self.picker.clone(),
        }
    }
}

impl<S: fmt::Debug, F> fmt::Debug for Steer<S, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let services: Vec<String> = self
            .services
            .iter()
            .map(|service| format!("{:?}", *service.lock()))
            .collect();
        f.debug_struct("Steer")
            .field("services", &services)
            .finish_non_exhaustive()
    }
}

/// Future returned by [`Steer`].
pub struct SteerFuture<S, Request>
where
    S: Service<Request>,
{
    state: SteerState<S, Request>,
}

enum SteerState<S, Request>
where
    S: Service<Request>,
{
    InvalidRoute {
        index: usize,
        service_count: usize,
    },
    PollReady {
        service: Arc<Mutex<S>>,
        waiters: Arc<Mutex<ReadinessWaiters>>,
        readiness: SteerReadiness<S, Request>,
        request: Option<Request>,
    },
    Calling {
        future: S::Future,
    },
    Done,
}

impl<S, Request> SteerFuture<S, Request>
where
    S: Service<Request>,
{
    fn invalid_route(index: usize, service_count: usize) -> Self {
        Self {
            state: SteerState::InvalidRoute {
                index,
                service_count,
            },
        }
    }

    fn new(
        service: Arc<Mutex<S>>,
        waiters: Arc<Mutex<ReadinessWaiters>>,
        request: Request,
    ) -> Self {
        waiters.lock().owners += 1;
        let readiness = SteerReadiness {
            service: Arc::clone(&service),
            waiters: Arc::clone(&waiters),
            waiter: None,
            waiting: true,
            marker: std::marker::PhantomData,
        };
        Self {
            state: SteerState::PollReady {
                service,
                waiters,
                readiness,
                request: Some(request),
            },
        }
    }
}

struct SteerReadiness<S, Request>
where
    S: Service<Request>,
{
    service: Arc<Mutex<S>>,
    waiters: Arc<Mutex<ReadinessWaiters>>,
    waiter: Option<u64>,
    waiting: bool,
    marker: std::marker::PhantomData<fn(Request)>,
}

impl<S, Request> SteerReadiness<S, Request>
where
    S: Service<Request>,
{
    fn dispatched(&mut self) {
        self.waiting = false;
        self.waiters.lock().owners -= 1;
    }
}

impl<S, Request> Drop for SteerReadiness<S, Request>
where
    S: Service<Request>,
{
    fn drop(&mut self) {
        let _release_scope = super::service::ReadinessReleaseScope::new();
        let waiters = Arc::clone(&self.waiters);
        let waiter = self.waiter;
        let retire_waiter = super::ReadinessRelease::new(move || {
            ReadinessWaiters::release(&waiters, waiter);
        });
        let release = if self.waiting {
            let mut service = self.service.lock();
            let last = {
                let mut waiters = self.waiters.lock();
                waiters.owners -= 1;
                waiters.owners == 0
            };
            last.then(|| service.release_readiness())
        } else {
            None
        };
        drop(release);
        // Never wake peers while holding either coordinator lock.
        drop(retire_waiter);
    }
}

impl<S, Request> fmt::Debug for SteerFuture<S, Request>
where
    S: Service<Request>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SteerFuture").finish_non_exhaustive()
    }
}

impl<S, Request> Future for SteerFuture<S, Request>
where
    S: Service<Request>,
    S::Future: Unpin,
    Request: Unpin,
{
    type Output = Result<S::Response, SteerError<S::Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        loop {
            let state = std::mem::replace(&mut this.state, SteerState::Done);
            match state {
                SteerState::InvalidRoute {
                    index,
                    service_count,
                } => {
                    return Poll::Ready(Err(SteerError::InvalidRoute {
                        index,
                        service_count,
                    }));
                }
                SteerState::PollReady {
                    service,
                    waiters,
                    mut readiness,
                    mut request,
                } => {
                    let _release_scope = super::service::ReadinessReleaseScope::new();
                    let mut inner = service.lock();
                    match inner.poll_ready(cx) {
                        Poll::Pending => {
                            drop(inner);
                            ReadinessWaiters::register(&waiters, &mut readiness.waiter, cx.waker());
                            this.state = SteerState::PollReady {
                                service,
                                waiters,
                                readiness,
                                request,
                            };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(err)) => {
                            drop(inner);
                            drop(readiness);
                            return Poll::Ready(Err(SteerError::Inner(err)));
                        }
                        Poll::Ready(Ok(())) => {
                            let Some(req) = request.take() else {
                                drop(inner);
                                drop(readiness);
                                return Poll::Ready(Err(SteerError::PolledAfterCompletion));
                            };
                            let future = inner.call(req);
                            readiness.dispatched();
                            drop(inner);
                            drop(readiness);
                            this.state = SteerState::Calling { future };
                        }
                    }
                }
                SteerState::Calling { mut future } => match Pin::new(&mut future).poll(cx) {
                    Poll::Pending => {
                        this.state = SteerState::Calling { future };
                        return Poll::Pending;
                    }
                    Poll::Ready(Ok(response)) => {
                        return Poll::Ready(Ok(response));
                    }
                    Poll::Ready(Err(err)) => {
                        return Poll::Ready(Err(SteerError::Inner(err)));
                    }
                },
                SteerState::Done => {
                    return Poll::Ready(Err(SteerError::PolledAfterCompletion));
                }
            }
        }
    }
}

impl<S, F, Request> Service<Request> for Steer<S, F>
where
    S: Service<Request>,
    S::Future: Unpin,
    F: Fn(&Request) -> usize,
    Request: Unpin,
{
    type Response = S::Response;
    type Error = SteerError<S::Error>;
    type Future = SteerFuture<S, Request>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Route selection is request-dependent. Polling every backend here can
        // strand reservations on services that never receive the request.
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let idx = (self.picker)(&req);
        if idx >= self.services.len() {
            return SteerFuture::invalid_route(idx, self.services.len());
        }
        SteerFuture::new(
            Arc::clone(&self.services[idx]),
            Arc::clone(&self.waiters[idx]),
            req,
        )
    }
}

// ─── SteerError ───────────────────────────────────────────────────────────

/// Error wrapping for steer operations.
#[derive(Debug)]
pub enum SteerError<E> {
    /// Inner service error.
    Inner(E),
    /// The picker returned an index outside the available service range.
    InvalidRoute {
        /// The out-of-range index chosen by the picker.
        index: usize,
        /// The number of available services.
        service_count: usize,
    },
    /// No services available.
    NoServices,
    /// The steer future was polled after it had already completed.
    PolledAfterCompletion,
}

impl<E: fmt::Display> fmt::Display for SteerError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "steer service error: {e}"),
            Self::InvalidRoute {
                index,
                service_count,
            } => write!(
                f,
                "steer picker selected invalid service index {index} (service count {service_count})"
            ),
            Self::NoServices => write!(f, "no services available"),
            Self::PolledAfterCompletion => write!(f, "steer future polled after completion"),
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for SteerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Inner(e) => Some(e),
            Self::InvalidRoute { .. } | Self::NoServices | Self::PolledAfterCompletion => None,
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use futures_lite::future::block_on;
    use std::future::{Ready, ready};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Waker;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn abandoned_readiness_cleanup_can_reenter_both_steer_locks() {
        use super::super::readiness_tests::{ReleaseCallback, ReleaseProbe};

        let callback: ReleaseCallback = Arc::new(Mutex::new(None));
        let mut steer = Steer::new(vec![ReleaseProbe(Arc::clone(&callback))], |_: &u8| 0);
        let service = Arc::downgrade(&steer.services[0]);
        let waiters = Arc::downgrade(&steer.waiters[0]);
        let released = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&released);
        *callback.lock() = Some(Box::new(move || {
            assert!(service.upgrade().unwrap().try_lock().is_some());
            assert!(waiters.upgrade().unwrap().try_lock().is_some());
            observed.fetch_add(1, Ordering::SeqCst);
        }));

        let mut pending = steer.call(1);
        let waker = noop_waker();
        assert!(Pin::new(&mut pending)
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        drop(pending);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn nested_filter_cleanup_runs_after_the_steer_service_unlocks() {
        use super::super::Filter;
        use super::super::readiness_tests::{ReadyReleaseProbe, ReleaseCallback};

        let callback: ReleaseCallback = Arc::new(Mutex::new(None));
        let filter = Filter::new(ReadyReleaseProbe(Arc::clone(&callback)), |_: &u8| false);
        let mut steer = Steer::new(vec![filter], |_: &u8| 0);
        let service = Arc::downgrade(&steer.services[0]);
        let waiters = Arc::downgrade(&steer.waiters[0]);
        let released = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&released);
        *callback.lock() = Some(Box::new(move || {
            assert!(service.upgrade().unwrap().try_lock().is_some());
            assert!(waiters.upgrade().unwrap().try_lock().is_some());
            observed.fetch_add(1, Ordering::SeqCst);
        }));

        let mut response = steer.call(1);
        let waker = noop_waker();
        assert!(matches!(
            Pin::new(&mut response).poll(&mut Context::from_waker(&waker)),
            Poll::Ready(Err(SteerError::Inner(super::super::FilterError::Rejected)))
        ));
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn panicking_inner_detacher_still_unregisters_the_steer_waiter_after_unlocking() {
        use super::super::ConcurrencyLimit;
        use super::super::readiness_tests::ReleaseCallback;
        use crate::sync::{OwnedSemaphorePermit, Semaphore};

        struct PanickingDetacher;

        impl Service<u8> for PanickingDetacher {
            type Response = u8;
            type Error = &'static str;
            type Future = Ready<Result<u8, Self::Error>>;

            fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn call(&mut self, request: u8) -> Self::Future {
                ready(Ok(request))
            }

            fn release_readiness(&mut self) -> super::super::ReadinessRelease {
                panic!("inner detachment panic");
            }
        }

        struct DropWake(ReleaseCallback);

        #[allow(clippy::manual_noop_waker)]
        impl std::task::Wake for DropWake {
            fn wake(self: Arc<Self>) {}
        }

        impl Drop for DropWake {
            fn drop(&mut self) {
                let callback = self.0.lock().take();
                if let Some(callback) = callback {
                    callback();
                }
            }
        }

        let semaphore = Arc::new(Semaphore::new(1));
        let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
        let mut steer = Steer::new(
            vec![ConcurrencyLimit::new(PanickingDetacher, Arc::clone(&semaphore))],
            |_: &u8| 0,
        );
        let service = Arc::downgrade(&steer.services[0]);
        let waiters = Arc::downgrade(&steer.waiters[0]);
        let dropped = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&dropped);
        let callback: ReleaseCallback = Arc::new(Mutex::new(Some(Box::new(move || {
            assert!(service.upgrade().unwrap().try_lock().is_some());
            assert!(waiters.upgrade().unwrap().try_lock().is_some());
            observed.fetch_add(1, Ordering::SeqCst);
        }))));
        let waker = Waker::from(Arc::new(DropWake(callback)));
        let mut pending = steer.call(1);
        assert!(Pin::new(&mut pending)
            .poll(&mut Context::from_waker(&waker))
            .is_pending());
        assert_eq!(steer.waiters[0].lock().wakers.len(), 1);
        drop(waker);
        let panic = catch_unwind(AssertUnwindSafe(|| drop(pending)))
            .expect_err("inner detachment panic must propagate");
        assert_eq!(panic.downcast_ref::<&str>(), Some(&"inner detachment panic"));
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert!(steer.waiters[0].lock().wakers.is_empty());
        assert_eq!(steer.waiters[0].lock().owners, 0);
        drop(held);
        assert!(OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).is_ok());
    }

    // Deterministic test services.
    #[derive(Debug, Clone)]
    struct IdService {
        id: usize,
    }

    impl Service<usize> for IdService {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<usize, std::convert::Infallible>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            ready(Ok(self.id))
        }
    }

    #[derive(Debug)]
    struct ReservingService {
        id: usize,
        available: Arc<AtomicUsize>,
        reserved: bool,
    }

    impl ReservingService {
        fn new(id: usize, available: Arc<AtomicUsize>) -> Self {
            Self {
                id,
                available,
                reserved: false,
            }
        }

        fn available(&self) -> usize {
            self.available.load(Ordering::SeqCst)
        }
    }

    impl Service<usize> for ReservingService {
        type Response = usize;
        type Error = &'static str;
        type Future = Ready<Result<usize, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.reserved {
                return Poll::Ready(Ok(()));
            }

            let available = self.available.load(Ordering::SeqCst);
            if available == 0 {
                return Poll::Pending;
            }

            self.available.fetch_sub(1, Ordering::SeqCst);
            self.reserved = true;
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            if !std::mem::replace(&mut self.reserved, false) {
                return ready(Err("not ready"));
            }

            self.available.fetch_add(1, Ordering::SeqCst);
            ready(Ok(self.id))
        }
    }

    #[derive(Debug, Clone)]
    struct FailService;

    impl Service<usize> for FailService {
        type Response = usize;
        type Error = &'static str;
        type Future = Ready<Result<usize, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            ready(Err("boom"))
        }
    }

    struct PanicOnPollFuture;

    impl Future for PanicOnPollFuture {
        type Output = Result<usize, std::convert::Infallible>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            panic!("panic in future poll");
        }
    }

    #[derive(Debug, Clone)]
    struct PanicOnPollService;

    impl Service<usize> for PanicOnPollService {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = PanicOnPollFuture;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: usize) -> Self::Future {
            PanicOnPollFuture
        }
    }

    #[derive(Debug, Clone)]
    struct CountingCallService {
        calls: Arc<AtomicUsize>,
    }

    impl CountingCallService {
        fn new(calls: Arc<AtomicUsize>) -> Self {
            Self { calls }
        }
    }

    impl Service<()> for CountingCallService {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<usize, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: ()) -> Self::Future {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ready(Ok(0))
        }
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    #[test]
    fn steer_new() {
        init_test("steer_new");
        let svcs = vec![IdService { id: 0 }, IdService { id: 1 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        assert_eq!(steer.len(), 2);
        assert!(!steer.is_empty());
        crate::test_complete!("steer_new");
    }

    #[test]
    #[should_panic(expected = "steer requires at least one service")]
    fn steer_empty_panics() {
        let svcs: Vec<IdService> = vec![];
        let _ = Steer::new(svcs, |_req: &()| 0);
    }

    #[test]
    fn steer_services_ref() {
        let svcs = vec![IdService { id: 10 }, IdService { id: 20 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        assert_eq!(steer.services().len(), 2);
        assert_eq!(steer.services()[0].id, 10);
    }

    #[test]
    fn steer_services_mut() {
        let svcs = vec![IdService { id: 10 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        {
            let mut guards = steer.services_mut();
            guards[0].id = 99;
        }
        assert_eq!(steer.services()[0].id, 99);
    }

    #[test]
    fn steer_debug() {
        let svcs = vec![IdService { id: 1 }];
        let steer = Steer::new(svcs, |_req: &()| 0);
        let dbg = format!("{steer:?}");
        assert!(dbg.contains("Steer"));
    }

    #[test]
    fn steer_picker_routes() {
        init_test("steer_picker_routes");
        let svcs = vec![IdService { id: 0 }, IdService { id: 1 }];
        let steer = Steer::new(svcs, |req: &usize| req % 2);
        let picker = &steer.picker;
        assert_eq!(picker(&0), 0);
        assert_eq!(picker(&1), 1);
        assert_eq!(picker(&2), 0);
        assert_eq!(picker(&3), 1);
        crate::test_complete!("steer_picker_routes");
    }

    #[test]
    fn steer_invalid_route_display() {
        let err: SteerError<std::io::Error> = SteerError::InvalidRoute {
            index: 5,
            service_count: 2,
        };
        let msg = format!("{err}");
        assert!(msg.contains("invalid service index 5"));
        assert!(msg.contains("service count 2"));
    }

    #[test]
    fn steer_error_inner_display() {
        let err: SteerError<std::io::Error> = SteerError::Inner(std::io::Error::other("fail"));
        assert!(format!("{err}").contains("steer service error"));
    }

    #[test]
    fn steer_error_no_services_display() {
        let err: SteerError<std::io::Error> = SteerError::NoServices;
        assert!(format!("{err}").contains("no services available"));
    }

    #[test]
    fn steer_error_polled_after_completion_display() {
        let err: SteerError<std::io::Error> = SteerError::PolledAfterCompletion;
        assert!(format!("{err}").contains("polled after completion"));
    }

    #[test]
    fn steer_error_source() {
        use std::error::Error;
        let err: SteerError<std::io::Error> = SteerError::Inner(std::io::Error::other("fail"));
        assert!(err.source().is_some());

        let invalid_route: SteerError<std::io::Error> = SteerError::InvalidRoute {
            index: 5,
            service_count: 2,
        };
        assert!(invalid_route.source().is_none());

        let err2: SteerError<std::io::Error> = SteerError::NoServices;
        assert!(err2.source().is_none());

        let err3: SteerError<std::io::Error> = SteerError::PolledAfterCompletion;
        assert!(err3.source().is_none());
    }

    #[test]
    fn steer_error_debug() {
        let err: SteerError<std::io::Error> = SteerError::NoServices;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NoServices"));
    }

    #[test]
    fn steer_error_debug_includes_polled_after_completion() {
        let err: SteerError<std::io::Error> = SteerError::PolledAfterCompletion;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("PolledAfterCompletion"));
    }

    #[test]
    fn steer_call_without_outer_poll_ready_still_routes_selected_backend() {
        init_test("steer_call_without_outer_poll_ready_still_routes_selected_backend");
        let mut steer = Steer::new(vec![IdService { id: 7 }], |_: &usize| 0);
        let result = block_on(steer.call(0)).expect("selected backend should succeed");
        assert_eq!(result, 7);
        crate::test_complete!("steer_call_without_outer_poll_ready_still_routes_selected_backend");
    }

    #[test]
    fn steer_call_only_reserves_selected_backend() {
        init_test("steer_call_only_reserves_selected_backend");
        let even_available = Arc::new(AtomicUsize::new(1));
        let odd_available = Arc::new(AtomicUsize::new(1));
        let mut steer = Steer::new(
            vec![
                ReservingService::new(0, Arc::clone(&even_available)),
                ReservingService::new(1, Arc::clone(&odd_available)),
            ],
            |req: &usize| req % 2,
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let ready = steer.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));
        assert_eq!(even_available.load(Ordering::SeqCst), 1);
        assert_eq!(odd_available.load(Ordering::SeqCst), 1);

        let result = block_on(steer.call(0)).expect("selected backend should succeed");
        assert_eq!(result, 0);

        let guards = steer.services_mut();
        assert_eq!(guards[0].available(), 1);
        assert_eq!(guards[1].available(), 1);
        crate::test_complete!("steer_call_only_reserves_selected_backend");
    }

    #[test]
    fn steer_invalid_picker_index_fails_closed_without_dispatching() {
        init_test("steer_invalid_picker_index_fails_closed_without_dispatching");
        let first_calls = Arc::new(AtomicUsize::new(0));
        let second_calls = Arc::new(AtomicUsize::new(0));
        let mut steer = Steer::new(
            vec![
                CountingCallService::new(Arc::clone(&first_calls)),
                CountingCallService::new(Arc::clone(&second_calls)),
            ],
            |(): &()| 5,
        );

        let result = block_on(steer.call(()));
        assert!(matches!(
            result,
            Err(SteerError::InvalidRoute {
                index: 5,
                service_count: 2
            })
        ));
        assert_eq!(first_calls.load(Ordering::SeqCst), 0);
        assert_eq!(second_calls.load(Ordering::SeqCst), 0);
        crate::test_complete!("steer_invalid_picker_index_fails_closed_without_dispatching");
    }

    #[test]
    fn steer_selected_route_is_not_blocked_by_other_backends() {
        init_test("steer_selected_route_is_not_blocked_by_other_backends");
        let blocked_available = Arc::new(AtomicUsize::new(0));
        let ready_available = Arc::new(AtomicUsize::new(1));
        let mut steer = Steer::new(
            vec![
                ReservingService::new(0, Arc::clone(&blocked_available)),
                ReservingService::new(1, Arc::clone(&ready_available)),
            ],
            |req: &usize| req % 2,
        );

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let ready = steer.poll_ready(&mut cx);
        assert!(matches!(ready, Poll::Ready(Ok(()))));

        let result = block_on(steer.call(1)).expect("ready route should succeed");
        assert_eq!(result, 1);
        assert_eq!(blocked_available.load(Ordering::SeqCst), 0);
        assert_eq!(ready_available.load(Ordering::SeqCst), 1);
        crate::test_complete!("steer_selected_route_is_not_blocked_by_other_backends");
    }

    #[test]
    fn steer_future_second_poll_fails_closed_after_success() {
        let mut future = Steer::new(vec![IdService { id: 7 }], |_: &usize| 0).call(0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Ok(7))));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_second_poll_fails_closed_after_inner_error() {
        let mut future = Steer::new(vec![FailService], |_: &usize| 0).call(0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(first, Poll::Ready(Err(SteerError::Inner("boom")))));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_second_poll_fails_closed_after_invalid_route() {
        let mut future = Steer::new(vec![IdService { id: 7 }], |_: &usize| 3).call(0);
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            first,
            Poll::Ready(Err(SteerError::InvalidRoute {
                index: 3,
                service_count: 1
            }))
        ));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_missing_request_fails_closed() {
        let mut future = SteerFuture::new(
            Arc::new(Mutex::new(IdService { id: 7 })),
            Arc::default(),
            0usize,
        );
        if let SteerState::PollReady { request, .. } = &mut future.state {
            *request = None;
        }
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let first = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            first,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
    }

    #[test]
    fn steer_future_inner_panic_fails_closed() {
        init_test("steer_future_inner_panic_fails_closed");
        let mut future = SteerFuture::<PanicOnPollService, usize> {
            state: SteerState::<PanicOnPollService, usize>::Calling {
                future: PanicOnPollFuture,
            },
        };
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = Pin::new(&mut future).poll(&mut cx);
        }));
        assert!(panic.is_err(), "inner panic should propagate");

        let second = Pin::new(&mut future).poll(&mut cx);
        assert!(matches!(
            second,
            Poll::Ready(Err(SteerError::PolledAfterCompletion))
        ));
        crate::test_complete!("steer_future_inner_panic_fails_closed");
    }

    /// A backend that, like RateLimit or the ConcurrencyLimit semaphore,
    /// keeps only the latest waker passed to `poll_ready`.
    struct LatestWakerGate {
        open: Arc<std::sync::atomic::AtomicBool>,
        waker: Arc<Mutex<Option<Waker>>>,
    }

    impl Service<usize> for LatestWakerGate {
        type Response = usize;
        type Error = std::convert::Infallible;
        type Future = Ready<Result<usize, std::convert::Infallible>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if self.open.load(Ordering::SeqCst) {
                return Poll::Ready(Ok(()));
            }
            *self.waker.lock() = Some(cx.waker().clone());
            Poll::Pending
        }

        fn call(&mut self, req: usize) -> Self::Future {
            ready(Ok(req))
        }
    }

    struct CountingWaker(AtomicUsize);

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn assert_other_waiter_woken(drop_instead_of_dispatch: bool) {
        let open = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gate_waker = Arc::new(Mutex::new(None));
        let mut steer = Steer::new(
            vec![LatestWakerGate {
                open: Arc::clone(&open),
                waker: Arc::clone(&gate_waker),
            }],
            |_: &usize| 0,
        );
        let mut first = steer.call(1);
        let mut second = steer.call(2);
        let first_wakes = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let second_wakes = Arc::new(CountingWaker(AtomicUsize::new(0)));
        let first_waker = Waker::from(Arc::clone(&first_wakes));
        let second_waker = Waker::from(Arc::clone(&second_wakes));
        assert!(
            Pin::new(&mut first)
                .poll(&mut Context::from_waker(&first_waker))
                .is_pending()
        );
        // The gate now holds only the second future's waker.
        assert!(
            Pin::new(&mut second)
                .poll(&mut Context::from_waker(&second_waker))
                .is_pending()
        );

        open.store(true, Ordering::SeqCst);
        gate_waker.lock().take().expect("gate waker").wake();
        assert_eq!(second_wakes.0.load(Ordering::SeqCst), 1);
        if drop_instead_of_dispatch {
            drop(second);
        } else {
            let done = Pin::new(&mut second).poll(&mut Context::from_waker(&second_waker));
            assert!(matches!(done, Poll::Ready(Ok(2))));
        }
        assert_eq!(
            first_wakes.0.load(Ordering::SeqCst),
            1,
            "the first future must be woken to re-poll the backend"
        );
        let done = Pin::new(&mut first).poll(&mut Context::from_waker(&first_waker));
        assert!(matches!(done, Poll::Ready(Ok(1))));
    }

    #[test]
    fn a_waiter_is_woken_when_another_dispatches_to_its_backend() {
        init_test("a_waiter_is_woken_when_another_dispatches_to_its_backend");
        assert_other_waiter_woken(false);
        crate::test_complete!("a_waiter_is_woken_when_another_dispatches_to_its_backend");
    }

    #[test]
    fn a_waiter_is_woken_when_another_waiting_future_is_dropped() {
        init_test("a_waiter_is_woken_when_another_waiting_future_is_dropped");
        assert_other_waiter_woken(true);
        crate::test_complete!("a_waiter_is_woken_when_another_waiting_future_is_dropped");
    }
}
