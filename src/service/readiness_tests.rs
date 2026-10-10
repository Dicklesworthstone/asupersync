//! Readiness ownership across real middleware compositions.

#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::{
    Buffer, CircuitBreaker, ConcurrencyLimit, Filter, Hedge, HedgeConfig, LoadBalanceError,
    LoadBalancer, LoadShed, LoadShedError, NoRetry, RateLimit, ReadinessRelease, Retry, RoundRobin,
    Service, ServiceExt, Steer, Timeout,
};
use crate::sync::{OwnedSemaphorePermit, Semaphore};
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

#[derive(Clone)]
struct Echo;

impl Service<u8> for Echo {
    type Response = u8;
    type Error = &'static str;
    type Future = Ready<Result<u8, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: u8) -> Self::Future {
        ready(Ok(request))
    }
}

fn poll<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(std::task::Waker::noop()))
}

fn ready_now<S: Service<u8>>(service: &mut S) -> bool {
    matches!(
        service.poll_ready(&mut Context::from_waker(std::task::Waker::noop())),
        Poll::Ready(Ok(()))
    )
}

#[test]
fn shed_idle_clone_cannot_keep_the_semaphore_queue_head() {
    let semaphore = Arc::new(Semaphore::new(1));
    let mut first = ConcurrencyLimit::new(Echo, Arc::clone(&semaphore));
    let mut shed = LoadShed::new(first.clone());
    let mut next = shed.clone();
    assert!(ready_now(&mut first));
    let mut active = first.call(1);
    assert!(ready_now(&mut shed));
    assert!(matches!(
        poll(&mut shed.call(2)),
        Poll::Ready(Err(LoadShedError::Overloaded(_)))
    ));
    assert!(matches!(poll(&mut active), Poll::Ready(Ok(1))));
    assert_eq!(semaphore.available_permits(), 1);
    assert!(ready_now(&mut next));
    assert!(matches!(poll(&mut next.call(3)), Poll::Ready(Ok(3))));
    assert_eq!(semaphore.available_permits(), 1);
    // Keep the shed handle alive throughout the successful competing request.
    assert!(ready_now(&mut shed));
    drop(shed.release_readiness());
    assert_eq!(semaphore.available_permits(), 1);
}

#[test]
fn wrapped_readiness_drop_releases_only_the_unused_attempt() {
    let semaphore = Arc::new(Semaphore::new(1));
    let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
    let limiter = ConcurrencyLimit::new(Echo, Arc::clone(&semaphore));
    let limited = RateLimit::new(limiter, 1, Duration::from_secs(3600));
    let timed = Timeout::new(limited, Duration::from_secs(3600));
    let mut wrapped = Filter::new(timed, |_: &u8| true);
    let mut waiting = wrapped.ready();
    assert!(poll(&mut waiting).is_pending());
    drop(waiting);
    drop(held);
    let mut contender = ConcurrencyLimit::new(Echo, Arc::clone(&semaphore));
    assert!(
        ready_now(&mut contender),
        "abandoned wrapper must remove its FIFO wait"
    );
    let mut dispatched = contender.call(7);
    drop(contender.release_readiness());
    assert_eq!(
        semaphore.available_permits(),
        0,
        "a call future retains its permit"
    );
    assert!(matches!(poll(&mut dispatched), Poll::Ready(Ok(7))));
    assert!(
        ready_now(&mut wrapped),
        "released rate token is reusable without a refill"
    );
    drop(wrapped.release_readiness());
    assert_eq!(semaphore.available_permits(), 1);
}

#[test]
fn buffer_waiters_share_readiness_until_the_last_request_is_abandoned() {
    let semaphore = Arc::new(Semaphore::new(1));
    let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
    let mut buffer = Buffer::new(ConcurrencyLimit::new(Echo, Arc::clone(&semaphore)), 2);
    let mut first = buffer.call(1);
    let mut surviving = buffer.clone().call(2);
    assert!(poll(&mut first).is_pending());
    assert!(poll(&mut surviving).is_pending());
    drop(first);
    drop(held);
    assert!(
        OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).is_err(),
        "the surviving buffered request retains its queue place"
    );
    assert!(matches!(poll(&mut surviving), Poll::Ready(Ok(2))));
    assert!(buffer.is_empty());

    let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
    let mut abandoned = buffer.clone().oneshot(3);
    assert!(poll(&mut abandoned).is_pending());
    drop(abandoned);
    drop(held);
    assert!(buffer.is_empty());
    assert!(
        OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).is_ok(),
        "the final abandoned oneshot must release shared inner readiness"
    );
}

#[test]
fn steer_waiters_share_readiness_until_the_last_request_is_abandoned() {
    let semaphore = Arc::new(Semaphore::new(1));
    let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
    let mut steer = Steer::new(
        vec![ConcurrencyLimit::new(Echo, Arc::clone(&semaphore))],
        |_: &u8| 0,
    );
    let mut first = steer.call(1);
    let mut surviving = steer.clone().call(2);
    assert!(poll(&mut first).is_pending());
    assert!(poll(&mut surviving).is_pending());
    drop(first);
    drop(held);
    assert!(
        OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).is_err(),
        "the surviving routed request retains its queue place"
    );
    assert!(matches!(poll(&mut surviving), Poll::Ready(Ok(2))));

    let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
    let mut abandoned = steer.call(3);
    assert!(poll(&mut abandoned).is_pending());
    drop(abandoned);
    drop(held);
    assert!(
        OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).is_ok(),
        "an idle route must not reserve another connection's capacity"
    );
}

#[test]
fn a_load_balancer_probe_cannot_leave_a_fifo_reservation_behind() {
    let semaphore = Arc::new(Semaphore::new(1));
    let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
    let balancer = LoadBalancer::new(
        RoundRobin::new(),
        vec![ConcurrencyLimit::new(Echo, Arc::clone(&semaphore))],
    );
    assert!(matches!(
        balancer.call_balanced(1),
        Err(LoadBalanceError::NoReadyBackends)
    ));
    drop(held);
    let permit = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1)
        .expect("the refused probe owns no future that could drive its reservation");
    drop(permit);
    assert!(matches!(
        poll(&mut balancer.call_balanced(2).unwrap()),
        Poll::Ready(Ok(2))
    ));
}

#[test]
fn an_open_circuit_releases_the_inner_readiness_it_rejects() {
    let semaphore = Arc::new(Semaphore::new(1));
    let policy = crate::combinator::CircuitBreakerPolicy {
        failure_threshold: 1,
        open_duration: Duration::from_secs(3600),
        ..crate::combinator::CircuitBreakerPolicy::default()
    };
    let mut breaker = CircuitBreaker::with_time_getter(
        ConcurrencyLimit::new(Echo, Arc::clone(&semaphore)),
        policy,
        || crate::types::Time::ZERO,
    );
    let permit = breaker
        .breaker()
        .should_allow(crate::types::Time::ZERO)
        .unwrap();
    breaker.breaker().record_failure(
        permit,
        "open for the refusal test",
        crate::types::Time::ZERO,
    );
    assert!(ready_now(&mut breaker));
    assert!(matches!(
        poll(&mut breaker.call(1)),
        Poll::Ready(Err(super::CircuitBreakerError::Open { .. }))
    ));
    assert_eq!(semaphore.available_permits(), 1);
    assert!(OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).is_ok());
}

#[test]
fn a_full_half_open_circuit_releases_the_readiness_it_rejects() {
    let semaphore = Arc::new(Semaphore::new(1));
    let policy = crate::combinator::CircuitBreakerPolicy {
        failure_threshold: 1,
        open_duration: Duration::ZERO,
        half_open_max_probes: 1,
        ..crate::combinator::CircuitBreakerPolicy::default()
    };
    let mut breaker = CircuitBreaker::with_time_getter(
        ConcurrencyLimit::new(Echo, Arc::clone(&semaphore)),
        policy,
        || crate::types::Time::ZERO,
    );
    let permit = breaker
        .breaker()
        .should_allow(crate::types::Time::ZERO)
        .unwrap();
    breaker
        .breaker()
        .record_failure(permit, "open", crate::types::Time::ZERO);
    let probe = breaker
        .breaker()
        .should_allow(crate::types::Time::ZERO)
        .unwrap();
    assert!(ready_now(&mut breaker));
    assert!(matches!(
        poll(&mut breaker.call(1)),
        Poll::Ready(Err(super::CircuitBreakerError::HalfOpenFull))
    ));
    assert_eq!(semaphore.available_permits(), 1);
    breaker
        .breaker()
        .record_success(probe, crate::types::Time::ZERO);
    assert!(ready_now(&mut breaker));
    assert!(matches!(poll(&mut breaker.call(2)), Poll::Ready(Ok(2))));
    assert_eq!(semaphore.available_permits(), 1);
}

#[derive(Debug)]
struct MakeLimited(Arc<Semaphore>);

impl super::MakeService for MakeLimited {
    type Service = ConcurrencyLimit<Echo>;
    type Error = std::convert::Infallible;

    fn make_service(&self) -> Result<Self::Service, Self::Error> {
        Ok(ConcurrencyLimit::new(Echo, Arc::clone(&self.0)))
    }
}

#[test]
fn reconnect_detaches_readiness_before_its_cleanup_action_runs() {
    let semaphore = Arc::new(Semaphore::new(1));
    let mut reconnect = super::Reconnect::new(
        MakeLimited(Arc::clone(&semaphore)),
        ConcurrencyLimit::new(Echo, Arc::clone(&semaphore)),
    );
    assert!(ready_now(&mut reconnect));
    let release = reconnect.release_readiness();
    assert_eq!(semaphore.available_permits(), 0, "cleanup remains detached");
    assert!(matches!(
        poll(&mut reconnect.call(1)),
        Poll::Ready(Err(super::ReconnectError::NotReady))
    ));
    drop(release);
    assert_eq!(semaphore.available_permits(), 1);
    assert!(ready_now(&mut reconnect));
    assert!(matches!(poll(&mut reconnect.call(2)), Poll::Ready(Ok(2))));
    assert_eq!(semaphore.available_permits(), 1);
}

// A legacy service whose clones share readiness state and whose destructor
// cannot identify the owner. The explicit hook is what can return its ticket.
#[derive(Clone)]
struct SharedTicket {
    tickets: Arc<AtomicUsize>,
}

impl Service<u8> for SharedTicket {
    type Response = u8;
    type Error = &'static str;
    type Future = Ready<Result<u8, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tickets.store(1, Ordering::SeqCst);
        Poll::Pending
    }

    fn call(&mut self, _: u8) -> Self::Future {
        panic!("ticket fixture never authorizes a dispatch")
    }

    fn release_readiness(&mut self) -> ReadinessRelease {
        let tickets = Arc::clone(&self.tickets);
        ReadinessRelease::new(move || {
            tickets.store(0, Ordering::SeqCst);
        })
    }
}

#[test]
fn owned_oneshot_and_retry_release_after_pending_even_if_the_service_survives() {
    let tickets = Arc::new(AtomicUsize::new(0));
    let service = SharedTicket {
        tickets: Arc::clone(&tickets),
    };
    let mut oneshot = service.clone().oneshot(1);
    assert!(poll(&mut oneshot).is_pending());
    assert_eq!(tickets.load(Ordering::SeqCst), 1);
    drop(oneshot);
    assert_eq!(tickets.load(Ordering::SeqCst), 0);

    let mut retry = Retry::new(service.clone(), NoRetry).call(2);
    assert!(poll(&mut retry).is_pending());
    assert_eq!(tickets.load(Ordering::SeqCst), 1);
    drop(retry);
    assert_eq!(tickets.load(Ordering::SeqCst), 0);
    drop(service);
}

#[test]
fn released_hedge_readiness_returns_its_primary_reservation() {
    let semaphore = Arc::new(Semaphore::new(1));
    let mut hedge = Hedge::new(
        ConcurrencyLimit::new(Echo, Arc::clone(&semaphore)),
        HedgeConfig::new(Duration::from_millis(10)),
    );
    assert!(ready_now(&mut hedge));
    drop(hedge.release_readiness());
    assert_eq!(semaphore.available_permits(), 1);
}

struct HedgeTicket {
    backup: bool,
    tickets: Arc<AtomicUsize>,
}

impl Clone for HedgeTicket {
    fn clone(&self) -> Self {
        Self {
            backup: true,
            tickets: Arc::clone(&self.tickets),
        }
    }
}

impl Service<u8> for HedgeTicket {
    type Response = u8;
    type Error = &'static str;
    type Future = std::future::Pending<Result<u8, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.backup {
            self.tickets.store(1, Ordering::SeqCst);
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn call(&mut self, _: u8) -> Self::Future {
        assert!(!self.backup, "the pending backup must never dispatch");
        std::future::pending()
    }

    fn release_readiness(&mut self) -> ReadinessRelease {
        let tickets = Arc::clone(&self.tickets);
        ReadinessRelease::new(move || {
            tickets.store(0, Ordering::SeqCst);
        })
    }
}

#[test]
fn a_dropped_hedge_releases_its_pending_backup_readiness() {
    let tickets = Arc::new(AtomicUsize::new(0));
    let mut hedge = Hedge::new(
        HedgeTicket {
            backup: false,
            tickets: Arc::clone(&tickets),
        },
        HedgeConfig::new(Duration::ZERO),
    );
    assert!(ready_now(&mut hedge));
    let mut response = hedge.call(1);
    assert!(poll(&mut response).is_pending());
    assert_eq!(
        tickets.load(Ordering::SeqCst),
        1,
        "the backup actually reached Pending"
    );
    drop(response);
    assert_eq!(tickets.load(Ordering::SeqCst), 0);
}

pub(super) type ReleaseCallback = Arc<parking_lot::Mutex<Option<Box<dyn FnOnce() + Send>>>>;

pub(super) struct ReleaseProbe(pub(super) ReleaseCallback);

impl Service<u8> for ReleaseProbe {
    type Response = u8;
    type Error = &'static str;
    type Future = Ready<Result<u8, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Pending
    }

    fn call(&mut self, _: u8) -> Self::Future {
        panic!("release probe is never ready")
    }

    fn release_readiness(&mut self) -> ReadinessRelease {
        self.0
            .lock()
            .take()
            .map_or_else(ReadinessRelease::default, ReadinessRelease::new)
    }
}

pub(super) struct ReadyReleaseProbe(pub(super) ReleaseCallback);

impl Service<u8> for ReadyReleaseProbe {
    type Response = u8;
    type Error = &'static str;
    type Future = Ready<Result<u8, Self::Error>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: u8) -> Self::Future {
        ready(Ok(request))
    }

    fn release_readiness(&mut self) -> ReadinessRelease {
        self.0
            .lock()
            .take()
            .map_or_else(ReadinessRelease::default, ReadinessRelease::new)
    }
}

#[test]
fn deferred_readiness_cleanup_is_nested_reentrant_and_panic_complete() {
    use super::service::ReadinessReleaseScope;

    let retired = Arc::new(AtomicUsize::new(0));
    let scope = ReadinessReleaseScope::new();
    let first = Arc::clone(&retired);
    drop(ReadinessRelease::new(move || {
        first.fetch_add(1, Ordering::SeqCst);
        let nested = ReadinessReleaseScope::new();
        let reentrant = Arc::clone(&first);
        drop(ReadinessRelease::new(move || {
            reentrant.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(first.load(Ordering::SeqCst), 1);
        drop(nested);
        assert_eq!(first.load(Ordering::SeqCst), 2);
        panic!("first cleanup panic");
    }));
    let second = Arc::clone(&retired);
    drop(ReadinessRelease::new(move || {
        second.fetch_add(10, Ordering::SeqCst);
        panic!("secondary cleanup panic");
    }));
    assert_eq!(retired.load(Ordering::SeqCst), 0);

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(scope)))
        .expect_err("the first cleanup panic must propagate");
    assert_eq!(panic.downcast_ref::<&str>(), Some(&"first cleanup panic"));
    assert_eq!(retired.load(Ordering::SeqCst), 12);
    let after = Arc::clone(&retired);
    drop(ReadinessRelease::new(move || {
        after.fetch_add(100, Ordering::SeqCst);
    }));
    assert_eq!(retired.load(Ordering::SeqCst), 112, "the scope fully retired");
}

#[cfg(not(target_arch = "wasm32"))]
async fn abandon_when_cancelled<F: Future>(
    cx: &crate::cx::Cx,
    future: F,
    parked: crate::channel::oneshot::Sender<()>,
) {
    let mut future = Box::pin(future);
    let mut parked = Some(parked);
    std::future::poll_fn(|task| {
        if cx.checkpoint().is_err() {
            return Poll::Ready(());
        }
        assert!(
            future.as_mut().poll(task).is_pending(),
            "capacity is held by the parent"
        );
        if let Some(parked) = parked.take() {
            parked.send_blocking(()).unwrap();
        }
        Poll::Pending
    })
    .await;
    // The pending operation is dropped without another inner poll. This is
    // the abandonment boundary that a readiness timeout also crosses.
}

#[cfg(not(target_arch = "wasm32"))]
fn native_abandoned_shared_wait(workers: usize, routed: bool) {
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};

    let runtime = if workers == 1 {
        RuntimeBuilder::current_thread()
    } else {
        RuntimeBuilder::new().worker_threads(workers)
    }
    .build()
    .unwrap();
    runtime.block_on(async move {
        let cx = crate::cx::Cx::current().unwrap();
        let semaphore = Arc::new(Semaphore::new(1));
        let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
        let mut buffer = Buffer::new(ConcurrencyLimit::new(Echo, Arc::clone(&semaphore)), 1);
        let mut steer = Steer::new(
            vec![ConcurrencyLimit::new(Echo, Arc::clone(&semaphore))],
            |_: &u8| 0,
        );
        let buffered = buffer.clone();
        let mut route = steer.clone();
        let (parked, mut witness) = crate::channel::oneshot::channel();
        let mut child = cx
            .spawn(move |child| async move {
                if routed {
                    abandon_when_cancelled(&child, route.call(7), parked).await;
                } else {
                    abandon_when_cancelled(&child, buffered.oneshot(7), parked).await;
                }
                child
                    .cancel_reason()
                    .expect("the caller acknowledged cancellation")
            })
            .unwrap();
        witness.recv(&cx).await.unwrap();
        child.abort();
        let reason = child.join(&cx).await.unwrap();
        assert_eq!(reason.kind, crate::types::CancelKind::User);
        assert_eq!(reason.message.as_deref(), Some("abort"));
        drop(held);
        let permit = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1)
            .expect("the abandoned shared service must return its queue place");
        drop(permit);
        assert!(buffer.is_empty());
        if routed {
            assert!(matches!(poll(&mut steer.call(9)), Poll::Ready(Ok(9))));
        } else {
            assert!(matches!(poll(&mut buffer.call(9)), Poll::Ready(Ok(9))));
        }
        assert_eq!(semaphore.available_permits(), 1);
    });
    let drained = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(drained.outcome, RootDrainOutcome::Quiescent, "{drained:?}");
    assert_eq!(
        (
            drained.live_tasks,
            drained.live_regions,
            drained.pending_obligations
        ),
        (0, 0, 0)
    );
    assert_eq!((drained.pending_spawns, drained.queued_finalizers), (0, 0));
    assert!(!drained.has_pending_obligation_posts);
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn native_cancelled_buffer_oneshot_releases_shared_readiness() {
    for workers in [1, 2] {
        native_abandoned_shared_wait(workers, false);
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn native_cancelled_steer_request_releases_shared_readiness() {
    for workers in [1, 2] {
        native_abandoned_shared_wait(workers, true);
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn native_dropped_ready_releases_a_service_returned_by_the_cancelled_task() {
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};

    for workers in [1, 2] {
        let runtime = if workers == 1 {
            RuntimeBuilder::current_thread()
        } else {
            RuntimeBuilder::new().worker_threads(workers)
        }
        .build()
        .unwrap();
        runtime.block_on(async {
            let cx = crate::cx::Cx::current().unwrap();
            let semaphore = Arc::new(Semaphore::new(1));
            let held = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1).unwrap();
            let mut service = ConcurrencyLimit::new(Echo, Arc::clone(&semaphore));
            let (parked, mut witness) = crate::channel::oneshot::channel();
            let mut child = cx
                .spawn(move |child| async move {
                    abandon_when_cancelled(&child, service.ready(), parked).await;
                    service
                })
                .unwrap();
            witness.recv(&cx).await.unwrap();
            child.abort();
            let mut retained = child.join(&cx).await.unwrap();
            drop(held);
            let permit = OwnedSemaphorePermit::try_acquire_arc(&semaphore, 1)
                .expect("returning the service must not keep an abandoned waiter");
            drop(permit);
            assert!(ready_now(&mut retained));
            assert!(matches!(poll(&mut retained.call(8)), Poll::Ready(Ok(8))));
        });
        let drained = runtime.shutdown_drained(Duration::from_secs(5));
        assert_eq!(drained.outcome, RootDrainOutcome::Quiescent, "{drained:?}");
        assert_eq!(
            (
                drained.live_tasks,
                drained.live_regions,
                drained.pending_obligations
            ),
            (0, 0, 0)
        );
        assert_eq!((drained.pending_spawns, drained.queued_finalizers), (0, 0));
        assert!(!drained.has_pending_obligation_posts);
    }
}
