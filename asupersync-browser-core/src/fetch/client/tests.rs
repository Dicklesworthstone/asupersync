//! Admission/retirement tests use ordinary Rust futures, not a fake HTTP host.
use super::*;
use std::marker::PhantomPinned;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::task::Waker;

fn limits() -> FetchBytesLimits { FetchBytesLimits::new(8, 32, 4) }
fn poll(task: &mut ClientFetch) -> Poll<Result<FetchBytesResponse, FetchBytesError>> {
    Pin::new(task).poll(&mut Context::from_waker(Waker::noop()))
}

struct Owner(asupersync::types::WasmHandleRef);
impl Owner {
    fn new() -> Self {
        Self(crate::with_dispatcher(|d| d.runtime_create(None)).unwrap())
    }
    fn request(&self) -> WasmFetchRequest {
        WasmFetchRequest {
            scope: self.0, url: "https://example.test/private?token=secret".into(),
            method: "GET".into(), credentials: false, body: None,
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        crate::runtime_close_impl(serde_json::to_string(&self.0).unwrap(), None).unwrap();
    }
}

// Exercise the exact running-state wrapper with a caller-owned Rust future.
// Native public fetch itself correctly returns UnsupportedHost immediately.
fn running<F>(client: &FetchBytesClient, future: F) -> ClientFetch
where F: Future<Output = Result<FetchBytesResponse, FetchBytesError>> + 'static {
    ClientFetch {
        state: Rc::clone(&client.state), request: None, consumer_version: None,
        active: Some(ActiveFetch { future: Box::pin(future), _credit: Credit::acquire(&client.state).unwrap() }),
        finished: false,
    }
}

#[test]
fn unpolled_requests_do_not_take_capacity_or_admit_dispatcher_work() {
    let owner = Owner::new();
    let client = FetchBytesClient::new(limits(), 1);
    let before = crate::DISPATCHER.with(|d| d.borrow().dispatch_count());
    let first = client.fetch(owner.request(), None);
    let second = client.fetch(owner.request(), None);
    assert_eq!(client.in_flight(), 0);
    assert_eq!(crate::DISPATCHER.with(|d| d.borrow().dispatch_count()), before);
    assert!(!format!("{first:?}").contains("secret"));
    drop((first, second));
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn zero_capacity_refuses_before_the_platform_or_dispatcher_path() {
    let owner = Owner::new();
    let client = FetchBytesClient::new(limits(), 0);
    let before = crate::DISPATCHER.with(|d| d.borrow().dispatch_count());
    let mut task = client.fetch(owner.request(), None);
    assert_eq!(poll(&mut task), Poll::Ready(Err(FetchBytesError::InFlightLimit { limit: 0 })));
    assert_eq!(client.in_flight(), 0);
    assert_eq!(crate::DISPATCHER.with(|d| d.borrow().dispatch_count()), before);
}

#[test]
fn clones_share_capacity_and_a_refused_request_never_spends_a_credit() {
    let owner = Owner::new();
    let client = FetchBytesClient::new(limits(), 1);
    let clone = client.clone();
    let active = running(&client, std::future::pending());
    let mut refused = clone.fetch(owner.request(), None);
    assert_eq!(poll(&mut refused), Poll::Ready(Err(FetchBytesError::InFlightLimit { limit: 1 })));
    drop(refused);
    assert_eq!(client.in_flight(), 1);
    drop(active);
    assert_eq!(clone.in_flight(), 0);
    let mut retry = clone.fetch(owner.request(), None);
    assert_eq!(poll(&mut retry), Poll::Ready(Err(FetchBytesError::UnsupportedHost)));
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn completed_wrapper_returns_credit_even_when_the_wrapper_is_retained() {
    let owner = Owner::new();
    let client = FetchBytesClient::new(limits(), 1);
    let mut completed = client.fetch(owner.request(), None);
    assert_eq!(poll(&mut completed), Poll::Ready(Err(FetchBytesError::UnsupportedHost)));
    assert_eq!(client.in_flight(), 0);
    let mut next = client.fetch(owner.request(), None);
    assert_eq!(poll(&mut next), Poll::Ready(Err(FetchBytesError::UnsupportedHost)));
    assert_eq!(client.in_flight(), 0);
    drop(completed);
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn dropping_running_calls_in_any_order_releases_exactly_their_own_credits() {
    let client = FetchBytesClient::new(limits(), 3);
    let a = running(&client, std::future::pending());
    let b = running(&client, std::future::pending());
    let c = running(&client, std::future::pending());
    assert_eq!(client.in_flight(), 3);
    drop(b);
    assert_eq!(client.in_flight(), 2);
    drop(a);
    assert_eq!(client.in_flight(), 1);
    drop(c);
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn reentrant_cleanup_cannot_reuse_capacity_before_inner_destruction_finishes() {
    struct Probe { client: FetchBytesClient, observed: Rc<Cell<bool>> }
    impl Future for Probe {
        type Output = Result<FetchBytesResponse, FetchBytesError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> { Poll::Pending }
    }
    impl Drop for Probe {
        fn drop(&mut self) {
            assert_eq!(self.client.in_flight(), 1);
            assert!(matches!(Credit::acquire(&self.client.state), Err(FetchBytesError::InFlightLimit { limit: 1 })));
            self.observed.set(true);
        }
    }
    let client = FetchBytesClient::new(limits(), 1);
    let observed = Rc::new(Cell::new(false));
    let task = running(&client, Probe { client: client.clone(), observed: Rc::clone(&observed) });
    drop(task);
    assert!(observed.get());
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn inner_cleanup_panic_still_releases_credit_after_cleanup_runs() {
    struct PanicDrop(FetchBytesClient);
    impl Future for PanicDrop {
        type Output = Result<FetchBytesResponse, FetchBytesError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(Err(FetchBytesError::Cancelled))
        }
    }
    impl Drop for PanicDrop {
        fn drop(&mut self) {
            assert_eq!(self.0.in_flight(), 1);
            panic!("client cleanup sentinel");
        }
    }
    let client = FetchBytesClient::new(limits(), 1);
    let mut task = running(&client, PanicDrop(client.clone()));
    assert!(catch_unwind(AssertUnwindSafe(|| poll(&mut task))).is_err());
    assert!(task.finished);
    assert_eq!(client.in_flight(), 0);
    drop(task);
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn poll_panic_retains_ownership_until_the_outer_owner_drops_the_future() {
    let client = FetchBytesClient::new(limits(), 1);
    let mut task = running(&client, std::future::poll_fn(|_| { panic!("client poll sentinel") }));
    assert!(catch_unwind(AssertUnwindSafe(|| poll(&mut task))).is_err());
    assert_eq!(client.in_flight(), 1);
    drop(task);
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn a_pinned_non_send_inner_future_keeps_its_credit_until_real_completion() {
    struct Pinned { ready: Rc<Cell<bool>>, _pin: PhantomPinned }
    impl Future for Pinned {
        type Output = Result<FetchBytesResponse, FetchBytesError>;
        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            if self.as_ref().get_ref().ready.get() {
                Poll::Ready(Ok(FetchBytesResponse { status: 201, body: vec![4, 2] }))
            } else { Poll::Pending }
        }
    }
    let client = FetchBytesClient::new(limits(), 1);
    let ready = Rc::new(Cell::new(false));
    let mut task = running(&client, Pinned { ready: Rc::clone(&ready), _pin: PhantomPinned });
    assert!(poll(&mut task).is_pending());
    assert_eq!(client.in_flight(), 1);
    ready.set(true);
    assert_eq!(poll(&mut task), Poll::Ready(Ok(FetchBytesResponse { status: 201, body: vec![4, 2] })));
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn logical_aggregate_budget_checks_overflow_instead_of_claiming_a_saturated_bound() {
    let client = FetchBytesClient::new(limits(), 3);
    assert_eq!(client.capacity(), 3);
    assert_eq!(client.max_in_flight_response_bytes(), Some(96));
    assert_eq!(FetchBytesClient::new(limits(), 0).max_in_flight_response_bytes(), Some(0));
    assert_eq!(FetchBytesClient::new(limits(), usize::MAX).max_in_flight_response_bytes(), None);
}
