//! Admission/retirement tests over ordinary owned Rust futures, not fake HTTP.
use super::*;
use crate::fetch::FetchBytesLimits;
use asupersync::types::WasmHandleRef;
use std::cell::Cell;
use std::marker::{PhantomData, PhantomPinned};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::task::Waker;

struct Owner(WasmHandleRef);
impl Owner {
    fn new() -> Self {
        crate::reset_dispatcher_for_tests();
        Self(crate::with_dispatcher(|d| d.runtime_create(None)).unwrap())
    }
    fn request(&self) -> WasmFetchRequest {
        WasmFetchRequest { scope: self.0, url: "https://example.invalid/".into(),
            method: "GET".into(), credentials: false, body: None }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        crate::runtime_close_impl(serde_json::to_string(&self.0).unwrap(), None).unwrap();
    }
}
fn client(capacity: usize) -> FetchBytesClient {
    FetchBytesClient::new(FetchBytesLimits::new(0, 32, 4), capacity)
}
fn poll(opening: &mut ClientStream) -> Poll<Result<ClientBody, FetchBytesError>> {
    Pin::new(opening).poll(&mut Context::from_waker(Waker::noop()))
}

#[test]
fn stream_construction_and_unpolled_drop_do_not_consume_credit() {
    let owner = Owner::new();
    let client = client(1);
    let opening = client.stream(owner.request(), 8, None);
    assert_eq!(client.in_flight(), 0);
    drop(opening);
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn buffered_and_streaming_calls_refuse_against_the_same_credit() {
    let owner = Owner::new();
    let client = client(1);
    let credit = Credit::acquire(&client.state).unwrap();
    let clone = client.clone();
    assert!(matches!(poll(&mut clone.stream(owner.request(), 8, None)),
        Poll::Ready(Err(FetchBytesError::InFlightLimit { limit: 1 }))));
    let mut buffered = clone.fetch(owner.request(), None);
    assert!(matches!(Pin::new(&mut buffered).poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(FetchBytesError::InFlightLimit { limit: 1 }))));
    assert_eq!(client.in_flight(), 1);
    drop(credit);
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn zero_capacity_refuses_before_native_host_or_handle_admission() {
    let owner = Owner::new();
    let client = client(0);
    assert!(matches!(poll(&mut client.stream(owner.request(), 8, None)),
        Poll::Ready(Err(FetchBytesError::InFlightLimit { limit: 0 }))));
    crate::DISPATCHER.with(|d| assert_eq!(d.borrow().handles().memory_report().live_handles, 1));
}

#[test]
fn native_unsupported_opening_returns_credit_before_wrapper_drop() {
    let owner = Owner::new();
    let client = client(1);
    let mut opening = client.stream(owner.request(), 8, None);
    assert!(matches!(poll(&mut opening), Poll::Ready(Err(FetchBytesError::UnsupportedHost))));
    assert_eq!(client.in_flight(), 0);
    assert!(opening.finished);
    assert!(opening.active.is_none());
}

struct RetirementProbe {
    client: FetchBytesClient,
    retired: Rc<Cell<bool>>,
    ready: bool,
    panic_on_drop: bool,
    _pin: PhantomPinned,
}
impl Future for RetirementProbe {
    type Output = Result<FetchStream, FetchBytesError>;
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.ready { Poll::Ready(Err(FetchBytesError::InvalidResponse)) }
        else { Poll::Pending }
    }
}
impl Drop for RetirementProbe {
    fn drop(&mut self) {
        assert_eq!(self.client.in_flight(), 1, "destruction remains admitted");
        assert!(matches!(Credit::acquire(&self.client.state),
            Err(FetchBytesError::InFlightLimit { limit: 1 })));
        self.retired.set(true);
        assert!(!self.panic_on_drop, "intentional retirement panic");
    }
}
fn install_probe(opening: &mut ClientStream, client: &FetchBytesClient,
    retired: &Rc<Cell<bool>>, ready: bool, panic_on_drop: bool)
{
    opening.request = None;
    opening.active = Some(Opening {
        future: Box::pin(RetirementProbe { client: client.clone(), retired: Rc::clone(retired),
            ready, panic_on_drop, _pin: PhantomPinned }),
        credit: Some(Credit::acquire(&client.state).unwrap()),
    });
}

#[test]
fn dropping_non_unpin_pending_opening_retires_before_capacity_returns() {
    let owner = Owner::new();
    let client = client(1);
    let retired = Rc::new(Cell::new(false));
    let mut opening = client.stream(owner.request(), 8, None);
    install_probe(&mut opening, &client, &retired, false, false);
    assert!(poll(&mut opening).is_pending());
    drop(opening);
    assert!(retired.get());
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn terminal_error_retires_the_future_even_if_opening_is_retained() {
    let owner = Owner::new();
    let client = client(1);
    let retired = Rc::new(Cell::new(false));
    let mut opening = client.stream(owner.request(), 8, None);
    install_probe(&mut opening, &client, &retired, true, false);
    assert!(matches!(poll(&mut opening), Poll::Ready(Err(FetchBytesError::InvalidResponse))));
    assert!(retired.get());
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn panicking_retirement_releases_credit_without_double_retirement() {
    let owner = Owner::new();
    let client = client(1);
    let retired = Rc::new(Cell::new(false));
    let mut opening = client.stream(owner.request(), 8, None);
    install_probe(&mut opening, &client, &retired, true, true);
    assert!(catch_unwind(AssertUnwindSafe(|| poll(&mut opening))).is_err());
    assert!(retired.get());
    assert!(opening.finished);
    assert!(opening.active.is_none());
    assert_eq!(client.in_flight(), 0);
    drop(opening);
    assert_eq!(client.in_flight(), 0);
}

#[test]
fn header_handoff_keeps_credit_until_body_retirement() {
    let owner = Owner::new();
    let client = client(1);
    let mut opening = client.stream(owner.request(), 8, None);
    // A deliberately unsupported native body tests credit transfer only; it
    // cannot perform or claim HTTP I/O. Real header/body journeys live in wasm.
    opening.request = None;
    opening.active = Some(Opening {
        future: Box::pin(std::future::ready(Ok(FetchStream { status: 200, _local: PhantomData }))),
        credit: Some(Credit::acquire(&client.state).unwrap()),
    });
    let Poll::Ready(Ok(mut body)) = poll(&mut opening) else { panic!("ready body handoff"); };
    drop(opening);
    assert_eq!(client.in_flight(), 1, "headers do not release capacity");
    assert_eq!(body.status(), 200);
    let error = Poll::Ready(Err(FetchBytesError::UnsupportedHost));
    assert_eq!(Pin::new(&mut body).poll_chunk(&mut Context::from_waker(Waker::noop())), error);
    assert_eq!(client.in_flight(), 0, "terminal body retirement releases capacity");
    assert_eq!(Pin::new(&mut body).poll_chunk(&mut Context::from_waker(Waker::noop())), error);
    drop(body);
    assert_eq!(client.in_flight(), 0);
}
