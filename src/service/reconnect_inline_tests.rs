#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::expect_fun_call,
    clippy::map_unwrap_or,
    clippy::cast_possible_wrap,
    clippy::future_not_send
)]
use super::*;
use crate::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::Waker;

fn init_test(name: &str) {
    crate::test_utils::init_test_logging();
    crate::test_phase!(name);
}

// Scripted maker and service for deterministic reconnect tests.
#[derive(Debug, Clone)]
struct ScriptedMaker {
    fail_count: std::cell::Cell<u32>,
}

impl ScriptedMaker {
    fn new() -> Self {
        Self {
            fail_count: std::cell::Cell::new(0),
        }
    }

    fn failing(n: u32) -> Self {
        Self {
            fail_count: std::cell::Cell::new(n),
        }
    }
}

#[derive(Debug)]
struct ScriptedMakerError;

impl fmt::Display for ScriptedMakerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "scripted maker error")
    }
}

impl std::error::Error for ScriptedMakerError {}

#[derive(Debug)]
struct ScriptedSvc {
    id: u32,
}

impl MakeService for ScriptedMaker {
    type Service = ScriptedSvc;
    type Error = ScriptedMakerError;

    fn make_service(&self) -> Result<ScriptedSvc, ScriptedMakerError> {
        let remaining = self.fail_count.get();
        if remaining > 0 {
            self.fail_count.set(remaining - 1);
            Err(ScriptedMakerError)
        } else {
            Ok(ScriptedSvc { id: 42 })
        }
    }
}

#[derive(Debug, Clone)]
struct ReconnectingMaker {
    next_id: Arc<AtomicU32>,
}

impl ReconnectingMaker {
    fn new(next_id: u32) -> Self {
        Self {
            next_id: Arc::new(AtomicU32::new(next_id)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReconnectingCallError;

impl fmt::Display for ReconnectingCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "reconnecting call error")
    }
}

impl std::error::Error for ReconnectingCallError {}

#[derive(Debug, Clone)]
struct CountingReconnectSvc {
    id: u32,
    calls: Arc<AtomicU32>,
}

#[derive(Debug, Clone)]
struct CountingReconnectMaker {
    next_id: Arc<AtomicU32>,
    calls: Arc<AtomicU32>,
}

impl CountingReconnectMaker {
    fn new(next_id: u32, calls: Arc<AtomicU32>) -> Self {
        Self {
            next_id: Arc::new(AtomicU32::new(next_id)),
            calls,
        }
    }
}

#[derive(Debug)]
struct ReconnectingSvc {
    id: u32,
    fail_next_call: bool,
}

#[derive(Debug, Clone)]
struct ManualCallController {
    state: Arc<parking_lot::Mutex<Option<Result<u32, ReconnectingCallError>>>>,
}

impl ManualCallController {
    fn new() -> Self {
        Self {
            state: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    fn fail(&self) {
        *self.state.lock() = Some(Err(ReconnectingCallError));
    }

    fn future(&self) -> ManualCallFuture {
        ManualCallFuture {
            state: Arc::clone(&self.state),
        }
    }
}

#[derive(Debug)]
struct ManualCallFuture {
    state: Arc<parking_lot::Mutex<Option<Result<u32, ReconnectingCallError>>>>,
}

impl Future for ManualCallFuture {
    type Output = Result<u32, ReconnectingCallError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.state.lock();
        state.take().map_or(Poll::Pending, Poll::Ready)
    }
}

#[derive(Debug, Clone)]
struct StaleFailureMaker {
    next_id: Arc<AtomicU32>,
}

impl StaleFailureMaker {
    fn new(next_id: u32) -> Self {
        Self {
            next_id: Arc::new(AtomicU32::new(next_id)),
        }
    }
}

#[derive(Debug)]
struct StaleFailureSvc {
    id: u32,
    delayed_failure: ManualCallController,
}

impl MakeService for ReconnectingMaker {
    type Service = ReconnectingSvc;
    type Error = ScriptedMakerError;

    fn make_service(&self) -> Result<Self::Service, Self::Error> {
        Ok(ReconnectingSvc {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            fail_next_call: false,
        })
    }
}

impl Service<()> for ReconnectingSvc {
    type Response = u32;
    type Error = ReconnectingCallError;
    type Future = std::future::Ready<Result<u32, ReconnectingCallError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        if self.fail_next_call {
            self.fail_next_call = false;
            std::future::ready(Err(ReconnectingCallError))
        } else {
            std::future::ready(Ok(self.id))
        }
    }
}

impl Service<()> for CountingReconnectSvc {
    type Response = u32;
    type Error = ReconnectingCallError;
    type Future = std::future::Ready<Result<u32, ReconnectingCallError>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::future::ready(Ok(self.id))
    }
}

impl MakeService for CountingReconnectMaker {
    type Service = CountingReconnectSvc;
    type Error = ScriptedMakerError;

    fn make_service(&self) -> Result<Self::Service, Self::Error> {
        Ok(CountingReconnectSvc {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            calls: Arc::clone(&self.calls),
        })
    }
}

#[derive(Debug, Clone)]
struct PanicReconnectMaker {
    next_id: Arc<AtomicU32>,
}

impl PanicReconnectMaker {
    fn new(next_id: u32) -> Self {
        Self {
            next_id: Arc::new(AtomicU32::new(next_id)),
        }
    }
}

#[derive(Debug)]
struct PanicReconnectSvc {
    id: u32,
    panic_on_call: bool,
}

impl MakeService for PanicReconnectMaker {
    type Service = PanicReconnectSvc;
    type Error = ScriptedMakerError;

    fn make_service(&self) -> Result<Self::Service, Self::Error> {
        Ok(PanicReconnectSvc {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            panic_on_call: false,
        })
    }
}

impl Service<()> for PanicReconnectSvc {
    type Response = u32;
    type Error = ReconnectingCallError;
    type Future = Pin<Box<dyn Future<Output = Result<u32, ReconnectingCallError>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: ()) -> Self::Future {
        assert!(
            !self.panic_on_call,
            "panic during reconnect call construction"
        );
        if self.id == 0 {
            Box::pin(PanicOnPollFuture)
        } else {
            Box::pin(std::future::ready(Ok(self.id)))
        }
    }
}

struct PanicOnPollFuture;

impl Future for PanicOnPollFuture {
    type Output = Result<u32, ReconnectingCallError>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        panic!("panic in future poll");
    }
}

impl MakeService for StaleFailureMaker {
    type Service = StaleFailureSvc;
    type Error = ScriptedMakerError;

    fn make_service(&self) -> Result<Self::Service, Self::Error> {
        Ok(StaleFailureSvc {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            delayed_failure: ManualCallController::new(),
        })
    }
}

enum StaleFailureFuture {
    Ready(Option<Result<u32, ReconnectingCallError>>),
    Pending(ManualCallFuture),
}

impl Future for StaleFailureFuture {
    type Output = Result<u32, ReconnectingCallError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Ready(result) => {
                Poll::Ready(result.take().expect("ready future polled after completion"))
            }
            Self::Pending(future) => Pin::new(future).poll(cx),
        }
    }
}

impl Service<u8> for StaleFailureSvc {
    type Response = u32;
    type Error = ReconnectingCallError;
    type Future = StaleFailureFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: u8) -> Self::Future {
        match req {
            1 => StaleFailureFuture::Pending(self.delayed_failure.future()),
            2 => StaleFailureFuture::Ready(Some(Err(ReconnectingCallError))),
            _ => StaleFailureFuture::Ready(Some(Ok(self.id))),
        }
    }
}

fn noop_waker() -> Waker {
    std::task::Waker::noop().clone()
}

// ================================================================
// MakeService / ScriptedMaker
// ================================================================

#[test]
fn scripted_maker_creates_service() {
    init_test("scripted_maker_creates_service");
    let maker = ScriptedMaker::new();
    let svc = maker.make_service().unwrap();
    assert_eq!(svc.id, 42);
    crate::test_complete!("scripted_maker_creates_service");
}

#[test]
fn scripted_maker_fails_then_succeeds() {
    init_test("scripted_maker_fails_then_succeeds");
    let maker = ScriptedMaker::failing(2);
    assert!(maker.make_service().is_err());
    assert!(maker.make_service().is_err());
    assert!(maker.make_service().is_ok());
    crate::test_complete!("scripted_maker_fails_then_succeeds");
}

// ================================================================
// Reconnect
// ================================================================

#[test]
fn reconnect_new() {
    init_test("reconnect_new");
    let maker = ScriptedMaker::new();
    let svc = maker.make_service().unwrap();
    let rc = Reconnect::new(maker, svc);
    assert!(rc.is_connected());
    assert_eq!(rc.reconnect_count(), 0);
    assert_eq!(rc.error_count(), 0);
    crate::test_complete!("reconnect_new");
}

#[test]
fn reconnect_lazy() {
    init_test("reconnect_lazy");
    let maker = ScriptedMaker::new();
    let rc = Reconnect::lazy(maker);
    assert!(!rc.is_connected());
    crate::test_complete!("reconnect_lazy");
}

#[test]
fn reconnect_manual() {
    init_test("reconnect_manual");
    let maker = ScriptedMaker::new();
    let mut rc = Reconnect::lazy(maker);
    assert!(!rc.is_connected());
    rc.reconnect().unwrap();
    assert!(rc.is_connected());
    assert_eq!(rc.reconnect_count(), 1);
    crate::test_complete!("reconnect_manual");
}

#[test]
fn reconnect_after_disconnect() {
    init_test("reconnect_after_disconnect");
    let maker = ScriptedMaker::new();
    let svc = maker.make_service().unwrap();
    let mut rc = Reconnect::new(maker, svc);
    assert!(rc.is_connected());
    rc.disconnect();
    assert!(!rc.is_connected());
    rc.reconnect().unwrap();
    assert!(rc.is_connected());
    assert_eq!(rc.reconnect_count(), 1);
    crate::test_complete!("reconnect_after_disconnect");
}

#[test]
fn reconnect_failure_tracked() {
    init_test("reconnect_failure_tracked");
    let maker = ScriptedMaker::failing(1);
    let mut rc = Reconnect::lazy(maker);
    assert!(rc.reconnect().is_err());
    assert_eq!(rc.error_count(), 1);
    assert!(!rc.is_connected());
    // Second attempt succeeds.
    rc.reconnect().unwrap();
    assert!(rc.is_connected());
    assert_eq!(rc.reconnect_count(), 1);
    crate::test_complete!("reconnect_failure_tracked");
}

#[test]
fn reconnects_after_call_error() {
    init_test("reconnects_after_call_error");
    let maker = ReconnectingMaker::new(1);
    let initial = ReconnectingSvc {
        id: 0,
        fail_next_call: true,
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let ready = rc.poll_ready(&mut cx);
    assert!(matches!(ready, Poll::Ready(Ok(()))));

    let mut first_call = rc.call(());
    let first_result = Pin::new(&mut first_call).poll(&mut cx);
    assert!(matches!(
        first_result,
        Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
    ));
    assert_eq!(rc.inner().map(|svc| svc.id), Some(0));
    assert_eq!(rc.reconnect_count(), 0);

    let reconnected = rc.poll_ready(&mut cx);
    assert!(matches!(reconnected, Poll::Ready(Ok(()))));
    assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
    assert_eq!(rc.reconnect_count(), 1);

    let mut second_call = rc.call(());
    let second_result = Pin::new(&mut second_call).poll(&mut cx);
    assert!(matches!(second_result, Poll::Ready(Ok(1))));

    crate::test_complete!("reconnects_after_call_error");
}

#[test]
fn reconnects_after_call_panic() {
    init_test("reconnects_after_call_panic");
    let maker = PanicReconnectMaker::new(1);
    let initial = PanicReconnectSvc {
        id: 0,
        panic_on_call: true,
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _f = rc.call(());
    }));
    assert!(panic.is_err(), "inner call should panic");
    assert_eq!(rc.inner().map(|svc| svc.id), Some(0));
    assert_eq!(rc.reconnect_count(), 0);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(
        rc.inner().map(|svc| svc.id),
        Some(1),
        "next poll_ready should reconnect after a synchronous call panic"
    );
    assert_eq!(rc.reconnect_count(), 1);

    let mut call = rc.call(());
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Ok(1))
    ));

    crate::test_complete!("reconnects_after_call_panic");
}

#[test]
fn reconnects_after_poll_panic() {
    init_test("reconnects_after_poll_panic");
    let maker = PanicReconnectMaker::new(1);
    let initial = PanicReconnectSvc {
        id: 0,
        panic_on_call: false, // will panic during poll instead
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

    let mut call = rc.call(());
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _f = Pin::new(&mut call).poll(&mut cx);
    }));
    assert!(panic.is_err(), "inner poll should panic");
    assert_eq!(rc.inner().map(|svc| svc.id), Some(0));
    assert_eq!(rc.reconnect_count(), 0);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(
        rc.inner().map(|svc| svc.id),
        Some(1),
        "next poll_ready should reconnect after a future poll panic"
    );
    assert_eq!(rc.reconnect_count(), 1);

    let mut call2 = rc.call(());
    assert!(matches!(
        Pin::new(&mut call2).poll(&mut cx),
        Poll::Ready(Ok(1))
    ));

    crate::test_complete!("reconnects_after_poll_panic");
}

#[test]
fn lazy_call_without_poll_ready_returns_not_ready() {
    init_test("lazy_call_without_poll_ready_returns_not_ready");
    let maker = ReconnectingMaker::new(1);
    let mut rc = Reconnect::lazy(maker);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut call = rc.call(());
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::NotReady))
    ));
    assert!(!rc.is_connected());
    assert_eq!(rc.reconnect_count(), 0);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
    assert_eq!(rc.reconnect_count(), 1);

    crate::test_complete!("lazy_call_without_poll_ready_returns_not_ready");
}

#[test]
fn connected_call_without_poll_ready_returns_not_ready() {
    init_test("connected_call_without_poll_ready_returns_not_ready");
    let calls = Arc::new(AtomicU32::new(0));
    let maker = CountingReconnectMaker::new(1, Arc::clone(&calls));
    let initial = CountingReconnectSvc {
        id: 7,
        calls: Arc::clone(&calls),
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut call = rc.call(());
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::NotReady))
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "readiness misuse must not invoke the connected inner service"
    );

    crate::test_complete!("connected_call_without_poll_ready_returns_not_ready");
}

#[test]
fn connected_ready_window_is_consumed_by_call() {
    init_test("connected_ready_window_is_consumed_by_call");
    let calls = Arc::new(AtomicU32::new(0));
    let maker = CountingReconnectMaker::new(1, Arc::clone(&calls));
    let initial = CountingReconnectSvc {
        id: 9,
        calls: Arc::clone(&calls),
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

    let mut first = rc.call(());
    assert!(matches!(
        Pin::new(&mut first).poll(&mut cx),
        Poll::Ready(Ok(9))
    ));

    let mut second = rc.call(());
    assert!(matches!(
        Pin::new(&mut second).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::NotReady))
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "exactly one call should consume a connected readiness window"
    );

    crate::test_complete!("connected_ready_window_is_consumed_by_call");
}

#[test]
fn call_after_disconnect_returns_not_ready() {
    init_test("call_after_disconnect_returns_not_ready");
    let maker = ReconnectingMaker::new(1);
    let initial = ReconnectingSvc {
        id: 0,
        fail_next_call: false,
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    rc.disconnect();
    assert!(!rc.is_connected());

    let mut call = rc.call(());
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::NotReady))
    ));
    assert_eq!(rc.reconnect_count(), 0);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
    assert_eq!(rc.reconnect_count(), 1);

    crate::test_complete!("call_after_disconnect_returns_not_ready");
}

#[test]
fn stale_call_error_does_not_drop_reconnected_service() {
    init_test("stale_call_error_does_not_drop_reconnected_service");
    let delayed_failure = ManualCallController::new();
    let maker = StaleFailureMaker::new(1);
    let initial = StaleFailureSvc {
        id: 0,
        delayed_failure: delayed_failure.clone(),
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

    let mut stale_call = rc.call(1);
    assert!(matches!(
        Pin::new(&mut stale_call).poll(&mut cx),
        Poll::Pending
    ));

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    let mut failing_call = rc.call(2);
    assert!(matches!(
        Pin::new(&mut failing_call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
    ));

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
    assert_eq!(rc.reconnect_count(), 1);

    delayed_failure.fail();
    assert!(matches!(
        Pin::new(&mut stale_call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
    ));

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
    assert_eq!(
        rc.reconnect_count(),
        1,
        "stale failures from a retired service must not force another reconnect"
    );

    crate::test_complete!("stale_call_error_does_not_drop_reconnected_service");
}

#[test]
fn reconnect_inner_ref() {
    let maker = ScriptedMaker::new();
    let svc = maker.make_service().unwrap();
    let rc = Reconnect::new(maker, svc);
    assert!(rc.inner().is_some());
    assert_eq!(rc.inner().unwrap().id, 42);
}

#[test]
fn reconnect_inner_mut() {
    let maker = ScriptedMaker::new();
    let svc = maker.make_service().unwrap();
    let mut rc = Reconnect::new(maker, svc);
    assert!(rc.inner_mut().is_some());
}

#[test]
fn reconnect_maker_ref() {
    let maker = ScriptedMaker::new();
    let svc = maker.make_service().unwrap();
    let rc = Reconnect::new(maker, svc);
    let _ = rc.maker();
}

#[test]
fn reconnect_debug() {
    let maker = ScriptedMaker::new();
    let svc = maker.make_service().unwrap();
    let rc = Reconnect::new(maker, svc);
    let dbg = format!("{rc:?}");
    assert!(dbg.contains("Reconnect"));
    assert!(dbg.contains("connected: true"));
}

// ================================================================
// ReconnectError
// ================================================================

#[test]
fn reconnect_error_inner_display() {
    let err: ReconnectError<std::io::Error, std::io::Error> =
        ReconnectError::Inner(std::io::Error::other("fail"));
    assert!(format!("{err}").contains("service error"));
}

#[test]
fn reconnect_error_connect_display() {
    let err: ReconnectError<std::io::Error, std::io::Error> =
        ReconnectError::Connect(std::io::Error::other("fail"));
    assert!(format!("{err}").contains("reconnect failed"));
}

#[test]
fn reconnect_error_not_ready_display() {
    let err: ReconnectError<std::io::Error, std::io::Error> = ReconnectError::NotReady;
    assert!(format!("{err}").contains("poll_ready required"));
}

#[test]
fn reconnect_error_polled_after_completion_display() {
    let err: ReconnectError<std::io::Error, std::io::Error> = ReconnectError::PolledAfterCompletion;
    assert!(format!("{err}").contains("polled after completion"));
}

#[test]
fn reconnect_error_source() {
    use std::error::Error;
    let err: ReconnectError<std::io::Error, std::io::Error> =
        ReconnectError::Inner(std::io::Error::other("fail"));
    assert!(err.source().is_some());

    let not_ready: ReconnectError<std::io::Error, std::io::Error> = ReconnectError::NotReady;
    assert!(not_ready.source().is_none());

    let done: ReconnectError<std::io::Error, std::io::Error> =
        ReconnectError::PolledAfterCompletion;
    assert!(done.source().is_none());
}

#[test]
fn reconnect_error_debug() {
    let err: ReconnectError<std::io::Error, std::io::Error> =
        ReconnectError::Inner(std::io::Error::other("fail"));
    let dbg = format!("{err:?}");
    assert!(dbg.contains("Inner"));
}

// ================================================================
// ReconnectLayer
// ================================================================

#[test]
fn reconnect_layer_new() {
    let layer = ReconnectLayer::new(ScriptedMaker::new());
    let dbg = format!("{layer:?}");
    assert!(dbg.contains("ReconnectLayer"));
}

#[test]
fn reconnect_layer_applies() {
    init_test("reconnect_layer_applies");
    let layer = ReconnectLayer::new(ScriptedMaker::new());
    let initial = ScriptedSvc { id: 1 };
    let svc = layer.layer(initial);
    assert!(svc.is_connected());
    assert_eq!(svc.inner().unwrap().id, 1);
    crate::test_complete!("reconnect_layer_applies");
}

// ================================================================
// ReconnectFuture
// ================================================================

#[test]
fn reconnect_future_debug() {
    let fut: ReconnectFuture<_, std::io::Error, std::io::Error> = ReconnectFuture::inner(
        std::future::ready(Ok::<i32, std::io::Error>(42)),
        Arc::new(ReconnectSignal::new()),
    );
    let dbg = format!("{fut:?}");
    assert!(dbg.contains("ReconnectFuture"));
}

#[test]
fn reconnect_call_without_poll_ready_second_poll_fails_closed() {
    init_test("reconnect_call_without_poll_ready_second_poll_fails_closed");
    let maker = ReconnectingMaker::new(1);
    let mut rc = Reconnect::lazy(maker);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    let mut call = rc.call(());
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::NotReady))
    ));
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::PolledAfterCompletion))
    ));

    crate::test_complete!("reconnect_call_without_poll_ready_second_poll_fails_closed");
}

#[test]
fn reconnect_success_second_poll_fails_closed() {
    init_test("reconnect_success_second_poll_fails_closed");
    let calls = Arc::new(AtomicU32::new(0));
    let maker = CountingReconnectMaker::new(1, Arc::clone(&calls));
    let initial = CountingReconnectSvc {
        id: 9,
        calls: Arc::clone(&calls),
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

    let mut call = rc.call(());
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Ok(9))
    ));
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::PolledAfterCompletion))
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "successful first poll must still invoke the inner service exactly once"
    );

    crate::test_complete!("reconnect_success_second_poll_fails_closed");
}

#[test]
fn reconnect_error_second_poll_fails_closed_and_refresh_still_applies() {
    init_test("reconnect_error_second_poll_fails_closed_and_refresh_still_applies");
    let maker = ReconnectingMaker::new(1);
    let initial = ReconnectingSvc {
        id: 0,
        fail_next_call: true,
    };
    let mut rc = Reconnect::new(maker, initial);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);

    assert!(matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))));

    let mut call = rc.call(());
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
    ));
    assert!(matches!(
        Pin::new(&mut call).poll(&mut cx),
        Poll::Ready(Err(ReconnectError::PolledAfterCompletion))
    ));

    assert!(
        matches!(rc.poll_ready(&mut cx), Poll::Ready(Ok(()))),
        "first terminal error poll must still trigger reconnect on next readiness probe"
    );
    assert_eq!(rc.inner().map(|svc| svc.id), Some(1));
    assert_eq!(rc.reconnect_count(), 1);

    crate::test_complete!("reconnect_error_second_poll_fails_closed_and_refresh_still_applies");
}

// Readiness recovery is part of the service contract, independent of whether
// the failed request and its next readiness waiter run on the same task.
type ReadinessFaultFuture =
    Pin<Box<dyn Future<Output = Result<u32, ReconnectingCallError>> + Send>>;

struct ReadinessFaultService {
    id: u32,
    ready: bool,
    failure: ManualCallController,
    calls: Arc<AtomicU32>,
    releases: Arc<AtomicU32>,
    before_ready: Option<Box<dyn FnOnce() + Send>>,
}

impl fmt::Debug for ReadinessFaultService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadinessFaultService")
            .field("id", &self.id)
            .field("ready", &self.ready)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct ReadinessFaultMaker {
    next_id: AtomicU32,
    calls: Arc<AtomicU32>,
    releases: Arc<AtomicU32>,
}

impl MakeService for ReadinessFaultMaker {
    type Service = ReadinessFaultService;
    type Error = ScriptedMakerError;

    fn make_service(&self) -> Result<Self::Service, Self::Error> {
        Ok(ReadinessFaultService {
            id: self.next_id.fetch_add(1, Ordering::SeqCst),
            ready: true,
            failure: ManualCallController::new(),
            calls: Arc::clone(&self.calls),
            releases: Arc::clone(&self.releases),
            before_ready: None,
        })
    }
}

impl Service<u8> for ReadinessFaultService {
    type Response = u32;
    type Error = ReconnectingCallError;
    type Future = ReadinessFaultFuture;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if let Some(before_ready) = self.before_ready.take() {
            before_ready();
        }
        if self.ready {
            Poll::Ready(Ok(()))
        } else {
            // This instance never recovers on its own. Reconnect must wake
            // its own waiter when an outstanding request reports failure.
            Poll::Pending
        }
    }

    fn call(&mut self, request: u8) -> Self::Future {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if request == 0 {
            return Box::pin(std::future::ready(Ok(self.id)));
        }
        self.ready = false;
        let failure = self.failure.future();
        Box::pin(async move {
            let result = failure.await;
            assert_ne!(request, 2, "parked reconnect call panic");
            result
        })
    }

    fn release_readiness(&mut self) -> super::super::ReadinessRelease {
        let releases = Arc::clone(&self.releases);
        super::super::ReadinessRelease::new(move || {
            releases.fetch_add(1, Ordering::SeqCst);
        })
    }
}

fn readiness_fault_reconnect() -> (Reconnect<ReadinessFaultMaker>, ManualCallController) {
    let failure = ManualCallController::new();
    let calls = Arc::new(AtomicU32::new(0));
    let releases = Arc::new(AtomicU32::new(0));
    let initial = ReadinessFaultService {
        id: 0,
        ready: true,
        failure: failure.clone(),
        calls: Arc::clone(&calls),
        releases: Arc::clone(&releases),
        before_ready: None,
    };
    let maker = ReadinessFaultMaker {
        next_id: AtomicU32::new(1),
        calls,
        releases,
    };
    (Reconnect::new(maker, initial), failure)
}

fn poll_reconnect_future<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}

struct ReconnectReadinessWake {
    wakes: Arc<AtomicU32>,
    drops: Arc<AtomicU32>,
    outer_lock: Option<Arc<Mutex<()>>>,
    forward: Option<Waker>,
    panic_on_wake: bool,
}

impl ReconnectReadinessWake {
    fn check_unlocked(&self) {
        if let Some(outer_lock) = &self.outer_lock {
            assert!(
                outer_lock.try_lock().is_ok(),
                "readiness callback ran under the shared service lock"
            );
        }
    }
}

impl std::task::Wake for ReconnectReadinessWake {
    fn wake(self: Arc<Self>) {
        Self::wake_by_ref(&self);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.check_unlocked();
        self.wakes.fetch_add(1, Ordering::SeqCst);
        if let Some(forward) = &self.forward {
            forward.wake_by_ref();
        }
        assert!(!self.panic_on_wake, "secondary readiness wake panic");
    }
}

impl Drop for ReconnectReadinessWake {
    fn drop(&mut self) {
        self.check_unlocked();
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn readiness_probe(
    wakes: &Arc<AtomicU32>,
    drops: &Arc<AtomicU32>,
    outer_lock: Option<Arc<Mutex<()>>>,
) -> Waker {
    Waker::from(Arc::new(ReconnectReadinessWake {
        wakes: Arc::clone(wakes),
        drops: Arc::clone(drops),
        outer_lock,
        forward: None,
        panic_on_wake: false,
    }))
}

#[test]
fn reconnect_failure_invalidates_an_already_granted_ready_window() {
    let (mut reconnect, failure) = readiness_fault_reconnect();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(reconnect.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    let mut first = reconnect.call(1);
    assert!(poll_reconnect_future(&mut first).is_pending());

    reconnect.inner_mut().unwrap().ready = true;
    assert!(matches!(reconnect.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    failure.fail();
    assert!(matches!(
        poll_reconnect_future(&mut first),
        Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
    ));
    assert!(matches!(
        poll_reconnect_future(&mut reconnect.call(0)),
        Poll::Ready(Err(ReconnectError::NotReady))
    ));
    assert_eq!(
        reconnect.maker().calls.load(Ordering::SeqCst),
        1,
        "the invalidated request must not reach the failed instance"
    );
    assert_eq!(reconnect.maker().releases.load(Ordering::SeqCst), 1);

    assert!(matches!(reconnect.poll_ready(&mut cx), Poll::Ready(Ok(()))));
    assert!(matches!(
        poll_reconnect_future(&mut reconnect.call(0)),
        Poll::Ready(Ok(1))
    ));
    assert_eq!(reconnect.reconnect_count(), 1);
}

#[test]
fn reconnect_failure_during_inner_readiness_cannot_lose_its_wake() {
    for inner_ready in [false, true] {
        let (mut reconnect, failure) = readiness_fault_reconnect();
        assert!(matches!(
            reconnect.poll_ready(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        let mut first = reconnect.call(1);
        assert!(poll_reconnect_future(&mut first).is_pending());
        failure.fail();
        let inner = reconnect.inner_mut().unwrap();
        inner.ready = inner_ready;
        inner.before_ready = Some(Box::new(move || {
            assert!(matches!(
                poll_reconnect_future(&mut first),
                Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
            ));
        }));

        let wakes = Arc::new(AtomicU32::new(0));
        let drops = Arc::new(AtomicU32::new(0));
        let waker = readiness_probe(&wakes, &drops, None);
        assert!(reconnect
            .poll_ready(&mut Context::from_waker(&waker))
            .is_pending());
        assert_eq!(
            wakes.load(Ordering::SeqCst),
            1,
            "failure before registration must still request the retry poll"
        );
        assert_eq!(
            reconnect.maker().releases.load(Ordering::SeqCst),
            u32::from(inner_ready)
        );
        assert!(matches!(
            reconnect.poll_ready(&mut Context::from_waker(&waker)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(reconnect.reconnect_count(), 1);
        assert!(matches!(
            poll_reconnect_future(&mut reconnect.call(0)),
            Poll::Ready(Ok(1))
        ));
        drop(waker);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn reconnect_replaces_releases_and_drops_readiness_wakers_after_unlock() {
    use super::super::service::ReadinessReleaseScope;

    let (mut reconnect, failure) = readiness_fault_reconnect();
    assert!(matches!(
        reconnect.poll_ready(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    ));
    let mut first = reconnect.call(1);
    assert!(poll_reconnect_future(&mut first).is_pending());

    let outer = Arc::new(Mutex::new(()));
    let wakes = Arc::new(AtomicU32::new(0));
    let drops = Arc::new(AtomicU32::new(0));
    let old = readiness_probe(&wakes, &drops, Some(Arc::clone(&outer)));
    assert!(reconnect
        .poll_ready(&mut Context::from_waker(&old))
        .is_pending());
    drop(old);

    let next = readiness_probe(&wakes, &drops, Some(Arc::clone(&outer)));
    let scope = ReadinessReleaseScope::new();
    let locked = outer.lock().unwrap();
    assert!(reconnect
        .poll_ready(&mut Context::from_waker(&next))
        .is_pending());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop(locked);
    drop(scope);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    drop(next);

    let scope = ReadinessReleaseScope::new();
    let locked = outer.lock().unwrap();
    failure.fail();
    assert!(matches!(
        poll_reconnect_future(&mut first),
        Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
    ));
    assert_eq!(wakes.load(Ordering::SeqCst), 0);
    drop(locked);
    drop(scope);
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    assert_eq!(drops.load(Ordering::SeqCst), 2);

    for drop_service in [false, true] {
        let (mut retained, _) = readiness_fault_reconnect();
        assert!(matches!(
            retained.poll_ready(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        let active = retained.call(1);
        let waker = readiness_probe(&wakes, &drops, Some(Arc::clone(&outer)));
        assert!(retained
            .poll_ready(&mut Context::from_waker(&waker))
            .is_pending());
        drop(waker);
        let before = drops.load(Ordering::SeqCst);
        let scope = ReadinessReleaseScope::new();
        let locked = outer.lock().unwrap();
        if drop_service {
            drop(retained);
        } else {
            drop(retained.release_readiness());
        }
        assert_eq!(drops.load(Ordering::SeqCst), before);
        drop(locked);
        drop(scope);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            before + 1,
            "an in-flight call must not retain abandoned readiness ownership"
        );
        drop(active);
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn reconnect_fault_from_retired_instance_cannot_wake_its_replacement() {
    for panics in [false, true] {
        let (mut reconnect, failure) = readiness_fault_reconnect();
        assert!(matches!(
            reconnect.poll_ready(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Ok(()))
        ));
        let mut first = reconnect.call(if panics { 2 } else { 1 });
        assert!(poll_reconnect_future(&mut first).is_pending());

        reconnect.reconnect().unwrap();
        reconnect.inner_mut().unwrap().ready = false;
        let wakes = Arc::new(AtomicU32::new(0));
        let drops = Arc::new(AtomicU32::new(0));
        let waker = readiness_probe(&wakes, &drops, None);
        assert!(reconnect
            .poll_ready(&mut Context::from_waker(&waker))
            .is_pending());

        std::thread::spawn(move || {
            failure.fail();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                poll_reconnect_future(&mut first)
            }));
            if panics {
                assert!(outcome.is_err());
            } else {
                assert!(matches!(
                    outcome.unwrap(),
                    Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
                ));
            }
        })
        .join()
        .unwrap();

        assert_eq!(wakes.load(Ordering::SeqCst), 0);
        reconnect.inner_mut().unwrap().ready = true;
        assert!(matches!(
            reconnect.poll_ready(&mut Context::from_waker(&waker)),
            Poll::Ready(Ok(()))
        ));
        assert_eq!(reconnect.reconnect_count(), 1);
        assert!(matches!(
            poll_reconnect_future(&mut reconnect.call(0)),
            Poll::Ready(Ok(1))
        ));
        drop(waker);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn reconnect_preserves_the_original_poll_panic_when_readiness_wake_panics() {
    let (mut reconnect, failure) = readiness_fault_reconnect();
    assert!(matches!(
        reconnect.poll_ready(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    ));
    let mut first = reconnect.call(2);
    assert!(poll_reconnect_future(&mut first).is_pending());
    let wakes = Arc::new(AtomicU32::new(0));
    let drops = Arc::new(AtomicU32::new(0));
    let waker = Waker::from(Arc::new(ReconnectReadinessWake {
        wakes: Arc::clone(&wakes),
        drops: Arc::clone(&drops),
        outer_lock: None,
        forward: None,
        panic_on_wake: true,
    }));
    assert!(reconnect
        .poll_ready(&mut Context::from_waker(&waker))
        .is_pending());
    failure.fail();
    let payload = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        poll_reconnect_future(&mut first)
    }))
    .expect_err("the original poll panic must propagate");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap();
    assert!(message.contains("parked reconnect call panic"));
    assert_eq!(wakes.load(Ordering::SeqCst), 1);
    drop(waker);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert!(matches!(
        reconnect.poll_ready(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(reconnect.reconnect_count(), 1);
}

#[test]
fn reconnect_public_auto_traits_remain_available() {
    fn check<T: Send + Sync + Unpin + std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
    check::<Reconnect<CountingReconnectMaker>>();
    check::<ReconnectFuture<std::future::Ready<Result<u8, ()>>, (), ()>>();
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn native_reconnect_call_failure_wakes_parked_readiness() {
    use super::super::ServiceExt;
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::time::Duration;

    for workers in [1, 2] {
        for panics in [false, true] {
            let runtime = if workers == 1 {
                RuntimeBuilder::current_thread()
            } else {
                RuntimeBuilder::new().worker_threads(workers)
            }
            .build()
            .unwrap();
            let wakes = Arc::new(AtomicU32::new(0));
            let drops = Arc::new(AtomicU32::new(0));
            let created = Arc::new(AtomicU32::new(0));
            runtime.block_on(async {
                let cx = crate::cx::Cx::current().unwrap();
                let (mut reconnect, failure) = readiness_fault_reconnect();
                assert!(matches!(
                    reconnect.poll_ready(&mut Context::from_waker(Waker::noop())),
                    Poll::Ready(Ok(()))
                ));
                let mut first = reconnect.call(if panics { 2 } else { 1 });
                assert!(poll_reconnect_future(&mut first).is_pending());

                let child_wakes = Arc::clone(&wakes);
                let child_drops = Arc::clone(&drops);
                let child_created = Arc::clone(&created);
                let (parked, mut witness) = crate::channel::oneshot::channel();
                let mut waiter = cx
                    .spawn(move |child| async move {
                        let mut readiness = Box::pin(reconnect.ready());
                        let mut parked = Some(parked);
                        crate::time::timeout(child.now(), Duration::from_secs(5), async {
                            std::future::poll_fn(|task| {
                                child_created.fetch_add(1, Ordering::SeqCst);
                                let relay = Waker::from(Arc::new(ReconnectReadinessWake {
                                    wakes: Arc::clone(&child_wakes),
                                    drops: Arc::clone(&child_drops),
                                    outer_lock: None,
                                    forward: Some(task.waker().clone()),
                                    panic_on_wake: false,
                                }));
                                let result = readiness
                                    .as_mut()
                                    .poll(&mut Context::from_waker(&relay));
                                if result.is_pending() {
                                    if let Some(parked) = parked.take() {
                                        parked.send_blocking(()).unwrap();
                                    }
                                }
                                result
                            })
                            .await
                        })
                        .await
                        .expect("the failed call must wake the parked readiness task")
                        .unwrap();
                        drop(readiness);
                        let response = reconnect.call(0).await.unwrap();
                        assert_eq!(reconnect.maker().calls.load(Ordering::SeqCst), 2);
                        (response, reconnect.reconnect_count())
                    })
                    .unwrap();
                crate::time::timeout(cx.now(), Duration::from_secs(5), witness.recv(&cx))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(wakes.load(Ordering::SeqCst), 0);
                let mut complete = move || {
                    failure.fail();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        poll_reconnect_future(&mut first)
                    }));
                    if panics {
                        assert!(result.is_err());
                    } else {
                        assert!(matches!(
                            result.unwrap(),
                            Poll::Ready(Err(ReconnectError::Inner(ReconnectingCallError)))
                        ));
                    }
                };
                if workers == 1 {
                    complete();
                } else {
                    std::thread::spawn(complete).join().unwrap();
                }
                assert!(
                    wakes.load(Ordering::SeqCst) > 0,
                    "the failed call emitted a real readiness notification"
                );
                assert_eq!(waiter.join(&cx).await.unwrap(), (1, 1));
            });
            let drained = runtime.shutdown_drained(Duration::from_secs(5));
            assert_eq!(drained.outcome, RootDrainOutcome::Quiescent, "{drained:?}");
            assert_eq!(
                (
                    drained.live_tasks,
                    drained.live_regions,
                    drained.pending_obligations,
                    drained.pending_spawns,
                    drained.queued_finalizers,
                ),
                (0, 0, 0, 0, 0)
            );
            assert!(!drained.has_pending_obligation_posts);
            assert_eq!(
                drops.load(Ordering::SeqCst),
                created.load(Ordering::SeqCst),
                "no readiness relay retains a retired native task"
            );
        }
    }
}
