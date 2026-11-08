use super::*;
use crate::security::AuthenticationTag;
use crate::transport::SymbolStreamExt;
use crate::types::{Symbol, SymbolKind};
use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};

enum Event {
    Symbol(AuthenticatedSymbol),
    Error(StreamError),
    End,
}

struct ScriptState {
    events: VecDeque<Event>,
    polls: usize,
    drops: usize,
    panic_after_take: bool,
    waiter: Option<Waker>,
}

struct Script(Arc<Mutex<ScriptState>>);

fn script(events: impl IntoIterator<Item = Event>) -> (Script, Arc<Mutex<ScriptState>>) {
    let state = Arc::new(Mutex::new(ScriptState {
        events: events.into_iter().collect(), polls: 0, drops: 0,
        panic_after_take: false, waiter: None,
    }));
    (Script(state.clone()), state)
}

fn publish(state: &Arc<Mutex<ScriptState>>, event: Event) {
    let waiter = {
        let mut state = state.lock().unwrap();
        state.events.push_back(event);
        state.waiter.take()
    };
    if let Some(waiter) = waiter { waiter.wake(); }
}

impl SymbolStream for Script {
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let mut state = self.0.lock().unwrap();
        state.polls += 1;
        let Some(event) = state.events.pop_front() else {
            state.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        };
        let panic_after_take = state.panic_after_take;
        drop(state);
        assert!(!panic_after_take, "fixture consumed input before panicking");
        match event {
            Event::Symbol(symbol) => Poll::Ready(Some(Ok(symbol))),
            Event::Error(error) => Poll::Ready(Some(Err(error))),
            Event::End => Poll::Ready(None),
        }
    }
}

impl Drop for Script {
    fn drop(&mut self) { self.0.lock().unwrap().drops += 1; }
}

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

fn symbol(object: u64, esi: u32, bytes: &[u8]) -> AuthenticatedSymbol {
    let raw = Symbol::new(SymbolId::new(ObjectId::new(0, object), 0, esi), bytes.to_vec(), SymbolKind::Source);
    let signed = SecurityContext::new(AuthKey::from_seed(42)).sign_symbol(&raw);
    // Every test symbol arrives without a trusted receiver-side flag.
    AuthenticatedSymbol::from_parts(signed.symbol().clone(), *signed.tag())
}

fn next(stream: &mut MultipathSymbolStream, cx: &mut Context<'_>) -> Option<Result<AuthenticatedSymbol, StreamError>> {
    for _ in 0..128 {
        if let Poll::Ready(value) = Pin::new(&mut *stream).poll_next(cx) { return value; }
    }
    panic!("ready scripted stream exceeded its bounded test poll count");
}

#[test]
fn limits_and_path_admission_reject_before_polling_sources() {
    for bounds in [(0, 8, 1, 1), (65, 8, 1, 1), (1, 0, 1, 1), (1, 8, 0, 1), (1, 8, 1, 0), (1, 8, usize::MAX, 2)] {
        assert!(MultipathStreamLimits::new(bounds.0, bounds.1, bounds.2, bounds.3).is_err());
    }
    let limits = MultipathStreamLimits::new(1, 8, 2, 3).unwrap();
    assert_eq!(limits.max_paths(), 1);
    assert_eq!(limits.max_symbol_bytes(), 8);
    assert_eq!(limits.max_objects(), 2);
    assert_eq!(limits.max_symbols_per_object(), 3);
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), limits);
    let (first, first_state) = script([Event::End]);
    stream.add_path(PathId(1), first).unwrap();
    let (excess, excess_state) = script([]);
    assert!(stream.add_path(PathId(2), excess).is_err());
    let (duplicate, duplicate_state) = script([]);
    assert!(stream.add_path(PathId(1), duplicate).is_err());
    for state in [excess_state, duplicate_state] {
        assert_eq!(state.lock().unwrap().polls, 0);
        assert_eq!(state.lock().unwrap().drops, 1);
    }
    assert_eq!(first_state.lock().unwrap().polls, 0);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(next(&mut stream, &mut cx).is_none());
    assert!(stream.is_exhausted());
    assert_eq!(stream.size_hint(), (0, Some(0)));
    assert_eq!(first_state.lock().unwrap().drops, 1);
    let (late, _) = script([]);
    assert!(matches!(stream.add_path(PathId(3), late), Err(StreamError::Closed)));
}

#[test]
fn cross_path_duplicates_are_authenticated_then_suppressed_without_reordering() {
    let first = symbol(1, 0, b"zero");
    assert!(!first.is_verified());
    let (a, _) = script([
        Event::Symbol(first.clone()), Event::Symbol(symbol(1, 1, b"one")), Event::End,
    ]);
    let (b, _) = script([
        Event::Symbol(first), Event::Symbol(symbol(1, 2, b"two")), Event::End,
    ]);
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::default());
    stream.add_path(PathId(1), a).unwrap();
    stream.add_path(PathId(2), b).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let mut ids = Vec::new();
    while let Some(symbol) = next(&mut stream, &mut cx) {
        let symbol = symbol.unwrap();
        assert!(symbol.is_verified());
        ids.push(symbol.symbol().esi());
    }
    assert_eq!(ids, [0, 1, 2]);
    assert_eq!(stream.path_stats(PathId(1)).unwrap().authenticated_symbols, 2);
    assert_eq!(stream.path_stats(PathId(2)).unwrap().authenticated_symbols, 2);
    assert_eq!(stream.path_stats(PathId(2)).unwrap().duplicate_symbols, 1);
    assert_eq!(stream.path_stats(PathId(2)).unwrap().delivered_symbols, 1);
    assert_eq!(stream.dedup_stats().symbols_tracked, 3);
    assert_eq!(stream.dedup_stats().duplicates_detected, 1);
    assert!(!format!("{stream:?}").contains("zero"));
}

#[test]
fn one_transport_failure_retires_its_owner_while_other_paths_keep_delivering() {
    let (a, failed) = script([
        Event::Symbol(symbol(1, 0, b"a")), Event::Error(StreamError::Reset),
    ]);
    let (b, healthy) = script([
        Event::Symbol(symbol(1, 1, b"b")), Event::Symbol(symbol(1, 2, b"c")), Event::End,
    ]);
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::default());
    stream.add_path(PathId(1), a).unwrap();
    stream.add_path(PathId(2), b).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    for esi in 0..3 {
        assert_eq!(next(&mut stream, &mut cx).unwrap().unwrap().symbol().esi(), esi);
    }
    assert!(stream.path_stats(PathId(1)).unwrap().failed);
    assert!(matches!(stream.path_error(PathId(1)), Some(StreamError::Reset)));
    assert_eq!(failed.lock().unwrap().drops, 1, "failed transport is released promptly");
    assert_eq!(healthy.lock().unwrap().drops, 0);
    assert!(matches!(next(&mut stream, &mut cx), Some(Err(StreamError::Reset))));
    assert!(stream.is_exhausted());
    assert!(matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None)));
    assert_eq!(failed.lock().unwrap().polls, 2, "a failed source is never polled again");
    assert_eq!(healthy.lock().unwrap().drops, 1);
}

#[test]
fn every_blocked_path_registers_a_wake_without_self_waking() {
    let limits = MultipathStreamLimits::new(64, 8, 1, 64).unwrap();
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), limits);
    let mut states = Vec::new();
    for path in 0..64 {
        let (input, state) = script([]);
        stream.add_path(PathId(path), input).unwrap();
        states.push(state);
    }
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    {
        let mut wait = Box::pin(stream.next());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
    }
    assert!(states.iter().all(|state| state.lock().unwrap().polls == 1));
    assert!(states.iter().all(|state| state.lock().unwrap().waiter.is_some()));
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    publish(&states[63], Event::Symbol(symbol(1, 63, b"last")));
    assert_eq!(counter.0.load(Ordering::SeqCst), 1, "the final path can wake the merged receiver");
    let received = next(&mut stream, &mut cx).unwrap().unwrap();
    assert_eq!(received.symbol().esi(), 63);
    assert_eq!(stream.path_stats(PathId(63)).unwrap().delivered_symbols, 1);
}

struct Repeated {
    symbol: AuthenticatedSymbol,
    polls: Arc<AtomicUsize>,
}

impl SymbolStream for Repeated {
    fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Some(Ok(self.symbol.clone())))
    }
}

#[test]
fn duplicate_flood_has_a_poll_budget_and_cannot_starve_a_new_ready_path() {
    let polls = Arc::new(AtomicUsize::new(0));
    let repeated = Repeated { symbol: symbol(1, 0, b"same"), polls: polls.clone() };
    let (second, second_state) = script([]);
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::default());
    stream.add_path(PathId(1), repeated).unwrap();
    stream.add_path(PathId(2), second).unwrap();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut cx = Context::from_waker(&waker);
    assert_eq!(next(&mut stream, &mut cx).unwrap().unwrap().symbol().esi(), 0);
    let before = polls.load(Ordering::SeqCst);
    assert!(Pin::new(&mut stream).poll_next(&mut cx).is_pending());
    assert_eq!(polls.load(Ordering::SeqCst) - before, 63);
    assert_eq!(second_state.lock().unwrap().polls, 1);
    assert_eq!(counter.0.load(Ordering::SeqCst), 1, "budget exhaustion schedules remaining ready work");
    assert_eq!(stream.dedup_stats().symbols_tracked, 1);
    publish(&second_state, Event::Symbol(symbol(1, 1, b"new")));
    assert_eq!(next(&mut stream, &mut cx).unwrap().unwrap().symbol().esi(), 1);
    assert_eq!(polls.load(Ordering::SeqCst) - before, 63, "ready sibling gets the next turn");
}

#[test]
fn invalid_authentication_cannot_poison_duplicate_history_and_payload_limits_precede_admission() {
    let valid = symbol(1, 0, b"good");
    let wrong = SecurityContext::new(AuthKey::from_seed(7)).sign_symbol(valid.symbol());
    assert!(wrong.is_verified());
    let sentinel = AuthenticatedSymbol::from_parts(valid.symbol().clone(), AuthenticationTag::zero());
    for invalid in [wrong, sentinel] {
        let (bad, _) = script([Event::Symbol(invalid)]);
        let (good, untouched) = script([Event::Symbol(valid.clone())]);
        let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::default());
        stream.add_path(PathId(1), bad).unwrap();
        stream.add_path(PathId(2), good).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(next(&mut stream, &mut cx), Some(Err(StreamError::AuthenticationFailed { .. }))));
        assert_eq!(stream.dedup_stats().objects_tracked, 0);
        assert_eq!(stream.dedup_stats().symbols_tracked, 0);
        assert_eq!(stream.path_stats(PathId(1)).unwrap().authenticated_symbols, 0);
        assert_eq!(untouched.lock().unwrap().polls, 0, "authentication failure is globally terminal");
        assert!(matches!(stream.path_error(PathId(1)), Some(StreamError::AuthenticationFailed { .. })));
    }
    let (large, _) = script([Event::Symbol(symbol(1, 0, b"ninebytes"))]);
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::new(1, 8, 1, 1).unwrap());
    stream.add_path(PathId(1), large).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(next(&mut stream, &mut cx), Some(Err(StreamError::ProtocolError { .. }))));
    assert_eq!(stream.dedup_stats().symbols_tracked, 0);
}

#[test]
fn cancellation_and_protocol_errors_are_never_hidden_as_path_failover() {
    let failures = [
        StreamError::Cancelled,
        StreamError::AuthenticationFailed { reason: "fixture".into() },
        StreamError::ProtocolError { details: "fixture".into() },
        StreamError::PolledAfterCompletion,
        StreamError::Io { source: io::ErrorKind::Interrupted.into() },
        StreamError::Io { source: io::ErrorKind::InvalidData.into() },
    ];
    for error in failures {
        let original = error.to_string();
        let (bad, _) = script([Event::Error(error)]);
        let (good, untouched) = script([Event::Symbol(symbol(1, 0, b"good"))]);
        let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::default());
        stream.add_path(PathId(1), bad).unwrap();
        stream.add_path(PathId(2), good).unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let error = next(&mut stream, &mut cx).unwrap().unwrap_err();
        assert_eq!(error.to_string(), original);
        assert_eq!(stream.path_error(PathId(1)).unwrap().to_string(), original);
        assert_eq!(untouched.lock().unwrap().polls, 0);
        assert!(stream.is_exhausted());
        assert!(matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None)));
    }
}

#[test]
fn bounded_history_overflow_passes_symbols_through_and_explicit_clear_releases_it() {
    let (input, control) = script([
        Event::Symbol(symbol(1, 0, b"a")),
        Event::Symbol(symbol(1, 1, b"b")),
        Event::Symbol(symbol(1, 1, b"b")),
        Event::Symbol(symbol(2, 0, b"c")),
        Event::Symbol(symbol(1, 0, b"a")),
    ]);
    let limits = MultipathStreamLimits::new(1, 8, 1, 1).unwrap();
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), limits);
    stream.add_path(PathId(1), input).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    for (object, esi) in [(1, 0), (1, 1), (1, 1), (2, 0)] {
        let symbol = next(&mut stream, &mut cx).unwrap().unwrap();
        assert_eq!(symbol.symbol().object_id(), ObjectId::new(0, object));
        assert_eq!(symbol.symbol().esi(), esi);
    }
    {
        let mut wait = Box::pin(stream.next());
        assert!(wait.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(stream.dedup_stats().objects_tracked, 1);
    assert_eq!(stream.dedup_stats().symbols_tracked, 1);
    assert_eq!(stream.dedup_stats().duplicates_detected, 1);
    stream.clear_object(ObjectId::new(0, 1));
    assert_eq!(stream.dedup_stats().objects_tracked, 0);
    publish(&control, Event::Symbol(symbol(1, 0, b"a")));
    assert_eq!(next(&mut stream, &mut cx).unwrap().unwrap().symbol().esi(), 0);
    assert_eq!(stream.dedup_stats().symbols_tracked, 1);
}

#[test]
fn caught_provider_panic_cannot_resume_unknown_consumed_input() {
    let (panicking, control) = script([Event::Symbol(symbol(1, 0, b"a"))]);
    control.lock().unwrap().panic_after_take = true;
    let (other, untouched) = script([Event::Symbol(symbol(1, 1, b"b"))]);
    let mut stream = MultipathSymbolStream::new(AuthKey::from_seed(42), MultipathStreamLimits::default());
    stream.add_path(PathId(1), panicking).unwrap();
    stream.add_path(PathId(2), other).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = Pin::new(&mut stream).poll_next(&mut cx);
    })).is_err());
    assert!(stream.is_exhausted());
    assert!(matches!(Pin::new(&mut stream).poll_next(&mut cx), Poll::Ready(None)));
    assert_eq!(control.lock().unwrap().polls, 1);
    assert_eq!(untouched.lock().unwrap().polls, 0);
    assert_eq!(stream.dedup_stats().symbols_tracked, 0);
    drop(stream);
    assert_eq!(control.lock().unwrap().drops, 1);
    assert_eq!(untouched.lock().unwrap().drops, 1);
}

#[cfg(not(target_arch = "wasm32"))]
#[path = "native_tests.rs"]
mod native;
