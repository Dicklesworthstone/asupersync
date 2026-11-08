//! Behavioral contracts for the asynchronous SDK's retained operation owners.

use super::*;
use crate::raptorq::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
use crate::security::{AuthKey, AuthenticationTag};
use crate::transport::SinkError;
use crate::types::symbol::{Symbol, SymbolId, SymbolKind};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

struct SinkState {
    accepted: Vec<AuthenticatedSymbol>,
    allowance: usize,
    flush_ready: bool,
    calls: usize,
    flushes: usize,
    panic_after_accept: bool,
    waiter: Option<Waker>,
    ambient_cancelled: Vec<Option<bool>>,
}

#[derive(Clone)]
struct GatedSink(Arc<Mutex<SinkState>>);

impl GatedSink {
    fn new(allowance: usize, flush_ready: bool) -> Self {
        Self(Arc::new(Mutex::new(SinkState {
            accepted: Vec::new(), allowance, flush_ready, calls: 0, flushes: 0,
            panic_after_accept: false, waiter: None, ambient_cancelled: Vec::new(),
        })))
    }

    fn release(&self, allowance: usize, flush_ready: bool) {
        let waiter = {
            let mut state = self.0.lock().unwrap();
            state.allowance = allowance;
            state.flush_ready = flush_ready;
            state.waiter.take()
        };
        if let Some(waiter) = waiter { waiter.wake(); }
    }

    fn accepted(&self) -> Vec<AuthenticatedSymbol> { self.0.lock().unwrap().accepted.clone() }
}

impl SymbolSink for GatedSink {
    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        state.ambient_cancelled.push(Cx::with_current(Cx::is_cancel_requested));
        if state.allowance == 0 {
            state.waiter = Some(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, symbol: AuthenticatedSymbol) -> Poll<Result<(), SinkError>> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        if state.allowance == 0 {
            state.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        state.allowance -= 1;
        state.accepted.push(symbol);
        let panic_after_accept = state.panic_after_accept;
        drop(state);
        assert!(!panic_after_accept, "fixture accepted a symbol before panicking");
        Poll::Ready(Ok(()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        state.flushes += 1;
        if state.flush_ready {
            Poll::Ready(Ok(()))
        } else {
            state.waiter = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        self.poll_flush(cx)
    }
}

struct SourceState {
    symbols: VecDeque<AuthenticatedSymbol>,
    allowance: usize,
    eof: bool,
    calls: usize,
    panic_after_take: bool,
    waiter: Option<Waker>,
    ambient_cancelled: Vec<Option<bool>>,
}

#[derive(Clone)]
struct GatedSource(Arc<Mutex<SourceState>>);

impl GatedSource {
    fn new(symbols: Vec<AuthenticatedSymbol>, allowance: usize, eof: bool) -> Self {
        Self(Arc::new(Mutex::new(SourceState {
            symbols: symbols.into(), allowance, eof, calls: 0,
            panic_after_take: false, waiter: None, ambient_cancelled: Vec::new(),
        })))
    }

    fn release(&self, allowance: usize) {
        let waiter = {
            let mut state = self.0.lock().unwrap();
            state.allowance = allowance;
            state.waiter.take()
        };
        if let Some(waiter) = waiter { waiter.wake(); }
    }
}

impl SymbolStream for GatedSource {
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<AuthenticatedSymbol, StreamError>>> {
        let mut state = self.0.lock().unwrap();
        state.calls += 1;
        state.ambient_cancelled.push(Cx::with_current(Cx::is_cancel_requested));
        if state.symbols.is_empty() && state.eof { return Poll::Ready(None); }
        if state.allowance == 0 || state.symbols.is_empty() {
            state.waiter = Some(cx.waker().clone());
            return Poll::Pending;
        }
        state.allowance -= 1;
        let symbol = state.symbols.pop_front().unwrap();
        let panic_after_take = state.panic_after_take;
        drop(state);
        assert!(!panic_after_take, "fixture consumed a symbol before panicking");
        Poll::Ready(Some(Ok(symbol)))
    }
}

fn config() -> RaptorQConfig {
    let mut config = RaptorQConfig::default();
    config.encoding.symbol_size = 64;
    config.encoding.max_block_size = 4096;
    config.encoding.repair_overhead = 1.5;
    config
}

fn signed(esi: u32) -> AuthenticatedSymbol {
    let symbol = Symbol::new(
        SymbolId::new(ObjectId::new(5, 12), 0, esi), vec![esi as u8; 64], SymbolKind::Source,
    );
    SecurityContext::new(AuthKey::from_seed(42)).sign_symbol(&symbol)
}

fn sender(sink: GatedSink) -> RaptorQSender<GatedSink> {
    RaptorQSenderBuilder::new().config(config()).transport(sink)
        .security(SecurityContext::new(AuthKey::from_seed(42))).build().unwrap()
}

fn receiver(source: GatedSource) -> RaptorQReceiver<GatedSource> {
    RaptorQReceiverBuilder::new().config(config()).source(source)
        .security(SecurityContext::new(AuthKey::from_seed(42))).build().unwrap()
}

fn finish<F: Future>(future: F, cx: &mut Context<'_>) -> F::Output {
    let mut future = Box::pin(future);
    for _ in 0..1024 {
        if let Poll::Ready(output) = future.as_mut().poll(cx) { return output; }
    }
    panic!("released scripted transport did not finish within the bounded poll count");
}

#[test]
fn encoded_send_pauses_through_backpressure_and_dropped_flush_without_duplicate_symbols() {
    let owner = Cx::for_testing();
    let sink = GatedSink::new(2, false);
    let mut sender = sender(sink.clone());
    let data = vec![19; 257];
    let object = ObjectId::new(5, 12);
    let mut session = sender.start_send_object(&owner, object, &data).unwrap();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut task = Context::from_waker(&waker);
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(session.symbols_sent(), 2);
    assert_eq!(sink.accepted().len(), 2);
    assert!(!session.is_finished());
    assert_eq!(counter.0.load(Ordering::SeqCst), 0, "backpressure must not spin");
    sink.release(usize::MAX, false);
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    let count = sink.accepted().len();
    assert!(count > 5, "source and repair symbols were sent before blocked flush");
    assert_eq!(session.symbols_sent(), count);
    assert!(sink.0.lock().unwrap().flushes > 0);
    assert!(!session.is_finished(), "buffered acceptance alone is not send completion");
    sink.release(usize::MAX, true);
    let outcome = finish(session.run(), &mut task).unwrap();
    assert_eq!(outcome.symbols_sent, count);
    assert_eq!(outcome.source_symbols, 5);
    assert!(session.is_finished());
    assert_eq!(sink.accepted().len(), count);
    let symbols = sink.accepted();
    let identities: HashSet<_> = symbols.iter().map(|symbol| symbol.symbol().id()).collect();
    assert_eq!(identities.len(), count, "resumption cannot repeat accepted encoding symbols");
    assert!(symbols.iter().all(|symbol| symbol.tag().verify(&AuthKey::from_seed(42), symbol.symbol())));
    assert!(finish(session.run(), &mut task).is_err(), "terminal session does not replay");
}

#[test]
fn supplied_symbol_send_preserves_the_pending_argument_and_finishes_local_flush() {
    let owner = Cx::for_testing();
    let sink = GatedSink::new(1, true);
    let mut sender = sender(sink.clone());
    let values = vec![signed(0), signed(1), signed(2)];
    let mut session = sender.start_send_symbols(&owner, values.clone()).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(session.symbols_sent(), 1);
    sink.release(usize::MAX, true);
    assert_eq!(finish(session.run(), &mut task).unwrap(), values.len());
    let accepted: Vec<_> = sink.accepted().into_iter().map(AuthenticatedSymbol::into_symbol).collect();
    let expected: Vec<_> = values.into_iter().map(AuthenticatedSymbol::into_symbol).collect();
    assert_eq!(accepted, expected);
    assert!(session.is_finished());
    assert_eq!(sink.0.lock().unwrap().flushes, 1);
}

#[test]
fn receive_session_retains_partial_decode_across_dropped_waits() {
    let owner = Cx::for_testing();
    let data: Vec<u8> = (0..257).map(|n| (n % 251) as u8).collect();
    let object = ObjectId::new(5, 12);
    let fixture = GatedSink::new(usize::MAX, true);
    sender(fixture.clone()).send_object(&owner, object, &data).unwrap();
    let source = GatedSource::new(fixture.accepted(), 2, true);
    let mut receiver = receiver(source.clone());
    let params = ObjectParams::new(object, data.len() as u64, 64, 1, 5);
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(session.symbols_received(), 2);
    assert!(!session.is_finished());
    source.release(usize::MAX);
    let outcome = finish(session.run(), &mut task).unwrap();
    assert_eq!(outcome.data, data);
    assert!(outcome.all_symbols_verified());
    assert_eq!(outcome.symbols_received, session.symbols_received());
    assert!(outcome.symbols_received >= 5);
    assert!(session.is_finished());
    let polls = source.0.lock().unwrap().calls;
    assert!(finish(session.run(), &mut task).is_err());
    assert_eq!(source.0.lock().unwrap().calls, polls);
}

#[test]
fn original_owner_cancellation_wakes_blocked_send_under_a_cancelled_foreign_context() {
    let owner = Cx::for_testing();
    let foreign = Cx::for_testing();
    foreign.set_cancel_requested(true);
    let sink = GatedSink::new(0, false);
    let mut sender = sender(sink.clone());
    let mut session = sender.start_send_symbols(&owner, vec![signed(0)]).unwrap();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut task = Context::from_waker(&waker);
    let _ambient = Cx::set_current(Some(foreign));
    let mut waiting = Box::pin(session.run());
    assert!(waiting.as_mut().poll(&mut task).is_pending(), "foreign cancellation cannot cancel the owner");
    assert_eq!(counter.0.load(Ordering::SeqCst), 0);
    assert_eq!(sink.0.lock().unwrap().ambient_cancelled, [Some(false)]);
    owner.set_cancel_requested(true);
    assert!(counter.0.load(Ordering::SeqCst) > 0, "owner cancellation must wake parked I/O");
    let error = match waiting.as_mut().poll(&mut task) {
        Poll::Ready(Err(error)) => error,
        other => panic!("cancelled send did not finish: {other:?}"),
    };
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    drop(waiting);
    assert!(session.is_finished());
    assert!(sink.accepted().is_empty());
}

#[test]
fn original_owner_cancellation_wakes_blocked_receive_and_stops_provider_polls() {
    let owner = Cx::for_testing();
    let foreign = Cx::for_testing();
    foreign.set_cancel_requested(true);
    let source = GatedSource::new(Vec::new(), 0, false);
    let mut receiver = receiver(source.clone());
    let params = ObjectParams::new(ObjectId::new(5, 12), 64, 64, 1, 1);
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut task = Context::from_waker(&waker);
    let _ambient = Cx::set_current(Some(foreign));
    let mut waiting = Box::pin(session.run());
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(source.0.lock().unwrap().ambient_cancelled, [Some(false)]);
    let polls = source.0.lock().unwrap().calls;
    owner.set_cancel_requested(true);
    assert!(counter.0.load(Ordering::SeqCst) > 0);
    let error = match waiting.as_mut().poll(&mut task) {
        Poll::Ready(Err(error)) => error,
        other => panic!("cancelled receive did not finish: {other:?}"),
    };
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    drop(waiting);
    assert!(session.is_finished());
    assert_eq!(session.symbols_received(), 0);
    assert_eq!(source.0.lock().unwrap().calls, polls);
}

#[test]
fn new_sessions_require_keys_and_reverify_supplied_tags_even_with_permissive_policy() {
    let owner = Cx::for_testing();
    let sink = GatedSink::new(usize::MAX, true);
    let mut unsigned = RaptorQSenderBuilder::new().config(config()).transport(sink.clone()).build().unwrap();
    assert!(unsigned.start_send_object(&owner, ObjectId::new(5, 12), &[0; 64]).is_err());
    assert!(unsigned.start_send_symbols(&owner, vec![signed(0)]).is_err());
    assert_eq!(sink.0.lock().unwrap().calls, 0);
    let empty = GatedSource::new(Vec::new(), 0, false);
    let mut unkeyed = RaptorQReceiverBuilder::new().config(config()).source(empty.clone()).build().unwrap();
    let params = ObjectParams::new(ObjectId::new(5, 12), 64, 64, 1, 1);
    assert!(unkeyed.start_receive_object(&owner, &params).is_err());
    assert_eq!(empty.0.lock().unwrap().calls, 0);

    let wrong_key = SecurityContext::new(AuthKey::from_seed(7)).sign_symbol(signed(0).symbol());
    assert!(wrong_key.is_verified(), "the foreign producer's flag is not receiver authority");
    let sentinel = AuthenticatedSymbol::from_parts(signed(0).into_symbol(), AuthenticationTag::zero());
    for mode in [AuthMode::Permissive, AuthMode::Disabled] {
        for invalid in [wrong_key.clone(), sentinel.clone()] {
            let source = GatedSource::new(vec![invalid.clone()], usize::MAX, true);
            let mut receiver = RaptorQReceiverBuilder::new().config(config()).source(source.clone())
                .security(SecurityContext::for_testing_with_mode(42, mode)).build().unwrap();
            let mut session = receiver.start_receive_object(&owner, &params).unwrap();
            let mut task = Context::from_waker(Waker::noop());
            assert_eq!(finish(session.run(), &mut task).unwrap_err().kind(), ErrorKind::CorruptedSymbol);
            assert_eq!(session.symbols_received(), 0);
            assert!(session.is_finished());

            let sink = GatedSink::new(usize::MAX, true);
            let mut sender = RaptorQSenderBuilder::new().config(config()).transport(sink.clone())
                .security(SecurityContext::for_testing_with_mode(42, mode)).build().unwrap();
            let mut session = sender.start_send_symbols(&owner, vec![invalid]).unwrap();
            assert_eq!(finish(session.run(), &mut task).unwrap_err().kind(), ErrorKind::CorruptedSymbol);
            assert!(sink.accepted().is_empty());
            assert_eq!(sink.0.lock().unwrap().calls, 0, "bad supplied tags refuse before transport readiness");
        }
    }
}

#[test]
fn caught_provider_panics_poison_send_and_receive_sessions_before_any_retry() {
    let owner = Cx::for_testing();
    let mut task = Context::from_waker(Waker::noop());
    let sink = GatedSink::new(usize::MAX, true);
    sink.0.lock().unwrap().panic_after_accept = true;
    let mut sender = sender(sink.clone());
    let mut session = sender.start_send_symbols(&owner, vec![signed(0), signed(1)]).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut run = Box::pin(session.run());
        let _ = run.as_mut().poll(&mut task);
    })).is_err());
    assert_eq!(sink.accepted().len(), 1);
    assert!(session.is_finished());
    sink.0.lock().unwrap().panic_after_accept = false;
    assert!(finish(session.run(), &mut task).is_err());
    assert_eq!(sink.accepted().len(), 1);

    let source = GatedSource::new(vec![signed(0)], usize::MAX, true);
    source.0.lock().unwrap().panic_after_take = true;
    let mut receiver = receiver(source.clone());
    let params = ObjectParams::new(ObjectId::new(5, 12), 64, 64, 1, 1);
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut run = Box::pin(session.run());
        let _ = run.as_mut().poll(&mut task);
    })).is_err());
    assert!(session.is_finished());
    source.0.lock().unwrap().panic_after_take = false;
    let polls = source.0.lock().unwrap().calls;
    assert!(finish(session.run(), &mut task).is_err());
    assert_eq!(source.0.lock().unwrap().calls, polls);
}

struct PanickingIterator {
    calls: Arc<AtomicUsize>,
}

impl Iterator for PanickingIterator {
    type Item = AuthenticatedSymbol;
    fn next(&mut self) -> Option<Self::Item> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(call, 0, "fixture iterator panicked after its first item");
        Some(signed(0))
    }
}

#[test]
fn caught_iterator_panic_cannot_restart_a_partially_sent_sequence() {
    let owner = Cx::for_testing();
    let sink = GatedSink::new(usize::MAX, true);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut sender = sender(sink.clone());
    let mut session = sender.start_send_symbols(&owner, PanickingIterator { calls: calls.clone() }).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut run = Box::pin(session.run());
        let _ = run.as_mut().poll(&mut task);
    })).is_err());
    assert_eq!(sink.accepted().len(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(session.is_finished());
    assert!(finish(session.run(), &mut task).is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(sink.accepted().len(), 1);
}

struct ReadyButBlockedSink(GatedSink);

impl SymbolSink for ReadyButBlockedSink {
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Poll::Ready(Ok(()))
    }

    fn poll_send(self: Pin<&mut Self>, cx: &mut Context<'_>, symbol: AuthenticatedSymbol) -> Poll<Result<(), SinkError>> {
        Pin::new(&mut self.get_mut().0).poll_send(cx, symbol)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), SinkError>> {
        Pin::new(&mut self.get_mut().0).poll_close(cx)
    }
}

#[test]
fn readiness_change_retains_the_same_pending_candidate_without_advancing_the_iterator() {
    let owner = Cx::for_testing();
    let sink = GatedSink::new(0, true);
    let values = vec![signed(0), signed(1), signed(2)];
    let advances = Arc::new(AtomicUsize::new(0));
    let observed = advances.clone();
    let input = values.clone().into_iter().inspect(move |_| {
        observed.fetch_add(1, Ordering::SeqCst);
    });
    let mut sender = RaptorQSenderBuilder::new().config(config())
        .transport(ReadyButBlockedSink(sink.clone()))
        .security(SecurityContext::new(AuthKey::from_seed(42))).build().unwrap();
    let mut session = sender.start_send_symbols(&owner, input).unwrap();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut task = Context::from_waker(&waker);
    for _ in 0..2 {
        {
            let mut waiting = Box::pin(session.run());
            assert!(waiting.as_mut().poll(&mut task).is_pending());
        }
        assert_eq!(advances.load(Ordering::SeqCst), 1, "Pending did not accept or replace the first argument");
        assert_eq!(session.symbols_sent(), 0);
        assert!(sink.accepted().is_empty());
    }
    assert_eq!(counter.0.load(Ordering::SeqCst), 0, "a blocked send waits for its transport wake");
    sink.release(usize::MAX, true);
    assert_eq!(finish(session.run(), &mut task).unwrap(), values.len());
    assert_eq!(advances.load(Ordering::SeqCst), values.len());
    let accepted: Vec<_> = sink.accepted().into_iter().map(AuthenticatedSymbol::into_symbol).collect();
    let expected: Vec<_> = values.into_iter().map(AuthenticatedSymbol::into_symbol).collect();
    assert_eq!(accepted, expected);
}

#[path = "session_budget_tests.rs"]
mod budget_tests;
