//! Deadline ownership, fairness, and completion accounting for SDK sessions.

use super::*;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, RegionId, TaskId, Time};

fn deadline_owner() -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::starting_at(Time::from_nanos(1_000)));
    let timer = TimerDriverHandle::with_virtual_clock(clock.clone());
    let owner = Cx::new_with_drivers(
        RegionId::new_for_test(1, 0),
        TaskId::new_for_test(1, 0),
        Budget::INFINITE.with_deadline(Time::from_nanos(1_100)),
        None,
        None,
        None,
        Some(timer.clone()),
        None,
    );
    (owner, clock, timer)
}

#[test]
fn parked_receive_uses_original_absolute_deadline_after_wait_replacement() {
    let (owner, clock, timer) = deadline_owner();
    let source = GatedSource::new(Vec::new(), 0, false);
    let mut receiver = receiver(source.clone());
    let params = ObjectParams::new(ObjectId::new(5, 12), 64, 64, 1, 1);
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    let first_counter = Arc::new(WakeCount::default());
    let first_waker = Waker::from(first_counter.clone());
    let mut first_task = Context::from_waker(&first_waker);
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut first_task).is_pending());
        assert_eq!(timer.pending_count(), 1);
    }
    assert_eq!(timer.pending_count(), 0, "a dropped wait retires its timer");
    // Remove the source's own readiness registration to isolate the dropped
    // wait's cancellation/deadline registrations from transport ownership.
    source.0.lock().unwrap().waiter = None;
    clock.advance(60);

    let second_counter = Arc::new(WakeCount::default());
    let second_waker = Waker::from(second_counter.clone());
    let mut second_task = Context::from_waker(&second_waker);
    let _foreign = Cx::set_current(Some(Cx::for_testing()));
    let mut waiting = Box::pin(session.run());
    assert!(waiting.as_mut().poll(&mut second_task).is_pending());
    assert_eq!(timer.pending_count(), 1);
    let calls = source.0.lock().unwrap().calls;
    clock.advance(40);
    let _ = timer.process_timers();
    assert_eq!(first_counter.0.load(Ordering::SeqCst), 0);
    assert!(second_counter.0.load(Ordering::SeqCst) > 0);
    let error = match waiting.as_mut().poll(&mut second_task) {
        Poll::Ready(Err(error)) => error,
        other => panic!("original owner deadline did not end parked receive: {other:?}"),
    };
    assert_eq!(error.kind(), ErrorKind::Cancelled);
    assert_eq!(source.0.lock().unwrap().calls, calls);
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn completed_send_retires_its_timer_while_the_ready_wait_is_still_alive() {
    let (owner, _clock, timer) = deadline_owner();
    let sink = GatedSink::new(0, true);
    let mut sender = sender(sink.clone());
    let mut session = sender.start_send_symbols(&owner, vec![signed(0)]).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    let mut waiting = Box::pin(session.run());
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    assert_eq!(timer.pending_count(), 1);
    sink.release(usize::MAX, true);
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Ok(1))));
    assert_eq!(timer.pending_count(), 0, "Ready retires the timer before Future drop");
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Err(_))));
    assert_eq!(sink.accepted().len(), 1);
}

#[test]
fn masked_elapsed_deadline_is_not_repolled_while_source_remains_pending() {
    let (owner, clock, timer) = deadline_owner();
    let source = GatedSource::new(Vec::new(), 0, false);
    let mut receiver = receiver(source);
    let params = ObjectParams::new(ObjectId::new(5, 12), 64, 64, 1, 1);
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    let mut waiting = Box::pin(session.run());
    owner.masked(|| {
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        clock.advance(100);
        let _ = timer.process_timers();
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert_eq!(timer.pending_count(), 0);
        // Sleep panics if polled after completion. The masked owner still
        // permits a pending provider, so this is a necessary third poll.
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    });
    assert!(matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Err(_))));
}

#[test]
fn dropping_wait_removes_its_cancel_registration_without_abandoning_session() {
    let owner = Cx::for_testing();
    let sink = GatedSink::new(0, true);
    let mut sender = sender(sink.clone());
    let mut session = sender.start_send_symbols(&owner, vec![signed(0)]).unwrap();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut task = Context::from_waker(&waker);
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    sink.0.lock().unwrap().waiter = None;
    owner.set_cancel_requested(true);
    assert_eq!(counter.0.load(Ordering::SeqCst), 0, "abandoned poller is no longer registered");
    assert_eq!(finish(session.run(), &mut task).unwrap_err().kind(), ErrorKind::Cancelled);
    assert!(session.is_finished());
    assert!(sink.accepted().is_empty());
}

#[test]
fn always_ready_send_yields_after_thirty_two_acceptances() {
    let owner = Cx::for_testing();
    let sink = GatedSink::new(usize::MAX, true);
    let mut sender = sender(sink.clone());
    let mut session = sender.start_send_symbols(&owner, (0..40).map(signed)).unwrap();
    let counter = Arc::new(WakeCount::default());
    let waker = Waker::from(counter.clone());
    let mut task = Context::from_waker(&waker);
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(session.symbols_sent(), 32);
    assert_eq!(sink.accepted().len(), 32);
    assert_eq!(counter.0.load(Ordering::SeqCst), 1);
    assert_eq!(finish(session.run(), &mut task).unwrap(), 40);
    assert_eq!(sink.accepted().len(), 40);
}

#[test]
fn duplicates_and_other_objects_consume_the_same_receive_poll_budget() {
    for other_objects in [false, true] {
        let owner = Cx::for_testing();
        let noise = if other_objects {
            let symbol = Symbol::new(
                SymbolId::new(ObjectId::new(9, 9), 0, 0),
                vec![0; 64],
                SymbolKind::Source,
            );
            SecurityContext::new(AuthKey::from_seed(42)).sign_symbol(&symbol)
        } else {
            signed(0)
        };
        let mut values = vec![noise; 64];
        values.push(signed(0));
        values.push(signed(1));
        let source = GatedSource::new(values, usize::MAX, true);
        let mut receiver = receiver(source.clone());
        let params = ObjectParams::new(ObjectId::new(5, 12), 128, 64, 1, 2);
        let mut session = receiver.start_receive_object(&owner, &params).unwrap();
        let counter = Arc::new(WakeCount::default());
        let waker = Waker::from(counter.clone());
        let mut task = Context::from_waker(&waker);
        {
            let mut waiting = Box::pin(session.run());
            assert!(waiting.as_mut().poll(&mut task).is_pending());
        }
        assert_eq!(source.0.lock().unwrap().calls, 32);
        assert_eq!(session.symbols_received(), if other_objects { 0 } else { 1 });
        assert_eq!(counter.0.load(Ordering::SeqCst), 1);
        let result = finish(session.run(), &mut task).unwrap();
        assert_eq!(result.symbols_received, 2);
        assert_eq!(result.data, [vec![0; 64], vec![1; 64]].concat());
        assert!(result.all_symbols_verified());
    }
}

#[test]
fn empty_objects_require_flush_but_do_not_poll_the_receive_source() {
    let owner = Cx::for_testing();
    let object = ObjectId::new(5, 12);
    let sink = GatedSink::new(0, false);
    let mut sender = sender(sink.clone());
    let mut session = sender.start_send_object(&owner, object, &[]).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(session.symbols_sent(), 0);
    assert!(sink.accepted().is_empty());
    sink.release(0, true);
    let sent = finish(session.run(), &mut task).unwrap();
    assert_eq!((sent.source_symbols, sent.repair_symbols, sent.symbols_sent), (0, 0, 0));

    let source = GatedSource::new(Vec::new(), 0, false);
    let mut receiver = receiver(source.clone());
    let params = ObjectParams::new(object, 0, 64, 0, 0);
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    let received = finish(session.run(), &mut task).unwrap();
    assert!(received.data.is_empty());
    assert_eq!(received.symbols_received, 0);
    assert_eq!(received.authentication, ReceiveAuthenticationSummary::default());
    assert!(received.all_symbols_verified());
    assert_eq!(source.0.lock().unwrap().calls, 0);
}

#[test]
fn eof_and_foreign_object_authentication_failures_are_terminal() {
    let owner = Cx::for_testing();
    let params = ObjectParams::new(ObjectId::new(5, 12), 128, 64, 1, 2);
    let source = GatedSource::new(vec![signed(0)], usize::MAX, true);
    let mut receiver = receiver(source.clone());
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    let error = finish(session.run(), &mut task).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::InsufficientSymbols);
    assert_eq!(session.symbols_received(), 1);
    let calls = source.0.lock().unwrap().calls;
    assert_eq!(finish(session.run(), &mut task).unwrap_err().kind(), error.kind());
    assert_eq!(source.0.lock().unwrap().calls, calls);

    let foreign = Symbol::new(
        SymbolId::new(ObjectId::new(9, 9), 0, 0),
        vec![0; 64],
        SymbolKind::Source,
    );
    let forged = SecurityContext::new(AuthKey::from_seed(7)).sign_symbol(&foreign);
    let source = GatedSource::new(vec![forged], usize::MAX, true);
    let mut receiver = super::receiver(source);
    let mut session = receiver.start_receive_object(&owner, &params).unwrap();
    assert_eq!(finish(session.run(), &mut task).unwrap_err().kind(), ErrorKind::CorruptedSymbol);
    assert_eq!(session.symbols_received(), 0);
}

#[test]
fn send_metrics_count_acceptance_once_and_object_completion_only_after_flush() {
    let owner = Cx::for_testing();
    let mut metrics = Metrics::new();
    let symbols = metrics.counter("raptorq.symbols_sent");
    let objects = metrics.counter("raptorq.objects_sent");
    let sink = GatedSink::new(2, false);
    let mut sender = RaptorQSenderBuilder::new()
        .config(config())
        .transport(sink.clone())
        .security(SecurityContext::new(AuthKey::from_seed(42)))
        .metrics(metrics)
        .build()
        .unwrap();
    let data = vec![19; 257];
    let mut session = sender.start_send_object(&owner, ObjectId::new(5, 12), &data).unwrap();
    let mut task = Context::from_waker(Waker::noop());
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    assert_eq!(symbols.get(), 2);
    assert_eq!(objects.get(), 0);
    sink.release(usize::MAX, false);
    {
        let mut waiting = Box::pin(session.run());
        assert!(waiting.as_mut().poll(&mut task).is_pending());
    }
    let accepted = session.symbols_sent();
    assert_eq!(symbols.get(), accepted as u64);
    assert_eq!(objects.get(), 0);
    sink.release(usize::MAX, true);
    assert_eq!(finish(session.run(), &mut task).unwrap().symbols_sent, accepted);
    assert_eq!(symbols.get(), accepted as u64);
    assert_eq!(objects.get(), 1);
    assert!(finish(session.run(), &mut task).is_err());
    assert_eq!(symbols.get(), accepted as u64);
    assert_eq!(objects.get(), 1);
}
