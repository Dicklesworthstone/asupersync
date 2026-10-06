use super::*;
use crate::stream::iter;
use crate::types::CancelKind;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn counter() -> (Arc<WakeCount>, Waker) {
    crate::test_utils::init_test_logging();
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    crate::test_utils::init_test_logging();
    future.poll(&mut Context::from_waker(Waker::noop()))
}

fn drain<T>(receiver: &mut mpsc::Receiver<T>) -> Vec<T> {
    let mut items = Vec::new();
    while let Ok(item) = receiver.try_recv() {
        items.push(item);
    }
    items
}

#[test]
fn recoverable_sends_every_item_in_source_order() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = mpsc::channel(8);
    let sink = into_sink(sender);
    let mut source = iter([1, 2, 3]);
    let mut pending = None;
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));

    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(()))));
    drop(run);
    assert_eq!(pending, None);
    assert_eq!(drain(&mut receiver), vec![1, 2, 3]);
}

#[test]
fn recoverable_empty_source_does_not_wait_for_channel_capacity() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = mpsc::channel(1);
    sender.try_send(99).unwrap();
    let sink = into_sink(sender);
    let mut source = iter([]);
    let mut pending = None;
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));

    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(()))));
    assert_eq!(drain(&mut receiver), vec![99]);
}

struct Idle(Arc<AtomicUsize>);

impl Stream for Idle {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<u8>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

#[test]
fn recoverable_pre_cancelled_run_does_not_advance_source() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = mpsc::channel(1);
    let sink = into_sink(sender);
    let polls = Arc::new(AtomicUsize::new(0));
    let mut source = Idle(Arc::clone(&polls));
    let mut pending = None;
    cx.cancel_fast(CancelKind::User);
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));

    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(mpsc::CheckedSendError::Channel(SendError::Cancelled(()))))
    ));
    drop(run);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(pending, None);
}

#[test]
fn recoverable_idle_source_wakes_on_cancellation_only() {
    let cx = Cx::for_testing();
    let (sender, _receiver) = mpsc::channel(1);
    let sink = into_sink(sender);
    let mut source = Idle(Arc::new(AtomicUsize::new(0)));
    let mut pending = None;
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));

    assert!(run.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        run.as_mut().poll(&mut task),
        Poll::Ready(Err(mpsc::CheckedSendError::Channel(SendError::Cancelled(()))))
    ));
    assert_eq!(Arc::strong_count(&count), 2);
    drop(run);
    assert_eq!(pending, None);
}

#[test]
fn recoverable_full_channel_cancellation_preserves_item_for_retry() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = mpsc::channel(1);
    sender.try_send(99).unwrap();
    let sink = into_sink(sender);
    let mut source = iter([1, 2]);
    let mut pending = None;
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));

    assert!(run.as_mut().poll(&mut task).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        run.as_mut().poll(&mut task),
        Poll::Ready(Err(mpsc::CheckedSendError::Channel(SendError::Cancelled(()))))
    ));
    drop(run);
    assert_eq!(pending, Some(1));
    assert_eq!(receiver.try_recv(), Ok(99));
    assert_eq!(sink.sender.telemetry_snapshot(1).send_waiter_count, 0);
    assert_eq!(Arc::strong_count(&count), 2);

    let retry_cx = Cx::for_testing();
    let mut retry = Box::pin(sink.send_all_recoverable(
        &retry_cx,
        &mut source,
        &mut pending,
    ));
    assert!(poll_once(retry.as_mut()).is_pending());
    assert_eq!(receiver.try_recv(), Ok(1));
    assert!(matches!(poll_once(retry.as_mut()), Poll::Ready(Ok(()))));
    drop(retry);
    assert_eq!(pending, None);
    assert_eq!(receiver.try_recv(), Ok(2));
}

#[test]
fn recoverable_repeated_drop_and_resume_has_no_loss_or_duplicates() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = mpsc::channel(1);
    let sink = into_sink(sender);
    let mut source = iter(0..20);
    let mut pending = None;
    let mut delivered = Vec::new();
    let mut completed = false;

    for _ in 0..=20 {
        let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
        let result = poll_once(run.as_mut());
        drop(run);
        let telemetry = sink.sender.telemetry_snapshot(1);
        assert_eq!(telemetry.send_waiter_count, 0);
        assert_eq!(telemetry.reserved_uncommitted_obligations, 0);
        delivered.extend(drain(&mut receiver));
        match result {
            Poll::Ready(Ok(())) => {
                completed = true;
                break;
            }
            Poll::Pending => {
                // Only the next undelivered item may have been read ahead.
                assert_eq!(pending, Some(i32::try_from(delivered.len()).unwrap()));
            }
            Poll::Ready(Err(error)) => panic!("unexpected refusal: {error}"),
        }
    }
    assert!(completed);
    assert_eq!(pending, None);
    assert_eq!(delivered, (0..20).collect::<Vec<_>>());
}

#[test]
fn recoverable_disconnection_allows_retry_with_a_new_sink() {
    let cx = Cx::for_testing();
    let (sender, receiver) = mpsc::channel(1);
    let sink = into_sink(sender);
    drop(receiver);
    let mut source = iter([1, 2, 3]);
    let mut pending = None;
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(mpsc::CheckedSendError::Channel(SendError::Disconnected(()))))
    ));
    drop(run);
    assert_eq!(pending, Some(1));

    let (sender, mut receiver) = mpsc::channel(4);
    let replacement = into_sink(sender);
    let mut retry = Box::pin(replacement.send_all_recoverable(
        &cx,
        &mut source,
        &mut pending,
    ));
    assert!(matches!(poll_once(retry.as_mut()), Poll::Ready(Ok(()))));
    drop(retry);
    assert_eq!(pending, None);
    assert_eq!(drain(&mut receiver), vec![1, 2, 3]);
}

#[test]
fn recoverable_sends_existing_pending_value_before_polling_source() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = mpsc::channel(4);
    let sink = into_sink(sender);
    let mut source = iter([2, 3]);
    let mut pending = Some(1);
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
    assert!(matches!(poll_once(run.as_mut()), Poll::Ready(Ok(()))));
    drop(run);
    assert_eq!(drain(&mut receiver), vec![1, 2, 3]);
    assert_eq!(pending, None);
}

#[test]
fn recoverable_yield_and_drop_retains_fifo_progress() {
    let cx = Cx::for_testing();
    let size = FORWARD_SEND_BUDGET + 3;
    let (sender, mut receiver) = mpsc::channel(size);
    let sink = into_sink(sender);
    let mut source = iter(0..size);
    let mut pending = None;
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));

    assert!(run.as_mut().poll(&mut task).is_pending());
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert_eq!(receiver.len(), FORWARD_SEND_BUDGET);
    drop(run);
    assert_eq!(pending, None);
    let mut retry = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
    assert!(matches!(poll_once(retry.as_mut()), Poll::Ready(Ok(()))));
    drop(retry);
    assert_eq!(drain(&mut receiver), (0..size).collect::<Vec<_>>());
}

#[derive(Debug)]
struct DropProbe {
    id: u8,
    drops: Arc<AtomicUsize>,
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn recoverable_drop_retains_non_clone_values_in_caller_state() {
    let cx = Cx::for_testing();
    let drops = Arc::new(AtomicUsize::new(0));
    let (sender, mut receiver) = mpsc::channel(1);
    let sink = into_sink(sender);
    let mut source = iter([
        DropProbe { id: 1, drops: Arc::clone(&drops) },
        DropProbe { id: 2, drops: Arc::clone(&drops) },
    ]);
    let mut pending = None;
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
    assert!(poll_once(run.as_mut()).is_pending());
    drop(run);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(pending.as_ref().map(|item| item.id), Some(2));
    let first = receiver.try_recv().unwrap();
    assert_eq!(first.id, 1);

    let mut retry = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
    assert!(matches!(poll_once(retry.as_mut()), Poll::Ready(Ok(()))));
    drop(retry);
    let second = receiver.try_recv().unwrap();
    assert_eq!(second.id, 2);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    drop((first, second));
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

struct CancelWithItem {
    cx: Cx,
    yielded: bool,
}

impl Stream for CancelWithItem {
    type Item = u8;

    fn poll_next(mut self: Pin<&mut Self>, _task: &mut Context<'_>) -> Poll<Option<u8>> {
        if self.yielded {
            return Poll::Ready(None);
        }
        self.yielded = true;
        self.cx.cancel_fast(CancelKind::User);
        Poll::Ready(Some(7))
    }
}

#[test]
fn recoverable_keeps_item_when_source_cancels_during_ready_poll() {
    let cx = Cx::for_testing();
    let (sender, mut receiver) = mpsc::channel(1);
    let sink = into_sink(sender);
    let mut source = CancelWithItem { cx: cx.clone(), yielded: false };
    let mut pending = None;
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(mpsc::CheckedSendError::Channel(SendError::Cancelled(()))))
    ));
    drop(run);
    assert_eq!(pending, Some(7));
    assert_eq!(receiver.try_recv(), Err(mpsc::RecvError::Empty));

    let retry_cx = Cx::for_testing();
    let mut retry = Box::pin(sink.send_all_recoverable(
        &retry_cx,
        &mut source,
        &mut pending,
    ));
    assert!(matches!(poll_once(retry.as_mut()), Poll::Ready(Ok(()))));
    drop(retry);
    assert_eq!(pending, None);
    assert_eq!(receiver.try_recv(), Ok(7));
}

fn admission_fixture(
    limit: usize,
) -> (crate::lab::LabRuntime, Cx, crate::runtime::TaskHandle<()>) {
    crate::test_utils::init_test_logging();
    let mut lab = crate::lab::LabRuntime::new(crate::lab::LabConfig::new(0x28_c002).max_steps(128));
    let root = lab.state.create_root_region(crate::types::Budget::INFINITE);
    assert!(lab.state.set_region_limits(
        root,
        crate::record::region::RegionLimits {
            max_obligations: Some(limit),
            ..crate::record::region::RegionLimits::UNLIMITED
        }
    ));
    let (task, handle) = lab
        .state
        .create_task(root, crate::types::Budget::INFINITE, async {})
        .unwrap();
    let cx = lab.state.task(task).unwrap().cx.clone().unwrap();
    (lab, cx, handle)
}

fn finish_admission_fixture(
    mut lab: crate::lab::LabRuntime,
    cx: &Cx,
    mut handle: crate::runtime::TaskHandle<()>,
    reservations: u64,
) {
    let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
    lab.scheduler.lock().schedule(cx.task_id(), 0);
    let report = lab.run_until_quiescent_with_report();
    assert!(
        report.oracle_report.all_passed(),
        "{:?}",
        report.oracle_report.failures()
    );
    assert!(report.invariant_violations.is_empty());
    assert!(handle.try_join().unwrap().is_some());
    let stats = mailbox.stats();
    assert_eq!(stats.posted, stats.applied);
    assert_eq!(stats.reserved, reservations);
    assert_eq!(stats.committed + stats.aborted, reservations);
    assert_eq!(stats.leaked, 0);
    assert_eq!(mailbox.open_tickets(), 0);
    assert_eq!(lab.state.pending_obligation_count(), 0);
    assert_eq!(lab.state.leak_count(), 0);
}

#[test]
fn recoverable_quota_refusal_preserves_item_and_retry_reuses_returned_credit() {
    use crate::runtime::obligation_mailbox::ObligationAdmissionError;
    let (lab, cx, handle) = admission_fixture(1);
    let (sender, mut receiver) = mpsc::channel(2);
    let sink = into_sink(sender);
    let (blocker, _blocker_receiver) = mpsc::channel::<u8>(1);
    let held = blocker.try_reserve_checked(&cx).unwrap();
    let mut source = iter([41, 43]);
    let mut pending = None;
    let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));

    assert!(matches!(
        poll_once(run.as_mut()),
        Poll::Ready(Err(mpsc::CheckedSendError::Admission {
            error: ObligationAdmissionError::LimitReached { limit: 1, live: 1 },
            value: (),
        }))
    ));
    drop(run);
    assert_eq!(pending, Some(41));
    assert!(receiver.is_empty());
    assert_eq!(sink.sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);

    // No lab step or mailbox drain: dropping the blocker must return quota
    // synchronously, and each successful forward must recycle that one credit.
    drop(held);
    let mut retry = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
    assert!(matches!(poll_once(retry.as_mut()), Poll::Ready(Ok(()))));
    drop(retry);
    assert_eq!(pending, None);
    assert_eq!(drain(&mut receiver), [41, 43]);
    finish_admission_fixture(lab, &cx, handle, 3);
}

#[test]
fn recoverable_close_during_admission_restores_item_before_settlement_notification() {
    use crate::runtime::obligation_mailbox::ObligationGateway;
    for panic_on_settlement in [false, true] {
        let (lab, cx, handle) = admission_fixture(1);
        let mailbox = Arc::clone(lab.state.obligation_gateway().unwrap().mailbox());
        let (sender, mut receiver) = mpsc::channel::<DropProbe>(1);
        let close_sender = sender.clone();
        let notifications = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&notifications);
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            mailbox,
            Arc::new(move || {
                let index = observed.fetch_add(1, Ordering::SeqCst);
                if index == 0 {
                    // Capacity was already reserved, but publication has not
                    // happened. Exercise the commit-refusal path, not the
                    // simpler disconnected-before-reservation path.
                    close_sender.close_receiver();
                } else if index == 1 && panic_on_settlement {
                    panic!("planted forwarding settlement notification panic");
                }
            }),
            Arc::downgrade(&liveness),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        let sink = into_sink(sender);
        let drops = Arc::new(AtomicUsize::new(0));
        let mut source = iter([
            DropProbe { id: 7, drops: Arc::clone(&drops) },
            DropProbe { id: 8, drops: Arc::clone(&drops) },
        ]);
        let mut pending = None;
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut run = Box::pin(sink.send_all_recoverable(&cx, &mut source, &mut pending));
            poll_once(run.as_mut())
        }));
        if panic_on_settlement {
            assert!(outcome.is_err(), "the planted settlement callback must run");
        } else {
            assert!(matches!(
                outcome,
                Ok(Poll::Ready(Err(mpsc::CheckedSendError::Channel(
                    SendError::Disconnected(())
                ))))
            ));
        }
        assert_eq!(notifications.load(Ordering::SeqCst), 2);
        assert_eq!(pending.as_ref().map(|item| item.id), Some(7));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(matches!(receiver.try_recv(), Err(mpsc::RecvError::Disconnected)));
        assert_eq!(sink.sender.telemetry_snapshot(1).reserved_uncommitted_obligations, 0);

        let (sender, mut receiver) = mpsc::channel(2);
        let replacement = into_sink(sender);
        let mut retry = Box::pin(replacement.send_all_recoverable(&cx, &mut source, &mut pending));
        assert!(matches!(poll_once(retry.as_mut()), Poll::Ready(Ok(()))));
        drop(retry);
        assert!(pending.is_none());
        let delivered = drain(&mut receiver);
        assert_eq!(delivered.iter().map(|item| item.id).collect::<Vec<_>>(), [7, 8]);
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        drop(delivered);
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        finish_admission_fixture(lab, &cx, handle, 3);
    }
}
