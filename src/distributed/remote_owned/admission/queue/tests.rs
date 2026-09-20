use super::*;
use crate::cx::ChildRegionSpec;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, RegionId, TaskId, Time};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

const WAIT: Duration = Duration::from_secs(10);
fn context() -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = Cx::new_with_drivers(RegionId::new_for_test(0, 1), TaskId::new_for_test(0, 1),
        Budget::INFINITE, None, None, None, Some(timer.clone()), None);
    (cx, clock, timer)
}
fn queue_limits() -> RemoteQueueLimits {
    RemoteQueueLimits { max_waiters: 8, max_input_bytes: 128,
        max_waiters_per_peer: 4, max_input_bytes_per_peer: 64 }
}
fn executor(total: usize, per_peer: usize, queue: RemoteQueueLimits) -> RemoteExecutor {
    RemoteExecutor::new_queued(RemoteAdmissionLimits { max_peers: 2,
        max_in_flight: total, max_input_bytes: 64 },
        ["alpha", "beta"].map(|name| (NodeId::new(name), RemotePeerLimits {
            max_in_flight: per_peer, max_input_bytes: 64, max_request_bytes: 128,
        })), queue).unwrap()
}
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready<F: Future>(future: Pin<&mut F>) -> F::Output {
    match poll(future) { Poll::Ready(value) => value, Poll::Pending => panic!("expected ready") }
}

#[test]
fn immediate_reservation_is_one_active_charge_until_dropped() {
    let (cx, _, timer) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha");
    let mut wait = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    assert_eq!(executor.usage().in_flight, 0, "unpolled future has no admission");
    let reservation = ready(wait.as_mut()).unwrap();
    assert_eq!(reservation.input_bytes(), 8);
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 8 });
    assert_eq!(executor.queue_usage(), RemoteQueueUsage::default());
    assert_eq!(timer.pending_count(), 0);
    drop(reservation);
    assert_eq!(executor.usage(), RemoteAdmissionUsage::default());
}

#[test]
fn fifo_and_mixed_immediate_calls_cannot_steal_a_released_slot() {
    let (cx, _, _) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let held = executor.acquire(&node, 8).unwrap();
    let mut first = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    let mut second = Box::pin(executor.reserve(&cx, &node, 4, WAIT));
    assert!(poll(first.as_mut()).is_pending()); assert!(poll(second.as_mut()).is_pending());
    assert_eq!(executor.queue_usage(), RemoteQueueUsage { waiters: 2, input_bytes: 12 });
    drop(held);
    assert!(matches!(executor.acquire(&node, 1), Err(RemoteAdmissionError::Queued)));
    assert!(poll(second.as_mut()).is_pending(), "out-of-order polling cannot overtake FIFO");
    let first = ready(first.as_mut()).unwrap();
    assert_eq!(executor.usage().input_bytes, 8);
    assert!(poll(second.as_mut()).is_pending());
    drop(first);
    let second = ready(second.as_mut()).unwrap();
    assert_eq!(executor.queue_usage(), RemoteQueueUsage::default());
    drop(second); assert_eq!(executor.usage().in_flight, 0);
}

#[test]
fn blocked_peer_head_does_not_stall_another_peer() {
    let (cx, _, _) = context(); let executor = executor(2, 1, queue_limits());
    let alpha = NodeId::new("alpha"); let beta = NodeId::new("beta");
    let held = executor.acquire(&alpha, 8).unwrap();
    let mut blocked = Box::pin(executor.reserve(&cx, &alpha, 8, WAIT));
    assert!(poll(blocked.as_mut()).is_pending());
    let mut other = Box::pin(executor.reserve(&cx, &beta, 8, WAIT));
    let permit = ready(other.as_mut()).unwrap();
    assert_eq!(executor.usage().in_flight, 2);
    assert_eq!(executor.peer_queue_usage(&alpha).unwrap().waiters, 1);
    drop(permit); drop(blocked); drop(held);
    assert_eq!(executor.queue_usage(), RemoteQueueUsage::default());
}

#[test]
fn dropping_a_byte_blocked_head_unblocks_its_smaller_successor() {
    let (cx, _, _) = context(); let executor = executor(3, 3, queue_limits());
    let alpha = NodeId::new("alpha"); let beta = NodeId::new("beta");
    let held = executor.acquire(&beta, 40).unwrap();
    let mut first = Box::pin(executor.reserve(&cx, &alpha, 32, WAIT));
    let mut second = Box::pin(executor.reserve(&cx, &alpha, 8, WAIT));
    assert!(poll(first.as_mut()).is_pending()); assert!(poll(second.as_mut()).is_pending());
    drop(first);
    let second = ready(second.as_mut()).unwrap();
    assert_eq!(executor.usage().input_bytes, 48);
    drop(second); drop(held);
}

struct Counter(AtomicUsize);
impl Wake for Counter {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn only_last_scope_or_proxy_share_release_wakes_queued_work() {
    let (cx, _, _) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let scope = executor.acquire(&node, 8).unwrap();
    let proxy = scope.clone();
    let count = Arc::new(Counter(AtomicUsize::new(0))); let waker = Waker::from(Arc::clone(&count));
    let mut wait = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    drop(scope);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert_eq!(executor.usage().in_flight, 1);
    drop(proxy);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    drop(ready(wait.as_mut()).unwrap());
}

#[test]
fn all_four_waiting_limits_are_enforced_without_changing_active_usage() {
    for dimension in 0..4 {
        let (cx, _, _) = context(); let mut queue = queue_limits();
        let name = match dimension {
            0 => { queue.max_waiters = 0; "waiters" }
            1 => { queue.max_input_bytes = 3; "input bytes" }
            2 => { queue.max_waiters_per_peer = 0; "peer waiters" }
            _ => { queue.max_input_bytes_per_peer = 3; "peer input bytes" }
        };
        let executor = executor(1, 1, queue); let node = NodeId::new("alpha");
        let held = executor.acquire(&node, 8).unwrap();
        let mut wait = Box::pin(executor.reserve(&cx, &node, 4, WAIT));
        assert!(matches!(ready(wait.as_mut()), Err(RemoteReserveError::QueueLimit(actual)) if actual == name));
        assert_eq!(executor.queue_usage(), RemoteQueueUsage::default());
        assert_eq!(executor.usage().input_bytes, 8); drop(held);
    }
}

#[test]
fn impossible_requests_refuse_instead_of_waiting_until_timeout() {
    let (cx, _, timer) = context(); let node = NodeId::new("alpha");
    for (total, per_peer, bytes) in [(0, 1, 8), (1, 0, 8), (1, 1, 65)] {
        let executor = executor(total, per_peer, queue_limits());
        let mut wait = Box::pin(executor.reserve(&cx, &node, bytes, WAIT));
        assert!(matches!(ready(wait.as_mut()), Err(RemoteReserveError::Admission(_))));
        assert_eq!(executor.queue_usage().waiters, 0); assert_eq!(timer.pending_count(), 0);
    }
}

#[test]
fn cancellation_wins_available_credit_and_removes_timer_and_waiter() {
    let (cx, _, timer) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let held = executor.acquire(&node, 8).unwrap();
    let mut wait = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    assert!(poll(wait.as_mut()).is_pending()); assert_eq!(timer.pending_count(), 1);
    cx.cancel_with(CancelKind::User, Some("reservation test")); drop(held);
    assert!(matches!(ready(wait.as_mut()), Err(RemoteReserveError::Cancelled)));
    assert_eq!(executor.queue_usage().waiters, 0); assert_eq!(executor.usage().in_flight, 0);
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn exact_deadline_wins_a_simultaneously_released_slot() {
    let (cx, clock, timer) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let held = executor.acquire(&node, 8).unwrap();
    let mut wait = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    assert!(poll(wait.as_mut()).is_pending());
    clock.advance_to(Time::from_nanos(10_000_000_000)); timer.process_timers(); drop(held);
    assert!(matches!(ready(wait.as_mut()), Err(RemoteReserveError::Deadline)));
    assert_eq!(executor.queue_usage().waiters, 0); assert_eq!(executor.usage().in_flight, 0);
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn external_drop_removes_queued_bytes_and_timer_without_dispatch() {
    let (cx, _, timer) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let held = executor.acquire(&node, 8).unwrap();
    let mut wait = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    assert!(poll(wait.as_mut()).is_pending()); drop(wait);
    assert_eq!(executor.queue_usage(), RemoteQueueUsage::default());
    assert_eq!(timer.pending_count(), 0); assert_eq!(executor.usage().in_flight, 1); drop(held);
}

#[test]
fn close_wakes_waiters_but_preserves_previously_issued_reservations() {
    let (cx, _, _) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha");
    let held = ready(Box::pin(executor.reserve(&cx, &node, 8, WAIT)).as_mut()).unwrap();
    let mut wait = Box::pin(executor.reserve(&cx, &node, 4, WAIT));
    assert!(poll(wait.as_mut()).is_pending()); assert!(executor.clone().close_admission());
    assert!(!executor.close_admission());
    assert!(matches!(ready(wait.as_mut()), Err(RemoteReserveError::Admission(RemoteAdmissionError::Closed))));
    assert_eq!(executor.queue_usage().waiters, 0); assert_eq!(executor.usage().in_flight, 1);
    drop(held); assert_eq!(executor.usage().in_flight, 0);
}

#[test]
fn reservation_length_mismatch_and_execution_setup_failure_release_charge() {
    let (cx, _, _) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha");
    for bytes in [3, 4] {
        let held = ready(Box::pin(executor.reserve(&cx, &node, 4, WAIT)).as_mut()).unwrap();
        let config = RemoteRunConfig { timeout: WAIT, child: ChildRegionSpec::inherit() };
        let mut run = Box::pin(held.run(&cx, ComputationName::new("not-dispatched"), RemoteInput::new(vec![0; bytes]), config));
        let result = ready(run.as_mut());
        if bytes == 3 { assert!(matches!(result, Err(RemoteReserveError::InputLength))); }
        else { assert!(matches!(result, Err(RemoteReserveError::Run(RemoteRunError::NoCapability)))); }
        assert_eq!(executor.usage().in_flight, 0);
    }
}

#[test]
fn queue_sequence_and_byte_arithmetic_refuse_overflow() {
    let (cx, _, _) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let held = executor.acquire(&node, 8).unwrap();
    executor.shared.state.lock().queue.as_mut().unwrap().next = u64::MAX;
    assert!(matches!(ready(Box::pin(executor.reserve(&cx, &node, 4, WAIT)).as_mut()), Err(RemoteReserveError::SequenceExhausted)));
    assert!(queued_next(RemoteQueueUsage { waiters: 1, input_bytes: usize::MAX }, 1,
        usize::MAX, usize::MAX, "waiters", "bytes").is_err());
    assert!(queued_next(RemoteQueueUsage { waiters: usize::MAX, input_bytes: 0 }, 0,
        usize::MAX, usize::MAX, "waiters", "bytes").is_err());
    assert_eq!(executor.queue_usage().waiters, 0); drop(held);
}

#[test]
fn old_constructor_does_not_silently_enable_waiting() {
    let (cx, _, _) = context();
    let executor = RemoteExecutor::new(RemoteAdmissionLimits { max_peers: 0, max_in_flight: 1, max_input_bytes: 8 }, []).unwrap();
    assert!(matches!(ready(Box::pin(executor.reserve(&cx, &NodeId::new("alpha"), 1, WAIT)).as_mut()), Err(RemoteReserveError::Disabled)));
}

#[test]
fn release_before_notification_registration_is_observed_by_predicate() {
    let (_, _, _) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let held = executor.acquire(&node, 8).unwrap();
    let id = executor.shared.state.lock().queue.as_mut().unwrap().insert(0, 8).unwrap();
    let ticket = Ticket { shared: Arc::clone(&executor.shared), id: Some(id) };
    assert!(!ticket.ready()); drop(held); // No Notify waiter existed at release.
    let mut changed = Box::pin(executor.shared.queue_notify.as_ref().unwrap().wait_until(|| ticket.ready()));
    assert!(poll(changed.as_mut()).is_ready()); drop(changed); drop(ticket);
    assert_eq!(executor.queue_usage().waiters, 0);
}

struct Reenter(RemoteExecutor, AtomicUsize);
impl Wake for Reenter {
    fn wake(self: Arc<Self>) {
        assert!(self.0.shared.state.try_lock().is_some(), "wakeup under budget mutex");
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}
#[test]
fn release_and_close_run_safe_wake_callbacks_outside_the_budget_lock() {
    let (cx, _, _) = context(); let executor = executor(1, 1, queue_limits());
    let node = NodeId::new("alpha"); let held = executor.acquire(&node, 8).unwrap();
    let witness = Arc::new(Reenter(executor.clone(), AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&witness));
    let mut wait = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    assert!(wait.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    drop(held); assert!(witness.1.load(Ordering::SeqCst) > 0);
    executor.close_admission(); drop(wait);
    assert_eq!(executor.usage().in_flight, 0); assert_eq!(executor.queue_usage().waiters, 0);
}
