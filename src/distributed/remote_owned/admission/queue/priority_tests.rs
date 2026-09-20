use super::*;
use crate::time::{TimerDriverHandle, VirtualClock};
use crate::types::{Budget, CancelKind, RegionId, TaskId, Time};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Wake, Waker};

const WAIT: Duration = Duration::from_secs(10);
fn context() -> (Cx, Arc<VirtualClock>, TimerDriverHandle) {
    let clock = Arc::new(VirtualClock::new());
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let cx = Cx::new_with_drivers(RegionId::new_for_test(0, 1), TaskId::new_for_test(0, 1),
        Budget::INFINITE, None, None, None, Some(timer.clone()), None);
    (cx, clock, timer)
}
fn queue() -> RemoteQueueLimits {
    RemoteQueueLimits { max_waiters: 8, max_input_bytes: 64,
        max_waiters_per_peer: 8, max_input_bytes_per_peer: 64 }
}
fn executor(bypass: usize) -> RemoteExecutor {
    build(bypass, 1, 64, queue())
}
fn build(bypass: usize, active: usize, bytes: usize, queue: RemoteQueueLimits) -> RemoteExecutor {
    RemoteExecutor::new_prioritized(
        RemoteAdmissionLimits { max_peers: 2, max_in_flight: active, max_input_bytes: bytes },
        ["a", "b"].map(|name| (NodeId::new(name), RemotePeerLimits {
            max_in_flight: active, max_input_bytes: bytes, max_request_bytes: bytes,
        })), queue, RemotePriorityPolicy { max_bypass: bypass },
    ).unwrap()
}
fn poll<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}
fn ready<F: Future>(future: Pin<&mut F>) -> F::Output {
    match poll(future) { Poll::Ready(value) => value, Poll::Pending => panic!("expected ready") }
}
fn empty(executor: &RemoteExecutor, timer: &TimerDriverHandle) {
    assert_eq!(executor.usage(), RemoteAdmissionUsage::default());
    assert_eq!(executor.queue_usage(), RemoteQueueUsage::default());
    assert_eq!(timer.pending_count(), 0);
}

#[test]
fn urgent_overtakes_older_normal_for_same_peer_without_an_extra_allowance() {
    let (cx, _, timer) = context(); let executor = executor(3); let node = NodeId::new("a");
    let held = executor.acquire(&node, 8).unwrap();
    let mut normal = Box::pin(executor.reserve(&cx, &node, 8, WAIT));
    let mut urgent = Box::pin(executor.reserve_with_priority(&cx, &node, 4, WAIT, RemotePriority::Urgent));
    assert!(poll(normal.as_mut()).is_pending()); assert!(poll(urgent.as_mut()).is_pending());
    assert_eq!(executor.queue_usage(), RemoteQueueUsage { waiters: 2, input_bytes: 12 });
    assert!(matches!(executor.acquire(&node, 0), Err(RemoteAdmissionError::Queued)));
    drop(held);
    assert!(poll(normal.as_mut()).is_pending(), "polling order cannot override priority");
    let urgent = ready(urgent.as_mut()).unwrap();
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 1, input_bytes: 4 });
    assert!(poll(normal.as_mut()).is_pending());
    drop(urgent); drop(ready(normal.as_mut()).unwrap()); empty(&executor, &timer);
}

#[test]
fn background_promotes_after_exactly_the_selected_queued_admission_count() {
    let (cx, _, timer) = context(); let executor = executor(2); let node = NodeId::new("a");
    let held = executor.acquire(&node, 1).unwrap();
    let mut background = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Background));
    assert!(poll(background.as_mut()).is_pending());
    for _ in 0..32 { assert!(poll(background.as_mut()).is_pending()); }
    assert_eq!(executor.shared.state.lock().queue.as_ref().unwrap().entries[&1].bypasses, 0);
    let mut urgent1 = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
    assert!(poll(urgent1.as_mut()).is_pending()); drop(held);
    let first = ready(urgent1.as_mut()).unwrap();
    let mut urgent2 = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
    assert!(poll(urgent2.as_mut()).is_pending()); drop(first);
    assert!(poll(background.as_mut()).is_pending(), "one bypass is below the threshold");
    let second = ready(urgent2.as_mut()).unwrap();
    let mut urgent3 = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
    assert!(poll(urgent3.as_mut()).is_pending()); drop(second);
    assert!(poll(urgent3.as_mut()).is_pending(), "young urgent cannot bypass promoted background");
    let old = ready(background.as_mut()).unwrap();
    assert!(poll(urgent3.as_mut()).is_pending()); drop(old);
    drop(ready(urgent3.as_mut()).unwrap()); empty(&executor, &timer);
}

#[test]
fn priority_is_fifo_within_a_class_and_enrollment_breaks_cross_peer_ties() {
    let (cx, _, timer) = context(); let executor = executor(8);
    let a = NodeId::new("a"); let b = NodeId::new("b");
    let held = executor.acquire(&a, 1).unwrap();
    let mut a1 = Box::pin(executor.reserve_with_priority(&cx, &a, 1, WAIT, RemotePriority::Urgent));
    let mut b1 = Box::pin(executor.reserve_with_priority(&cx, &b, 1, WAIT, RemotePriority::Urgent));
    let mut a2 = Box::pin(executor.reserve_with_priority(&cx, &a, 1, WAIT, RemotePriority::Urgent));
    assert!(poll(a1.as_mut()).is_pending()); assert!(poll(b1.as_mut()).is_pending()); assert!(poll(a2.as_mut()).is_pending());
    drop(held);
    assert!(poll(a2.as_mut()).is_pending()); assert!(poll(b1.as_mut()).is_pending());
    drop(ready(a1.as_mut()).unwrap());
    assert!(poll(a2.as_mut()).is_pending()); drop(ready(b1.as_mut()).unwrap());
    drop(ready(a2.as_mut()).unwrap()); empty(&executor, &timer);
}

#[test]
fn zero_bypass_prefers_oldest_feasible_head_regardless_of_class() {
    let (cx, _, timer) = context(); let executor = executor(0); let node = NodeId::new("a");
    let held = executor.acquire(&node, 1).unwrap();
    let mut low = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Background));
    let mut high = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
    assert!(poll(low.as_mut()).is_pending()); assert!(poll(high.as_mut()).is_pending()); drop(held);
    assert!(poll(high.as_mut()).is_pending()); drop(ready(low.as_mut()).unwrap());
    drop(ready(high.as_mut()).unwrap()); empty(&executor, &timer);
}

#[test]
fn an_unfittable_urgent_head_cannot_hold_capacity_needed_by_another_class() {
    let (cx, _, timer) = context(); let executor = build(2, 2, 16, queue());
    let a = NodeId::new("a"); let b = NodeId::new("b");
    let held = executor.acquire(&b, 12).unwrap();
    let mut high = Box::pin(executor.reserve_with_priority(&cx, &a, 8, WAIT, RemotePriority::Urgent));
    let mut low = Box::pin(executor.reserve_with_priority(&cx, &a, 4, WAIT, RemotePriority::Background));
    assert!(poll(high.as_mut()).is_pending());
    let small = ready(low.as_mut()).unwrap();
    assert_eq!(executor.usage(), RemoteAdmissionUsage { in_flight: 2, input_bytes: 16 });
    assert!(poll(high.as_mut()).is_pending()); drop(small); drop(held);
    drop(ready(high.as_mut()).unwrap()); empty(&executor, &timer);
}

#[test]
fn ordinary_constructor_and_normal_only_prioritized_queue_preserve_fifo() {
    let (cx, _, timer) = context(); let node = NodeId::new("a");
    let old = RemoteExecutor::new_queued(RemoteAdmissionLimits { max_peers: 1, max_in_flight: 1, max_input_bytes: 8 },
        [(node.clone(), RemotePeerLimits { max_in_flight: 1, max_input_bytes: 8, max_request_bytes: 8 })], queue()).unwrap();
    for priority in [RemotePriority::Background, RemotePriority::Urgent] {
        let mut wait = Box::pin(old.reserve_with_priority(&cx, &node, 1, WAIT, priority));
        assert!(matches!(ready(wait.as_mut()), Err(RemoteReserveError::PriorityDisabled)));
        empty(&old, &timer);
    }
    for executor in [old, executor(3)] {
        let held = executor.acquire(&node, 1).unwrap();
        let mut first = Box::pin(executor.reserve(&cx, &node, 1, WAIT));
        let mut second = Box::pin(executor.reserve(&cx, &node, 1, WAIT));
        assert!(poll(first.as_mut()).is_pending()); assert!(poll(second.as_mut()).is_pending()); drop(held);
        assert!(poll(second.as_mut()).is_pending()); drop(ready(first.as_mut()).unwrap());
        drop(ready(second.as_mut()).unwrap()); empty(&executor, &timer);
    }
}

#[test]
fn urgent_has_no_capacity_or_waiting_limit_bypass() {
    let (cx, _, timer) = context(); let node = NodeId::new("a");
    for dimension in 0..4 {
        let mut bounds = queue();
        let expected = match dimension {
            0 => { bounds.max_waiters = 1; "waiters" }
            1 => { bounds.max_input_bytes = 1; "input bytes" }
            2 => { bounds.max_waiters_per_peer = 1; "peer waiters" }
            _ => { bounds.max_input_bytes_per_peer = 1; "peer input bytes" }
        };
        let executor = build(2, 1, 8, bounds); let held = executor.acquire(&node, 1).unwrap();
        let mut first = Box::pin(executor.reserve(&cx, &node, 1, WAIT));
        assert!(poll(first.as_mut()).is_pending());
        let mut urgent = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
        assert!(matches!(ready(urgent.as_mut()), Err(RemoteReserveError::QueueLimit(name)) if name == expected));
        assert_eq!(executor.usage().in_flight, 1); assert_eq!(executor.queue_usage().waiters, 1);
        drop(first); drop(held); empty(&executor, &timer);
    }
    let executor = executor(2);
    let unknown = NodeId::new("untrusted");
    assert!(matches!(ready(Box::pin(executor.reserve_with_priority(&cx, &unknown, 0, WAIT, RemotePriority::Urgent)).as_mut()),
        Err(RemoteReserveError::Admission(RemoteAdmissionError::UnknownPeer))));
    assert!(matches!(ready(Box::pin(executor.reserve_with_priority(&cx, &node, 65, WAIT, RemotePriority::Urgent)).as_mut()),
        Err(RemoteReserveError::Admission(RemoteAdmissionError::RequestBytes))));
    empty(&executor, &timer);
}

#[test]
fn cancelling_or_dropping_a_selected_priority_head_unblocks_its_successors() {
    for cancel in [false, true] {
        let (cx, _, timer) = context(); let (other_cx, _, _) = context();
        let executor = executor(2); let node = NodeId::new("a");
        let held = executor.acquire(&node, 1).unwrap();
        let mut high = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
        let mut low = Box::pin(executor.reserve_with_priority(&other_cx, &node, 1, WAIT, RemotePriority::Background));
        assert!(poll(high.as_mut()).is_pending()); assert!(poll(low.as_mut()).is_pending()); drop(held);
        assert!(poll(low.as_mut()).is_pending());
        if cancel {
            cx.cancel_with(CancelKind::User, Some("cancel queued urgent"));
            assert!(matches!(ready(high.as_mut()), Err(RemoteReserveError::Cancelled)));
        }
        drop(high); drop(ready(low.as_mut()).unwrap()); empty(&executor, &timer);
    }
}

#[test]
fn deadline_dominates_priority_and_promotion() {
    let (cx, clock, timer) = context(); let executor = executor(0); let node = NodeId::new("a");
    let held = executor.acquire(&node, 1).unwrap();
    let mut high = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
    assert!(poll(high.as_mut()).is_pending());
    clock.advance_to(Time::from_nanos(10_000_000_000)); timer.process_timers(); drop(held);
    assert!(matches!(ready(high.as_mut()), Err(RemoteReserveError::Deadline))); empty(&executor, &timer);
}

#[test]
fn promotion_counter_saturates_and_cannot_wrap_away_eligibility() {
    let executor = executor(usize::MAX);
    let mut state = executor.shared.state.lock(); let queue = state.queue.as_mut().unwrap();
    let old = queue.insert_priority(0, 0, RemotePriority::Background).unwrap();
    queue.entries.get_mut(&old).unwrap().bypasses = usize::MAX - 1;
    queue.insert_priority(1, 0, RemotePriority::Urgent).unwrap();
    queue.admitted(); queue.admitted();
    assert_eq!(queue.entries[&old].bypasses, usize::MAX);
    assert_eq!(selected(&executor.shared, &state), Some(old));
}

// A wake emitted by claim() is arbitrary safe user code. It runs AFTER charging
// and unlocking but BEFORE delivering the reservation. Test both terminal races.
struct ClaimWake {
    armed: AtomicBool,
    executor: RemoteExecutor,
    caller: Cx,
    clock: Arc<VirtualClock>,
    deadline: bool,
}
impl Wake for ClaimWake {
    fn wake(self: Arc<Self>) {
        assert!(self.executor.shared.state.try_lock().is_some(), "callback under quota mutex");
        if self.armed.swap(false, Ordering::AcqRel) {
            if self.deadline { self.clock.advance_to(Time::from_nanos(10_000_000_000)); }
            else { self.caller.cancel_with(CancelKind::User, Some("claim callback")); }
        }
    }
}

#[test]
fn claim_notification_cannot_deliver_a_reservation_after_callback_cancellation() {
    for deadline in [false, true] {
        let (cx, clock, timer) = context(); let (other_cx, _, _) = context();
        let executor = executor(2); let node = NodeId::new("a");
        let held = executor.acquire(&node, 1).unwrap();
        let mut winner = Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, RemotePriority::Urgent));
        let mut observer = Box::pin(executor.reserve(&other_cx, &node, 1, WAIT));
        assert!(poll(winner.as_mut()).is_pending());
        let callback = Arc::new(ClaimWake { armed: AtomicBool::new(false), executor: executor.clone(),
            caller: cx.clone(), clock, deadline });
        let waker = Waker::from(Arc::clone(&callback));
        assert!(observer.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        drop(held); // Initial capacity notification must not fire the terminal race.
        assert!(observer.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
        callback.armed.store(true, Ordering::Release);
        let result = ready(winner.as_mut());
        if deadline { assert!(matches!(result, Err(RemoteReserveError::Deadline))); }
        else { assert!(matches!(result, Err(RemoteReserveError::Cancelled))); }
        assert_eq!(executor.usage().in_flight, 0, "cancelled delivered credit must be returned");
        drop(observer); empty(&executor, &timer);
    }
}

#[test]
fn closing_priority_admission_wakes_all_classes_without_revoking_issued_credit() {
    let (cx, _, timer) = context(); let executor = executor(2); let node = NodeId::new("a");
    let held = executor.acquire(&node, 1).unwrap();
    let mut waits = [RemotePriority::Background, RemotePriority::Normal, RemotePriority::Urgent]
        .map(|priority| Box::pin(executor.reserve_with_priority(&cx, &node, 1, WAIT, priority)));
    for wait in &mut waits { assert!(poll(wait.as_mut()).is_pending()); }
    assert!(executor.clone().close_admission());
    for wait in &mut waits {
        assert!(matches!(ready(wait.as_mut()), Err(RemoteReserveError::Admission(RemoteAdmissionError::Closed))));
    }
    assert_eq!(executor.usage().in_flight, 1); drop(held); empty(&executor, &timer);
}
