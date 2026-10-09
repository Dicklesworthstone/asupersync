//! Nonblocking collection must arm completion notifications, not rescan sleepers.

use super::*;
use crate::channel::oneshot;
use crate::runtime::spawn_mailbox::AdmittedTaskSlot;
use crate::runtime::task_handle::RetirementBarrier;
use crate::types::TaskId;
use std::sync::Weak;
use std::sync::atomic::{AtomicUsize, Ordering};

type Completion = oneshot::Sender<Result<Result<u32, &'static str>, JoinError>>;

fn member(slot: u32) -> (Completion, TaskHandle<Result<u32, &'static str>>) {
    crate::test_utils::init_test_logging();
    let (send, receive) = oneshot::channel();
    (
        send,
        TaskHandle::new(TaskId::new_for_test(slot, 0), receive, Weak::new()),
    )
}

#[test]
fn nonblocking_collection_parks_candidates_without_an_async_join() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let mut senders = Vec::new();
    for slot in 1..=256 {
        let (send, handle) = member(slot);
        set.insert_member(handle);
        senders.push(send);
    }
    assert_eq!(set.ready.candidates.lock().len(), 256);
    assert!(set.try_join_next().is_none());
    assert!(
        set.ready.candidates.lock().is_empty(),
        "sleepers no longer need rescanning"
    );
    assert!(set.members.values().all(|member| member.waker.is_some()));
    for _ in 0..32 {
        assert!(set.try_join_next().is_none());
        assert!(set.ready.candidates.lock().is_empty());
    }
    assert_eq!(set.len(), 256);
    assert_eq!(set.summary().completed(), 0);
    drop(senders);
}

#[test]
fn nonblocking_completion_arrivals_repopulate_only_their_own_candidates() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let mut senders = Vec::new();
    for slot in 1..=64 {
        let (send, handle) = member(slot);
        set.insert_member(handle);
        senders.push(Some(send));
    }
    assert!(set.try_join_next().is_none());
    for index in (0..64).rev() {
        senders[index]
            .take()
            .unwrap()
            .send(&cx, Ok(Ok(index as u32)))
            .unwrap();
        assert_eq!(
            set.ready
                .candidates
                .lock()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![index as u64],
        );
        assert!(matches!(set.try_join_next(), Some(Outcome::Ok(value)) if value == index as u32));
        assert!(set.try_join_next().is_none());
    }
    assert!(set.is_empty());
    assert_eq!(set.summary().completed(), 64);
}

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

#[test]
fn async_collection_after_nonblocking_parking_receives_completion_wake() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (send, handle) = member(1);
    set.insert_member(handle);
    assert!(set.try_join_next().is_none());
    let ready = Arc::clone(&set.ready);
    assert!(ready.candidates.lock().is_empty());
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    let mut task = Context::from_waker(&waker);
    let mut wait = Box::pin(set.join_next(&cx));
    assert!(wait.as_mut().poll(&mut task).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 0, "park without spinning");
    send.send(&cx, Ok(Ok(9))).unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 1);
    assert!(matches!(
        wait.as_mut().poll(&mut task),
        Poll::Ready(Some(Outcome::Ok(9)))
    ));
    assert!(ready.waiter.lock().is_none());
}

#[test]
fn a_ready_arrival_between_nonblocking_and_async_wait_is_not_lost() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (send, handle) = member(1);
    set.insert_member(handle);
    assert!(set.try_join_next().is_none());
    assert!(set.ready.waiter.lock().is_none());
    send.send(&cx, Ok(Ok(23))).unwrap();
    let mut wait = Box::pin(set.join_next(&cx));
    assert!(matches!(
        wait.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Some(Outcome::Ok(23)))
    ));
}

#[test]
fn nonblocking_collection_keeps_earliest_spawned_ready_tie_break() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (first, first_handle) = member(1);
    let (second, second_handle) = member(2);
    let (third, third_handle) = member(3);
    set.insert_member(first_handle);
    set.insert_member(second_handle);
    set.insert_member(third_handle);
    assert!(set.try_join_next().is_none());
    third.send(&cx, Ok(Ok(3))).unwrap();
    first.send(&cx, Ok(Ok(1))).unwrap();
    second.send(&cx, Ok(Err("second"))).unwrap();
    assert!(matches!(set.try_join_next(), Some(Outcome::Ok(1))));
    assert!(matches!(set.try_join_next(), Some(Outcome::Err("second"))));
    assert!(matches!(set.try_join_next(), Some(Outcome::Ok(3))));
    assert_eq!(set.summary().completed(), 3);
    assert_eq!(set.summary().worst(), Severity::Err);
}

#[test]
fn sender_disconnection_wakes_a_nonblocking_parked_member() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (send, handle) = member(1);
    set.insert_member(handle);
    assert!(set.try_join_next().is_none());
    assert!(set.ready.candidates.lock().is_empty());
    drop(send);
    assert!(set.ready.candidates.lock().contains(&0));
    assert!(matches!(set.try_join_next(), Some(Outcome::Cancelled(_))));
    assert!(set.is_empty());
}

#[test]
fn nonblocking_readiness_respects_retirement_before_exposing_a_value() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let barrier = RetirementBarrier::pending();
    let admitted = Arc::new(AdmittedTaskSlot::new().with_retirement_barrier(Arc::clone(&barrier)));
    let (send, receive) = oneshot::channel();
    let handle = TaskHandle::new_pending(TaskId::new_for_test(1, 0), receive, admitted);
    set.insert_member(handle);
    send.send(&cx, Ok(Ok(31))).unwrap();
    assert!(
        set.try_join_next().is_none(),
        "publication is not retirement"
    );
    assert!(set.ready.candidates.lock().is_empty());
    assert_eq!(set.summary().completed(), 0);
    barrier.open_and_wake();
    assert!(set.ready.candidates.lock().contains(&0));
    assert!(matches!(set.try_join_next(), Some(Outcome::Ok(31))));
    assert!(set.is_empty());
}

#[test]
fn late_spurious_wake_of_a_retired_member_cannot_lose_a_live_completion() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (first, first_handle) = member(1);
    let (second, second_handle) = member(2);
    set.insert_member(first_handle);
    set.insert_member(second_handle);
    assert!(set.try_join_next().is_none());
    let retired_wake = set.members.get(&0).unwrap().waker.as_ref().unwrap().clone();
    first.send(&cx, Ok(Ok(1))).unwrap();
    assert!(matches!(set.try_join_next(), Some(Outcome::Ok(1))));
    retired_wake.wake();
    second.send(&cx, Ok(Ok(2))).unwrap();
    assert!(matches!(set.try_join_next(), Some(Outcome::Ok(2))));
    assert!(set.ready.candidates.lock().is_empty());
    assert_eq!(set.summary().completed(), 2);
}
