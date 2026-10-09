//! Collector wake subscriptions must not outlive their borrowing waits.

use super::*;
use crate::channel::oneshot;
use crate::types::TaskId;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

fn member(
    slot: u32,
) -> (
    oneshot::Sender<Result<Result<u32, &'static str>, JoinError>>,
    TaskHandle<Result<u32, &'static str>>,
) {
    crate::test_utils::init_test_logging();
    let (send, receive) = oneshot::channel();
    let handle = TaskHandle::new(TaskId::new_for_test(slot, 0), receive, Weak::new());
    (send, handle)
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

fn counter() -> (Arc<WakeCount>, Waker) {
    let count = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&count));
    (count, waker)
}

#[test]
fn dropped_wait_retires_collector_but_preserves_members_and_outcomes() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (send, handle) = member(1);
    set.insert_member(handle);
    let ready = Arc::clone(&set.ready);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut waiting = Box::pin(set.join_next(&cx));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    drop(waiting);

    assert!(ready.waiter.lock().is_none());
    assert_eq!(Arc::strong_count(&count), 2, "no obsolete executor owner");
    assert_eq!(set.len(), 1);
    send.send(&cx, Ok(Ok(17))).unwrap();
    assert_eq!(
        count.0.load(Ordering::SeqCst),
        0,
        "the old collector is gone"
    );
    assert!(ready.candidates.lock().contains(&0), "member wake survives");
    let mut retry = Box::pin(set.join_next(&cx));
    assert!(matches!(
        retry.as_mut().poll(&mut task),
        Poll::Ready(Some(Outcome::Ok(17)))
    ));
    drop(retry);
    assert!(set.is_empty());
    assert_eq!(set.summary().completed(), 1);
}

#[test]
fn completed_wait_retires_collector_before_the_future_is_dropped() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (first, first_handle) = member(1);
    let (second, second_handle) = member(2);
    set.insert_member(first_handle);
    set.insert_member(second_handle);
    let ready = Arc::clone(&set.ready);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut waiting = Box::pin(set.join_next(&cx));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    first.send(&cx, Ok(Ok(1))).unwrap();
    assert!(matches!(
        waiting.as_mut().poll(&mut task),
        Poll::Ready(Some(Outcome::Ok(1)))
    ));
    assert!(ready.waiter.lock().is_none());
    assert_eq!(Arc::strong_count(&count), 2);
    count.0.store(0, Ordering::SeqCst);
    second.send(&cx, Ok(Ok(2))).unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    drop(waiting);
    assert!(matches!(set.try_join_next(), Some(Outcome::Ok(2))));
}

#[test]
fn moving_a_pending_collector_retires_its_old_waker() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (send, handle) = member(1);
    set.insert_member(handle);
    let (old_count, old_waker) = counter();
    let (new_count, new_waker) = counter();
    let mut old_task = Context::from_waker(&old_waker);
    let mut new_task = Context::from_waker(&new_waker);
    let mut waiting = Box::pin(set.join_next(&cx));
    assert!(waiting.as_mut().poll(&mut old_task).is_pending());
    assert!(waiting.as_mut().poll(&mut new_task).is_pending());
    assert_eq!(Arc::strong_count(&old_count), 2);
    send.send(&cx, Ok(Ok(3))).unwrap();
    assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
    assert!(new_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(
        waiting.as_mut().poll(&mut new_task),
        Poll::Ready(Some(Outcome::Ok(3)))
    ));
    assert_eq!(Arc::strong_count(&new_count), 2);
}

#[test]
fn unchanged_task_reuses_the_same_arc_registration() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (_send, handle) = member(1);
    set.insert_member(handle);
    let ready = Arc::clone(&set.ready);
    let (_count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut waiting = Box::pin(set.join_next(&cx));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    let original = ready.waiter.lock().as_ref().unwrap().clone();
    for _ in 0..8 {
        assert!(waiting.as_mut().poll(&mut task).is_pending());
        assert!(Arc::ptr_eq(
            ready.waiter.lock().as_ref().unwrap(),
            &original
        ));
    }
    drop(waiting);
    assert!(ready.waiter.lock().is_none());
}

struct ReenterOnRetirement {
    ready: Weak<ReadyMembers>,
    retired: Arc<AtomicUsize>,
    locked: Arc<AtomicBool>,
}

// The waker's Drop is the point: it reenters the ready set on retirement.
#[allow(clippy::manual_noop_waker)]
impl Wake for ReenterOnRetirement {
    fn wake(self: Arc<Self>) {}
}

impl Drop for ReenterOnRetirement {
    fn drop(&mut self) {
        self.retired.fetch_add(1, Ordering::SeqCst);
        let Some(ready) = self.ready.upgrade() else {
            return;
        };
        // Fail as an assertion in the parent, not by hanging a test process.
        // The old in-lock replacement sets this flag when its last owner drops.
        let waiter = ready.waiter.try_lock();
        let candidates = ready.candidates.try_lock();
        if waiter.is_none() || candidates.is_none() {
            self.locked.store(true, Ordering::SeqCst);
            return;
        }
        drop(waiter);
        drop(candidates);
        // Reenter the production completion-wake path during final retirement.
        // It must see the replacement collector, not the one being destroyed.
        Waker::from(Arc::new(MemberWake { index: 0, ready })).wake();
    }
}

#[test]
fn replacement_retirement_reenters_after_unlock_and_sees_new_collector() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (_send, handle) = member(1);
    set.insert_member(handle);
    let retired = Arc::new(AtomicUsize::new(0));
    let locked = Arc::new(AtomicBool::new(false));
    let ready = Arc::clone(&set.ready);
    let mut waiting = Box::pin(set.join_next(&cx));
    {
        let old = Waker::from(Arc::new(ReenterOnRetirement {
            ready: Arc::downgrade(&ready),
            retired: Arc::clone(&retired),
            locked: Arc::clone(&locked),
        }));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&old))
                .is_pending()
        );
    }
    assert_eq!(retired.load(Ordering::SeqCst), 0);
    let (count, new) = counter();
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(&new))
            .is_pending()
    );
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    assert!(!locked.load(Ordering::SeqCst));
    assert!(
        count.0.load(Ordering::SeqCst) > 0,
        "reentrant event reached replacement"
    );
}

#[test]
fn drop_retirement_reenters_after_unlock_without_resurrecting_collector() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (_send, handle) = member(1);
    set.insert_member(handle);
    let ready = Arc::clone(&set.ready);
    let retired = Arc::new(AtomicUsize::new(0));
    let locked = Arc::new(AtomicBool::new(false));
    let mut waiting = Box::pin(set.join_next(&cx));
    {
        let old = Waker::from(Arc::new(ReenterOnRetirement {
            ready: Arc::downgrade(&ready),
            retired: Arc::clone(&retired),
            locked: Arc::clone(&locked),
        }));
        assert!(
            waiting
                .as_mut()
                .poll(&mut Context::from_waker(&old))
                .is_pending()
        );
    }
    drop(waiting);
    assert_eq!(retired.load(Ordering::SeqCst), 1);
    assert!(!locked.load(Ordering::SeqCst));
    assert!(ready.waiter.lock().is_none());
    assert!(ready.candidates.lock().contains(&0));
}

#[test]
fn fail_fast_completion_clears_collector_even_if_ready_state_is_retained() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (send, handle) = member(1);
    set.insert_member(handle);
    let ready = Arc::clone(&set.ready);
    let (count, waker) = counter();
    let mut task = Context::from_waker(&waker);
    let mut waiting = Box::pin(set.try_join_all(&cx));
    assert!(waiting.as_mut().poll(&mut task).is_pending());
    send.send(&cx, Ok(Ok(5))).unwrap();
    assert!(
        matches!(waiting.as_mut().poll(&mut task), Poll::Ready(Outcome::Ok(values)) if values == [5])
    );
    assert!(ready.waiter.lock().is_none());
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn fail_fast_abandonment_clears_the_collector_subscription() {
    let cx = Cx::for_testing();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (_send, handle) = member(1);
    set.insert_member(handle);
    let ready = Arc::clone(&set.ready);
    let (count, waker) = counter();
    let mut waiting = Box::pin(set.try_join_all(&cx));
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(waiting);
    assert!(ready.waiter.lock().is_none());
    assert_eq!(Arc::strong_count(&count), 2);
    Waker::from(Arc::new(MemberWake { index: 0, ready })).wake();
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
}

#[test]
fn owner_aware_borrowed_wait_retires_both_subscriptions_on_drop() {
    let cx = Cx::for_testing();
    let owner = Cx::detached_cancel_context();
    let mut set = JoinSet::<u32, &'static str, _>::in_cx(&cx);
    let (send, handle) = member(1);
    set.insert_member(handle);
    let ready = Arc::clone(&set.ready);
    let (count, waker) = counter();
    let mut waiting = Box::pin(set.join_next_cancel_on_owner(&owner));
    assert!(
        waiting
            .as_mut()
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(waiting);
    assert!(ready.waiter.lock().is_none());
    assert_eq!(Arc::strong_count(&count), 2);
    owner.cancel_with(crate::types::CancelKind::User, Some("observer left"));
    send.send(&cx, Ok(Ok(11))).unwrap();
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert!(matches!(set.try_join_next(), Some(Outcome::Ok(11))));
}

#[test]
fn retiring_an_old_registration_does_not_clear_a_replacement_owner() {
    let ready = Arc::new(ReadyMembers::default());
    let mut old = CollectorWait::new(Arc::clone(&ready));
    let mut new = CollectorWait::new(Arc::clone(&ready));
    let (old_count, old_waker) = counter();
    let (new_count, new_waker) = counter();
    old.refresh(&old_waker);
    new.refresh(&new_waker);
    drop(old);
    Waker::from(Arc::new(MemberWake {
        index: 7,
        ready: Arc::clone(&ready),
    }))
    .wake();
    assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
    assert_eq!(new_count.0.load(Ordering::SeqCst), 1);
    drop(new);
    assert!(ready.waiter.lock().is_none());
}
