//! Cancellation-only wakeups, FIFO handoff, and independent context authority.
#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::types::CancelKind;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Wake;

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.wake_by_ref(); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn counter() -> (Arc<Wakes>, Waker) {
    crate::test_utils::init_test_logging();
    let count = Arc::new(Wakes::default());
    (Arc::clone(&count), Waker::from(count))
}
fn poll<F: Future>(future: Pin<&mut F>, waker: &Waker) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(waker))
}

#[test]
fn cancellation_wakes_waiter_without_releasing_the_lock() {
    let cx = Cx::detached_cancel_context();
    let mutex = Mutex::new(41);
    let held = mutex.try_lock().unwrap();
    let (count, waker) = counter();
    let mut waiting = Box::pin(mutex.lock(&cx));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0, "cancellation is the only event");
    assert!(matches!(poll(waiting.as_mut(), &waker), Poll::Ready(Err(LockError::Cancelled))));
    assert_eq!(mutex.waiters(), 0);
    assert!(mutex.is_locked());
    assert_eq!(*held, 41);
    assert_eq!(Arc::strong_count(&count), 2, "completed future retains no executor");
    assert!(matches!(poll(waiting.as_mut(), &waker), Poll::Ready(Err(LockError::PolledAfterCompletion))));
}

#[test]
fn owned_acquisition_inherits_cancellation_wakeups() {
    let cx = Cx::for_testing();
    let mutex = Arc::new(Mutex::new(7));
    let _held = mutex.try_lock().unwrap();
    let (count, waker) = counter();
    let mut waiting = Box::pin(OwnedMutexGuard::lock(Arc::clone(&mutex), &cx));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(poll(waiting.as_mut(), &waker), Poll::Ready(Err(LockError::Cancelled))));
    assert_eq!(mutex.waiters(), 0);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn dropping_one_same_waker_wait_does_not_unsubscribe_another() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let _held = mutex.try_lock().unwrap();
    let (count, waker) = counter();
    let mut first = Box::pin(mutex.lock(&cx));
    let mut second = Box::pin(mutex.lock(&cx));
    assert!(poll(first.as_mut(), &waker).is_pending());
    assert!(poll(second.as_mut(), &waker).is_pending());
    drop(first);
    assert_eq!(mutex.waiters(), 1);
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(poll(second.as_mut(), &waker), Poll::Ready(Err(LockError::Cancelled))));
    assert_eq!(mutex.waiters(), 0);
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn dropped_wait_does_not_keep_a_cancellation_or_unlock_subscription() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let held = mutex.try_lock().unwrap();
    let (count, waker) = counter();
    let mut waiting = Box::pin(mutex.lock(&cx));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    drop(waiting);
    assert_eq!(Arc::strong_count(&count), 2);
    cx.cancel_fast(CancelKind::User);
    drop(held);
    assert_eq!(count.0.load(Ordering::SeqCst), 0);
    assert!(mutex.try_lock().is_ok());
}

#[test]
fn moving_a_wait_updates_both_wake_targets() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let _held = mutex.try_lock().unwrap();
    let (old, old_waker) = counter();
    let (new, new_waker) = counter();
    let mut waiting = Box::pin(mutex.lock(&cx));
    assert!(poll(waiting.as_mut(), &old_waker).is_pending());
    assert!(poll(waiting.as_mut(), &new_waker).is_pending());
    assert_eq!(Arc::strong_count(&old), 2);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert!(new.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(poll(waiting.as_mut(), &new_waker), Poll::Ready(Err(LockError::Cancelled))));
    assert_eq!(Arc::strong_count(&new), 2);
}

#[test]
fn cancelled_grantee_passes_ownership_to_the_next_waiter() {
    let first_cx = Cx::for_testing();
    let next_cx = Cx::for_testing();
    let mutex = Mutex::new(9);
    let held = mutex.try_lock().unwrap();
    let (first_count, first_waker) = counter();
    let (next_count, next_waker) = counter();
    let mut first = Box::pin(mutex.lock(&first_cx));
    let mut next = Box::pin(mutex.lock(&next_cx));
    assert!(poll(first.as_mut(), &first_waker).is_pending());
    assert!(poll(next.as_mut(), &next_waker).is_pending());
    drop(held); // The FIFO turn now belongs to the first waiter.
    assert!(first_count.0.load(Ordering::SeqCst) > 0);
    first_cx.cancel_fast(CancelKind::User);
    assert!(matches!(poll(first.as_mut(), &first_waker), Poll::Ready(Err(LockError::Cancelled))));
    assert!(next_count.0.load(Ordering::SeqCst) > 0);
    assert!(matches!(mutex.try_lock(), Err(TryLockError::Locked)), "no barging past the successor");
    let Poll::Ready(Ok(guard)) = poll(next.as_mut(), &next_waker) else { panic!("successor must own the turn") };
    assert_eq!(*guard, 9);
    drop(guard);
    assert!(mutex.try_lock().is_ok());
}

#[test]
fn ready_and_precancelled_locks_do_not_subscribe() {
    for cancelled in [false, true] {
        let cx = Cx::for_testing();
        if cancelled { cx.cancel_fast(CancelKind::User); }
        let mutex = Mutex::new(());
        let (count, waker) = counter();
        let mut waiting = Box::pin(mutex.lock(&cx));
        match poll(waiting.as_mut(), &waker) {
            Poll::Ready(Ok(guard)) => { assert!(!cancelled); drop(guard); }
            Poll::Ready(Err(LockError::Cancelled)) => assert!(cancelled),
            _ => panic!("ready lock must not park"),
        }
        assert_eq!(mutex.waiters(), 0);
        assert_eq!(Arc::strong_count(&count), 2);
        cx.cancel_fast(CancelKind::User);
        assert_eq!(count.0.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn successful_acquisition_clears_subscription_before_future_drop() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let held = mutex.try_lock().unwrap();
    let (count, waker) = counter();
    let mut waiting = Box::pin(mutex.lock(&cx));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    drop(held);
    let Poll::Ready(Ok(guard)) = poll(waiting.as_mut(), &waker) else { panic!("ready guard") };
    assert_eq!(Arc::strong_count(&count), 2);
    let before = count.0.load(Ordering::SeqCst);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), before);
    drop(guard);
}

#[test]
fn masked_cancellation_does_not_forfeit_a_fifo_turn() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let held = mutex.try_lock().unwrap();
    let (count, waker) = counter();
    let mut waiting = Box::pin(mutex.lock(&cx));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(count.0.load(Ordering::SeqCst) > 0);
    cx.masked(|| {
        assert!(poll(waiting.as_mut(), &waker).is_pending());
        assert_eq!(mutex.waiters(), 1);
        drop(held);
        let Poll::Ready(Ok(guard)) = poll(waiting.as_mut(), &waker) else { panic!("masked acquisition") };
        drop(guard);
    });
    assert!(cx.is_cancel_requested());
    assert_eq!(Arc::strong_count(&count), 2);
}

#[test]
fn terminal_cancellation_retires_deadline_state_without_waiting_for_deadline() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let _held = mutex.try_lock().unwrap();
    let (_, waker) = counter();
    let deadline = crate::time::wall_now() + std::time::Duration::from_secs(3600);
    let mut waiting = Box::pin(mutex.lock_until(&cx, deadline));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    cx.cancel_fast(CancelKind::User);
    assert!(matches!(poll(waiting.as_mut(), &waker), Poll::Ready(Err(LockError::Cancelled))));
    assert!(waiting.deadline_sleep.is_none());
    assert!(waiting.cancelled.is_none());
    assert_eq!(mutex.waiters(), 0);
}

#[test]
fn poisoned_completion_retires_the_cancellation_observer() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let held = mutex.try_lock().unwrap();
    let (count, waker) = counter();
    let mut waiting = Box::pin(mutex.lock(&cx));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    mutex.poison_for_testing();
    drop(held);
    assert!(matches!(poll(waiting.as_mut(), &waker), Poll::Ready(Err(LockError::Poisoned))));
    assert_eq!(Arc::strong_count(&count), 2);
    let before = count.0.load(Ordering::SeqCst);
    cx.cancel_fast(CancelKind::User);
    assert_eq!(count.0.load(Ordering::SeqCst), before);
}

struct CancelOnDrop(Cx);
// The waker's Drop is the point: it cancels the context on retirement.
#[allow(clippy::manual_noop_waker)]
impl Wake for CancelOnDrop { fn wake(self: Arc<Self>) {} }
impl Drop for CancelOnDrop {
    fn drop(&mut self) { self.0.cancel_fast(CancelKind::User); }
}

#[test]
fn cancellation_from_waker_retirement_cannot_be_lost_during_migration() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(());
    let _held = mutex.try_lock().unwrap();
    let mut waiting = Box::pin(mutex.lock(&cx));
    {
        let old = Waker::from(Arc::new(CancelOnDrop(cx.clone())));
        assert!(poll(waiting.as_mut(), &old).is_pending());
    }
    assert!(!cx.is_cancel_requested());
    let (count, waker) = counter();
    assert!(matches!(poll(waiting.as_mut(), &waker), Poll::Ready(Err(LockError::Cancelled))));
    assert!(cx.is_cancel_requested());
    assert_eq!(mutex.waiters(), 0);
    assert_eq!(Arc::strong_count(&count), 2);
}

async fn independent_authority(cx: Cx) {
    let mutex = Arc::new(Mutex::new(()));
    let held = OwnedMutexGuard::try_lock(Arc::clone(&mutex)).unwrap();
    let authority = Cx::detached_cancel_context();
    let observed = authority.clone();
    let target = Arc::clone(&mutex);
    let (started, mut parked) = crate::channel::oneshot::channel();
    let completed = Arc::new(AtomicBool::new(false));
    let child_completed = Arc::clone(&completed);
    let mut task = cx.spawn(move |_child| async move {
        let mut waiting = Box::pin(OwnedMutexGuard::lock(target, &observed));
        let mut started = Some(started);
        let result = std::future::poll_fn(|task| {
            let result = waiting.as_mut().poll(task);
            if result.is_pending() && let Some(started) = started.take() {
                started.send_blocking(()).unwrap();
            }
            result
        }).await;
        assert!(matches!(result, Err(LockError::Cancelled)));
        child_completed.store(true, Ordering::SeqCst);
    }).unwrap();
    parked.recv(&cx).await.unwrap();
    authority.cancel_fast(CancelKind::User);
    for _ in 0..64 { crate::runtime::yield_now().await; }
    let completed_without_unlock = completed.load(Ordering::SeqCst);
    // Freeze the assertion before unlock, but release afterward so the old
    // implementation also terminates instead of hanging the test harness.
    drop(held);
    task.join(&cx).await.unwrap();
    assert!(completed_without_unlock, "no runtime task cancellation or unlock rescued this wait");
    assert!(!cx.is_cancel_requested());
    assert!(mutex.try_lock().is_ok());
}

#[test]
fn explicit_independent_context_wakes_lock_waits_under_lab() {
    for seed in [0x10c0, 0x10c1, 0x10c2] {
        let ((), report) = crate::lab::run_async_under_lab(seed, independent_authority);
        assert!(report.quiescent && report.invariant_violations.is_empty());
    }
}

#[test]
#[cfg(not(target_arch = "wasm32"))]
fn explicit_independent_context_wakes_lock_waits_on_native_runtime() {
    let runtime = crate::runtime::RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(runtime.handle().spawn(async {
        independent_authority(Cx::current().unwrap()).await;
    }));
}

/// The deadline of `lock_until` measures time, not the running task's
/// cancellation. With an ambient context other than the lock's `cx`, it used
/// the cancel-aware `Sleep::poll`, so cancelling the running task made the
/// wait return `TimedOut` an hour early (and each `.await` could finish that
/// way without yielding) (br-asupersync-x2cqdf).
#[test]
fn ambient_cancellation_is_not_a_lock_until_timeout() {
    let ambient = Cx::for_testing();
    let _current = Cx::set_current(Some(ambient.clone()));
    let authority = Cx::for_testing();
    let mutex = Mutex::new(());
    let _held = mutex.try_lock().unwrap();
    let (_, waker) = counter();
    let deadline = crate::time::wall_now() + std::time::Duration::from_secs(3600);
    let mut waiting = Box::pin(mutex.lock_until(&authority, deadline));
    assert!(poll(waiting.as_mut(), &waker).is_pending());
    ambient.cancel_fast(CancelKind::User);
    assert!(
        poll(waiting.as_mut(), &waker).is_pending(),
        "an hour-long deadline cannot have passed"
    );
    assert_eq!(mutex.waiters(), 1);
}

/// A waker payload whose destructor panics once armed. Every clone of a
/// `Waker::from(Arc<..>)` shares it, so it runs when the last clone drops.
struct PanicsWhenLastDropped(Arc<std::sync::atomic::AtomicBool>);
// Its Drop is the point; `Waker::noop()` carries no payload to drop.
#[allow(clippy::manual_noop_waker)]
impl Wake for PanicsWhenLastDropped {
    fn wake(self: Arc<Self>) {}
    fn wake_by_ref(self: &Arc<Self>) {}
}
impl Drop for PanicsWhenLastDropped {
    fn drop(&mut self) {
        if self.0.swap(false, Ordering::SeqCst) {
            panic!("waker destructor panicked");
        }
    }
}

/// Completing an acquisition drops the wait's cancel observer, which holds
/// the last clones of a user waker. A panic in that waker's destructor used
/// to unwind through the guard just acquired and poison the mutex, although
/// no critical section ran (br-asupersync-x2cqdf L2). The panic still reaches
/// the caller; the mutex ends unlocked and not poisoned.
#[test]
fn panicking_waker_destructor_after_acquire_does_not_poison() {
    let cx = Cx::for_testing();
    let mutex = Mutex::new(5);
    let held = mutex.try_lock().unwrap();
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut waiting = Box::pin(mutex.lock(&cx));
    {
        let waker = Waker::from(Arc::new(PanicsWhenLastDropped(Arc::clone(&armed))));
        assert!(poll(waiting.as_mut(), &waker).is_pending());
    }
    // The hand-off consumes the queued clone; the cancel observer's clones
    // are the last ones left.
    drop(held);
    armed.store(true, Ordering::SeqCst);
    let (_, other) = counter();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = poll(waiting.as_mut(), &other);
    }));
    assert!(
        outcome.is_err(),
        "the destructor's panic reaches the caller"
    );
    assert!(!armed.load(Ordering::SeqCst), "the armed destructor ran");
    assert!(!mutex.is_poisoned(), "no critical section ran");
    assert_eq!(*mutex.try_lock().expect("unlocked after the panic"), 5);
}
