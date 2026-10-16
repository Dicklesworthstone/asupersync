use super::*;
use crate::runtime::spawn_blocking::release_fallback_slot;
use std::sync::atomic::Ordering;

#[derive(Default)]
struct WakeCount(AtomicUsize);

impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn poll(admission: &mut FallbackAdmission<'_>, waker: &Waker) -> Poll<()> {
    Pin::new(admission).poll(&mut Context::from_waker(waker))
}

#[test]
fn dropping_pending_admission_retires_task_without_worker_progress() {
    let count = AtomicUsize::new(1);
    let queue = Mutex::new(VecDeque::new());
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    for _ in 0..1024 {
        let mut admission = FallbackAdmission::new(&count, 1, &queue);
        assert!(poll(&mut admission, &waker).is_pending());
        assert_eq!(queue.lock().len(), 1);
        drop(admission);
        assert!(queue.lock().is_empty());
        assert_eq!(Arc::strong_count(&wakes), 2);
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
}

#[test]
fn admissions_sharing_a_task_waker_have_independent_registrations() {
    let count = AtomicUsize::new(1);
    let queue = Mutex::new(VecDeque::new());
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut first = FallbackAdmission::new(&count, 1, &queue);
    let mut second = FallbackAdmission::new(&count, 1, &queue);
    assert!(poll(&mut first, &waker).is_pending());
    assert!(poll(&mut second, &waker).is_pending());
    assert_eq!(queue.lock().len(), 2);
    drop(first);
    assert_eq!(queue.lock().len(), 1);
    release_fallback_slot(&count, &queue);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    assert!(poll(&mut second, &waker).is_ready());
    assert!(queue.lock().is_empty());
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn repoll_replaces_target_without_accumulating_queue_entries() {
    let count = AtomicUsize::new(1);
    let queue = Mutex::new(VecDeque::new());
    let old = Arc::new(WakeCount::default());
    let latest = Arc::new(WakeCount::default());
    let old_waker = Waker::from(Arc::clone(&old));
    let latest_waker = Waker::from(Arc::clone(&latest));
    let mut admission = FallbackAdmission::new(&count, 1, &queue);
    assert!(poll(&mut admission, &old_waker).is_pending());
    for _ in 0..32 {
        assert!(poll(&mut admission, &latest_waker).is_pending());
        assert_eq!(queue.lock().len(), 1);
    }
    assert_eq!(Arc::strong_count(&old), 2);
    release_fallback_slot(&count, &queue);
    assert_eq!(old.0.load(Ordering::SeqCst), 0);
    assert_eq!(latest.0.load(Ordering::SeqCst), 1);
    assert!(poll(&mut admission, &latest_waker).is_ready());
    assert_eq!(Arc::strong_count(&latest), 2);
}

#[test]
fn uncontended_admission_needs_no_registration() {
    let count = AtomicUsize::new(0);
    let queue = Mutex::new(VecDeque::new());
    let mut admission = FallbackAdmission::new(&count, 1, &queue);
    assert!(poll(&mut admission, Waker::noop()).is_ready());
    assert!(admission.registration.is_none());
    assert!(queue.lock().is_empty());
    drop(admission);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    release_fallback_slot(&count, &queue);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn a_waiter_that_loses_the_release_race_registers_again() {
    let count = AtomicUsize::new(1);
    let queue = Mutex::new(VecDeque::new());
    let wakes = Arc::new(WakeCount::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut admission = FallbackAdmission::new(&count, 1, &queue);
    assert!(poll(&mut admission, &waker).is_pending());
    release_fallback_slot(&count, &queue);
    assert!(try_claim_fallback_slot(&count, 1));
    assert!(poll(&mut admission, &waker).is_pending());
    assert_eq!(queue.lock().len(), 1);
    release_fallback_slot(&count, &queue);
    assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
    assert!(poll(&mut admission, &waker).is_ready());
}

#[test]
fn cancellation_racing_release_leaves_no_registration_or_task_reference() {
    for _ in 0..64 {
        let count = AtomicUsize::new(1);
        let queue = Mutex::new(VecDeque::new());
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut admission = FallbackAdmission::new(&count, 1, &queue);
        assert!(poll(&mut admission, &waker).is_pending());
        std::thread::scope(|scope| {
            let release = scope.spawn(|| release_fallback_slot(&count, &queue));
            drop(admission);
            release.join().unwrap();
        });
        assert!(queue.lock().is_empty());
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&wakes), 2);
    }
}

struct ReentrantWake {
    queue: Arc<Mutex<VecDeque<Waker>>>,
    callbacks: Arc<AtomicUsize>,
}

impl Wake for ReentrantWake {
    fn wake(self: Arc<Self>) {
        assert!(self.queue.try_lock().is_some(), "wake under queue lock");
        self.callbacks.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for ReentrantWake {
    fn drop(&mut self) {
        assert!(self.queue.try_lock().is_some(), "waker drop under queue lock");
        self.callbacks.fetch_add(1, Ordering::SeqCst);
    }
}

fn reentrant_waker(
    queue: &Arc<Mutex<VecDeque<Waker>>>,
    callbacks: &Arc<AtomicUsize>,
) -> Waker {
    Waker::from(Arc::new(ReentrantWake {
        queue: Arc::clone(queue),
        callbacks: Arc::clone(callbacks),
    }))
}

#[test]
fn replacement_and_cancellation_drop_task_wakers_outside_queue_lock() {
    let count = AtomicUsize::new(1);
    let queue = Arc::new(Mutex::new(VecDeque::new()));
    let callbacks = Arc::new(AtomicUsize::new(0));
    let mut admission = FallbackAdmission::new(&count, 1, &queue);
    let first = reentrant_waker(&queue, &callbacks);
    assert!(poll(&mut admission, &first).is_pending());
    drop(first);
    let second = reentrant_waker(&queue, &callbacks);
    assert!(poll(&mut admission, &second).is_pending());
    assert_eq!(callbacks.load(Ordering::SeqCst), 1);
    drop(second);
    drop(admission);
    assert_eq!(callbacks.load(Ordering::SeqCst), 2);
    assert!(queue.lock().is_empty());
}

#[test]
fn release_invokes_task_waker_outside_queue_lock() {
    let count = AtomicUsize::new(1);
    let queue = Arc::new(Mutex::new(VecDeque::new()));
    let callbacks = Arc::new(AtomicUsize::new(0));
    let mut admission = FallbackAdmission::new(&count, 1, &queue);
    let waker = reentrant_waker(&queue, &callbacks);
    assert!(poll(&mut admission, &waker).is_pending());
    drop(waker);
    release_fallback_slot(&count, &queue);
    assert_eq!(callbacks.load(Ordering::SeqCst), 2);
    assert!(poll(&mut admission, Waker::noop()).is_ready());
    assert!(queue.lock().is_empty());
}
