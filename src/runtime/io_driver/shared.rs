//! One dispatcher per caller-supplied reactor allocation (8ynh18).
//!
//! The registry owns neither a reactor nor a live driver. It retains only weak
//! identities and vacant token generations, so sharing grants no new I/O
//! authority and cannot keep a runtime alive. Lookup is construction-only;
//! registration, polling and wakeup do not consult a process-wide lock.

use super::*;
use parking_lot::Condvar;
use std::sync::OnceLock;

static REACTORS: OnceLock<Mutex<Vec<Arc<ReactorSlot>>>> = OnceLock::new();

struct ReactorSlot {
    reactor: Weak<dyn Reactor>,
    state: Mutex<SlotState>,
    retired: Condvar,
}

enum SlotState {
    // No wakers may remain here. Keep generations across driver incarnations:
    // delayed backend events and cleanup from an older driver must not name a
    // newly registered source, even when the caller retains the same reactor.
    Vacant(TokenSlab),
    Live(Weak<DriverOwner>),
}

/// Lifetime shared by independently constructed handles of the same reactor.
/// The handle's ordinary fields preserve its existing hot paths and lock API.
pub(super) struct DriverOwner {
    inner: Arc<Mutex<IoDriver>>,
    reactor: Arc<dyn Reactor>,
    capabilities: IoReactorCapabilitySnapshot,
    is_polling: Arc<AtomicBool>,
    slot: Arc<ReactorSlot>,
}

pub(super) fn handle(reactor: Arc<dyn Reactor>, capacity: Option<usize>) -> IoDriverHandle {
    // A backend hook may run user code: do not call it under registry/slot locks.
    let capabilities = reactor.capability_snapshot();
    let identity = Arc::downgrade(&reactor);
    let slot = {
        let mut slots = REACTORS.get_or_init(|| Mutex::new(Vec::new())).lock();
        // Dead slots contain only vacant storage and weak references. In
        // particular, removing one here cannot run a user's waker destructor.
        slots.retain(|slot| slot.reactor.strong_count() != 0);
        if let Some(slot) = slots.iter().find(|slot| slot.reactor.ptr_eq(&identity)) {
            Arc::clone(slot)
        } else {
            let slot = Arc::new(ReactorSlot {
                reactor: identity,
                state: Mutex::new(SlotState::Vacant(TokenSlab::new())),
                retired: Condvar::new(),
            });
            slots.push(Arc::clone(&slot));
            slot
        }
    };

    let owner = {
        let mut state = slot.state.lock();
        loop {
            match &mut *state {
                SlotState::Vacant(slab) => {
                    // Allocate before taking the saved slab: a rejected
                    // capacity must not erase its generations during unwind.
                    let mut driver = match capacity {
                        Some(capacity) => IoDriver::with_capacity(reactor.clone(), capacity),
                        None => IoDriver::new(reactor.clone()),
                    };
                    driver.wakers = std::mem::take(slab);
                    let owner = Arc::new(DriverOwner {
                        inner: Arc::new(Mutex::new(driver)),
                        reactor: reactor.clone(),
                        capabilities,
                        is_polling: Arc::new(AtomicBool::new(false)),
                        slot: Arc::clone(&slot),
                    });
                    *state = SlotState::Live(Arc::downgrade(&owner));
                    break owner;
                }
                SlotState::Live(live) => {
                    if let Some(owner) = live.upgrade() {
                        break owner;
                    }
                    // The last Arc can be gone before its destructor starts.
                    // Do not reset the token namespace in that window. Drop
                    // publishes the vacant slab before invoking backend hooks
                    // or destroying wakers, then releases this waiter.
                    slot.retired.wait(&mut state);
                }
            }
        }
    };

    IoDriverHandle {
        inner: Arc::clone(&owner.inner),
        reactor: Arc::clone(&owner.reactor),
        capabilities: owner.capabilities,
        is_polling: Arc::clone(&owner.is_polling),
        _shared_owner: owner,
    }
}

impl Drop for DriverOwner {
    fn drop(&mut self) {
        let (vacant, tokens, mut wakers) = {
            let mut driver = self.inner.lock();
            let mut vacant = std::mem::take(&mut driver.wakers);
            let tokens: Vec<_> = vacant.iter().map(|(token, _)| token).collect();
            let mut wakers = std::mem::take(&mut driver.waker_buf);
            for &token in &tokens {
                if let Some(waker) = vacant.remove(token) {
                    wakers.push(waker);
                }
            }
            driver.interests.clear();
            driver.undispatched.clear();
            (vacant, tokens, wakers)
        };
        debug_assert!(vacant.is_empty());
        {
            let mut state = self.slot.state.lock();
            *state = SlotState::Vacant(vacant);
        }
        self.slot.retired.notify_all();

        // The new incarnation may now start, but it cannot reuse any of these
        // tokens: remove(), not clear(), advanced each occupied generation and
        // preserved permanently retired slots. No user code runs under the
        // registry, slot or driver mutex. A backend/waker destructor can even
        // construct a fresh handle for this reactor without deadlocking.
        let mut first_panic = None;
        for token in tokens {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for _ in 0..2 {
                    let _ = self.reactor.wake();
                    match self.reactor.deregister(Token::new(token.to_usize())) {
                        Ok(()) => break,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                        Err(_) => {}
                    }
                }
            }));
            if let Err(payload) = result {
                first_panic.get_or_insert(payload);
            }
        }
        for waker in wakers.drain(..) {
            if let Err(payload) =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(waker)))
            {
                first_panic.get_or_insert(payload);
            }
        }
        if let Some(payload) = first_panic {
            std::panic::resume_unwind(payload);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::runtime::reactor_model::{LabReactorModel, ReactorOperation};
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::AtomicUsize;
    use std::task::Wake;

    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn register(
        driver: &IoDriverHandle,
        source: &UnixStream,
    ) -> (IoRegistration, Arc<Counter>) {
        let counter = Arc::new(Counter::default());
        let registration = driver
            .register(source, Interest::READABLE, Waker::from(Arc::clone(&counter)))
            .expect("register source");
        (registration, counter)
    }

    #[test]
    fn independent_handles_dispatch_both_owners_without_token_collision() {
        let reactor = Arc::new(LabReactorModel::new());
        let first = IoDriverHandle::new(reactor.clone());
        let second = IoDriverHandle::with_capacity(reactor.clone(), 7);
        let (a, _peer_a) = UnixStream::pair().unwrap();
        let (b, _peer_b) = UnixStream::pair().unwrap();
        let (a, count_a) = register(&first, &a);
        let (b, count_b) = register(&second, &b);
        assert_ne!(a.token(), b.token());
        reactor.set_ready(a.token(), Interest::READABLE).unwrap();
        reactor.set_ready(b.token(), Interest::READABLE).unwrap();
        assert_eq!(second.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), 2);
        assert_eq!(count_a.0.load(Ordering::SeqCst), 1);
        assert_eq!(count_b.0.load(Ordering::SeqCst), 1);
        assert_eq!(first.stats().unknown_tokens, 0);
        drop(first);
        assert_eq!(second.waker_count(), 2);
        drop(a);
        assert_eq!(second.waker_count(), 1);
        drop(b);
        assert!(second.is_empty());
        assert_eq!(reactor.registration_count(), 0);
    }

    #[test]
    fn independent_handles_share_the_poll_leader_and_first_capacity() {
        let reactor = Arc::new(LabReactorModel::new());
        let first = IoDriverHandle::with_capacity(reactor.clone(), 17);
        let second = IoDriverHandle::with_capacity(reactor, 33);
        assert!(Arc::ptr_eq(&first.inner, &second.inner));
        assert!(Arc::ptr_eq(&first.is_polling, &second.is_polling));
        assert_eq!(second.lock().events.capacity(), 17);
        first.is_polling.store(true, Ordering::Release);
        assert_eq!(second.try_turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), None);
        first.is_polling.store(false, Ordering::Release);
        assert_eq!(second.try_turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), Some(0));
    }

    #[test]
    fn distinct_reactors_keep_separate_namespaces_and_driver_state() {
        let a = IoDriverHandle::new(Arc::new(LabReactorModel::new()));
        let b = IoDriverHandle::new(Arc::new(LabReactorModel::new()));
        assert!(!Arc::ptr_eq(&a.inner, &b.inner));
        assert!(!Arc::ptr_eq(&a.is_polling, &b.is_polling));
        let (source, _peer) = UnixStream::pair().unwrap();
        let (ra, _) = register(&a, &source);
        let (rb, _) = register(&b, &source);
        assert_eq!(ra.token(), rb.token(), "fresh independent reactors retain deterministic tokens");
    }

    #[test]
    fn retired_driver_cleans_registrations_and_never_reissues_old_tokens() {
        let reactor = Arc::new(LabReactorModel::new());
        let first = IoDriverHandle::new(reactor.clone());
        let (source, _peer) = UnixStream::pair().unwrap();
        let (old, old_count) = register(&first, &source);
        let old_token = old.token();
        let weak = Arc::downgrade(&first.inner);
        drop(first);
        assert!(weak.upgrade().is_none());
        assert_eq!(reactor.registration_count(), 0);
        let second = IoDriverHandle::new(reactor.clone());
        let (fresh, fresh_count) = register(&second, &source);
        assert_ne!(old_token, fresh.token());
        drop(old); // Its obsolete Weak must not deregister the new incarnation.
        assert_eq!(reactor.registration_count(), 1);
        reactor.set_ready(fresh.token(), Interest::READABLE).unwrap();
        second.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap();
        assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
        assert_eq!(fresh_count.0.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_retirement_cleanup_cannot_alias_the_next_driver() {
        let reactor = Arc::new(LabReactorModel::new());
        let first = IoDriverHandle::new(reactor.clone());
        let (old_source, _old_peer) = UnixStream::pair().unwrap();
        let (source, _peer) = UnixStream::pair().unwrap();
        let (old, old_count) = register(&first, &old_source);
        let token = old.token();
        for _ in 0..2 {
            reactor.fail_next(ReactorOperation::Deregister, Some(token), io::ErrorKind::Other).unwrap();
        }
        drop(first);
        assert_eq!(reactor.registration_count(), 1, "injected cleanup failure retained the old backend token");
        let second = IoDriverHandle::new(reactor.clone());
        let (fresh, fresh_count) = register(&second, &source);
        assert_ne!(fresh.token(), token);
        reactor.set_ready(token, Interest::READABLE).unwrap();
        reactor.set_ready(fresh.token(), Interest::READABLE).unwrap();
        second.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap();
        assert_eq!(old_count.0.load(Ordering::SeqCst), 0);
        assert_eq!(fresh_count.0.load(Ordering::SeqCst), 1);
        assert_eq!(second.stats().unknown_tokens, 1);
        reactor.deregister(token).unwrap();
        drop(old);
        drop(fresh);
        assert_eq!(reactor.registration_count(), 0);
    }

    #[test]
    fn registry_does_not_keep_a_reactor_or_waker_alive() {
        let reactor = Arc::new(LabReactorModel::new());
        let reactor_weak = Arc::downgrade(&reactor);
        let driver = IoDriverHandle::new(reactor);
        let (source, _peer) = UnixStream::pair().unwrap();
        let (registration, counter) = register(&driver, &source);
        let counter_weak = Arc::downgrade(&counter);
        drop(counter);
        drop(driver);
        assert!(counter_weak.upgrade().is_none());
        // The registration itself still explicitly owns a reactor Arc.
        drop(registration);
        assert!(reactor_weak.upgrade().is_none());
    }

    #[test]
    fn concurrent_constructors_choose_one_driver() {
        let reactor: Arc<dyn Reactor> = Arc::new(LabReactorModel::new());
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let reactor = Arc::clone(&reactor);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                IoDriverHandle::new(reactor)
            }));
        }
        let handles: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        for handle in &handles[1..] {
            assert!(Arc::ptr_eq(&handles[0].inner, &handle.inner));
            assert!(Arc::ptr_eq(&handles[0].is_polling, &handle.is_polling));
        }
    }
}
