//! One dispatcher per caller-supplied reactor allocation (8ynh18).
//!
//! The registry owns neither a reactor nor a live driver. It retains only weak
//! identities and vacant token generations, so sharing grants no new I/O
//! authority and cannot keep a runtime alive. Lookup is construction-only;
//! registration, polling and wakeup do not consult a process-wide lock.
//!
//! Constructor groups retain separate leader flags (clones keep their group's
//! flag). A scheduler follower assumes its own timer wheel is driven by that
//! leader, which is false for another runtime. A shared physical poll gate
//! serializes backend polls; another group's turn waits only within its own
//! timeout instead of returning the local-follower `None` result.

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
    poll_gate: Arc<Mutex<()>>,
    events_capacity: usize,
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
                    let events_capacity = driver.events.capacity();
                    let owner = Arc::new(DriverOwner {
                        inner: Arc::new(Mutex::new(driver)),
                        reactor: reactor.clone(),
                        capabilities,
                        poll_gate: Arc::new(Mutex::new(())),
                        events_capacity,
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
                    // finishes backend cleanup, then publishes the vacant
                    // slab before destroying wakers and releases this waiter.
                    slot.retired.wait(&mut state);
                }
            }
        }
    };

    IoDriverHandle {
        inner: Arc::clone(&owner.inner),
        reactor: Arc::new(ParticipantReactor {
            backend: Arc::clone(&owner.reactor),
            driver: Arc::downgrade(&owner.inner),
            poll_gate: Arc::clone(&owner.poll_gate),
            events_capacity: owner.events_capacity,
            woken: AtomicBool::new(false),
        }),
        capabilities: owner.capabilities,
        is_polling: Arc::new(AtomicBool::new(false)),
        _shared_owner: owner,
    }
}

/// One runtime's polling participant. Registrations may retain this transport
/// adapter without retaining the dispatcher or any task wakers.
struct ParticipantReactor {
    backend: Arc<dyn Reactor>,
    driver: Weak<Mutex<IoDriver>>,
    poll_gate: Arc<Mutex<()>>,
    events_capacity: usize,
    // A peer can consume the physical eventfd/pipe wake while this participant
    // waits for the poll gate. Retain the logical wake until our own turn.
    woken: AtomicBool,
}

impl Reactor for ParticipantReactor {
    fn capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
        self.backend.capability_snapshot()
    }

    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        self.backend.register(source, token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.backend.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        self.backend.deregister(token)
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        events.clear();
        let (poll_guard, timeout) = if let Some(guard) = self.poll_gate.try_lock() {
            (guard, timeout)
        } else {
            // Browser turns must never block. Native contenders spend only
            // their own timeout, not the current poller's possibly longer one.
            #[cfg(target_arch = "wasm32")]
            return Ok(0);
            #[cfg(not(target_arch = "wasm32"))]
            match timeout {
                Some(timeout) => {
                    let start = std::time::Instant::now();
                    let Some(guard) = self.poll_gate.try_lock_for(timeout) else {
                        return Ok(0);
                    };
                    (guard, Some(timeout.saturating_sub(start.elapsed())))
                }
                None => (self.poll_gate.lock(), None),
            }
        };

        // A preceding poll can release its ring before its driver extraction
        // runs. Before another backend wait starts, cross the same driver gate
        // used by mutations: otherwise it could consume a mutator's wake and
        // re-enter the ring while that mutator holds the gate waiting for it.
        // The preliminary wake also releases an explicitly locked direct turn.
        if let Some(driver) = self.driver.upgrade() {
            drop(lock_for_mutation(&driver, self.backend.as_ref()));
        }
        // Concurrent participants can temporarily own the usual scratch
        // buffer. Give the empty replacement the dispatcher's capacity rather
        // than passing a zero-sized batch to a backend that honors the hint.
        if events.capacity() == 0 && self.events_capacity != 0 {
            *events = Events::with_capacity(self.events_capacity);
        }
        let timeout = if self.woken.swap(false, Ordering::AcqRel) {
            Some(Duration::ZERO)
        } else {
            timeout
        };
        let result = self.backend.poll(events, timeout);
        drop(poll_guard);
        result
    }

    fn wake(&self) -> io::Result<()> {
        self.woken.store(true, Ordering::Release);
        self.backend.wake()
    }

    fn registration_count(&self) -> usize {
        self.backend.registration_count()
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
        // Keep constructors waiting until backend cleanup finishes. Publishing
        // first would let a new driver's poll consume a cleanup wake and block
        // in io_uring again before deregister acquires the ring. There are no
        // live handle polls now, so cleanup needs no wake. Backend calls run
        // outside registry, slot and driver mutexes. As with ordinary backend
        // mutations, they must not recursively construct the same dispatcher.
        let mut first_panic = None;
        for token in tokens {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for _ in 0..2 {
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
        {
            let mut state = self.slot.state.lock();
            *state = SlotState::Vacant(vacant);
        }
        self.slot.retired.notify_all();

        // remove(), not clear(), advanced each occupied generation and kept
        // permanently retired slots. Delayed events still cannot alias the new
        // driver even after cleanup failures. Publish before dropping wakers:
        // their destructors may re-enter the constructor without deadlocking.
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
    fn independent_handles_share_physical_poll_ownership_and_first_capacity() {
        let reactor = Arc::new(LabReactorModel::new());
        let first = IoDriverHandle::with_capacity(reactor.clone(), 17);
        let second = IoDriverHandle::with_capacity(reactor, 33);
        assert!(Arc::ptr_eq(&first.inner, &second.inner));
        assert!(Arc::ptr_eq(
            &first._shared_owner.poll_gate,
            &second._shared_owner.poll_gate
        ));
        assert!(!Arc::ptr_eq(&first.is_polling, &second.is_polling));
        let cloned = first.clone();
        assert!(Arc::ptr_eq(&first.is_polling, &cloned.is_polling));
        assert_eq!(second.lock().events.capacity(), 17);
        first.is_polling.store(true, Ordering::Release);
        let held_poll = first._shared_owner.poll_gate.lock();
        assert_eq!(cloned.try_turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), None);
        assert_eq!(second.try_turn_with(Some(Duration::ZERO), |_, _| {}).unwrap(), Some(0));
        drop(held_poll);
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
            assert!(Arc::ptr_eq(
                &handles[0]._shared_owner.poll_gate,
                &handle._shared_owner.poll_gate
            ));
        }
    }

    struct RetirementProbe {
        backend: LabReactorModel,
        slot: OnceLock<Weak<ReactorSlot>>,
        calls: AtomicUsize,
        published_early: AtomicBool,
        panic_next: AtomicBool,
    }

    impl Reactor for RetirementProbe {
        fn register(
            &self,
            source: &dyn Source,
            token: Token,
            interest: Interest,
        ) -> io::Result<()> {
            self.backend.register(source, token, interest)
        }

        fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
            self.backend.modify(token, interest)
        }

        fn deregister(&self, token: Token) -> io::Result<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let slot = self.slot.get().and_then(Weak::upgrade).unwrap();
            if matches!(*slot.state.lock(), SlotState::Vacant(_)) {
                self.published_early.store(true, Ordering::SeqCst);
            }
            let result = self.backend.deregister(token);
            if self.panic_next.swap(false, Ordering::SeqCst) {
                panic!("injected retirement callback panic");
            }
            result
        }

        fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
            self.backend.poll(events, timeout)
        }

        fn wake(&self) -> io::Result<()> {
            self.backend.wake()
        }

        fn registration_count(&self) -> usize {
            self.backend.registration_count()
        }
    }

    fn retirement_probe() -> (Arc<RetirementProbe>, IoDriverHandle) {
        let backend = Arc::new(RetirementProbe {
            backend: LabReactorModel::new(),
            slot: OnceLock::new(),
            calls: AtomicUsize::new(0),
            published_early: AtomicBool::new(false),
            panic_next: AtomicBool::new(false),
        });
        let driver = IoDriverHandle::new(backend.clone());
        assert!(backend
            .slot
            .set(Arc::downgrade(&driver._shared_owner.slot))
            .is_ok());
        (backend, driver)
    }

    #[test]
    fn retirement_finishes_all_backend_cleanup_before_publishing_the_namespace() {
        for panic in [false, true] {
            let (backend, driver) = retirement_probe();
            let (source_a, _peer_a) = UnixStream::pair().unwrap();
            let (source_b, _peer_b) = UnixStream::pair().unwrap();
            let (a, _) = register(&driver, &source_a);
            let (b, _) = register(&driver, &source_b);
            backend.panic_next.store(panic, Ordering::SeqCst);
            let retired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(driver);
            }));
            assert_eq!(retired.is_err(), panic);
            assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
            assert!(!backend.published_early.load(Ordering::SeqCst));
            assert_eq!(backend.registration_count(), 0);
            let next = IoDriverHandle::new(backend.clone());
            assert!(next.is_empty(), "a caught backend panic must not strand construction");
            drop(a);
            drop(b);
        }
    }

    struct ReenterOnDrop {
        backend: Arc<dyn Reactor>,
        replacement: Arc<Mutex<Option<IoDriverHandle>>>,
    }

    impl Wake for ReenterOnDrop {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for ReenterOnDrop {
        fn drop(&mut self) {
            let replacement = IoDriverHandle::new(Arc::clone(&self.backend));
            *self.replacement.lock() = Some(replacement);
        }
    }

    #[test]
    fn retiring_waker_destructor_can_construct_the_next_dispatcher() {
        let backend = Arc::new(LabReactorModel::new());
        let driver = IoDriverHandle::new(backend.clone());
        let replacement = Arc::new(Mutex::new(None));
        let (source, _peer) = UnixStream::pair().unwrap();
        let old = driver
            .register(
                &source,
                Interest::READABLE,
                Waker::from(Arc::new(ReenterOnDrop {
                    backend: backend.clone(),
                    replacement: Arc::clone(&replacement),
                })),
            )
            .unwrap();
        let token = old.token();
        drop(driver);
        let next = replacement.lock().take().expect("reentrant constructor completed");
        assert_eq!(backend.registration_count(), 0);
        let (fresh, _) = register(&next, &source);
        assert_ne!(fresh.token(), token);
        drop(old);
        assert_eq!(backend.registration_count(), 1);
        drop(fresh);
        drop(next);
        assert_eq!(backend.registration_count(), 0);
    }

    #[test]
    fn another_participants_poll_budget_is_not_a_local_follower_result() {
        let backend = Arc::new(LabReactorModel::new());
        let leader = IoDriverHandle::new(backend.clone());
        let participant = IoDriverHandle::new(backend);
        let gate = leader._shared_owner.poll_gate.lock();
        let (done, received) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let result = participant.try_turn_with(Some(Duration::from_millis(10)), |_, _| {});
            let _ = done.send(result);
        });
        // The competing physical turn stays claimed through the whole call.
        // It must return within its own budget, not wait for this guard or
        // tell its scheduler that a peer is processing its timer wheel.
        let result = received.recv_timeout(Duration::from_secs(5));
        drop(gate);
        thread.join().unwrap();
        assert_eq!(result.expect("own poll budget expired").unwrap(), Some(0));
    }

    #[test]
    fn a_peer_consuming_the_physical_wake_does_not_erase_the_owners_wake() {
        let backend = Arc::new(LabReactorModel::new());
        let peer = IoDriverHandle::new(backend.clone());
        let owner = IoDriverHandle::new(backend.clone());
        owner.wake().unwrap();
        peer.turn_with(Some(Duration::ZERO), |_, _| {}).unwrap();
        let before = backend.now();
        owner
            .turn_with(Some(Duration::from_secs(30)), |_, _| {})
            .unwrap();
        assert_eq!(backend.now(), before, "the owner's wake must keep its turn nonblocking");
        owner
            .turn_with(Some(Duration::from_secs(1)), |_, _| {})
            .unwrap();
        assert_eq!(backend.now(), before.saturating_add_nanos(1_000_000_000));
    }

    #[cfg(target_os = "linux")]
    mod native {
        use super::*;
        use crate::runtime::RuntimeBuilder;
        use crate::runtime::reactor::EpollReactor;
        use std::future::{Future, poll_fn};
        use std::io::{Read, Write};
        use std::pin::pin;
        use std::sync::mpsc;
        use std::task::Poll;

        const WATCHDOG: Duration = Duration::from_secs(5);

        struct Rescue {
            requested: AtomicBool,
            wakers: Mutex<[Option<Waker>; 2]>,
        }

        impl Rescue {
            fn release(&self) {
                self.requested.store(true, Ordering::Release);
                let wakers = self.wakers.lock().clone();
                for waker in wakers.into_iter().flatten() {
                    waker.wake();
                }
            }
        }

        async fn receive_one(
            index: usize,
            source: UnixStream,
            parked: mpsc::Sender<(usize, Token)>,
            timer_fired: mpsc::Sender<()>,
            rescue: Arc<Rescue>,
        ) -> io::Result<u8> {
            source.set_nonblocking(true)?;
            let cx = crate::Cx::current().expect("native runtime context");
            let driver = cx.io_driver_handle().expect("runtime I/O driver");
            let mut registration: Option<IoRegistration> = None;
            let mut parked_sent = false;
            let mut received = None;
            let mut timer_done = index == 0;
            let mut timer = pin!(crate::time::sleep(
                crate::time::wall_now(),
                Duration::from_millis(50),
            ));
            let result = poll_fn(|task_cx| {
                rescue.wakers.lock()[index] = Some(task_cx.waker().clone());
                if rescue.requested.load(Ordering::Acquire) {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "test watchdog rescue is not successful I/O",
                    )));
                }
                if !timer_done && timer.as_mut().poll(task_cx).is_ready() {
                    timer_done = true;
                    let _ = timer_fired.send(());
                }
                if received.is_none() {
                    let mut byte = [0_u8; 1];
                    match (&source).read(&mut byte) {
                        Ok(0) => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
                        Ok(_) => received = Some(byte[0]),
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            let armed = match registration.as_mut() {
                                Some(registration) => {
                                    registration.rearm(Interest::READABLE, task_cx.waker())
                                }
                                None => driver
                                    .register(
                                        &source,
                                        Interest::READABLE,
                                        task_cx.waker().clone(),
                                    )
                                    .map(|new| {
                                        registration = Some(new);
                                        true
                                    }),
                            };
                            match armed {
                                Ok(true) => {}
                                Ok(false) => return Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
                                Err(error) => return Poll::Ready(Err(error)),
                            }
                            if !parked_sent {
                                parked_sent = true;
                                let token = registration.as_ref().unwrap().token();
                                let _ = parked.send((index, token));
                            }
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
                }
                match received {
                    Some(byte) if timer_done => Poll::Ready(Ok(byte)),
                    _ => Poll::Pending,
                }
            })
            .await;
            drop(registration);
            result
        }

        fn cloned_builders_share_io_without_sharing_timer_or_shutdown_ownership(multi: bool) {
            let backend = Arc::new(EpollReactor::new().unwrap());
            let builder = if multi {
                RuntimeBuilder::new().worker_threads(2)
            } else {
                RuntimeBuilder::current_thread()
            }
            .with_reactor(backend.clone());
            let rescue = Arc::new(Rescue {
                requested: AtomicBool::new(false),
                wakers: Mutex::new([None, None]),
            });
            let (parked_tx, parked_rx) = mpsc::channel();
            let (done_tx, done_rx) = mpsc::channel();
            let (timer_tx, timer_rx) = mpsc::channel();
            let mut peers = Vec::new();
            let mut workers = Vec::new();
            for index in 0..2 {
                let (source, peer) = UnixStream::pair().unwrap();
                peers.push(peer);
                let builder = builder.clone();
                let rescue = Arc::clone(&rescue);
                let parked = parked_tx.clone();
                let done = done_tx.clone();
                let timer = timer_tx.clone();
                workers.push(std::thread::spawn(move || {
                    let result = match builder.build() {
                        Ok(runtime) => {
                            let result = runtime.block_on(receive_one(
                                index, source, parked, timer, rescue,
                            ));
                            // A's runtime is gone before B's byte is written.
                            drop(runtime);
                            result
                        }
                        Err(error) => Err(io::Error::other(error.to_string())),
                    };
                    let _ = done.send((index, result));
                }));
            }
            drop(parked_tx);
            drop(done_tx);
            drop(timer_tx);

            // A parked witness follows an actual WouldBlock and a successful
            // production registration, not a sleep or assumed scheduling order.
            let first_parked = parked_rx.recv_timeout(WATCHDOG);
            let second_parked = parked_rx.recv_timeout(WATCHDOG);
            let timer = timer_rx.recv_timeout(WATCHDOG);
            let sent_a = peers[0].write_all(b"A");
            let first_done = done_rx.recv_timeout(WATCHDOG);
            let sent_b = peers[1].write_all(b"B");
            let second_done = done_rx.recv_timeout(WATCHDOG);

            // Always rescue and join before asserting, even on old-code failure.
            // Rescue is excluded from the successful result oracle below.
            rescue.release();
            drop(peers);
            let joined: Vec<_> = workers.into_iter().map(|worker| worker.join()).collect();
            *rescue.wakers.lock() = [None, None];
            let first_parked = first_parked.expect("first runtime reached registered Pending");
            let second_parked = second_parked.expect("second runtime reached registered Pending");
            assert_ne!(first_parked.0, second_parked.0);
            assert_ne!(first_parked.1, second_parked.1, "shared wire tokens must not collide");
            timer.expect("B drives its own timer while A waits in the shared reactor");
            sent_a.unwrap();
            sent_b.unwrap();
            let (first_index, first_result) = first_done.expect("A completes and shuts down");
            let (second_index, second_result) = second_done.expect("B survives A's shutdown");
            assert_eq!((first_index, first_result.unwrap()), (0, b'A'));
            assert_eq!((second_index, second_result.unwrap()), (1, b'B'));
            assert!(joined.iter().all(Result::is_ok));
            assert_eq!(backend.registration_count(), 0);
        }

        #[test]
        fn cloned_current_thread_builders_keep_shared_io_and_independent_lifecycles_live() {
            cloned_builders_share_io_without_sharing_timer_or_shutdown_ownership(false);
        }

        #[test]
        fn cloned_multi_worker_builders_keep_shared_io_and_independent_lifecycles_live() {
            cloned_builders_share_io_without_sharing_timer_or_shutdown_ownership(true);
        }
    }
}
