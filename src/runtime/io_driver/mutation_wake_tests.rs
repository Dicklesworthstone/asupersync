//! Regression coverage for br-asupersync-8ynh18's driver/ring lock inversion.
//!
//! A backend wake must happen after the driver gate is acquired, not before it:
//! otherwise a poller can consume the wake and start another blocking ring wait
//! while the mutator is still waiting for that gate. Each retry must establish
//! the same ordering again. These probes exercise the production entry points
//! and observe the gate at the instant the backend is woken. They do not claim
//! to execute a native io_uring kernel wait.

use super::*;
use crate::runtime::reactor::{IoUringCapabilityPolicy, LabReactor};
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;

struct GateProbeReactor {
    inner: LabReactor,
    driver: OnceLock<Weak<Mutex<IoDriver>>>,
    guarded_wakes: Mutex<Vec<bool>>,
    deregister_failures: AtomicUsize,
    backend: IoReactorBackend,
}

impl GateProbeReactor {
    fn new(backend: IoReactorBackend) -> Self {
        Self {
            inner: LabReactor::new(),
            driver: OnceLock::new(),
            guarded_wakes: Mutex::new(Vec::new()),
            deregister_failures: AtomicUsize::new(0),
            backend,
        }
    }

    fn take_wakes(&self) -> Vec<bool> {
        std::mem::take(&mut *self.guarded_wakes.lock())
    }
}

impl Reactor for GateProbeReactor {
    fn capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
        IoReactorCapabilitySnapshot::from_policy(
            self.backend,
            None,
            IoUringCapabilityPolicy::default(),
            [None, None, None, None, None, None],
        )
    }

    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.register(source, token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        if self
            .deregister_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(io::Error::other("injected deregistration failure"));
        }
        self.inner.deregister(token)
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        self.inner.poll(events, timeout)
    }

    fn wake(&self) -> io::Result<()> {
        let guarded = self
            .driver
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|driver| driver.try_lock().is_none());
        self.guarded_wakes.lock().push(guarded);
        self.inner.wake()
    }

    fn registration_count(&self) -> usize {
        self.inner.registration_count()
    }
}

fn fixture(backend: IoReactorBackend) -> (IoDriverHandle, Arc<GateProbeReactor>, UnixStream, UnixStream) {
    let reactor = Arc::new(GateProbeReactor::new(backend));
    let driver = IoDriverHandle::new(reactor.clone());
    assert!(reactor.driver.set(Arc::downgrade(&driver.inner)).is_ok());
    let (source, peer) = UnixStream::pair().expect("socket pair");
    (driver, reactor, source, peer)
}

fn register(driver: &IoDriverHandle, source: &UnixStream) -> IoRegistration {
    driver
        .register(source, Interest::READABLE, Waker::noop().clone())
        .expect("register source")
}

#[test]
fn registration_wake_is_inside_the_driver_gate() {
    let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
    let registration = register(&driver, &source);
    assert_eq!(reactor.take_wakes(), vec![true]);
    assert_eq!(driver.waker_count(), 1);
    drop(registration);
    assert_eq!(driver.waker_count(), 0);
}

#[test]
fn interest_change_wake_is_inside_the_driver_gate() {
    let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
    let mut registration = register(&driver, &source);
    reactor.take_wakes();
    registration.set_interest(Interest::WRITABLE).unwrap();
    assert_eq!(reactor.take_wakes(), vec![true]);
    assert_eq!(registration.interest(), Interest::WRITABLE);
}

#[test]
fn both_cached_and_uncached_rearms_wake_inside_the_driver_gate() {
    let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
    let mut registration = register(&driver, &source);
    reactor.take_wakes();
    let waker = Waker::noop();
    assert!(registration.rearm(Interest::READABLE, waker).unwrap());
    assert!(registration.rearm(Interest::WRITABLE, waker).unwrap());
    assert_eq!(reactor.take_wakes(), vec![true, true]);
    assert_eq!(registration.interest(), Interest::WRITABLE);
}

#[test]
fn accumulating_rearms_keep_the_gate_and_the_interest_union() {
    let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
    let mut registration = register(&driver, &source);
    reactor.take_wakes();
    assert!(registration.rearm_accumulating(Interest::WRITABLE, Waker::noop()).unwrap());
    assert_eq!(reactor.take_wakes(), vec![true]);
    assert_eq!(registration.interest(), Interest::READABLE | Interest::WRITABLE);
}

#[test]
fn every_explicit_deregistration_and_drop_retry_gets_its_own_guarded_wake() {
    // With two or three injected failures, the explicit call fails and its
    // armed Drop performs the remaining attempts. A wake before just the first
    // attempt is insufficient: each attempt releases the driver gate.
    for failures in 0..=3 {
        let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
        let registration = register(&driver, &source);
        reactor.take_wakes();
        reactor.deregister_failures.store(failures, Ordering::SeqCst);
        let result = registration.deregister();
        assert_eq!(result.is_ok(), failures < 2, "failures={failures}");
        assert_eq!(reactor.take_wakes(), vec![true; failures + 1], "failures={failures}");
        assert!(driver.is_empty());
        assert_eq!(reactor.registration_count(), 0);
    }
}

#[test]
fn drop_and_its_retry_wake_inside_the_driver_gate() {
    for failures in 0..=1 {
        let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
        let registration = register(&driver, &source);
        reactor.take_wakes();
        reactor.deregister_failures.store(failures, Ordering::SeqCst);
        drop(registration);
        assert_eq!(reactor.take_wakes(), vec![true; failures + 1]);
        assert!(driver.is_empty());
        assert_eq!(reactor.registration_count(), 0);
    }
}

#[test]
fn epoll_keeps_its_no_wake_interest_fast_path() {
    let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Epoll);
    let mut registration = register(&driver, &source);
    assert_eq!(reactor.take_wakes(), vec![true]);
    registration.set_interest(Interest::READABLE).unwrap();
    assert!(registration.rearm(Interest::WRITABLE, Waker::noop()).unwrap());
    assert!(registration.rearm_accumulating(Interest::READABLE, Waker::noop()).unwrap());
    assert!(reactor.take_wakes().is_empty());
    registration.deregister().unwrap();
    assert_eq!(reactor.take_wakes(), vec![true]);
    assert!(driver.is_empty());
}
