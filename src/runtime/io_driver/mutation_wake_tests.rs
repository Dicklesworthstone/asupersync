//! Regression coverage for br-asupersync-8ynh18's driver/ring lock inversion.
//!
//! The final backend wake must happen after the driver gate is acquired:
//! otherwise a poller can consume the wake and start another blocking ring wait
//! while the mutator is still waiting for that gate. Each retry must establish
//! the same ordering again. The single-threaded probes observe the gate at the
//! exact wake call. Threaded probes additionally cover the public locked-turn
//! path, which needs a preliminary wake when the driver gate is contended.
//! These tests exercise production entry points, not a native io_uring kernel.

use super::*;
use crate::runtime::reactor::{IoUringCapabilityPolicy, LabReactor};
use std::os::unix::net::UnixStream;
use std::sync::OnceLock;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

struct PollWait {
    entered: mpsc::Sender<()>,
    released: Mutex<bool>,
    changed: parking_lot::Condvar,
}

impl PollWait {
    fn wait(&self) {
        let mut released = self.released.lock();
        let _ = self.entered.send(());
        while !*released {
            self.changed.wait(&mut released);
        }
    }

    fn release(&self) {
        *self.released.lock() = true;
        self.changed.notify_all();
    }
}

struct GateProbeReactor {
    inner: LabReactor,
    driver: OnceLock<Weak<Mutex<IoDriver>>>,
    guarded_wakes: Mutex<Vec<bool>>,
    deregister_failures: AtomicUsize,
    backend: IoReactorBackend,
    poll_wait: Mutex<Option<Arc<PollWait>>>,
    // Wakes still to drop unseen, as another poller consuming them would.
    swallowed_wakes: Mutex<usize>,
}

impl GateProbeReactor {
    fn new(backend: IoReactorBackend) -> Self {
        Self {
            inner: LabReactor::new(),
            driver: OnceLock::new(),
            guarded_wakes: Mutex::new(Vec::new()),
            deregister_failures: AtomicUsize::new(0),
            backend,
            poll_wait: Mutex::new(None),
            swallowed_wakes: Mutex::new(0),
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

    // `fetch_update` is deprecated on the pinned nightly and absent from the
    // stable subset (see `database::sqlite`), hence the allow.
    #[allow(deprecated)]
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
        let wait = self.poll_wait.lock().clone();
        if let Some(wait) = wait {
            wait.wait();
            self.inner.poll(events, Some(Duration::ZERO))
        } else {
            self.inner.poll(events, timeout)
        }
    }

    fn wake(&self) -> io::Result<()> {
        {
            let mut swallowed = self.swallowed_wakes.lock();
            if *swallowed > 0 {
                *swallowed -= 1;
                return Ok(());
            }
        }
        let guarded = self
            .driver
            .get()
            .and_then(Weak::upgrade)
            .is_some_and(|driver| driver.try_lock().is_none());
        self.guarded_wakes.lock().push(guarded);
        let wait = self.poll_wait.lock().clone();
        if let Some(wait) = wait {
            wait.release();
        }
        self.inner.wake()
    }

    fn registration_count(&self) -> usize {
        self.inner.registration_count()
    }
}

fn fixture(
    backend: IoReactorBackend,
) -> (IoDriverHandle, Arc<GateProbeReactor>, UnixStream, UnixStream) {
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
    let _ = reactor.take_wakes();
    registration.set_interest(Interest::WRITABLE).unwrap();
    assert_eq!(reactor.take_wakes(), vec![true]);
    assert_eq!(registration.interest(), Interest::WRITABLE);
}

#[test]
fn both_cached_and_uncached_rearms_wake_inside_the_driver_gate() {
    let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
    let mut registration = register(&driver, &source);
    let _ = reactor.take_wakes();
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
    let _ = reactor.take_wakes();
    assert!(
        registration
            .rearm_accumulating(Interest::WRITABLE, Waker::noop())
            .unwrap()
    );
    assert_eq!(reactor.take_wakes(), vec![true]);
    assert_eq!(
        registration.interest(),
        Interest::READABLE | Interest::WRITABLE
    );
}

#[test]
fn every_explicit_deregistration_and_drop_retry_gets_its_own_guarded_wake() {
    // With two or three injected failures, the explicit call fails and its
    // armed Drop performs the remaining attempts. A wake before just the first
    // attempt is insufficient: each attempt releases the driver gate.
    for failures in 0..=3 {
        let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
        let registration = register(&driver, &source);
        let _ = reactor.take_wakes();
        reactor.deregister_failures.store(failures, Ordering::SeqCst);
        let result = registration.deregister();
        assert_eq!(result.is_ok(), failures < 2, "failures={failures}");
        assert_eq!(
            reactor.take_wakes(),
            vec![true; failures + 1],
            "failures={failures}"
        );
        assert!(driver.is_empty());
        assert_eq!(reactor.registration_count(), 0);
    }
}

#[test]
fn drop_and_its_retry_wake_inside_the_driver_gate() {
    for failures in 0..=1 {
        let (driver, reactor, source, _peer) = fixture(IoReactorBackend::Injected);
        let registration = register(&driver, &source);
        let _ = reactor.take_wakes();
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
    assert!(
        registration
            .rearm_accumulating(Interest::READABLE, Waker::noop())
            .unwrap()
    );
    assert!(reactor.take_wakes().is_empty());
    registration.deregister().unwrap();
    assert_eq!(reactor.take_wakes(), vec![true]);
    assert!(driver.is_empty());
}

/// Enter the actual public locked-turn API before starting a mutation on
/// another thread. No sleep guesses the race: the backend signals that the
/// driver gate is held in poll. A watchdog rescue always releases and joins
/// both workers before assertions, so removing the pre-lock wake fails rather
/// than hanging the test process. The normal handle-turn gate ordering is
/// independently asserted above; dropping the under-gate wake fails those.
fn mutation_interrupts_locked_turn(
    backend: IoReactorBackend,
    operation: impl FnOnce(IoRegistration, &IoDriverHandle, &UnixStream) -> io::Result<()> + Send,
) {
    mutation_interrupts_locked_turn_after_lost_wakes(backend, 0, operation);
}

/// [`mutation_interrupts_locked_turn`], with the first `lost_wakes` wakes
/// consumed unseen once the locked turn is waiting.
fn mutation_interrupts_locked_turn_after_lost_wakes(
    backend: IoReactorBackend,
    lost_wakes: usize,
    operation: impl FnOnce(IoRegistration, &IoDriverHandle, &UnixStream) -> io::Result<()> + Send,
) {
    let (driver, reactor, source, _peer) = fixture(backend);
    let registration = register(&driver, &source);
    let (entered_tx, entered_rx) = mpsc::channel();
    let wait = Arc::new(PollWait {
        entered: entered_tx,
        released: Mutex::new(false),
        changed: parking_lot::Condvar::new(),
    });
    *reactor.poll_wait.lock() = Some(Arc::clone(&wait));
    let (done_tx, done_rx) = mpsc::channel();
    let watchdog = Duration::from_secs(10);

    std::thread::scope(|scope| {
        let polling = scope.spawn(|| driver.lock().turn(None));
        let entered = entered_rx.recv_timeout(watchdog);
        *reactor.swallowed_wakes.lock() = lost_wakes;
        let driver_ref = &driver;
        let source_ref = &source;
        let mutation = scope.spawn(move || {
            let result = operation(registration, driver_ref, source_ref);
            let _ = done_tx.send(result.is_ok());
            result
        });
        let progressed = done_rx.recv_timeout(watchdog);

        // This is rescue, not the wake whose progress is asserted: the result
        // above must already have arrived. Also rescue delayed startup, then
        // join both workers before any panic can leave the backend blocked.
        wait.release();
        let poll_result = polling.join();
        let mutation_result = mutation.join();
        assert!(entered.is_ok(), "poller did not enter: {entered:?}");
        assert!(
            matches!(progressed, Ok(true)),
            "{backend:?}: mutation needed watchdog rescue: {progressed:?}"
        );
        assert!(poll_result.expect("poll thread panicked").is_ok());
        assert!(mutation_result.expect("mutation thread panicked").is_ok());
    });
    assert!(driver.is_empty());
    assert_eq!(reactor.registration_count(), 0);
}

/// r14 F1 item 1: another poller, such as the scheduler leader, can consume
/// lock_for_mutation's preliminary wake before a public locked turn starts to
/// wait. With a single wake, the mutator then blocked for that turn's whole
/// wait, here forever. It now wakes again until it holds the driver gate.
#[test]
fn a_consumed_preliminary_wake_is_repeated_until_the_mutation_gets_the_gate() {
    for backend in [IoReactorBackend::Injected, IoReactorBackend::Epoll] {
        mutation_interrupts_locked_turn_after_lost_wakes(backend, 3, |old, driver, source| {
            let new = driver.register(source, Interest::READABLE, Waker::noop().clone())?;
            drop(new);
            drop(old);
            Ok(())
        });
    }
}

#[test]
fn registration_interrupts_a_turn_holding_the_public_driver_guard() {
    for backend in [IoReactorBackend::Injected, IoReactorBackend::Epoll] {
        mutation_interrupts_locked_turn(backend, |old, driver, source| {
            let new = driver.register(source, Interest::READABLE, Waker::noop().clone())?;
            drop(new);
            drop(old);
            Ok(())
        });
    }
}

#[test]
fn interest_change_interrupts_a_turn_holding_the_public_driver_guard() {
    for backend in [IoReactorBackend::Injected, IoReactorBackend::Epoll] {
        mutation_interrupts_locked_turn(backend, |mut registration, _, _| {
            registration.set_interest(Interest::WRITABLE)
        });
    }
}

#[test]
fn rearm_interrupts_a_turn_holding_the_public_driver_guard() {
    for backend in [IoReactorBackend::Injected, IoReactorBackend::Epoll] {
        mutation_interrupts_locked_turn(backend, |mut registration, _, _| {
            assert!(registration.rearm(Interest::WRITABLE, Waker::noop())?);
            Ok(())
        });
    }
}

#[test]
fn accumulating_rearm_interrupts_a_turn_holding_the_public_driver_guard() {
    for backend in [IoReactorBackend::Injected, IoReactorBackend::Epoll] {
        mutation_interrupts_locked_turn(backend, |mut registration, _, _| {
            assert!(registration.rearm_accumulating(Interest::WRITABLE, Waker::noop())?);
            Ok(())
        });
    }
}

#[test]
fn deregistration_interrupts_a_turn_holding_the_public_driver_guard() {
    for backend in [IoReactorBackend::Injected, IoReactorBackend::Epoll] {
        mutation_interrupts_locked_turn(backend, |registration, _, _| registration.deregister());
    }
}

#[test]
fn drop_interrupts_a_turn_holding_the_public_driver_guard() {
    for backend in [IoReactorBackend::Injected, IoReactorBackend::Epoll] {
        mutation_interrupts_locked_turn(backend, |registration, _, _| {
            drop(registration);
            Ok(())
        });
    }
}
