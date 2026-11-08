//! Real readiness and ownership regressions for br-asupersync-olysw5.

use super::*;
use crate::runtime::reactor::{Events, Interest, Source, Token, create_reactor};
use crate::time::VirtualClock;
use crate::types::Time;
use std::net::UdpSocket;
use std::sync::mpsc;
use std::task::Wake;
use std::thread::ThreadId;

const WATCHDOG: Duration = Duration::from_secs(5);
const RESCUE: Duration = Duration::from_secs(30);

fn native_builder() -> RuntimeBuilder {
    RuntimeBuilder::new()
        .worker_threads(1)
        .blocking_threads(0, 0)
        .thread_name_prefix("background-io-test")
}

// Enter a single long Future::poll, rather than repeatedly yielding. Dropping
// the fixture releases the worker even when a readiness assertion fails.
struct HeldWorker {
    release: mpsc::Sender<()>,
    thread: ThreadId,
    _join: JoinHandle<()>,
}

impl HeldWorker {
    fn enter(runtime: &Runtime) -> Self {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let join = runtime.handle().spawn(async move {
            let _ = entered_tx.send(std::thread::current().id());
            let _ = release_rx.recv_timeout(RESCUE);
        });
        let thread = entered_rx
            .recv_timeout(WATCHDOG)
            .expect("sole worker entered the blocking poll");
        Self {
            release: release_tx,
            thread,
            _join: join,
        }
    }
}

impl Drop for HeldWorker {
    fn drop(&mut self) {
        let _ = self.release.send(());
    }
}

#[derive(Debug)]
struct WakeStamp {
    thread: ThreadId,
    name: Option<String>,
}

struct NoticeWake {
    sender: mpsc::Sender<WakeStamp>,
    panic: bool,
}

impl Wake for NoticeWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let thread = std::thread::current();
        let _ = self.sender.send(WakeStamp {
            thread: thread.id(),
            name: thread.name().map(str::to_owned),
        });
        assert!(!self.panic, "injected readiness Waker panic");
    }
}

fn notice_waker(panic: bool) -> (Waker, mpsc::Receiver<WakeStamp>) {
    let (sender, receiver) = mpsc::channel();
    (Waker::from(Arc::new(NoticeWake { sender, panic })), receiver)
}

fn assert_helper_wake(stamp: WakeStamp, worker: &HeldWorker) {
    assert_ne!(stamp.thread, worker.thread, "the sole worker is still held");
    assert_eq!(stamp.name.as_deref(), Some("background-io-test-io"));
}

fn runtime_drivers(runtime: &Runtime) -> (IoDriverHandle, TimerDriverHandle) {
    let state = runtime
        .inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (
        state.io_driver_handle().expect("installed I/O driver"),
        state.timer_driver_handle().expect("installed timer driver"),
    )
}

#[test]
fn background_io_is_opt_in_and_preserves_async_worker_count() {
    let ordinary = native_builder()
        .enable_platform_reactor(false)
        .build()
        .expect("ordinary runtime needs no reactor");
    assert_eq!(ordinary.inner.worker_threads.lock().len(), 1);
    assert!(ordinary.shutdown_timeout(WATCHDOG));

    let enabled = native_builder()
        .with_reactor(create_reactor().expect("platform reactor"))
        .background_io_driver(true)
        .build()
        .expect("runtime with independent I/O");
    assert_eq!(enabled.inner.config.worker_threads, 1);
    assert_eq!(enabled.inner.worker_threads.lock().len(), 2);
    assert!(enabled.shutdown_timeout(WATCHDOG));
}

#[test]
fn background_io_rejects_missing_driver_and_threadless_host() {
    let missing = native_builder()
        .enable_platform_reactor(false)
        .background_io_driver(true)
        .build()
        .err()
        .expect("an independent I/O driver needs a reactor");
    assert_eq!(missing.kind(), crate::error::ErrorKind::ConfigError);

    let threadless = native_builder()
        .browser_host_services(Arc::new(BrowserHostServices::new()))
        .background_io_driver(true)
        .build()
        .err()
        .expect("browser services cannot spawn the native readiness thread");
    assert_eq!(threadless.kind(), crate::error::ErrorKind::ConfigError);
}

#[test]
fn background_io_wakes_real_socket_while_the_only_worker_is_blocked() {
    let runtime = native_builder()
        .with_reactor(create_reactor().expect("platform reactor"))
        .background_io_driver(true)
        .build()
        .expect("runtime");
    let worker = HeldWorker::enter(&runtime);
    let (io, _) = runtime_drivers(&runtime);
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver socket");
    receiver.set_nonblocking(true).expect("nonblocking receiver");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender socket");
    let (waker, wakes) = notice_waker(false);
    let registration = io
        .register(&receiver, Interest::READABLE, waker)
        .expect("register actual UDP readiness after the worker is held");
    sender
        .send_to(b"readiness", receiver.local_addr().unwrap())
        .expect("send actual datagram");

    assert_helper_wake(
        wakes.recv_timeout(WATCHDOG).expect("independent socket wake"),
        &worker,
    );
    let mut bytes = [0; 16];
    let received = receiver.recv(&mut bytes).expect("read ready datagram");
    assert_eq!(&bytes[..received], b"readiness");
    drop(registration);
    drop(worker);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn background_io_fires_wall_clock_timer_while_the_only_worker_is_blocked() {
    let runtime = native_builder()
        .with_reactor(create_reactor().expect("platform reactor"))
        .background_io_driver(true)
        .build()
        .expect("runtime");
    let worker = HeldWorker::enter(&runtime);
    let (_, timer) = runtime_drivers(&runtime);
    let (waker, wakes) = notice_waker(false);
    let _timer = timer.register(timer.now() + Duration::from_millis(20), waker);

    assert_helper_wake(
        wakes.recv_timeout(WATCHDOG).expect("independent timer wake"),
        &worker,
    );
    drop(worker);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

// Hold exactly one helper poll until a wake arrives after its wait was
// selected. The rescue timeout is longer than the assertion watchdog, so a
// missing timer-publication wake cannot pass via the pump's fallback timeout.
#[derive(Default)]
struct PollGate {
    armed: bool,
    entered: bool,
    released: bool,
}

struct GatedReactor {
    inner: Arc<dyn Reactor>,
    gate: Mutex<PollGate>,
    changed: Condvar,
}

impl GatedReactor {
    fn new() -> Self {
        Self {
            inner: create_reactor().expect("platform reactor"),
            gate: Mutex::new(PollGate::default()),
            changed: Condvar::new(),
        }
    }

    fn arm_next_helper_poll(&self) {
        self.gate.lock().armed = true;
        // Interrupt the current physical wait without releasing the newly
        // armed gate, even if the helper reaches it before this call returns.
        self.inner.wake().expect("interrupt current poll");
    }

    fn wait_until_entered(&self) {
        let started = Instant::now();
        let mut gate = self.gate.lock();
        while !gate.entered {
            let remaining = WATCHDOG.saturating_sub(started.elapsed());
            assert!(!remaining.is_zero(), "helper entered its selected wait");
            self.changed.wait_for(&mut gate, remaining);
        }
    }
}

impl Reactor for GatedReactor {
    fn capability_snapshot(&self) -> IoReactorCapabilitySnapshot {
        self.inner.capability_snapshot()
    }

    fn register(&self, source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.register(source, token, interest)
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.inner.modify(token, interest)
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        self.inner.deregister(token)
    }

    fn poll(&self, events: &mut Events, timeout: Option<Duration>) -> io::Result<usize> {
        let mut gate = self.gate.lock();
        if gate.armed
            && std::thread::current().name() == Some("background-io-test-io")
        {
            gate.armed = false;
            gate.entered = true;
            self.changed.notify_all();
            while !gate.released {
                if self.changed.wait_for(&mut gate, RESCUE).timed_out() {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "test poll rescue"));
                }
            }
            drop(gate);
            return self.inner.poll(events, Some(Duration::ZERO));
        }
        drop(gate);
        self.inner.poll(events, timeout)
    }

    fn wake(&self) -> io::Result<()> {
        let mut gate = self.gate.lock();
        if gate.entered {
            gate.released = true;
            self.changed.notify_all();
        }
        drop(gate);
        self.inner.wake()
    }

    fn registration_count(&self) -> usize {
        self.inner.registration_count()
    }
}

#[test]
fn background_io_new_earlier_timer_interrupts_an_existing_wait() {
    let reactor = Arc::new(GatedReactor::new());
    let clock = Arc::new(VirtualClock::starting_at(Time::ZERO));
    let timer = TimerDriverHandle::with_virtual_clock(Arc::clone(&clock));
    let runtime = native_builder()
        .with_reactor(reactor.clone())
        .with_timer_driver(timer.clone())
        .background_io_driver(true)
        .build()
        .expect("runtime");
    let worker = HeldWorker::enter(&runtime);
    let far = timer.register(Time::from_secs(100), Waker::noop().clone());
    reactor.arm_next_helper_poll();
    reactor.wait_until_entered();

    clock.advance_to(Time::from_secs(1));
    let (waker, wakes) = notice_waker(false);
    let _early = timer.register(Time::from_secs(1), waker);
    let fired = wakes.recv_timeout(WATCHDOG);
    // Always release the controlled wait before a failure unwinds the test.
    reactor.wake().expect("release test gate");
    assert_helper_wake(fired.expect("earlier deadline publication woke helper"), &worker);
    assert!(timer.cancel(&far));
    drop(worker);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn background_io_recovers_after_a_readiness_waker_panics() {
    let runtime = native_builder()
        .with_reactor(create_reactor().expect("platform reactor"))
        .background_io_driver(true)
        .build()
        .expect("runtime");
    let worker = HeldWorker::enter(&runtime);
    let (io, timer) = runtime_drivers(&runtime);
    let receiver = UdpSocket::bind("127.0.0.1:0").expect("receiver socket");
    receiver.set_nonblocking(true).expect("nonblocking receiver");
    let sender = UdpSocket::bind("127.0.0.1:0").expect("sender socket");
    let (waker, panics) = notice_waker(true);
    let registration = io
        .register(&receiver, Interest::READABLE, waker)
        .expect("register panicking Waker");
    sender.send_to(b"panic", receiver.local_addr().unwrap()).unwrap();
    assert_helper_wake(
        panics.recv_timeout(WATCHDOG).expect("panicking callback ran"),
        &worker,
    );
    drop(registration);

    let (waker, recovered) = notice_waker(false);
    let _timer = timer.register(timer.now() + Duration::from_millis(1), waker);
    assert_helper_wake(
        recovered.recv_timeout(WATCHDOG).expect("helper survived the callback"),
        &worker,
    );
    drop(worker);
    assert!(runtime.shutdown_timeout(WATCHDOG));
}

#[test]
fn background_io_callback_can_drop_the_last_runtime_without_self_join() {
    struct DropRuntimeWake {
        runtime: Mutex<Option<Runtime>>,
        finished: mpsc::Sender<()>,
    }

    impl Wake for DropRuntimeWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }

        fn wake_by_ref(self: &Arc<Self>) {
            let runtime = self.runtime.lock().take();
            drop(runtime);
            let _ = self.finished.send(());
        }
    }

    let runtime = native_builder()
        .with_reactor(create_reactor().expect("platform reactor"))
        .background_io_driver(true)
        .build()
        .expect("runtime");
    let worker = HeldWorker::enter(&runtime);
    let state = Arc::downgrade(&runtime.inner.state);
    let (_, timer) = runtime_drivers(&runtime);
    let (finished, dropped) = mpsc::channel();
    let waker = Waker::from(Arc::new(DropRuntimeWake {
        runtime: Mutex::new(Some(runtime)),
        finished,
    }));
    let _timer = timer.register(timer.now() + Duration::from_millis(1), waker);
    dropped
        .recv_timeout(WATCHDOG)
        .expect("last owner drop returns on the helper while the worker is still held");
    assert!(state.upgrade().is_some(), "reaper retains the blocked worker's state");
    drop(worker);
    let started = Instant::now();
    while state.upgrade().is_some() {
        assert!(started.elapsed() < WATCHDOG, "off-thread teardown finishes");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn background_io_start_failure_stops_workers_despite_a_retained_start_hook_owner() {
    let (owner_tx, owner_rx) = mpsc::channel();
    let runtime = native_builder()
        .on_thread_start(move || {
            let ambient = Runtime::current_handle().expect("worker has ambient runtime");
            let inner = ambient.try_inner().expect("runtime is live during worker start");
            let _ = owner_tx.send(RuntimeHandle::strong(inner));
        })
        .build()
        .expect("runtime before helper startup");
    let retained = owner_rx.recv_timeout(WATCHDOG).expect("owner retained by start hook");
    let complete = Arc::clone(&runtime.inner.shutdown_completion);
    let stopped = runtime.inner.scheduler.shutdown_signal();
    let result = runtime.with_background_io_driver_start(|_| {
        Err(Error::new(crate::error::ErrorKind::Internal).with_message("injected spawn refusal"))
    });

    assert!(result.is_err(), "preserve the helper spawn failure");
    assert!(retained.try_spawn(async {}).is_err(), "failed startup closes admission");
    assert!(stopped.load(Ordering::Acquire), "existing workers were told to stop");
    assert!(!complete.wait_timeout(Duration::ZERO), "the external owner still exists");
    drop(retained);
    assert!(complete.wait_timeout(WATCHDOG), "teardown finishes after releasing the owner");
}
