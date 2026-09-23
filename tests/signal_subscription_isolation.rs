//! Process-isolated Unix signal subscriptions: real OS delivery and dispositions.
//! Bridge plan R26a / br-asupersync-bi2462. The parent never installs handlers.
#![cfg(unix)]

use asupersync::signal::{Signal, SignalKind, ctrl_c, signal};
use std::future::Future;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
use std::time::{Duration, Instant};

const CASE: &str = "ASUPERSYNC_SIGNAL_SUBSCRIPTION_ISOLATION_CASE";
const CHILD_COMPLETE: i32 = 73; // Reject zero-selected children and early exit(0).
const CHILD_BOUND: Duration = Duration::from_secs(10);
const DELIVERY_BOUND: Duration = Duration::from_secs(3);

// Reap even when an assertion or a watchdog fails; never leave a test child alive.
struct ChildOwner(Option<Child>);

impl Drop for ChildOwner {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn child_status(test: &str, case: &str) -> ExitStatus {
    let child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(CASE, case)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn isolated signal test");
    let mut owner = ChildOwner(Some(child));
    let started = Instant::now();
    loop {
        if let Some(status) = owner.0.as_mut().unwrap().try_wait().expect("child status") {
            drop(owner.0.take());
            eprintln!("signal_subscription case={case} status={status:?} elapsed={:?}", started.elapsed());
            return status;
        }
        assert!(started.elapsed() < CHILD_BOUND, "signal child {case} exceeded watchdog");
        thread::sleep(Duration::from_millis(2));
    }
}

struct WakeProbe {
    thread: thread::Thread,
    notified: AtomicBool,
    wakes: AtomicUsize,
}

impl Wake for WakeProbe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::AcqRel);
        self.notified.store(true, Ordering::Release);
        self.thread.unpark();
    }
}

impl WakeProbe {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            thread: thread::current(),
            notified: AtomicBool::new(false),
            wakes: AtomicUsize::new(0),
        })
    }

    fn wait(&self, until: Instant) {
        while !self.notified.swap(false, Ordering::AcqRel) {
            let remaining = until.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "parked signal receiver was never woken");
            thread::park_timeout(remaining);
        }
    }
}

fn receive_all(streams: &mut [Signal], raw: &[i32]) {
    let probe = WakeProbe::new();
    let waker = Waker::from(Arc::clone(&probe));
    let mut task = Context::from_waker(&waker);
    let mut waits: Vec<_> = streams.iter_mut().map(|stream| Box::pin(stream.recv())).collect();
    for wait in &mut waits {
        assert!(wait.as_mut().poll(&mut task).is_pending(), "receiver must park before delivery");
    }
    assert_eq!(probe.wakes.load(Ordering::Acquire), 0, "no ready signal before raise");
    eprintln!("signal_subscription parked={} raising={raw:?}", waits.len());
    for &number in raw {
        signal_hook::low_level::raise(number).expect("raise real OS signal");
    }
    let until = Instant::now() + DELIVERY_BOUND;
    let mut complete = vec![false; waits.len()];
    while complete.iter().any(|done| !done) {
        assert!(Instant::now() < until, "signal fanout exceeded the delivery bound");
        // No timer-driven repoll can conceal a lost wake: require an actual
        // notification before every sweep after the initial Pending witness.
        probe.wait(until);
        for (wait, done) in waits.iter_mut().zip(&mut complete) {
            if !*done {
                match wait.as_mut().poll(&mut task) {
                    Poll::Ready(Some(())) => *done = true,
                    Poll::Ready(None) => panic!("signal stream unexpectedly closed"),
                    Poll::Pending => {}
                }
            }
        }
    }
    eprintln!("signal_subscription received={} wakes={}", complete.len(), probe.wakes.load(Ordering::Acquire));
    drop(waits);
    for stream in streams {
        let mut extra = std::pin::pin!(stream.recv());
        assert!(extra.as_mut().poll(&mut task).is_pending(), "one raise must not duplicate a delivery");
    }
}

fn raw_signal(name: &str) -> i32 {
    match name {
        "term" => signal_hook::consts::SIGTERM,
        "hup" => signal_hook::consts::SIGHUP,
        "usr1" => signal_hook::consts::SIGUSR1,
        "alarm" => signal_hook::consts::SIGALRM,
        _ => panic!("unknown signal scenario {name}"),
    }
}

#[test]
fn ctrl_c_leaves_unrequested_termination_signals_alone() {
    if let Ok(case) = std::env::var(CASE) {
        let (mode, name) = case.split_once(':').expect("child mode and signal");
        let raw = raw_signal(name);
        // Keep the actual Ctrl-C future alive across the unrelated signal.
        let mut wait = std::pin::pin!(ctrl_c());
        match mode {
            "baseline" => {}
            "subscribed" => assert!(wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending()),
            _ => panic!("unknown child mode {mode}"),
        }
        eprintln!("signal_subscription mode={mode} unrelated_signal={raw} raising=true");
        signal_hook::low_level::raise(raw).expect("raise unrelated signal");
        // An eager all-signals dispatcher swallows the signal and reaches this
        // distinct failure code. Correct code dies from the original signal.
        std::process::exit(91);
    }
    for name in ["term", "hup", "usr1", "alarm"] {
        let expected = Some(raw_signal(name));
        for mode in ["baseline", "subscribed"] {
            let case = format!("{mode}:{name}");
            let status = child_status("ctrl_c_leaves_unrequested_termination_signals_alone", &case);
            assert_eq!(status.signal(), expected, "case={case}: registration changed termination behavior");
        }
    }
}

#[test]
fn late_and_duplicate_subscriptions_receive_without_capturing_other_kinds() {
    if let Ok(case) = std::env::var(CASE) {
        assert_eq!(case, "delivery");
        // Start the iterator on one kind. Register a different kind only after
        // it has already dispatched a real signal, not just after construction.
        let mut interrupts = [signal(SignalKind::Interrupt).unwrap()];
        receive_all(&mut interrupts, &[signal_hook::consts::SIGINT]);
        let mut users = [signal(SignalKind::User1).unwrap(), signal(SignalKind::User1).unwrap()];
        receive_all(&mut users, &[signal_hook::consts::SIGUSR1]);
        // Cancelling a borrowed receive drops its waiter, not its stream.
        {
            let mut cancelled_wait = std::pin::pin!(users[0].recv());
            assert!(cancelled_wait.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
        }
        receive_all(&mut users, &[signal_hook::consts::SIGUSR1]);
        let [first, second] = users;
        drop(first);
        receive_all(&mut [second], &[signal_hook::consts::SIGUSR1]);
        let mut second_kind = [signal(SignalKind::User2).unwrap()];
        receive_all(&mut second_kind, &[signal_hook::consts::SIGUSR2]);
        std::process::exit(CHILD_COMPLETE);
    }
    assert_eq!(
        child_status("late_and_duplicate_subscriptions_receive_without_capturing_other_kinds", "delivery").code(),
        Some(CHILD_COMPLETE),
        "the child must finish its actual signal assertions, not just exit successfully",
    );
}

#[test]
fn concurrent_first_subscriptions_share_delivery_without_losing_a_kind() {
    if let Ok(case) = std::env::var(CASE) {
        assert_eq!(case, "concurrent");
        let start = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8).map(|index| {
            let start = Arc::clone(&start);
            thread::spawn(move || {
                start.wait();
                let kind = if index % 2 == 0 { SignalKind::User1 } else { SignalKind::User2 };
                signal(kind).expect("concurrent subscription")
            })
        }).collect();
        let mut streams: Vec<_> = handles.into_iter().map(|handle| handle.join().expect("subscription thread")).collect();
        receive_all(&mut streams, &[signal_hook::consts::SIGUSR1, signal_hook::consts::SIGUSR2]);
        std::process::exit(CHILD_COMPLETE);
    }
    assert_eq!(
        child_status("concurrent_first_subscriptions_share_delivery_without_losing_a_kind", "concurrent").code(),
        Some(CHILD_COMPLETE),
        "the concurrent child must finish all parked receives",
    );
}
