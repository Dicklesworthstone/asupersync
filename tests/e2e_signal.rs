//! E2E: Signal handling under load — graceful shutdown, drain in-flight,
//! ShutdownController coordination, multiple receivers, double shutdown.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use asupersync::signal::{ShutdownController, SignalKind};

#[cfg(unix)]
fn parked_signal_child(kind: SignalKind, scenario: &'static str) {
    use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
    use std::future::{Future, poll_fn};
    use std::io::Write;

    // A launcher (nohup-style wrappers, RCH workers) can start this process
    // with SIGTERM blocked, and the mask is inherited. Unblock it BEFORE any
    // asupersync call, so both scenarios measure asupersync's registrations
    // rather than the launcher (tests/signal_subscription_isolation.rs guards
    // the same hazard). Runtime threads spawned below inherit this mask.
    let mut term = SigSet::empty();
    term.add(Signal::SIGTERM);
    pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&term), None).expect("unblock SIGTERM");

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .expect("signal child runtime");
    runtime.block_on(async move {
        let mut wait = Box::pin(async move {
            if kind == SignalKind::interrupt() {
                assert!(asupersync::signal::is_available());
                asupersync::signal::ctrl_c().await.expect("Ctrl-C listener");
            } else {
                assert!(asupersync::signal::is_available());
                let mut stream = asupersync::signal::signal(kind).expect("SIGTERM listener");
                assert_eq!(stream.recv().await, Some(()));
            }
        });
        let mut parked = false;
        poll_fn(|cx| {
            let result = wait.as_mut().poll(cx);
            if result.is_pending() && !parked {
                parked = true;
                println!("SIGNAL_PARKED scenario={scenario} kind={kind:?}");
                std::io::stdout().flush().expect("flush parked witness");
            }
            result
        })
        .await;
        println!("SIGNAL_DELIVERED scenario={scenario} kind={kind:?}");
        std::io::stdout().flush().expect("flush delivery witness");
    });
}

/// Whether this process inherited SIGTERM as ignored. `SIG_IGN` survives
/// `exec`, so a child would start with it too, and the default-termination
/// case could then only measure the launcher. Read from /proc rather than via
/// `sigaction`, which would need `unsafe`.
#[cfg(unix)]
fn sigterm_ignored_by_launcher() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("SigIgn:"))
            .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
            .is_some_and(|mask| mask & (1_u64 << (libc::SIGTERM - 1)) != 0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

#[cfg(unix)]
fn run_signal_subprocess(test_name: &str, scenario: &str, expect_default_term: bool) {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::Instant;

    if expect_default_term && sigterm_ignored_by_launcher() {
        eprintln!(
            "scenario={scenario} SKIPPED: this test process inherited SIGTERM as ignored, \
             so a child cannot show the default termination (would measure the launcher, \
             not asupersync)"
        );
        return;
    }

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if matches!(self.0.try_wait(), Ok(None)) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }

    let mut child = ChildGuard(
        Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env("ASUPERSYNC_SIGNAL_TEST_CHILD", scenario)
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn isolated signal child"),
    );
    let stdout = child.0.stdout.take().expect("child stdout");
    let (send_line, receive_line) = mpsc::channel();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            send_line
                .send(line.expect("child stdout line"))
                .expect("parent reader");
        }
    });
    let started = Instant::now();
    let mut lines = Vec::new();
    loop {
        let remaining = Duration::from_secs(10).saturating_sub(started.elapsed());
        let line = receive_line
            .recv_timeout(remaining)
            .expect("child never reported a parked signal waiter");
        let parked = line.contains(&format!("SIGNAL_PARKED scenario={scenario}"));
        lines.push(line);
        if parked {
            break;
        }
    }
    eprintln!(
        "scenario={scenario} stage=parked elapsed={:?}",
        started.elapsed()
    );
    let pid = Pid::from_raw(child.0.id().try_into().expect("PID fits i32"));
    kill(pid, Signal::SIGTERM).expect("send SIGTERM after parked witness");
    let triggered = Instant::now();
    eprintln!(
        "scenario={scenario} stage=sigterm_sent elapsed={:?}",
        started.elapsed()
    );
    let status = loop {
        if let Some(status) = child.0.try_wait().expect("wait for signal child") {
            break status;
        }
        assert!(
            triggered.elapsed() < Duration::from_secs(1),
            "signal child did not exit within one second of SIGTERM: {lines:?}"
        );
        thread::sleep(Duration::from_millis(10));
    };
    reader.join().expect("read child output");
    lines.extend(receive_line.try_iter());
    eprintln!(
        "scenario={scenario} stage=child_exited status={status:?} elapsed={:?} output={lines:?}",
        started.elapsed()
    );
    if expect_default_term {
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{lines:?}");
        assert!(!lines.iter().any(|line| line.contains("SIGNAL_DELIVERED")));
    } else {
        assert!(status.success(), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains(&format!("SIGNAL_DELIVERED scenario={scenario}"))),
            "SIGTERM was not delivered to the requested stream: {lines:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn e2e_ctrl_c_only_preserves_default_sigterm() {
    if std::env::var("ASUPERSYNC_SIGNAL_TEST_CHILD").as_deref() == Ok("ctrl-c-only") {
        parked_signal_child(SignalKind::interrupt(), "ctrl-c-only");
        return;
    }
    run_signal_subprocess(
        "e2e_ctrl_c_only_preserves_default_sigterm",
        "ctrl-c-only",
        true,
    );
}

#[cfg(unix)]
#[test]
fn e2e_requested_sigterm_reaches_parked_listener() {
    if std::env::var("ASUPERSYNC_SIGNAL_TEST_CHILD").as_deref() == Ok("requested-sigterm") {
        parked_signal_child(SignalKind::terminate(), "requested-sigterm");
        return;
    }
    run_signal_subprocess(
        "e2e_requested_sigterm_reaches_parked_listener",
        "requested-sigterm",
        false,
    );
}

// =========================================================================
// Phase 1: Graceful shutdown with in-flight work
// =========================================================================

#[test]
fn e2e_graceful_shutdown_drain_inflight() {
    common::init_test_logging();
    test_phase!("Graceful Shutdown with In-Flight Work");

    let controller = ShutdownController::new();
    let completed = Arc::new(AtomicUsize::new(0));

    // Simulate 5 "in-flight" workers
    test_section!("Start workers");
    let mut handles = Vec::new();
    for i in 0..5 {
        let rx = controller.subscribe();
        let completed = Arc::clone(&completed);
        handles.push(thread::spawn(move || {
            // Simulate work
            thread::sleep(Duration::from_millis(10 + i * 5));
            // Check if shutdown was requested
            if rx.is_shutting_down() {
                tracing::debug!(worker = i, "worker saw shutdown, finishing up");
            }
            completed.fetch_add(1, Ordering::SeqCst);
        }));
    }

    test_section!("Initiate shutdown");
    thread::sleep(Duration::from_millis(20)); // Let some workers start
    controller.shutdown();
    assert!(controller.is_shutting_down());

    test_section!("Wait for drain");
    for h in handles {
        h.join().expect("worker panicked");
    }

    let total = completed.load(Ordering::SeqCst);
    tracing::info!(completed = total, "all workers drained");
    assert_eq!(total, 5);

    test_complete!("e2e_graceful_shutdown", workers_completed = total);
}

// =========================================================================
// Phase 2: Double shutdown is idempotent
// =========================================================================

#[test]
fn e2e_double_shutdown_idempotent() {
    common::init_test_logging();
    test_phase!("Double Shutdown");

    let controller = ShutdownController::new();
    let rx = controller.subscribe();

    assert!(!controller.is_shutting_down());

    test_section!("First shutdown");
    controller.shutdown();
    assert!(controller.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_section!("Second shutdown (no-op)");
    controller.shutdown();
    assert!(controller.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_section!("Third shutdown (still no-op)");
    controller.shutdown();
    assert!(controller.is_shutting_down());

    test_complete!("e2e_double_shutdown");
}

// =========================================================================
// Phase 3: Multiple receivers all notified
// =========================================================================

#[test]
fn e2e_multi_receiver_notification() {
    common::init_test_logging();
    test_phase!("Multi-Receiver Notification");

    let controller = ShutdownController::new();
    let notified = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();

    test_section!("Subscribe 10 receivers");
    for i in 0..10 {
        let rx = controller.subscribe();
        let notified = Arc::clone(&notified);
        handles.push(thread::spawn(move || {
            // Busy-wait for shutdown (since we can't async poll in threads easily)
            while !rx.is_shutting_down() {
                thread::sleep(Duration::from_millis(1));
            }
            notified.fetch_add(1, Ordering::SeqCst);
            tracing::debug!(receiver = i, "notified");
        }));
    }

    test_section!("Trigger shutdown");
    thread::sleep(Duration::from_millis(10)); // Let receivers start polling
    controller.shutdown();

    test_section!("Verify all notified");
    for h in handles {
        h.join().expect("receiver panicked");
    }
    let total = notified.load(Ordering::SeqCst);
    assert_eq!(total, 10);
    tracing::info!(receivers_notified = total, "all receivers saw shutdown");

    test_complete!("e2e_multi_receiver", receivers = total);
}

// =========================================================================
// Phase 4: Shutdown from cloned controller
// =========================================================================

#[test]
fn e2e_shutdown_from_clone() {
    common::init_test_logging();
    test_phase!("Shutdown From Clone");

    let controller = ShutdownController::new();
    let clone = controller.clone();
    let rx = controller.subscribe();

    test_section!("Shutdown via clone");
    clone.shutdown();

    assert!(controller.is_shutting_down());
    assert!(clone.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_complete!("e2e_shutdown_from_clone");
}

// =========================================================================
// Phase 5: Receiver subscribed after shutdown
// =========================================================================

#[test]
fn e2e_late_subscriber_sees_shutdown() {
    common::init_test_logging();
    test_phase!("Late Subscriber");

    let controller = ShutdownController::new();
    controller.shutdown();

    test_section!("Subscribe after shutdown");
    let rx = controller.subscribe();
    assert!(rx.is_shutting_down());

    test_complete!("e2e_late_subscriber");
}

// =========================================================================
// Phase 6: Concurrent shutdown from multiple threads
// =========================================================================

#[test]
fn e2e_concurrent_shutdown_calls() {
    common::init_test_logging();
    test_phase!("Concurrent Shutdown Calls");

    let controller = Arc::new(ShutdownController::new());
    let rx = controller.subscribe();

    test_section!("Race 10 shutdown calls");
    let mut handles = Vec::new();
    for _ in 0..10 {
        let c = Arc::clone(&controller);
        handles.push(thread::spawn(move || {
            c.shutdown();
        }));
    }

    for h in handles {
        h.join().expect("shutdown caller panicked");
    }

    assert!(controller.is_shutting_down());
    assert!(rx.is_shutting_down());

    test_complete!("e2e_concurrent_shutdown");
}

// =========================================================================
// Phase 7: Signal kind enumeration (API surface)
// =========================================================================

#[test]
fn e2e_signal_kind_variants() {
    common::init_test_logging();
    test_phase!("Signal Kind Variants");

    let kinds = [
        SignalKind::interrupt(),
        SignalKind::terminate(),
        SignalKind::hangup(),
        SignalKind::quit(),
        SignalKind::user_defined1(),
        SignalKind::user_defined2(),
        SignalKind::child(),
        SignalKind::window_change(),
        SignalKind::pipe(),
        SignalKind::alarm(),
    ];

    for kind in &kinds {
        tracing::debug!(kind = ?kind, "signal kind available");
    }
    assert_eq!(kinds.len(), 10);

    test_complete!("e2e_signal_kinds", count = kinds.len());
}
