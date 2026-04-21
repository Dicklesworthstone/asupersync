#![allow(clippy::all)]
//! Stress tests for io_uring reactor edge cases under high contention.
//!
//! This module provides conformance testing for io_uring reactor behavior under
//! extreme conditions: SQE overflow, burst registration/deregistration patterns,
//! timeout vs error distinction, stale completion handling, and cancellation
//! during ring-full conditions.
//!
//! Tests drive the live reactor directly with kernel primitives and
//! wall-clock timing to exercise high-contention edge cases.
//!
//! Requires: Linux kernel 5.1+, feature `io-uring`.

#![cfg(all(target_os = "linux", feature = "io-uring"))]
#![allow(unsafe_code)]

use asupersync::runtime::reactor::{Events, Interest, IoUringReactor, Reactor, Token};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum number of concurrent registrations for stress tests.
const STRESS_MAX_REGISTRATIONS: usize = 1000;

/// Number of burst operations to test SQE overflow.
const BURST_OPERATIONS: usize = 512;

/// Test eventfd timeout threshold for ETIME vs error distinction.
const TIMEOUT_THRESHOLD_MS: u64 = 50;

// =========================================================================
// Test infrastructure
// =========================================================================

/// Wrapper for raw FD sources to implement reactor Source trait.
#[derive(Debug)]
struct StressFdSource {
    fd: RawFd,
}

impl StressFdSource {
    fn new(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl AsRawFd for StressFdSource {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

/// Creates a non-blocking eventfd for testing.
fn create_test_eventfd() -> io::Result<OwnedFd> {
    let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly created and owned
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Creates a non-blocking pipe pair for testing.
fn create_test_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 creates valid FDs
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// Triggers readiness on an eventfd.
fn trigger_eventfd(fd: RawFd) -> io::Result<()> {
    let value: u64 = 1;
    let bytes = value.to_ne_bytes();
    let written = unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
    if written < 0 {
        let err = io::Error::last_os_error();
        if err.kind() == io::ErrorKind::WouldBlock {
            return Ok(()); // Already signaled
        }
        return Err(err);
    }
    Ok(())
}

/// Drains an eventfd without blocking.
fn drain_eventfd(fd: RawFd) -> io::Result<u64> {
    let mut value = 0u64;
    let n = unsafe {
        libc::read(
            fd,
            (&raw mut value).cast::<libc::c_void>(),
            std::mem::size_of::<u64>(),
        )
    };
    if n < 0 {
        let err = io::Error::last_os_error();
        if matches!(
            err.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
        ) {
            return Ok(0);
        }
        return Err(err);
    }
    Ok(value)
}

// =========================================================================
// Stress Test 1: SQE Overflow and Re-submission Under Burst Load
// =========================================================================

#[test]
fn stress_sqe_overflow_burst_registrations() {
    let reactor = IoUringReactor::new().expect("io_uring reactor creation");

    // Create many eventfds for burst registration
    let mut eventfds = Vec::new();
    let mut sources = Vec::new();
    for _i in 0..BURST_OPERATIONS {
        let eventfd = create_test_eventfd().expect("eventfd creation");
        sources.push(StressFdSource::new(eventfd.as_raw_fd()));
        eventfds.push(eventfd);
    }

    // Burst register all sources simultaneously
    let start = Instant::now();
    let mut successful_registrations = 0;
    let mut overflow_retries = 0;

    for (i, source) in sources.iter().enumerate() {
        let token = Token::new(i + 1);
        match reactor.register(source, token, Interest::READABLE) {
            Ok(()) => successful_registrations += 1,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                overflow_retries += 1;
                // Retry after brief pause to allow SQE drain
                thread::sleep(Duration::from_micros(100));
                if let Ok(()) = reactor.register(source, token, Interest::READABLE) {
                    successful_registrations += 1;
                }
            }
            Err(e) => panic!("Unexpected registration error: {e}"),
        }
    }

    let registration_duration = start.elapsed();

    // Verify burst registration behavior
    assert!(
        successful_registrations >= BURST_OPERATIONS / 2,
        "Expected at least half of burst registrations to succeed, got {successful_registrations}/{BURST_OPERATIONS}"
    );
    assert!(
        registration_duration < Duration::from_secs(5),
        "Burst registration took too long: {registration_duration:?} (retries={overflow_retries})"
    );

    // Test SQE overflow recovery by triggering many eventfds simultaneously
    for eventfd in &eventfds[..successful_registrations.min(100)] {
        trigger_eventfd(eventfd.as_raw_fd()).expect("eventfd trigger");
    }

    // Poll should handle the burst of completions
    let mut events = Events::with_capacity(BURST_OPERATIONS);
    let mut total_events = 0;
    let poll_start = Instant::now();

    for _ in 0..50 {
        // Give plenty of attempts
        let n = reactor
            .poll(&mut events, Some(Duration::from_millis(20)))
            .expect("poll");
        total_events += n;
        if total_events >= 50 {
            // Expect at least some events
            break;
        }
    }

    let poll_duration = poll_start.elapsed();

    assert!(
        total_events > 0,
        "Should receive events from triggered eventfds"
    );
    assert!(
        poll_duration < Duration::from_secs(2),
        "Burst event processing took too long: {poll_duration:?}"
    );

    // Cleanup
    for i in 0..successful_registrations {
        let _ = reactor.deregister(Token::new(i + 1));
    }
}

// =========================================================================
// Stress Test 2: ETIME Handling (Timeout vs Failure Distinction)
// =========================================================================

#[test]
fn stress_etime_timeout_vs_error_distinction() {
    let reactor = IoUringReactor::new().expect("io_uring reactor creation");
    let eventfd = create_test_eventfd().expect("eventfd creation");
    let source = StressFdSource::new(eventfd.as_raw_fd());
    let token = Token::new(100);

    reactor
        .register(&source, token, Interest::READABLE)
        .expect("registration");

    // Test 1: Short timeout should return ETIME (not treated as error)
    let mut events = Events::with_capacity(10);
    let timeout_start = Instant::now();

    let poll_result = reactor.poll(
        &mut events,
        Some(Duration::from_millis(TIMEOUT_THRESHOLD_MS)),
    );
    let timeout_elapsed = timeout_start.elapsed();

    // Should succeed (ETIME is handled as non-error)
    assert!(
        poll_result.is_ok(),
        "Short timeout poll should not error: {:?}",
        poll_result
    );
    let event_count = poll_result.unwrap();
    assert_eq!(event_count, 0, "Timeout poll should return 0 events");
    assert!(events.is_empty(), "Timeout should not produce events");

    // Verify timing approximates the requested timeout
    assert!(
        timeout_elapsed >= Duration::from_millis(TIMEOUT_THRESHOLD_MS / 2),
        "Timeout duration too short: {timeout_elapsed:?}"
    );
    assert!(
        timeout_elapsed < Duration::from_millis(TIMEOUT_THRESHOLD_MS * 3),
        "Timeout duration too long: {timeout_elapsed:?}"
    );

    // Test 2: Zero timeout should return immediately
    let zero_start = Instant::now();
    let zero_result = reactor.poll(&mut events, Some(Duration::ZERO));
    let zero_elapsed = zero_start.elapsed();

    assert!(zero_result.is_ok(), "Zero timeout should not error");
    assert_eq!(
        zero_result.unwrap(),
        0,
        "Zero timeout should return 0 events"
    );
    assert!(
        zero_elapsed < Duration::from_millis(50),
        "Zero timeout took too long: {zero_elapsed:?}"
    );

    // Test 3: None timeout behavior (should block until wake or event)
    let reactor_wake = Arc::new(reactor);
    let wake_reactor = Arc::clone(&reactor_wake);

    let wake_handle = thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        wake_reactor.wake().expect("wake should succeed");
    });

    let none_start = Instant::now();
    let none_result = reactor_wake.poll(&mut events, None);
    let none_elapsed = none_start.elapsed();

    assert!(none_result.is_ok(), "None timeout should not error");
    assert!(
        none_elapsed >= Duration::from_millis(50) && none_elapsed < Duration::from_millis(200),
        "None timeout should block until wake: {none_elapsed:?}"
    );

    wake_handle.join().unwrap();

    reactor_wake.deregister(token).expect("deregistration");
}

// =========================================================================
// Stress Test 3: Stale Completion Suppression After Deregister
// =========================================================================

#[test]
fn stress_stale_completion_suppression() {
    let reactor = IoUringReactor::new().expect("io_uring reactor creation");
    let mut test_iterations = 0;
    let mut stale_detected = 0;

    // Run multiple iterations to catch race conditions
    for iteration in 0..20 {
        let eventfd = create_test_eventfd().expect("eventfd creation");
        let source = StressFdSource::new(eventfd.as_raw_fd());
        let token = Token::new(1000 + iteration);

        reactor
            .register(&source, token, Interest::READABLE)
            .expect("registration");

        // Trigger the eventfd to create a pending completion
        trigger_eventfd(eventfd.as_raw_fd()).expect("eventfd trigger");

        // Immediately deregister before poll (creates stale completion potential)
        reactor.deregister(token).expect("deregistration");

        // Poll should suppress any stale completions for the deregistered token
        let mut events = Events::with_capacity(64);
        let poll_attempts = 5;

        for _ in 0..poll_attempts {
            let n = reactor
                .poll(&mut events, Some(Duration::from_millis(20)))
                .expect("poll");

            for event in events.iter().take(n) {
                if event.token == token {
                    stale_detected += 1;
                }
            }

            events.clear();

            // Small delay to allow completion processing
            if n > 0 {
                thread::sleep(Duration::from_micros(500));
            }
        }

        test_iterations += 1;

        // Cleanup the eventfd
        drain_eventfd(eventfd.as_raw_fd()).ok();
    }

    assert_eq!(
        stale_detected, 0,
        "Detected {stale_detected} stale completions across {test_iterations} iterations"
    );
}

// =========================================================================
// Stress Test 4: Registration/Deregistration Race with In-flight Operations
// =========================================================================

#[test]
fn stress_registration_deregistration_races() {
    let reactor = Arc::new(IoUringReactor::new().expect("io_uring reactor creation"));
    let race_iterations = 100;
    let concurrent_operations = 20;

    let error_count = Arc::new(AtomicU64::new(0));
    let success_count = Arc::new(AtomicU64::new(0));
    let race_detected = Arc::new(AtomicBool::new(false));

    let mut handles = Vec::new();

    // Spawn multiple threads doing concurrent register/deregister cycles
    for thread_id in 0..concurrent_operations {
        let reactor_clone = Arc::clone(&reactor);
        let error_count_clone = Arc::clone(&error_count);
        let success_count_clone = Arc::clone(&success_count);
        let race_detected_clone = Arc::clone(&race_detected);

        let handle = thread::spawn(move || {
            for iteration in 0..race_iterations {
                let eventfd = match create_test_eventfd() {
                    Ok(fd) => fd,
                    Err(_) => continue,
                };
                let source = StressFdSource::new(eventfd.as_raw_fd());
                let token = Token::new((thread_id * race_iterations + iteration) + 10000);

                // Register
                match reactor_clone.register(&source, token, Interest::READABLE) {
                    Ok(()) => {
                        // Trigger immediately after registration
                        if trigger_eventfd(eventfd.as_raw_fd()).is_ok() {
                            // Brief window for potential race
                            thread::sleep(Duration::from_micros(100));

                            // Deregister while event might be in-flight
                            match reactor_clone.deregister(token) {
                                Ok(()) => {
                                    success_count_clone.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                                    // Acceptable race - already deregistered
                                    success_count_clone.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    error_count_clone.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        } else {
                            let _ = reactor_clone.deregister(token);
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                        // Acceptable race condition
                        race_detected_clone.store(true, Ordering::Relaxed);
                    }
                    Err(_) => {
                        error_count_clone.fetch_add(1, Ordering::Relaxed);
                    }
                }

                // Small random delay to vary timing
                if iteration % 10 == 0 {
                    thread::sleep(Duration::from_micros(thread_id as u64 * 50));
                }
            }
        });

        handles.push(handle);
    }

    // Let threads run for a while, then poll to clear any pending events
    thread::sleep(Duration::from_millis(100));

    let mut events = Events::with_capacity(512);
    for _ in 0..50 {
        let _ = reactor.poll(&mut events, Some(Duration::from_millis(5)));
        events.clear();
        thread::sleep(Duration::from_millis(10));
    }

    // Join all threads
    for handle in handles {
        handle.join().expect("thread join");
    }

    let final_errors = error_count.load(Ordering::Relaxed);
    let final_successes = success_count.load(Ordering::Relaxed);
    // Verify acceptable outcomes
    assert!(
        final_errors < final_successes / 10, // Allow up to 10% error rate
        "Too many errors: {final_errors} errors vs {final_successes} successes"
    );

    assert_eq!(
        reactor.registration_count(),
        0,
        "All registrations should be cleaned up"
    );
    let _ = race_detected.load(Ordering::Relaxed);
}

// =========================================================================
// Stress Test 5: Ring Full + Operation Cancel Path
// =========================================================================

#[test]
fn stress_ring_full_cancellation_path() {
    let reactor = IoUringReactor::new().expect("io_uring reactor creation");

    // Create many pipes to fill up the submission queue
    let mut pipes = Vec::new();
    let mut sources = Vec::new();

    for i in 0..STRESS_MAX_REGISTRATIONS {
        if let Ok((read_fd, write_fd)) = create_test_pipe() {
            sources.push((
                StressFdSource::new(read_fd.as_raw_fd()),
                Token::new(i + 20000),
            ));
            pipes.push((read_fd, write_fd));
        } else {
            break; // Resource limit reached
        }
    }

    let pipe_count = pipes.len();

    // Register all pipes rapidly to potentially fill SQ
    let mut registered_tokens = Vec::new();
    let mut registration_failures = 0;

    for (source, token) in &sources {
        match reactor.register(source, *token, Interest::READABLE) {
            Ok(()) => registered_tokens.push(*token),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                registration_failures += 1;
                // Try to submit and retry
                let _ = reactor.wake(); // Force submission
                thread::sleep(Duration::from_micros(100));
                if let Ok(()) = reactor.register(source, *token, Interest::READABLE) {
                    registered_tokens.push(*token);
                }
            }
            Err(_) => break,
        }
    }

    // Trigger readiness on half the pipes
    for (_, (_, write_fd)) in pipes.iter().enumerate().take(registered_tokens.len() / 2) {
        let _ = unsafe {
            libc::write(
                write_fd.as_raw_fd(),
                b"x".as_ptr().cast::<libc::c_void>(),
                1,
            )
        };
    }

    // Rapidly deregister tokens while events might be in-flight
    let deregistration_start = Instant::now();
    let mut successful_deregisters = 0;

    for (i, token) in registered_tokens.iter().enumerate() {
        if i % 3 == 0 {
            // Deregister every third token
            if reactor.deregister(*token).is_ok() {
                successful_deregisters += 1;
            }
        }

        // Intermittent polling during deregistration
        if i % 10 == 0 {
            let mut events = Events::with_capacity(64);
            let _ = reactor.poll(&mut events, Some(Duration::ZERO));
        }
    }

    let deregistration_duration = deregistration_start.elapsed();

    // Final poll to clear remaining events
    let mut events = Events::with_capacity(1024);
    let mut final_events = 0;
    let poll_start = Instant::now();

    for _ in 0..20 {
        match reactor.poll(&mut events, Some(Duration::from_millis(25))) {
            Ok(n) => {
                final_events += n;
                events.clear();
            }
            Err(_) => break,
        }
    }

    let final_poll_duration = poll_start.elapsed();

    // Verify no crashes occurred during ring full conditions
    assert!(
        successful_deregisters > 0,
        "Should successfully deregister some tokens even under stress (pipes={pipe_count}, registration_failures={registration_failures})"
    );

    assert!(
        deregistration_duration < Duration::from_secs(5),
        "Deregistration under stress took too long: {deregistration_duration:?}"
    );

    assert!(
        final_poll_duration < Duration::from_secs(2),
        "Final poll clearing took too long: {final_poll_duration:?} (final_events={final_events})"
    );

    // Cleanup remaining registrations
    for token in &registered_tokens {
        let _ = reactor.deregister(*token);
    }
}

// =========================================================================
// Comprehensive Stress Test: All Edge Cases Combined
// =========================================================================

#[test]
fn comprehensive_io_uring_stress() {
    let reactor = Arc::new(IoUringReactor::new().expect("io_uring reactor creation"));
    let test_duration = Duration::from_millis(500);
    let start_time = Instant::now();

    let operation_counts = Arc::new(AtomicU64::new(0));
    let error_counts = Arc::new(AtomicU64::new(0));

    // Worker thread 1: Continuous register/modify/deregister cycles
    let reactor1 = Arc::clone(&reactor);
    let ops1 = Arc::clone(&operation_counts);
    let errors1 = Arc::clone(&error_counts);
    let worker1 = thread::spawn(move || {
        let mut local_ops = 0u64;
        while start_time.elapsed() < test_duration {
            if let Ok(eventfd) = create_test_eventfd() {
                let source = StressFdSource::new(eventfd.as_raw_fd());
                let token = Token::new(((local_ops % 10000) + 40000) as usize);

                if reactor1
                    .register(&source, token, Interest::READABLE)
                    .is_ok()
                {
                    let _ = reactor1.modify(token, Interest::WRITABLE);
                    let _ = reactor1.deregister(token);
                    local_ops += 1;
                } else {
                    errors1.fetch_add(1, Ordering::Relaxed);
                }
            }

            if local_ops % 50 == 0 {
                thread::sleep(Duration::from_micros(100));
            }
        }
        ops1.fetch_add(local_ops, Ordering::Relaxed);
    });

    // Worker thread 2: High-frequency polling
    let reactor2 = Arc::clone(&reactor);
    let ops2 = Arc::clone(&operation_counts);
    let worker2 = thread::spawn(move || {
        let mut events = Events::with_capacity(128);
        let mut poll_count = 0u64;

        while start_time.elapsed() < test_duration {
            match reactor2.poll(&mut events, Some(Duration::ZERO)) {
                Ok(_) => poll_count += 1,
                Err(_) => break,
            }
            events.clear();

            if poll_count % 100 == 0 {
                thread::sleep(Duration::from_micros(50));
            }
        }
        ops2.fetch_add(poll_count, Ordering::Relaxed);
    });

    // Worker thread 3: Wake spam
    let reactor3 = Arc::clone(&reactor);
    let ops3 = Arc::clone(&operation_counts);
    let worker3 = thread::spawn(move || {
        let mut wake_count = 0u64;

        while start_time.elapsed() < test_duration {
            if reactor3.wake().is_ok() {
                wake_count += 1;
            }

            if wake_count % 200 == 0 {
                thread::sleep(Duration::from_micros(200));
            }
        }
        ops3.fetch_add(wake_count, Ordering::Relaxed);
    });

    // Let workers run
    worker1.join().expect("worker1 join");
    worker2.join().expect("worker2 join");
    worker3.join().expect("worker3 join");

    let final_duration = start_time.elapsed();
    let total_operations = operation_counts.load(Ordering::Relaxed);
    let total_errors = error_counts.load(Ordering::Relaxed);
    let final_registrations = reactor.registration_count();

    // Verify system remained stable under stress
    assert!(
        total_operations > 1000,
        "Expected significant operation volume under stress, got {total_operations}"
    );

    assert!(
        total_errors < total_operations / 20, // Max 5% error rate
        "Too many errors under stress: {total_errors}/{total_operations}"
    );

    assert_eq!(
        final_registrations, 0,
        "Registrations leaked: {} still registered",
        final_registrations
    );

    // Final stability check
    let mut final_events = Events::with_capacity(64);
    for _ in 0..10 {
        reactor
            .poll(&mut final_events, Some(Duration::from_millis(10)))
            .expect("final poll");
        final_events.clear();
    }
    assert!(
        reactor.is_empty(),
        "Reactor should be empty after comprehensive test (ops={total_operations}, errors={total_errors}, duration_ms={})",
        final_duration.as_millis()
    );
}
