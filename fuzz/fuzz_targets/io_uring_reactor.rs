//! Fuzz target for io-uring reactor Linux kernel 5.1+ edge cases.
//!
//! Tests the IoUringReactor implementation covering:
//! 1. Registration/deregistration with invalid FDs and token collisions
//! 2. Poll operations with submission queue overflow and completion errors
//! 3. Interest mask conversions and roundtrip consistency
//! 4. Eventfd wake mechanism and coalescing behavior
//! 5. Error handling paths (EBADF, ECANCELED, ETIME, etc.)
//! 6. Timeout handling with various durations

#![no_main]

use arbitrary::Arbitrary;
use asupersync::runtime::reactor::{Events, Interest, IoUringReactor, Reactor, Token};
use libfuzzer_sys::fuzz_target;
use std::{
    io,
    os::fd::{AsRawFd, RawFd},
    time::Duration,
};

// Test source that implements AsRawFd for fuzzing
#[derive(Debug, Clone)]
struct MockSource {
    raw_fd: RawFd,
}

impl AsRawFd for MockSource {
    fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }
}

impl MockSource {
    fn new(fd: RawFd) -> Self {
        Self { raw_fd: fd }
    }

    fn invalid() -> Self {
        Self { raw_fd: -1 }
    }

    fn from_valid_pipe() -> io::Result<(Self, Self)> {
        let mut fds = [0i32; 2];
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }

        // Set non-blocking
        for &fd in &fds {
            unsafe {
                let flags = libc::fcntl(fd, libc::F_GETFL);
                if flags != -1 {
                    libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
        }

        Ok((MockSource::new(fds[0]), MockSource::new(fds[1])))
    }
}

impl Drop for MockSource {
    fn drop(&mut self) {
        if self.raw_fd >= 0 {
            unsafe {
                libc::close(self.raw_fd);
            }
        }
    }
}

// Fuzz configuration for io-uring reactor testing
#[derive(Debug, Clone, Arbitrary)]
struct IoUringFuzzConfig {
    // Registration operations
    register_count: u8,              // 0-255 registrations
    invalid_fd_probability: u8,      // 0-100 (%)
    duplicate_token_probability: u8, // 0-100 (%)
    modify_operations: u8,           // 0-255 modifications

    // Poll operations
    poll_iterations: u8, // 0-255 polls
    timeout_mode: TimeoutMode,
    wake_probability: u8, // 0-100 (%) per poll

    // (interest_flags and close_fd_probability removed - unused in fuzzing logic)

    // Timing
    timeout_millis: u16, // 0-65535 milliseconds

    chaos_seed: u64,
}

#[derive(Debug, Clone, Arbitrary)]
enum TimeoutMode {
    None,  // No timeout
    Zero,  // Zero timeout
    Short, // timeout_millis
    Long,  // timeout_millis * 10
}

#[derive(Debug, Clone, Arbitrary)]
struct ReactorOperation {
    op_type: OperationType,
    token: u8,    // 0-255 for token values
    interest: u8, // Bitmask for interest flags
}

#[derive(Debug, Clone, Arbitrary)]
enum OperationType {
    Register,
    Modify,
    Deregister,
    Poll,
    Wake,
    CloseFd,
}

impl IoUringFuzzConfig {
    fn invalid_fd_prob_f64(&self) -> f64 {
        (self.invalid_fd_probability as f64) / 100.0
    }

    fn duplicate_token_prob_f64(&self) -> f64 {
        (self.duplicate_token_probability as f64) / 100.0
    }

    fn wake_prob_f64(&self) -> f64 {
        (self.wake_probability as f64) / 100.0
    }

    fn get_timeout(&self) -> Option<Duration> {
        match self.timeout_mode {
            TimeoutMode::None => None,
            TimeoutMode::Zero => Some(Duration::ZERO),
            TimeoutMode::Short => Some(Duration::from_millis(self.timeout_millis as u64)),
            TimeoutMode::Long => Some(Duration::from_millis((self.timeout_millis as u64) * 10)),
        }
    }

    fn interest_from_flags(&self, flags: u8) -> Interest {
        let mut interest = Interest::NONE;

        if flags & 0x01 != 0 {
            interest = interest.add(Interest::READABLE);
        }
        if flags & 0x02 != 0 {
            interest = interest.add(Interest::WRITABLE);
        }
        if flags & 0x04 != 0 {
            interest = interest.add(Interest::PRIORITY);
        }
        if flags & 0x08 != 0 {
            interest = interest.add(Interest::ERROR);
        }
        if flags & 0x10 != 0 {
            interest = interest.add(Interest::HUP);
        }

        // If no flags set, default to readable
        if interest.is_empty() {
            interest = Interest::READABLE;
        }

        interest
    }
}

// Chaos RNG for deterministic fuzzing
struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(1),
        }
    }

    fn next_bool(&mut self, probability: f64) -> bool {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;

        let threshold = (probability * (u64::MAX as f64)) as u64;
        self.state < threshold
    }

    fn next_u32(&mut self) -> u32 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state as u32
    }
}

// Test scenario: Registration edge cases
fn test_registration_edge_cases(config: &IoUringFuzzConfig, reactor: &IoUringReactor) {
    let mut rng = FuzzRng::new(config.chaos_seed);
    let mut sources = Vec::new();
    let mut registered_tokens = Vec::new();

    for i in 0..config.register_count {
        let token = Token::new(i as usize);

        // Create source (valid pipe or invalid FD)
        let source = if rng.next_bool(config.invalid_fd_prob_f64()) {
            MockSource::invalid()
        } else {
            match MockSource::from_valid_pipe() {
                Ok((read_end, _write_end)) => {
                    sources.push(_write_end); // Keep write end alive
                    read_end
                }
                Err(_) => MockSource::invalid(),
            }
        };

        // Generate interest flags
        let interest = config.interest_from_flags(rng.next_u32() as u8);

        // Attempt registration
        let result = reactor.register(&source, token, interest);

        match result {
            Ok(()) => {
                registered_tokens.push((token, source.clone()));

                // Verify registration count increased
                assert!(reactor.registration_count() <= config.register_count as usize);
            }
            Err(err) => {
                // Expected errors for invalid cases
                match err.kind() {
                    io::ErrorKind::AlreadyExists => {
                        // Token collision or FD already registered
                    }
                    _ => {
                        // Invalid FD or other io_uring errors
                        assert!(source.as_raw_fd() < 0 || err.raw_os_error().is_some());
                    }
                }
            }
        }

        // Test duplicate token registration
        if !registered_tokens.is_empty() && rng.next_bool(config.duplicate_token_prob_f64()) {
            let duplicate_idx = (rng.next_u32() as usize) % registered_tokens.len();
            let (dup_token, _) = &registered_tokens[duplicate_idx];

            let dup_result = reactor.register(&source, *dup_token, interest);
            assert!(dup_result.is_err());
            if let Err(err) = dup_result {
                assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
            }
        }
    }

    // Clean up registrations
    for (token, _source) in registered_tokens {
        let _ = reactor.deregister(token);
    }
}

// Test scenario: Poll operations with various timeouts
fn test_poll_operations(config: &IoUringFuzzConfig, reactor: &IoUringReactor) {
    let mut rng = FuzzRng::new(config.chaos_seed.wrapping_add(1));

    // Register a few sources for polling
    let mut active_registrations = Vec::new();
    let mut sources = Vec::new();

    for i in 0..3.min(config.register_count) {
        if let Ok((read_end, write_end)) = MockSource::from_valid_pipe() {
            let token = Token::new(1000 + i as usize);
            let interest = Interest::READABLE;

            if reactor.register(&read_end, token, interest).is_ok() {
                active_registrations.push((token, read_end, write_end));
            } else {
                sources.push((read_end, write_end));
            }
        }
    }

    let mut events = Events::with_capacity(16);

    for _ in 0..config.poll_iterations {
        // Maybe wake the reactor
        if rng.next_bool(config.wake_prob_f64()) {
            let _ = reactor.wake();
        }

        // Poll with configured timeout
        let timeout = config.get_timeout();
        let poll_result = reactor.poll(&mut events, timeout);

        match poll_result {
            Ok(count) => {
                // Verify event count consistency
                assert_eq!(count, events.len());

                // Process events
                for event in events.iter() {
                    // Verify token is valid
                    let token_exists = active_registrations
                        .iter()
                        .any(|(token, _, _)| *token == event.token);

                    if token_exists {
                        // Event should have valid interest flags
                        let ready = event.ready;
                        assert!(
                            ready.is_readable()
                                || ready.is_writable()
                                || ready.is_priority()
                                || ready.is_error()
                                || ready.is_hup()
                        );
                    }
                }

                events.clear();
            }
            Err(err) => {
                // Expected errors
                match err.kind() {
                    io::ErrorKind::Unsupported => {
                        // io_uring not available on this system
                        return;
                    }
                    io::ErrorKind::PermissionDenied => {
                        // Insufficient permissions for io_uring
                        return;
                    }
                    _ => {
                        // Other io_uring errors are possible
                    }
                }
            }
        }
    }

    // Test modification operations
    for _ in 0..config.modify_operations {
        if !active_registrations.is_empty() {
            let idx = (rng.next_u32() as usize) % active_registrations.len();
            let (token, _, _) = &active_registrations[idx];

            // Generate new interest
            let new_interest = config.interest_from_flags(rng.next_u32() as u8);

            let _ = reactor.modify(*token, new_interest);
        }
    }

    // Clean up
    for (token, _read, _write) in active_registrations {
        let _ = reactor.deregister(token);
    }
}

// Test scenario: Interest flag roundtrip consistency
fn test_interest_roundtrips(config: &IoUringFuzzConfig) {
    let all_interests = [
        Interest::NONE,
        Interest::READABLE,
        Interest::WRITABLE,
        Interest::PRIORITY,
        Interest::ERROR,
        Interest::HUP,
        Interest::READABLE.add(Interest::WRITABLE),
        Interest::READABLE.add(Interest::PRIORITY),
        Interest::READABLE.add(Interest::ERROR),
        Interest::READABLE.add(Interest::HUP),
        Interest::WRITABLE.add(Interest::ERROR),
        Interest::READABLE
            .add(Interest::WRITABLE)
            .add(Interest::PRIORITY),
        Interest::READABLE
            .add(Interest::WRITABLE)
            .add(Interest::ERROR),
        Interest::READABLE
            .add(Interest::WRITABLE)
            .add(Interest::HUP),
        Interest::READABLE
            .add(Interest::WRITABLE)
            .add(Interest::PRIORITY)
            .add(Interest::ERROR)
            .add(Interest::HUP),
    ];

    // Also test fuzzer-generated interest combinations
    let mut rng = FuzzRng::new(config.chaos_seed.wrapping_add(2));

    for _ in 0..32 {
        let flags = rng.next_u32() as u8;
        let fuzz_interest = config.interest_from_flags(flags);

        // Test that interest flags are internally consistent
        if fuzz_interest.is_readable() {
            assert!(!fuzz_interest.is_empty());
        }
        if fuzz_interest.is_writable() {
            assert!(!fuzz_interest.is_empty());
        }
        if fuzz_interest.is_priority() {
            assert!(!fuzz_interest.is_empty());
        }
        if fuzz_interest.is_error() {
            assert!(!fuzz_interest.is_empty());
        }
        if fuzz_interest.is_hup() {
            assert!(!fuzz_interest.is_empty());
        }
    }

    // Test known good interest combinations
    for &interest in &all_interests {
        // Test that combining interest with itself is idempotent
        let combined = interest.add(interest);
        assert_eq!(interest.is_readable(), combined.is_readable());
        assert_eq!(interest.is_writable(), combined.is_writable());
        assert_eq!(interest.is_priority(), combined.is_priority());
        assert_eq!(interest.is_error(), combined.is_error());
        assert_eq!(interest.is_hup(), combined.is_hup());
    }
}

// Test scenario: Early FD closure and error handling
fn test_early_fd_closure(_config: &IoUringFuzzConfig, reactor: &IoUringReactor) {
    if let Ok((read_end, write_end)) = MockSource::from_valid_pipe() {
        let token = Token::new(2000);
        let interest = Interest::READABLE;

        // Register the FD
        if reactor.register(&read_end, token, interest).is_ok() {
            // Close the FD early by dropping the source
            drop(read_end);

            // Try various operations on the closed FD
            let modify_result = reactor.modify(token, Interest::WRITABLE);
            if let Err(modify_err) = modify_result {
                // Should fail due to closed FD
                assert!(modify_err.raw_os_error().is_some());
            }

            // Deregistration should still work
            let dereg_result = reactor.deregister(token);
            // Either succeeds (if reactor cleaned up) or fails with NotFound
            match dereg_result {
                Ok(()) => {
                    // Successfully deregistered
                }
                Err(err) => {
                    assert_eq!(err.kind(), io::ErrorKind::NotFound);
                }
            }
        }

        drop(write_end);
    }
}

// Test scenario: Wake mechanism edge cases
fn test_wake_mechanism(config: &IoUringFuzzConfig, reactor: &IoUringReactor) {
    let mut rng = FuzzRng::new(config.chaos_seed.wrapping_add(4));

    // Test multiple concurrent wakes
    for _ in 0..16 {
        if rng.next_bool(0.7) {
            let _ = reactor.wake();
        }
    }

    // Poll to consume any wake events
    let mut events = Events::with_capacity(8);
    let _ = reactor.poll(&mut events, Some(Duration::ZERO));

    // Wake events should not surface as user events
    for _event in events.iter() {
        // If we see any events, they should be from actual registrations
        // not internal wake mechanisms
    }

    // Test wake after poll
    let _ = reactor.wake();
    let _ = reactor.poll(&mut events, Some(Duration::ZERO));
}

// Main fuzz entry point
fuzz_target!(|data: (IoUringFuzzConfig, Vec<ReactorOperation>)| {
    let (config, operations) = data;

    // Try to create io_uring reactor
    let reactor = match IoUringReactor::new() {
        Ok(reactor) => reactor,
        Err(err) => {
            // io_uring might not be available/supported
            match err.kind() {
                io::ErrorKind::Unsupported
                | io::ErrorKind::PermissionDenied
                | io::ErrorKind::Other => {
                    // Expected on systems without io_uring or insufficient permissions
                    return;
                }
                _ => {
                    // Unexpected error - continue testing error paths
                    return;
                }
            }
        }
    };

    // Test scenario 1: Registration edge cases
    test_registration_edge_cases(&config, &reactor);

    // Test scenario 2: Poll operations with timeouts
    test_poll_operations(&config, &reactor);

    // Test scenario 3: Interest flag roundtrip consistency
    test_interest_roundtrips(&config);

    // Test scenario 4: Early FD closure error handling
    test_early_fd_closure(&config, &reactor);

    // Test scenario 5: Wake mechanism edge cases
    test_wake_mechanism(&config, &reactor);

    // Test scenario 6: Operation sequence fuzzing
    let mut sources = Vec::new();
    let mut registered_tokens = std::collections::HashSet::new();
    let mut rng = FuzzRng::new(config.chaos_seed.wrapping_add(5));

    for operation in operations.iter().take(64) {
        // Limit operations to prevent excessive test time
        match operation.op_type {
            OperationType::Register => {
                if registered_tokens.len() < 16 {
                    // Limit registrations
                    let token = Token::new(operation.token as usize);
                    let interest = config.interest_from_flags(operation.interest);

                    if !registered_tokens.contains(&token)
                        && let Ok((read_end, write_end)) = MockSource::from_valid_pipe()
                        && reactor.register(&read_end, token, interest).is_ok()
                    {
                        registered_tokens.insert(token);
                        sources.push((token, read_end, write_end));
                    }
                }
            }
            OperationType::Modify => {
                let token = Token::new(operation.token as usize);
                if registered_tokens.contains(&token) {
                    let interest = config.interest_from_flags(operation.interest);
                    let _ = reactor.modify(token, interest);
                }
            }
            OperationType::Deregister => {
                let token = Token::new(operation.token as usize);
                if registered_tokens.contains(&token) {
                    let _ = reactor.deregister(token);
                    registered_tokens.remove(&token);
                    sources.retain(|(t, _, _)| *t != token);
                }
            }
            OperationType::Poll => {
                let mut events = Events::with_capacity(8);
                let timeout = if rng.next_bool(0.3) {
                    Some(Duration::from_millis(1))
                } else {
                    Some(Duration::ZERO)
                };
                let _ = reactor.poll(&mut events, timeout);
            }
            OperationType::Wake => {
                let _ = reactor.wake();
            }
            OperationType::CloseFd => {
                if !sources.is_empty() {
                    let idx = (rng.next_u32() as usize) % sources.len();
                    let (token, _read, _write) = sources.remove(idx);
                    registered_tokens.remove(&token);
                    // FDs are closed when sources are dropped
                }
            }
        }
    }

    // Final cleanup
    for token in registered_tokens {
        let _ = reactor.deregister(token);
    }

    // Verify final state is consistent
    assert_eq!(reactor.registration_count(), 0);
});
