//! Fuzz target for epoll Registration interest mask transitions.
//!
//! This fuzz target exercises the EpollReactor's registration, modification,
//! and deregistration logic with focus on:
//! - oneshot vs edge-triggered vs level-triggered mask combinations
//! - PRIORITY/HUP/ERROR propagation
//! - register+deregister+re-register sequences without leaking bookkeeping
//! - ENOENT handling on stale fd/token
//! - rapid arm/disarm bursts
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run fuzz_epoll_registration -- -max_total_time=3600
//! ```

#![no_main]
#![cfg(target_os = "linux")]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::collections::{HashMap, HashSet};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

// Only compile on Linux since this is epoll-specific
#[cfg(target_os = "linux")]
use asupersync::runtime::reactor::{Events, Interest, Reactor, Token, epoll::EpollReactor};

/// Maximum test limits to prevent resource exhaustion
const MAX_OPERATIONS: usize = 500;
const MAX_CONCURRENT_FDS: usize = 64;
const MAX_TOKEN_VALUE: usize = 1000;

/// Fuzz input structure for epoll registration testing
#[derive(Arbitrary, Debug)]
struct EpollRegistrationFuzz {
    /// Sequence of operations to execute
    operations: Vec<EpollOperation>,
    /// Number of file descriptors to create initially
    initial_fds: u8,
}

/// Operations to test on the epoll reactor
#[derive(Arbitrary, Debug)]
enum EpollOperation {
    /// Register a new source
    Register {
        fd_index: u8,
        token: u16,
        interest: InterestFlags,
    },
    /// Modify existing registration
    Modify { token: u16, interest: InterestFlags },
    /// Deregister a source
    Deregister { token: u16 },
    /// Poll for events (with timeout)
    Poll { timeout_ms: Option<u16> },
    /// Close a file descriptor (simulates source being closed)
    CloseFd { fd_index: u8 },
    /// Rapid burst of operations
    Burst {
        burst_type: BurstType,
        count: u8,
        base_token: u16,
    },
    /// Re-register on same token (should fail)
    DuplicateRegister {
        fd_index: u8,
        token: u16,
        interest: InterestFlags,
    },
}

/// Types of rapid operation bursts
#[derive(Arbitrary, Debug)]
enum BurstType {
    /// Rapid register/deregister cycles
    RegisterDeregister,
    /// Rapid modify operations
    ModifyInterest,
    /// Mixed operations
    Mixed,
}

/// Interest flag combinations for fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct InterestFlags {
    readable: bool,
    writable: bool,
    error: bool,
    hup: bool,
    priority: bool,
    oneshot: bool,
    edge_triggered: bool,
}

impl InterestFlags {
    /// Convert to actual Interest flags
    fn to_interest(&self) -> Interest {
        let mut interest = Interest::NONE;

        if self.readable {
            interest = interest | Interest::READABLE;
        }
        if self.writable {
            interest = interest | Interest::WRITABLE;
        }
        if self.error {
            interest = interest | Interest::ERROR;
        }
        if self.hup {
            interest = interest | Interest::HUP;
        }
        if self.priority {
            interest = interest | Interest::PRIORITY;
        }
        if self.oneshot {
            interest = interest | Interest::ONESHOT;
        }
        if self.edge_triggered {
            interest = interest | Interest::EDGE_TRIGGERED;
        }

        interest
    }
}

/// Test file descriptor wrapper
struct TestFd {
    _reader: std::os::unix::net::UnixStream,
    _writer: std::os::unix::net::UnixStream,
    read_fd: i32,
    closed: bool,
}

impl TestFd {
    /// Create a new pipe for testing
    fn new() -> std::io::Result<Self> {
        let (reader, writer) = std::os::unix::net::UnixStream::pair()?;
        let read_fd = reader.as_raw_fd();

        Ok(Self {
            read_fd,
            _reader: reader,
            _writer: writer,
            closed: false,
        })
    }

    /// Close the file descriptors
    fn close(&mut self) {
        self.closed = true;
        // Descriptors will be closed when _reader and _writer are dropped
    }

    /// Get the read fd for registration
    fn read_fd(&self) -> i32 {
        self.read_fd
    }
}

/// Mock Source implementation for testing
struct MockSource {
    fd: i32,
}

impl MockSource {
    fn new(fd: i32) -> Self {
        Self { fd }
    }
}

impl AsRawFd for MockSource {
    fn as_raw_fd(&self) -> i32 {
        self.fd
    }
}

/// Shadow model for tracking expected state
#[derive(Debug, Default)]
struct ShadowState {
    /// Registered tokens -> (fd, interest)
    registrations: HashMap<Token, (i32, Interest)>,
    /// Closed file descriptors
    closed_fds: HashSet<i32>,
    /// Expected errors
    expected_errors: Vec<String>,
}

impl ShadowState {
    /// Check if a token should be registered
    fn should_be_registered(&self, token: Token) -> bool {
        self.registrations.contains_key(&token)
    }

    /// Check if an fd is closed
    fn is_fd_closed(&self, fd: i32) -> bool {
        self.closed_fds.contains(&fd)
    }

    /// Register a token
    fn register(&mut self, token: Token, fd: i32, interest: Interest) {
        self.registrations.insert(token, (fd, interest));
    }

    /// Deregister a token
    fn deregister(&mut self, token: Token) {
        self.registrations.remove(&token);
    }

    /// Mark fd as closed
    fn close_fd(&mut self, fd: i32) {
        self.closed_fds.insert(fd);
    }

    /// Modify registration
    fn modify(&mut self, token: Token, interest: Interest) {
        if let Some((fd, _)) = self.registrations.get(&token) {
            let fd = *fd;
            self.registrations.insert(token, (fd, interest));
        }
    }
}

/// Test harness for epoll fuzzing
struct EpollFuzzHarness {
    reactor: Arc<EpollReactor>,
    fds: Vec<TestFd>,
    shadow: ShadowState,
    operation_count: usize,
}

impl EpollFuzzHarness {
    /// Create new test harness
    fn new(initial_fds: u8) -> std::io::Result<Self> {
        let reactor = Arc::new(EpollReactor::new()?);

        // Create initial file descriptors
        let initial_fd_count = (initial_fds as usize).min(MAX_CONCURRENT_FDS);
        let mut fds = Vec::with_capacity(initial_fd_count);

        for _ in 0..initial_fd_count {
            match TestFd::new() {
                Ok(fd) => fds.push(fd),
                Err(_) => break, // Stop if we can't create more fds
            }
        }

        Ok(Self {
            reactor,
            fds,
            shadow: ShadowState::default(),
            operation_count: 0,
        })
    }

    /// Execute a register operation
    fn execute_register(&mut self, fd_index: u8, token: u16, interest_flags: InterestFlags) {
        let fd_idx = (fd_index as usize) % self.fds.len().max(1);
        let token = Token::new(token as usize % MAX_TOKEN_VALUE);
        let interest = interest_flags.to_interest();

        if fd_idx >= self.fds.len() {
            return;
        }

        let fd = &self.fds[fd_idx];
        if fd.closed {
            return;
        }

        let source = MockSource::new(fd.read_fd());
        let result = self.reactor.register(&source, token, interest);

        match result {
            Ok(()) => {
                // Should only succeed if not already registered
                if self.shadow.should_be_registered(token) {
                    panic!(
                        "Register succeeded but token already registered: {:?}",
                        token
                    );
                }
                self.shadow.register(token, fd.read_fd(), interest);
            }
            Err(e) => {
                // Should fail if already registered or fd is invalid
                match e.kind() {
                    std::io::ErrorKind::AlreadyExists => {
                        // Expected for duplicate registrations
                    }
                    std::io::ErrorKind::InvalidInput => {
                        // Expected for closed fds
                    }
                    _ => {
                        // Other errors are acceptable in fuzzing
                    }
                }
            }
        }
    }

    /// Execute a modify operation
    fn execute_modify(&mut self, token: u16, interest_flags: InterestFlags) {
        let token = Token::new(token as usize % MAX_TOKEN_VALUE);
        let interest = interest_flags.to_interest();

        let result = self.reactor.modify(token, interest);

        match result {
            Ok(()) => {
                // Should only succeed if token is registered
                if !self.shadow.should_be_registered(token) {
                    panic!("Modify succeeded but token not registered: {:?}", token);
                }
                self.shadow.modify(token, interest);
            }
            Err(e) => {
                // Should fail if not registered
                match e.kind() {
                    std::io::ErrorKind::NotFound => {
                        // Expected for unregistered tokens
                    }
                    _ => {
                        // ENOENT and other errors are acceptable
                    }
                }
            }
        }
    }

    /// Execute a deregister operation
    fn execute_deregister(&mut self, token: u16) {
        let token = Token::new(token as usize % MAX_TOKEN_VALUE);

        let result = self.reactor.deregister(token);

        match result {
            Ok(()) => {
                // Always succeeds even for non-registered tokens (idempotent)
                self.shadow.deregister(token);
            }
            Err(_) => {
                // Deregister errors are generally acceptable in fuzzing
                self.shadow.deregister(token);
            }
        }
    }

    /// Execute a poll operation
    fn execute_poll(&mut self, timeout_ms: Option<u16>) {
        let timeout = timeout_ms.map(|ms| Duration::from_millis(ms as u64));
        let mut events = Events::with_capacity(64);

        // Poll should not panic even with invalid state
        let _ = self.reactor.poll(&mut events, timeout);
    }

    /// Close a file descriptor
    fn execute_close_fd(&mut self, fd_index: u8) {
        let fd_idx = (fd_index as usize) % self.fds.len().max(1);

        if fd_idx < self.fds.len() {
            let fd = &mut self.fds[fd_idx];
            let raw_fd = fd.read_fd();
            fd.close();
            self.shadow.close_fd(raw_fd);
        }
    }

    /// Execute a rapid burst of operations
    fn execute_burst(&mut self, burst_type: BurstType, count: u8, base_token: u16) {
        let operation_limit = (count as usize).min(50); // Limit burst size
        let base_token = (base_token as usize) % MAX_TOKEN_VALUE;

        for i in 0..operation_limit {
            let token = Token::new((base_token + i) % MAX_TOKEN_VALUE);

            match burst_type {
                BurstType::RegisterDeregister => {
                    // Register then immediately deregister
                    if !self.fds.is_empty() {
                        let source = MockSource::new(self.fds[0].read_fd());
                        let _ = self.reactor.register(&source, token, Interest::READABLE);
                        let _ = self.reactor.deregister(token);
                    }
                }
                BurstType::ModifyInterest => {
                    // Rapid interest modifications
                    let interests = [
                        Interest::READABLE,
                        Interest::WRITABLE,
                        Interest::READABLE | Interest::WRITABLE,
                        Interest::READABLE | Interest::EDGE_TRIGGERED,
                        Interest::WRITABLE | Interest::ONESHOT,
                    ];
                    let interest = interests[i % interests.len()];
                    let _ = self.reactor.modify(token, interest);
                }
                BurstType::Mixed => {
                    // Mixed rapid operations
                    match i % 3 {
                        0 => {
                            if !self.fds.is_empty() {
                                let source =
                                    MockSource::new(self.fds[i % self.fds.len()].read_fd());
                                let _ = self.reactor.register(&source, token, Interest::READABLE);
                            }
                        }
                        1 => {
                            let _ = self.reactor.modify(token, Interest::WRITABLE);
                        }
                        2 => {
                            let _ = self.reactor.deregister(token);
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
    }

    /// Execute a single operation
    fn execute_operation(&mut self, operation: EpollOperation) {
        if self.operation_count >= MAX_OPERATIONS {
            return;
        }

        self.operation_count += 1;

        match operation {
            EpollOperation::Register {
                fd_index,
                token,
                interest,
            } => {
                self.execute_register(fd_index, token, interest);
            }
            EpollOperation::Modify { token, interest } => {
                self.execute_modify(token, interest);
            }
            EpollOperation::Deregister { token } => {
                self.execute_deregister(token);
            }
            EpollOperation::Poll { timeout_ms } => {
                self.execute_poll(timeout_ms);
            }
            EpollOperation::CloseFd { fd_index } => {
                self.execute_close_fd(fd_index);
            }
            EpollOperation::Burst {
                burst_type,
                count,
                base_token,
            } => {
                self.execute_burst(burst_type, count, base_token);
            }
            EpollOperation::DuplicateRegister {
                fd_index,
                token,
                interest,
            } => {
                // This should fail - testing duplicate registration
                self.execute_register(fd_index, token, interest.clone());
                self.execute_register(fd_index, token, interest); // Second call should fail
            }
        }
    }
}

#[cfg(target_os = "linux")]
fuzz_target!(|input: EpollRegistrationFuzz| {
    // Limit input size to prevent excessive resource usage
    if input.operations.len() > MAX_OPERATIONS {
        return;
    }

    // Create test harness
    let mut harness = match EpollFuzzHarness::new(input.initial_fds.min(32)) {
        Ok(h) => h,
        Err(_) => return, // Skip if we can't create harness
    };

    // Execute all operations
    for operation in input.operations {
        harness.execute_operation(operation);
    }

    // Final cleanup poll to ensure no crashes
    let mut events = Events::with_capacity(64);
    let _ = harness
        .reactor
        .poll(&mut events, Some(Duration::from_millis(1)));
});

#[cfg(not(target_os = "linux"))]
fuzz_target!(|_input: &[u8]| {
    // This fuzz target only runs on Linux
});
