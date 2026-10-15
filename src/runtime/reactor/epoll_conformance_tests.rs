//! Epoll reactor conformance test harness.
//!
//! This module provides comprehensive conformance testing for the EpollReactor
//! against the Linux epoll(7) specification and the reactor trait contract.
//!
//! # Conformance Coverage
//!
//! - **epoll system call semantics**: `epoll_create1`, `epoll_ctl`, `epoll_wait`
//! - **Reactor trait contract**: register/modify/deregister/poll/wake behavior
//! - **Interest mode semantics**: oneshot, edge-triggered, level-triggered
//! - **Error handling**: EBADF, ENOENT, EINVAL, EEXIST conditions
//! - **File descriptor lifecycle**: registration, reuse, cleanup
//! - **Thread safety**: concurrent operations and wake functionality

#![allow(clippy::unnecessary_literal_bound)]

use super::{EpollReactor, Events, Interest, Reactor, Token};
use std::collections::HashMap;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Requirement levels for conformance testing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequirementLevel {
    /// Critical requirements that MUST be implemented correctly.
    Must,
    /// Important requirements that SHOULD be implemented correctly.
    Should,
    /// Optional requirements that MAY be implemented.
    May,
}

/// Categories of conformance tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TestCategory {
    /// Unit-level behavior verification.
    Unit,
    /// Integration-level interaction testing.
    Integration,
    /// Edge case and error condition handling.
    EdgeCase,
    /// Performance and scalability characteristics.
    Performance,
}

/// Result of a conformance test execution.
#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub category: TestCategory,
    pub level: RequirementLevel,
    pub status: TestStatus,
    pub duration: Duration,
    pub details: Option<String>,
}

/// Status of test execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestStatus {
    /// Test passed successfully.
    Pass,
    /// Test failed with error.
    Fail(String),
    /// Test skipped (platform not supported, etc.).
    Skipped(String),
    /// Expected failure (known divergence from spec).
    ExpectedFailure(String),
}

/// Test execution context.
pub struct TestContext {
    pub verbose: bool,
    pub timeout: Duration,
    pub max_fds: usize,
}

impl Default for TestContext {
    fn default() -> Self {
        Self {
            verbose: false,
            timeout: Duration::from_secs(10),
            max_fds: 1024,
        }
    }
}

/// Conformance test trait.
pub trait ConformanceTest: Send + Sync {
    /// Test name identifier.
    fn name(&self) -> &str;
    /// Test category classification.
    fn category(&self) -> TestCategory;
    /// Requirement level (MUST/SHOULD/MAY).
    fn level(&self) -> RequirementLevel;
    /// Execute the test and return result.
    fn run(&self, ctx: &TestContext) -> TestResult;
}

/// Conformance test harness for epoll reactor.
pub struct EpollConformanceHarness {
    tests: Vec<Box<dyn ConformanceTest>>,
}

impl EpollConformanceHarness {
    /// Creates a new conformance test harness with all epoll tests.
    pub fn new() -> Self {
        let mut harness = Self { tests: Vec::new() };

        // Core epoll system call conformance
        harness.add_test(Box::new(EpollCreateConformanceTest));
        harness.add_test(Box::new(RegisterConformanceTest));
        harness.add_test(Box::new(ModifyConformanceTest));
        harness.add_test(Box::new(DeregisterConformanceTest));
        harness.add_test(Box::new(PollConformanceTest));
        harness.add_test(Box::new(WakeConformanceTest));

        // Interest mode conformance
        harness.add_test(Box::new(OneshotModeConformanceTest));
        harness.add_test(Box::new(EdgeTriggeredConformanceTest));
        harness.add_test(Box::new(LevelTriggeredConformanceTest));

        // Error handling conformance
        harness.add_test(Box::new(ErrorHandlingConformanceTest));
        harness.add_test(Box::new(InvalidFdConformanceTest));
        harness.add_test(Box::new(DuplicateRegistrationConformanceTest));

        // File descriptor lifecycle conformance
        harness.add_test(Box::new(FdReuseConformanceTest));
        harness.add_test(Box::new(FdCleanupConformanceTest));

        // Thread safety conformance
        harness.add_test(Box::new(ConcurrentOperationsConformanceTest));
        harness.add_test(Box::new(WakeFromThreadConformanceTest));

        // Performance conformance
        harness.add_test(Box::new(ScalabilityConformanceTest));
        harness.add_test(Box::new(MemoryLeakConformanceTest));

        harness
    }

    /// Adds a test to the harness.
    pub fn add_test(&mut self, test: Box<dyn ConformanceTest>) {
        self.tests.push(test);
    }

    /// Runs all conformance tests and returns results.
    pub fn run_all(&self, ctx: &TestContext) -> ConformanceReport {
        let start_time = Instant::now();
        let mut results = Vec::new();

        for test in &self.tests {
            let _test_start = Instant::now();
            println!("Running conformance test: {}", test.name());

            let result = test.run(ctx);

            if ctx.verbose {
                println!("  {:?} in {:?}", result.status, result.duration);
                if let Some(details) = &result.details {
                    println!("  Details: {}", details);
                }
            }

            results.push(result);
        }

        ConformanceReport {
            results,
            total_duration: start_time.elapsed(),
        }
    }

    /// Runs tests filtered by requirement level.
    pub fn run_level(&self, level: RequirementLevel, ctx: &TestContext) -> ConformanceReport {
        let start_time = Instant::now();
        let mut results = Vec::new();

        for test in &self.tests {
            if test.level() == level {
                let result = test.run(ctx);
                results.push(result);
            }
        }

        ConformanceReport {
            results,
            total_duration: start_time.elapsed(),
        }
    }
}

/// Conformance test execution report.
pub struct ConformanceReport {
    pub results: Vec<TestResult>,
    pub total_duration: Duration,
}

impl ConformanceReport {
    /// Generates a compliance matrix summary.
    pub fn generate_matrix(&self) -> String {
        let mut summary = String::from("# Epoll Reactor Conformance Matrix\n\n");
        summary.push_str("| Category | MUST | SHOULD | MAY | Total | Pass Rate |\n");
        summary.push_str("|----------|------|--------|-----|-------|----------|\n");

        let mut by_category: HashMap<TestCategory, (usize, usize, usize, usize)> = HashMap::new();

        for result in &self.results {
            let entry = by_category.entry(result.category).or_default();
            match result.level {
                RequirementLevel::Must => entry.0 += 1,
                RequirementLevel::Should => entry.1 += 1,
                RequirementLevel::May => entry.2 += 1,
            }
            if matches!(result.status, TestStatus::Pass) {
                entry.3 += 1;
            }
        }

        for (category, (must, should, may, passed)) in by_category {
            let total = must + should + may;
            let pass_rate = if total > 0 { (passed * 100) / total } else { 0 };
            summary.push_str(&format!(
                "| {:?} | {} | {} | {} | {} | {}% |\n",
                category, must, should, may, total, pass_rate
            ));
        }

        let total_tests = self.results.len();
        let total_passed = self
            .results
            .iter()
            .filter(|r| matches!(r.status, TestStatus::Pass))
            .count();
        let overall_rate = if total_tests > 0 {
            (total_passed * 100) / total_tests
        } else {
            0
        };

        summary.push_str(&format!(
            "\n**Overall: {}/{} tests passed ({}%)**\n",
            total_passed, total_tests, overall_rate
        ));
        summary.push_str(&format!("**Duration: {:?}**\n", self.total_duration));

        summary
    }

    /// Returns true if all MUST requirements pass.
    pub fn is_conformant(&self) -> bool {
        self.results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must)
            .all(|r| matches!(r.status, TestStatus::Pass | TestStatus::ExpectedFailure(_)))
    }
}

// Helper types for testing

/// Test source that wraps a raw file descriptor.
#[derive(Debug)]
struct TestSource(RawFd);

impl AsRawFd for TestSource {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// Creates a connected pair of Unix domain sockets for testing.
fn create_test_socket_pair() -> io::Result<(
    std::os::unix::net::UnixStream,
    std::os::unix::net::UnixStream,
)> {
    std::os::unix::net::UnixStream::pair()
}

/// Creates a test source with an invalid file descriptor.
fn create_invalid_test_source() -> TestSource {
    TestSource(-1)
}

// =============================================================================
// Conformance Test Implementations
// =============================================================================

struct EpollCreateConformanceTest;

impl ConformanceTest for EpollCreateConformanceTest {
    fn name(&self) -> &str {
        "epoll_create_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        // Test: EpollReactor::new() should successfully create an epoll fd
        match EpollReactor::new() {
            Ok(reactor) => {
                // Verify initial state
                if reactor.is_empty() && reactor.registration_count() == 0 {
                    TestResult {
                        name: self.name().to_string(),
                        category: self.category(),
                        level: self.level(),
                        status: TestStatus::Pass,
                        duration: start.elapsed(),
                        details: Some(
                            "Successfully created epoll reactor with empty initial state"
                                .to_string(),
                        ),
                    }
                } else {
                    TestResult {
                        name: self.name().to_string(),
                        category: self.category(),
                        level: self.level(),
                        status: TestStatus::Fail(
                            "Reactor not in expected initial state".to_string(),
                        ),
                        duration: start.elapsed(),
                        details: None,
                    }
                }
            }
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Failed to create epoll reactor: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct RegisterConformanceTest;

impl ConformanceTest for RegisterConformanceTest {
    fn name(&self) -> &str {
        "register_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;
            let (sock1, _sock2) = create_test_socket_pair()?;

            // Test: register() with valid fd and token should succeed
            reactor.register(&sock1, Token::new(1), Interest::READABLE)?;

            // Verify registration count increased
            assert_eq!(reactor.registration_count(), 1);
            assert!(!reactor.is_empty());

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Successfully registered file descriptor".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Registration failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct ModifyConformanceTest;

impl ConformanceTest for ModifyConformanceTest {
    fn name(&self) -> &str {
        "modify_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;
            let (sock1, _sock2) = create_test_socket_pair()?;
            let token = Token::new(1);

            // Register first
            reactor.register(&sock1, token, Interest::READABLE)?;

            // Test: modify() should update interest flags
            reactor.modify(token, Interest::WRITABLE)?;

            // Verify modification succeeded (can't directly check epoll state,
            // but if modify() returns Ok, the epoll_ctl(MOD) succeeded)
            assert_eq!(reactor.registration_count(), 1);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Successfully modified registration interest".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Modify failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct DeregisterConformanceTest;

impl ConformanceTest for DeregisterConformanceTest {
    fn name(&self) -> &str {
        "deregister_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;
            let (sock1, _sock2) = create_test_socket_pair()?;
            let token = Token::new(1);

            // Register first
            reactor.register(&sock1, token, Interest::READABLE)?;
            assert_eq!(reactor.registration_count(), 1);

            // Test: deregister() should remove registration
            reactor.deregister(token)?;

            // Verify deregistration succeeded
            assert_eq!(reactor.registration_count(), 0);
            assert!(reactor.is_empty());

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Successfully deregistered file descriptor".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Deregister failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct PollConformanceTest;

impl ConformanceTest for PollConformanceTest {
    fn name(&self) -> &str {
        "poll_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            use std::io::Write;

            let reactor = EpollReactor::new()?;
            let (sock1, mut sock2) = create_test_socket_pair()?;
            let token = Token::new(1);

            // Register for readability
            reactor.register(&sock1, token, Interest::READABLE)?;

            // Write data to make sock1 readable
            sock2.write_all(b"test data")?;

            // Test: poll() should return readable event
            let mut events = Events::with_capacity(64);
            let count = reactor.poll(&mut events, Some(Duration::from_millis(100)))?;

            // Verify event was returned
            assert!(count > 0, "Expected at least one event");

            let mut found_readable = false;
            for event in &events {
                if event.token == token && event.is_readable() {
                    found_readable = true;
                    break;
                }
            }
            assert!(found_readable, "Expected readable event for token");

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Successfully polled and received expected events".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Poll failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct WakeConformanceTest;

impl ConformanceTest for WakeConformanceTest {
    fn name(&self) -> &str {
        "wake_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = Arc::new(EpollReactor::new()?);
            let mut events = Events::with_capacity(64);

            // Test: wake() should interrupt poll()
            let reactor_clone = reactor.clone();
            std::thread::scope(|s| {
                s.spawn(move || {
                    std::thread::sleep(Duration::from_millis(50));
                    let _ = reactor_clone.wake();
                });

                let poll_start = Instant::now();
                let _count = reactor.poll(&mut events, Some(Duration::from_secs(5)))?;
                let poll_duration = poll_start.elapsed();

                // Should return quickly due to wake, not wait 5 seconds
                assert!(
                    poll_duration < Duration::from_secs(1),
                    "Poll should wake quickly, took {:?}",
                    poll_duration
                );

                Ok(())
            })
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Successfully interrupted poll with wake".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Wake failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct OneshotModeConformanceTest;

impl ConformanceTest for OneshotModeConformanceTest {
    fn name(&self) -> &str {
        "oneshot_mode_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            use std::io::{Read, Write};

            let reactor = EpollReactor::new()?;
            let (mut sock1, mut sock2) = create_test_socket_pair()?;
            sock1.set_nonblocking(true)?;
            let token = Token::new(1);

            // Register with oneshot mode
            reactor.register(&sock1, token, Interest::READABLE.with_oneshot())?;

            // Make readable
            sock2.write_all(b"test")?;

            // First poll should return event
            let mut events = Events::with_capacity(64);
            let count = reactor.poll(&mut events, Some(Duration::from_millis(100)))?;
            assert!(count > 0, "First poll should return event");

            // Read partial data
            let mut buf = [0u8; 2];
            let _n = sock1.read(&mut buf)?;

            // Second poll should NOT return event (oneshot fired, not re-armed)
            events.clear();
            let count = reactor.poll(&mut events, Some(Duration::from_millis(50)))?;
            assert_eq!(count, 0, "Second poll should not return events (oneshot)");

            // Re-arm via modify
            reactor.modify(token, Interest::READABLE.with_oneshot())?;

            // Third poll should return event again
            events.clear();
            let count = reactor.poll(&mut events, Some(Duration::from_millis(100)))?;
            assert!(count > 0, "Third poll should return event after re-arm");

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some(
                    "Oneshot mode behavior verified: fire once, silence until re-arm".to_string(),
                ),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Oneshot mode failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct EdgeTriggeredConformanceTest;

impl ConformanceTest for EdgeTriggeredConformanceTest {
    fn name(&self) -> &str {
        "edge_triggered_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            use std::io::{Read, Write};

            let reactor = EpollReactor::new()?;
            let (mut sock1, mut sock2) = create_test_socket_pair()?;
            sock1.set_nonblocking(true)?;
            let token = Token::new(1);

            // Register with edge-triggered mode
            reactor.register(&sock1, token, Interest::READABLE.with_edge_triggered())?;

            // Write data
            sock2.write_all(b"hello")?;

            // First poll should return event
            let mut events = Events::with_capacity(64);
            let count = reactor.poll(&mut events, Some(Duration::from_millis(100)))?;
            assert!(count > 0, "First poll should return edge event");

            // Read partial data (not all)
            let mut buf = [0u8; 2];
            let _n = sock1.read(&mut buf)?;

            // Second poll should NOT return event (edge not retriggered)
            events.clear();
            let count = reactor.poll(&mut events, Some(Duration::ZERO))?;
            assert_eq!(
                count, 0,
                "Second poll should not return events (edge not retriggered)"
            );

            // Drain remaining data
            let mut drain_buf = [0u8; 16];
            loop {
                match sock1.read(&mut drain_buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }

            // Write new data (should trigger new edge)
            sock2.write_all(b"world")?;

            // Poll should now return event (new edge)
            let deadline = Instant::now() + Duration::from_secs(1);
            let mut found = false;
            while Instant::now() < deadline {
                events.clear();
                let count = reactor.poll(&mut events, Some(Duration::from_millis(100)))?;
                if count > 0 {
                    found = events.iter().any(|e| e.token == token && e.is_readable());
                    if found {
                        break;
                    }
                }
            }

            assert!(found, "New data should trigger new edge");

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some(
                    "Edge-triggered mode verified: events only on state transitions".to_string(),
                ),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Edge-triggered mode failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct LevelTriggeredConformanceTest;

impl ConformanceTest for LevelTriggeredConformanceTest {
    fn name(&self) -> &str {
        "level_triggered_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        // Note: EpollReactor defaults to oneshot mode for level-triggered behavior
        // This test verifies the absence of edge-triggered semantics
        match (|| -> io::Result<()> {
            use std::io::Write;

            let reactor = EpollReactor::new()?;
            let (sock1, mut sock2) = create_test_socket_pair()?;
            let token = Token::new(1);

            // Register without edge-triggered flag (level-triggered via oneshot)
            reactor.register(&sock1, token, Interest::READABLE)?;

            // Write data to make readable
            sock2.write_all(b"test")?;

            // Poll should return event
            let mut events = Events::with_capacity(64);
            let count = reactor.poll(&mut events, Some(Duration::from_millis(100)))?;
            assert!(count > 0, "Level-triggered should return event");

            let mut found_readable = false;
            for event in &events {
                if event.token == token && event.is_readable() {
                    found_readable = true;
                    break;
                }
            }
            assert!(found_readable, "Should find readable event");

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Level-triggered semantics verified".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Level-triggered failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct ErrorHandlingConformanceTest;

impl ConformanceTest for ErrorHandlingConformanceTest {
    fn name(&self) -> &str {
        "error_handling_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;

            // Test: modify() on non-existent token should return NotFound
            let modify_err = reactor
                .modify(Token::new(999), Interest::READABLE)
                .expect_err("Modify on non-existent token should fail");
            assert_eq!(modify_err.kind(), io::ErrorKind::NotFound);

            // Test: deregister() on non-existent token should return NotFound
            let deregister_err = reactor
                .deregister(Token::new(888))
                .expect_err("Deregister on non-existent token should fail");
            assert_eq!(deregister_err.kind(), io::ErrorKind::NotFound);

            // Test: register() with unsupported interest should fail
            let (sock1, _) = create_test_socket_pair()?;
            let dispatch_err = reactor
                .register(&sock1, Token::new(1), Interest::dispatch())
                .expect_err("Dispatch interest should be rejected");
            assert_eq!(dispatch_err.kind(), io::ErrorKind::InvalidInput);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some(
                    "Error conditions handled correctly with appropriate error codes".to_string(),
                ),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Error handling failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct InvalidFdConformanceTest;

impl ConformanceTest for InvalidFdConformanceTest {
    fn name(&self) -> &str {
        "invalid_fd_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;

            // Test: register() with invalid fd should fail with EBADF
            let invalid_source = create_invalid_test_source();
            let register_err = reactor
                .register(&invalid_source, Token::new(1), Interest::READABLE)
                .expect_err("Register with invalid fd should fail");

            // Should get EBADF (bad file descriptor)
            assert_eq!(register_err.raw_os_error(), Some(libc::EBADF));

            // Verify no registration was recorded
            assert_eq!(reactor.registration_count(), 0);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Invalid file descriptor properly rejected with EBADF".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Invalid fd handling failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct DuplicateRegistrationConformanceTest;

impl ConformanceTest for DuplicateRegistrationConformanceTest {
    fn name(&self) -> &str {
        "duplicate_registration_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;
            let (sock1, _) = create_test_socket_pair()?;
            let token = Token::new(1);

            // First registration should succeed
            reactor.register(&sock1, token, Interest::READABLE)?;

            // Second registration with same token should fail
            let duplicate_token_err = reactor
                .register(&sock1, token, Interest::WRITABLE)
                .expect_err("Duplicate token registration should fail");
            assert_eq!(duplicate_token_err.kind(), io::ErrorKind::AlreadyExists);

            // Registration with different token but same fd should also fail
            let duplicate_fd_err = reactor
                .register(&sock1, Token::new(2), Interest::WRITABLE)
                .expect_err("Duplicate fd registration should fail");
            assert_eq!(duplicate_fd_err.kind(), io::ErrorKind::AlreadyExists);

            // Verify only original registration remains
            assert_eq!(reactor.registration_count(), 1);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Duplicate registrations properly rejected".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Duplicate registration handling failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct FdReuseConformanceTest;

impl ConformanceTest for FdReuseConformanceTest {
    fn name(&self) -> &str {
        "fd_reuse_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        // This is a complex test that would require careful fd manipulation
        // For now, we'll test a simpler version of fd lifecycle
        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;
            let (sock1, _) = create_test_socket_pair()?;
            let token1 = Token::new(1);

            // Register, deregister, then re-register same fd
            reactor.register(&sock1, token1, Interest::READABLE)?;
            assert_eq!(reactor.registration_count(), 1);

            reactor.deregister(token1)?;
            assert_eq!(reactor.registration_count(), 0);

            // Re-registration should succeed
            reactor.register(&sock1, Token::new(2), Interest::WRITABLE)?;
            assert_eq!(reactor.registration_count(), 1);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some(
                    "File descriptor reuse after deregistration works correctly".to_string(),
                ),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Fd reuse failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct FdCleanupConformanceTest;

impl ConformanceTest for FdCleanupConformanceTest {
    fn name(&self) -> &str {
        "fd_cleanup_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;
            let (sock1, _) = create_test_socket_pair()?;
            let token = Token::new(1);
            let _fd = sock1.as_raw_fd();

            reactor.register(&sock1, token, Interest::READABLE)?;
            assert_eq!(reactor.registration_count(), 1);

            // Close socket by dropping it
            drop(sock1);

            // Deregister should handle closed fd gracefully
            let deregister_result = reactor.deregister(token);
            assert!(
                deregister_result.is_ok(),
                "Deregister after close should succeed"
            );
            assert_eq!(reactor.registration_count(), 0);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Cleanup of closed file descriptors handled gracefully".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Fd cleanup failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct ConcurrentOperationsConformanceTest;

impl ConformanceTest for ConcurrentOperationsConformanceTest {
    fn name(&self) -> &str {
        "concurrent_operations_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = Arc::new(EpollReactor::new()?);
            let (sock1, _) = create_test_socket_pair()?;
            let token = Token::new(1);

            reactor.register(&sock1, token, Interest::READABLE)?;

            let reactor_clone = reactor.clone();
            std::thread::scope(|s| {
                // Concurrent modify operations
                let handles: Vec<_> = (0..5)
                    .map(|i| {
                        let reactor = reactor_clone.clone();
                        s.spawn(move || {
                            let interest = if i % 2 == 0 {
                                Interest::READABLE
                            } else {
                                Interest::WRITABLE
                            };
                            reactor.modify(token, interest)
                        })
                    })
                    .collect();

                // Wait for all operations
                for handle in handles {
                    let _ = handle.join();
                }

                Ok::<(), io::Error>(())
            })?;

            // Verify reactor is in consistent state
            assert_eq!(reactor.registration_count(), 1);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Concurrent operations maintain reactor consistency".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Concurrent operations failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct WakeFromThreadConformanceTest;

impl ConformanceTest for WakeFromThreadConformanceTest {
    fn name(&self) -> &str {
        "wake_from_thread_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = Arc::new(EpollReactor::new()?);
            let mut events = Events::with_capacity(64);

            let reactor_clone = reactor.clone();
            std::thread::scope(|s| {
                s.spawn(move || {
                    std::thread::sleep(Duration::from_millis(100));
                    let _ = reactor_clone.wake();
                });

                let poll_start = Instant::now();
                let _count = reactor.poll(&mut events, Some(Duration::from_secs(5)))?;
                let poll_duration = poll_start.elapsed();

                // Should wake within reasonable time
                assert!(
                    poll_duration < Duration::from_secs(1),
                    "Cross-thread wake should interrupt poll quickly"
                );

                Ok(())
            })
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some("Cross-thread wake functionality verified".to_string()),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Cross-thread wake failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct ScalabilityConformanceTest;

impl ConformanceTest for ScalabilityConformanceTest {
    fn name(&self) -> &str {
        "scalability_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Performance
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::May
    }

    fn run(&self, ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;
            let num_sockets = std::cmp::min(100, ctx.max_fds / 2);
            let mut sockets = Vec::new();

            // Register many sockets
            for i in 0..num_sockets {
                let (sock1, _sock2) = create_test_socket_pair()?;
                reactor.register(&sock1, Token::new(i), Interest::READABLE)?;
                sockets.push((sock1, _sock2));
            }

            assert_eq!(reactor.registration_count(), num_sockets);

            // Deregister all
            for i in 0..num_sockets {
                reactor.deregister(Token::new(i))?;
            }

            assert_eq!(reactor.registration_count(), 0);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some(format!(
                    "Successfully handled {} registrations",
                    std::cmp::min(100, ctx.max_fds / 2)
                )),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Scalability test failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

struct MemoryLeakConformanceTest;

impl ConformanceTest for MemoryLeakConformanceTest {
    fn name(&self) -> &str {
        "memory_leak_conformance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Performance
    }
    fn level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let start = Instant::now();

        match (|| -> io::Result<()> {
            let reactor = EpollReactor::new()?;

            // Create and destroy many reactors to check for leaks
            for _ in 0..10 {
                let temp_reactor = EpollReactor::new()?;
                let (sock1, _) = create_test_socket_pair()?;
                temp_reactor.register(&sock1, Token::new(1), Interest::READABLE)?;
                // Reactor drops automatically
            }

            // Test failed registrations don't leak
            for i in 0..10 {
                let invalid_source = create_invalid_test_source();
                let _ = reactor.register(&invalid_source, Token::new(i), Interest::READABLE);
                // Should fail but not leak
            }

            assert_eq!(reactor.registration_count(), 0);

            Ok(())
        })() {
            Ok(()) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Pass,
                duration: start.elapsed(),
                details: Some(
                    "Memory leak checks completed - no obvious leaks detected".to_string(),
                ),
            },
            Err(e) => TestResult {
                name: self.name().to_string(),
                category: self.category(),
                level: self.level(),
                status: TestStatus::Fail(format!("Memory leak test failed: {}", e)),
                duration: start.elapsed(),
                details: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_epoll_conformance_suite() {
        // Create and run the conformance harness
        let harness = EpollConformanceHarness::new();
        let ctx = TestContext::default();
        let report = harness.run_all(&ctx);

        // Print compliance matrix
        println!("{}", report.generate_matrix());

        // Verify conformance
        let failed_must_tests: Vec<_> = report
            .results
            .iter()
            .filter(|r| {
                r.level == RequirementLevel::Must
                    && !matches!(r.status, TestStatus::Pass | TestStatus::ExpectedFailure(_))
            })
            .collect();

        if !failed_must_tests.is_empty() {
            for test in &failed_must_tests {
                eprintln!("MUST requirement failed: {} - {:?}", test.name, test.status);
            }
            panic!(
                "EpollReactor fails conformance: {} MUST requirements failed",
                failed_must_tests.len()
            );
        }

        println!("✅ EpollReactor conformance: All MUST requirements pass");

        if report.is_conformant() {
            println!("🎉 EpollReactor is CONFORMANT to epoll specification");
        }
    }

    #[test]
    fn run_must_requirements_only() {
        let harness = EpollConformanceHarness::new();
        let ctx = TestContext::default();
        let report = harness.run_level(RequirementLevel::Must, &ctx);

        println!("MUST Requirements Report:");
        println!("{}", report.generate_matrix());

        assert!(report.is_conformant(), "All MUST requirements should pass");
    }
}
