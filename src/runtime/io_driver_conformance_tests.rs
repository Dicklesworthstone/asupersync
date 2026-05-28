//! IoDriver conformance test harness.
//!
//! This module provides comprehensive conformance testing for the IoDriver
//! against event loop contracts, waker management, and reactor bridging requirements.
//!
//! # Conformance Coverage
//!
//! - **Event Loop Contract**: turn() processes I/O events and dispatches wakers correctly
//! - **Registration Contract**: register() adds sources with wakers, returns valid tokens
//! - **Deregistration Contract**: deregister() cleans up sources and prevents resource leaks
//! - **Waker Management**: Token→waker mapping with proper lifecycle and deduplication
//! - **Interest Modification**: modify_interest() changes event monitoring correctly
//! - **Wake Contract**: wake() unblocks polling from other threads safely
//! - **Statistics Contract**: Accurate operation tracking for diagnostics
//! - **Error Handling**: Graceful degradation when reactor operations fail

#![allow(clippy::unnecessary_literal_bound)]

use super::IoDriver;
use crate::runtime::reactor::{Event, Events, Interest, Reactor, Source, Token};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, RawSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub passed: bool,
    pub error_message: Option<String>,
    pub execution_time: Duration,
}

/// Context for conformance test execution.
pub struct TestContext {
    pub test_name: String,
    pub timeout: Duration,
}

impl TestContext {
    pub fn new(test_name: &str) -> Self {
        Self {
            test_name: test_name.to_string(),
            timeout: Duration::from_secs(5),
        }
    }
}

/// Trait defining a conformance test.
pub trait ConformanceTest: Send + Sync {
    fn name(&self) -> &str;
    fn category(&self) -> TestCategory;
    fn requirement_level(&self) -> RequirementLevel;
    fn run(&self, ctx: &TestContext) -> TestResult;
}

/// Mock reactor for testing IoDriver behavior.
#[derive(Debug)]
pub struct MockReactor {
    events: Mutex<Vec<Event>>,
    registrations: Mutex<HashMap<Token, Interest>>,
    poll_calls: AtomicUsize,
    wake_calls: AtomicUsize,
    should_fail_register: AtomicBool,
    should_fail_deregister: AtomicBool,
    should_fail_modify: AtomicBool,
    should_fail_poll: AtomicBool,
    should_fail_wake: AtomicBool,
}

impl MockReactor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            registrations: Mutex::new(HashMap::new()),
            poll_calls: AtomicUsize::new(0),
            wake_calls: AtomicUsize::new(0),
            should_fail_register: AtomicBool::new(false),
            should_fail_deregister: AtomicBool::new(false),
            should_fail_modify: AtomicBool::new(false),
            should_fail_poll: AtomicBool::new(false),
            should_fail_wake: AtomicBool::new(false),
        })
    }

    pub fn push_event(&self, token: Token, interest: Interest) {
        self.events
            .lock()
            .unwrap()
            .push(Event::new(token, interest));
    }

    pub fn poll_calls(&self) -> usize {
        self.poll_calls.load(Ordering::Relaxed)
    }

    pub fn wake_calls(&self) -> usize {
        self.wake_calls.load(Ordering::Relaxed)
    }

    pub fn registration_count(&self) -> usize {
        self.registrations.lock().unwrap().len()
    }

    pub fn is_registered(&self, token: Token) -> bool {
        self.registrations.lock().unwrap().contains_key(&token)
    }

    pub fn set_fail_register(&self, should_fail: bool) {
        self.should_fail_register
            .store(should_fail, Ordering::Relaxed);
    }

    pub fn set_fail_deregister(&self, should_fail: bool) {
        self.should_fail_deregister
            .store(should_fail, Ordering::Relaxed);
    }

    pub fn set_fail_modify(&self, should_fail: bool) {
        self.should_fail_modify
            .store(should_fail, Ordering::Relaxed);
    }

    pub fn set_fail_poll(&self, should_fail: bool) {
        self.should_fail_poll.store(should_fail, Ordering::Relaxed);
    }

    pub fn set_fail_wake(&self, should_fail: bool) {
        self.should_fail_wake.store(should_fail, Ordering::Relaxed);
    }
}

impl Reactor for MockReactor {
    fn register(&self, _source: &dyn Source, token: Token, interest: Interest) -> io::Result<()> {
        if self.should_fail_register.load(Ordering::Relaxed) {
            return Err(io::Error::other("Mock register failure"));
        }

        self.registrations.lock().unwrap().insert(token, interest);
        Ok(())
    }

    fn deregister(&self, token: Token) -> io::Result<()> {
        if self.should_fail_deregister.load(Ordering::Relaxed) {
            return Err(io::Error::other("Mock deregister failure"));
        }

        let removed = self.registrations.lock().unwrap().remove(&token).is_some();
        if removed {
            Ok(())
        } else {
            Err(io::Error::new(ErrorKind::NotFound, "Token not found"))
        }
    }

    fn modify(&self, token: Token, interest: Interest) -> io::Result<()> {
        if self.should_fail_modify.load(Ordering::Relaxed) {
            return Err(io::Error::other("Mock modify failure"));
        }

        let mut registrations = self.registrations.lock().unwrap();
        if let std::collections::hash_map::Entry::Occupied(mut entry) = registrations.entry(token) {
            entry.insert(interest);
            Ok(())
        } else {
            Err(io::Error::new(ErrorKind::NotFound, "Token not found"))
        }
    }

    fn poll(&self, events: &mut Events, _timeout: Option<Duration>) -> io::Result<usize> {
        if self.should_fail_poll.load(Ordering::Relaxed) {
            return Err(io::Error::other("Mock poll failure"));
        }

        self.poll_calls.fetch_add(1, Ordering::Relaxed);

        let mut mock_events = self.events.lock().unwrap();
        let count = mock_events.len();

        events.clear();
        for event in mock_events.drain(..) {
            events.push(event);
        }

        Ok(count)
    }

    fn wake(&self) -> io::Result<()> {
        if self.should_fail_wake.load(Ordering::Relaxed) {
            return Err(io::Error::other("Mock wake failure"));
        }

        self.wake_calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn registration_count(&self) -> usize {
        MockReactor::registration_count(self)
    }
}

/// Mock I/O source for testing.
#[cfg(unix)]
type MockRawSource = RawFd;
#[cfg(windows)]
type MockRawSource = RawSocket;

#[derive(Debug)]
pub struct MockSource {
    raw: MockRawSource,
}

impl MockSource {
    pub fn new(raw: MockRawSource) -> Self {
        Self { raw }
    }
}

#[cfg(unix)]
impl AsRawFd for MockSource {
    fn as_raw_fd(&self) -> RawFd {
        self.raw
    }
}

#[cfg(windows)]
impl AsRawSocket for MockSource {
    fn as_raw_socket(&self) -> RawSocket {
        self.raw
    }
}

/// Test waker that tracks wake calls.
#[derive(Debug, Clone)]
pub struct TestWaker {
    wake_count: Arc<AtomicUsize>,
}

impl TestWaker {
    pub fn new() -> Self {
        Self {
            wake_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn wake_count(&self) -> usize {
        self.wake_count.load(Ordering::Relaxed)
    }

    pub fn into_waker(self) -> Waker {
        let wake_count = Arc::clone(&self.wake_count);

        struct CountingWaker {
            wake_count: Arc<AtomicUsize>,
        }

        impl Wake for CountingWaker {
            fn wake(self: Arc<Self>) {
                self.wake_count.fetch_add(1, Ordering::Relaxed);
            }

            fn wake_by_ref(self: &Arc<Self>) {
                self.wake_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        Arc::new(CountingWaker { wake_count }).into()
    }
}

/// IoDriver conformance test harness.
pub struct IoDriverConformanceHarness {
    tests: Vec<Box<dyn ConformanceTest>>,
}

impl IoDriverConformanceHarness {
    pub fn new() -> Self {
        let mut harness = Self { tests: Vec::new() };
        harness.register_all_tests();
        harness
    }

    fn register_all_tests(&mut self) {
        // Event Loop Contract Tests
        self.tests.push(Box::new(BasicEventLoopTest));
        self.tests.push(Box::new(EventDeduplicationTest));
        self.tests.push(Box::new(MultipleEventsTest));
        self.tests.push(Box::new(TimeoutHandlingTest));

        // Registration Contract Tests
        self.tests.push(Box::new(BasicRegistrationTest));
        self.tests.push(Box::new(RegistrationFailureTest));
        self.tests.push(Box::new(WakerRegistrationTest));

        // Deregistration Contract Tests
        self.tests.push(Box::new(BasicDeregistrationTest));
        self.tests.push(Box::new(DeregistrationCleanupTest));
        self.tests.push(Box::new(DeregisterUnknownTokenTest));

        // Waker Management Tests
        self.tests.push(Box::new(WakerUpdateTest));
        self.tests.push(Box::new(WakerDispatchTest));
        self.tests.push(Box::new(UnknownTokenHandlingTest));

        // Interest Modification Tests
        self.tests.push(Box::new(InterestModificationTest));
        self.tests.push(Box::new(ModifyUnknownTokenTest));

        // Wake Contract Tests
        self.tests.push(Box::new(WakeTest));
        self.tests.push(Box::new(WakeFailureTest));

        // Statistics Tests
        self.tests.push(Box::new(StatisticsAccuracyTest));
        self.tests.push(Box::new(WakerCountTest));

        // Error Handling Tests
        self.tests.push(Box::new(PollFailureHandlingTest));
        self.tests.push(Box::new(ReactorFailureRecoveryTest));

        // Performance Tests
        self.tests.push(Box::new(TurnPerformanceTest));
        self.tests.push(Box::new(RegistrationPerformanceTest));
    }

    pub fn run_all_tests(&self) -> ConformanceReport {
        let mut results = Vec::new();

        for test in &self.tests {
            let ctx = TestContext::new(test.name());
            let start = Instant::now();
            let mut result = test.run(&ctx);
            result.execution_time = start.elapsed();
            results.push(result);
        }

        ConformanceReport { results }
    }
}

/// Comprehensive test report with compliance metrics.
pub struct ConformanceReport {
    pub results: Vec<TestResult>,
}

impl ConformanceReport {
    pub fn pass_rate(&self) -> f64 {
        if self.results.is_empty() {
            return 1.0;
        }
        let passed = self.results.iter().filter(|r| r.passed).count();
        passed as f64 / self.results.len() as f64
    }

    pub fn must_pass_rate(&self) -> f64 {
        let must_tests: Vec<_> = self
            .results
            .iter()
            .filter(|r| r.level == RequirementLevel::Must)
            .collect();
        if must_tests.is_empty() {
            return 1.0;
        }
        let passed = must_tests.iter().filter(|r| r.passed).count();
        passed as f64 / must_tests.len() as f64
    }

    pub fn generate_compliance_matrix(&self) -> String {
        let mut matrix = String::new();
        matrix.push_str("# IoDriver Event Loop Conformance Report\n\n");
        matrix.push_str("| Test | Category | Level | Status | Time |\n");
        matrix.push_str("|------|----------|-------|--------|------|\n");

        for result in &self.results {
            let status = if result.passed {
                "✅ PASS"
            } else {
                "❌ FAIL"
            };
            let level = match result.level {
                RequirementLevel::Must => "MUST",
                RequirementLevel::Should => "SHOULD",
                RequirementLevel::May => "MAY",
            };
            let category = match result.category {
                TestCategory::Unit => "Unit",
                TestCategory::Integration => "Integration",
                TestCategory::EdgeCase => "EdgeCase",
                TestCategory::Performance => "Performance",
            };

            matrix.push_str(&format!(
                "| {} | {} | {} | {} | {:.2}ms |\n",
                result.name,
                category,
                level,
                status,
                result.execution_time.as_millis()
            ));
        }

        matrix.push_str("\n## Summary\n");
        matrix.push_str(&format!(
            "- **Overall Pass Rate**: {:.1}%\n",
            self.pass_rate() * 100.0
        ));
        matrix.push_str(&format!(
            "- **MUST Requirements**: {:.1}%\n",
            self.must_pass_rate() * 100.0
        ));
        matrix.push_str(&format!("- **Total Tests**: {}\n", self.results.len()));

        matrix
    }
}

// Test implementations below...

/// Test: Basic event loop processes events correctly.
struct BasicEventLoopTest;

impl ConformanceTest for BasicEventLoopTest {
    fn name(&self) -> &str {
        "basic_event_loop"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(42);

        // Register source
        let token = driver
            .register(&source, Interest::READABLE, test_waker.clone().into_waker())
            .unwrap();

        // Push event
        reactor.push_event(token, Interest::READABLE);

        // Process events
        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        let passed = event_count == 1 && test_waker.wake_count() == 1 && reactor.poll_calls() == 1;

        let error_message = if !passed {
            Some(format!(
                "Expected 1 event, 1 wake, 1 poll call. Got: events={}, wakes={}, polls={}",
                event_count,
                test_waker.wake_count(),
                reactor.poll_calls()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Event deduplication in single poll cycle.
struct EventDeduplicationTest;

impl ConformanceTest for EventDeduplicationTest {
    fn name(&self) -> &str {
        "event_deduplication"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(43);

        let token = driver
            .register(&source, Interest::READABLE, test_waker.clone().into_waker())
            .unwrap();

        // Push multiple events with same token
        reactor.push_event(token, Interest::READABLE);
        reactor.push_event(token, Interest::READABLE);
        reactor.push_event(token, Interest::WRITABLE);

        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        // Should get 3 events but only 1 wake (deduplicated)
        let passed = event_count == 3 && test_waker.wake_count() == 1;

        let error_message = if !passed {
            Some(format!(
                "Expected 3 events, 1 wake. Got: events={}, wakes={}",
                event_count,
                test_waker.wake_count()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Multiple different tokens handled correctly.
struct MultipleEventsTest;

impl ConformanceTest for MultipleEventsTest {
    fn name(&self) -> &str {
        "multiple_events"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let waker1 = TestWaker::new();
        let waker2 = TestWaker::new();
        let source1 = MockSource::new(44);
        let source2 = MockSource::new(45);

        let token1 = driver
            .register(&source1, Interest::READABLE, waker1.clone().into_waker())
            .unwrap();
        let token2 = driver
            .register(&source2, Interest::WRITABLE, waker2.clone().into_waker())
            .unwrap();

        // Push events for both tokens
        reactor.push_event(token1, Interest::READABLE);
        reactor.push_event(token2, Interest::WRITABLE);

        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        let passed = event_count == 2 && waker1.wake_count() == 1 && waker2.wake_count() == 1;

        let error_message = if !passed {
            Some(format!(
                "Expected 2 events, 1 wake each. Got: events={}, waker1={}, waker2={}",
                event_count,
                waker1.wake_count(),
                waker2.wake_count()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Timeout handling in event loop.
struct TimeoutHandlingTest;

impl ConformanceTest for TimeoutHandlingTest {
    fn name(&self) -> &str {
        "timeout_handling"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        // No events - should timeout immediately
        let start = Instant::now();
        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();
        let elapsed = start.elapsed();

        let passed = event_count == 0 && elapsed < Duration::from_millis(50);

        let error_message = if !passed {
            Some(format!(
                "Expected 0 events, quick return. Got: events={}, elapsed={:?}",
                event_count, elapsed
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: elapsed,
        }
    }
}

/// Test: Basic registration returns valid token.
struct BasicRegistrationTest;

impl ConformanceTest for BasicRegistrationTest {
    fn name(&self) -> &str {
        "basic_registration"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(46);

        let result = driver.register(&source, Interest::READABLE, test_waker.into_waker());

        let passed = match result.as_ref() {
            Ok(token) => {
                reactor.is_registered(*token)
                    && driver.stats().registrations == 1
                    && !driver.is_empty()
            }
            Err(_) => false,
        };

        let error_message = if !passed {
            Some(format!(
                "Registration failed or state inconsistent. Result: {:?}, registrations: {}",
                result,
                driver.stats().registrations
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Registration failure handling.
struct RegistrationFailureTest;

impl ConformanceTest for RegistrationFailureTest {
    fn name(&self) -> &str {
        "registration_failure"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        reactor.set_fail_register(true);
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(47);

        let result = driver.register(&source, Interest::READABLE, test_waker.into_waker());

        let passed = result.is_err()
            && driver.is_empty()  // No waker should be stored
            && driver.stats().registrations == 0;

        let error_message = if !passed {
            Some(format!(
                "Expected failure with clean state. Got: {:?}, empty={}, registrations={}",
                result,
                driver.is_empty(),
                driver.stats().registrations
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Waker-only registration.
struct WakerRegistrationTest;

impl ConformanceTest for WakerRegistrationTest {
    fn name(&self) -> &str {
        "waker_registration"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor);

        let test_waker = TestWaker::new();
        let _token = driver.register_waker(test_waker.into_waker());

        let passed =
            driver.waker_count() == 1 && driver.stats().registrations == 1 && !driver.is_empty();

        let error_message = if !passed {
            Some(format!(
                "Waker registration failed. Count: {}, registrations: {}",
                driver.waker_count(),
                driver.stats().registrations
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Basic deregistration cleans up correctly.
struct BasicDeregistrationTest;

impl ConformanceTest for BasicDeregistrationTest {
    fn name(&self) -> &str {
        "basic_deregistration"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(48);

        let token = driver
            .register(&source, Interest::READABLE, test_waker.into_waker())
            .unwrap();
        let result = driver.deregister(token);

        let passed = result.is_ok()
            && !reactor.is_registered(token)
            && driver.is_empty()
            && driver.stats().deregistrations == 1;

        let error_message = if !passed {
            Some(format!(
                "Deregistration failed or incomplete. Result: {:?}, registered: {}, empty: {}",
                result,
                reactor.is_registered(token),
                driver.is_empty()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Deregistration cleans up even on reactor failure.
struct DeregistrationCleanupTest;

impl ConformanceTest for DeregistrationCleanupTest {
    fn name(&self) -> &str {
        "deregistration_cleanup"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(49);

        let token = driver
            .register(&source, Interest::READABLE, test_waker.into_waker())
            .unwrap();

        // Make reactor fail
        reactor.set_fail_deregister(true);
        let result = driver.deregister(token);

        // Should clean up driver state even if reactor fails
        let passed = result.is_err()
            && driver.is_empty()  // Driver state cleaned up
            && driver.stats().deregistrations == 1;

        let error_message = if !passed {
            Some(format!(
                "Expected reactor failure but driver cleanup. Result: {:?}, empty: {}",
                result,
                driver.is_empty()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Deregistering unknown token handled gracefully.
struct DeregisterUnknownTokenTest;

impl ConformanceTest for DeregisterUnknownTokenTest {
    fn name(&self) -> &str {
        "deregister_unknown_token"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor);

        let unknown_token = Token::new(999);
        let result = driver.deregister(unknown_token);

        // Should handle gracefully (NotFound is treated as success)
        let passed = result.is_ok();

        let error_message = if !passed {
            Some(format!(
                "Expected success for unknown token. Got: {:?}",
                result
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Waker update functionality.
struct WakerUpdateTest;

impl ConformanceTest for WakerUpdateTest {
    fn name(&self) -> &str {
        "waker_update"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let old_waker = TestWaker::new();
        let new_waker = TestWaker::new();
        let source = MockSource::new(50);

        let token = driver
            .register(&source, Interest::READABLE, old_waker.clone().into_waker())
            .unwrap();
        let update_result = driver.update_waker(token, new_waker.clone().into_waker());

        // Test that new waker is used
        reactor.push_event(token, Interest::READABLE);
        let _event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        let passed = update_result && old_waker.wake_count() == 0 && new_waker.wake_count() == 1;

        let error_message = if !passed {
            Some(format!(
                "Waker update failed. Update: {}, old_wakes: {}, new_wakes: {}",
                update_result,
                old_waker.wake_count(),
                new_waker.wake_count()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Waker dispatch correctness.
struct WakerDispatchTest;

impl ConformanceTest for WakerDispatchTest {
    fn name(&self) -> &str {
        "waker_dispatch"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(51);

        let token = driver
            .register(&source, Interest::READABLE, test_waker.clone().into_waker())
            .unwrap();
        reactor.push_event(token, Interest::READABLE);

        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        let passed = event_count == 1
            && test_waker.wake_count() == 1
            && driver.stats().wakers_dispatched == 1;

        let error_message = if !passed {
            Some(format!(
                "Dispatch failed. Events: {}, wakes: {}, dispatched: {}",
                event_count,
                test_waker.wake_count(),
                driver.stats().wakers_dispatched
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Unknown tokens handled without panic.
struct UnknownTokenHandlingTest;

impl ConformanceTest for UnknownTokenHandlingTest {
    fn name(&self) -> &str {
        "unknown_token_handling"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        // Push event with unknown token
        let unknown_token = Token::new(999);
        reactor.push_event(unknown_token, Interest::READABLE);

        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        let passed = event_count == 1
            && driver.stats().unknown_tokens == 1
            && driver.stats().wakers_dispatched == 0;

        let error_message = if !passed {
            Some(format!(
                "Unknown token handling failed. Events: {}, unknown: {}, dispatched: {}",
                event_count,
                driver.stats().unknown_tokens,
                driver.stats().wakers_dispatched
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Interest modification works correctly.
struct InterestModificationTest;

impl ConformanceTest for InterestModificationTest {
    fn name(&self) -> &str {
        "interest_modification"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(52);

        let token = driver
            .register(&source, Interest::READABLE, test_waker.into_waker())
            .unwrap();
        let modify_result = driver.modify_interest(token, Interest::WRITABLE);

        let passed = modify_result.is_ok();

        let error_message = if !passed {
            Some(format!("Interest modification failed: {:?}", modify_result))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Modifying unknown token handled gracefully.
struct ModifyUnknownTokenTest;

impl ConformanceTest for ModifyUnknownTokenTest {
    fn name(&self) -> &str {
        "modify_unknown_token"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor);

        let unknown_token = Token::new(999);
        let result = driver.modify_interest(unknown_token, Interest::WRITABLE);

        let passed = result
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::NotFound);

        let error_message = if !passed {
            Some(format!("Expected NotFound error. Got: {:?}", result))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Wake function works correctly.
struct WakeTest;

impl ConformanceTest for WakeTest {
    fn name(&self) -> &str {
        "wake"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let driver = IoDriver::new(reactor.clone());

        let result = driver.wake();

        let passed = result.is_ok() && reactor.wake_calls() == 1;

        let error_message = if !passed {
            Some(format!(
                "Wake failed. Result: {:?}, calls: {}",
                result,
                reactor.wake_calls()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Wake failure handling.
struct WakeFailureTest;

impl ConformanceTest for WakeFailureTest {
    fn name(&self) -> &str {
        "wake_failure"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        reactor.set_fail_wake(true);
        let driver = IoDriver::new(reactor);

        let result = driver.wake();

        let passed = result.is_err();

        let error_message = if !passed {
            Some(format!("Expected wake failure. Got: {:?}", result))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Statistics accuracy.
struct StatisticsAccuracyTest;

impl ConformanceTest for StatisticsAccuracyTest {
    fn name(&self) -> &str {
        "statistics_accuracy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(53);

        // Register
        let token = driver
            .register(&source, Interest::READABLE, test_waker.into_waker())
            .unwrap();

        // Push event and turn
        reactor.push_event(token, Interest::READABLE);
        let _event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        // Deregister
        let _result = driver.deregister(token);

        let stats = driver.stats();
        let passed = stats.registrations == 1
            && stats.deregistrations == 1
            && stats.polls == 1
            && stats.events_received == 1
            && stats.wakers_dispatched == 1
            && stats.unknown_tokens == 0;

        let error_message = if !passed {
            Some(format!("Statistics inaccurate: {:?}", stats))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Waker count tracking.
struct WakerCountTest;

impl ConformanceTest for WakerCountTest {
    fn name(&self) -> &str {
        "waker_count"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor);

        assert_eq!(driver.waker_count(), 0);
        assert!(driver.is_empty());

        let test_waker = TestWaker::new();
        let _token = driver.register_waker(test_waker.into_waker());

        let mid_count = driver.waker_count();
        let mid_empty = driver.is_empty();

        driver.deregister_waker(_token);

        let final_count = driver.waker_count();
        let final_empty = driver.is_empty();

        let passed = mid_count == 1 && !mid_empty && final_count == 0 && final_empty;

        let error_message = if !passed {
            Some(format!(
                "Waker count tracking failed. Mid: {}/{}, Final: {}/{}",
                mid_count, mid_empty, final_count, final_empty
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Poll failure handling preserves state.
struct PollFailureHandlingTest;

impl ConformanceTest for PollFailureHandlingTest {
    fn name(&self) -> &str {
        "poll_failure_handling"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        let test_waker = TestWaker::new();
        let source = MockSource::new(54);

        let _token = driver
            .register(&source, Interest::READABLE, test_waker.into_waker())
            .unwrap();

        // Make poll fail
        reactor.set_fail_poll(true);
        let result = driver.turn(Some(Duration::ZERO));

        // Driver state should be preserved
        let passed = result.is_err() && driver.waker_count() == 1 && !driver.is_empty();

        let error_message = if !passed {
            Some(format!(
                "Poll failure corrupted state. Result: {:?}, count: {}",
                result,
                driver.waker_count()
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Reactor failure recovery.
struct ReactorFailureRecoveryTest;

impl ConformanceTest for ReactorFailureRecoveryTest {
    fn name(&self) -> &str {
        "reactor_failure_recovery"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        // Register successfully
        let test_waker = TestWaker::new();
        let source = MockSource::new(55);
        let token = driver
            .register(&source, Interest::READABLE, test_waker.into_waker())
            .unwrap();

        // Make modifications fail
        reactor.set_fail_modify(true);
        let modify_result = driver.modify_interest(token, Interest::WRITABLE);

        // Driver should remain functional
        reactor.set_fail_modify(false);
        reactor.push_event(token, Interest::READABLE);
        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();

        let passed = modify_result.is_err() && event_count == 1;

        let error_message = if !passed {
            Some(format!(
                "Recovery failed. Modify: {:?}, events: {}",
                modify_result, event_count
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Turn performance under load.
struct TurnPerformanceTest;

impl ConformanceTest for TurnPerformanceTest {
    fn name(&self) -> &str {
        "turn_performance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Performance
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::May
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor.clone());

        // Register many wakers
        let mut tokens = Vec::new();
        for i in 0..1000 {
            let test_waker = TestWaker::new();
            let source = MockSource::new(i);
            if let Ok(token) = driver.register(&source, Interest::READABLE, test_waker.into_waker())
            {
                tokens.push(token);
            }
        }

        // Push events for all
        for token in &tokens {
            reactor.push_event(*token, Interest::READABLE);
        }

        let start = Instant::now();
        let event_count = driver.turn(Some(Duration::ZERO)).unwrap();
        let elapsed = start.elapsed();

        // Should process 1000 events in reasonable time
        let passed = event_count == 1000 && elapsed < Duration::from_millis(100);

        let error_message = if !passed {
            Some(format!(
                "Performance inadequate. Events: {}, time: {:?}",
                event_count, elapsed
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: elapsed,
        }
    }
}

/// Test: Registration performance under load.
struct RegistrationPerformanceTest;

impl ConformanceTest for RegistrationPerformanceTest {
    fn name(&self) -> &str {
        "registration_performance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Performance
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::May
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut driver = IoDriver::new(reactor);

        let start = Instant::now();

        // Register 1000 sources
        for i in 0..1000 {
            let test_waker = TestWaker::new();
            let source = MockSource::new(i);
            let _token = driver.register(&source, Interest::READABLE, test_waker.into_waker());
        }

        let elapsed = start.elapsed();

        // Should register 1000 sources quickly
        let passed = driver.waker_count() == 1000 && elapsed < Duration::from_millis(100);

        let error_message = if !passed {
            Some(format!(
                "Registration performance poor. Count: {}, time: {:?}",
                driver.waker_count(),
                elapsed
            ))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: elapsed,
        }
    }
}
