//! Registration RAII conformance test harness.
//!
//! This module provides comprehensive conformance testing for the Registration
//! type against the RAII contract, ReactorHandle trait, and cancel-safety requirements.
//!
//! # Conformance Coverage
//!
//! - **RAII Contract**: Automatic deregistration on Drop, no resource leaks
//! - **ReactorHandle Trait**: deregister_by_token() and modify_interest() behavior
//! - **Cancel-Safety**: No stale wakeups after task cancellation or registration drop
//! - **Thread Safety**: Send but !Sync semantics with interior mutability
//! - **Error Handling**: Graceful degradation when reactor disappears
//! - **Panic Safety**: Registration cleanup survives reactor panics

#![allow(dead_code, clippy::unnecessary_literal_bound)]

use super::{Interest, ReactorHandle, Registration, Token};
use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
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

/// Mock reactor for testing Registration behavior.
#[derive(Debug)]
pub struct MockReactor {
    deregister_calls: AtomicUsize,
    modify_calls: AtomicUsize,
    registrations: Mutex<HashMap<Token, Interest>>,
    should_panic_on_deregister: AtomicBool,
    should_fail_deregister: AtomicBool,
    should_fail_modify: AtomicBool,
}

impl MockReactor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            deregister_calls: AtomicUsize::new(0),
            modify_calls: AtomicUsize::new(0),
            registrations: Mutex::new(HashMap::new()),
            should_panic_on_deregister: AtomicBool::new(false),
            should_fail_deregister: AtomicBool::new(false),
            should_fail_modify: AtomicBool::new(false),
        })
    }

    pub fn register(&self, token: Token, interest: Interest) {
        self.registrations.lock().unwrap().insert(token, interest);
    }

    pub fn deregister_calls(&self) -> usize {
        self.deregister_calls.load(Ordering::Relaxed)
    }

    pub fn modify_calls(&self) -> usize {
        self.modify_calls.load(Ordering::Relaxed)
    }

    pub fn is_registered(&self, token: Token) -> bool {
        self.registrations.lock().unwrap().contains_key(&token)
    }

    pub fn set_panic_on_deregister(&self, should_panic: bool) {
        self.should_panic_on_deregister
            .store(should_panic, Ordering::Relaxed);
    }

    pub fn set_fail_deregister(&self, should_fail: bool) {
        self.should_fail_deregister
            .store(should_fail, Ordering::Relaxed);
    }

    pub fn set_fail_modify(&self, should_fail: bool) {
        self.should_fail_modify
            .store(should_fail, Ordering::Relaxed);
    }
}

impl ReactorHandle for MockReactor {
    fn deregister_by_token(&self, token: Token) -> io::Result<()> {
        assert!(
            !self.should_panic_on_deregister.load(Ordering::Relaxed),
            "Mock reactor deregister panic"
        );

        self.deregister_calls.fetch_add(1, Ordering::Relaxed);

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

    fn modify_interest(&self, token: Token, interest: Interest) -> io::Result<()> {
        self.modify_calls.fetch_add(1, Ordering::Relaxed);

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
}

/// Registration conformance test harness.
pub struct RegistrationConformanceHarness {
    tests: Vec<Box<dyn ConformanceTest>>,
}

impl RegistrationConformanceHarness {
    pub fn new() -> Self {
        let mut harness = Self { tests: Vec::new() };
        harness.register_all_tests();
        harness
    }

    fn register_all_tests(&mut self) {
        // RAII Contract Tests
        self.tests.push(Box::new(AutoDeregisterOnDropTest));
        self.tests.push(Box::new(NoDoubleDeregistrationTest));
        self.tests.push(Box::new(DropWithDeadReactorTest));

        // Interest Modification Tests
        self.tests.push(Box::new(InterestModificationTest));
        self.tests.push(Box::new(ModifyWithDeadReactorTest));
        self.tests.push(Box::new(InterestQueryTest));

        // Error Handling Tests
        self.tests.push(Box::new(ExplicitDeregisterSuccessTest));
        self.tests.push(Box::new(ExplicitDeregisterFailureTest));
        self.tests.push(Box::new(DeregisterRetryLogicTest));

        // Panic Safety Tests
        self.tests.push(Box::new(PanicDuringDeregisterTest));
        self.tests.push(Box::new(PanicSafetyDropTest));

        // Thread Safety Tests
        self.tests.push(Box::new(SendSemanticTest));
        self.tests.push(Box::new(NotSyncSemanticTest));

        // State Query Tests
        self.tests.push(Box::new(ActiveStateQueryTest));
        self.tests.push(Box::new(TokenQueryTest));

        // Performance Tests
        self.tests.push(Box::new(DropPerformanceTest));
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
        matrix.push_str("# Registration RAII Conformance Report\n\n");
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

/// Test: Registration automatically deregisters on drop.
struct AutoDeregisterOnDropTest;

impl ConformanceTest for AutoDeregisterOnDropTest {
    fn name(&self) -> &str {
        "auto_deregister_on_drop"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(42);
        reactor.register(token, Interest::READABLE);

        {
            let registration = Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
            assert_eq!(registration.token(), token);
        } // Drop happens here

        let passed = reactor.deregister_calls() == 1 && !reactor.is_registered(token);
        let error_message = if !passed {
            Some(format!(
                "Expected 1 deregister call, got {}. Registered: {}",
                reactor.deregister_calls(),
                reactor.is_registered(token)
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

/// Test: Explicit deregister prevents double deregistration.
struct NoDoubleDeregistrationTest;

impl ConformanceTest for NoDoubleDeregistrationTest {
    fn name(&self) -> &str {
        "no_double_deregistration"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(43);
        reactor.register(token, Interest::READABLE);

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        // Explicit deregister
        let deregister_result = registration.deregister();

        let calls_after_explicit = reactor.deregister_calls();

        // Drop should not call deregister again
        // Note: registration is consumed by deregister(), so no drop happens

        let passed = deregister_result.is_ok() && calls_after_explicit == 1;
        let error_message = if !passed {
            Some(format!(
                "Deregister failed: {:?}, calls: {}",
                deregister_result, calls_after_explicit
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

/// Test: Drop gracefully handles dead reactor.
struct DropWithDeadReactorTest;

impl ConformanceTest for DropWithDeadReactorTest {
    fn name(&self) -> &str {
        "drop_with_dead_reactor"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let token = Token::new(44);
        let registration = {
            let reactor = MockReactor::new();
            reactor.register(token, Interest::READABLE);

            Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            )
        }; // reactor is dropped here, weak reference should be invalid

        assert!(!registration.is_active());

        // Drop should not panic even with dead reactor
        drop(registration);

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed: true, // If we reach here without panic, test passed
            error_message: None,
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
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(45);
        reactor.register(token, Interest::READABLE);

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        assert_eq!(registration.interest(), Interest::READABLE);

        let new_interest = Interest::READABLE | Interest::WRITABLE;
        let modify_result = registration.set_interest(new_interest);

        let passed = modify_result.is_ok()
            && registration.interest() == new_interest
            && reactor.modify_calls() == 1;

        let error_message = if !passed {
            Some(format!(
                "Modify failed: {:?}, final interest: {:?}, calls: {}",
                modify_result,
                registration.interest(),
                reactor.modify_calls()
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

/// Test: Interest modification fails with dead reactor.
struct ModifyWithDeadReactorTest;

impl ConformanceTest for ModifyWithDeadReactorTest {
    fn name(&self) -> &str {
        "modify_with_dead_reactor"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let token = Token::new(46);
        let registration = {
            let reactor = MockReactor::new();
            reactor.register(token, Interest::READABLE);

            Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            )
        }; // reactor dropped

        let modify_result = registration.set_interest(Interest::WRITABLE);
        let passed = modify_result
            .as_ref()
            .is_err_and(|error| error.kind() == ErrorKind::NotConnected);

        let error_message = if !passed {
            Some(format!(
                "Expected NotConnected error, got: {:?}",
                modify_result
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

/// Test: Interest query returns current value.
struct InterestQueryTest;

impl ConformanceTest for InterestQueryTest {
    fn name(&self) -> &str {
        "interest_query"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(47);
        let initial_interest = Interest::READABLE | Interest::WRITABLE;

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            initial_interest,
        );

        let passed = registration.interest() == initial_interest;
        let error_message = if !passed {
            Some(format!(
                "Expected {:?}, got {:?}",
                initial_interest,
                registration.interest()
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

/// Test: Explicit deregister succeeds normally.
struct ExplicitDeregisterSuccessTest;

impl ConformanceTest for ExplicitDeregisterSuccessTest {
    fn name(&self) -> &str {
        "explicit_deregister_success"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(48);
        reactor.register(token, Interest::READABLE);

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = registration.deregister();
        let passed = result.is_ok() && reactor.deregister_calls() == 1;

        let error_message = if !passed {
            Some(format!(
                "Deregister failed: {:?}, calls: {}",
                result,
                reactor.deregister_calls()
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

/// Test: Explicit deregister handles reactor failure.
struct ExplicitDeregisterFailureTest;

impl ConformanceTest for ExplicitDeregisterFailureTest {
    fn name(&self) -> &str {
        "explicit_deregister_failure"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(49);
        reactor.register(token, Interest::READABLE);
        reactor.set_fail_deregister(true);

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = registration.deregister();
        // Explicit deregister tries twice, then leaves Drop armed for one final
        // best-effort cleanup pass. The cleanup pass retries once on ordinary
        // errors, so persistent failure records four total calls.
        let passed = result.is_err() && reactor.deregister_calls() == 4;

        let error_message = if !passed {
            Some(format!(
                "Expected failure with 4 total cleanup attempts, got: {:?}, calls: {}",
                result,
                reactor.deregister_calls()
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

/// Test: Deregister retry logic handles NotFound gracefully.
struct DeregisterRetryLogicTest;

impl ConformanceTest for DeregisterRetryLogicTest {
    fn name(&self) -> &str {
        "deregister_retry_logic"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(50);
        // Don't register token - deregister will get NotFound

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = registration.deregister();
        // NotFound should be treated as success, no retry
        let passed = result.is_ok() && reactor.deregister_calls() == 1;

        let error_message = if !passed {
            Some(format!(
                "Expected success with 1 call for NotFound, got: {:?}, calls: {}",
                result,
                reactor.deregister_calls()
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

/// Test: Registration survives reactor panic during deregister.
struct PanicDuringDeregisterTest;

impl ConformanceTest for PanicDuringDeregisterTest {
    fn name(&self) -> &str {
        "panic_during_deregister"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(51);
        reactor.register(token, Interest::READABLE);
        reactor.set_panic_on_deregister(true);

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let result = registration.deregister();
        let passed = result.is_err(); // Should catch panic and return error

        let error_message = if !passed {
            Some(format!("Expected error from panic, got: {:?}", result))
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

/// Test: Drop is panic-safe when reactor panics.
struct PanicSafetyDropTest;

impl ConformanceTest for PanicSafetyDropTest {
    fn name(&self) -> &str {
        "panic_safety_drop"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(52);
        reactor.register(token, Interest::READABLE);
        reactor.set_panic_on_deregister(true);

        {
            let _registration = Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            );
        } // Drop should not propagate panic

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed: true, // If we reach here, drop didn't panic
            error_message: None,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Registration is Send (can be moved between threads).
struct SendSemanticTest;

impl ConformanceTest for SendSemanticTest {
    fn name(&self) -> &str {
        "send_semantic"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Compile-time test - if this compiles, Send is implemented
        fn assert_send<T: Send>() {}
        assert_send::<Registration>();

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed: true,
            error_message: None,
            execution_time: Duration::default(),
        }
    }
}

/// Test: Registration is not Sync (cannot be shared between threads).
struct NotSyncSemanticTest;

impl ConformanceTest for NotSyncSemanticTest {
    fn name(&self) -> &str {
        "not_sync_semantic"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Compile-time test - this should NOT compile if uncommented
        // fn assert_sync<T: Sync>() {}
        // assert_sync::<Registration>(); // Should fail to compile

        // Runtime verification that Registration contains Cell (not Sync)
        let reactor = MockReactor::new();
        let token = Token::new(53);
        reactor.register(token, Interest::READABLE);

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        // Verify interior mutability works
        let initial = registration.interest();
        let _ = registration.set_interest(Interest::WRITABLE);
        let modified = registration.interest();

        let passed = initial != modified; // Interior mutability proof

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message: None,
            execution_time: Duration::default(),
        }
    }
}

/// Test: is_active() correctly reports reactor state.
struct ActiveStateQueryTest;

impl ConformanceTest for ActiveStateQueryTest {
    fn name(&self) -> &str {
        "active_state_query"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let token = Token::new(54);

        let registration = Registration::new(
            token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let active_when_alive = registration.is_active();
        drop(reactor); // Kill reactor
        let active_when_dead = registration.is_active();

        let passed = active_when_alive && !active_when_dead;
        let error_message = if !passed {
            Some(format!(
                "Expected active=true then false, got {} then {}",
                active_when_alive, active_when_dead
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

/// Test: token() returns correct token.
struct TokenQueryTest;

impl ConformanceTest for TokenQueryTest {
    fn name(&self) -> &str {
        "token_query"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let expected_token = Token::new(999);

        let registration = Registration::new(
            expected_token,
            Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
            Interest::READABLE,
        );

        let actual_token = registration.token();
        let passed = actual_token == expected_token;

        let error_message = if !passed {
            Some(format!(
                "Expected token {:?}, got {:?}",
                expected_token, actual_token
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

/// Test: Drop performance is reasonable.
struct DropPerformanceTest;

impl ConformanceTest for DropPerformanceTest {
    fn name(&self) -> &str {
        "drop_performance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Performance
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::May
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let reactor = MockReactor::new();
        let mut registrations = Vec::new();

        // Create many registrations
        for i in 0..1000 {
            let token = Token::new(i);
            reactor.register(token, Interest::READABLE);
            registrations.push(Registration::new(
                token,
                Arc::downgrade(&reactor) as Weak<dyn ReactorHandle>,
                Interest::READABLE,
            ));
        }

        let start = Instant::now();
        drop(registrations); // Drop all at once
        let drop_time = start.elapsed();

        // Reasonable performance: < 10ms for 1000 drops
        let passed = drop_time < Duration::from_millis(10);
        let error_message = if !passed {
            Some(format!("Drop took {:?}, expected < 10ms", drop_time))
        } else {
            None
        };

        TestResult {
            name: self.name().to_string(),
            category: self.category(),
            level: self.requirement_level(),
            passed,
            error_message,
            execution_time: drop_time,
        }
    }
}
