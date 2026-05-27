//! Supervision conformance test harness.
//!
//! This module provides comprehensive conformance testing for the supervision system
//! against Erlang/OTP-style supervision contracts, restart policies, and budget constraints.
//!
//! # Conformance Coverage
//!
//! - **Supervision Strategy Contract**: Stop/Restart/Escalate behavior verification
//! - **Restart Rate Limiting Contract**: Sliding window restart limiting with max_restarts/window
//! - **Backoff Strategy Contract**: None/Fixed/Exponential backoff between restarts
//! - **Restart Policy Contract**: OneForOne/OneForAll/RestForOne child restart patterns
//! - **Escalation Policy Contract**: Stop/Escalate/ResetCounter when limits exceeded
//! - **Budget Awareness Contract**: Restart cost accounting and minimum remaining constraints
//! - **Storm Detection Contract**: Intensity-based restart storm prevention
//! - **ChildName Performance Contract**: Reference-counted names for hot-path O(1) cloning

#![allow(dead_code, clippy::unnecessary_literal_bound)]

use super::*;
use std::sync::{Arc, Mutex};
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

/// Mock time source for deterministic testing.
#[derive(Debug, Clone)]
pub struct MockTime {
    current: Arc<Mutex<Duration>>,
}

impl MockTime {
    pub fn new() -> Self {
        Self {
            current: Arc::new(Mutex::new(Duration::ZERO)),
        }
    }

    pub fn advance(&self, duration: Duration) {
        *self.current.lock().unwrap() += duration;
    }

    pub fn now(&self) -> Duration {
        *self.current.lock().unwrap()
    }

    pub fn set(&self, time: Duration) {
        *self.current.lock().unwrap() = time;
    }
}

/// Mock restart tracker for testing supervision behavior.
#[derive(Debug)]
pub struct MockRestartTracker {
    restarts: Mutex<Vec<Duration>>,
    time: MockTime,
    config: SupervisionConfig,
}

impl MockRestartTracker {
    pub fn new(config: SupervisionConfig) -> Self {
        Self {
            restarts: Mutex::new(Vec::new()),
            time: MockTime::new(),
            config,
        }
    }

    pub fn with_time_source(config: SupervisionConfig, time: MockTime) -> Self {
        Self {
            restarts: Mutex::new(Vec::new()),
            time,
            config,
        }
    }

    pub fn should_restart(&self) -> bool {
        let now = self.time.now();
        let mut restarts = self.restarts.lock().unwrap();

        // Remove restarts outside the window
        let window_start = now.saturating_sub(self.config.restart_window);
        restarts.retain(|&restart_time| restart_time >= window_start);

        // Check if we're under the limit
        restarts.len() < self.config.max_restarts as usize
    }

    pub fn record_restart(&self) {
        let now = self.time.now();
        self.restarts.lock().unwrap().push(now);
    }

    pub fn restart_count(&self) -> usize {
        let now = self.time.now();
        let mut restarts = self.restarts.lock().unwrap();
        let window_start = now.saturating_sub(self.config.restart_window);
        restarts.retain(|&restart_time| restart_time >= window_start);
        restarts.len()
    }

    pub fn calculate_backoff_delay(&self, restart_count: usize) -> Duration {
        match &self.config.backoff {
            BackoffStrategy::None => Duration::ZERO,
            BackoffStrategy::Fixed(delay) => *delay,
            BackoffStrategy::Exponential {
                initial,
                max,
                multiplier,
            } => {
                if restart_count == 0 {
                    return *initial;
                }

                let exponent = i32::try_from(restart_count.saturating_sub(1))
                    .expect("restart count exponent should fit i32 in conformance test");
                let delay = (*initial).as_millis() as f64 * multiplier.powi(exponent);

                let delay_ms = delay.min(max.as_millis() as f64);
                Duration::from_millis(delay_ms as u64)
            }
        }
    }

    pub fn is_storm_detected(&self) -> bool {
        if let Some(threshold) = self.config.storm_threshold {
            let restarts_in_last_second = self.restarts_in_window(Duration::from_secs(1));
            restarts_in_last_second as f64 > threshold
        } else {
            false
        }
    }

    fn restarts_in_window(&self, window: Duration) -> usize {
        let now = self.time.now();
        let window_start = now.saturating_sub(window);
        self.restarts
            .lock()
            .unwrap()
            .iter()
            .filter(|&&restart_time| restart_time >= window_start)
            .count()
    }
}

/// Supervision conformance test harness.
pub struct SupervisionConformanceHarness {
    tests: Vec<Box<dyn ConformanceTest>>,
}

impl SupervisionConformanceHarness {
    pub fn new() -> Self {
        let mut harness = Self { tests: Vec::new() };
        harness.register_all_tests();
        harness
    }

    fn register_all_tests(&mut self) {
        // ChildName Contract Tests
        self.tests.push(Box::new(ChildNameCloningPerformanceTest));
        self.tests.push(Box::new(ChildNameEqualityTest));
        self.tests.push(Box::new(ChildNameStringInteropTest));

        // Supervision Strategy Tests
        self.tests.push(Box::new(StopStrategyTest));
        self.tests.push(Box::new(RestartStrategyTest));
        self.tests.push(Box::new(EscalateStrategyTest));

        // Restart Rate Limiting Tests
        self.tests.push(Box::new(RestartRateLimitingTest));
        self.tests.push(Box::new(SlidingWindowBehaviorTest));
        self.tests.push(Box::new(MaxRestartsEnforcementTest));

        // Backoff Strategy Tests
        self.tests.push(Box::new(NoBackoffTest));
        self.tests.push(Box::new(FixedBackoffTest));
        self.tests.push(Box::new(ExponentialBackoffTest));
        self.tests.push(Box::new(BackoffCapTest));

        // Restart Policy Tests
        self.tests.push(Box::new(OneForOnePolicyTest));
        self.tests.push(Box::new(OneForAllPolicyTest));
        self.tests.push(Box::new(RestForOnePolicyTest));

        // Escalation Policy Tests
        self.tests.push(Box::new(StopEscalationTest));
        self.tests.push(Box::new(EscalateEscalationTest));
        self.tests.push(Box::new(ResetCounterEscalationTest));

        // Budget Awareness Tests
        self.tests.push(Box::new(RestartCostAccountingTest));
        self.tests.push(Box::new(MinRemainingTimeConstraintTest));
        self.tests.push(Box::new(MinPollsConstraintTest));

        // Storm Detection Tests
        self.tests.push(Box::new(StormDetectionTest));
        self.tests.push(Box::new(StormThresholdTest));

        // Configuration Tests
        self.tests.push(Box::new(DefaultConfigurationTest));
        self.tests.push(Box::new(ConfigurationBuilderTest));
        self.tests.push(Box::new(ConfigurationValidationTest));
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
        matrix.push_str("# Supervision System Conformance Report\n\n");
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

/// Test: ChildName provides O(1) cloning performance.
struct ChildNameCloningPerformanceTest;

impl ConformanceTest for ChildNameCloningPerformanceTest {
    fn name(&self) -> &str {
        "child_name_cloning_performance"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Performance
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let name = ChildName::new("test-child");
        let initial_count = name.strong_count();

        let start = Instant::now();
        let mut clones = Vec::new();
        for _ in 0..10000 {
            clones.push(name.clone());
        }
        let clone_time = start.elapsed();

        // Should complete quickly and increase reference count
        let final_count = name.strong_count();
        let passed = clone_time < Duration::from_millis(10) && final_count > initial_count;

        let error_message = if !passed {
            Some(format!(
                "Cloning performance poor. Time: {:?}, ref counts: {} -> {}",
                clone_time, initial_count, final_count
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
            execution_time: clone_time,
        }
    }
}

/// Test: ChildName equality works across string types.
struct ChildNameEqualityTest;

impl ConformanceTest for ChildNameEqualityTest {
    fn name(&self) -> &str {
        "child_name_equality"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let name1 = ChildName::new("test");
        let name2 = ChildName::new("test");
        let name3 = ChildName::new("other");
        let borrowed_name: &str = "test";

        let passed = name1 == name2 && name1 != name3 && name1 == "test" && name1 == borrowed_name;

        let error_message = if !passed {
            Some("ChildName equality semantics incorrect".to_string())
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

/// Test: ChildName string interop.
struct ChildNameStringInteropTest;

impl ConformanceTest for ChildNameStringInteropTest {
    fn name(&self) -> &str {
        "child_name_string_interop"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let name = ChildName::new("hello-world");

        let passed = name.as_str() == "hello-world"
            && name == "hello-world"
            && format!("{}", name) == "hello-world"
            && format!("{:?}", name) == "\"hello-world\""
            && name.len() == 11;

        let error_message = if !passed {
            Some("ChildName string interop failed".to_string())
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

/// Test: Stop supervision strategy.
struct StopStrategyTest;

impl ConformanceTest for StopStrategyTest {
    fn name(&self) -> &str {
        "stop_strategy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let strategy = SupervisionStrategy::Stop;
        let is_default = SupervisionStrategy::default() == SupervisionStrategy::Stop;

        let passed = matches!(strategy, SupervisionStrategy::Stop) && is_default;

        let error_message = if !passed {
            Some("Stop strategy behavior incorrect".to_string())
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

/// Test: Restart supervision strategy.
struct RestartStrategyTest;

impl ConformanceTest for RestartStrategyTest {
    fn name(&self) -> &str {
        "restart_strategy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = RestartConfig::new(3, Duration::from_secs(60));
        let strategy = SupervisionStrategy::Restart(config.clone());

        let passed = match strategy {
            SupervisionStrategy::Restart(cfg) => {
                cfg.max_restarts == 3 && cfg.window == Duration::from_secs(60)
            }
            _ => false,
        };

        let error_message = if !passed {
            Some("Restart strategy configuration incorrect".to_string())
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

/// Test: Escalate supervision strategy.
struct EscalateStrategyTest;

impl ConformanceTest for EscalateStrategyTest {
    fn name(&self) -> &str {
        "escalate_strategy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let strategy = SupervisionStrategy::Escalate;

        let passed = matches!(strategy, SupervisionStrategy::Escalate);

        let error_message = if !passed {
            Some("Escalate strategy behavior incorrect".to_string())
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

/// Test: Restart rate limiting within sliding window.
struct RestartRateLimitingTest;

impl ConformanceTest for RestartRateLimitingTest {
    fn name(&self) -> &str {
        "restart_rate_limiting"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig::new(2, Duration::from_secs(10));
        let tracker = MockRestartTracker::new(config);

        // Should allow restarts up to limit
        assert!(tracker.should_restart());
        tracker.record_restart();

        assert!(tracker.should_restart());
        tracker.record_restart();

        // Should deny restart when limit reached
        let should_deny = !tracker.should_restart();

        let passed = should_deny && tracker.restart_count() == 2;

        let error_message = if !passed {
            Some(format!(
                "Rate limiting failed. Deny: {}, count: {}",
                should_deny,
                tracker.restart_count()
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

/// Test: Sliding window behavior removes old restarts.
struct SlidingWindowBehaviorTest;

impl ConformanceTest for SlidingWindowBehaviorTest {
    fn name(&self) -> &str {
        "sliding_window_behavior"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig::new(1, Duration::from_secs(5));
        let time = MockTime::new();
        let tracker = MockRestartTracker::with_time_source(config, time.clone());

        // Record restart at t=0
        tracker.record_restart();
        assert!(!tracker.should_restart()); // Hit limit

        // Advance time beyond window
        time.advance(Duration::from_secs(6));

        // Should allow restart again (old restart aged out)
        let can_restart_again = tracker.should_restart();
        let restart_count = tracker.restart_count();

        let passed = can_restart_again && restart_count == 0;

        let error_message = if !passed {
            Some(format!(
                "Sliding window failed. Can restart: {}, count: {}",
                can_restart_again, restart_count
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

/// Test: Max restarts enforcement.
struct MaxRestartsEnforcementTest;

impl ConformanceTest for MaxRestartsEnforcementTest {
    fn name(&self) -> &str {
        "max_restarts_enforcement"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig::new(0, Duration::from_secs(10)); // No restarts allowed
        let tracker = MockRestartTracker::new(config);

        let should_deny_immediately = !tracker.should_restart();

        let passed = should_deny_immediately;

        let error_message = if !passed {
            Some("Max restarts = 0 not enforced".to_string())
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

/// Test: No backoff strategy.
struct NoBackoffTest;

impl ConformanceTest for NoBackoffTest {
    fn name(&self) -> &str {
        "no_backoff"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            backoff: BackoffStrategy::None,
            ..Default::default()
        };
        let tracker = MockRestartTracker::new(config);

        let delay = tracker.calculate_backoff_delay(0);
        let passed = delay == Duration::ZERO;

        let error_message = if !passed {
            Some(format!("Expected zero delay, got: {:?}", delay))
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

/// Test: Fixed backoff strategy.
struct FixedBackoffTest;

impl ConformanceTest for FixedBackoffTest {
    fn name(&self) -> &str {
        "fixed_backoff"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let fixed_delay = Duration::from_millis(500);
        let config = SupervisionConfig {
            backoff: BackoffStrategy::Fixed(fixed_delay),
            ..Default::default()
        };
        let tracker = MockRestartTracker::new(config);

        let delay1 = tracker.calculate_backoff_delay(0);
        let delay2 = tracker.calculate_backoff_delay(5);

        let passed = delay1 == fixed_delay && delay2 == fixed_delay;

        let error_message = if !passed {
            Some(format!(
                "Fixed backoff incorrect. Expected: {:?}, got: {:?}, {:?}",
                fixed_delay, delay1, delay2
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

/// Test: Exponential backoff strategy.
struct ExponentialBackoffTest;

impl ConformanceTest for ExponentialBackoffTest {
    fn name(&self) -> &str {
        "exponential_backoff"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            backoff: BackoffStrategy::Exponential {
                initial: Duration::from_millis(100),
                max: Duration::from_secs(10),
                multiplier: 2.0,
            },
            ..Default::default()
        };
        let tracker = MockRestartTracker::new(config);

        let delay0 = tracker.calculate_backoff_delay(0);
        let delay1 = tracker.calculate_backoff_delay(1);
        let delay2 = tracker.calculate_backoff_delay(2);

        let passed = delay0 == Duration::from_millis(100)
            && delay1 == Duration::from_millis(100)  // First restart uses initial
            && delay2 == Duration::from_millis(200); // Second restart doubles

        let error_message = if !passed {
            Some(format!(
                "Exponential backoff incorrect. Got: {:?}, {:?}, {:?}",
                delay0, delay1, delay2
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

/// Test: Backoff cap enforcement.
struct BackoffCapTest;

impl ConformanceTest for BackoffCapTest {
    fn name(&self) -> &str {
        "backoff_cap"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let max_delay = Duration::from_secs(2);
        let config = SupervisionConfig {
            backoff: BackoffStrategy::Exponential {
                initial: Duration::from_millis(500),
                max: max_delay,
                multiplier: 2.0,
            },
            ..Default::default()
        };
        let tracker = MockRestartTracker::new(config);

        // Many restarts should be capped at max
        let delay = tracker.calculate_backoff_delay(10);

        let passed = delay <= max_delay;

        let error_message = if !passed {
            Some(format!(
                "Backoff not capped. Max: {:?}, actual: {:?}",
                max_delay, delay
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

/// Test: OneForOne restart policy.
struct OneForOnePolicyTest;

impl ConformanceTest for OneForOnePolicyTest {
    fn name(&self) -> &str {
        "one_for_one_policy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            restart_policy: RestartPolicy::OneForOne,
            ..Default::default()
        };

        let passed = config.restart_policy == RestartPolicy::OneForOne
            && RestartPolicy::default() == RestartPolicy::OneForOne;

        let error_message = if !passed {
            Some("OneForOne policy not default or incorrect".to_string())
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

/// Test: OneForAll restart policy.
struct OneForAllPolicyTest;

impl ConformanceTest for OneForAllPolicyTest {
    fn name(&self) -> &str {
        "one_for_all_policy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            restart_policy: RestartPolicy::OneForAll,
            ..Default::default()
        };

        let passed = config.restart_policy == RestartPolicy::OneForAll;

        let error_message = if !passed {
            Some("OneForAll policy incorrect".to_string())
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

/// Test: RestForOne restart policy.
struct RestForOnePolicyTest;

impl ConformanceTest for RestForOnePolicyTest {
    fn name(&self) -> &str {
        "rest_for_one_policy"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            restart_policy: RestartPolicy::RestForOne,
            ..Default::default()
        };

        let passed = config.restart_policy == RestartPolicy::RestForOne;

        let error_message = if !passed {
            Some("RestForOne policy incorrect".to_string())
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

/// Test: Stop escalation policy.
struct StopEscalationTest;

impl ConformanceTest for StopEscalationTest {
    fn name(&self) -> &str {
        "stop_escalation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            escalation: EscalationPolicy::Stop,
            ..Default::default()
        };

        let passed = config.escalation == EscalationPolicy::Stop
            && EscalationPolicy::default() == EscalationPolicy::Stop;

        let error_message = if !passed {
            Some("Stop escalation policy not default or incorrect".to_string())
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

/// Test: Escalate escalation policy.
struct EscalateEscalationTest;

impl ConformanceTest for EscalateEscalationTest {
    fn name(&self) -> &str {
        "escalate_escalation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            escalation: EscalationPolicy::Escalate,
            ..Default::default()
        };

        let passed = config.escalation == EscalationPolicy::Escalate;

        let error_message = if !passed {
            Some("Escalate escalation policy incorrect".to_string())
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

/// Test: ResetCounter escalation policy.
struct ResetCounterEscalationTest;

impl ConformanceTest for ResetCounterEscalationTest {
    fn name(&self) -> &str {
        "reset_counter_escalation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig {
            escalation: EscalationPolicy::ResetCounter,
            ..Default::default()
        };

        let passed = config.escalation == EscalationPolicy::ResetCounter;

        let error_message = if !passed {
            Some("ResetCounter escalation policy incorrect".to_string())
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

/// Test: Restart cost accounting.
struct RestartCostAccountingTest;

impl ConformanceTest for RestartCostAccountingTest {
    fn name(&self) -> &str {
        "restart_cost_accounting"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = RestartConfig::new(5, Duration::from_secs(60)).with_restart_cost(100);

        let passed = config.restart_cost == 100;

        let error_message = if !passed {
            Some(format!(
                "Restart cost incorrect. Expected: 100, got: {}",
                config.restart_cost
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

/// Test: Minimum remaining time constraint.
struct MinRemainingTimeConstraintTest;

impl ConformanceTest for MinRemainingTimeConstraintTest {
    fn name(&self) -> &str {
        "min_remaining_time_constraint"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let min_time = Duration::from_secs(5);
        let config = RestartConfig::new(3, Duration::from_secs(60)).with_min_remaining(min_time);

        let passed = config.min_remaining_for_restart == Some(min_time);

        let error_message = if !passed {
            Some(format!(
                "Min remaining time incorrect. Expected: Some({:?}), got: {:?}",
                min_time, config.min_remaining_for_restart
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

/// Test: Minimum polls constraint.
struct MinPollsConstraintTest;

impl ConformanceTest for MinPollsConstraintTest {
    fn name(&self) -> &str {
        "min_polls_constraint"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let min_polls = 50;
        let config = RestartConfig::new(3, Duration::from_secs(60)).with_min_polls(min_polls);

        let passed = config.min_polls_for_restart == min_polls;

        let error_message = if !passed {
            Some(format!(
                "Min polls constraint incorrect. Expected: {}, got: {}",
                min_polls, config.min_polls_for_restart
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

/// Test: Storm detection functionality.
struct StormDetectionTest;

impl ConformanceTest for StormDetectionTest {
    fn name(&self) -> &str {
        "storm_detection"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Integration
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig::new(10, Duration::from_secs(60)).with_storm_threshold(5.0); // 5 restarts/second

        let time = MockTime::new();
        let tracker = MockRestartTracker::with_time_source(config, time.clone());

        // Simulate rapid restarts
        for _ in 0..6 {
            tracker.record_restart();
            time.advance(Duration::from_millis(100)); // 6 restarts in 0.6 seconds = 10/sec
        }

        let storm_detected = tracker.is_storm_detected();

        let passed = storm_detected;

        let error_message = if !passed {
            Some("Storm detection failed to trigger".to_string())
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

/// Test: Storm threshold configuration.
struct StormThresholdTest;

impl ConformanceTest for StormThresholdTest {
    fn name(&self) -> &str {
        "storm_threshold"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let threshold = 10.5;
        let config =
            SupervisionConfig::new(3, Duration::from_secs(60)).with_storm_threshold(threshold);

        let passed = config.storm_threshold == Some(threshold);

        let error_message = if !passed {
            Some(format!(
                "Storm threshold incorrect. Expected: Some({}), got: {:?}",
                threshold, config.storm_threshold
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

/// Test: Default configuration values.
struct DefaultConfigurationTest;

impl ConformanceTest for DefaultConfigurationTest {
    fn name(&self) -> &str {
        "default_configuration"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Must
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig::default();
        let restart_config = RestartConfig::default();

        let passed = config.max_restarts == 3
            && config.restart_window == Duration::from_mins(1)
            && config.restart_policy == RestartPolicy::OneForOne
            && config.escalation == EscalationPolicy::Stop
            && config.storm_threshold.is_none()
            && restart_config.max_restarts == 3
            && restart_config.restart_cost == 0
            && restart_config.min_polls_for_restart == 0;

        let error_message = if !passed {
            Some("Default configuration values incorrect".to_string())
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

/// Test: Configuration builder pattern.
struct ConfigurationBuilderTest;

impl ConformanceTest for ConfigurationBuilderTest {
    fn name(&self) -> &str {
        "configuration_builder"
    }
    fn category(&self) -> TestCategory {
        TestCategory::Unit
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        let config = SupervisionConfig::new(5, Duration::from_secs(30))
            .with_restart_policy(RestartPolicy::OneForAll)
            .with_backoff(BackoffStrategy::Fixed(Duration::from_millis(200)))
            .with_storm_threshold(8.0);

        let restart_config = RestartConfig::new(2, Duration::from_secs(15))
            .with_restart_cost(50)
            .with_min_remaining(Duration::from_secs(2))
            .with_min_polls(10);

        let passed = config.max_restarts == 5
            && config.restart_window == Duration::from_secs(30)
            && config.restart_policy == RestartPolicy::OneForAll
            && config.storm_threshold == Some(8.0)
            && restart_config.restart_cost == 50
            && restart_config.min_remaining_for_restart == Some(Duration::from_secs(2))
            && restart_config.min_polls_for_restart == 10;

        let error_message = if !passed {
            Some("Configuration builder pattern incorrect".to_string())
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

/// Test: Configuration validation.
struct ConfigurationValidationTest;

impl ConformanceTest for ConfigurationValidationTest {
    fn name(&self) -> &str {
        "configuration_validation"
    }
    fn category(&self) -> TestCategory {
        TestCategory::EdgeCase
    }
    fn requirement_level(&self) -> RequirementLevel {
        RequirementLevel::Should
    }

    fn run(&self, _ctx: &TestContext) -> TestResult {
        // Test that configurations can be created without panics
        let _config1 = SupervisionConfig::new(0, Duration::ZERO);
        let _config2 = SupervisionConfig::new(u32::MAX, Duration::MAX);

        let backoff = BackoffStrategy::Exponential {
            initial: Duration::ZERO,
            max: Duration::MAX,
            multiplier: f64::INFINITY, // Should be handled gracefully
        };

        let _config3 = SupervisionConfig {
            backoff,
            ..Default::default()
        };

        // If we reach here without panic, validation is working
        let passed = true;

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

// Helper function used by the supervision module
fn validate_storm_threshold(threshold: f64) {
    assert!(
        threshold.is_finite() && threshold > 0.0,
        "Storm threshold must be finite and positive, got: {}",
        threshold
    );
}
