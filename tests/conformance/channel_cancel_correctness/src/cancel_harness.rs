//! Cancellation test infrastructure for systematic channel conformance testing.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;

use crate::resource_tracking::{ResourceTracker, ResourceLeakError};

/// Configuration for cancellation test scenarios.
#[derive(Debug, Clone)]
pub struct CancelTestHarness {
    /// Maximum duration for a single test.
    pub timeout: Duration,
    /// Delay before triggering cancellation.
    pub cancel_delay: Duration,
    /// Resource leak detection and tracking.
    pub resource_tracker: Arc<ResourceTracker>,
    /// Configuration for high-concurrency stress tests.
    pub stress_config: StressConfig,
    /// Whether to fail fast on first violation.
    pub fail_fast: bool,
    /// Test identification for debugging.
    pub test_id: String,
}

impl Default for CancelTestHarness {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            cancel_delay: Duration::from_millis(10),
            resource_tracker: Arc::new(ResourceTracker::new()),
            stress_config: StressConfig::default(),
            fail_fast: true,
            test_id: "default".to_string(),
        }
    }
}

impl CancelTestHarness {
    /// Create a new harness with custom configuration.
    pub fn new(test_id: impl Into<String>) -> Self {
        Self {
            test_id: test_id.into(),
            ..Default::default()
        }
    }

    /// Set timeout for test execution.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set delay before cancellation trigger.
    pub fn with_cancel_delay(mut self, delay: Duration) -> Self {
        self.cancel_delay = delay;
        self
    }

    /// Set stress testing configuration.
    pub fn with_stress_config(mut self, config: StressConfig) -> Self {
        self.stress_config = config;
        self
    }

    /// Enable or disable fail-fast mode.
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Assert that no resource leaks occurred during the test.
    pub fn assert_no_resource_leaks(&self) -> Result<(), ResourceLeakError> {
        self.resource_tracker.assert_no_leaks()
    }

    /// Reset resource tracking for a new test.
    pub fn reset_tracking(&self) {
        self.resource_tracker.reset();
    }
}

/// Configuration for stress testing scenarios.
#[derive(Debug, Clone)]
pub struct StressConfig {
    /// Number of concurrent operations to run.
    pub concurrency_level: usize,
    /// Number of iterations per operation.
    pub iterations: usize,
    /// Maximum number of operations to cancel.
    pub max_cancellations: usize,
    /// Whether to randomize cancellation timing.
    pub randomize_timing: bool,
}

impl Default for StressConfig {
    fn default() -> Self {
        Self {
            concurrency_level: 10,
            iterations: 100,
            max_cancellations: 50,
            randomize_timing: true,
        }
    }
}

/// Channel types that can be tested for cancellation conformance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChannelType {
    Mpsc,
    Broadcast,
    Watch,
    Oneshot,
}

impl std::fmt::Display for ChannelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelType::Mpsc => write!(f, "mpsc"),
            ChannelType::Broadcast => write!(f, "broadcast"),
            ChannelType::Watch => write!(f, "watch"),
            ChannelType::Oneshot => write!(f, "oneshot"),
        }
    }
}

/// Different cancellation scenarios to test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CancelScenario {
    SendCancel,
    ReceiveCancel,
    DropCancel,
    MultiCancel,
    RaceCondition,
}

impl std::fmt::Display for CancelScenario {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CancelScenario::SendCancel => write!(f, "send_cancel"),
            CancelScenario::ReceiveCancel => write!(f, "receive_cancel"),
            CancelScenario::DropCancel => write!(f, "drop_cancel"),
            CancelScenario::MultiCancel => write!(f, "multi_cancel"),
            CancelScenario::RaceCondition => write!(f, "race_condition"),
        }
    }
}

/// Results from a cancellation conformance test.
#[derive(Debug, Clone)]
pub struct CancelTestResult {
    /// Whether the test passed all requirements.
    pub passed: bool,
    /// Duration the test took to complete.
    pub duration: Duration,
    /// Number of operations that were successfully cancelled.
    pub operations_cancelled: usize,
    /// Number of operations that completed normally.
    pub operations_completed: usize,
    /// Resource usage before the test.
    pub initial_resources: ResourceSnapshot,
    /// Resource usage after the test.
    pub final_resources: ResourceSnapshot,
    /// Any violations detected during the test.
    pub violations: Vec<ProtocolViolation>,
    /// Additional test-specific metrics.
    pub metrics: HashMap<String, f64>,
}

impl CancelTestResult {
    /// Create a new test result.
    pub fn new(passed: bool, duration: Duration) -> Self {
        Self {
            passed,
            duration,
            operations_cancelled: 0,
            operations_completed: 0,
            initial_resources: ResourceSnapshot::default(),
            final_resources: ResourceSnapshot::default(),
            violations: Vec::new(),
            metrics: HashMap::new(),
        }
    }

    /// Add a protocol violation to the result.
    pub fn add_violation(&mut self, violation: ProtocolViolation) {
        self.violations.push(violation);
        self.passed = false;
    }

    /// Add a custom metric to the result.
    pub fn add_metric(&mut self, name: impl Into<String>, value: f64) {
        self.metrics.insert(name.into(), value);
    }

    /// Check if any resource leaks were detected.
    pub fn has_resource_leaks(&self) -> bool {
        self.final_resources.waker_count > self.initial_resources.waker_count ||
        self.final_resources.memory_usage > self.initial_resources.memory_usage + 1024 // 1KB tolerance
    }
}

/// Snapshot of resource usage at a point in time.
#[derive(Debug, Clone, Default)]
pub struct ResourceSnapshot {
    /// Number of active waker registrations.
    pub waker_count: usize,
    /// Estimated memory usage in bytes.
    pub memory_usage: usize,
    /// Timestamp when snapshot was taken.
    pub timestamp: Option<Instant>,
}

/// Protocol violations detected during testing.
#[derive(Debug, Clone)]
pub enum ProtocolViolation {
    /// Cancellation signal was not properly propagated.
    CancelNotPropagated {
        channel_type: ChannelType,
        scenario: CancelScenario,
        details: String,
    },
    /// Resource leak detected (wakers, memory, etc.).
    ResourceLeak {
        resource_type: String,
        leaked_count: usize,
        details: String,
    },
    /// Channel state became inconsistent after cancellation.
    StateInconsistency {
        channel_type: ChannelType,
        expected_state: String,
        actual_state: String,
    },
    /// Operation took too long to respond to cancellation.
    SlowCancellation {
        channel_type: ChannelType,
        scenario: CancelScenario,
        duration: Duration,
        threshold: Duration,
    },
    /// Drop during cancellation caused corruption.
    DropCorruption {
        channel_type: ChannelType,
        details: String,
    },
}

impl std::fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolViolation::CancelNotPropagated { channel_type, scenario, details } => {
                write!(f, "Cancel not propagated in {} {}: {}", channel_type, scenario, details)
            }
            ProtocolViolation::ResourceLeak { resource_type, leaked_count, details } => {
                write!(f, "Resource leak: {} {} leaked - {}", leaked_count, resource_type, details)
            }
            ProtocolViolation::StateInconsistency { channel_type, expected_state, actual_state } => {
                write!(f, "State inconsistency in {}: expected '{}', got '{}'",
                       channel_type, expected_state, actual_state)
            }
            ProtocolViolation::SlowCancellation { channel_type, scenario, duration, threshold } => {
                write!(f, "Slow cancellation in {} {}: took {:?}, threshold {:?}",
                       channel_type, scenario, duration, threshold)
            }
            ProtocolViolation::DropCorruption { channel_type, details } => {
                write!(f, "Drop corruption in {}: {}", channel_type, details)
            }
        }
    }
}

/// Trait for implementing cancellation conformance tests.
pub trait CancelCorrectnessTest {
    /// Name of the test for identification.
    fn test_name(&self) -> &str;

    /// Channel type being tested.
    fn channel_type(&self) -> ChannelType;

    /// Cancellation scenario being tested.
    fn cancel_scenario(&self) -> CancelScenario;

    /// Run the conformance test with the provided harness.
    fn run_test(&self, harness: &CancelTestHarness) -> CancelTestResult;

    /// Optional setup before running the test.
    fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }

    /// Optional cleanup after running the test.
    fn cleanup(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(())
    }
}

/// Test execution engine for running cancellation conformance test suites.
pub struct CancelTestEngine {
    /// All registered conformance tests.
    tests: Vec<Box<dyn CancelCorrectnessTest>>,
    /// Default harness configuration.
    default_harness: CancelTestHarness,
    /// Whether to stop on first failure.
    fail_fast: bool,
}

impl CancelTestEngine {
    /// Create a new test engine.
    pub fn new() -> Self {
        Self {
            tests: Vec::new(),
            default_harness: CancelTestHarness::default(),
            fail_fast: true,
        }
    }

    /// Add a conformance test to the engine.
    pub fn add_test(&mut self, test: Box<dyn CancelCorrectnessTest>) {
        self.tests.push(test);
    }

    /// Set the default harness configuration.
    pub fn with_default_harness(mut self, harness: CancelTestHarness) -> Self {
        self.default_harness = harness;
        self
    }

    /// Set fail-fast behavior.
    pub fn with_fail_fast(mut self, fail_fast: bool) -> Self {
        self.fail_fast = fail_fast;
        self
    }

    /// Run all registered conformance tests.
    pub fn run_all_tests(&self) -> ConformanceTestReport {
        let start_time = Instant::now();
        let mut results = HashMap::new();
        let mut total_violations = 0;
        let mut failed_tests = 0;

        for test in &self.tests {
            let test_id = format!("{}:{}:{}",
                                  test.channel_type(),
                                  test.cancel_scenario(),
                                  test.test_name());

            // Setup test
            if let Err(e) = test.setup() {
                eprintln!("Setup failed for test {}: {}", test_id, e);
                continue;
            }

            // Reset resource tracking
            self.default_harness.reset_tracking();

            // Run test
            let result = test.run_test(&self.default_harness);

            // Cleanup test
            if let Err(e) = test.cleanup() {
                eprintln!("Cleanup failed for test {}: {}", test_id, e);
            }

            // Track results
            if !result.passed {
                failed_tests += 1;
                total_violations += result.violations.len();
            }

            results.insert(test_id.clone(), result);

            // Fail fast if requested
            if self.fail_fast && !results[&test_id].passed {
                break;
            }
        }

        ConformanceTestReport {
            total_tests: self.tests.len(),
            passed_tests: self.tests.len() - failed_tests,
            failed_tests,
            total_violations,
            duration: start_time.elapsed(),
            results,
        }
    }
}

/// Overall report from running the conformance test suite.
#[derive(Debug)]
pub struct ConformanceTestReport {
    /// Total number of tests run.
    pub total_tests: usize,
    /// Number of tests that passed.
    pub passed_tests: usize,
    /// Number of tests that failed.
    pub failed_tests: usize,
    /// Total number of protocol violations detected.
    pub total_violations: usize,
    /// Total time taken for all tests.
    pub duration: Duration,
    /// Individual test results.
    pub results: HashMap<String, CancelTestResult>,
}

impl ConformanceTestReport {
    /// Check if all tests passed.
    pub fn all_passed(&self) -> bool {
        self.failed_tests == 0
    }

    /// Get the pass rate as a percentage.
    pub fn pass_rate(&self) -> f64 {
        if self.total_tests == 0 {
            100.0
        } else {
            (self.passed_tests as f64 / self.total_tests as f64) * 100.0
        }
    }

    /// Print a summary of the test results.
    pub fn print_summary(&self) {
        println!("=== Channel Cancellation Protocol Conformance Report ===");
        println!("Total tests: {}", self.total_tests);
        println!("Passed: {}", self.passed_tests);
        println!("Failed: {}", self.failed_tests);
        println!("Pass rate: {:.1}%", self.pass_rate());
        println!("Total violations: {}", self.total_violations);
        println!("Duration: {:?}", self.duration);

        if !self.all_passed() {
            println!("\n=== Failed Tests ===");
            for (test_id, result) in &self.results {
                if !result.passed {
                    println!("\nTest: {}", test_id);
                    println!("  Duration: {:?}", result.duration);
                    for violation in &result.violations {
                        println!("  VIOLATION: {}", violation);
                    }
                }
            }
        }
    }
}

impl Default for CancelTestEngine {
    fn default() -> Self {
        Self::new()
    }
}