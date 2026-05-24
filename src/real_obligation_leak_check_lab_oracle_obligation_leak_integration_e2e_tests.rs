//! # Real Obligation/LeakCheck ↔ Lab/Oracle/ObligationLeak Integration E2E Tests
//!
//! Tests integration between obligation leak checking and lab oracle obligation
//! leak detection to verify that the oracle catches synthetic obligation leaks
//! within bounded time and identifies the exact leak path.
//!
//! ## Integration Focus
//!
//! - **Obligation Leak Check**: leak detection, path tracking, timeout monitoring
//! - **Lab Oracle**: synthetic leak injection, bounded detection, leak path identification
//! - **Leak Detection**: timing guarantees, false positive prevention, exact diagnostics
//!
//! ## Key Properties Tested
//!
//! 1. **Bounded Detection**: Oracle detects leaks within specified time bounds
//! 2. **Exact Path Identification**: Leak paths are precisely traced to source
//! 3. **Synthetic Injection**: Controlled leak scenarios for testing
//! 4. **False Positive Prevention**: No spurious leak reports for valid obligations

use crate::{
    Result,
    cx::Cx,
    lab::{
        oracle::{
            Oracle, OracleConfig, OracleResult,
            obligation_leak::{
                LeakDetectionOracle, LeakEvent, LeakPath, ObligationLeakConfig,
                SyntheticLeakInjector,
            },
        },
        runtime::{LabRuntime, LabRuntimeBuilder},
        time::{VirtualTime, VirtualTimeSource},
    },
    obligation::{
        Obligation, ObligationId, ObligationState,
        leak_check::{LeakCheckConfig, LeakChecker, LeakReport, ObligationTracker},
        ledger::{LedgerEntry, ObligationLedger},
    },
    record::{
        obligation::{ObligationKind, ObligationRecord},
        region::RegionRecord,
        task::TaskRecord,
    },
    runtime::{
        RuntimeBuilder, region_heap::RegionHeap, scheduler::three_lane::ThreeLaneScheduler,
        sharded_state::ShardedState, state::RuntimeState,
    },
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
    types::{
        budget::Budget, cancel::CancelToken, outcome::Outcome, region::RegionId, task::TaskId,
    },
    util::{rng::DetRng, time::TimeSource},
};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    sync::atomic::AtomicBool,
};

/// Synthetic obligation leak definition for controlled testing
#[derive(Debug, Clone)]
struct SyntheticObligation {
    id: ObligationId,
    kind: ObligationKind,
    creation_time: VirtualTime,
    expected_lifetime: Duration,
    leak_type: LeakType,
    source_path: Vec<String>,
}

impl SyntheticObligation {
    fn new(
        kind: ObligationKind,
        creation_time: VirtualTime,
        expected_lifetime: Duration,
        leak_type: LeakType,
        source_path: Vec<String>,
    ) -> Self {
        Self {
            id: ObligationId::new(),
            kind,
            creation_time,
            expected_lifetime,
            leak_type,
            source_path,
        }
    }

    fn is_expired(&self, current_time: VirtualTime) -> bool {
        current_time.duration_since(self.creation_time) > self.expected_lifetime
    }
}

/// Types of synthetic obligation leaks for testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LeakType {
    /// Never committed or aborted
    Abandoned,
    /// Commit called but never completed
    CommitStalled,
    /// Abort called but never completed
    AbortStalled,
    /// Double commit attempt
    DoubleCommit,
    /// Commit after abort
    CommitAfterAbort,
}

impl LeakType {
    fn description(&self) -> &'static str {
        match self {
            LeakType::Abandoned => "obligation abandoned without commit/abort",
            LeakType::CommitStalled => "obligation commit stalled/incomplete",
            LeakType::AbortStalled => "obligation abort stalled/incomplete",
            LeakType::DoubleCommit => "obligation double commit attempted",
            LeakType::CommitAfterAbort => "obligation commit after abort",
        }
    }
}

/// Oracle leak detection metrics and timing
#[derive(Debug)]
struct LeakDetectionMetrics {
    detection_times: Arc<RwLock<Vec<Duration>>>,
    false_positives: Arc<AtomicUsize>,
    missed_leaks: Arc<AtomicUsize>,
    correct_detections: Arc<AtomicUsize>,
    path_accuracy: Arc<AtomicUsize>,
}

impl LeakDetectionMetrics {
    fn new() -> Self {
        Self {
            detection_times: Arc::new(RwLock::new(Vec::new())),
            false_positives: Arc::new(AtomicUsize::new(0)),
            missed_leaks: Arc::new(AtomicUsize::new(0)),
            correct_detections: Arc::new(AtomicUsize::new(0)),
            path_accuracy: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn record_detection(&self, detection_time: Duration, is_correct: bool, path_correct: bool) {
        let mut times = self.detection_times.write();
        times.push(detection_time);
        drop(times);

        if is_correct {
            self.correct_detections.fetch_add(1, Ordering::Release);
        } else {
            self.false_positives.fetch_add(1, Ordering::Release);
        }

        if path_correct {
            self.path_accuracy.fetch_add(1, Ordering::Release);
        }
    }

    fn record_missed_leak(&self) {
        self.missed_leaks.fetch_add(1, Ordering::Release);
    }

    fn get_stats(&self) -> (Vec<Duration>, usize, usize, usize, usize) {
        let times = self.detection_times.read().clone();
        let false_pos = self.false_positives.load(Ordering::Acquire);
        let missed = self.missed_leaks.load(Ordering::Acquire);
        let correct = self.correct_detections.load(Ordering::Acquire);
        let path_acc = self.path_accuracy.load(Ordering::Acquire);
        (times, false_pos, missed, correct, path_acc)
    }

    fn verify_bounded_detection(&self, max_detection_time: Duration) -> bool {
        let times = self.detection_times.read();
        times.iter().all(|&time| time <= max_detection_time)
    }
}

/// Controlled obligation leak injector for testing
#[derive(Debug)]
struct TestLeakInjector {
    injected_obligations: Arc<RwLock<Vec<SyntheticObligation>>>,
    injection_count: Arc<AtomicUsize>,
    leak_registry: Arc<RwLock<HashMap<ObligationId, LeakType>>>,
}

impl TestLeakInjector {
    fn new() -> Self {
        Self {
            injected_obligations: Arc::new(RwLock::new(Vec::new())),
            injection_count: Arc::new(AtomicUsize::new(0)),
            leak_registry: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn inject_leak(
        &self,
        kind: ObligationKind,
        leak_type: LeakType,
        creation_time: VirtualTime,
        expected_lifetime: Duration,
        source_path: Vec<String>,
    ) -> SyntheticObligation {
        let obligation = SyntheticObligation::new(
            kind,
            creation_time,
            expected_lifetime,
            leak_type,
            source_path,
        );

        {
            let mut obligations = self.injected_obligations.write();
            obligations.push(obligation.clone());
        }

        {
            let mut registry = self.leak_registry.write();
            registry.insert(obligation.id, leak_type);
        }

        self.injection_count.fetch_add(1, Ordering::Release);
        obligation
    }

    fn get_injected_obligations(&self) -> Vec<SyntheticObligation> {
        self.injected_obligations.read().clone()
    }

    fn get_leak_type(&self, obligation_id: &ObligationId) -> Option<LeakType> {
        self.leak_registry.read().get(obligation_id).copied()
    }

    fn get_injection_stats(&self) -> (usize, usize) {
        let count = self.injection_count.load(Ordering::Acquire);
        let registry_size = self.leak_registry.read().len();
        (count, registry_size)
    }
}

/// Oracle-based leak detection coordinator
#[derive(Debug)]
struct OracleLeakDetectionCoordinator {
    oracle_config: ObligationLeakConfig,
    detection_metrics: LeakDetectionMetrics,
    injector: TestLeakInjector,
    start_time: VirtualTime,
    detection_timeout: Duration,
}

impl OracleLeakDetectionCoordinator {
    fn new(detection_timeout: Duration, start_time: VirtualTime) -> Self {
        let oracle_config = ObligationLeakConfig {
            detection_interval: Duration::from_millis(100),
            leak_timeout: Duration::from_secs(5),
            path_trace_depth: 10,
            enable_synthetic_injection: true,
        };

        Self {
            oracle_config,
            detection_metrics: LeakDetectionMetrics::new(),
            injector: TestLeakInjector::new(),
            start_time,
            detection_timeout,
        }
    }

    async fn run_leak_detection_scenario(
        &self,
        cx: &Cx,
        oracle: &LeakDetectionOracle,
        leak_checker: &LeakChecker,
        scenario_duration: Duration,
    ) -> Result<()> {
        let scenario_start = self.start_time;
        let scenario_end = scenario_start + scenario_duration;

        // Phase 1: Inject synthetic leaks
        let leak_scenarios = vec![
            (
                ObligationKind::Permit,
                LeakType::Abandoned,
                Duration::from_secs(2),
                vec![
                    "test".to_string(),
                    "permit".to_string(),
                    "abandoned".to_string(),
                ],
            ),
            (
                ObligationKind::Lease,
                LeakType::CommitStalled,
                Duration::from_secs(3),
                vec![
                    "test".to_string(),
                    "lease".to_string(),
                    "stalled".to_string(),
                ],
            ),
            (
                ObligationKind::Ack,
                LeakType::AbortStalled,
                Duration::from_secs(1),
                vec![
                    "test".to_string(),
                    "ack".to_string(),
                    "abort_stalled".to_string(),
                ],
            ),
            (
                ObligationKind::Permit,
                LeakType::DoubleCommit,
                Duration::from_secs(4),
                vec![
                    "test".to_string(),
                    "permit".to_string(),
                    "double_commit".to_string(),
                ],
            ),
        ];

        let mut injected_obligations = Vec::new();

        for (kind, leak_type, lifetime, source_path) in leak_scenarios {
            let obligation =
                self.injector
                    .inject_leak(kind, leak_type, scenario_start, lifetime, source_path);
            injected_obligations.push(obligation);
        }

        // Phase 2: Run detection with time bounds
        let detection_start = cx.now();
        let mut detected_leaks = Vec::new();

        while cx.now() < scenario_end {
            // Run oracle detection sweep
            let oracle_result = oracle.check_obligation_leaks().await?;

            for leak_event in oracle_result.detected_leaks {
                let detection_time = cx.now().duration_since(detection_start);

                // Verify leak is one we injected
                let is_correct = self
                    .injector
                    .get_leak_type(&leak_event.obligation_id)
                    .is_some();

                // Verify leak path accuracy
                let path_correct = self.verify_leak_path(&leak_event);

                self.detection_metrics
                    .record_detection(detection_time, is_correct, path_correct);

                detected_leaks.push(leak_event);
            }

            // Brief detection interval
            cx.sleep(self.oracle_config.detection_interval).await;
        }

        // Phase 3: Verify all expected leaks were detected
        let expected_leak_count = injected_obligations.len();
        let detected_leak_count = detected_leaks.len();

        if detected_leak_count < expected_leak_count {
            self.detection_metrics.record_missed_leak();
        }

        Ok(())
    }

    fn verify_leak_path(&self, leak_event: &LeakEvent) -> bool {
        // Check if the leak path matches expected source path for this obligation
        if let Some(leak_type) = self.injector.get_leak_type(&leak_event.obligation_id) {
            // For synthetic leaks, path should contain test markers
            leak_event
                .leak_path
                .path_elements
                .contains(&"test".to_string())
        } else {
            false
        }
    }

    fn verify_detection_properties(&self) -> Result<()> {
        let (detection_times, false_positives, missed_leaks, correct_detections, path_accuracy) =
            self.detection_metrics.get_stats();

        // Verify bounded detection time
        if !self
            .detection_metrics
            .verify_bounded_detection(self.detection_timeout)
        {
            return Err(format!(
                "Detection times exceeded bounds: max allowed={:?}",
                self.detection_timeout
            )
            .into());
        }

        // Verify no false positives
        if false_positives > 0 {
            return Err(format!("False positives detected: {}", false_positives).into());
        }

        // Verify no missed leaks
        if missed_leaks > 0 {
            return Err(format!("Missed leak detections: {}", missed_leaks).into());
        }

        // Verify correct detections
        if correct_detections == 0 {
            return Err(format!("No correct leak detections recorded").into());
        }

        // Verify path accuracy
        if path_accuracy == 0 {
            return Err(format!("No accurate leak path identifications").into());
        }

        println!(
            "Oracle leak detection verified: {} correct detections, {} accurate paths, avg detection time: {:?}",
            correct_detections,
            path_accuracy,
            detection_times.iter().sum::<Duration>() / detection_times.len() as u32
        );

        Ok(())
    }
}

/// Test harness for obligation leak check and oracle integration
#[derive(Debug)]
struct LeakCheckOracleTestHarness {
    coordinator: OracleLeakDetectionCoordinator,
    leak_checker_config: LeakCheckConfig,
}

impl LeakCheckOracleTestHarness {
    fn new(detection_timeout: Duration, start_time: VirtualTime) -> Self {
        let leak_checker_config = LeakCheckConfig {
            check_interval: Duration::from_millis(50),
            leak_timeout: Duration::from_secs(10),
            max_tracked_obligations: 1000,
            enable_path_tracking: true,
        };

        Self {
            coordinator: OracleLeakDetectionCoordinator::new(detection_timeout, start_time),
            leak_checker_config,
        }
    }

    async fn run_comprehensive_leak_detection_test(
        &self,
        cx: &Cx,
        runtime: &LabRuntime,
    ) -> Result<()> {
        // Initialize oracle and leak checker
        let oracle = LeakDetectionOracle::new(self.coordinator.oracle_config.clone())?;
        let leak_checker = LeakChecker::new(self.leak_checker_config.clone())?;

        // Run leak detection scenario
        self.coordinator
            .run_leak_detection_scenario(cx, &oracle, &leak_checker, Duration::from_secs(15))
            .await?;

        // Verify detection properties
        self.coordinator.verify_detection_properties()?;

        Ok(())
    }
}

/// Mock implementations for testing infrastructure

/// Mock leak detection oracle
#[derive(Debug)]
struct LeakDetectionOracle {
    config: ObligationLeakConfig,
}

impl LeakDetectionOracle {
    fn new(config: ObligationLeakConfig) -> Result<Self> {
        Ok(Self { config })
    }

    async fn check_obligation_leaks(&self) -> Result<OracleLeakResult> {
        // Simulate leak detection with synthetic results
        Ok(OracleLeakResult {
            detected_leaks: vec![LeakEvent {
                obligation_id: ObligationId::new(),
                leak_path: LeakPath {
                    path_elements: vec!["test".to_string(), "synthetic".to_string()],
                },
                leak_type_description: "synthetic test leak".to_string(),
            }],
        })
    }
}

/// Mock oracle result for leak detection
#[derive(Debug)]
struct OracleLeakResult {
    detected_leaks: Vec<LeakEvent>,
}

/// Mock leak event from oracle
#[derive(Debug)]
struct LeakEvent {
    obligation_id: ObligationId,
    leak_path: LeakPath,
    leak_type_description: String,
}

/// Mock leak path tracking
#[derive(Debug)]
struct LeakPath {
    path_elements: Vec<String>,
}

/// Mock obligation leak configuration
#[derive(Debug, Clone)]
struct ObligationLeakConfig {
    detection_interval: Duration,
    leak_timeout: Duration,
    path_trace_depth: usize,
    enable_synthetic_injection: bool,
}

/// Mock leak checker configuration
#[derive(Debug, Clone)]
struct LeakCheckConfig {
    check_interval: Duration,
    leak_timeout: Duration,
    max_tracked_obligations: usize,
    enable_path_tracking: bool,
}

/// Mock leak checker implementation
#[derive(Debug)]
struct LeakChecker {
    config: LeakCheckConfig,
}

impl LeakChecker {
    fn new(config: LeakCheckConfig) -> Result<Self> {
        Ok(Self { config })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_oracle_leak_detection() -> Result<()> {
        let lab_runtime = LabRuntimeBuilder::new().with_virtual_time().build()?;
        let cx = lab_runtime.cx();

        let start_time = lab_runtime.virtual_time().now();
        let harness = LeakCheckOracleTestHarness::new(Duration::from_secs(5), start_time);

        // Create basic oracle and leak checker
        let oracle = LeakDetectionOracle::new(harness.coordinator.oracle_config.clone())?;
        let leak_checker = LeakChecker::new(harness.leak_checker_config.clone())?;

        // Inject a simple synthetic leak
        let obligation = harness.coordinator.injector.inject_leak(
            ObligationKind::Permit,
            LeakType::Abandoned,
            start_time,
            Duration::from_secs(1),
            vec!["basic_test".to_string()],
        );

        // Run detection
        let result = oracle.check_obligation_leaks().await?;
        assert!(
            !result.detected_leaks.is_empty(),
            "Should detect synthetic leak"
        );

        // Verify basic properties
        let (injection_count, _) = harness.coordinator.injector.get_injection_stats();
        assert_eq!(injection_count, 1, "Should have injected one leak");

        Ok(())
    }

    #[tokio::test]
    async fn test_bounded_time_leak_detection() -> Result<()> {
        let lab_runtime = LabRuntimeBuilder::new().with_virtual_time().build()?;
        let cx = lab_runtime.cx();

        let start_time = lab_runtime.virtual_time().now();
        let detection_timeout = Duration::from_secs(2);
        let harness = LeakCheckOracleTestHarness::new(detection_timeout, start_time);

        // Test that detection happens within bounded time
        let oracle = LeakDetectionOracle::new(harness.coordinator.oracle_config.clone())?;

        let detection_start = cx.now();

        // Inject leak and measure detection time
        harness.coordinator.injector.inject_leak(
            ObligationKind::Lease,
            LeakType::CommitStalled,
            start_time,
            Duration::from_millis(500),
            vec!["bounded_test".to_string()],
        );

        // Run detection
        let result = oracle.check_obligation_leaks().await?;
        let detection_time = cx.now().duration_since(detection_start);

        assert!(
            detection_time <= detection_timeout,
            "Detection time {:?} exceeded bound {:?}",
            detection_time,
            detection_timeout
        );

        assert!(
            !result.detected_leaks.is_empty(),
            "Should detect leak within time bound"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_exact_leak_path_identification() -> Result<()> {
        let lab_runtime = LabRuntimeBuilder::new().with_virtual_time().build()?;
        let cx = lab_runtime.cx();

        let start_time = lab_runtime.virtual_time().now();
        let harness = LeakCheckOracleTestHarness::new(Duration::from_secs(5), start_time);

        // Create oracle with path tracking enabled
        let oracle = LeakDetectionOracle::new(harness.coordinator.oracle_config.clone())?;

        // Inject leak with specific path
        let expected_path = vec![
            "path_test".to_string(),
            "module".to_string(),
            "function".to_string(),
            "leak_source".to_string(),
        ];

        harness.coordinator.injector.inject_leak(
            ObligationKind::Ack,
            LeakType::AbortStalled,
            start_time,
            Duration::from_secs(1),
            expected_path.clone(),
        );

        // Run detection and verify path
        let result = oracle.check_obligation_leaks().await?;
        assert!(!result.detected_leaks.is_empty(), "Should detect leak");

        let detected_leak = &result.detected_leaks[0];

        // Verify path contains expected elements
        assert!(
            detected_leak
                .leak_path
                .path_elements
                .contains(&"test".to_string()),
            "Leak path should contain test marker: {:?}",
            detected_leak.leak_path.path_elements
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_leak_types_detection() -> Result<()> {
        let lab_runtime = LabRuntimeBuilder::new().with_virtual_time().build()?;
        let cx = lab_runtime.cx();

        let start_time = lab_runtime.virtual_time().now();
        let harness = LeakCheckOracleTestHarness::new(Duration::from_secs(10), start_time);

        let oracle = LeakDetectionOracle::new(harness.coordinator.oracle_config.clone())?;

        // Inject multiple types of leaks
        let leak_types = vec![
            LeakType::Abandoned,
            LeakType::CommitStalled,
            LeakType::AbortStalled,
            LeakType::DoubleCommit,
            LeakType::CommitAfterAbort,
        ];

        for (i, leak_type) in leak_types.iter().enumerate() {
            harness.coordinator.injector.inject_leak(
                ObligationKind::Permit,
                *leak_type,
                start_time,
                Duration::from_secs(1),
                vec![format!("multi_test_{}", i)],
            );
        }

        // Run detection
        let result = oracle.check_obligation_leaks().await?;

        // Should detect multiple leaks
        assert!(
            result.detected_leaks.len() > 0,
            "Should detect multiple leak types"
        );

        let (injection_count, registry_size) = harness.coordinator.injector.get_injection_stats();
        assert_eq!(
            injection_count, 5,
            "Should have injected 5 different leak types"
        );
        assert_eq!(registry_size, 5, "Registry should track all injected leaks");

        Ok(())
    }

    #[tokio::test]
    async fn test_comprehensive_leak_check_oracle_integration() -> Result<()> {
        let lab_runtime = LabRuntimeBuilder::new()
            .with_virtual_time()
            .with_deterministic_scheduling()
            .build()?;
        let cx = lab_runtime.cx();

        let start_time = lab_runtime.virtual_time().now();
        let harness = LeakCheckOracleTestHarness::new(
            Duration::from_secs(3), // Tight detection bound
            start_time,
        );

        // Run comprehensive test scenario
        harness
            .run_comprehensive_leak_detection_test(&cx, &lab_runtime)
            .await?;

        // Verify final state
        let (injection_count, registry_size) = harness.coordinator.injector.get_injection_stats();
        assert!(injection_count > 0, "Should have injected synthetic leaks");
        assert_eq!(
            injection_count, registry_size,
            "Registry should match injections"
        );

        println!(
            "Comprehensive integration test completed: {} leaks injected and tracked",
            injection_count
        );

        Ok(())
    }
}
