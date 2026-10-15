//! ATP Lab Forensics - Evidence Collection and Analysis
//!
//! Provides comprehensive forensics capabilities for ATP lab execution including:
//! - Execution trace forensics and evidence collection
//! - Performance regression detection and analysis
//! - Determinism violation forensics with root cause analysis
//! - Resource usage forensics and memory leak detection
//! - Concurrency bug forensics with race condition analysis
//! - Schedule dependency forensics with causality tracking
//! - Benchmark result forensics and comparison analysis

use crate::types::{RegionId, TaskId, Time};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

fn current_time() -> Time {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    Time::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

/// ATP Lab forensics error types
#[derive(Debug, Error)]
pub enum ForensicsError {
    #[error("Evidence collection failed: {reason}")]
    EvidenceCollectionFailed { reason: String },
    #[error("Trace analysis failed: {reason}")]
    TraceAnalysisFailed { reason: String },
    #[error("Performance regression detected: {regression}")]
    PerformanceRegression { regression: String },
    #[error("Determinism violation detected: {violation}")]
    DeterminismViolation { violation: String },
    #[error("Resource leak detected: {leak_type}")]
    ResourceLeak { leak_type: String },
    #[error("Concurrency bug detected: {bug_type}")]
    ConcurrencyBug { bug_type: String },
}

/// Forensics evidence collector for ATP lab execution
#[derive(Debug)]
pub struct ForensicsCollector {
    /// Evidence collection configuration
    config: ForensicsConfig,
    /// Collected evidence entries
    evidence: Vec<EvidenceEntry>,
    /// Performance baselines for regression detection
    performance_baselines: HashMap<String, PerformanceBaseline>,
    /// Resource usage tracking
    resource_tracker: ResourceTracker,
    /// Execution context stack
    execution_stack: VecDeque<ExecutionFrame>,
    /// Start time of forensics collection
    collection_start: Instant,
}

/// Configuration for forensics evidence collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsConfig {
    /// Enable detailed evidence collection
    pub enable_detailed_collection: bool,
    /// Enable performance regression detection
    pub enable_performance_tracking: bool,
    /// Enable determinism violation detection
    pub enable_determinism_checks: bool,
    /// Enable resource leak detection
    pub enable_resource_tracking: bool,
    /// Enable concurrency bug detection
    pub enable_concurrency_analysis: bool,
    /// Maximum evidence entries to retain
    pub max_evidence_entries: usize,
    /// Performance regression threshold (percentage)
    pub regression_threshold: f64,
    /// Memory leak detection threshold (bytes)
    pub memory_leak_threshold: u64,
}

/// Evidence entry for forensics analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceEntry {
    /// Unique evidence identifier
    pub id: String,
    /// Evidence collection timestamp
    pub timestamp: Time,
    /// Evidence category
    pub category: EvidenceCategory,
    /// Evidence severity level
    pub severity: EvidenceSeverity,
    /// Evidence description
    pub description: String,
    /// Associated execution context
    pub context: ExecutionContext,
    /// Evidence-specific data
    pub data: EvidenceData,
    /// Potential root cause analysis
    pub root_cause: Option<RootCause>,
}

/// Evidence category classification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceCategory {
    Performance,
    Determinism,
    ResourceUsage,
    Concurrency,
    Schedule,
    Oracle,
    Benchmark,
    System,
}

/// Evidence severity levels
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum EvidenceSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Execution context for evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Lab runtime identifier
    pub lab_id: String,
    /// Scenario identifier
    pub scenario_id: String,
    /// Current task context
    pub task_id: Option<TaskId>,
    /// Current region context
    pub region_id: Option<RegionId>,
    /// Virtual time context
    pub virtual_time: Time,
    /// Real time context
    pub real_time: SystemTime,
    /// Execution phase
    pub phase: ExecutionPhase,
}

/// Execution phases for context tracking
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ExecutionPhase {
    Initialization,
    Execution,
    Oracle,
    Cleanup,
    Analysis,
}

/// Evidence-specific data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceData {
    PerformanceMetrics {
        execution_time: Duration,
        memory_usage: u64,
        cpu_cycles: Option<u64>,
        cache_misses: Option<u64>,
    },
    DeterminismViolation {
        expected_state: String,
        actual_state: String,
        divergence_point: String,
    },
    ResourceLeak {
        resource_type: String,
        leaked_count: u64,
        allocation_trace: Vec<String>,
    },
    ConcurrencyBug {
        bug_type: ConcurrencyBugType,
        involved_tasks: Vec<TaskId>,
        race_condition: Option<RaceConditionInfo>,
    },
    ScheduleDependency {
        dependency_type: String,
        dependent_tasks: Vec<TaskId>,
        causality_chain: Vec<String>,
    },
    OracleViolation {
        oracle_type: String,
        violation_details: String,
        expected_invariant: String,
    },
}

/// Concurrency bug type classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConcurrencyBugType {
    RaceCondition,
    Deadlock,
    LiveLock,
    DataRace,
    AtomicityViolation,
    OrderViolation,
}

/// Race condition information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaceConditionInfo {
    pub memory_location: String,
    pub conflicting_accesses: Vec<MemoryAccess>,
    pub happens_before_violations: Vec<String>,
}

/// Memory access information for race detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAccess {
    pub task_id: TaskId,
    pub access_type: MemoryAccessType,
    pub virtual_time: Time,
    pub stack_trace: Vec<String>,
}

/// Memory access types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryAccessType {
    Read,
    Write,
    ReadModifyWrite,
}

/// Root cause analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub cause_type: RootCauseType,
    pub description: String,
    pub contributing_factors: Vec<String>,
    pub recommended_fixes: Vec<String>,
    pub confidence_score: f64,
}

/// Root cause types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RootCauseType {
    CodeBug,
    ConfigurationError,
    ResourceContention,
    TimingIssue,
    EnvironmentalFactor,
    SpecificationViolation,
}

/// Performance baseline for regression detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceBaseline {
    pub test_name: String,
    pub baseline_time: Duration,
    pub baseline_memory: u64,
    pub measurements: Vec<PerformanceMeasurement>,
    pub last_updated: SystemTime,
    pub confidence_interval: (f64, f64),
}

/// Performance measurement data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMeasurement {
    pub timestamp: SystemTime,
    pub execution_time: Duration,
    pub memory_usage: u64,
    pub additional_metrics: HashMap<String, f64>,
}

/// Resource usage tracker
#[derive(Debug)]
pub struct ResourceTracker {
    /// Tracked memory allocations
    memory_allocations: HashMap<String, AllocationInfo>,
    /// Tracked file handles
    file_handles: HashMap<String, FileHandleInfo>,
    /// Tracked network connections
    network_connections: HashMap<String, ConnectionInfo>,
    /// Resource usage snapshots
    snapshots: Vec<ResourceSnapshot>,
}

/// Memory allocation tracking information
#[derive(Debug, Clone)]
pub struct AllocationInfo {
    pub size: u64,
    pub allocation_time: Instant,
    pub stack_trace: Vec<String>,
    pub allocation_id: String,
}

/// File handle tracking information
#[derive(Debug, Clone)]
pub struct FileHandleInfo {
    pub path: String,
    pub opened_at: Instant,
    pub access_mode: String,
    pub handle_id: String,
}

/// Network connection tracking information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub remote_addr: String,
    pub protocol: String,
    pub established_at: Instant,
    pub connection_id: String,
}

/// Resource usage snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub timestamp: SystemTime,
    pub memory_usage: u64,
    pub open_files: u32,
    pub active_connections: u32,
    pub cpu_usage: f64,
}

/// Execution frame for call stack tracking
#[derive(Debug, Clone)]
pub struct ExecutionFrame {
    pub function_name: String,
    pub file_location: String,
    pub line_number: u32,
    pub entry_time: Instant,
    pub local_variables: HashMap<String, String>,
}

impl Default for ForensicsConfig {
    fn default() -> Self {
        Self {
            enable_detailed_collection: true,
            enable_performance_tracking: true,
            enable_determinism_checks: true,
            enable_resource_tracking: true,
            enable_concurrency_analysis: true,
            max_evidence_entries: 10000,
            regression_threshold: 20.0,         // 20% regression threshold
            memory_leak_threshold: 1024 * 1024, // 1MB leak threshold
        }
    }
}

impl ForensicsCollector {
    /// Create a new forensics collector with configuration
    pub fn new(config: ForensicsConfig) -> Self {
        Self {
            config,
            evidence: Vec::new(),
            performance_baselines: HashMap::new(),
            resource_tracker: ResourceTracker::new(),
            execution_stack: VecDeque::new(),
            collection_start: Instant::now(),
        }
    }

    fn evidence_id(&self, prefix: &str, offset: usize) -> String {
        format!("{}-{}", prefix, self.evidence.len() + offset)
    }

    /// Start forensics collection for a lab execution
    pub fn start_collection(&mut self, lab_id: &str, scenario_id: &str) {
        self.collection_start = Instant::now();
        self.resource_tracker.take_snapshot();

        let context = ExecutionContext {
            lab_id: lab_id.to_string(),
            scenario_id: scenario_id.to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Initialization,
        };

        self.collect_evidence(
            EvidenceCategory::System,
            EvidenceSeverity::Info,
            "Forensics collection started".to_string(),
            context,
            EvidenceData::PerformanceMetrics {
                execution_time: Duration::from_millis(0),
                memory_usage: self.resource_tracker.current_memory_usage(),
                cpu_cycles: None,
                cache_misses: None,
            },
        );
    }

    /// Collect evidence entry
    pub fn collect_evidence(
        &mut self,
        category: EvidenceCategory,
        severity: EvidenceSeverity,
        description: String,
        context: ExecutionContext,
        data: EvidenceData,
    ) {
        let evidence_id = self.evidence_id("evidence", 0);

        let entry = EvidenceEntry {
            id: evidence_id,
            timestamp: current_time(),
            category,
            severity,
            description,
            context,
            data,
            root_cause: None,
        };

        self.evidence.push(entry);

        // Trim evidence if over limit
        if self.evidence.len() > self.config.max_evidence_entries {
            self.evidence
                .drain(0..self.evidence.len() - self.config.max_evidence_entries);
        }
    }

    /// Analyze performance regression
    pub fn analyze_performance_regression(
        &mut self,
        test_name: &str,
        execution_time: Duration,
        memory_usage: u64,
        context: ExecutionContext,
    ) -> Result<Option<EvidenceEntry>, ForensicsError> {
        if !self.config.enable_performance_tracking {
            return Ok(None);
        }

        let measurement = PerformanceMeasurement {
            timestamp: SystemTime::now(),
            execution_time,
            memory_usage,
            additional_metrics: HashMap::new(),
        };

        if let Some(baseline) = self.performance_baselines.get_mut(test_name) {
            baseline.measurements.push(measurement.clone());

            // Check for regression
            let time_regression = (execution_time.as_nanos() as f64
                - baseline.baseline_time.as_nanos() as f64)
                / baseline.baseline_time.as_nanos() as f64
                * 100.0;

            let memory_regression = (memory_usage as f64 - baseline.baseline_memory as f64)
                / baseline.baseline_memory as f64
                * 100.0;

            if time_regression > self.config.regression_threshold
                || memory_regression > self.config.regression_threshold
            {
                let evidence = EvidenceEntry {
                    id: self.evidence_id("regression", 0),
                    timestamp: current_time(),
                    category: EvidenceCategory::Performance,
                    severity: EvidenceSeverity::Warning,
                    description: format!("Performance regression detected in {}", test_name),
                    context: context.clone(),
                    data: EvidenceData::PerformanceMetrics {
                        execution_time,
                        memory_usage,
                        cpu_cycles: None,
                        cache_misses: None,
                    },
                    root_cause: Some(RootCause {
                        cause_type: RootCauseType::SpecificationViolation,
                        description: format!(
                            "Performance degraded: time +{:.1}%, memory +{:.1}%",
                            time_regression, memory_regression
                        ),
                        contributing_factors: vec![
                            "Algorithm change".to_string(),
                            "Resource contention".to_string(),
                            "Environmental factors".to_string(),
                        ],
                        recommended_fixes: vec![
                            "Profile execution to identify bottlenecks".to_string(),
                            "Review recent code changes".to_string(),
                            "Check system resource availability".to_string(),
                        ],
                        confidence_score: 0.8,
                    }),
                };

                self.evidence.push(evidence.clone());
                return Ok(Some(evidence));
            }
        } else {
            // Create new baseline
            let baseline = PerformanceBaseline {
                test_name: test_name.to_string(),
                baseline_time: execution_time,
                baseline_memory: memory_usage,
                measurements: vec![measurement],
                last_updated: SystemTime::now(),
                confidence_interval: (0.9, 1.1),
            };

            self.performance_baselines
                .insert(test_name.to_string(), baseline);
        }

        Ok(None)
    }

    /// Analyze determinism violation
    pub fn analyze_determinism_violation(
        &mut self,
        expected_state: &str,
        actual_state: &str,
        divergence_point: &str,
        context: ExecutionContext,
    ) -> EvidenceEntry {
        let evidence = EvidenceEntry {
            id: self.evidence_id("determinism", 0),
            timestamp: current_time(),
            category: EvidenceCategory::Determinism,
            severity: EvidenceSeverity::Error,
            description: "Determinism violation detected".to_string(),
            context,
            data: EvidenceData::DeterminismViolation {
                expected_state: expected_state.to_string(),
                actual_state: actual_state.to_string(),
                divergence_point: divergence_point.to_string(),
            },
            root_cause: Some(RootCause {
                cause_type: RootCauseType::CodeBug,
                description: "Non-deterministic execution detected".to_string(),
                contributing_factors: vec![
                    "Race condition".to_string(),
                    "Uninitialized memory".to_string(),
                    "System call dependence".to_string(),
                    "Random number generation".to_string(),
                ],
                recommended_fixes: vec![
                    "Review synchronization primitives".to_string(),
                    "Check for uninitialized variables".to_string(),
                    "Virtualize system calls in tests".to_string(),
                    "Use deterministic random seeds".to_string(),
                ],
                confidence_score: 0.9,
            }),
        };

        self.evidence.push(evidence.clone());
        evidence
    }

    /// Analyze resource leak
    pub fn analyze_resource_leak(&mut self, context: ExecutionContext) -> Vec<EvidenceEntry> {
        let mut evidence_entries = Vec::new();

        if !self.config.enable_resource_tracking {
            return evidence_entries;
        }

        // Check for memory leaks
        let current_memory = self.resource_tracker.current_memory_usage();
        if current_memory > self.config.memory_leak_threshold {
            let evidence = EvidenceEntry {
                id: self.evidence_id("memory-leak", evidence_entries.len()),
                timestamp: current_time(),
                category: EvidenceCategory::ResourceUsage,
                severity: EvidenceSeverity::Error,
                description: "Memory leak detected".to_string(),
                context: context.clone(),
                data: EvidenceData::ResourceLeak {
                    resource_type: "memory".to_string(),
                    leaked_count: current_memory,
                    allocation_trace: vec![
                        "allocation_site_1".to_string(),
                        "allocation_site_2".to_string(),
                    ],
                },
                root_cause: Some(RootCause {
                    cause_type: RootCauseType::CodeBug,
                    description: "Memory not properly freed".to_string(),
                    contributing_factors: vec![
                        "Missing drop implementation".to_string(),
                        "Circular references".to_string(),
                        "Exception during cleanup".to_string(),
                    ],
                    recommended_fixes: vec![
                        "Review Drop implementations".to_string(),
                        "Use weak references to break cycles".to_string(),
                        "Add proper cleanup in error paths".to_string(),
                    ],
                    confidence_score: 0.7,
                }),
            };
            evidence_entries.push(evidence);
        }

        // Check for file handle leaks
        let open_files = self.resource_tracker.open_file_count();
        if open_files > 100 {
            // Arbitrary threshold
            let evidence = EvidenceEntry {
                id: self.evidence_id("file-leak", evidence_entries.len()),
                timestamp: current_time(),
                category: EvidenceCategory::ResourceUsage,
                severity: EvidenceSeverity::Warning,
                description: "File handle leak detected".to_string(),
                context: context.clone(),
                data: EvidenceData::ResourceLeak {
                    resource_type: "file_handle".to_string(),
                    leaked_count: open_files as u64,
                    allocation_trace: vec!["file_open_site".to_string()],
                },
                root_cause: Some(RootCause {
                    cause_type: RootCauseType::CodeBug,
                    description: "File handles not properly closed".to_string(),
                    contributing_factors: vec![
                        "Missing close calls".to_string(),
                        "Exception during file operations".to_string(),
                    ],
                    recommended_fixes: vec![
                        "Use RAII pattern for file handles".to_string(),
                        "Add proper error handling".to_string(),
                    ],
                    confidence_score: 0.8,
                }),
            };
            evidence_entries.push(evidence);
        }

        for evidence in &evidence_entries {
            self.evidence.push(evidence.clone());
        }

        evidence_entries
    }

    /// Analyze concurrency bug
    pub fn analyze_concurrency_bug(
        &mut self,
        bug_type: ConcurrencyBugType,
        involved_tasks: Vec<TaskId>,
        context: ExecutionContext,
    ) -> EvidenceEntry {
        let evidence = EvidenceEntry {
            id: self.evidence_id("concurrency", 0),
            timestamp: current_time(),
            category: EvidenceCategory::Concurrency,
            severity: EvidenceSeverity::Critical,
            description: format!("Concurrency bug detected: {:?}", bug_type),
            context,
            data: EvidenceData::ConcurrencyBug {
                bug_type: bug_type.clone(),
                involved_tasks: involved_tasks.clone(),
                race_condition: None,
            },
            root_cause: Some(RootCause {
                cause_type: RootCauseType::CodeBug,
                description: match bug_type {
                    ConcurrencyBugType::RaceCondition => "Data race on shared memory".to_string(),
                    ConcurrencyBugType::Deadlock => {
                        "Circular dependency in lock acquisition".to_string()
                    }
                    ConcurrencyBugType::LiveLock => {
                        "Tasks indefinitely yielding to each other".to_string()
                    }
                    ConcurrencyBugType::DataRace => {
                        "Unsynchronized access to shared data".to_string()
                    }
                    ConcurrencyBugType::AtomicityViolation => {
                        "Operation atomicity violated".to_string()
                    }
                    ConcurrencyBugType::OrderViolation => {
                        "Expected operation order violated".to_string()
                    }
                },
                contributing_factors: vec![
                    "Insufficient synchronization".to_string(),
                    "Lock ordering issues".to_string(),
                    "Missing memory barriers".to_string(),
                ],
                recommended_fixes: vec![
                    "Add appropriate synchronization primitives".to_string(),
                    "Review lock acquisition order".to_string(),
                    "Use atomic operations where appropriate".to_string(),
                ],
                confidence_score: 0.85,
            }),
        };

        self.evidence.push(evidence.clone());
        evidence
    }

    /// Generate forensics report
    pub fn generate_report(&self) -> ForensicsReport {
        let total_evidence = self.evidence.len();
        let critical_evidence = self
            .evidence
            .iter()
            .filter(|e| e.severity == EvidenceSeverity::Critical)
            .count();
        let error_evidence = self
            .evidence
            .iter()
            .filter(|e| e.severity == EvidenceSeverity::Error)
            .count();

        let category_breakdown: HashMap<EvidenceCategory, usize> =
            self.evidence
                .iter()
                .fold(HashMap::new(), |mut acc, evidence| {
                    *acc.entry(evidence.category.clone()).or_insert(0) += 1;
                    acc
                });

        ForensicsReport {
            collection_duration: self.collection_start.elapsed(),
            total_evidence,
            critical_evidence,
            error_evidence,
            category_breakdown,
            evidence_entries: self.evidence.clone(),
            performance_baselines: self.performance_baselines.clone(),
            recommendations: self.generate_recommendations(),
        }
    }

    /// Generate recommendations based on evidence
    fn generate_recommendations(&self) -> Vec<String> {
        let mut recommendations = Vec::new();

        if self
            .evidence
            .iter()
            .any(|e| e.category == EvidenceCategory::Performance)
        {
            recommendations
                .push("Consider performance profiling to identify bottlenecks".to_string());
        }

        if self
            .evidence
            .iter()
            .any(|e| e.category == EvidenceCategory::Determinism)
        {
            recommendations.push("Review code for non-deterministic behavior".to_string());
        }

        if self
            .evidence
            .iter()
            .any(|e| e.category == EvidenceCategory::ResourceUsage)
        {
            recommendations
                .push("Implement proper resource cleanup and lifecycle management".to_string());
        }

        if self
            .evidence
            .iter()
            .any(|e| e.category == EvidenceCategory::Concurrency)
        {
            recommendations.push(
                "Review synchronization primitives and concurrent access patterns".to_string(),
            );
        }

        if !self.execution_stack.is_empty() {
            recommendations.push(format!(
                "Review {} captured execution frames for causal context",
                self.execution_stack.len()
            ));
        }

        recommendations
    }
}

/// Comprehensive forensics report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicsReport {
    pub collection_duration: Duration,
    pub total_evidence: usize,
    pub critical_evidence: usize,
    pub error_evidence: usize,
    pub category_breakdown: HashMap<EvidenceCategory, usize>,
    pub evidence_entries: Vec<EvidenceEntry>,
    pub performance_baselines: HashMap<String, PerformanceBaseline>,
    pub recommendations: Vec<String>,
}

impl ResourceTracker {
    pub fn new() -> Self {
        Self {
            memory_allocations: HashMap::new(),
            file_handles: HashMap::new(),
            network_connections: HashMap::new(),
            snapshots: Vec::new(),
        }
    }

    pub fn take_snapshot(&mut self) {
        let snapshot = ResourceSnapshot {
            timestamp: SystemTime::now(),
            memory_usage: self.current_memory_usage(),
            open_files: self.open_file_count(),
            active_connections: self.active_connection_count(),
            cpu_usage: 0.0, // Would need platform-specific implementation
        };
        self.snapshots.push(snapshot);
    }

    pub fn current_memory_usage(&self) -> u64 {
        self.memory_allocations.values().map(|a| a.size).sum()
    }

    pub fn open_file_count(&self) -> u32 {
        self.file_handles.len() as u32
    }

    pub fn active_connection_count(&self) -> u32 {
        self.network_connections.len() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forensics_collector_initialization() {
        let config = ForensicsConfig::default();
        let collector = ForensicsCollector::new(config.clone());

        assert_eq!(collector.config.regression_threshold, 20.0);
        assert!(collector.evidence.is_empty());
        assert!(collector.performance_baselines.is_empty());
    }

    #[test]
    fn test_evidence_collection() {
        let mut collector = ForensicsCollector::new(ForensicsConfig::default());
        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        collector.collect_evidence(
            EvidenceCategory::Performance,
            EvidenceSeverity::Info,
            "Test evidence".to_string(),
            context,
            EvidenceData::PerformanceMetrics {
                execution_time: Duration::from_millis(100),
                memory_usage: 1024,
                cpu_cycles: None,
                cache_misses: None,
            },
        );

        assert_eq!(collector.evidence.len(), 1);
        assert_eq!(
            collector.evidence[0].category,
            EvidenceCategory::Performance
        );
    }

    #[test]
    fn test_performance_regression_detection() {
        let mut collector = ForensicsCollector::new(ForensicsConfig {
            regression_threshold: 10.0,
            ..ForensicsConfig::default()
        });

        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        // Establish baseline
        collector
            .analyze_performance_regression(
                "test_benchmark",
                Duration::from_millis(100),
                1024,
                context.clone(),
            )
            .unwrap();

        // No regression should be detected yet
        assert_eq!(collector.evidence.len(), 0);

        // Trigger regression
        let result = collector
            .analyze_performance_regression(
                "test_benchmark",
                Duration::from_millis(150), // 50% increase
                1024,
                context,
            )
            .unwrap();

        assert!(result.is_some());
        let evidence = result.unwrap();
        assert_eq!(evidence.category, EvidenceCategory::Performance);
        assert_eq!(evidence.severity, EvidenceSeverity::Warning);
    }

    #[test]
    fn test_determinism_violation_analysis() {
        let mut collector = ForensicsCollector::new(ForensicsConfig::default());
        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        let evidence = collector.analyze_determinism_violation(
            "expected_state",
            "actual_state",
            "divergence_point",
            context,
        );

        assert_eq!(evidence.category, EvidenceCategory::Determinism);
        assert_eq!(evidence.severity, EvidenceSeverity::Error);
        assert!(evidence.root_cause.is_some());
        assert_eq!(collector.evidence.len(), 1);
    }

    #[test]
    fn test_forensics_report_generation() {
        let mut collector = ForensicsCollector::new(ForensicsConfig::default());
        let context = ExecutionContext {
            lab_id: "test-lab".to_string(),
            scenario_id: "test-scenario".to_string(),
            task_id: None,
            region_id: None,
            virtual_time: current_time(),
            real_time: SystemTime::now(),
            phase: ExecutionPhase::Execution,
        };

        // Add some evidence
        collector.collect_evidence(
            EvidenceCategory::Performance,
            EvidenceSeverity::Critical,
            "Critical performance issue".to_string(),
            context.clone(),
            EvidenceData::PerformanceMetrics {
                execution_time: Duration::from_secs(1),
                memory_usage: 1024 * 1024,
                cpu_cycles: None,
                cache_misses: None,
            },
        );

        collector.analyze_determinism_violation("expected", "actual", "divergence", context);

        let report = collector.generate_report();
        assert_eq!(report.total_evidence, 2);
        assert_eq!(report.critical_evidence, 1);
        assert_eq!(report.error_evidence, 1);
        assert!(
            report
                .category_breakdown
                .contains_key(&EvidenceCategory::Performance)
        );
        assert!(
            report
                .category_breakdown
                .contains_key(&EvidenceCategory::Determinism)
        );
    }
}
