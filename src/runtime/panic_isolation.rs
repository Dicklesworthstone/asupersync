//! Panic isolation framework for structured concurrency runtime.
//!
//! This module provides comprehensive panic isolation that prevents individual
//! task panics from corrupting runtime state or crashing the entire system.
//! It leverages region boundaries for isolation and enables graceful degradation.

use crate::observability::metrics::MetricsProvider;
use crate::types::{ObligationId, Outcome, RegionId, TaskId, outcome::PanicPayload};
use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static PANIC_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Configuration for panic isolation behavior.
#[derive(Debug, Clone)]
pub struct PanicIsolationConfig {
    /// Whether to capture backtraces for panics (adds overhead)
    pub capture_backtraces: bool,
    /// Whether to log panic details to the observability system
    pub enable_panic_logging: bool,
    /// Maximum number of panics per region before escalating
    pub panic_threshold_per_region: Option<u32>,
    /// Whether to enable panic recovery for finalizers
    pub isolate_finalizer_panics: bool,
    /// Whether to enable panic recovery for task execution
    pub isolate_task_panics: bool,
}

impl Default for PanicIsolationConfig {
    fn default() -> Self {
        Self {
            capture_backtraces: cfg!(debug_assertions),
            enable_panic_logging: true,
            panic_threshold_per_region: Some(10),
            isolate_task_panics: true,
            isolate_finalizer_panics: true,
        }
    }
}

/// Context information for a panic that occurred in the runtime.
#[derive(Debug, Clone)]
pub struct PanicContext {
    /// Unique identifier for this panic occurrence
    pub panic_id: u64,
    /// Where the panic occurred in the runtime
    pub location: PanicLocation,
    /// Timestamp when the panic was caught
    pub timestamp: Instant,
    /// Captured panic payload (if any)
    pub panic_message: Option<String>,
    /// Captured backtrace (if enabled)
    pub backtrace: Option<String>,
    /// Region where the panic occurred (if applicable)
    pub region_id: Option<RegionId>,
    /// Task that panicked (if applicable)
    pub task_id: Option<TaskId>,
    /// Obligation associated with the panic (if applicable)
    pub obligation_id: Option<ObligationId>,
}

/// Location where a panic occurred in the runtime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PanicLocation {
    /// Panic occurred during task execution
    TaskExecution {
        /// The ID of the task that panicked
        task_id: TaskId,
        /// The region owning the task
        region_id: RegionId,
        /// Number of polling attempts before panic
        poll_attempt: u32,
    },
    /// Panic occurred during finalizer execution
    FinalizerExecution {
        /// The region being finalized
        region_id: RegionId,
        /// Type of finalizer that panicked
        finalizer_type: FinalizerType,
    },
    /// Panic occurred during region cleanup
    RegionCleanup {
        /// The region being cleaned up
        region_id: RegionId,
        /// Phase of cleanup when panic occurred
        cleanup_phase: CleanupPhase,
    },
    /// Panic occurred during obligation resolution
    ObligationHandling {
        /// The obligation being processed
        obligation_id: ObligationId,
        /// The region owning the obligation
        region_id: RegionId,
    },
    /// Panic occurred in scheduler code
    SchedulerInternal {
        /// Worker ID if applicable
        worker_id: Option<usize>,
        /// Description of the operation being performed
        operation: String,
    },
}

/// Types of finalizers where panics can occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinalizerType {
    /// Synchronous finalizer
    Sync,
    /// Asynchronous finalizer
    Async,
    /// Custom finalizer with description
    Custom(String),
}

/// Phases of region cleanup where panics can occur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupPhase {
    /// Running finalizers during region close
    Finalizers,
    /// Resolving outstanding obligations
    ObligationResolution,
    /// Cleaning up allocated resources
    ResourceCleanup,
    /// Transitioning region state
    StateTransition,
}

/// Result of panic isolation attempt.
#[derive(Debug, Clone)]
pub enum PanicIsolationResult<T> {
    /// Operation completed successfully
    Success(T),
    /// Operation panicked and was isolated
    Panicked(PanicContext),
    /// Operation was skipped due to previous panic threshold
    Skipped {
        /// Reason for skipping the operation
        reason: String,
        /// Context about the skip decision
        context: PanicContext,
    },
}

impl<T> PanicIsolationResult<T> {
    /// Returns true if the operation completed successfully.
    pub fn is_success(&self) -> bool {
        matches!(self, PanicIsolationResult::Success(_))
    }

    /// Returns true if the operation panicked.
    pub fn is_panicked(&self) -> bool {
        matches!(self, PanicIsolationResult::Panicked(_))
    }

    /// Returns the success value if available.
    pub fn into_success(self) -> Option<T> {
        match self {
            PanicIsolationResult::Success(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the panic context if the operation panicked.
    pub fn panic_context(&self) -> Option<&PanicContext> {
        match self {
            PanicIsolationResult::Panicked(ctx)
            | PanicIsolationResult::Skipped { context: ctx, .. } => Some(ctx),
            PanicIsolationResult::Success(_) => None,
        }
    }
}

/// Panic isolation framework for the runtime.
pub struct PanicIsolator {
    config: PanicIsolationConfig,
    metrics: Arc<dyn MetricsProvider>,
    region_panic_counts: Mutex<BTreeMap<RegionId, u32>>,
}

impl PanicIsolator {
    /// Create a new panic isolator with the given configuration.
    pub fn new(config: PanicIsolationConfig, metrics: Arc<dyn MetricsProvider>) -> Self {
        Self {
            config,
            metrics,
            region_panic_counts: Mutex::new(BTreeMap::new()),
        }
    }

    /// Isolate panic-prone task execution.
    ///
    /// This wraps task polling in a panic isolation boundary and provides
    /// structured error handling when tasks panic.
    pub fn isolate_task_execution<F, T>(
        &self,
        task_id: TaskId,
        region_id: RegionId,
        poll_attempt: u32,
        operation: F,
    ) -> PanicIsolationResult<T>
    where
        F: FnOnce() -> T,
    {
        if !self.config.isolate_task_panics {
            return PanicIsolationResult::Success(operation());
        }

        let location = PanicLocation::TaskExecution {
            task_id,
            region_id,
            poll_attempt,
        };

        self.isolate_operation(location, operation)
    }

    /// Isolate panic-prone finalizer execution.
    ///
    /// This wraps finalizer execution in a panic isolation boundary to ensure
    /// that panicking finalizers don't prevent other finalizers from running
    /// or block region closure.
    pub fn isolate_finalizer_execution<F, T>(
        &self,
        region_id: RegionId,
        finalizer_type: FinalizerType,
        operation: F,
    ) -> PanicIsolationResult<T>
    where
        F: FnOnce() -> T,
    {
        if !self.config.isolate_finalizer_panics {
            return PanicIsolationResult::Success(operation());
        }

        let location = PanicLocation::FinalizerExecution {
            region_id,
            finalizer_type,
        };

        self.isolate_operation(location, operation)
    }

    /// Isolate panic-prone region cleanup operations.
    pub fn isolate_region_cleanup<F, T>(
        &self,
        region_id: RegionId,
        phase: CleanupPhase,
        operation: F,
    ) -> PanicIsolationResult<T>
    where
        F: FnOnce() -> T,
    {
        let location = PanicLocation::RegionCleanup {
            region_id,
            cleanup_phase: phase,
        };

        self.isolate_operation(location, operation)
    }

    /// Isolate panic-prone obligation handling.
    pub fn isolate_obligation_handling<F, T>(
        &self,
        obligation_id: ObligationId,
        region_id: RegionId,
        operation: F,
    ) -> PanicIsolationResult<T>
    where
        F: FnOnce() -> T,
    {
        let location = PanicLocation::ObligationHandling {
            obligation_id,
            region_id,
        };

        self.isolate_operation(location, operation)
    }

    /// Isolate panic-prone scheduler operations.
    pub fn isolate_scheduler_operation<F, T>(
        &self,
        worker_id: Option<usize>,
        operation_name: String,
        operation: F,
    ) -> PanicIsolationResult<T>
    where
        F: FnOnce() -> T,
    {
        let location = PanicLocation::SchedulerInternal {
            worker_id,
            operation: operation_name,
        };

        self.isolate_operation(location, operation)
    }

    /// Core panic isolation implementation.
    fn isolate_operation<F, T>(
        &self,
        location: PanicLocation,
        operation: F,
    ) -> PanicIsolationResult<T>
    where
        F: FnOnce() -> T,
    {
        if let Some((reason, context)) = self.skip_context_for_threshold(&location) {
            if self.config.enable_panic_logging {
                self.report_skip(&reason, &context);
            }
            return PanicIsolationResult::Skipped { reason, context };
        }

        match std::panic::catch_unwind(AssertUnwindSafe(operation)) {
            Ok(result) => PanicIsolationResult::Success(result),
            Err(panic_payload) => {
                let panic_id = PANIC_COUNTER.fetch_add(1, Ordering::SeqCst);
                let context = self.create_panic_context(panic_id, location, &panic_payload);
                self.record_region_panic(&context);

                // Report panic to observability system
                if self.config.enable_panic_logging {
                    self.report_panic(&context);
                }

                // Update metrics
                self.metrics.record_panic(&context);

                PanicIsolationResult::Panicked(context)
            }
        }
    }

    fn skip_context_for_threshold(
        &self,
        location: &PanicLocation,
    ) -> Option<(String, PanicContext)> {
        let threshold = self.config.panic_threshold_per_region?;
        let region_id = self.location_region(location)?;
        let panic_count = {
            let guard = self.region_panic_counts.lock();
            guard.get(&region_id).copied().unwrap_or(0)
        };

        if panic_count < threshold {
            return None;
        }

        let reason = format!(
            "region {} exceeded panic threshold {} with {} isolated panics",
            region_id, threshold, panic_count
        );
        let panic_id = PANIC_COUNTER.fetch_add(1, Ordering::SeqCst);
        let context = self.create_skip_context(panic_id, location.clone(), reason.clone());
        Some((reason, context))
    }

    fn create_skip_context(
        &self,
        panic_id: u64,
        location: PanicLocation,
        reason: String,
    ) -> PanicContext {
        let (region_id, task_id, obligation_id) = self.location_ids(&location);
        PanicContext {
            panic_id,
            location,
            timestamp: Instant::now(),
            panic_message: Some(reason),
            backtrace: None,
            region_id,
            task_id,
            obligation_id,
        }
    }

    fn record_region_panic(&self, context: &PanicContext) {
        let Some(region_id) = context.region_id else {
            return;
        };
        let mut guard = self.region_panic_counts.lock();
        let count = guard.entry(region_id).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn location_region(&self, location: &PanicLocation) -> Option<RegionId> {
        self.location_ids(location).0
    }

    fn location_ids(
        &self,
        location: &PanicLocation,
    ) -> (Option<RegionId>, Option<TaskId>, Option<ObligationId>) {
        match location {
            PanicLocation::TaskExecution {
                task_id, region_id, ..
            } => (Some(*region_id), Some(*task_id), None),
            PanicLocation::FinalizerExecution { region_id, .. } => (Some(*region_id), None, None),
            PanicLocation::RegionCleanup { region_id, .. } => (Some(*region_id), None, None),
            PanicLocation::ObligationHandling {
                obligation_id,
                region_id,
            } => (Some(*region_id), None, Some(*obligation_id)),
            PanicLocation::SchedulerInternal { .. } => (None, None, None),
        }
    }

    /// Create detailed panic context from caught panic.
    fn create_panic_context(
        &self,
        panic_id: u64,
        location: PanicLocation,
        panic_payload: &Box<dyn std::any::Any + Send>,
    ) -> PanicContext {
        let panic_message = if let Some(s) = panic_payload.downcast_ref::<&str>() {
            Some((*s).to_string())
        } else if let Some(s) = panic_payload.downcast_ref::<String>() {
            Some(s.clone())
        } else {
            Some("Non-string panic payload".to_string())
        };

        let backtrace = if self.config.capture_backtraces {
            Some(format!("{}", Backtrace::force_capture()))
        } else {
            None
        };

        let (region_id, task_id, obligation_id) = self.location_ids(&location);

        PanicContext {
            panic_id,
            location,
            timestamp: Instant::now(),
            panic_message,
            backtrace,
            region_id,
            task_id,
            obligation_id,
        }
    }

    /// Report panic to the observability system.
    #[allow(unused_variables)]
    fn report_panic(&self, context: &PanicContext) {
        crate::tracing_compat::error!(
            panic_id = context.panic_id,
            location = ?context.location,
            panic_message = ?context.panic_message,
            region_id = ?context.region_id,
            task_id = ?context.task_id,
            obligation_id = ?context.obligation_id,
            timestamp = ?context.timestamp,
            "panic isolated"
        );

        if let Some(ref backtrace) = context.backtrace {
            crate::tracing_compat::error!(
                panic_id = context.panic_id,
                backtrace = %backtrace,
                "panic backtrace captured"
            );
        }
    }

    #[allow(unused_variables)]
    fn report_skip(&self, reason: &str, context: &PanicContext) {
        crate::tracing_compat::warn!(
            panic_id = context.panic_id,
            reason,
            location = ?context.location,
            region_id = ?context.region_id,
            task_id = ?context.task_id,
            obligation_id = ?context.obligation_id,
            timestamp = ?context.timestamp,
            "panic isolation skipped operation after threshold escalation"
        );
    }

    /// Convert isolated panic to a proper task outcome.
    pub fn panic_to_outcome(&self, context: &PanicContext) -> Outcome<(), crate::error::Error> {
        let panic_payload = PanicPayload::new(format!(
            "Task panicked in isolation (ID={}): {}",
            context.panic_id,
            context.panic_message.as_deref().unwrap_or("unknown")
        ));

        Outcome::Panicked(panic_payload)
    }
}

impl fmt::Display for PanicLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PanicLocation::TaskExecution {
                task_id,
                region_id,
                poll_attempt,
            } => {
                write!(
                    f,
                    "TaskExecution(task={:?}, region={:?}, poll={})",
                    task_id.0, region_id.0, poll_attempt
                )
            }
            PanicLocation::FinalizerExecution {
                region_id,
                finalizer_type,
            } => {
                write!(
                    f,
                    "FinalizerExecution(region={:?}, type={:?})",
                    region_id.0, finalizer_type
                )
            }
            PanicLocation::RegionCleanup {
                region_id,
                cleanup_phase,
            } => {
                write!(
                    f,
                    "RegionCleanup(region={:?}, phase={:?})",
                    region_id.0, cleanup_phase
                )
            }
            PanicLocation::ObligationHandling {
                obligation_id,
                region_id,
            } => {
                write!(
                    f,
                    "ObligationHandling(obligation={:?}, region={:?})",
                    obligation_id.0, region_id.0
                )
            }
            PanicLocation::SchedulerInternal {
                worker_id,
                operation,
            } => {
                if let Some(id) = worker_id {
                    write!(f, "SchedulerInternal(worker={}, op={})", id, operation)
                } else {
                    write!(f, "SchedulerInternal(op={})", operation)
                }
            }
        }
    }
}

/// Extension trait for MetricsProvider to support panic recording.
pub trait MetricsProviderPanicExt {
    /// Record a panic occurrence for metrics.
    fn record_panic(&self, context: &PanicContext);
}

impl<T: ?Sized + MetricsProvider> MetricsProviderPanicExt for T {
    fn record_panic(&self, context: &PanicContext) {
        // Record panic metrics - implementation would depend on the metrics system
        // For now, we'll just use a placeholder since the actual MetricsProvider
        // interface would need to be extended.
        let _location_tag = match &context.location {
            PanicLocation::TaskExecution { .. } => "task_execution",
            PanicLocation::FinalizerExecution { .. } => "finalizer_execution",
            PanicLocation::RegionCleanup { .. } => "region_cleanup",
            PanicLocation::ObligationHandling { .. } => "obligation_handling",
            PanicLocation::SchedulerInternal { .. } => "scheduler_internal",
        };

        // Metrics recording would happen here
        // self.increment_counter("runtime.panics.isolated", &[("location", location_tag)]);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::observability::metrics::NoOpMetrics;
    use crate::types::{RegionId, TaskId};
    use crate::util::ArenaIndex;

    #[test]
    fn test_panic_isolation_success() {
        let config = PanicIsolationConfig::default();
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(1, 0)),
            RegionId::from_arena(ArenaIndex::new(1, 0)),
            1,
            || 42,
        );

        assert!(result.is_success());
        assert_eq!(result.into_success(), Some(42));
    }

    #[test]
    fn test_panic_isolation_catches_panic() {
        let config = PanicIsolationConfig::default();
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(1, 0)),
            RegionId::from_arena(ArenaIndex::new(1, 0)),
            1,
            || panic!("test panic"),
        );

        assert!(result.is_panicked());
        if let PanicIsolationResult::Panicked(context) = result {
            assert_eq!(context.panic_message, Some("test panic".to_string()));
            assert!(matches!(
                context.location,
                PanicLocation::TaskExecution { .. }
            ));
        }
    }

    #[test]
    fn test_panic_context_creation() {
        let config = PanicIsolationConfig {
            capture_backtraces: true,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let result = isolator.isolate_finalizer_execution(
            RegionId::from_arena(ArenaIndex::new(2, 0)),
            FinalizerType::Sync,
            || panic!("finalizer panic"),
        );

        if let PanicIsolationResult::Panicked(context) = result {
            assert!(context.backtrace.is_some());
            assert_eq!(
                context.region_id,
                Some(RegionId::from_arena(ArenaIndex::new(2, 0)))
            );
            assert!(matches!(
                context.location,
                PanicLocation::FinalizerExecution { .. }
            ));
        } else {
            panic!("Expected panicked result");
        }
    }

    #[test]
    fn test_panic_to_outcome_conversion() {
        let config = PanicIsolationConfig::default();
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        let context = PanicContext {
            panic_id: 1,
            location: PanicLocation::TaskExecution {
                task_id: TaskId::from_arena(ArenaIndex::new(1, 0)),
                region_id: RegionId::from_arena(ArenaIndex::new(1, 0)),
                poll_attempt: 1,
            },
            timestamp: Instant::now(),
            panic_message: Some("test panic".to_string()),
            backtrace: None,
            region_id: Some(RegionId::from_arena(ArenaIndex::new(1, 0))),
            task_id: Some(TaskId::from_arena(ArenaIndex::new(1, 0))),
            obligation_id: None,
        };

        let outcome = isolator.panic_to_outcome(&context);
        assert!(matches!(outcome, Outcome::Panicked(_)));
    }

    #[test]
    fn test_disabled_isolation() {
        let config = PanicIsolationConfig {
            isolate_task_panics: false,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);

        // This should not panic because isolation is disabled,
        // but we can't easily test this without actually panicking
        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(1, 0)),
            RegionId::from_arena(ArenaIndex::new(1, 0)),
            1,
            || 42,
        );

        assert!(result.is_success());
        assert_eq!(result.into_success(), Some(42));
    }

    #[test]
    fn test_region_panic_threshold_skips_followup_operations() {
        let config = PanicIsolationConfig {
            panic_threshold_per_region: Some(1),
            capture_backtraces: false,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(7, 0));

        let first = isolator.isolate_task_execution(task_id, region_id, 1, || panic!("boom"));
        assert!(matches!(first, PanicIsolationResult::Panicked(_)));

        let second = isolator.isolate_task_execution(task_id, region_id, 2, || 99);
        match second {
            PanicIsolationResult::Skipped { reason, context } => {
                assert!(reason.contains("exceeded panic threshold 1"));
                assert_eq!(context.region_id, Some(region_id));
                assert_eq!(context.task_id, Some(task_id));
                assert_eq!(context.panic_message.as_deref(), Some(reason.as_str()));
            }
            other => panic!("expected skipped result, got {:?}", other),
        }
    }

    #[test]
    fn test_panic_threshold_isolated_per_region() {
        let config = PanicIsolationConfig {
            panic_threshold_per_region: Some(1),
            capture_backtraces: false,
            ..Default::default()
        };
        let metrics = Arc::new(NoOpMetrics);
        let isolator = PanicIsolator::new(config, metrics);
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_a = RegionId::from_arena(ArenaIndex::new(8, 0));
        let region_b = RegionId::from_arena(ArenaIndex::new(9, 0));

        let first = isolator.isolate_task_execution(task_id, region_a, 1, || panic!("boom"));
        assert!(matches!(first, PanicIsolationResult::Panicked(_)));

        let other_region = isolator.isolate_task_execution(task_id, region_b, 1, || 7);
        assert!(matches!(other_region, PanicIsolationResult::Success(7)));
    }
}
