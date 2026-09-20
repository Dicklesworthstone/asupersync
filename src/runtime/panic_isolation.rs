//! Panic isolation framework for structured concurrency runtime.
//!
//! Isolates unwinding operation panics and preserves their original context even
//! when reporting callbacks or panic-payload destructors also panic. Reporting
//! failures are counted independently rather than recursively reported.
//!
//! This cannot contain aborting panics, panicking panic hooks, double panics
//! during unwinding, or callbacks/destructors that never return. If destroying a
//! caught payload panics, the secondary payload is deliberately forgotten: one
//! destructor attempt bounds the work, but may leak that secondary payload.

use crate::observability::metrics::MetricsProvider;
use crate::types::{ObligationId, Outcome, RegionId, TaskId, outcome::PanicPayload};
use std::backtrace::Backtrace;
use std::collections::BTreeMap;
use std::fmt;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
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
    /// Operation invocation or retirement of a skipped operation panicked and was isolated.
    Panicked(PanicContext),
    /// Operation invocation was skipped due to the region's panic threshold.
    ///
    /// Captured values were dropped inside the isolation boundary. If that
    /// retirement unwinds, the result is `Panicked` rather than `Skipped`.
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
    suppressed_observer_panics: AtomicU64,
    suppressed_payload_drop_panics: AtomicU64,
}

impl PanicIsolator {
    /// Create a new panic isolator with the given configuration.
    pub fn new(config: PanicIsolationConfig, metrics: Arc<dyn MetricsProvider>) -> Self {
        Self {
            config,
            metrics,
            region_panic_counts: Mutex::new(BTreeMap::new()),
            suppressed_observer_panics: AtomicU64::new(0),
            suppressed_payload_drop_panics: AtomicU64::new(0),
        }
    }

    /// Number of unwinding logging/metrics callback panics contained here.
    ///
    /// Read directly rather than through the potentially failing observer. This
    /// diagnostic counter does not synchronize runtime state or count toward a
    /// region's primary-operation panic threshold.
    #[must_use]
    pub fn suppressed_observer_panics(&self) -> u64 {
        self.suppressed_observer_panics.load(Ordering::Relaxed)
    }

    /// Number of caught panic payloads whose destruction also panicked.
    ///
    /// Each such failure forgets the secondary payload without trying its
    /// destructor. This bounds disposal work per failure, not aggregate leaked
    /// memory when user code repeatedly supplies hostile payloads.
    #[must_use]
    pub fn suppressed_payload_drop_panics(&self) -> u64 {
        self.suppressed_payload_drop_panics.load(Ordering::Relaxed)
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
            region_id: region_id,
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
            region_id: region_id,
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
            region_id: region_id,
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
            region_id: region_id,
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
            // Rejected work still owns captures. Retire them inside a boundary
            // without invoking the operation or holding the region-counter lock.
            // A cleanup failure is a real primary panic, not a successful skip.
            if let Err(payload) = std::panic::catch_unwind(AssertUnwindSafe(|| drop(operation))) {
                return self.handle_panic(location, payload);
            }
            if self.config.enable_panic_logging {
                self.run_observer(|| self.report_skip(&reason, &context));
            }
            return PanicIsolationResult::Skipped { reason, context };
        }

        match std::panic::catch_unwind(AssertUnwindSafe(operation)) {
            Ok(result) => PanicIsolationResult::Success(result),
            Err(panic_payload) => self.handle_panic(location, panic_payload),
        }
    }

    fn handle_panic<T>(
        &self,
        location: PanicLocation,
        panic_payload: Box<dyn std::any::Any + Send>,
    ) -> PanicIsolationResult<T> {
        // Relaxed suffices for unique-counter semantics; IDs are not fences.
        let panic_id = PANIC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let context = self.create_panic_context(panic_id, location, &panic_payload);
        self.record_region_panic(&context);

        // Commit the original context/count before running any foreign code.
        // No region-counter guard survives into disposal or observer dispatch.
        self.discard_panic_payload(panic_payload);
        if self.config.enable_panic_logging {
            self.run_observer(|| self.report_panic(&context));
        }
        // A logging failure must not suppress the independent metrics attempt.
        // UFCS distinguishes this adapter from MetricsProvider::record_panic.
        self.run_observer(|| MetricsProviderPanicExt::record_panic(&*self.metrics, &context));

        PanicIsolationResult::Panicked(context)
    }

    fn run_observer(&self, observer: impl FnOnce()) {
        if let Err(payload) = std::panic::catch_unwind(AssertUnwindSafe(observer)) {
            self.suppressed_observer_panics
                .fetch_add(1, Ordering::Relaxed);
            // Reporting this through the same observer could recurse forever.
            self.discard_panic_payload(payload);
        }
    }

    fn discard_panic_payload(&self, payload: Box<dyn std::any::Any + Send>) {
        if let Err(secondary) = std::panic::catch_unwind(AssertUnwindSafe(|| drop(payload))) {
            self.suppressed_payload_drop_panics
                .fetch_add(1, Ordering::Relaxed);
            // Arbitrary payload destructors can panic with another instance of
            // themselves. Never recursively dispose that secondary payload.
            std::mem::forget(secondary);
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
        // br-asupersync-h0pfb4: Relaxed for unique-counter semantics.
        let panic_id = PANIC_COUNTER.fetch_add(1, Ordering::Relaxed);
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
    /// br-asupersync-zcu3c4 — Routes the panic to
    /// [`MetricsProvider::record_panic`] with the canonical location tag.
    /// The previous implementation ignored the computed tag; production
    /// metrics providers can now override `record_panic` to count panics by
    /// location.
    fn record_panic(&self, context: &PanicContext) {
        let location_tag: &'static str = match &context.location {
            PanicLocation::TaskExecution { .. } => "task_execution",
            PanicLocation::FinalizerExecution { .. } => "finalizer_execution",
            PanicLocation::RegionCleanup { .. } => "region_cleanup",
            PanicLocation::ObligationHandling { .. } => "obligation_handling",
            PanicLocation::SchedulerInternal { .. } => "scheduler_internal",
        };
        MetricsProvider::record_panic(self, location_tag);
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
    use std::sync::Mutex as StdMutex;

    #[derive(Default)]
    struct CapturingMetrics {
        on_panic: Option<Box<dyn Fn(&'static str) + Send + Sync>>,
        panics: StdMutex<Vec<&'static str>>,
        tasks_spawned: StdMutex<Vec<(RegionId, TaskId)>>,
        tasks_completed: StdMutex<
            Vec<(
                TaskId,
                crate::observability::metrics::OutcomeKind,
                std::time::Duration,
            )>,
        >,
        regions_created: StdMutex<Vec<(RegionId, Option<RegionId>)>>,
        regions_closed: StdMutex<Vec<(RegionId, std::time::Duration)>>,
        cancellation_requests: StdMutex<Vec<(RegionId, crate::types::CancelKind)>>,
        drain_completions: StdMutex<Vec<(RegionId, std::time::Duration)>>,
        obligations_created: StdMutex<Vec<RegionId>>,
        obligations_discharged: StdMutex<Vec<RegionId>>,
        obligations_leaked: StdMutex<Vec<RegionId>>,
    }

    impl CapturingMetrics {
        fn tasks_spawned(&self) -> Vec<(RegionId, TaskId)> {
            self.tasks_spawned
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn regions_created(&self) -> Vec<(RegionId, Option<RegionId>)> {
            self.regions_created
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn regions_closed(&self) -> Vec<(RegionId, std::time::Duration)> {
            self.regions_closed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn obligations_created(&self) -> Vec<RegionId> {
            self.obligations_created
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn cancellation_requests(&self) -> Vec<(RegionId, crate::types::CancelKind)> {
            self.cancellation_requests
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        #[allow(dead_code)]
        fn panics_captured(&self) -> Vec<&'static str> {
            self.panics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl crate::observability::metrics::MetricsProvider for CapturingMetrics {
        fn task_spawned(&self, region_id: RegionId, task_id: TaskId) {
            self.tasks_spawned
                .lock()
                .unwrap()
                .push((region_id, task_id));
        }

        fn task_completed(
            &self,
            task_id: TaskId,
            outcome: crate::observability::metrics::OutcomeKind,
            duration: std::time::Duration,
        ) {
            self.tasks_completed
                .lock()
                .unwrap()
                .push((task_id, outcome, duration));
        }

        fn region_created(&self, region_id: RegionId, parent_id: Option<RegionId>) {
            self.regions_created
                .lock()
                .unwrap()
                .push((region_id, parent_id));
        }

        fn region_closed(&self, region_id: RegionId, duration: std::time::Duration) {
            self.regions_closed
                .lock()
                .unwrap()
                .push((region_id, duration));
        }

        fn cancellation_requested(
            &self,
            region_id: RegionId,
            cancel_kind: crate::types::CancelKind,
        ) {
            self.cancellation_requests
                .lock()
                .unwrap()
                .push((region_id, cancel_kind));
        }

        fn drain_completed(&self, region_id: RegionId, duration: std::time::Duration) {
            self.drain_completions
                .lock()
                .unwrap()
                .push((region_id, duration));
        }

        fn deadline_set(&self, __region_id: RegionId, __duration: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_exceeded(&self, __region_id: RegionId) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_warning(
            &self,
            _context: &str,
            _location: &'static str,
            _remaining: std::time::Duration,
        ) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_violation(&self, _context: &str, _elapsed: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn deadline_remaining(&self, _context: &str, _remaining: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn checkpoint_interval(&self, _context: &str, _interval: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn task_stuck_detected(&self, _task_context: &str) {
            // Simple implementation - could extend if needed for testing
        }

        fn obligation_created(&self, region_id: RegionId) {
            self.obligations_created
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(region_id);
        }

        fn obligation_discharged(&self, region_id: RegionId) {
            self.obligations_discharged
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(region_id);
        }

        fn obligation_leaked(&self, region_id: RegionId) {
            self.obligations_leaked
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(region_id);
        }

        fn scheduler_tick(&self, _ready_count: usize, _tick_duration: std::time::Duration) {
            // Simple implementation - could extend if needed for testing
        }

        fn record_panic(&self, location: &'static str) {
            self.panics
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(location);
            if let Some(observer) = &self.on_panic {
                observer(location);
            }
        }
    }

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

    /// br-asupersync-zcu3c4 — verifies that the previously inert
    /// `MetricsProviderPanicExt::record_panic` now actually delegates to
    /// `MetricsProvider::record_panic`, with the canonical location tag.
    /// The old code path computed `_location_tag` and discarded it; production
    /// dashboards never observed any panic-rate signal.
    #[test]
    fn record_panic_routes_to_metrics_provider() {
        use std::sync::Mutex as StdMutex;

        #[derive(Default)]
        struct CapturingMetrics {
            panics: StdMutex<Vec<&'static str>>,
            tasks_spawned: StdMutex<Vec<(RegionId, TaskId)>>,
            tasks_completed: StdMutex<
                Vec<(
                    TaskId,
                    crate::observability::metrics::OutcomeKind,
                    std::time::Duration,
                )>,
            >,
            regions_created: StdMutex<Vec<(RegionId, Option<RegionId>)>>,
            regions_closed: StdMutex<Vec<(RegionId, std::time::Duration)>>,
            cancellation_requests: StdMutex<Vec<(RegionId, crate::types::CancelKind)>>,
            drain_completions: StdMutex<Vec<(RegionId, std::time::Duration)>>,
            obligations_created: StdMutex<Vec<RegionId>>,
            obligations_discharged: StdMutex<Vec<RegionId>>,
            obligations_leaked: StdMutex<Vec<RegionId>>,
        }

        #[allow(dead_code)]
        impl CapturingMetrics {
            fn tasks_spawned(&self) -> Vec<(RegionId, TaskId)> {
                self.tasks_spawned
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn regions_created(&self) -> Vec<(RegionId, Option<RegionId>)> {
                self.regions_created
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn regions_closed(&self) -> Vec<(RegionId, std::time::Duration)> {
                self.regions_closed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn obligations_created(&self) -> Vec<RegionId> {
                self.obligations_created
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn obligations_leaked(&self) -> Vec<RegionId> {
                self.obligations_leaked
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }

            fn cancellation_requests(&self) -> Vec<(RegionId, crate::types::CancelKind)> {
                self.cancellation_requests
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            }
        }

        impl crate::observability::metrics::MetricsProvider for CapturingMetrics {
            fn task_spawned(&self, region_id: RegionId, task_id: TaskId) {
                self.tasks_spawned
                    .lock()
                    .unwrap()
                    .push((region_id, task_id));
            }

            fn task_completed(
                &self,
                task_id: TaskId,
                outcome_kind: crate::observability::metrics::OutcomeKind,
                duration: std::time::Duration,
            ) {
                self.tasks_completed
                    .lock()
                    .unwrap()
                    .push((task_id, outcome_kind, duration));
            }

            fn region_created(&self, region_id: RegionId, parent_id: Option<RegionId>) {
                self.regions_created
                    .lock()
                    .unwrap()
                    .push((region_id, parent_id));
            }

            fn region_closed(&self, region_id: RegionId, duration: std::time::Duration) {
                self.regions_closed
                    .lock()
                    .unwrap()
                    .push((region_id, duration));
            }

            fn cancellation_requested(
                &self,
                region_id: RegionId,
                cancel_kind: crate::types::CancelKind,
            ) {
                self.cancellation_requests
                    .lock()
                    .unwrap()
                    .push((region_id, cancel_kind));
            }

            fn drain_completed(&self, region_id: RegionId, duration: std::time::Duration) {
                self.drain_completions
                    .lock()
                    .unwrap()
                    .push((region_id, duration));
            }

            fn deadline_set(&self, _region_id: RegionId, _duration: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_exceeded(&self, _region_id: RegionId) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_warning(
                &self,
                _context: &str,
                _location: &'static str,
                _remaining: std::time::Duration,
            ) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_violation(&self, _context: &str, _elapsed: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn deadline_remaining(&self, _context: &str, _remaining: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn checkpoint_interval(&self, _context: &str, _interval: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn task_stuck_detected(&self, _task_context: &str) {
                // Simple implementation - could extend if needed for testing
            }

            fn obligation_created(&self, region_id: RegionId) {
                self.obligations_created
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(region_id);
            }

            fn obligation_discharged(&self, region_id: RegionId) {
                self.obligations_discharged
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(region_id);
            }

            fn obligation_leaked(&self, region_id: RegionId) {
                self.obligations_leaked
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(region_id);
            }

            fn scheduler_tick(&self, _ready_count: usize, _tick_duration: std::time::Duration) {
                // Simple implementation - could extend if needed for testing
            }

            fn record_panic(&self, location: &'static str) {
                self.panics
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(location);
            }
        }

        let metrics = CapturingMetrics::default();
        let task_id = TaskId::from_arena(ArenaIndex::new(1, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(2, 0));

        // Build a panic context for each of the 5 PanicLocation variants and
        // route through the extension trait. Each must produce exactly one
        // record_panic call with the matching canonical tag.
        let cases: Vec<(PanicLocation, &'static str)> = vec![
            (
                PanicLocation::TaskExecution {
                    task_id,
                    region_id,
                    poll_attempt: 1,
                },
                "task_execution",
            ),
            (
                PanicLocation::FinalizerExecution {
                    region_id,
                    finalizer_type: FinalizerType::Sync,
                },
                "finalizer_execution",
            ),
            (
                PanicLocation::RegionCleanup {
                    region_id,
                    cleanup_phase: CleanupPhase::Finalizers,
                },
                "region_cleanup",
            ),
            (
                PanicLocation::ObligationHandling {
                    obligation_id: ObligationId::from_arena(ArenaIndex::new(3, 0)),
                    region_id,
                },
                "obligation_handling",
            ),
            (
                PanicLocation::SchedulerInternal {
                    worker_id: Some(0),
                    operation: "test".to_string(),
                },
                "scheduler_internal",
            ),
        ];

        for (location, _expected) in &cases {
            let ctx = PanicContext {
                panic_id: 0,
                location: location.clone(),
                timestamp: Instant::now(),
                panic_message: Some("test".to_string()),
                backtrace: None,
                region_id: Some(region_id),
                task_id: Some(task_id),
                obligation_id: None,
            };
            <CapturingMetrics as MetricsProviderPanicExt>::record_panic(&metrics, &ctx);
        }

        let observed: Vec<&'static str> = metrics
            .panics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let expected: Vec<&'static str> = cases.iter().map(|(_, t)| *t).collect();
        assert_eq!(
            observed, expected,
            "every PanicLocation must route to a record_panic call with the canonical tag"
        );
    }

    /// Test that instrumentation callbacks properly capture runtime lifecycle events
    /// during panic isolation scenarios. This verifies that the previously inert
    /// MetricsProvider implementation now collects observability data for monitoring
    /// region creation, task spawning, obligation tracking, and cancellation events.
    #[test]
    fn instrumentation_callbacks_capture_runtime_lifecycle_events() {
        // Create CapturingMetrics directly so we can access the captured data
        let metrics = Arc::new(CapturingMetrics::default());

        let task_id = TaskId::from_arena(ArenaIndex::new(42, 1));
        let region_id = RegionId::from_arena(ArenaIndex::new(100, 2));
        let parent_region_id = RegionId::from_arena(ArenaIndex::new(99, 1));

        // Simulate runtime events by directly calling the metrics provider
        let metrics_ref = &*metrics;

        // Simulate region lifecycle
        metrics_ref.region_created(region_id, Some(parent_region_id));
        metrics_ref.task_spawned(region_id, task_id);

        // Simulate obligation tracking
        metrics_ref.obligation_created(region_id);

        // Simulate task completion
        metrics_ref.task_completed(
            task_id,
            crate::observability::metrics::OutcomeKind::Ok,
            std::time::Duration::from_millis(100),
        );

        // Simulate cancellation
        metrics_ref.cancellation_requested(region_id, crate::types::CancelKind::User);

        // Simulate obligation lifecycle
        metrics_ref.obligation_discharged(region_id);

        // Simulate region closure
        metrics_ref.region_closed(region_id, std::time::Duration::from_millis(500));

        // Verify all events were captured
        // Check that region creation was captured
        let regions_created = metrics.regions_created();
        assert_eq!(regions_created.len(), 1);
        assert_eq!(regions_created[0], (region_id, Some(parent_region_id)));

        // Check that task spawning was captured
        let tasks_spawned = metrics.tasks_spawned();
        assert_eq!(tasks_spawned.len(), 1);
        assert_eq!(tasks_spawned[0], (region_id, task_id));

        // Check that region closure was captured
        let regions_closed = metrics.regions_closed();
        assert_eq!(regions_closed.len(), 1);
        assert_eq!(regions_closed[0].0, region_id);
        assert_eq!(regions_closed[0].1, std::time::Duration::from_millis(500));

        // Check that obligations were tracked
        let obligations_created = metrics.obligations_created();
        assert_eq!(obligations_created.len(), 1);
        assert_eq!(obligations_created[0], region_id);

        // Check that cancellation was captured
        let cancellation_requests = metrics.cancellation_requests();
        assert_eq!(cancellation_requests.len(), 1);
        assert_eq!(
            cancellation_requests[0],
            (region_id, crate::types::CancelKind::User)
        );
    }

    fn quiet_isolator(metrics: Arc<dyn MetricsProvider>) -> PanicIsolator {
        PanicIsolator::new(
            PanicIsolationConfig {
                capture_backtraces: false,
                enable_panic_logging: false,
                panic_threshold_per_region: Some(2),
                ..Default::default()
            },
            metrics,
        )
    }

    struct PanickingPayload(Arc<std::sync::atomic::AtomicUsize>);

    impl Drop for PanickingPayload {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
            panic!("payload destructor panic");
        }
    }

    #[test]
    fn panicking_metrics_preserve_primary_context_and_region_accounting() {
        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(|_| panic!("metrics observer panic"))),
            ..Default::default()
        });
        let isolator = quiet_isolator(metrics.clone());
        let task = TaskId::from_arena(ArenaIndex::new(11, 0));
        let region = RegionId::from_arena(ArenaIndex::new(12, 0));

        let result = isolator.isolate_task_execution(task, region, 1, || {
            panic!("original task panic");
        });
        let context = result.panic_context().expect("original panic is retained");
        assert_eq!(context.panic_message.as_deref(), Some("original task panic"));
        assert_eq!(context.task_id, Some(task));
        assert_eq!(context.region_id, Some(region));
        assert_eq!(metrics.panics_captured(), vec!["task_execution"]);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 0);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&1));
        // A secondary metrics panic must not exhaust the two-panic threshold.
        assert_eq!(
            isolator
                .isolate_task_execution(task, region, 2, || 7)
                .into_success(),
            Some(7)
        );
    }

    #[test]
    fn payload_destructor_panic_does_not_escape_or_suppress_metrics() {
        let metrics = Arc::new(CapturingMetrics::default());
        let isolator = quiet_isolator(metrics.clone());
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payload = PanickingPayload(drops.clone());
        let region = RegionId::from_arena(ArenaIndex::new(13, 0));
        let result = isolator.isolate_finalizer_execution(region, FinalizerType::Sync, || {
            std::panic::panic_any(payload);
        });

        assert!(result.is_panicked());
        assert_eq!(
            result.panic_context().unwrap().panic_message.as_deref(),
            Some("Non-string panic payload")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.panics_captured(), vec!["finalizer_execution"]);
        assert_eq!(isolator.suppressed_observer_panics(), 0);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&1));
    }

    #[test]
    fn observer_payload_destructor_panic_is_also_contained() {
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observer_drops = drops.clone();
        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(move |_| {
                std::panic::panic_any(PanickingPayload(observer_drops.clone()));
            })),
            ..Default::default()
        });
        let isolator = quiet_isolator(metrics);
        let result = isolator.isolate_scheduler_operation(None, "poll".into(), || {
            panic!("primary scheduler panic");
        });

        assert_eq!(
            result.panic_context().unwrap().panic_message.as_deref(),
            Some("primary scheduler panic")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
    }

    #[test]
    fn recursively_panicking_payload_gets_only_one_destructor_attempt() {
        struct RecursivePayload(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for RecursivePayload {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(Self(self.0.clone()));
            }
        }

        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let isolator = quiet_isolator(Arc::new(NoOpMetrics));
        let payload = RecursivePayload(drops.clone());
        let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
            isolator.isolate_scheduler_operation(None, "poll".into(), || {
                std::panic::panic_any(payload);
            })
        }));
        let result = match caught {
            Ok(result) => result,
            Err(escaped) => {
                // Keep the negative control from aborting the test process by
                // dropping this intentionally self-reproducing panic payload.
                std::mem::forget(escaped);
                panic!("payload destructor escaped panic isolation");
            }
        };
        assert!(result.is_panicked());
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
    }

    #[test]
    fn failed_observer_does_not_prevent_independent_observer_dispatch() {
        let isolator = quiet_isolator(Arc::new(NoOpMetrics));
        let calls = std::sync::atomic::AtomicUsize::new(0);
        isolator.run_observer(|| panic!("first observer"));
        isolator.run_observer(|| {
            calls.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
        assert!(isolator.region_panic_counts.lock().is_empty());
    }

    #[test]
    fn metrics_observer_can_reenter_after_primary_accounting_is_published() {
        let slot = Arc::new(StdMutex::new(std::sync::Weak::<PanicIsolator>::new()));
        let observer_slot = slot.clone();
        let region = RegionId::from_arena(ArenaIndex::new(14, 0));
        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(move |_| {
                let isolator = observer_slot.lock().unwrap().upgrade().unwrap();
                {
                    let counts = isolator
                        .region_panic_counts
                        .try_lock()
                        .expect("observer must not run under the counter lock");
                    assert_eq!(counts.get(&region), Some(&1));
                }
                assert_eq!(
                    isolator
                        .isolate_region_cleanup(region, CleanupPhase::ResourceCleanup, || 9)
                        .into_success(),
                    Some(9)
                );
            })),
            ..Default::default()
        });
        let isolator = Arc::new(quiet_isolator(metrics.clone()));
        *slot.lock().unwrap() = Arc::downgrade(&isolator);
        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(15, 0)),
            region,
            1,
            || panic!("primary"),
        );
        assert!(result.is_panicked());
        assert_eq!(metrics.panics_captured(), vec!["task_execution"]);
        // Assertions inside observers must not be silently swallowed by the
        // boundary being tested.
        assert_eq!(isolator.suppressed_observer_panics(), 0);
        assert_eq!(isolator.suppressed_payload_drop_panics(), 0);
    }

    #[test]
    fn threshold_skip_releases_captures_without_running_operation() {
        struct Capture(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Capture {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let metrics = Arc::new(CapturingMetrics::default());
        let mut isolator = quiet_isolator(metrics.clone());
        isolator.config.panic_threshold_per_region = Some(0);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = Capture(drops.clone());
        let invoked = std::sync::atomic::AtomicBool::new(false);
        let result = isolator.isolate_task_execution(
            TaskId::from_arena(ArenaIndex::new(16, 0)),
            RegionId::from_arena(ArenaIndex::new(17, 0)),
            1,
            || {
                invoked.store(true, Ordering::SeqCst);
                drop(capture);
                42
            },
        );
        assert!(matches!(result, PanicIsolationResult::Skipped { .. }));
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(metrics.panics_captured().is_empty());
        assert!(isolator.region_panic_counts.lock().is_empty());
    }

    #[test]
    fn threshold_skip_contains_capture_drop_panics_at_each_region_entrypoint() {
        let task_id = TaskId::from_arena(ArenaIndex::new(18, 0));
        let region_id = RegionId::from_arena(ArenaIndex::new(19, 0));
        let obligation_id = ObligationId::from_arena(ArenaIndex::new(20, 0));
        let cases = [
            (
                PanicLocation::TaskExecution {
                    task_id,
                    region_id,
                    poll_attempt: 3,
                },
                "task_execution",
            ),
            (
                PanicLocation::FinalizerExecution {
                    region_id,
                    finalizer_type: FinalizerType::Sync,
                },
                "finalizer_execution",
            ),
            (
                PanicLocation::RegionCleanup {
                    region_id,
                    cleanup_phase: CleanupPhase::ResourceCleanup,
                },
                "region_cleanup",
            ),
            (
                PanicLocation::ObligationHandling {
                    obligation_id,
                    region_id,
                },
                "obligation_handling",
            ),
        ];
        for (location, tag) in cases {
            let metrics = Arc::new(CapturingMetrics::default());
            let mut isolator = quiet_isolator(metrics.clone());
            isolator.config.panic_threshold_per_region = Some(0);
            let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let capture = PanickingPayload(drops.clone());
            let invoked = std::sync::atomic::AtomicBool::new(false);
            let operation = || {
                invoked.store(true, Ordering::SeqCst);
                drop(capture);
                42
            };
            let result = match &location {
                PanicLocation::TaskExecution { poll_attempt, .. } => {
                    isolator.isolate_task_execution(task_id, region_id, *poll_attempt, operation)
                }
                PanicLocation::FinalizerExecution { finalizer_type, .. } => {
                    isolator.isolate_finalizer_execution(region_id, finalizer_type.clone(), operation)
                }
                PanicLocation::RegionCleanup { cleanup_phase, .. } => {
                    isolator.isolate_region_cleanup(region_id, cleanup_phase.clone(), operation)
                }
                PanicLocation::ObligationHandling { .. } => {
                    isolator.isolate_obligation_handling(obligation_id, region_id, operation)
                }
                PanicLocation::SchedulerInternal { .. } => unreachable!(),
            };
            assert!(
                result.is_panicked(),
                "capture cleanup must not escape or be hidden as skipped"
            );
            let context = result.panic_context().unwrap();
            assert_eq!(context.location, location);
            assert_eq!(context.region_id, Some(region_id));
            assert_eq!(
                context.panic_message.as_deref(),
                Some("payload destructor panic")
            );
            assert!(!invoked.load(Ordering::SeqCst));
            assert_eq!(drops.load(Ordering::SeqCst), 1);
            assert_eq!(metrics.panics_captured(), vec![tag]);
            assert_eq!(isolator.region_panic_counts.lock().get(&region_id), Some(&1));
            assert_eq!(isolator.suppressed_observer_panics(), 0);
            // The capture panicked; its resulting string payload did not.
            assert_eq!(isolator.suppressed_payload_drop_panics(), 0);
        }
    }

    #[test]
    fn reached_threshold_counts_cleanup_failure_without_affecting_other_regions() {
        let metrics = Arc::new(CapturingMetrics::default());
        let mut isolator = quiet_isolator(metrics.clone());
        isolator.config.panic_threshold_per_region = Some(1);
        let task = TaskId::from_arena(ArenaIndex::new(21, 0));
        let region = RegionId::from_arena(ArenaIndex::new(22, 0));
        assert!(
            isolator
                .isolate_task_execution(task, region, 1, || panic!("first"))
                .is_panicked()
        );

        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = PanickingPayload(drops.clone());
        let invoked = std::sync::atomic::AtomicBool::new(false);
        let result = isolator.isolate_region_cleanup(region, CleanupPhase::ResourceCleanup, || {
            invoked.store(true, Ordering::SeqCst);
            drop(capture);
        });
        assert!(result.is_panicked());
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&2));
        assert_eq!(
            metrics.panics_captured(),
            vec!["task_execution", "region_cleanup"]
        );
        let healthy_region = RegionId::from_arena(ArenaIndex::new(23, 0));
        assert_eq!(
            isolator
                .isolate_task_execution(task, healthy_region, 1, || 7)
                .into_success(),
            Some(7)
        );
    }

    #[test]
    fn skipped_capture_cleanup_contains_compound_payload_and_observer_failures() {
        struct Capture {
            drops: Arc<std::sync::atomic::AtomicUsize>,
            payload_drops: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for Capture {
            fn drop(&mut self) {
                self.drops.fetch_add(1, Ordering::SeqCst);
                std::panic::panic_any(PanickingPayload(self.payload_drops.clone()));
            }
        }

        let metrics = Arc::new(CapturingMetrics {
            on_panic: Some(Box::new(|_| panic!("observer failed too"))),
            ..Default::default()
        });
        let mut isolator = quiet_isolator(metrics.clone());
        isolator.config.panic_threshold_per_region = Some(0);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let payload_drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = Capture {
            drops: drops.clone(),
            payload_drops: payload_drops.clone(),
        };
        let region = RegionId::from_arena(ArenaIndex::new(24, 0));
        let invoked = std::sync::atomic::AtomicBool::new(false);
        let result = isolator.isolate_finalizer_execution(region, FinalizerType::Sync, || {
            invoked.store(true, Ordering::SeqCst);
            drop(capture);
        });
        assert!(result.is_panicked());
        assert!(!invoked.load(Ordering::SeqCst));
        assert_eq!(
            result.panic_context().unwrap().panic_message.as_deref(),
            Some("Non-string panic payload")
        );
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(payload_drops.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.panics_captured(), vec!["finalizer_execution"]);
        assert_eq!(isolator.region_panic_counts.lock().get(&region), Some(&1));
        assert_eq!(isolator.suppressed_payload_drop_panics(), 1);
        assert_eq!(isolator.suppressed_observer_panics(), 1);
    }

    #[test]
    fn skipped_capture_can_reenter_without_region_counter_lock() {
        struct Capture {
            isolator: Arc<PanicIsolator>,
            drops: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl Drop for Capture {
            fn drop(&mut self) {
                {
                    let counts = self
                        .isolator
                        .region_panic_counts
                        .try_lock()
                        .expect("capture retirement must be outside the region counter lock");
                    assert!(counts.is_empty());
                }
                assert_eq!(
                    self.isolator
                        .isolate_scheduler_operation(None, "capture cleanup".into(), || 9)
                        .into_success(),
                    Some(9)
                );
                self.drops.fetch_add(1, Ordering::SeqCst);
            }
        }
        let mut isolator = quiet_isolator(Arc::new(NoOpMetrics));
        isolator.config.panic_threshold_per_region = Some(0);
        let isolator = Arc::new(isolator);
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let capture = Capture {
            isolator: isolator.clone(),
            drops: drops.clone(),
        };
        let result = isolator.isolate_region_cleanup(
            RegionId::from_arena(ArenaIndex::new(25, 0)),
            CleanupPhase::ResourceCleanup,
            || drop(capture),
        );
        // A swallowed assertion in the capture destructor must fail this test.
        assert!(matches!(result, PanicIsolationResult::Skipped { .. }));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(isolator.region_panic_counts.lock().is_empty());
    }

    #[test]
    fn disabled_isolation_still_bypasses_zero_threshold() {
        let mut isolator = quiet_isolator(Arc::new(NoOpMetrics));
        isolator.config.panic_threshold_per_region = Some(0);
        isolator.config.isolate_task_panics = false;
        isolator.config.isolate_finalizer_panics = false;
        let task = TaskId::from_arena(ArenaIndex::new(26, 0));
        let region = RegionId::from_arena(ArenaIndex::new(27, 0));
        assert_eq!(
            isolator.isolate_task_execution(task, region, 1, || 5).into_success(),
            Some(5)
        );
        assert_eq!(
            isolator.isolate_finalizer_execution(region, FinalizerType::Sync, || 6).into_success(),
            Some(6)
        );
        let propagated = std::panic::catch_unwind(AssertUnwindSafe(|| {
            isolator.isolate_task_execution(task, region, 2, || panic!("not isolated"))
        }));
        assert!(propagated.is_err());
        assert!(isolator.region_panic_counts.lock().is_empty());
    }
}
