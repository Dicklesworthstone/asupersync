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
    /// Maximum number of panics per region before refusing further task polls.
    /// Finalizers, region cleanup, and obligation resolution still run under
    /// their isolation boundaries so escalation cannot abandon cleanup.
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
    /// Task invocation was skipped due to the region's panic threshold.
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
        // Escalation stops ordinary work, never the work needed to release its
        // resources. In particular, skipping a finalizer here used to discard
        // its closure while the scheduler still recorded it as having run
        // (br-asupersync-bzonpu). Cleanup panics remain isolated and counted;
        // they do not prevent the next independent cleanup attempt.
        if !matches!(location, PanicLocation::TaskExecution { .. }) {
            return None;
        }
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
#[path = "panic_isolation_inline_tests.rs"]
mod tests;
