//! Bounded owned and host runtime samples for the desktop profile.
//!
//! These samples compose the reviewed desktop profile with explicit,
//! host-visible bounds: worker threads, blocking-pool bounds, global queue
//! depth, and owned root regions. They exist so embedders can copy a complete
//! reviewed construction instead of reassembling the engine knobs by hand.
//!
//! Clocks: the owned sample runs entirely on the runtime's monotonic clock.
//! The host sample delegates the clock domain to the caller — every deadline
//! is expressed against a host-supplied [`std::time::Instant`], and the
//! sample reports whether the runtime met it. A deadline already in the past
//! is a typed refusal, never a silent pass.
//!
//! Budgets: [`validate_priority_max_meet`] runs the real [`Budget::meet`]
//! rule and verifies its documented algebra (priority-max, tightest bounds)
//! before a sample accepts a budget pair.
//!
//! No hidden globals: every sample holds its own configuration; two samples
//! with different profiles coexist and close independently.

use std::time::{Duration, Instant};

use crate::Budget;
use crate::desktop_profile::{
    DesktopRuntime, DesktopRuntimeProfile, DesktopRuntimeStartError, ForeignCallCompletion,
};

/// A bounded runtime owned end-to-end by the sample holder.
///
/// All limits come from the supplied profile and are echoed in the drain
/// report so operators can retain bounded evidence of the envelope a sample
/// actually ran under.
pub struct OwnedRuntimeSample {
    profile: DesktopRuntimeProfile,
    limits: SampleLimits,
    runtime: Option<DesktopRuntime>,
}

impl std::fmt::Debug for OwnedRuntimeSample {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedRuntimeSample")
            .field("profile", &self.profile)
            .field("limits", &self.limits)
            .field("runtime_active", &self.runtime.is_some())
            .finish()
    }
}

/// The explicit bounds a sample runs under, captured from the profile's
/// materialized configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleLimits {
    /// Explicit worker bound.
    pub worker_threads: usize,
    /// Explicit blocking-pool upper bound.
    pub blocking_max_threads: usize,
    /// Explicit global queue depth bound.
    pub global_queue_limit: usize,
    /// Explicit owned-region heap ceiling.
    pub root_max_heap_bytes: usize,
}

/// Bounded evidence returned when a sample closes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SampleDrainReport {
    /// Whether the engine drained within the supplied timeout.
    pub drained: bool,
    /// The bounds the sample ran under.
    pub limits: SampleLimits,
}

impl OwnedRuntimeSample {
    /// Validate and start an owned sample with the profile's explicit bounds.
    ///
    /// Zero or inverted bounds are refused by the profile before any thread
    /// is created; construction is inert until this call.
    pub fn start(profile: DesktopRuntimeProfile) -> Result<Self, DesktopRuntimeStartError> {
        let config = profile
            .runtime_config()
            .map_err(DesktopRuntimeStartError::InvalidProfile)?;
        let limits = SampleLimits {
            worker_threads: config.worker_threads,
            blocking_max_threads: config.blocking.max_threads,
            global_queue_limit: config.global_queue_limit,
            root_max_heap_bytes: config
                .root_region_limits
                .and_then(|region| region.max_heap_bytes)
                .unwrap_or(0),
        };
        let runtime = profile.start()?;
        Ok(Self {
            profile,
            limits,
            runtime: Some(runtime),
        })
    }

    /// The explicit profile this sample runs under.
    pub const fn profile(&self) -> &DesktopRuntimeProfile {
        &self.profile
    }

    /// The materialized explicit bounds this sample runs under.
    pub const fn limits(&self) -> &SampleLimits {
        &self.limits
    }

    /// Run one future to completion on the sample's explicit worker set.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime
            .as_ref()
            .expect("owned sample runtime is present until close")
            .block_on(future)
    }

    /// Drain the runtime and report the envelope the sample ran under.
    pub fn close(mut self, timeout: Duration) -> SampleDrainReport {
        let drained = self
            .runtime
            .take()
            .map(|runtime| runtime.close(timeout))
            .unwrap_or(false);
        SampleDrainReport {
            drained,
            limits: self.limits,
        }
    }
}

/// A runtime sample whose clock domain is delegated to the host.
///
/// The engine still owns its workers, blocking pool, queues, and bounded
/// regions; only time authority comes from outside. Closing the sample
/// releases owned resources and cannot affect host-owned state.
pub struct HostClockSample {
    limits: SampleLimits,
    runtime: Option<DesktopRuntime>,
}

impl std::fmt::Debug for HostClockSample {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostClockSample")
            .field("limits", &self.limits)
            .field("runtime_active", &self.runtime.is_some())
            .finish()
    }
}

/// Outcome of one foreign call executed under a host-delegated deadline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ForeignCallOutcome<T> {
    /// The operation's value, conserved across cancellation-safe delivery.
    pub value: T,
    /// Whether execution finished within the host's allowed window.
    pub met: bool,
    /// The host-allowed window, measured just before execution.
    pub allowed: Duration,
    /// Wall time actually consumed.
    pub elapsed: Duration,
}

/// Typed refusal from the host-delegated clock domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SampleClockError {
    /// The host supplied a deadline that had already passed.
    DeadlineInPast,
}

impl HostClockSample {
    /// Start a host-clock sample on the standard bounded profile.
    pub fn start() -> Result<Self, DesktopRuntimeStartError> {
        Self::start_with(DesktopRuntimeProfile::standard())
    }

    /// Start a host-clock sample with an explicit profile.
    pub fn start_with(profile: DesktopRuntimeProfile) -> Result<Self, DesktopRuntimeStartError> {
        let config = profile
            .runtime_config()
            .map_err(DesktopRuntimeStartError::InvalidProfile)?;
        let limits = SampleLimits {
            worker_threads: config.worker_threads,
            blocking_max_threads: config.blocking.max_threads,
            global_queue_limit: config.global_queue_limit,
            root_max_heap_bytes: config
                .root_region_limits
                .and_then(|region| region.max_heap_bytes)
                .unwrap_or(0),
        };
        Ok(Self {
            limits,
            runtime: Some(profile.start()?),
        })
    }

    /// The materialized explicit bounds this sample runs under.
    pub const fn limits(&self) -> &SampleLimits {
        &self.limits
    }

    /// Run one foreign call, judged against a host clock deadline.
    ///
    /// The host owns the time domain: the window is measured against the
    /// caller's [`Instant`] before and after the runtime executes the call,
    /// so the report reflects host-observable time, not engine-internal time.
    pub fn run_foreign_call_before<T, F>(
        &self,
        host_deadline: Instant,
        operation: F,
    ) -> Result<ForeignCallOutcome<T>, SampleClockError>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let allowed = host_deadline
            .checked_duration_since(Instant::now())
            .ok_or(SampleClockError::DeadlineInPast)?;
        let completion = ForeignCallCompletion::new();
        let started = Instant::now();
        let value = self.block_on(crate::desktop_profile::run_foreign_call(
            completion, operation,
        ));
        let elapsed = started.elapsed();
        Ok(ForeignCallOutcome {
            value,
            met: elapsed <= allowed,
            allowed,
            elapsed,
        })
    }

    /// Run one future to completion on this sample's worker set.
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime
            .as_ref()
            .expect("host sample runtime is present until close")
            .block_on(future)
    }

    /// Drain the sample's owned resources; host-owned state is untouched.
    pub fn close(self, timeout: Duration) -> SampleDrainReport {
        let drained = self
            .runtime
            .map(|runtime| runtime.close(timeout))
            .unwrap_or(false);
        SampleDrainReport {
            drained,
            limits: self.limits,
        }
    }
}

/// Which documented [`Budget::meet`] algebra rule was violated.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BudgetMeetViolation {
    /// The rule name: `"priority_max"`, `"tightest_deadline"`, or
    /// `"tightest_cost_quota"`.
    pub rule: &'static str,
}

/// Validate a budget pair through the real meet rule before use.
///
/// The meet operation must yield the maximum of the two priorities and the
/// tightest of each present bound. Samples call this so a runtime is never
/// started under a budget pair whose composed meaning is unclear.
pub fn validate_priority_max_meet(
    parent: Budget,
    child: Budget,
) -> Result<Budget, BudgetMeetViolation> {
    let met = parent.meet(child);
    if met.priority != parent.priority.max(child.priority) {
        return Err(BudgetMeetViolation {
            rule: "priority_max",
        });
    }
    if met.deadline != tightest(parent.deadline, child.deadline) {
        return Err(BudgetMeetViolation {
            rule: "tightest_deadline",
        });
    }
    if met.cost_quota != tightest(parent.cost_quota, child.cost_quota) {
        return Err(BudgetMeetViolation {
            rule: "tightest_cost_quota",
        });
    }
    Ok(met)
}

fn tightest<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (one, None) => one,
        (None, other) => other,
    }
}
