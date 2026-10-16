//! Deadline propagation utilities.
//!
//! Deadline jitter is intentionally opt-in and separated from
//! [`Budget`](crate::types::Budget) deadline composition. A budget deadline
//! remains the exact cancellation bound; callers that want thundering-herd
//! smoothing apply [`DeadlineJitterPolicy`] only to the timer or timed-lane
//! wakeup they register for that work.

use crate::cx::Scope;
use crate::tracing_compat::debug;
use crate::types::{Policy, RegionId, TaskId, Time};
use std::time::Duration;

#[inline]
fn duration_to_nanos(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

/// Scope inputs used to derive deterministic deadline jitter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineJitterScope {
    /// Derive jitter from task identity only.
    Task,
    /// Derive jitter from region identity only.
    Region,
    /// Derive jitter from task and region identity.
    TaskAndRegion,
}

/// Opt-in deterministic deadline-slack jitter policy.
///
/// The policy never schedules before the original deadline. It computes a
/// stable slack offset in `0..=max_jitter` from the configured seed and scope
/// IDs, then returns a decision containing both original and jittered
/// deadlines. Default sleeps and timer-wheel registrations remain exact unless
/// a caller explicitly applies this policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineJitterPolicy {
    max_jitter: Duration,
    seed: u64,
    scope: DeadlineJitterScope,
    policy_id: u64,
}

impl DeadlineJitterPolicy {
    /// Creates a deterministic deadline jitter policy.
    #[must_use]
    pub const fn new(max_jitter: Duration, seed: u64) -> Self {
        Self {
            max_jitter,
            seed,
            scope: DeadlineJitterScope::TaskAndRegion,
            policy_id: seed,
        }
    }

    /// Creates a disabled policy that leaves deadlines unchanged.
    #[must_use]
    pub const fn disabled() -> Self {
        Self::new(Duration::ZERO, 0)
    }

    /// Sets the identity scope used for deterministic jitter derivation.
    #[must_use]
    pub const fn with_scope(mut self, scope: DeadlineJitterScope) -> Self {
        self.scope = scope;
        self
    }

    /// Sets the stable policy identifier emitted in decisions and trace events.
    #[must_use]
    pub const fn with_policy_id(mut self, policy_id: u64) -> Self {
        self.policy_id = policy_id;
        self
    }

    /// Returns the maximum configured deadline slack.
    #[must_use]
    pub const fn max_jitter(self) -> Duration {
        self.max_jitter
    }

    /// Returns the deterministic seed.
    #[must_use]
    pub const fn seed(self) -> u64 {
        self.seed
    }

    /// Returns the configured identity scope.
    #[must_use]
    pub const fn scope(self) -> DeadlineJitterScope {
        self.scope
    }

    /// Returns the stable policy identifier.
    #[must_use]
    pub const fn policy_id(self) -> u64 {
        self.policy_id
    }

    /// Computes a deterministic jitter offset for the task/region pair.
    #[must_use]
    pub fn jitter_for(self, task_id: TaskId, region_id: RegionId) -> Duration {
        let max_ns = duration_to_nanos(self.max_jitter);
        if max_ns == 0 {
            return Duration::ZERO;
        }

        let mixed = mix_deadline_jitter(self.seed ^ self.scope_key(task_id, region_id));
        let jitter_ns = if max_ns == u64::MAX {
            mixed
        } else {
            mixed % (max_ns + 1)
        };
        Duration::from_nanos(jitter_ns)
    }

    /// Applies this policy to an original deadline.
    ///
    /// The returned decision includes all fields required for structured
    /// tracing and deterministic replay.
    #[must_use]
    pub fn apply(
        self,
        original_deadline: Time,
        task_id: TaskId,
        region_id: RegionId,
    ) -> DeadlineJitterDecision {
        let jitter = self.jitter_for(task_id, region_id);
        let jitter_ns = duration_to_nanos(jitter);
        let jittered_deadline = original_deadline.saturating_add_nanos(jitter_ns);

        debug!(
            policy_id = self.policy_id,
            task_id = task_id.as_u64(),
            region_id = region_id.as_u64(),
            original_deadline_ns = original_deadline.as_nanos(),
            jittered_deadline_ns = jittered_deadline.as_nanos(),
            jitter_ns,
            "deadline jitter applied"
        );

        DeadlineJitterDecision {
            policy_id: self.policy_id,
            scope: self.scope,
            task_id,
            region_id,
            original_deadline,
            jittered_deadline,
            jitter,
        }
    }

    fn scope_key(self, task_id: TaskId, region_id: RegionId) -> u64 {
        match self.scope {
            DeadlineJitterScope::Task => task_id.as_u64(),
            DeadlineJitterScope::Region => region_id.as_u64(),
            DeadlineJitterScope::TaskAndRegion => {
                task_id.as_u64().rotate_left(17) ^ region_id.as_u64().rotate_right(11)
            }
        }
    }
}

impl Default for DeadlineJitterPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Deterministic result of applying a [`DeadlineJitterPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineJitterDecision {
    /// Stable policy identifier.
    pub policy_id: u64,
    /// Identity scope used to derive the jitter.
    pub scope: DeadlineJitterScope,
    /// Task identity used by the policy.
    pub task_id: TaskId,
    /// Region identity used by the policy.
    pub region_id: RegionId,
    /// Original unjittered deadline.
    pub original_deadline: Time,
    /// Deadline after applying non-negative slack.
    pub jittered_deadline: Time,
    /// Non-negative slack added to the original deadline.
    pub jitter: Duration,
}

#[inline]
fn mix_deadline_jitter(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

/// Updates a scope with a new deadline.
///
/// If the scope already has a tighter deadline, it is preserved.
#[must_use]
#[inline]
pub fn with_deadline<'a, P: Policy>(scope: &Scope<'a, P>, deadline: Time) -> Scope<'a, P> {
    let current_budget = scope.budget();
    // Budget::with_deadline replaces it. We want min.
    let new_deadline = current_budget
        .deadline
        .map_or(deadline, |existing| existing.min(deadline));
    let new_budget = current_budget.with_deadline(new_deadline);

    // Create a new scope with the updated budget, preserving the source
    // scope's capability budget and pending-spawn counter — deadline
    // tightening must not widen resource envelopes or detach the region's
    // spawn accounting (br-asupersync-iwt7w3).
    Scope::new_with_capability_budget(scope.region_id(), new_budget, scope.capability_budget())
        .with_pending_spawn_counter(scope.pending_spawn_counter_handle())
}

/// Updates a scope with a timeout relative to a start time.
#[must_use]
#[inline]
pub fn with_timeout<'a, P: Policy>(
    scope: &Scope<'a, P>,
    duration: Duration,
    now: Time,
) -> Scope<'a, P> {
    let deadline = now.saturating_add_nanos(duration_to_nanos(duration));
    with_deadline(scope, deadline)
}

#[cfg(test)]
#[path = "deadline_inline_tests.rs"]
mod tests;
