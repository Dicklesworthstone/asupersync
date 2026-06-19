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
    use crate::types::Budget;
    use crate::types::policy::FailFast;
    use crate::util::ArenaIndex;
    use proptest::prelude::*;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn test_region() -> crate::types::RegionId {
        crate::types::RegionId::from_arena(ArenaIndex::new(0, 1))
    }

    #[test]
    fn with_deadline_sets_deadline_on_scope_without_one() {
        init_test("with_deadline_sets_deadline_on_scope_without_one");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        // Budget::INFINITE has no deadline
        crate::assert_with_log!(
            scope.budget().deadline.is_none(),
            "no initial deadline",
            true,
            scope.budget().deadline.is_none()
        );

        let deadline = Time::from_secs(10);
        let new_scope = with_deadline(&scope, deadline);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(deadline),
            "deadline set",
            Some(deadline),
            new_scope.budget().deadline
        );
        crate::assert_with_log!(
            new_scope.region_id() == test_region(),
            "region preserved",
            test_region(),
            new_scope.region_id()
        );
        crate::test_complete!("with_deadline_sets_deadline_on_scope_without_one");
    }

    #[test]
    fn with_deadline_preserves_tighter_existing_deadline() {
        init_test("with_deadline_preserves_tighter_existing_deadline");
        let budget = Budget::INFINITE.with_deadline(Time::from_secs(5));
        let scope = Scope::<FailFast>::new(test_region(), budget);

        // Try to set a looser deadline (10s > 5s)
        let new_scope = with_deadline(&scope, Time::from_secs(10));
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(5)),
            "tighter deadline preserved",
            Some(Time::from_secs(5)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_deadline_preserves_tighter_existing_deadline");
    }

    #[test]
    fn with_deadline_tightens_when_new_is_earlier() {
        init_test("with_deadline_tightens_when_new_is_earlier");
        let budget = Budget::INFINITE.with_deadline(Time::from_secs(10));
        let scope = Scope::<FailFast>::new(test_region(), budget);

        // Set a tighter deadline (3s < 10s)
        let new_scope = with_deadline(&scope, Time::from_secs(3));
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(3)),
            "tighter deadline applied",
            Some(Time::from_secs(3)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_deadline_tightens_when_new_is_earlier");
    }

    #[test]
    fn with_timeout_computes_absolute_deadline() {
        init_test("with_timeout_computes_absolute_deadline");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::from_secs(100);
        let duration = Duration::from_secs(5);

        let new_scope = with_timeout(&scope, duration, now);
        // Deadline should be now + duration = 105s
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(105)),
            "deadline = now + duration",
            Some(Time::from_secs(105)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_computes_absolute_deadline");
    }

    #[test]
    fn with_timeout_zero_duration_sets_deadline_to_now() {
        init_test("with_timeout_zero_duration_sets_deadline_to_now");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::from_secs(42);

        let new_scope = with_timeout(&scope, Duration::ZERO, now);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(now),
            "zero timeout deadline",
            Some(now),
            new_scope.budget().deadline
        );
        crate::assert_with_log!(
            new_scope.region_id() == test_region(),
            "region preserved",
            test_region(),
            new_scope.region_id()
        );
        crate::test_complete!("with_timeout_zero_duration_sets_deadline_to_now");
    }

    #[test]
    fn with_timeout_respects_existing_tighter_deadline() {
        init_test("with_timeout_respects_existing_tighter_deadline");
        let budget = Budget::INFINITE.with_deadline(Time::from_secs(102));
        let scope = Scope::<FailFast>::new(test_region(), budget);
        let now = Time::from_secs(100);
        let duration = Duration::from_secs(10); // Would be 110s

        let new_scope = with_timeout(&scope, duration, now);
        // Existing 102s deadline is tighter than 110s
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(102)),
            "existing tighter deadline preserved",
            Some(Time::from_secs(102)),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_respects_existing_tighter_deadline");
    }

    #[test]
    fn with_timeout_saturates_at_time_max_for_huge_duration() {
        init_test("with_timeout_saturates_at_time_max_for_huge_duration");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::from_secs(1);

        let new_scope = with_timeout(&scope, Duration::MAX, now);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::MAX),
            "huge duration saturates to Time::MAX",
            Some(Time::MAX),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_saturates_at_time_max_for_huge_duration");
    }

    #[test]
    fn with_timeout_saturates_when_now_is_near_time_max() {
        init_test("with_timeout_saturates_when_now_is_near_time_max");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let now = Time::MAX.saturating_sub_nanos(5);

        let new_scope = with_timeout(&scope, Duration::from_nanos(10), now);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::MAX),
            "near-max now plus timeout saturates",
            Some(Time::MAX),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_timeout_saturates_when_now_is_near_time_max");
    }

    proptest! {
        #[test]
        fn with_timeout_metamorphic_composition_is_order_independent(
            now_nanos in 0u64..1_000_000_000,
            first_timeout_nanos in 0u64..1_000_000_000,
            second_timeout_nanos in 0u64..1_000_000_000,
        ) {
            let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
            let now = Time::from_nanos(now_nanos);
            let first_timeout = Duration::from_nanos(first_timeout_nanos);
            let second_timeout = Duration::from_nanos(second_timeout_nanos);

            let first_then_second =
                with_timeout(&with_timeout(&scope, first_timeout, now), second_timeout, now);
            let second_then_first =
                with_timeout(&with_timeout(&scope, second_timeout, now), first_timeout, now);
            let expected = now
                .saturating_add_nanos(first_timeout_nanos)
                .min(now.saturating_add_nanos(second_timeout_nanos));

            prop_assert_eq!(first_then_second.budget().deadline, Some(expected));
            prop_assert_eq!(second_then_first.budget().deadline, Some(expected));
            prop_assert_eq!(
                first_then_second.budget().deadline,
                second_then_first.budget().deadline,
                "timeout composition must keep the earliest deadline regardless of order",
            );
            prop_assert_eq!(first_then_second.region_id(), test_region());
            prop_assert_eq!(second_then_first.region_id(), test_region());
        }

        #[test]
        fn with_timeout_metamorphic_matches_explicit_saturating_deadline(
            now_nanos in any::<u64>(),
            timeout_nanos in any::<u64>(),
            existing_deadline_nanos in any::<u64>(),
        ) {
            let budget = Budget::INFINITE.with_deadline(Time::from_nanos(existing_deadline_nanos));
            let scope = Scope::<FailFast>::new(test_region(), budget);
            let now = Time::from_nanos(now_nanos);
            let timeout = Duration::from_nanos(timeout_nanos);
            let computed_deadline = now.saturating_add_nanos(timeout_nanos);

            let via_timeout = with_timeout(&scope, timeout, now);
            let via_explicit_deadline = with_deadline(&scope, computed_deadline);
            let expected = Time::from_nanos(existing_deadline_nanos).min(computed_deadline);

            prop_assert_eq!(
                via_timeout.budget().deadline,
                Some(expected),
                "with_timeout must keep the earlier of the existing and computed deadlines",
            );
            prop_assert_eq!(
                via_timeout.budget().deadline,
                via_explicit_deadline.budget().deadline,
                "with_timeout must match with_deadline using the computed absolute deadline",
            );
            prop_assert_eq!(via_timeout.region_id(), test_region());
            prop_assert_eq!(via_explicit_deadline.region_id(), test_region());
        }
    }

    #[test]
    fn with_deadline_preserves_non_deadline_budget_fields() {
        init_test("with_deadline_preserves_non_deadline_budget_fields");
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(7)
            .with_cost_quota(11)
            .with_priority(222);
        let scope = Scope::<FailFast>::new(test_region(), budget);

        let new_scope = with_deadline(&scope, Time::from_secs(3));
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::from_secs(3)),
            "deadline tightened",
            Some(Time::from_secs(3)),
            new_scope.budget().deadline
        );
        crate::assert_with_log!(
            new_scope.budget().poll_quota == 7,
            "poll quota preserved",
            7,
            new_scope.budget().poll_quota
        );
        crate::assert_with_log!(
            new_scope.budget().cost_quota == Some(11),
            "cost quota preserved",
            Some(11),
            new_scope.budget().cost_quota
        );
        crate::assert_with_log!(
            new_scope.budget().priority == 222,
            "priority preserved",
            222,
            new_scope.budget().priority
        );
        crate::test_complete!("with_deadline_preserves_non_deadline_budget_fields");
    }

    #[test]
    fn with_deadline_preserves_capability_budget() {
        init_test("with_deadline_preserves_capability_budget");
        let capability_budget = crate::types::CapabilityBudget::new()
            .with_memory_bytes(4096)
            .with_cpu_units(17)
            .with_io_bytes(2048);
        let scope = Scope::<FailFast>::new_with_capability_budget(
            test_region(),
            Budget::INFINITE,
            capability_budget,
        );

        let new_scope = with_deadline(&scope, Time::from_secs(5));
        crate::assert_with_log!(
            new_scope.capability_budget() == capability_budget,
            "capability budget preserved across deadline tightening",
            capability_budget,
            new_scope.capability_budget()
        );

        let timeout_scope = with_timeout(&scope, Duration::from_secs(1), Time::ZERO);
        crate::assert_with_log!(
            timeout_scope.capability_budget() == capability_budget,
            "capability budget preserved across with_timeout",
            capability_budget,
            timeout_scope.capability_budget()
        );
        crate::test_complete!("with_deadline_preserves_capability_budget");
    }

    #[test]
    fn with_deadline_zero_deadline() {
        init_test("with_deadline_zero_deadline");
        let scope = Scope::<FailFast>::new(test_region(), Budget::INFINITE);
        let new_scope = with_deadline(&scope, Time::ZERO);
        crate::assert_with_log!(
            new_scope.budget().deadline == Some(Time::ZERO),
            "zero deadline set",
            Some(Time::ZERO),
            new_scope.budget().deadline
        );
        crate::test_complete!("with_deadline_zero_deadline");
    }
}
