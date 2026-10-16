    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use serde_json::json;

    fn scrub_budget_event(deadline: Option<Time>) -> &'static str {
        if deadline.is_some() {
            "[DEADLINE]"
        } else {
            "[NONE]"
        }
    }

    // =========================================================================
    // Constants Tests
    // =========================================================================

    #[test]
    fn infinite_budget_values() {
        let b = Budget::INFINITE;
        assert_eq!(b.deadline, None);
        assert_eq!(b.poll_quota, u32::MAX);
        assert_eq!(b.cost_quota, None);
        assert_eq!(b.priority, 0);
    }

    #[test]
    fn zero_budget_values() {
        let b = Budget::ZERO;
        assert_eq!(b.deadline, Some(Time::ZERO));
        assert_eq!(b.poll_quota, 0);
        assert_eq!(b.cost_quota, Some(0));
        assert_eq!(b.priority, 255);
    }

    #[test]
    fn new_returns_default_priority() {
        let b = Budget::new();
        assert_eq!(b.priority, 128);
        assert_ne!(b, Budget::INFINITE);
    }

    #[test]
    fn default_returns_new() {
        assert_eq!(Budget::default(), Budget::new());
        assert_ne!(Budget::default(), Budget::INFINITE);
    }

    // =========================================================================
    // Builder Methods Tests
    // =========================================================================

    #[test]
    fn with_deadline_sets_deadline() {
        let deadline = Time::from_secs(30);
        let budget = Budget::new().with_deadline(deadline);
        assert_eq!(budget.deadline, Some(deadline));
    }

    #[test]
    fn tightened_by_timeout_never_loosens_existing_deadline() {
        let now = Time::from_secs(100);
        // Ambient deadline (t=110) is sooner than now + 30s (t=130): keep it.
        let ambient = Budget::new().with_deadline(Time::from_secs(110));
        let tightened = ambient.tightened_by_timeout(now, Duration::from_secs(30));
        assert_eq!(tightened.deadline, Some(Time::from_secs(110)));
    }

    #[test]
    fn tightened_by_timeout_tightens_looser_deadline() {
        let now = Time::from_secs(100);
        // Ambient deadline (t=500) is later than now + 30s (t=130): tighten.
        let ambient = Budget::new().with_deadline(Time::from_secs(500));
        let tightened = ambient.tightened_by_timeout(now, Duration::from_secs(30));
        assert_eq!(tightened.deadline, Some(Time::from_secs(130)));
    }

    #[test]
    fn tightened_by_timeout_bounds_open_budget() {
        let now = Time::from_secs(100);
        let bounded = Budget::new().tightened_by_timeout(now, Duration::from_secs(30));
        assert_eq!(bounded.deadline, Some(Time::from_secs(130)));
    }

    #[test]
    fn tightened_by_timeout_preserves_other_dimensions() {
        let now = Time::from_secs(0);
        let budget = Budget::new()
            .with_poll_quota(77)
            .with_cost_quota(11)
            .with_priority(200)
            .tightened_by_timeout(now, Duration::from_secs(1));
        assert_eq!(budget.poll_quota, 77);
        assert_eq!(budget.cost_quota, Some(11));
        assert_eq!(budget.priority, 200);
    }

    #[test]
    fn remaining_snapshot_maps_sentinels_to_none() {
        let now = Time::from_secs(10);
        let unlimited = Budget::new().remaining(now);
        assert_eq!(unlimited.deadline, None);
        assert_eq!(unlimited.polls, None);
        assert_eq!(unlimited.cost, None);

        let bounded = Budget::new()
            .with_deadline(Time::from_secs(30))
            .with_poll_quota(5)
            .with_cost_quota(9)
            .remaining(now);
        assert_eq!(bounded.deadline, Some(Duration::from_secs(20)));
        assert_eq!(bounded.polls, Some(5));
        assert_eq!(bounded.cost, Some(9));
    }

    #[test]
    fn remaining_snapshot_past_deadline_reports_none() {
        let now = Time::from_secs(50);
        let expired = Budget::new()
            .with_deadline(Time::from_secs(30))
            .remaining(now);
        assert_eq!(expired.deadline, None);
    }

    #[test]
    fn deadline_at_constructors_are_absolute_instants() {
        // The rename's whole point: these are instants, not durations.
        let secs = Budget::with_deadline_at_secs(30);
        assert_eq!(secs.deadline, Some(Time::from_secs(30)));
        let ns = Budget::with_deadline_at_ns(2_000_000_000);
        assert_eq!(ns.deadline, Some(Time::from_nanos(2_000_000_000)));
    }

    #[test]
    fn with_poll_quota_sets_quota() {
        let budget = Budget::new().with_poll_quota(42);
        assert_eq!(budget.poll_quota, 42);
    }

    #[test]
    fn with_cost_quota_sets_quota() {
        let budget = Budget::new().with_cost_quota(1000);
        assert_eq!(budget.cost_quota, Some(1000));
    }

    #[test]
    fn with_priority_sets_priority() {
        let budget = Budget::new().with_priority(255);
        assert_eq!(budget.priority, 255);
    }

    #[test]
    fn builder_chaining() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(5000)
            .with_priority(200);

        assert_eq!(budget.deadline, Some(Time::from_secs(10)));
        assert_eq!(budget.poll_quota, 100);
        assert_eq!(budget.cost_quota, Some(5000));
        assert_eq!(budget.priority, 200);
    }

    // =========================================================================
    // is_exhausted Tests
    // =========================================================================

    #[test]
    fn is_exhausted_false_for_infinite() {
        assert!(!Budget::INFINITE.is_exhausted());
    }

    #[test]
    fn is_exhausted_true_for_zero() {
        assert!(Budget::ZERO.is_exhausted());
    }

    #[test]
    fn is_exhausted_when_poll_quota_zero() {
        let budget = Budget::new().with_poll_quota(0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn is_exhausted_when_cost_quota_zero() {
        let budget = Budget::new().with_cost_quota(0);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn is_exhausted_false_with_resources() {
        let budget = Budget::new().with_poll_quota(10).with_cost_quota(100);
        assert!(!budget.is_exhausted());
    }

    // =========================================================================
    // is_past_deadline Tests
    // =========================================================================

    #[test]
    fn is_past_deadline_true_when_past() {
        let budget = Budget::new().with_deadline(Time::from_secs(5));
        let now = Time::from_secs(10);
        assert!(budget.is_past_deadline(now));
    }

    #[test]
    fn is_past_deadline_false_when_not_past() {
        let budget = Budget::new().with_deadline(Time::from_secs(10));
        let now = Time::from_secs(5);
        assert!(!budget.is_past_deadline(now));
    }

    #[test]
    fn is_past_deadline_true_at_exact_time() {
        let deadline = Time::from_secs(5);
        let budget = Budget::new().with_deadline(deadline);
        assert!(budget.is_past_deadline(deadline));
    }

    #[test]
    fn is_past_deadline_false_when_no_deadline() {
        let budget = Budget::new();
        assert!(!budget.is_past_deadline(Time::from_secs(1_000_000)));
    }

    // =========================================================================
    // consume_poll Tests
    // =========================================================================

    #[test]
    fn consume_poll_decrements() {
        let mut budget = Budget::new().with_poll_quota(2);

        assert_eq!(budget.consume_poll(), Some(2));
        assert_eq!(budget.poll_quota, 1);

        assert_eq!(budget.consume_poll(), Some(1));
        assert_eq!(budget.poll_quota, 0);

        assert_eq!(budget.consume_poll(), None);
        assert_eq!(budget.poll_quota, 0);
    }

    #[test]
    fn consume_poll_returns_none_at_zero() {
        let mut budget = Budget::new().with_poll_quota(0);
        assert_eq!(budget.consume_poll(), None);
        assert_eq!(budget.poll_quota, 0);
    }

    #[test]
    fn consume_poll_transitions_to_exhausted() {
        let mut budget = Budget::new().with_poll_quota(1);
        assert!(!budget.is_exhausted());

        budget.consume_poll();
        assert!(budget.is_exhausted());
    }

    // =========================================================================
    // Combine Tests (Product Semiring Semantics)
    // =========================================================================

    #[test]
    fn combine_takes_tighter() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_priority(50);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200)
            .with_priority(100);

        let combined = a.combine(b);

        // Deadline: min
        assert_eq!(combined.deadline, Some(Time::from_secs(5)));
        // Poll quota: min
        assert_eq!(combined.poll_quota, 100);
        // Priority: max
        assert_eq!(combined.priority, 100);
    }

    #[test]
    fn combine_deadline_none_with_some() {
        let a = Budget::new(); // No deadline
        let b = Budget::new().with_deadline(Time::from_secs(5));

        // a.combine(b) should have b's deadline
        assert_eq!(a.combine(b).deadline, Some(Time::from_secs(5)));
        // b.combine(a) should also have b's deadline
        assert_eq!(b.combine(a).deadline, Some(Time::from_secs(5)));
    }

    #[test]
    fn combine_deadline_none_with_none() {
        let a = Budget::new();
        let b = Budget::new();
        assert_eq!(a.combine(b).deadline, None);
    }

    #[test]
    fn combine_cost_quota_none_with_some() {
        let a = Budget::new(); // cost_quota = None
        let b = Budget::new().with_cost_quota(100);

        // Should take the defined quota
        assert_eq!(a.combine(b).cost_quota, Some(100));
        assert_eq!(b.combine(a).cost_quota, Some(100));
    }

    #[test]
    fn combine_cost_quota_takes_min() {
        let a = Budget::new().with_cost_quota(50);
        let b = Budget::new().with_cost_quota(100);

        assert_eq!(a.combine(b).cost_quota, Some(50));
        assert_eq!(b.combine(a).cost_quota, Some(50));
    }

    #[test]
    fn combine_with_zero_absorbs() {
        let any_budget = Budget::new()
            .with_deadline(Time::from_secs(100))
            .with_poll_quota(1000)
            .with_cost_quota(10000)
            .with_priority(200);

        let combined = any_budget.combine(Budget::ZERO);

        // ZERO's deadline (Time::ZERO) is tighter
        assert_eq!(combined.deadline, Some(Time::ZERO));
        // ZERO's poll_quota (0) is tighter
        assert_eq!(combined.poll_quota, 0);
        // ZERO's cost_quota (Some(0)) is tighter
        assert_eq!(combined.cost_quota, Some(0));
        // Priority: max of 200 and 255 = 255
        assert_eq!(combined.priority, 255);
    }

    #[test]
    fn combine_with_infinite_preserves() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(1000)
            .with_priority(50);

        let combined = budget.combine(Budget::INFINITE);

        // All values should be preserved (INFINITE doesn't constrain)
        assert_eq!(combined.deadline, Some(Time::from_secs(10)));
        assert_eq!(combined.poll_quota, 100);
        assert_eq!(combined.cost_quota, Some(1000));
        // Priority: max of 50 and 0 = 50
        assert_eq!(combined.priority, 50);
    }

    // =========================================================================
    // Capability Budget Planner Tests
    // =========================================================================

    #[test]
    fn capability_budget_child_inherits_parent_and_tightens_overrides() {
        let parent = CapabilityBudget::new()
            .with_memory_bytes(1_024)
            .with_cpu_units(100)
            .with_io_bytes(10_000)
            .with_cleanup_budget(Budget::new().with_poll_quota(50))
            .with_artifact_bytes(4_096);
        let child = CapabilityBudget::new()
            .with_memory_bytes(2_048)
            .with_cpu_units(25)
            .with_io_bytes(1_000)
            .with_cleanup_budget(Budget::new().with_poll_quota(10));

        let effective = parent.meet(child);

        assert_eq!(effective.memory_bytes, Some(1_024));
        assert_eq!(effective.cpu_units, Some(25));
        assert_eq!(effective.io_bytes, Some(1_000));
        assert_eq!(
            effective.cleanup_budget.map(|budget| budget.poll_quota),
            Some(10)
        );
        assert_eq!(effective.artifact_bytes, Some(4_096));
    }

    #[test]
    fn capability_budget_optional_absent_dimension_admits() {
        let requirements = CapabilityBudgetRequirements::NONE;

        let effective = CapabilityBudget::new()
            .plan_child(CapabilityBudget::new(), requirements)
            .expect("optional absent envelopes should admit");

        assert_eq!(effective, CapabilityBudget::UNSPECIFIED);
    }

    #[test]
    fn capability_budget_required_absent_dimension_rejects() {
        let requirements = CapabilityBudgetRequirements::new().require_memory_bytes();

        let err = CapabilityBudget::new()
            .plan_child(CapabilityBudget::new(), requirements)
            .expect_err("required missing memory budget must reject");

        assert_eq!(
            err,
            CapabilityBudgetRefusal::MissingRequired(CapabilityBudgetDimension::MemoryBytes)
        );
    }

    #[test]
    fn capability_budget_required_exhausted_dimension_rejects() {
        let requirements = CapabilityBudgetRequirements::new()
            .require_cpu_units()
            .require_cleanup();
        let parent = CapabilityBudget::new()
            .with_cpu_units(0)
            .with_cleanup_budget(Budget::new().with_poll_quota(10));

        let err = parent
            .plan_child(CapabilityBudget::new(), requirements)
            .expect_err("required exhausted CPU budget must reject");

        assert_eq!(
            err,
            CapabilityBudgetRefusal::Exhausted(CapabilityBudgetDimension::CpuUnits)
        );
    }

    #[test]
    fn capability_budget_required_exhausted_cleanup_rejects() {
        let requirements = CapabilityBudgetRequirements::new().require_cleanup();
        let parent = CapabilityBudget::new().with_cleanup_budget(Budget::new().with_poll_quota(0));

        let err = parent
            .plan_child(CapabilityBudget::new(), requirements)
            .expect_err("required exhausted cleanup budget must reject");

        assert_eq!(
            err,
            CapabilityBudgetRefusal::Exhausted(CapabilityBudgetDimension::Cleanup)
        );
    }

    // =========================================================================
    // Debug/Display Tests
    // =========================================================================

    #[test]
    fn debug_shows_constrained_fields() {
        let budget = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500);

        let debug = format!("{budget:?}");

        // Debug should include constrained fields
        assert!(debug.contains("deadline"));
        assert!(debug.contains("poll_quota"));
        assert!(debug.contains("cost_quota"));
        assert!(debug.contains("priority"));
    }

    #[test]
    fn debug_omits_unconstrained_fields() {
        let budget = Budget::INFINITE;
        let debug = format!("{budget:?}");

        // INFINITE has no deadline, MAX poll_quota, and no cost_quota
        // Debug should omit deadline and poll_quota but include priority
        assert!(!debug.contains("deadline"));
        assert!(!debug.contains("poll_quota")); // u32::MAX is omitted
        assert!(debug.contains("priority"));
    }

    // =========================================================================
    // Equality Tests
    // =========================================================================

    #[test]
    fn equality_works() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100);

        let b = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100);

        assert_eq!(a, b);
    }

    #[test]
    fn inequality_on_deadline() {
        let a = Budget::new().with_deadline(Time::from_secs(10));
        let b = Budget::new().with_deadline(Time::from_secs(20));
        assert_ne!(a, b);
    }

    #[test]
    fn copy_semantics() {
        let a = Budget::new().with_poll_quota(100);
        let b = a; // Copy
        assert_eq!(a.poll_quota, b.poll_quota);
        // Modifying b doesn't affect a
        let mut c = a;
        c.poll_quota = 50;
        assert_eq!(a.poll_quota, 100);
        assert_eq!(c.poll_quota, 50);
    }

    // =========================================================================
    // New Convenience Method Tests
    // =========================================================================

    #[test]
    fn unlimited_returns_infinite() {
        assert_eq!(Budget::unlimited(), Budget::INFINITE);
    }

    #[test]
    fn with_deadline_secs_constructor() {
        let budget = Budget::with_deadline_at_secs(30);
        assert_eq!(budget.deadline, Some(Time::from_secs(30)));
        assert_eq!(budget.poll_quota, u32::MAX);
        assert_eq!(budget.cost_quota, None);
        assert_eq!(budget.priority, 128);
    }

    #[test]
    fn with_deadline_ns_constructor() {
        let budget = Budget::with_deadline_at_ns(30_000_000_000);
        assert_eq!(budget.deadline, Some(Time::from_nanos(30_000_000_000)));
    }

    #[test]
    fn with_timeout_sets_deadline_relative_to_now() {
        let now = Time::from_secs(100);
        let budget = Budget::new().with_timeout(now, Duration::from_secs(30));

        assert_eq!(budget.deadline, Some(Time::from_secs(130)));
        assert_eq!(budget.remaining_time(now), Some(Duration::from_secs(30)));
    }

    #[test]
    fn with_timeout_saturates_at_max_time() {
        let now = Time::MAX.saturating_sub_nanos(5);
        let budget = Budget::new().with_timeout(now, Duration::from_nanos(10));

        assert_eq!(budget.deadline, Some(Time::MAX));
    }

    #[test]
    fn with_timeout_keeps_other_constraints() {
        let now = Time::from_secs(7);
        let budget = Budget::new()
            .with_poll_quota(42)
            .with_cost_quota(99)
            .with_priority(200)
            .with_timeout(now, Duration::from_secs(3));

        assert_eq!(budget.deadline, Some(Time::from_secs(10)));
        assert_eq!(budget.poll_quota, 42);
        assert_eq!(budget.cost_quota, Some(99));
        assert_eq!(budget.priority, 200);
    }

    #[test]
    fn meet_is_alias_for_combine() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200);

        assert_eq!(a.meet(b), a.combine(b));
    }

    // =========================================================================
    // consume_cost Tests
    // =========================================================================

    #[test]
    fn consume_cost_basic() {
        let mut budget = Budget::new().with_cost_quota(100);

        assert!(budget.consume_cost(30));
        assert_eq!(budget.cost_quota, Some(70));

        assert!(budget.consume_cost(70));
        assert_eq!(budget.cost_quota, Some(0));

        assert!(!budget.consume_cost(1));
        assert_eq!(budget.cost_quota, Some(0));
    }

    #[test]
    fn consume_cost_unlimited() {
        let mut budget = Budget::new(); // No cost quota = unlimited
        assert!(budget.consume_cost(1_000_000));
        assert_eq!(budget.cost_quota, None);
    }

    #[test]
    fn consume_cost_exact_amount() {
        let mut budget = Budget::new().with_cost_quota(50);
        assert!(budget.consume_cost(50));
        assert_eq!(budget.cost_quota, Some(0));
    }

    #[test]
    fn consume_cost_transitions_to_exhausted() {
        let mut budget = Budget::new().with_cost_quota(10).with_poll_quota(u32::MAX);
        assert!(!budget.is_exhausted());

        budget.consume_cost(10);
        assert!(budget.is_exhausted());
    }

    // =========================================================================
    // Inspection Method Tests
    // =========================================================================

    #[test]
    fn remaining_time_basic() {
        let budget = Budget::with_deadline_at_secs(30);
        let now = Time::from_secs(10);

        let remaining = budget.remaining_time(now);
        assert_eq!(remaining, Some(Duration::from_secs(20)));
    }

    #[test]
    fn remaining_time_no_deadline() {
        let budget = Budget::unlimited();
        assert_eq!(budget.remaining_time(Time::from_secs(1000)), None);
    }

    #[test]
    fn remaining_time_past_deadline() {
        let budget = Budget::with_deadline_at_secs(10);
        assert_eq!(budget.remaining_time(Time::from_secs(15)), None);
    }

    #[test]
    fn remaining_time_at_deadline() {
        let budget = Budget::with_deadline_at_secs(10);
        assert_eq!(budget.remaining_time(Time::from_secs(10)), None);
    }

    #[test]
    fn remaining_polls_basic() {
        let budget = Budget::new().with_poll_quota(100);
        assert_eq!(budget.remaining_polls(), 100);
    }

    #[test]
    fn remaining_polls_unlimited() {
        let budget = Budget::unlimited();
        assert_eq!(budget.remaining_polls(), u32::MAX);
    }

    #[test]
    fn remaining_cost_basic() {
        let budget = Budget::new().with_cost_quota(1000);
        assert_eq!(budget.remaining_cost(), Some(1000));
    }

    #[test]
    fn remaining_cost_unlimited() {
        let budget = Budget::unlimited();
        assert_eq!(budget.remaining_cost(), None);
    }

    #[test]
    fn to_timeout_is_alias_for_remaining_time() {
        let budget = Budget::with_deadline_at_secs(30);
        let now = Time::from_secs(10);

        assert_eq!(budget.to_timeout(now), budget.remaining_time(now));
    }

    // =========================================================================
    // Min-Plus Network Calculus Tests
    // =========================================================================

    #[test]
    fn min_plus_curve_validation_rejects_non_monotone() {
        let err = MinPlusCurve::new(vec![0, 2, 1], 0).expect_err("non-monotone samples");
        assert!(matches!(
            err,
            CurveError::NonMonotone {
                index: 2,
                prev: 2,
                next: 1
            }
        ));
    }

    #[test]
    fn min_plus_convolution_basic() {
        let a = MinPlusCurve::new(vec![0, 1, 2], 1).expect("valid curve");
        let b = MinPlusCurve::new(vec![0, 0, 1], 1).expect("valid curve");
        let conv = a.min_plus_convolution(&b, 2);
        assert_eq!(conv.samples(), &[0, 0, 1]);
    }

    #[test]
    fn min_plus_backlog_delay_demo() {
        let arrival = MinPlusCurve::from_token_bucket(5, 2, 10);
        let service = MinPlusCurve::from_rate_latency(3, 2, 10);
        let budget = CurveBudget { arrival, service };

        let backlog = budget.backlog_bound(10);
        let delay = budget.delay_bound(10, 10);

        assert_eq!(backlog, 9);
        assert_eq!(delay, Some(4));
    }

    // =========================================================================
    // Budget Algebra Formal Lemmas (bd-hf5bz)
    //
    // These tests serve as mechanized proof artifacts for the budget algebra.
    // Each test corresponds to a named lemma that downstream proofs
    // (bd-3cq88, bd-2qmr4, bd-3fp4g, bd-ecp8u) can reference.
    //
    // Algebra summary:
    //   (Budget, meet, INFINITE) forms a bounded meet-semilattice where:
    //   - meet uses min on deadline/poll/cost and max on priority.
    //   - INFINITE is the top element (identity for meet).
    //   - ZERO is the bottom element (absorbing for meet, modulo priority).
    //
    // Code mapping:
    //   meet        → Budget::meet / Budget::combine  (src/types/budget.rs)
    //   identity    → Budget::INFINITE
    //   absorbing   → Budget::ZERO
    //   consumption → Budget::consume_poll, Budget::consume_cost
    //
    // Min-plus / tropical structure:
    //   (DeadlineMicros, min, add, ∞, 0) forms a tropical semiring
    //   used in plan analysis for sequential/parallel budget composition.
    //   Code mapping → src/plan/analysis.rs :: DeadlineMicros
    //
    //   (MinPlusCurve, min_plus_convolution) forms a min-plus algebra
    //   for network calculus admission control.
    //   Code mapping → MinPlusCurve / CurveBudget (src/types/budget.rs)
    // =========================================================================

    // -- Lemma 1: meet is commutative --
    // ∀ a b. a.meet(b) == b.meet(a)

    #[test]
    fn lemma_meet_commutative() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(50);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200)
            .with_cost_quota(300)
            .with_priority(100);

        assert_eq!(a.meet(b), b.meet(a));
    }

    #[test]
    fn lemma_meet_commutative_with_none_deadline() {
        let a = Budget::new().with_poll_quota(100);
        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200);
        assert_eq!(a.meet(b), b.meet(a));
    }

    #[test]
    fn lemma_meet_commutative_with_none_cost() {
        let a = Budget::new().with_cost_quota(100);
        let b = Budget::new(); // cost_quota = None
        assert_eq!(a.meet(b), b.meet(a));
    }

    // -- Lemma 2: meet is associative --
    // ∀ a b c. a.meet(b.meet(c)) == a.meet(b).meet(c)

    #[test]
    fn lemma_meet_associative() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(50);

        let b = Budget::new()
            .with_deadline(Time::from_secs(5))
            .with_poll_quota(200)
            .with_cost_quota(300)
            .with_priority(100);

        let c = Budget::new()
            .with_deadline(Time::from_secs(8))
            .with_poll_quota(150)
            .with_cost_quota(400)
            .with_priority(75);

        assert_eq!(a.meet(b.meet(c)), a.meet(b).meet(c));
    }

    #[test]
    fn lemma_meet_associative_with_none_fields() {
        let a = Budget::new().with_deadline(Time::from_secs(10));
        let b = Budget::new().with_cost_quota(300);
        let c = Budget::new().with_poll_quota(50);

        assert_eq!(a.meet(b.meet(c)), a.meet(b).meet(c));
    }

    // -- Lemma 3: meet is idempotent --
    // ∀ a. a.meet(a) == a

    #[test]
    fn lemma_meet_idempotent() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(75);
        assert_eq!(a.meet(a), a);
    }

    #[test]
    fn lemma_meet_idempotent_infinite() {
        assert_eq!(Budget::INFINITE.meet(Budget::INFINITE), Budget::INFINITE);
    }

    #[test]
    fn lemma_meet_idempotent_zero() {
        assert_eq!(Budget::ZERO.meet(Budget::ZERO), Budget::ZERO);
    }

    // -- Lemma 4: INFINITE is the identity for meet --
    // ∀ a. a.meet(INFINITE) == a

    #[test]
    fn lemma_identity_left() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(50);

        // INFINITE has priority 0 (identity for max).
        // meet takes max priority.
        let result = Budget::INFINITE.meet(a);
        assert_eq!(result.deadline, a.deadline);
        assert_eq!(result.poll_quota, a.poll_quota);
        assert_eq!(result.cost_quota, a.cost_quota);
        assert_eq!(result.priority, a.priority);
    }

    #[test]
    fn lemma_identity_right() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(10))
            .with_poll_quota(100)
            .with_cost_quota(500)
            .with_priority(200);

        let result = a.meet(Budget::INFINITE);
        assert_eq!(result.deadline, a.deadline);
        assert_eq!(result.poll_quota, a.poll_quota);
        assert_eq!(result.cost_quota, a.cost_quota);
        assert_eq!(result.priority, a.priority);
    }

    // -- Lemma 5: ZERO is absorbing for quotas --
    // ∀ a. a.meet(ZERO).poll_quota == 0
    // ∀ a. a.meet(ZERO).cost_quota == Some(0)
    // ∀ a. a.meet(ZERO).deadline == Some(Time::ZERO)

    #[test]
    fn lemma_zero_absorbing_quotas() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(100))
            .with_poll_quota(1000)
            .with_cost_quota(10000);

        let result = a.meet(Budget::ZERO);
        assert_eq!(result.deadline, Some(Time::ZERO));
        assert_eq!(result.poll_quota, 0);
        assert_eq!(result.cost_quota, Some(0));
    }

    #[test]
    fn lemma_zero_absorbing_symmetric() {
        let a = Budget::new()
            .with_deadline(Time::from_secs(100))
            .with_poll_quota(1000)
            .with_cost_quota(10000);

        let left = a.meet(Budget::ZERO);
        let right = Budget::ZERO.meet(a);
        assert_eq!(left.deadline, right.deadline);
        assert_eq!(left.poll_quota, right.poll_quota);
        assert_eq!(left.cost_quota, right.cost_quota);
    }

    // -- Lemma 6: meet is monotone (narrowing) --
    // ∀ a b. a.meet(b).poll_quota ≤ a.poll_quota
    // ∀ a b. a.meet(b).poll_quota ≤ b.poll_quota
    // (and analogously for cost_quota, deadline)

    #[test]
    fn lemma_meet_monotone_poll() {
        let a = Budget::new().with_poll_quota(100);
        let b = Budget::new().with_poll_quota(200);
        let result = a.meet(b);
        assert!(result.poll_quota <= a.poll_quota);
        assert!(result.poll_quota <= b.poll_quota);
    }

    #[test]
    fn lemma_meet_monotone_cost() {
        let a = Budget::new().with_cost_quota(100);
        let b = Budget::new().with_cost_quota(200);
        let result = a.meet(b);
        assert!(result.cost_quota.unwrap() <= a.cost_quota.unwrap());
        assert!(result.cost_quota.unwrap() <= b.cost_quota.unwrap());
    }

    #[test]
    fn lemma_meet_monotone_deadline() {
        let a = Budget::new().with_deadline(Time::from_secs(10));
        let b = Budget::new().with_deadline(Time::from_secs(20));
        let result = a.meet(b);
        assert!(result.deadline.unwrap() <= a.deadline.unwrap());
        assert!(result.deadline.unwrap() <= b.deadline.unwrap());
    }

    // -- Lemma 7: consume_poll strictly decreases quota (well-founded) --
    // ∀ b. b.poll_quota > 0 → consume_poll(&mut b) = Some(old) ∧ b.poll_quota < old

    #[test]
    fn lemma_consume_poll_strictly_decreasing() {
        let mut budget = Budget::new().with_poll_quota(5);
        let mut prev = budget.poll_quota;
        while budget.poll_quota > 0 {
            let old = budget.consume_poll().expect("quota > 0");
            assert_eq!(old, prev);
            assert!(budget.poll_quota < prev);
            prev = budget.poll_quota;
        }
        // Exhausted: consume returns None
        assert_eq!(budget.consume_poll(), None);
    }

    // -- Lemma 8: consume_cost strictly decreases quota (well-founded) --
    // ∀ b cost. b.cost_quota = Some(q) ∧ q ≥ cost → consume_cost succeeds ∧ new_q < q

    #[test]
    fn lemma_consume_cost_strictly_decreasing() {
        let mut budget = Budget::new().with_cost_quota(100);
        let initial = budget.cost_quota.unwrap();
        assert!(budget.consume_cost(30));
        let after = budget.cost_quota.unwrap();
        assert!(after < initial);
        assert_eq!(after, 70);
    }

    // -- Lemma 9: sufficient budget implies progress --
    // ∀ b. ¬b.is_exhausted() → (consume_poll succeeds ∨ cost_quota = None ∨ cost_quota > 0)

    #[test]
    fn lemma_sufficient_budget_enables_progress() {
        let mut budget = Budget::new().with_poll_quota(10).with_cost_quota(100);
        assert!(!budget.is_exhausted());

        // Can make progress via poll
        assert!(budget.consume_poll().is_some());
        // Can make progress via cost
        assert!(budget.consume_cost(1));
    }

    #[test]
    fn lemma_exhausted_blocks_progress() {
        let mut budget = Budget::new().with_poll_quota(0);
        assert!(budget.is_exhausted());
        assert!(budget.consume_poll().is_none());
    }

    // -- Lemma 10: budget consumption terminates --
    // Starting from finite quota q, after exactly q calls to consume_poll,
    // the budget is exhausted.

    #[test]
    fn lemma_poll_termination() {
        let q = 7u32;
        let mut budget = Budget::new().with_poll_quota(q);
        for _ in 0..q {
            assert!(!budget.is_exhausted());
            budget.consume_poll().expect("should succeed");
        }
        assert!(budget.is_exhausted());
        assert_eq!(budget.poll_quota, 0);
    }

    #[test]
    fn lemma_cost_termination() {
        let mut budget = Budget::new().with_cost_quota(100);
        // Consume in chunks of 25
        for _ in 0..4 {
            assert!(budget.consume_cost(25));
        }
        assert_eq!(budget.cost_quota, Some(0));
        assert!(!budget.consume_cost(1));
    }

    // -- Lemma 11: min-plus curve convolution associativity --
    // (a ⊗ b) ⊗ c == a ⊗ (b ⊗ c)  over a finite horizon

    #[test]
    fn lemma_convolution_associative() {
        let a = MinPlusCurve::new(vec![0, 1, 3], 2).expect("valid");
        let b = MinPlusCurve::new(vec![0, 2, 4], 2).expect("valid");
        let c = MinPlusCurve::new(vec![0, 1, 2], 1).expect("valid");
        let h = 4;

        let ab_c = a.min_plus_convolution(&b, h).min_plus_convolution(&c, h);
        let a_bc = a.min_plus_convolution(&b.min_plus_convolution(&c, h), h);

        for t in 0..=h {
            assert_eq!(
                ab_c.value_at(t),
                a_bc.value_at(t),
                "associativity failed at t={t}"
            );
        }
    }

    // -- Lemma 12: min-plus convolution commutativity --
    // a ⊗ b == b ⊗ a  over a finite horizon

    #[test]
    fn lemma_convolution_commutative() {
        let a = MinPlusCurve::new(vec![0, 1, 3], 2).expect("valid");
        let b = MinPlusCurve::new(vec![0, 2, 4], 2).expect("valid");
        let h = 4;

        let ab = a.min_plus_convolution(&b, h);
        let ba = b.min_plus_convolution(&a, h);

        for t in 0..=h {
            assert_eq!(
                ab.value_at(t),
                ba.value_at(t),
                "commutativity failed at t={t}"
            );
        }
    }

    // -- Lemma 13: backlog bound monotonicity --
    // Increasing arrival or decreasing service cannot reduce backlog.

    #[test]
    fn lemma_backlog_monotone_arrival() {
        let service = MinPlusCurve::from_rate_latency(3, 2, 10);
        let small_arrival = MinPlusCurve::from_token_bucket(2, 1, 10);
        let large_arrival = MinPlusCurve::from_token_bucket(5, 2, 10);

        let small_backlog = backlog_bound(&small_arrival, &service, 10);
        let large_backlog = backlog_bound(&large_arrival, &service, 10);

        assert!(large_backlog >= small_backlog);
    }

    // -- Lemma 14: delay bound monotonicity --
    // Higher arrival burst leads to equal or worse delay bound.

    #[test]
    fn lemma_delay_monotone_arrival() {
        let service = MinPlusCurve::from_rate_latency(3, 2, 10);
        let small_arrival = MinPlusCurve::from_token_bucket(2, 1, 10);
        let large_arrival = MinPlusCurve::from_token_bucket(5, 2, 10);

        let small_delay = delay_bound(&small_arrival, &service, 10, 20).unwrap_or(0);
        let large_delay = delay_bound(&large_arrival, &service, 10, 20).unwrap_or(0);

        assert!(large_delay >= small_delay);
    }

    // -- Lemma 15: convolution tail rate is min of input rates --
    // For min-plus convolution: (f ⊗ g)(t) = inf_s [f(s) + g(t-s)]
    // the asymptotic growth rate is min(r_f, r_g), not r_f + r_g.

    #[test]
    fn lemma_convolution_tail_rate_is_min() {
        let slow = MinPlusCurve::new(vec![0, 1], 1).expect("valid");
        let fast = MinPlusCurve::new(vec![0, 3], 3).expect("valid");
        let conv = slow.min_plus_convolution(&fast, 10);

        // Tail rate must be min(1, 3) = 1
        assert_eq!(conv.tail_rate(), 1);

        // Verify beyond-horizon extrapolation matches the brute-force minimum
        // at a point well past the computed samples.
        let t = 20;
        let mut brute = u64::MAX;
        for s in 0..=t {
            brute = brute.min(slow.value_at(s).saturating_add(fast.value_at(t - s)));
        }
        assert_eq!(conv.value_at(t), brute);
    }

    // ── derive-trait coverage (wave 74) ──────────────────────────────────

    #[test]
    fn budget_clone_copy() {
        let b = Budget::new().with_poll_quota(42);
        let b2 = b; // Copy
        let b3 = b;
        assert_eq!(b, b2);
        assert_eq!(b2, b3);
    }

    #[test]
    fn curve_error_debug_clone_eq() {
        let e1 = CurveError::EmptySamples;
        let e2 = e1.clone();
        assert_eq!(e1, e2);

        let e3 = CurveError::NonMonotone {
            index: 2,
            prev: 10,
            next: 5,
        };
        let e4 = e3.clone();
        assert_eq!(e3, e4);
        assert_ne!(e1, e3);
        let dbg = format!("{e3:?}");
        assert!(dbg.contains("NonMonotone"));
    }

    #[test]
    fn min_plus_curve_debug_clone_eq() {
        let c1 = MinPlusCurve::new(vec![0, 1, 2], 1).unwrap();
        let c2 = c1.clone();
        assert_eq!(c1, c2);
        let dbg = format!("{c1:?}");
        assert!(dbg.contains("MinPlusCurve"));
    }

    #[test]
    fn curve_budget_debug_clone_eq() {
        let arrival = MinPlusCurve::new(vec![0, 2, 4], 2).unwrap();
        let service = MinPlusCurve::new(vec![0, 3, 6], 3).unwrap();
        let cb = CurveBudget { arrival, service };
        let cb2 = cb.clone();
        assert_eq!(cb, cb2);
        let dbg = format!("{cb:?}");
        assert!(dbg.contains("CurveBudget"));
    }

    #[test]
    fn budget_event_snapshot_scrubbed() {
        let mut budget = Budget::new()
            .with_deadline(Time::from_secs(12))
            .with_poll_quota(3)
            .with_cost_quota(40)
            .with_priority(180);

        let before = budget;
        let poll_before = budget.consume_poll();
        let after_poll = budget;
        let cost_ok = budget.consume_cost(15);
        let after_cost = budget;

        insta::assert_json_snapshot!(
            "budget_event_scrubbed",
            json!({
                "events": [
                    {
                        "event": "created",
                        "deadline": scrub_budget_event(before.deadline),
                        "poll_quota": before.poll_quota,
                        "cost_quota": before.cost_quota,
                        "priority": before.priority,
                    },
                    {
                        "event": "consume_poll",
                        "returned": poll_before,
                        "poll_quota_after": after_poll.poll_quota,
                    },
                    {
                        "event": "consume_cost",
                        "accepted": cost_ok,
                        "cost_quota_after": after_cost.cost_quota,
                        "exhausted": after_cost.is_exhausted(),
                    }
                ]
            })
        );
    }
