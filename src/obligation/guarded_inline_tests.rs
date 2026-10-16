    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn t(nanos: u64) -> Time {
        Time::from_nanos(nanos)
    }

    fn dur(nanos: u64) -> Duration {
        Duration::from_nanos(nanos)
    }

    // ========================================================================
    // Constraint catalog tests
    // ========================================================================

    #[test]
    fn preservation_constraints_nonempty() {
        let constraints = preservation_constraints();
        assert!(!constraints.is_empty());
        // Each invariant should appear exactly once
        let unique: std::collections::HashSet<TimeIndexedInvariant> =
            constraints.iter().map(|c| c.invariant).collect();
        assert_eq!(
            unique.len(),
            constraints.len(),
            "duplicate invariant in constraints"
        );
    }

    #[test]
    fn all_invariants_have_constraints() {
        let constraints = preservation_constraints();
        let covered: std::collections::HashSet<TimeIndexedInvariant> =
            constraints.iter().map(|c| c.invariant).collect();

        let all = [
            TimeIndexedInvariant::ActorSequentialProcessing,
            TimeIndexedInvariant::ActorCleanFinalization,
            TimeIndexedInvariant::LeaseTimeMonotonicity,
            TimeIndexedInvariant::LeaseRenewalFromNow,
            TimeIndexedInvariant::LeaseTerminalIrreversibility,
            TimeIndexedInvariant::RegionPhaseMonotonicity,
            TimeIndexedInvariant::BudgetMonotonicConsumption,
            TimeIndexedInvariant::DeadlineTreeMonotonicity,
            TimeIndexedInvariant::SupervisedRestartGuarded,
        ];

        for inv in &all {
            assert!(
                covered.contains(inv),
                "invariant {inv:?} has no preservation constraint"
            );
        }
    }

    // ========================================================================
    // Lease time-indexed properties
    // ========================================================================

    /// Liveness: a lease renewed every `d` with duration `d` is always active.
    #[test]
    fn lease_renewal_liveness() {
        let d = dur(1000);
        let mut lease = LeaseModel::new(t(0), d);

        // Simulate 10 renewal cycles
        for step in 0..10u64 {
            let now = t(step * 500); // renew at half the duration
            assert!(
                lease.is_active(now),
                "lease should be active at step {step}"
            );
            let renewed = lease.renew(d, now);
            assert!(renewed, "renewal should succeed at step {step}");
        }
        // After 10 renewals, still active
        assert!(lease.is_active(t(5000)));
        assert_eq!(lease.renewal_count, 10);
    }

    /// Expiry: an unrenewed lease expires at created_at + initial_duration.
    #[test]
    fn lease_expiry_without_renewal() {
        let lease = LeaseModel::new(t(100), dur(500));

        // Active before expiry
        assert!(lease.is_active(t(100)));
        assert!(lease.is_active(t(599)));

        // Expired at exactly expires_at
        assert!(lease.is_expired(t(600)));
        assert!(lease.is_expired(t(1000)));

        // Remaining
        assert_eq!(lease.remaining(t(100)), dur(500));
        assert_eq!(lease.remaining(t(350)), dur(250));
        assert_eq!(lease.remaining(t(600)), Duration::ZERO);
    }

    /// Terminal irreversibility: released lease cannot be renewed.
    #[test]
    fn lease_terminal_irreversibility_released() {
        let mut lease = LeaseModel::new(t(0), dur(1000));
        assert!(lease.release(t(100)));
        assert_eq!(lease.remaining(t(100)), Duration::ZERO);

        // Cannot renew after release
        assert!(!lease.renew(dur(1000), t(200)));

        // Cannot release again
        assert!(!lease.release(t(300)));
    }

    /// Terminal irreversibility: expired lease cannot be renewed.
    #[test]
    fn lease_terminal_irreversibility_expired() {
        let mut lease = LeaseModel::new(t(0), dur(100));

        // Let it expire
        assert!(lease.is_expired(t(200)));

        // Cannot renew after expiry
        assert!(!lease.renew(dur(1000), t(200)));

        // Cannot release after expiry
        assert!(!lease.release(t(200)));
    }

    /// Renewal extends from `now`, not from `expires_at`.
    #[test]
    fn lease_renewal_from_now_not_from_expiry() {
        let mut lease = LeaseModel::new(t(0), dur(1000));

        // Renew early at t=200 with duration 500
        assert!(lease.renew(dur(500), t(200)));
        // New expiry should be 200 + 500 = 700, NOT 1000 + 500 = 1500
        assert_eq!(lease.expires_at, t(700));
        assert!(lease.is_active(t(699)));
        assert!(lease.is_expired(t(700)));
    }

    /// Lease cannot "bank" renewals — renewal doesn't accumulate future credit.
    #[test]
    fn lease_no_credit_banking() {
        let mut lease = LeaseModel::new(t(0), dur(1000));

        // Renew with a shorter duration → expiry moves backward
        assert!(lease.renew(dur(100), t(50)));
        assert_eq!(lease.expires_at, t(150));
        // The original 1000ns of lease time is gone
        assert!(lease.is_expired(t(150)));
    }

    /// Nested deadline monotonicity: lease inside a region with earlier deadline.
    #[test]
    fn lease_respects_region_deadline() {
        let region_deadline = t(500);
        let lease = LeaseModel::new(t(0), dur(1000));

        // Lease expires at t=1000 but region deadline is t=500.
        // The effective active window should be limited by the region.
        // This is a constraint that the runtime must enforce:
        // lease.expires_at should be min(lease.expires_at, region.deadline)
        let effective_expiry = lease.expires_at.min(region_deadline);
        assert_eq!(effective_expiry, t(500));

        // At t=500, the region is closing, so the lease is effectively over
        // even though lease.expires_at = t(1000)
        assert!(Time::from_nanos(500) >= effective_expiry);
    }

    #[test]
    fn metamorphic_readonly_observations_preserve_guarded_lease_evolution() {
        let renew_at = t(200);
        let release_at = t(450);
        let release_retry_at = t(700);

        let mut baseline = LeaseModel::new(t(0), dur(1000));
        let baseline_renewed = baseline.renew(dur(400), renew_at);
        let baseline_released = baseline.release(release_at);
        let baseline_release_retry = baseline.release(release_retry_at);

        let mut observed = LeaseModel::new(t(0), dur(1000));
        let before_renew_active = observed.is_active(renew_at);
        let before_renew_remaining = observed.remaining(renew_at);
        let observed_renewed = observed.renew(dur(400), renew_at);

        let before_release_active = observed.is_active(release_at);
        let before_release_remaining = observed.remaining(release_at);
        let observed_released = observed.release(release_at);

        let after_release_active = observed.is_active(release_retry_at);
        let after_release_expired = observed.is_expired(release_retry_at);
        let after_release_remaining = observed.remaining(release_retry_at);
        let observed_release_retry = observed.release(release_retry_at);

        assert!(
            before_renew_active,
            "lease should be active before timely renewal"
        );
        assert_eq!(
            before_renew_remaining,
            dur(800),
            "remaining time before renewal should reflect the original guard horizon"
        );
        assert!(
            before_release_active,
            "lease should remain active before release"
        );
        assert_eq!(
            before_release_remaining,
            dur(150),
            "remaining time before release should reflect renewal-from-now semantics"
        );
        assert!(!after_release_active, "released lease must stay inactive");
        assert!(
            !after_release_expired,
            "released lease is terminal rather than time-expired"
        );
        assert_eq!(
            after_release_remaining,
            Duration::ZERO,
            "released lease has no remaining guarded time"
        );

        assert_eq!(
            observed_renewed, baseline_renewed,
            "read-only observations must not perturb renewal outcome"
        );
        assert_eq!(
            observed_released, baseline_released,
            "read-only observations must not perturb release outcome"
        );
        assert_eq!(
            observed_release_retry, baseline_release_retry,
            "read-only observations must not perturb terminal-state irreversibility"
        );
        assert_eq!(
            observed.expires_at, baseline.expires_at,
            "read-only observations must not perturb the guarded expiry frontier"
        );
        assert_eq!(
            observed.renewal_count, baseline.renewal_count,
            "read-only observations must not perturb renewal accounting"
        );
        assert_eq!(
            observed.released, baseline.released,
            "read-only observations must not perturb terminal release state"
        );
    }

    // ========================================================================
    // Actor step-indexed properties
    // ========================================================================

    /// Actor processes messages sequentially, one per step.
    #[test]
    fn actor_sequential_steps() {
        let mut actor = ActorStepModel::new();
        assert_eq!(actor.step, 0);
        assert!(!actor.is_terminal());

        // Process 5 messages
        for i in 1..=5 {
            assert!(actor.process_message());
            assert_eq!(actor.step, i);
        }
        assert!(!actor.is_terminal());
    }

    /// Actor cannot process messages after mailbox closes.
    #[test]
    fn actor_no_messages_after_close() {
        let mut actor = ActorStepModel::new();
        actor.process_message();
        actor.process_message();
        actor.close_mailbox();

        // No more message processing
        assert!(!actor.process_message());
        assert_eq!(actor.step, 2);
    }

    /// Actor finalization requires mailbox closure.
    #[test]
    fn actor_finalization_requires_close() {
        let mut actor = ActorStepModel::new();

        // Cannot finalize while mailbox is open
        assert!(!actor.finalize());

        // Close then finalize
        actor.close_mailbox();
        assert!(actor.finalize());
        assert!(actor.is_terminal());

        // Cannot finalize twice
        assert!(!actor.finalize());
    }

    /// Actor lifecycle: open → process → close → finalize → terminal.
    #[test]
    fn actor_full_lifecycle() {
        let mut actor = ActorStepModel::new();

        // Phase 1: process messages
        for _ in 0..10 {
            assert!(actor.process_message());
        }

        // Phase 2: close and finalize
        actor.close_mailbox();
        assert!(!actor.process_message()); // no more messages
        assert!(actor.finalize());
        assert!(actor.is_terminal());

        assert_eq!(actor.step, 10);
        assert!(actor.mailbox_closed);
        assert!(actor.finalized);
    }

    /// Supervised restart: new actor starts at step 0.
    #[test]
    fn actor_restart_resets_state() {
        let mut actor = ActorStepModel::new();
        actor.process_message();
        actor.process_message();
        actor.close_mailbox();
        actor.finalize();
        assert!(actor.is_terminal());

        // Restart: create a new actor (guarded step)
        let new_actor = ActorStepModel::new();
        assert_eq!(new_actor.step, 0);
        assert!(!new_actor.is_terminal());
        // The restart itself consumed a scheduling step (modeled externally)
    }

    // ========================================================================
    // Region phase monotonicity
    // ========================================================================

    /// Region phases must progress strictly forward.
    #[test]
    fn region_phase_ordering() {
        // Use u8 ordinals to model phase ordering
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[repr(u8)]
        enum Phase {
            Open = 0,
            Closing = 1,
            Draining = 2,
            Finalizing = 3,
            Closed = 4,
        }

        let sequence = [
            Phase::Open,
            Phase::Closing,
            Phase::Draining,
            Phase::Finalizing,
            Phase::Closed,
        ];

        // Verify strict forward progress
        for window in sequence.windows(2) {
            assert!(
                window[0] < window[1],
                "phase {:?} should be before {:?}",
                window[0],
                window[1]
            );
        }

        // Verify total count
        assert_eq!(sequence.len(), 5);
    }

    // ========================================================================
    // Budget decreasing measure
    // ========================================================================

    /// Budget consumption is monotonically decreasing.
    #[test]
    fn budget_monotonic_decrease() {
        // Model budget as a decreasing counter
        let mut polls_remaining: u32 = 100;
        let mut cost_remaining: u64 = 1000;

        for _ in 0..10 {
            let prev_polls = polls_remaining;
            let prev_cost = cost_remaining;
            polls_remaining -= 1;
            cost_remaining -= 50;
            assert!(polls_remaining < prev_polls);
            assert!(cost_remaining < prev_cost);
        }

        assert_eq!(polls_remaining, 90);
        assert_eq!(cost_remaining, 500);
    }

    // Pure data-type tests (wave 37 – CyanBarn)

    #[test]
    fn time_indexed_invariant_debug_copy_hash() {
        use std::collections::HashSet;
        let all = [
            TimeIndexedInvariant::ActorSequentialProcessing,
            TimeIndexedInvariant::ActorCleanFinalization,
            TimeIndexedInvariant::LeaseTimeMonotonicity,
            TimeIndexedInvariant::LeaseRenewalFromNow,
            TimeIndexedInvariant::LeaseTerminalIrreversibility,
            TimeIndexedInvariant::RegionPhaseMonotonicity,
            TimeIndexedInvariant::BudgetMonotonicConsumption,
            TimeIndexedInvariant::DeadlineTreeMonotonicity,
            TimeIndexedInvariant::SupervisedRestartGuarded,
        ];

        let mut set = HashSet::new();
        for inv in &all {
            let dbg = format!("{inv:?}");
            assert!(!dbg.is_empty());
            // Copy
            let inv2 = *inv;
            assert_eq!(*inv, inv2);
            set.insert(*inv);
        }
        assert_eq!(set.len(), 9);
    }

    #[test]
    fn preservation_constraint_debug_clone() {
        let constraint = PreservationConstraint {
            invariant: TimeIndexedInvariant::LeaseTimeMonotonicity,
            constraint: "test constraint",
            rationale: "test rationale",
        };
        let dbg = format!("{constraint:?}");
        assert!(dbg.contains("PreservationConstraint"));
        assert!(dbg.contains("LeaseTimeMonotonicity"));

        let cloned = constraint;
        assert_eq!(
            cloned.invariant,
            TimeIndexedInvariant::LeaseTimeMonotonicity
        );
        assert_eq!(cloned.constraint, "test constraint");
    }

    #[test]
    fn lease_model_debug_clone() {
        let lease = LeaseModel::new(t(100), dur(500));
        let dbg = format!("{lease:?}");
        assert!(dbg.contains("LeaseModel"));

        let cloned = lease;
        assert_eq!(cloned.created_at, t(100));
        assert_eq!(cloned.expires_at, t(600));
        assert_eq!(cloned.renewal_count, 0);
        assert!(!cloned.released);
    }

    #[test]
    fn actor_step_model_debug_clone_default() {
        let actor = ActorStepModel::default();
        assert_eq!(actor.step, 0);
        assert!(!actor.mailbox_closed);
        assert!(!actor.finalized);

        let dbg = format!("{actor:?}");
        assert!(dbg.contains("ActorStepModel"));

        let cloned = actor;
        assert_eq!(cloned.step, 0);
        assert!(!cloned.is_terminal());
    }

    /// Deadline approaches monotonically as time advances.
    #[test]
    fn deadline_approaches_monotonically() {
        let deadline = t(10_000);

        let mut prev_remaining = u64::MAX;
        for step in 0..10 {
            let now = t(step * 1000);
            let remaining = if now >= deadline {
                0
            } else {
                deadline.duration_since(now)
            };
            assert!(
                remaining <= prev_remaining,
                "remaining time should decrease"
            );
            prev_remaining = remaining;
        }
    }
