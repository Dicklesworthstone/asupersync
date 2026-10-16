    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::collections::HashSet;

    fn expected_oracle_invariant_count() -> usize {
        let mut count = 24;
        if cfg!(feature = "messaging-fabric") {
            count += 4;
        }
        count
    }

    fn expected_builtin_mutation_count() -> usize {
        let mut count = 13;
        if cfg!(feature = "messaging-fabric") {
            count += 4;
        }
        count
    }

    #[test]
    fn all_oracle_invariants_count() {
        assert_eq!(
            ALL_ORACLE_INVARIANTS.len(),
            expected_oracle_invariant_count()
        );
    }

    #[test]
    fn all_oracle_invariants_unique() {
        let set: HashSet<&str> = ALL_ORACLE_INVARIANTS.iter().copied().collect();
        assert_eq!(set.len(), ALL_ORACLE_INVARIANTS.len());
    }

    #[test]
    fn builtin_mutations_count() {
        assert_eq!(builtin_mutations().len(), expected_builtin_mutation_count());
    }

    #[test]
    fn builtin_mutations_stable_order() {
        assert_eq!(builtin_mutations(), builtin_mutations());
    }

    #[test]
    fn mutation_names_unique() {
        let names: Vec<&str> = builtin_mutations().iter().map(|m| m.name()).collect();
        let set: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(set.len(), names.len(), "mutation names must be unique");
    }

    #[test]
    fn mutation_invariants_all_in_all_oracle_invariants() {
        let all_set: HashSet<&str> = ALL_ORACLE_INVARIANTS.iter().copied().collect();
        for m in builtin_mutations() {
            assert!(
                all_set.contains(m.invariant()),
                "mutation {:?} targets unknown invariant {}",
                m,
                m.invariant()
            );
        }
    }

    #[test]
    fn mutation_name_matches_variant() {
        assert_eq!(BuiltinMutation::TaskLeak.name(), "mutation_task_leak");
        assert_eq!(
            BuiltinMutation::ObligationLeak.name(),
            "mutation_obligation_leak"
        );
        assert_eq!(BuiltinMutation::Quiescence.name(), "mutation_quiescence");
        assert_eq!(BuiltinMutation::LoserDrain.name(), "mutation_loser_drain");
        assert_eq!(BuiltinMutation::Finalizer.name(), "mutation_finalizer");
        assert_eq!(
            BuiltinMutation::RegionTreeMultipleRoots.name(),
            "mutation_region_tree_multiple_roots"
        );
        assert_eq!(
            BuiltinMutation::AmbientAuthoritySpawnWithoutCapability.name(),
            "mutation_ambient_authority_spawn_without_capability"
        );
        assert_eq!(
            BuiltinMutation::DeadlineMonotoneChildUnbounded.name(),
            "mutation_deadline_child_unbounded"
        );
        assert_eq!(
            BuiltinMutation::CancelPropagationMissingChild.name(),
            "mutation_cancel_missing_child"
        );
        assert_eq!(BuiltinMutation::ActorLeak.name(), "mutation_actor_leak");
        assert_eq!(
            BuiltinMutation::SupervisionRestartLimitExceeded.name(),
            "mutation_supervision_restart_limit"
        );
        assert_eq!(
            BuiltinMutation::MailboxCapacityExceeded.name(),
            "mutation_mailbox_capacity_exceeded"
        );
        assert_eq!(
            BuiltinMutation::CrossRegionRRefAccess.name(),
            "mutation_cross_region_rref_access"
        );
        #[cfg(feature = "messaging-fabric")]
        {
            assert_eq!(
                BuiltinMutation::FabricPublishMissingSubscriberDelivery.name(),
                "mutation_fabric_publish_missing_subscriber_delivery"
            );
            assert_eq!(
                BuiltinMutation::FabricReplyUnresolvedOnClose.name(),
                "mutation_fabric_reply_unresolved_on_close"
            );
            assert_eq!(
                BuiltinMutation::FabricQuiescenceBusyCellOnClose.name(),
                "mutation_fabric_quiescence_busy_cell_on_close"
            );
            assert_eq!(
                BuiltinMutation::FabricRedeliveryBoundExceeded.name(),
                "mutation_fabric_redelivery_bound_exceeded"
            );
        }
    }

    #[test]
    fn mutation_invariant_mapping() {
        assert_eq!(BuiltinMutation::TaskLeak.invariant(), INVARIANT_TASK_LEAK);
        assert_eq!(
            BuiltinMutation::ObligationLeak.invariant(),
            INVARIANT_OBLIGATION_LEAK
        );
        assert_eq!(
            BuiltinMutation::Quiescence.invariant(),
            INVARIANT_QUIESCENCE
        );
        assert_eq!(
            BuiltinMutation::LoserDrain.invariant(),
            INVARIANT_LOSER_DRAIN
        );
        assert_eq!(BuiltinMutation::Finalizer.invariant(), INVARIANT_FINALIZER);
        assert_eq!(
            BuiltinMutation::RegionTreeMultipleRoots.invariant(),
            INVARIANT_REGION_TREE
        );
        assert_eq!(
            BuiltinMutation::AmbientAuthoritySpawnWithoutCapability.invariant(),
            INVARIANT_AMBIENT_AUTHORITY
        );
        assert_eq!(
            BuiltinMutation::DeadlineMonotoneChildUnbounded.invariant(),
            INVARIANT_DEADLINE_MONOTONE
        );
        assert_eq!(
            BuiltinMutation::CancelPropagationMissingChild.invariant(),
            INVARIANT_CANCELLATION_PROTOCOL
        );
        assert_eq!(BuiltinMutation::ActorLeak.invariant(), INVARIANT_ACTOR_LEAK);
        assert_eq!(
            BuiltinMutation::SupervisionRestartLimitExceeded.invariant(),
            INVARIANT_SUPERVISION
        );
        assert_eq!(
            BuiltinMutation::MailboxCapacityExceeded.invariant(),
            INVARIANT_MAILBOX
        );
        assert_eq!(
            BuiltinMutation::CrossRegionRRefAccess.invariant(),
            INVARIANT_RREF_ACCESS
        );
        #[cfg(feature = "messaging-fabric")]
        {
            assert_eq!(
                BuiltinMutation::FabricPublishMissingSubscriberDelivery.invariant(),
                INVARIANT_FABRIC_PUBLISH
            );
            assert_eq!(
                BuiltinMutation::FabricReplyUnresolvedOnClose.invariant(),
                INVARIANT_FABRIC_REPLY
            );
            assert_eq!(
                BuiltinMutation::FabricQuiescenceBusyCellOnClose.invariant(),
                INVARIANT_FABRIC_QUIESCENCE
            );
            assert_eq!(
                BuiltinMutation::FabricRedeliveryBoundExceeded.invariant(),
                INVARIANT_FABRIC_REDELIVERY
            );
        }
    }

    #[test]
    fn builtin_mutation_equality_and_hash() {
        let a = BuiltinMutation::TaskLeak;
        let b = BuiltinMutation::TaskLeak;
        let c = BuiltinMutation::Finalizer;
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mut set = HashSet::new();
        set.insert(a);
        set.insert(b);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn builtin_mutation_debug() {
        assert!(format!("{:?}", BuiltinMutation::TaskLeak).contains("TaskLeak"));
    }

    #[test]
    fn builtin_mutation_clone_copy() {
        let a = BuiltinMutation::TaskLeak;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn baseline_task_leak_no_panic() {
        let mut h = MetaHarness::new(42);
        BuiltinMutation::TaskLeak.apply_baseline(&mut h);
    }

    #[test]
    fn mutation_task_leak_no_panic() {
        let mut h = MetaHarness::new(42);
        BuiltinMutation::TaskLeak.apply_mutation(&mut h);
    }

    #[test]
    fn baseline_all_mutations_no_panic() {
        for m in builtin_mutations() {
            let mut h = MetaHarness::new(42);
            m.apply_baseline(&mut h);
        }
    }

    #[test]
    fn mutation_all_mutations_no_panic() {
        for m in builtin_mutations() {
            let mut h = MetaHarness::new(42);
            m.apply_mutation(&mut h);
        }
    }

    #[test]
    fn baseline_produces_no_violations() {
        for m in builtin_mutations() {
            let mut h = MetaHarness::new(42);
            m.apply_baseline(&mut h);
            let v = h.oracles.check_all(h.now());
            assert!(
                v.is_empty(),
                "baseline for {m:?} produced violations: {v:?}"
            );
        }
    }

    #[test]
    fn mutation_produces_expected_violation() {
        for m in builtin_mutations() {
            let mut h = MetaHarness::new(42);
            m.apply_mutation(&mut h);
            let v = h.oracles.check_all(h.now());
            let detected = v
                .iter()
                .any(|vv| invariant_from_violation(vv) == m.invariant());
            let inv = m.invariant();
            assert!(
                detected,
                "mutation {m:?} did not trigger expected invariant {inv}; got {v:?}"
            );
        }
    }
