    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn test_region_state_valid_transitions() {
        use RegionState::*;

        // Valid transitions
        assert!(Open.is_valid_transition(Closing));
        assert!(Closing.is_valid_transition(Draining));
        assert!(Closing.is_valid_transition(Finalizing));
        assert!(Draining.is_valid_transition(Finalizing));
        assert!(Finalizing.is_valid_transition(Closed));

        // Invalid transitions
        assert!(!Open.is_valid_transition(Draining));
        assert!(!Open.is_valid_transition(Finalizing));
        assert!(!Open.is_valid_transition(Closed));
        assert!(!Closing.is_valid_transition(Open));
        assert!(!Closing.is_valid_transition(Closed));
        assert!(!Draining.is_valid_transition(Open));
        assert!(!Draining.is_valid_transition(Closing));
        assert!(!Draining.is_valid_transition(Closed));
        assert!(!Finalizing.is_valid_transition(Open));
        assert!(!Finalizing.is_valid_transition(Closing));
        assert!(!Finalizing.is_valid_transition(Draining));
        assert!(!Closed.is_valid_transition(Open));
        assert!(!Closed.is_valid_transition(Closing));
        assert!(!Closed.is_valid_transition(Draining));
        assert!(!Closed.is_valid_transition(Finalizing));
    }

    #[test]
    fn test_obligation_state_valid_transitions() {
        use ObligationState::*;

        // Valid transitions
        assert!(Reserved.is_valid_transition(Committed));
        assert!(Reserved.is_valid_transition(Aborted));
        assert!(Reserved.is_valid_transition(Leaked));

        // Invalid transitions (terminal states)
        assert!(!Committed.is_valid_transition(Reserved));
        assert!(!Committed.is_valid_transition(Aborted));
        assert!(!Committed.is_valid_transition(Leaked));
        assert!(!Aborted.is_valid_transition(Reserved));
        assert!(!Aborted.is_valid_transition(Committed));
        assert!(!Aborted.is_valid_transition(Leaked));
        assert!(!Leaked.is_valid_transition(Reserved));
        assert!(!Leaked.is_valid_transition(Committed));
        assert!(!Leaked.is_valid_transition(Aborted));
    }

    #[test]
    fn test_state_verifier_task_validation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            ..Default::default()
        });

        use crate::record::task::TaskPhase::*;
        let task_id = TaskId::new_for_test(1, 0);

        // Valid transition
        assert!(
            verifier
                .validate_task_transition(task_id, Created, Running, "test")
                .is_ok()
        );

        // Invalid transition
        assert!(
            verifier
                .validate_task_transition(task_id, Created, Finalizing, "test")
                .is_err()
        );

        let stats = verifier.stats();
        assert_eq!(stats.task_transitions, 2);
        assert_eq!(stats.task_violations, 1);
    }

    #[test]
    fn test_state_verifier_region_validation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            ..Default::default()
        });

        use RegionState::*;
        let region_id = RegionId::new_for_test(1, 0);

        // Valid transition
        assert!(
            verifier
                .validate_region_transition(region_id, Open, Closing, "test")
                .is_ok()
        );

        // Invalid transition
        assert!(
            verifier
                .validate_region_transition(region_id, Open, Closed, "test")
                .is_err()
        );

        let stats = verifier.stats();
        assert_eq!(stats.region_transitions, 2);
        assert_eq!(stats.region_violations, 1);
    }

    #[test]
    fn test_state_verifier_obligation_validation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            ..Default::default()
        });

        use ObligationState::*;
        let obligation_id = ObligationId::new_for_test(1, 0);

        // Valid transition
        assert!(
            verifier
                .validate_obligation_transition(obligation_id, Reserved, Committed, "test")
                .is_ok()
        );

        // Invalid transition
        assert!(
            verifier
                .validate_obligation_transition(obligation_id, Committed, Reserved, "test")
                .is_err()
        );

        let stats = verifier.stats();
        assert_eq!(stats.obligation_transitions, 2);
        assert_eq!(stats.obligation_violations, 1);
    }

    #[test]
    fn test_validation_can_be_disabled() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            enable_validation: false,
            panic_on_violation: true,
            enable_diagnostics: true,
            ..Default::default()
        });

        use crate::record::task::TaskPhase::*;
        let task_id = TaskId::new_for_test(2, 0);

        assert!(
            verifier
                .validate_task_transition(task_id, Created, Finalizing, "disabled")
                .is_ok()
        );

        let stats = verifier.stats();
        assert_eq!(stats.total_transitions, 0);
        assert_eq!(stats.violations_detected, 0);
        assert!(verifier.violations().is_empty());
    }

    #[test]
    fn test_violation_tracking() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: false,
            enable_diagnostics: false,
            max_tracked_violations: 2,
            ..Default::default()
        });

        use ObligationState::*;
        let obligation_id = ObligationId::new_for_test(1, 0);

        // Generate violations
        let _ =
            verifier.validate_obligation_transition(obligation_id, Committed, Reserved, "test1");
        let _ = verifier.validate_obligation_transition(obligation_id, Aborted, Reserved, "test2");
        let _ = verifier.validate_obligation_transition(obligation_id, Leaked, Reserved, "test3");

        let violations = verifier.violations();
        assert_eq!(violations.len(), 2); // Limited to max_tracked_violations
        assert_eq!(violations[0].context, "test2"); // Oldest dropped
        assert_eq!(violations[1].context, "test3");

        verifier.clear_violations();
        assert_eq!(verifier.violations().len(), 0);
    }

    #[test]
    #[should_panic(expected = "Invalid state transition")]
    fn test_panic_on_violation() {
        let verifier = StateTransitionVerifier::new(StateVerifierConfig {
            panic_on_violation: true,
            enable_diagnostics: false,
            ..Default::default()
        });

        use ObligationState::*;
        let obligation_id = ObligationId::new_for_test(1, 0);

        // This should panic
        let _ = verifier.validate_obligation_transition(obligation_id, Committed, Reserved, "test");
    }
