    use super::*;
    use crate::types::PanicPayload;

    #[test]
    fn impossible_quorum_is_decided_before_parked_suffix() {
        let mut selection = Selection::<u8, &str>::new(3, 4);
        assert!(selection.record(Outcome::Err("first")).is_none());
        let decision = selection.record(Outcome::Err("second")).unwrap();
        assert!(matches!(decision, Decision::Impossible));
        selection.outcomes.extend([
            Outcome::Cancelled(CancelReason::fail_fast()),
            Outcome::Cancelled(CancelReason::fail_fast()),
        ]);
        assert!(matches!(selection.finish(decision, None),
            Err(QuorumError::InsufficientSuccesses { required: 3, total: 4, achieved: 0, errors })
            if errors == ["first", "second"]));
    }

    #[test]
    fn quorum_keeps_only_selected_successes_after_late_retirement() {
        let mut selection = Selection::<u8, &str>::new(2, 4);
        assert!(selection.record(Outcome::Err("retryable application failure")).is_none());
        assert!(selection.record(Outcome::Ok(8)).is_none());
        let decision = selection.record(Outcome::Ok(3)).unwrap();
        selection.outcomes.push(Outcome::Ok(99));
        assert_eq!(selection.finish(decision, None).unwrap(), [8, 3]);
    }

    #[test]
    fn cleanup_panic_overrides_success_owner_cancel_and_invalid_input() {
        for decision in [Decision::Satisfied, Decision::Invalid, Decision::Impossible] {
            let mut selection = Selection::<u8, &str>::new(1, 2);
            selection.outcomes.push(Outcome::Ok(7));
            selection.outcomes.push(Outcome::Panicked(PanicPayload::new("cleanup")));
            assert!(matches!(selection.finish(decision, Some(CancelReason::shutdown())),
                Err(QuorumError::Panicked(_))));
        }
    }

    #[test]
    fn spontaneous_cancellation_does_not_prevent_an_achievable_quorum() {
        let mut selection = Selection::<u8, &str>::new(1, 2);
        assert!(selection.record(Outcome::Cancelled(CancelReason::shutdown())).is_none());
        let decision = selection.record(Outcome::Ok(6)).unwrap();
        assert_eq!(selection.finish(decision, None).unwrap(), [6]);
    }

    /// Review r32-e8 of 915d1ff53 (M2): when member cancellations make the
    /// quorum impossible, the strongest reason is reported, not the first
    /// (br-asupersync-1sngsf). Cleanup cancellations of the losers do not vote.
    #[test]
    fn impossible_quorum_reports_the_strongest_spontaneous_cancellation() {
        let mut selection = Selection::<u8, &str>::new(2, 3);
        assert!(
            selection
                .record(Outcome::Cancelled(CancelReason::user("member's own stop")))
                .is_none()
        );
        let decision = selection
            .record(Outcome::Cancelled(CancelReason::shutdown()))
            .unwrap();
        assert!(matches!(decision, Decision::Impossible));
        selection
            .outcomes
            .push(Outcome::Cancelled(CancelReason::fail_fast()));
        let Err(QuorumError::Cancelled(reason)) = selection.finish(decision, None) else {
            panic!("an impossible quorum after member cancellations reports Cancelled");
        };
        assert_eq!(reason.kind(), CancelReason::shutdown().kind());
    }
