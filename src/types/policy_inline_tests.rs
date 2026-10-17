    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[inline]
    fn test_task_id() -> TaskId {
        TaskId::from_arena(crate::util::ArenaIndex::new(0, 0))
    }

    #[test]
    fn fail_fast_triggers_on_err_or_panic_only() {
        let policy = FailFast;

        let ok = Outcome::<(), crate::error::Error>::Ok(());
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &ok),
            PolicyAction::Continue
        );

        let cancelled = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &cancelled),
            PolicyAction::Continue
        );

        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &err),
            PolicyAction::CancelSiblings(CancelReason::sibling_failed())
        );

        let panicked = Outcome::<(), crate::error::Error>::Panicked(PanicPayload::new("boom"));
        assert_eq!(
            policy.on_child_outcome(test_task_id(), &panicked),
            PolicyAction::CancelSiblings(CancelReason::sibling_failed())
        );
    }

    #[test]
    fn aggregate_takes_panic_over_cancel_over_error() {
        let policy = CollectAll;
        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let cancelled = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        let panicked = Outcome::<(), crate::error::Error>::Panicked(PanicPayload::new("boom"));

        assert!(matches!(
            policy.aggregate_outcomes(std::slice::from_ref(&err)),
            AggregateDecision::FirstError(_)
        ));
        match policy.aggregate_outcomes(&[err, cancelled.clone()]) {
            AggregateDecision::Cancelled(r) => assert_eq!(r, CancelReason::timeout()),
            other => panic!("expected Cancelled, got {other:?}"),
        }
        match policy.aggregate_outcomes(&[cancelled, panicked]) {
            AggregateDecision::Panicked {
                payload: p,
                first_panic_index: idx,
            } => {
                assert_eq!(p.message(), "boom");
                assert_eq!(idx, 1);
            }
            other => panic!("expected Panicked, got {other:?}"),
        }
    }

    /// Invariant: FailFast aggregate on all-Ok outcomes returns AllOk.
    #[test]
    fn fail_fast_aggregate_all_ok() {
        let policy = FailFast;
        let ok1 = Outcome::<(), crate::error::Error>::Ok(());
        let ok2 = Outcome::<(), crate::error::Error>::Ok(());
        assert!(matches!(
            policy.aggregate_outcomes(&[ok1, ok2]),
            AggregateDecision::AllOk
        ));
    }

    /// Invariant: CollectAll always returns Continue regardless of outcome type.
    #[test]
    fn collect_all_always_continues() {
        let policy = CollectAll;
        let tid = test_task_id();

        let ok = Outcome::<(), crate::error::Error>::Ok(());
        assert_eq!(policy.on_child_outcome(tid, &ok), PolicyAction::Continue);

        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        assert_eq!(policy.on_child_outcome(tid, &err), PolicyAction::Continue);

        let panicked = Outcome::<(), crate::error::Error>::Panicked(PanicPayload::new("boom"));
        assert_eq!(
            policy.on_child_outcome(tid, &panicked),
            PolicyAction::Continue
        );

        let cancelled = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        assert_eq!(
            policy.on_child_outcome(tid, &cancelled),
            PolicyAction::Continue
        );
    }

    /// Invariant: PolicyAction Display renders all variants correctly.
    #[test]
    fn policy_action_display() {
        assert_eq!(format!("{}", PolicyAction::Continue), "continue");
        assert_eq!(format!("{}", PolicyAction::Escalate), "escalate");
        let cancel = PolicyAction::CancelSiblings(CancelReason::sibling_failed());
        let s = format!("{cancel}");
        assert!(s.starts_with("cancel siblings:"), "{s}");
    }

    /// Invariant: FailFast aggregate follows Panicked > Cancelled > Err severity lattice.
    #[test]
    fn fail_fast_aggregate_severity_lattice() {
        let policy = FailFast;
        let ok = Outcome::<(), crate::error::Error>::Ok(());
        let err = Outcome::<(), crate::error::Error>::Err(crate::error::Error::new(
            crate::error::ErrorKind::User,
        ));
        let cancelled = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());
        let panicked = Outcome::<(), crate::error::Error>::Panicked(PanicPayload::new("boom"));

        // Err > Ok
        assert!(matches!(
            policy.aggregate_outcomes(&[ok.clone(), err]),
            AggregateDecision::FirstError(_)
        ));
        // Cancelled > Err
        match policy.aggregate_outcomes(&[
            Outcome::Err(crate::error::Error::new(crate::error::ErrorKind::User)),
            cancelled,
        ]) {
            AggregateDecision::Cancelled(_) => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
        // Panicked > everything
        match policy.aggregate_outcomes(&[
            ok,
            Outcome::Err(crate::error::Error::new(crate::error::ErrorKind::User)),
            Outcome::Cancelled(CancelReason::timeout()),
            panicked,
        ]) {
            AggregateDecision::Panicked {
                first_panic_index, ..
            } => {
                assert_eq!(first_panic_index, 3);
            }
            other => panic!("expected Panicked, got {other:?}"),
        }
    }

    #[test]
    fn aggregate_strengthens_cancel_reasons_deterministically() {
        let policy = CollectAll;
        let a = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::user("b"));
        let b = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::user("a"));
        let timeout = Outcome::<(), crate::error::Error>::Cancelled(CancelReason::timeout());

        match policy.aggregate_outcomes(&[a.clone(), b.clone()]) {
            AggregateDecision::Cancelled(r) => assert_eq!(r, CancelReason::user("a")),
            other => panic!("expected Cancelled, got {other:?}"),
        }
        match policy.aggregate_outcomes(&[b, timeout, a]) {
            AggregateDecision::Cancelled(r) => assert_eq!(r, CancelReason::timeout()),
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    // =========================================================================
    // Wave 47 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn policy_action_debug_clone_eq() {
        let actions = [
            PolicyAction::Continue,
            PolicyAction::CancelSiblings(CancelReason::sibling_failed()),
            PolicyAction::Escalate,
        ];
        for a in &actions {
            let dbg = format!("{a:?}");
            assert!(!dbg.is_empty());
            let cloned = a.clone();
            assert_eq!(&cloned, a);
        }
        assert_ne!(actions[0], actions[1]);
        assert_ne!(actions[0], actions[2]);
    }

    #[test]
    fn aggregate_decision_debug_clone() {
        let d1: AggregateDecision<crate::error::Error> = AggregateDecision::AllOk;
        let dbg = format!("{d1:?}");
        assert!(dbg.contains("AllOk"), "{dbg}");
        let _cloned = d1;

        let d2: AggregateDecision<crate::error::Error> =
            AggregateDecision::Cancelled(CancelReason::timeout());
        let dbg2 = format!("{d2:?}");
        assert!(dbg2.contains("Cancelled"), "{dbg2}");
        let _cloned2 = d2;
    }

    #[test]
    fn fail_fast_debug_clone_copy_default() {
        let ff = FailFast;
        let dbg = format!("{ff:?}");
        assert_eq!(dbg, "FailFast");
        let copied = ff;
        let cloned = ff;
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
    }

    #[test]
    fn collect_all_debug_clone_copy_default() {
        let ca = CollectAll;
        let dbg = format!("{ca:?}");
        assert_eq!(dbg, "CollectAll");
        let copied = ca;
        let cloned = ca;
        assert_eq!(format!("{copied:?}"), format!("{cloned:?}"));
    }
