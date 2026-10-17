    #![allow(clippy::pedantic, clippy::nursery)]

    use super::*;
    use super::tests::{finish, fixture, flush};
    use crate::runtime::obligation_mailbox::ObligationGateway;

    #[test]
    fn independent_runtime_ids_cannot_alias_shared_discovery() {
        let (first_lab, first, first_handle) = fixture(1);
        let (second_lab, second, second_handle) = fixture(1);
        assert_eq!(first.task_id(), second.task_id());
        assert_eq!(first.region_id(), second.region_id());
        let names = TrackedNameRegistry::new();
        let mut lease = names.register(&first, "worker").unwrap();
        let clone = names.clone();
        // Lookups:
        // Ambient whereis returns raw TaskId without runtime domain validation:
        assert_eq!(clone.whereis("worker"), Some(first.task_id()));
        // whereis_cx validates runtime domain: caller in first runtime succeeds:
        assert_eq!(clone.whereis_cx(&first, "worker"), Ok(Some(first.task_id())));
        // whereis_cx rejects caller from second runtime:
        assert_eq!(clone.whereis_cx(&second, "worker"), Err(TrackedNameError::DifferentRuntime));
        // Cross-runtime transfer is refused:
        assert_eq!(lease.try_transfer(&second), Err(TrackedNameError::DifferentRuntime));
        lease.release().unwrap();

        assert!(matches!(clone.register(&second, "worker"), Err(TrackedNameError::DifferentRuntime)));
        assert!(matches!(clone.reserve(&second, "startup"), Err(TrackedNameError::DifferentRuntime)));
        assert_eq!(clone.whereis("worker"), None);
        assert_eq!(clone.whereis("startup"), None);
        assert_eq!(clone.whereis_cx(&first, "worker"), Ok(None));
        assert_eq!(clone.whereis_cx(&second, "worker"), Err(TrackedNameError::DifferentRuntime));
        // Failed cross-runtime attempts must not retain the second runtime's quota.
        TrackedNameRegistry::new().register(&second, "worker").unwrap().release().unwrap();
        names.register(&first, "worker").unwrap().release().unwrap();
        finish(first_lab, &first, first_handle, 2);
        finish(second_lab, &second, second_handle, 3);
    }

    #[test]
    fn dead_runtime_binding_is_not_reusable_or_a_strong_runtime_owner() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        names.register(&cx, "worker").unwrap().release().unwrap();
        let weak = Arc::downgrade(lab.state.obligation_gateway().unwrap().mailbox());
        finish(lab, &cx, handle, 1);
        drop(cx);
        assert!(weak.upgrade().is_none(), "registry retained runtime mailbox resources");
        let (lab, cx, handle) = fixture(1);
        assert!(matches!(names.register(&cx, "worker"), Err(TrackedNameError::DifferentRuntime)));
        finish(lab, &cx, handle, 1);
    }

    #[test]
    fn gateway_wrappers_in_one_runtime_share_the_identity_binding() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        names.register(&cx, "worker").unwrap().release().unwrap();
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(|| {}),
            Arc::downgrade(&liveness),
        ));
        let wrapped = cx.clone().with_obligation_gateway(Some(gateway), None);
        names.reserve(&wrapped, "worker").unwrap().commit().unwrap().release().unwrap();
        finish(lab, &cx, handle, 2);
    }

    #[test]
    fn admission_callback_cannot_publish_for_a_retired_holder() {
        let (mut lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let retired = cx.clone();
        let liveness = Arc::new(());
        let gateway = Arc::new(ObligationGateway::new(
            Arc::clone(lab.state.obligation_gateway().unwrap().mailbox()),
            Arc::new(move || retired.revoke_obligation_admission()),
            Arc::downgrade(&liveness),
        ));
        let cx = cx.with_obligation_gateway(Some(gateway), None);
        assert!(matches!(names.register(&cx, "worker"),
            Err(TrackedNameError::Admission(ObligationAdmissionError::HolderNotLive))));
        assert!(!cx.is_cancel_requested());
        assert_eq!(names.whereis("worker"), None);
        flush(&mut lab);
        assert_eq!(lab.state.pending_obligation_count(), 0);
        assert_eq!(lab.state.leak_count(), 0);
        drop(handle);
    }

    #[test]
    fn retired_holder_cannot_commit_an_unpublished_name() {
        let (mut lab, cx, mut handle) = fixture(1);
        lab.state.set_obligation_leak_response(crate::runtime::config::ObligationLeakResponse::Silent);
        let names = TrackedNameRegistry::new();
        let permit = names.reserve(&cx, "worker").unwrap();
        flush(&mut lab);
        assert_eq!(lab.state.pending_obligation_count(), 1);
        lab.scheduler.lock().schedule(cx.task_id(), 0);
        let _report = lab.run_until_quiescent_with_report();
        assert!(!matches!(handle.try_join(), Ok(None)));
        assert_eq!(lab.state.leak_count(), 1);
        assert!(matches!(permit.commit(),
            Err(TrackedNameError::Admission(ObligationAdmissionError::HolderNotLive))));
        assert_eq!(names.whereis("worker"), None);
        assert_eq!(lab.state.leak_count(), 1, "late cleanup changed the audit outcome");
    }

    #[test]
    fn runtime_teardown_cannot_be_followed_by_name_publication() {
        let (lab, cx, handle) = fixture(1);
        let names = TrackedNameRegistry::new();
        let permit = names.reserve(&cx, "worker").unwrap();
        drop(handle);
        drop(lab);
        assert!(matches!(permit.commit(),
            Err(TrackedNameError::Admission(ObligationAdmissionError::RuntimeUnavailable))));
        assert_eq!(names.whereis("worker"), None);
    }
