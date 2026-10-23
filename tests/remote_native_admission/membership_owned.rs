//! Membership owns admitted native cancellation and terminal buffer retention.
use super::*;
use asupersync::distributed::membership::owned::work::{
    MembershipWorkError, MembershipWorkTrigger,
};
use asupersync::distributed::membership::owned::OwnedLeaseStatus;
use asupersync::distributed::remote_owned::{RemoteLeaseSettlement, RemoteRunTrigger};
use asupersync::observability::task_inspector::TaskInspectorConfig;
use asupersync::remote::NativeRemoteMembershipError;

const LEASE: Duration = Duration::from_secs(30);

fn config() -> RemoteRunConfig {
    RemoteRunConfig {
        timeout: Duration::from_secs(20),
        child: ChildRegionSpec::inherit(),
    }
}

#[derive(Debug, Clone, Copy)]
enum Retirement {
    Dead,
    Left,
    Superseded,
    ControllerClosed,
}

impl Retirement {
    fn apply(self, owner: &OwnedMembershipController) -> OwnedLeaseStatus {
        match self {
            Self::Dead => {
                apply(owner, 1, 2, MembershipKind::Dead);
                OwnedLeaseStatus::Revoked
            }
            Self::Left => {
                apply(owner, 1, 2, MembershipKind::Left);
                OwnedLeaseStatus::Revoked
            }
            Self::Superseded => {
                apply(owner, 2, 2, MembershipKind::Alive);
                OwnedLeaseStatus::Superseded
            }
            Self::ControllerClosed => {
                owner.close();
                OwnedLeaseStatus::Closed
            }
        }
    }
}

#[test]
fn admitted_membership_retirement_cancels_and_drains_the_exact_native_invocation() {
    native(|cx, runtime| async move {
        for case in [
            Retirement::Dead,
            Retirement::Left,
            Retirement::Superseded,
            Retirement::ControllerClosed,
        ] {
            let owner = authority(&cx);
            apply(&owner, 1, 1, MembershipKind::Alive);
            let witness = Arc::new(Witness::default());
            let mut serving = start_service(
                &cx,
                "peer",
                include_bytes!("../fixtures/tls/server.crt"),
                include_bytes!("../fixtures/tls/server.key"),
                Arc::clone(&witness),
            )
            .await;
            let admitted = domain(
                &runtime,
                serving.route.clone().with_membership(owner.clone(), 1).unwrap(),
            );
            let _stop = Stop {
                owner: owner.clone(),
                native: Vec::new(),
                admitted: vec![admitted.clone()],
                services: vec![serving.operator.clone()],
                witness: Arc::clone(&witness),
            };
            let executing = admitted.clone();
            let mut task = cx
                .spawn(move |caller| async move {
                    executing
                        .reserve(&caller, &NodeId::new("peer"), 0, WAIT)
                        .await
                        .unwrap()
                        .run_membership_owned(
                            &caller,
                            &ComputationName::new("wait"),
                            &[],
                            LEASE,
                            config(),
                        )
                        .await
                })
                .unwrap();
            eventually(&cx, || witness.parked.load(Ordering::Acquire)).await;
            assert_eq!(owner.live_leases(), 1);
            assert_eq!(admitted.usage().in_flight, 1);
            assert_eq!(admitted.usage().buffer_bytes, CHARGE);

            let expected = case.apply(&owner);
            eventually(&cx, || witness.cancelled.load(Ordering::Acquire)).await;
            assert!(
                task.try_join().unwrap().is_none(),
                "{case:?}: local membership retirement must not bypass remote cleanup"
            );
            assert!(!witness.retired.load(Ordering::Acquire));
            assert_eq!(admitted.usage().in_flight, 1);
            assert_eq!(admitted.usage().buffer_bytes, CHARGE);
            assert!(!cx.is_cancel_requested());

            witness.release();
            let report = asupersync::time::timeout(cx.now(), WAIT, task.join(&cx))
                .await
                .expect("membership and native cleanup terminate")
                .expect("owner task returns its typed result")
                .expect("membership admission succeeded");
            assert!(!report.is_success(), "{case:?}: {report:?}");
            assert!(matches!(
                report.work.trigger,
                MembershipWorkTrigger::LeaseEnded(status) if status == expected
            ));
            assert_eq!(report.work.lease.unwrap(), expected);
            let outer = report.work.close.unwrap();
            assert_ne!(outer.region_id, cx.region_id());
            let remote = report
                .work
                .task
                .unwrap()
                .expect("body cancellation retains the nested remote report");
            assert!(matches!(remote.trigger, RemoteRunTrigger::Cancelled(_)));
            assert!(remote.cancel_error.is_none());
            assert_ne!(remote.close.unwrap().region_id, outer.region_id);
            let reply = remote.task.unwrap();
            assert_eq!(reply.settlement, RemoteLeaseSettlement::Aborted);
            assert!(matches!(reply.outcome, Outcome::Ok(RemoteOutcome::Cancelled(_))));
            assert!(reply.cancellation.is_some());
            assert!(witness.retired.load(Ordering::Acquire));
            assert_eq!(owner.live_leases(), 0);
            eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
            assert_eq!(admitted.usage().in_flight, 0);
            assert!(admitted.close(&cx).await.unwrap());
            let _ = serving.operator.begin_drain();
            assert!(serving.task.join(&cx).await.unwrap().is_ok());
            assert_eq!(serving.operator.active_connections(), 0);
        }
    });
}

#[test]
fn admitted_membership_requires_a_bound_live_generation_and_explicit_rejoin() {
    native(|cx, runtime| async move {
        let owner = authority(&cx);
        apply(&owner, 1, 1, MembershipKind::Alive);
        let witness = Arc::new(Witness::default());
        let mut serving = start_service(
            &cx,
            "peer",
            include_bytes!("../fixtures/tls/server.crt"),
            include_bytes!("../fixtures/tls/server.key"),
            Arc::clone(&witness),
        )
        .await;
        let unbound = domain(&runtime, serving.route.clone());
        let bound = domain(
            &runtime,
            serving.route.clone().with_membership(owner.clone(), 1).unwrap(),
        );
        let mut stop = Stop {
            owner: owner.clone(),
            native: Vec::new(),
            admitted: vec![unbound.clone(), bound.clone()],
            services: vec![serving.operator.clone()],
            witness: Arc::clone(&witness),
        };
        let peer = NodeId::new("peer");
        let echo = ComputationName::new("echo");
        let refused = unbound
            .reserve(&cx, &peer, 0, WAIT)
            .await
            .unwrap()
            .run_membership_owned(&cx, &echo, &[], LEASE, config())
            .await;
        assert!(matches!(refused, Err(NativeRemoteMembershipError::MembershipRequired)));
        assert_eq!(unbound.usage().buffer_bytes, 0);

        let reserved = bound.reserve(&cx, &peer, 0, WAIT).await.unwrap();
        apply(&owner, 1, 2, MembershipKind::Suspect);
        let refused = reserved
            .run_membership_owned(&cx, &echo, &[], LEASE, config())
            .await;
        assert!(matches!(
            refused,
            Err(NativeRemoteMembershipError::Membership(MembershipWorkError::Lease(
                OwnedMembershipError::Control(MembershipControlError::GrantDenied)
            )))
        ));
        apply(&owner, 1, 3, MembershipKind::Alive);
        let stale = bound.reserve(&cx, &peer, 0, WAIT).await.unwrap();
        apply(&owner, 2, 4, MembershipKind::Alive);
        let refused = stale
            .run_membership_owned(&cx, &echo, &[], LEASE, config())
            .await;
        assert!(matches!(
            refused,
            Err(NativeRemoteMembershipError::Membership(MembershipWorkError::Lease(
                OwnedMembershipError::Control(MembershipControlError::GrantDenied)
            )))
        ));
        assert_eq!(owner.live_leases(), 0);
        assert_eq!(bound.usage().buffer_bytes, 0);
        assert_eq!(serving.operator.active_connections(), 0);

        let fresh = domain(
            &runtime,
            serving.route.clone().with_membership(owner.clone(), 2).unwrap(),
        );
        stop.admitted.push(fresh.clone());
        let report = fresh
            .reserve(&cx, &peer, 5, WAIT)
            .await
            .unwrap()
            .run_membership_owned(&cx, &echo, b"fresh", LEASE, config())
            .await
            .unwrap();
        assert!(report.is_success(), "{report:?}");
        assert!(matches!(report.work.lease, Ok(OwnedLeaseStatus::Released)));
        let outer = report.work.close.as_ref().unwrap();
        let remote = report.work.task.as_ref().unwrap().as_ref().unwrap();
        assert_ne!(remote.close.as_ref().unwrap().region_id, outer.region_id);
        assert!(matches!(
            &remote.task.as_ref().unwrap().outcome,
            Outcome::Ok(RemoteOutcome::Success(bytes)) if bytes == b"fresh"
        ));
        eventually(&cx, || fresh.usage().buffer_bytes == 0).await;
        assert_eq!(owner.live_leases(), 0);

        let unpolled = fresh.reserve(&cx, &peer, 0, WAIT).await.unwrap();
        let invocation = unpolled.run_membership_owned(&cx, &echo, &[], LEASE, config());
        assert_eq!(fresh.usage().buffer_bytes, CHARGE);
        drop(invocation);
        assert_eq!(fresh.usage().buffer_bytes, 0);
        assert_eq!(owner.live_leases(), 0);
        assert!(unbound.close(&cx).await.unwrap());
        assert!(bound.close(&cx).await.unwrap());
        assert!(fresh.close(&cx).await.unwrap());
        let _ = serving.operator.begin_drain();
        assert!(serving.task.join(&cx).await.unwrap().is_ok());
    });
}

#[test]
fn admitted_membership_retains_unread_body_result_credit_until_consume_or_drop() {
    native(|cx, runtime| async move {
        for consume in [true, false] {
            let owner = authority(&cx);
            apply(&owner, 1, 1, MembershipKind::Alive);
            let witness = Arc::new(Witness::default());
            let mut serving = start_service(
                &cx,
                "peer",
                include_bytes!("../fixtures/tls/server.crt"),
                include_bytes!("../fixtures/tls/server.key"),
                Arc::clone(&witness),
            )
            .await;
            let admitted = domain(
                &runtime,
                serving.route.clone().with_membership(owner.clone(), 1).unwrap(),
            );
            let _stop = Stop {
                owner: owner.clone(),
                native: Vec::new(),
                admitted: vec![admitted.clone()],
                services: vec![serving.operator.clone()],
                witness: Arc::clone(&witness),
            };
            // Inspectors can contain a detached, non-Sync RuntimeState variant.
            // Build each live inspector only within a synchronous query, never
            // retain that enum across an await in this Send native task.
            eventually(&cx, || {
                runtime
                    .task_inspector(TaskInspectorConfig::default())
                    .unwrap()
                    .inspect_task(serving.task.task_id())
                    .is_some()
            })
            .await;
            let baseline: Vec<_> = runtime
                .task_inspector(TaskInspectorConfig::default())
                .unwrap()
                .list_tasks()
                .iter()
                .map(|task| task.id)
                .collect();
            let reserved = admitted
                .reserve(&cx, &NodeId::new("peer"), 0, WAIT)
                .await
                .unwrap();
            let computation = ComputationName::new("wait");
            let mut invocation = Box::pin(
                reserved.run_membership_owned(&cx, &computation, &[], LEASE, config()),
            );
            let mut parked = std::pin::pin!(
                witness.changed.wait_until(|| witness.parked.load(Ordering::Acquire))
            );
            asupersync::time::timeout(cx.now(), WAIT, poll_fn(|task| {
                assert!(invocation.as_mut().poll(task).is_pending());
                parked.as_mut().poll(task)
            }))
            .await
            .expect("membership body has started the real native peer");

            // Stop polling the outer owner. Native-domain shutdown independently
            // cancels the peer, so its body and local child can finish while the
            // outer membership TaskHandle still owns an unread terminal value.
            assert!(admitted.begin_drain());
            eventually(&cx, || witness.cancelled.load(Ordering::Acquire)).await;
            assert!(!witness.retired.load(Ordering::Acquire));
            assert_eq!(admitted.usage().buffer_bytes, CHARGE);
            witness.release();
            assert!(admitted.close(&cx).await.unwrap());
            eventually(&cx, || {
                witness.retired.load(Ordering::Acquire)
                    && serving.operator.active_connections() == 0
                    && runtime
                        .task_inspector(TaskInspectorConfig::default())
                        .unwrap()
                        .list_tasks()
                        .iter()
                        .all(|task| baseline.contains(&task.id))
            })
            .await;
            assert_eq!(owner.live_leases(), 1, "outer owner was not polled again");
            assert_eq!(admitted.usage().in_flight, 1);
            assert_eq!(
                admitted.usage().buffer_bytes,
                CHARGE,
                "all invocation tasks retired; only the unread body result remains"
            );

            if consume {
                let report = invocation.await.unwrap();
                assert!(!report.is_success());
                assert!(report.work.close.is_ok());
                assert!(report.work.task.as_ref().unwrap().as_ref().unwrap().close.is_ok());
                eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
                // Holding the public report now retains caller-owned bytes.
                assert!(report.work.task.is_ok());
            } else {
                drop(invocation);
                eventually(&cx, || admitted.usage().buffer_bytes == 0).await;
            }
            assert_eq!(owner.live_leases(), 0);
            assert_eq!(admitted.usage().in_flight, 0);
            assert_eq!(admitted.usage().waiters, 0);
            assert!(!cx.is_cancel_requested());
            let _ = serving.operator.begin_drain();
            assert!(serving.task.join(&cx).await.unwrap().is_ok());
        }
    });
}
