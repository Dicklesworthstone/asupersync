    use super::*;
    use crate::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor};
    use crate::remote::RemoteCap;
    use crate::security::AuthKey;
    use crate::time::{TimerDriver, TimerDriverHandle};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn no_remote_capability_or_runtime_never_creates_a_membership_lease() {
        let timer = TimerDriverHandle::new(Arc::new(TimerDriver::new()));
        let owner = OwnedMembershipController::new(
            NodeId::new("authority"),
            1,
            AuthKey::from_seed(7),
            vec![MembershipFloor { node: NodeId::new("worker"), incarnation: 1, sequence: 0 }],
            MembershipControllerLimits { max_members: 1, max_lease_ids: 1 },
            timer,
        ).unwrap();
        for (cx, has_cap) in [
            (Cx::for_testing(), false),
            (Cx::for_testing_with_remote(RemoteCap::new()), true),
        ] {
            let result = futures_lite::future::block_on(owner.run_remote(
                &cx, NodeId::new("worker"), 1, ComputationName::new("echo"), RemoteInput::empty(),
                RemoteRunConfig { timeout: Duration::from_secs(1), child: crate::cx::ChildRegionSpec::inherit() },
            ));
            assert!(match result {
                Err(MembershipRemoteError::Remote(RemoteRunError::NoRemoteRuntime)) => has_cap,
                Err(MembershipRemoteError::Remote(RemoteRunError::NoCapability)) => !has_cap,
                _ => false,
            });
            assert_eq!(owner.live_leases(), 0);
        }
    }
