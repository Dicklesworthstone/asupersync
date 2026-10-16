    use super::*;
    use crate::distributed::membership::{MembershipEvent, MembershipKind};
    use crate::distributed::membership::authority::{MembershipControllerLimits, MembershipFloor, MembershipUpdate};
    use crate::security::AuthKey;

    fn fixture() -> (Mutex<MembershipLeaseController>, NodeId, Vec<u8>) {
        let authority = NodeId::new("authority"); let node = NodeId::new("worker");
        let state = MembershipLeaseController::new(authority.clone(), 7, AuthKey::from_seed(42),
            vec![MembershipFloor { node: node.clone(), incarnation: 0, sequence: 0 }],
            MembershipControllerLimits { max_members: 1, max_lease_ids: 4 }).unwrap();
        let data = MembershipUpdate { event: MembershipEvent { node, incarnation: 1, kind: MembershipKind::Alive }, sequence: 1 }
            .authenticated_bytes(&authority, 7, &AuthKey::from_seed(42)).unwrap();
        (Mutex::new(state), authority, data)
    }

    #[test]
    fn exact_receipt_follows_admission_and_duplicates_do_not_repeat_effects() {
        let (state, authority, bytes) = fixture();
        for _ in 0..2 {
            assert!(matches!(apply_request(&state, &authority, &bytes), RemoteOutcome::Success(reply) if reply == bytes));
        }
        assert_eq!(state.lock().stamp(&NodeId::new("worker")).unwrap().sequence, 1);
    }

    #[test]
    fn valid_signature_cannot_substitute_for_authenticated_peer_authority() {
        let (state, _, bytes) = fixture();
        assert!(matches!(apply_request(&state, &NodeId::new("other"), &bytes), RemoteOutcome::Failed(_)));
        assert!(state.lock().stamp(&NodeId::new("worker")).is_none());
    }

    #[test]
    fn busy_local_owner_refuses_without_blocking_or_applying() {
        let (state, authority, bytes) = fixture();
        let guard = state.lock();
        assert!(matches!(apply_request(&state, &authority, &bytes), RemoteOutcome::Failed(message) if message == "membership controller is busy"));
        assert!(guard.stamp(&NodeId::new("worker")).is_none());
        drop(guard);
        assert!(matches!(apply_request(&state, &authority, &bytes), RemoteOutcome::Success(_)));
    }

    #[test]
    fn authenticated_peer_cannot_bypass_statement_mac_or_size() {
        let (state, authority, mut bytes) = fixture();
        let n = bytes.len(); bytes[n-1] ^= 1;
        assert!(matches!(apply_request(&state, &authority, &bytes), RemoteOutcome::Failed(_)));
        assert!(matches!(apply_request(&state, &authority, &[0; MAX_MEMBERSHIP_UPDATE_BYTES + 1]), RemoteOutcome::Failed(_)));
        assert!(state.lock().stamp(&NodeId::new("worker")).is_none());
    }
