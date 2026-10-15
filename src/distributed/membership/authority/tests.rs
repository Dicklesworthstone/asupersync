use super::*;
use crate::types::{RegionId, TaskId};

fn node() -> NodeId { NodeId::new("worker") }
fn authority() -> NodeId { NodeId::new("membership-authority") }
fn limits() -> MembershipControllerLimits { MembershipControllerLimits { max_members: 2, max_lease_ids: 8 } }
fn controller() -> MembershipLeaseController {
    MembershipLeaseController::new(authority(), 7, AuthKey::from_seed(42),
        vec![MembershipFloor { node: node(), incarnation: 10, sequence: 20 }], limits()).unwrap()
}
fn bytes(incarnation: u64, sequence: u64, kind: MembershipKind) -> Vec<u8> {
    MembershipUpdate { event: MembershipEvent { node: node(), incarnation, kind }, sequence }
        .authenticated_bytes(&authority(), 7, &AuthKey::from_seed(42)).unwrap()
}
fn apply(c: &mut MembershipLeaseController, incarnation: u64, sequence: u64, kind: MembershipKind) -> MembershipApplied {
    c.apply_authenticated(&bytes(incarnation, sequence, kind)).unwrap()
}
fn lease(id: u32) -> Lease {
    Lease::new(ObligationId::new_for_test(id, 1), RegionId::new_for_test(1, 1),
        TaskId::new_for_test(1, 1), Duration::from_secs(30), Time::ZERO)
}
fn initialized() -> MembershipLeaseController {
    let mut c = controller(); apply(&mut c, 10, 21, MembershipKind::Alive); c
}
fn sign_body(mut body: Vec<u8>) -> Vec<u8> {
    let tag = AuthenticationTag::compute_for_domain_payload(&AuthKey::from_seed(42), DOMAIN, &body);
    body.extend_from_slice(tag.as_bytes()); body
}

#[test]
fn requires_fresh_authenticated_alive_before_admission() {
    let mut c = controller();
    let rejected = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap_err();
    assert!(matches!(rejected.error, MembershipControlError::GrantDenied));
    assert_eq!(rejected.lease.obligation_id(), ObligationId::new_for_test(1, 1));
    assert!(matches!(c.apply_authenticated(&bytes(10, 20, MembershipKind::Alive)), Err(MembershipControlError::Stale)));
    assert!(matches!(c.apply_authenticated(&bytes(9, 21, MembershipKind::Alive)), Err(MembershipControlError::Stale)));
    apply(&mut c, 10, 21, MembershipKind::Alive);
    let token = c.try_grant(&node(), 10, rejected.lease, Time::ZERO).unwrap();
    assert_eq!(token.incarnation(), 10); assert_eq!(c.active_leases(&node()), 1);
}

#[test]
fn terminal_incarnation_rejects_resurrection_but_new_one_accepts_fresh_lease() {
    let mut c = initialized();
    let old = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
    assert_eq!(apply(&mut c, 10, 22, MembershipKind::Dead), MembershipApplied::Applied { revoked: 1 });
    assert_eq!(c.active_leases(&node()), 0);
    assert!(matches!(c.apply_authenticated(&bytes(10, 23, MembershipKind::Alive)), Err(MembershipControlError::Terminal)));
    apply(&mut c, 11, 23, MembershipKind::Alive);
    assert!(matches!(c.renew(&old, Duration::from_secs(5), Time::ZERO), Err(MembershipControlError::UnknownLease)));
    assert!(matches!(c.try_grant(&node(), 11, lease(1), Time::ZERO).unwrap_err().error, MembershipControlError::ReusedLease));
    c.try_grant(&node(), 11, lease(2), Time::ZERO).unwrap();
    assert_eq!(c.revocations().len(), 1); assert_eq!(c.revocations()[0].lease, old);
}

#[test]
fn higher_incarnation_retires_live_leases_without_needing_an_intermediate_death() {
    let mut c = initialized();
    let first = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
    let second = c.try_grant(&node(), 10, lease(2), Time::ZERO).unwrap();
    assert_eq!(apply(&mut c, 11, 22, MembershipKind::Alive), MembershipApplied::Applied { revoked: 2 });
    assert_eq!(c.revocations().iter().map(|r| r.lease.clone()).collect::<Vec<_>>(), [first, second]);
    assert!(c.revocations().iter().all(|r| r.reason == MembershipRevocationReason::Superseded));
}

#[test]
fn delayed_old_incarnation_cannot_revoke_rejoined_member_even_with_larger_sequence() {
    let mut c = initialized(); apply(&mut c, 11, 22, MembershipKind::Alive);
    c.try_grant(&node(), 11, lease(1), Time::ZERO).unwrap();
    assert!(matches!(c.apply_authenticated(&bytes(10, 900, MembershipKind::Dead)), Err(MembershipControlError::Stale)));
    assert_eq!(c.stamp(&node()).unwrap().sequence, 22);
    assert_eq!(c.active_leases(&node()), 1); assert!(c.revocations().is_empty());
}

#[test]
fn latest_duplicates_are_idempotent_and_equivocation_or_older_sequences_refuse() {
    let mut c = initialized();
    assert_eq!(apply(&mut c, 10, 21, MembershipKind::Alive), MembershipApplied::Duplicate);
    assert!(matches!(c.apply_authenticated(&bytes(10, 21, MembershipKind::Dead)), Err(MembershipControlError::Conflict)));
    apply(&mut c, 10, 22, MembershipKind::Suspect);
    assert!(matches!(c.apply_authenticated(&bytes(10, 21, MembershipKind::Alive)), Err(MembershipControlError::Stale)));
    assert_eq!(c.stamp(&node()).unwrap().kind, MembershipKind::Suspect);
}

#[test]
fn suspicion_retains_existing_leases_and_refutation_resumes_only_new_grants() {
    let mut c = initialized(); let token = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
    apply(&mut c, 10, 22, MembershipKind::Suspect);
    assert!(c.try_grant(&node(), 10, lease(2), Time::ZERO).is_err());
    c.renew(&token, Duration::from_secs(60), Time::from_secs(1)).unwrap();
    assert_eq!(c.next_expiry(), Some(Time::from_secs(61)));
    apply(&mut c, 10, 23, MembershipKind::Alive);
    c.try_grant(&node(), 10, lease(2), Time::from_secs(1)).unwrap();
    assert_eq!(c.active_leases(&node()), 2); assert!(c.revocations().is_empty());
}

#[test]
fn outbox_survives_repeated_reads_and_rejoin_until_explicit_cleanup_acknowledgement() {
    let mut c = initialized(); let token = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
    apply(&mut c, 10, 22, MembershipKind::Left);
    let pending = c.revocations().to_vec();
    assert_eq!(apply(&mut c, 10, 22, MembershipKind::Left), MembershipApplied::Duplicate);
    apply(&mut c, 11, 23, MembershipKind::Alive);
    assert_eq!(c.revocations(), pending); assert!(c.acknowledge_revocation(&token));
    assert!(!c.acknowledge_revocation(&token)); assert!(c.revocations().is_empty());
    assert!(matches!(c.try_grant(&node(), 11, lease(1), Time::ZERO).unwrap_err().error, MembershipControlError::ReusedLease));
}

#[test]
fn release_returns_terminal_owner_and_prevents_cross_incarnation_identity_reuse() {
    let mut c = initialized(); let token = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
    let released = c.release(&token, Time::from_secs(1)).unwrap();
    assert!(released.is_released()); assert_eq!(released.obligation_id(), token.obligation_id());
    assert!(c.release(&token, Time::from_secs(1)).is_err());
    assert!(c.next_expiry().is_none()); assert!(c.revocations().is_empty());
    assert!(matches!(c.try_grant(&node(), 10, lease(1), Time::from_secs(1)).unwrap_err().error, MembershipControlError::ReusedLease));
    let regenerated = Lease::new(ObligationId::new_for_test(1, 2), RegionId::new_for_test(1, 1),
        TaskId::new_for_test(1, 1), Duration::from_secs(30), Time::from_secs(1));
    c.try_grant(&node(), 10, regenerated, Time::from_secs(1)).unwrap();
}

#[test]
fn deadline_wins_renewal_and_revocation_is_enqueued_once() {
    let mut c = initialized(); let token = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
    assert!(matches!(c.renew(&token, Duration::from_secs(30), Time::from_secs(30)), Err(MembershipControlError::UnknownLease)));
    assert_eq!(c.revocations().len(), 1); assert_eq!(c.revocations()[0].reason, MembershipRevocationReason::Expired);
    assert_eq!(c.expire(Time::from_secs(30)).unwrap(), 0);
    apply(&mut c, 10, 22, MembershipKind::Dead);
    assert_eq!(c.revocations().len(), 1);
}

#[test]
fn backward_clock_refuses_without_losing_a_lease_and_zero_renewal_does_not_expire_it() {
    let mut c = initialized(); let token = c.try_grant(&node(), 10, lease(1), Time::from_secs(2)).unwrap();
    assert!(matches!(c.expire(Time::from_secs(1)), Err(MembershipControlError::Clock)));
    assert!(matches!(c.release(&token, Time::from_secs(1)), Err(MembershipControlError::Clock)));
    assert!(c.renew(&token, Duration::ZERO, Time::from_secs(2)).is_err());
    assert_eq!(c.next_expiry(), Some(Time::from_secs(30))); assert_eq!(c.active_leases(&node()), 1);
}

#[test]
fn lifetime_capacity_does_not_evict_fences_or_consume_refused_lease_owners() {
    let mut c = initialized(); c.limits.max_lease_ids = 1;
    let token = c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
    c.release(&token, Time::ZERO).unwrap();
    let rejected = c.try_grant(&node(), 10, lease(2), Time::ZERO).unwrap_err();
    assert!(matches!(rejected.error, MembershipControlError::Capacity));
    assert!(rejected.lease.is_active(Time::ZERO));
    assert_eq!(c.seen_leases.len(), 1);
}

#[test]
fn forged_key_wrong_authority_wrong_epoch_and_unprovisioned_subject_never_mutate() {
    let mut c = controller();
    let update = MembershipUpdate { event: MembershipEvent { node: node(), incarnation: 10, kind: MembershipKind::Alive }, sequence: 21 };
    for (author, epoch, key) in [(authority(), 7, 43), (authority(), 8, 42), (NodeId::new("other"), 7, 42)] {
        let data = update.authenticated_bytes(&author, epoch, &AuthKey::from_seed(key)).unwrap();
        assert!(c.apply_authenticated(&data).is_err()); assert!(c.stamp(&node()).is_none());
    }
    let unknown = MembershipUpdate { event: MembershipEvent { node: NodeId::new("unknown"), ..update.event }, sequence: 21 };
    assert!(matches!(c.apply_authenticated(&unknown.authenticated_bytes(&authority(), 7, &AuthKey::from_seed(42)).unwrap()), Err(MembershipControlError::UnknownMember)));
}

#[test]
fn every_truncated_prefix_and_single_bit_mutation_is_refused() {
    let data = bytes(10, 21, MembershipKind::Alive);
    for length in 0..data.len() { assert!(controller().apply_authenticated(&data[..length]).is_err()); }
    for index in 0..data.len() {
        for bit in 0..8 {
            let mut bad = data.clone(); bad[index] ^= 1 << bit;
            assert!(controller().apply_authenticated(&bad).is_err(), "byte {index} bit {bit}");
        }
    }
    let mut sentinel = data; let end = sentinel.len(); sentinel[end-32..].fill(0);
    assert!(matches!(controller().apply_authenticated(&sentinel), Err(MembershipControlError::Authentication)));
}

#[test]
fn authenticated_noncanonical_tags_lengths_utf8_and_trailing_fields_are_rejected() {
    let data = bytes(10, 21, MembershipKind::Alive); let body = &data[..data.len()-32];
    let mut bad = body.to_vec(); *bad.last_mut().unwrap() = 4;
    assert!(matches!(controller().apply_authenticated(&sign_body(bad)), Err(MembershipControlError::Format)));
    let mut bad = body.to_vec(); bad.push(0);
    assert!(matches!(controller().apply_authenticated(&sign_body(bad)), Err(MembershipControlError::Format)));
    let mut bad = body.to_vec(); bad[13 + authority().as_str().len() + 8 + 1] = 255;
    assert!(matches!(controller().apply_authenticated(&sign_body(bad)), Err(MembershipControlError::Format)));
    let mut bad = body.to_vec(); bad[12] = 0;
    assert!(matches!(controller().apply_authenticated(&sign_body(bad)), Err(MembershipControlError::Format)));
}

#[test]
fn all_new_incarnation_states_revoke_old_leases_and_only_alive_admits_new_ones() {
    for kind in [MembershipKind::Alive, MembershipKind::Suspect, MembershipKind::Dead, MembershipKind::Left] {
        let mut c = initialized(); c.try_grant(&node(), 10, lease(1), Time::ZERO).unwrap();
        assert_eq!(apply(&mut c, 11, 22, kind), MembershipApplied::Applied { revoked: 1 });
        assert_eq!(c.try_grant(&node(), 11, lease(2), Time::ZERO).is_ok(), kind == MembershipKind::Alive);
    }
}

#[test]
fn exact_wire_bound_and_maximum_sequence_do_not_wrap() {
    let label = NodeId::new("a".repeat(255));
    let update = MembershipUpdate { event: MembershipEvent { node: label.clone(), incarnation: u64::MAX, kind: MembershipKind::Alive }, sequence: u64::MAX };
    let bytes = update.authenticated_bytes(&label, u64::MAX, &AuthKey::from_seed(42)).unwrap();
    assert_eq!(bytes.len(), MAX_MEMBERSHIP_UPDATE_BYTES);
    let mut c = MembershipLeaseController::new(label.clone(), u64::MAX, AuthKey::from_seed(42),
        vec![MembershipFloor { node: label.clone(), incarnation: 0, sequence: 0 }], limits()).unwrap();
    c.apply_authenticated(&bytes).unwrap();
    assert_eq!(c.apply_authenticated(&bytes).unwrap(), MembershipApplied::Duplicate);
    let mut invalid = bytes; invalid.push(0);
    assert!(matches!(c.apply_authenticated(&invalid), Err(MembershipControlError::Format)));
    assert_eq!(c.stamp(&label).unwrap().sequence, u64::MAX);
}

#[test]
fn allow_list_rejects_duplicates_empty_labels_and_count_overflow() {
    let floor = MembershipFloor { node: node(), incarnation: 0, sequence: 0 };
    assert!(MembershipLeaseController::new(authority(), 7, AuthKey::from_seed(42), vec![floor.clone(), floor.clone()], limits()).is_err());
    let bound = MembershipControllerLimits { max_members: 0, max_lease_ids: 0 };
    assert!(MembershipLeaseController::new(authority(), 7, AuthKey::from_seed(42), vec![floor], bound).is_err());
    assert!(MembershipLeaseController::new(NodeId::new(""), 7, AuthKey::from_seed(42), vec![], limits()).is_err());
}

#[test]
fn revoked_identity_cannot_be_reused_by_a_different_member() {
    let other = NodeId::new("other");
    let mut c = MembershipLeaseController::new(authority(), 7, AuthKey::from_seed(42),
        [node(), other.clone()].map(|node| MembershipFloor { node, incarnation: 0, sequence: 0 }).to_vec(), limits()).unwrap();
    for member in [node(), other.clone()] {
        let data = MembershipUpdate { event: MembershipEvent { node: member, incarnation: 1, kind: MembershipKind::Alive }, sequence: 1 }
            .authenticated_bytes(&authority(), 7, &AuthKey::from_seed(42)).unwrap();
        c.apply_authenticated(&data).unwrap();
    }
    let token = c.try_grant(&node(), 1, lease(1), Time::ZERO).unwrap();
    c.release(&token, Time::ZERO).unwrap();
    assert!(matches!(c.try_grant(&other, 1, lease(1), Time::ZERO).unwrap_err().error, MembershipControlError::ReusedLease));
}
