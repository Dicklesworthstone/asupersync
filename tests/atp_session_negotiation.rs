//! End-to-end ATP session-negotiation contract tests.
//!
//! These tests exercise the public ATP protocol surface the daemon/CLI/SDK will
//! eventually drive over native QUIC streams. They intentionally stay in memory:
//! the contract is that bad peers, replayed nonces, expired grants, and feature
//! confusion are rejected before any object writer, relay, or mailbox can store
//! bytes.

use asupersync::atp::path::PathCandidateId;
use asupersync::net::atp::protocol::{
    AtpFeature, CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, ClientHello,
    FeatureSet, PeerId, SessionContextKind, SessionNegotiator, SessionPolicy, SessionTraceId,
    TransferNonce,
};

fn peer(label: &str) -> PeerId {
    PeerId::from_label(label)
}

fn grant(
    issuer: PeerId,
    subject: PeerId,
    action: CapabilityAction,
    context: SessionContextKind,
) -> CapabilityGrant {
    CapabilityGrant::new(
        CapabilityGrantId::from_label(action.code()),
        issuer,
        subject,
        [action],
        CapabilityScope::for_context(context),
    )
}

fn policy(
    bob: PeerId,
    context: SessionContextKind,
    action: CapabilityAction,
    features: &[AtpFeature],
) -> SessionPolicy {
    SessionPolicy::new(bob, 1_000)
        .with_supported_features(features)
        .with_required_features(&[AtpFeature::EncryptionPolicy])
        .with_required_actions(&[action])
        .with_accepted_contexts(&[context])
}

fn hello(
    context: SessionContextKind,
    action: CapabilityAction,
    features: &[AtpFeature],
) -> ClientHello {
    let alice = peer("alice");
    let bob = peer("bob");
    ClientHello::new(
        alice,
        bob,
        TransferNonce::from_seed(context.code()),
        context,
        SessionTraceId::new(9001),
    )
    .with_features(features)
    .with_requested_actions(&[action])
    .with_grants(vec![grant(bob, alice, action, context)])
}

#[test]
fn e2e_first_contact_pairing_logs_transcript_proof() {
    let features = [
        AtpFeature::EncryptionPolicy,
        AtpFeature::ProofBundles,
        AtpFeature::Resume,
    ];
    let hello = hello(
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    );
    let mut policy = policy(
        peer("bob"),
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    );
    let mut client = SessionNegotiator::client(peer("alice"));
    let mut server = SessionNegotiator::server(peer("bob"));

    client.start_client_hello(&hello).unwrap();
    let (server_hello, _server_frame, server_proof) =
        server.accept_client_hello(&hello, &mut policy).unwrap();
    let (session, client_proof) = client
        .finish_client(&hello, &server_hello, &policy)
        .unwrap();

    assert_eq!(session.context, SessionContextKind::Direct);
    assert_eq!(client_proof.session_id, server_proof.session_id);
    assert_eq!(client_proof.rejected_reason, None);
    assert!(
        client_proof
            .selected_features
            .contains(&"encryption_policy")
    );
    assert!(!client_proof.transcript_hash.is_empty());
}

#[test]
fn e2e_expired_and_revoked_grants_fail_before_storage() {
    let features = [AtpFeature::EncryptionPolicy];
    let alice = peer("alice");
    let bob = peer("bob");
    let base = ClientHello::new(
        alice,
        bob,
        TransferNonce::from_seed("bad-grant"),
        SessionContextKind::Direct,
        SessionTraceId::new(12),
    )
    .with_features(&features)
    .with_requested_actions(&[CapabilityAction::Write]);
    let mut policy = policy(
        bob,
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    );

    let expired = grant(
        bob,
        alice,
        CapabilityAction::Write,
        SessionContextKind::Direct,
    )
    .with_validity(0, 500);
    let mut server = SessionNegotiator::server(bob);
    let expired_error = server
        .accept_client_hello(&base.clone().with_grants(vec![expired]), &mut policy)
        .unwrap_err();
    assert_eq!(expired_error.code(), "missing_grant_action");

    let revoked = grant(
        bob,
        alice,
        CapabilityAction::Write,
        SessionContextKind::Direct,
    )
    .revoked();
    let mut server = SessionNegotiator::server(bob);
    let revoked_error = server
        .accept_client_hello(&base.with_grants(vec![revoked]), &mut policy)
        .unwrap_err();
    assert_eq!(revoked_error.code(), "missing_grant_action");
}

#[test]
fn e2e_relay_mailbox_swarm_and_downgrade_paths_are_explicit() {
    for (context, action, context_feature) in [
        (
            SessionContextKind::Relay,
            CapabilityAction::Relay,
            AtpFeature::Relay,
        ),
        (
            SessionContextKind::Mailbox,
            CapabilityAction::Mailbox,
            AtpFeature::Mailbox,
        ),
        (
            SessionContextKind::Swarm,
            CapabilityAction::Seed,
            AtpFeature::Swarm,
        ),
    ] {
        let offered = [
            AtpFeature::EncryptionPolicy,
            context_feature,
            AtpFeature::Repair,
            AtpFeature::Compression,
            AtpFeature::WebTransportAdapter,
        ];
        let supported = [
            AtpFeature::EncryptionPolicy,
            context_feature,
            AtpFeature::Repair,
        ];
        let hello = hello(context, action, &offered);
        let mut policy = policy(peer("bob"), context, action, &supported);
        let mut server = SessionNegotiator::server(peer("bob"));

        let (server_hello, _frame, _proof) =
            server.accept_client_hello(&hello, &mut policy).unwrap();

        assert!(server_hello.selected_features.contains(context_feature));
        assert!(server_hello.selected_features.contains(AtpFeature::Repair));
        assert!(
            !server_hello
                .selected_features
                .contains(AtpFeature::Compression)
        );
        assert!(
            server_hello
                .downgrade_warnings
                .iter()
                .any(|warning| warning.feature == AtpFeature::Compression)
        );
    }
}

#[test]
fn e2e_replay_path_and_object_escalation_are_fail_closed() {
    let alice = peer("alice");
    let bob = peer("bob");
    let path = PathCandidateId::new(1);
    let root = [3u8; 32];
    let scoped_grant = CapabilityGrant::new(
        CapabilityGrantId::from_label("scoped"),
        bob,
        alice,
        [CapabilityAction::Write],
        CapabilityScope::for_context(SessionContextKind::Direct)
            .with_path_id(path)
            .with_manifest_root(root),
    );
    let features = [AtpFeature::EncryptionPolicy];
    let mut policy = policy(
        bob,
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    )
    .require_manifest_binding();

    let replay_nonce = TransferNonce::from_seed("replay");
    let replay_hello = ClientHello::new(
        alice,
        bob,
        replay_nonce,
        SessionContextKind::Direct,
        SessionTraceId::new(1),
    )
    .with_features(&features)
    .with_requested_actions(&[CapabilityAction::Write])
    .with_path_id(path)
    .with_manifest_root(root)
    .with_grants(vec![scoped_grant.clone()]);
    let mut replay_policy = policy.clone().with_seen_nonce(replay_nonce);
    let mut server = SessionNegotiator::server(bob);
    let replay_error = server
        .accept_client_hello(&replay_hello, &mut replay_policy)
        .unwrap_err();
    assert_eq!(replay_error.code(), "replayed_nonce");

    let escalation = ClientHello::new(
        alice,
        bob,
        TransferNonce::from_seed("scope-escalation"),
        SessionContextKind::Direct,
        SessionTraceId::new(2),
    )
    .with_features(&features)
    .with_requested_actions(&[CapabilityAction::Write])
    .with_path_id(PathCandidateId::new(99))
    .with_manifest_root([4u8; 32])
    .with_grants(vec![scoped_grant]);
    let mut server = SessionNegotiator::server(bob);
    let scope_error = server
        .accept_client_hello(&escalation, &mut policy)
        .unwrap_err();
    assert_eq!(scope_error.code(), "missing_grant_action");
}

#[test]
fn e2e_successful_accept_updates_replay_cache() {
    let features = [AtpFeature::EncryptionPolicy];
    let hello = hello(
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    );
    let mut policy = policy(
        peer("bob"),
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    );
    let mut server = SessionNegotiator::server(peer("bob"));

    server.accept_client_hello(&hello, &mut policy).unwrap();

    assert!(policy.seen_nonces.contains(&hello.nonce));

    let mut replay_server = SessionNegotiator::server(peer("bob"));
    let replay_error = replay_server
        .accept_client_hello(&hello, &mut policy)
        .unwrap_err();

    assert_eq!(replay_error.code(), "replayed_nonce");
}

#[test]
fn e2e_feature_confusion_is_rejected_on_client_finish() {
    let features = [AtpFeature::EncryptionPolicy];
    let hello = hello(
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    );
    let mut policy = policy(
        peer("bob"),
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &features,
    );
    let mut server = SessionNegotiator::server(peer("bob"));
    let (mut server_hello, _frame, _proof) =
        server.accept_client_hello(&hello, &mut policy).unwrap();
    server_hello.selected_features =
        FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy, AtpFeature::Compression]);

    let mut client = SessionNegotiator::client(peer("alice"));
    client.start_client_hello(&hello).unwrap();
    let error = client
        .finish_client(&hello, &server_hello, &policy)
        .unwrap_err();

    assert_eq!(error.code(), "feature_confusion");
}
