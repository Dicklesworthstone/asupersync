//! ATP-N8: adversarial security and Byzantine-behavior e2e scenarios.
//!
//! These tests stay deterministic and in-memory while exercising the receive
//! trust boundary: malicious mailbox relays, replayed receipts, quota abuse, and
//! equivocated negotiation responses must fail before data becomes trusted.

use asupersync::atp::inbox::{
    MailboxRetrievalReceipt, MailboxSecurityError, MailboxTamperEvidence, ObjectDigest,
};
use asupersync::atp::quota::{
    QuotaAllocation, QuotaBucket, QuotaError, QuotaLedger, QuotaLimit, QuotaUsage,
};
use asupersync::net::atp::protocol::{
    AtpFeature, CapabilityAction, CapabilityGrant, CapabilityGrantId, CapabilityScope, ClientHello,
    FeatureSet, PeerId, SessionContextKind, SessionNegotiator, SessionPolicy, SessionTraceId,
    TransferNonce,
};

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::new([byte; 32])
}

fn mailbox_evidence() -> MailboxTamperEvidence {
    MailboxTamperEvidence {
        manifest_root: digest(0x11),
        stored_object_digest: digest(0x22),
        manifest_epoch: 7,
        sequence: 41,
        content_length: 4096,
        expires_at_epoch_secs: 2_000,
        previous_record_digest: Some(digest(0x33)),
    }
}

fn mailbox_receipt() -> MailboxRetrievalReceipt {
    MailboxRetrievalReceipt {
        manifest_root: digest(0x11),
        stored_object_digest: digest(0x22),
        manifest_epoch: 7,
        sequence: 41,
        bytes_returned: 4096,
        retrieved_at_epoch_secs: 1_900,
    }
}

fn peer(label: &str) -> PeerId {
    PeerId::from_label(label)
}

fn write_grant(issuer: PeerId, subject: PeerId) -> CapabilityGrant {
    CapabilityGrant::new(
        CapabilityGrantId::from_label("direct-write"),
        issuer,
        subject,
        [CapabilityAction::Write],
        CapabilityScope::for_context(SessionContextKind::Direct),
    )
}

fn direct_write_hello(features: &[AtpFeature]) -> ClientHello {
    let alice = peer("alice");
    let bob = peer("bob");
    ClientHello::new(
        alice,
        bob,
        TransferNonce::from_seed("equivocation"),
        SessionContextKind::Direct,
        SessionTraceId::new(88),
    )
    .with_features(features)
    .with_requested_actions(&[CapabilityAction::Write])
    .with_grants(vec![write_grant(bob, alice)])
}

fn direct_write_policy(features: &[AtpFeature]) -> SessionPolicy {
    SessionPolicy::new(peer("bob"), 1_000)
        .with_supported_features(features)
        .with_required_features(&[AtpFeature::EncryptionPolicy])
        .with_required_actions(&[CapabilityAction::Write])
        .with_accepted_contexts(&[SessionContextKind::Direct])
}

#[test]
fn byzantine_tampering_manifest_substitution_is_rejected() {
    let evidence = mailbox_evidence();
    let mut receipt = mailbox_receipt();
    receipt.manifest_root = digest(0x44);

    let err = evidence
        .validate_retrieval(&receipt, None)
        .expect_err("manifest substitution must fail before trust");

    assert_eq!(
        err,
        MailboxSecurityError::DigestMismatch {
            field: "manifest_root"
        }
    );
    assert!(err.to_string().contains("manifest_root"));
}

#[test]
fn byzantine_replay_reuses_old_mailbox_sequence_is_rejected() {
    let evidence = mailbox_evidence();
    let receipt = mailbox_receipt();

    let err = evidence
        .validate_retrieval(&receipt, Some(41))
        .expect_err("replayed mailbox sequence must fail closed");

    assert_eq!(
        err,
        MailboxSecurityError::Replay {
            last_seen_sequence: Some(41),
            observed_sequence: 41
        }
    );
    assert!(err.to_string().contains("replay"));
}

#[test]
fn byzantine_dos_mailbox_quota_exhaustion_preserves_ledger() {
    let mut ledger = QuotaLedger::new();
    ledger.set_limit(QuotaBucket::Mailbox, QuotaLimit::new(16 * 1024, 2));

    assert!(
        ledger
            .reserve(
                "mailbox-a",
                QuotaAllocation::one_record(QuotaBucket::Mailbox, 4096),
            )
            .is_ok()
    );
    assert!(
        ledger
            .reserve(
                "mailbox-b",
                QuotaAllocation::one_record(QuotaBucket::Mailbox, 4096),
            )
            .is_ok()
    );

    let err = ledger
        .reserve(
            "mailbox-flood",
            QuotaAllocation::one_record(QuotaBucket::Mailbox, 1),
        )
        .expect_err("third mailbox record must trip the record quota");

    assert!(matches!(
        err,
        QuotaError::Exhausted {
            bucket: QuotaBucket::Mailbox,
            ..
        }
    ));
    assert_eq!(
        ledger.usage(QuotaBucket::Mailbox),
        QuotaUsage {
            bytes: 8192,
            records: 2
        }
    );
    assert_eq!(ledger.allocation_count(), 2);
}

#[test]
fn byzantine_equivocation_in_selected_features_is_rejected() {
    let features = [AtpFeature::EncryptionPolicy];
    let hello = direct_write_hello(&features);
    let mut policy = direct_write_policy(&features);
    let mut server = SessionNegotiator::server(peer("bob"));
    let (mut server_hello, _frame, _proof) = server
        .accept_client_hello(&hello, &mut policy)
        .expect("baseline server hello should satisfy policy");

    server_hello.selected_features =
        FeatureSet::from_slice(&[AtpFeature::EncryptionPolicy, AtpFeature::Relay]);

    let mut client = SessionNegotiator::client(peer("alice"));
    client
        .start_client_hello(&hello)
        .expect("client hello starts before byzantine server response");
    let err = client
        .finish_client(&hello, &server_hello, &policy)
        .expect_err("equivocated server feature set must fail closed");

    assert_eq!(err.code(), "feature_confusion");
    assert!(err.to_string().contains("feature"));
}
