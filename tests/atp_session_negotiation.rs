//! End-to-end ATP session-negotiation contract tests.
//!
//! These tests exercise the public ATP protocol surface the daemon/CLI/SDK will
//! eventually drive over native QUIC streams. The policy cases stay in memory;
//! the TLS-gated extension cases use two real native-runtime child processes.
//! Historical extension order is an explicit wire fixture, not a released
//! historical binary or a claim about the daemon's transfer workflow.

use asupersync::atp::path::PathCandidateId;
use asupersync::net::atp::protocol::{
    ATP_ADAPTER_PARITY_MATRIX, AtpAdapterKind, AtpFeature, CapabilityAction, CapabilityGrant,
    CapabilityGrantId, CapabilityScope, ClientHello, FeatureSet, PeerId, SessionContextKind,
    SessionNegotiator, SessionPolicy, SessionTraceId, TransferNonce,
};
use std::collections::BTreeSet;

fn peer(label: &str) -> PeerId {
    PeerId::from_label(label)
}

fn relay_peer() -> PeerId {
    peer("relay")
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
        let hello = if context == SessionContextKind::Relay {
            hello.with_relay_peer(relay_peer())
        } else {
            hello
        };
        let policy = policy(peer("bob"), context, action, &supported);
        let mut policy = if context == SessionContextKind::Relay {
            policy.with_trusted_relays(&[relay_peer()])
        } else {
            policy
        };
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
fn e2e_adapter_parity_matrix_and_downgrade_reasons_are_explicit() {
    let adapters = ATP_ADAPTER_PARITY_MATRIX
        .iter()
        .map(|row| row.adapter)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        adapters,
        BTreeSet::from([
            AtpAdapterKind::NativeQuic,
            AtpAdapterKind::H3,
            AtpAdapterKind::WebTransport,
            AtpAdapterKind::MasqueConnectUdp,
            AtpAdapterKind::TcpTls443Fallback,
        ])
    );

    for row in ATP_ADAPTER_PARITY_MATRIX {
        assert!(
            !row.supported_features.is_empty(),
            "{} must declare supported features",
            row.adapter.code()
        );
        assert!(
            !row.unsupported_features.is_empty(),
            "{} must declare explicit downgrade features",
            row.adapter.code()
        );
        assert!(
            !row.adapter_downgrade_reason.trim().is_empty(),
            "{} must expose a stable downgrade reason",
            row.adapter.code()
        );
        assert!(
            row.proof_summary_label.contains(row.adapter.code())
                || row.adapter == AtpAdapterKind::NativeQuic,
            "{} proof summary must name the adapter",
            row.adapter.code()
        );
        for feature in row.supported_features {
            assert!(
                !row.downgrades(*feature),
                "{} must not both support and downgrade {}",
                row.adapter.code(),
                feature.code()
            );
        }
        if let Some(feature) = row.adapter.negotiated_feature() {
            assert!(
                row.supports(feature),
                "{} must support its advertised negotiation feature",
                row.adapter.code()
            );
        }
    }

    let native = ATP_ADAPTER_PARITY_MATRIX
        .iter()
        .find(|row| row.adapter == AtpAdapterKind::NativeQuic)
        .expect("native QUIC row");
    assert!(native.supports(AtpFeature::Datagrams));
    assert!(native.supports(AtpFeature::Swarm));
    assert!(native.supports(AtpFeature::ProofBundles));

    let tcp_tls = ATP_ADAPTER_PARITY_MATRIX
        .iter()
        .find(|row| row.adapter == AtpAdapterKind::TcpTls443Fallback)
        .expect("TCP/TLS fallback row");
    assert!(tcp_tls.downgrades(AtpFeature::Datagrams));
    assert_eq!(
        tcp_tls.adapter_downgrade_reason,
        "tcp_tls_443_fallback_lacks_datagrams"
    );

    let hello = hello(
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &[
            AtpFeature::EncryptionPolicy,
            AtpFeature::Repair,
            AtpFeature::H3Adapter,
            AtpFeature::WebTransportAdapter,
            AtpFeature::MasqueAdapter,
            AtpFeature::Datagrams,
        ],
    );
    let mut policy = policy(
        peer("bob"),
        SessionContextKind::Direct,
        CapabilityAction::Write,
        &[AtpFeature::EncryptionPolicy, AtpFeature::Repair],
    );
    let mut server = SessionNegotiator::server(peer("bob"));

    let (server_hello, _frame, _proof) = server.accept_client_hello(&hello, &mut policy).unwrap();
    let warnings = server_hello
        .downgrade_warnings
        .iter()
        .map(|warning| (warning.feature, warning.reason_code))
        .collect::<BTreeSet<_>>();

    assert!(warnings.contains(&(AtpFeature::H3Adapter, "h3_adapter_not_supported_by_peer")));
    assert!(warnings.contains(&(
        AtpFeature::WebTransportAdapter,
        "webtransport_adapter_not_supported_by_peer"
    )));
    assert!(warnings.contains(&(
        AtpFeature::MasqueAdapter,
        "masque_adapter_not_supported_by_peer"
    )));
    assert!(warnings.contains(&(
        AtpFeature::Datagrams,
        "datagrams_not_supported_by_selected_adapter"
    )));
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

#[cfg(feature = "tls")]
mod extension_wire {
    use super::{grant, peer, policy};
    use asupersync::bytes::BytesMut;
    use asupersync::codec::Decoder;
    use asupersync::io::{AsyncReadExt, AsyncWriteExt};
    use asupersync::net::atp::h3::codec::H3FrameCodec;
    use asupersync::net::atp::protocol::{
        AtpFeature, AtpFrameCodec, CapabilityAction, ClientHello, Frame, FrameError, FrameType,
        MAX_EXTENSION_COUNT, MAX_EXTENSION_SIZE, MAX_FRAME_SIZE, MAX_HEADER_SIZE, ProtocolVersion,
        ServerHello, SessionContextKind, SessionNegotiationState, SessionNegotiator,
        SessionTraceId, TranscriptHasher, TransferNonce, VarInt,
    };
    use asupersync::net::{TcpListener, TcpStream};
    use asupersync::runtime::RuntimeBuilder;
    use asupersync::tls::{TlsAcceptor, TlsConnector, TlsStream};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
    use rustls::time_provider::TimeProvider;
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const BEAD: &str = "asupersync-bi2462.43";
    const CHILD_TEST: &str = "extension_wire::native_extension_peer";
    const ALPN: &[u8] = b"atp-extension-proof/1";
    // Inside the checked-in certificate's validity interval. This replaces
    // only the verification clock; WebPKI still checks chain, usage, signature,
    // hostname and validity, and the server requires a client certificate.
    const CERTIFICATE_TEST_TIME: u64 = 1_780_272_000;

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn frame(role: &str, index: usize) -> Frame {
        let (kind, payload) = match index {
            0 => (
                FrameType::Control,
                format!("extension-proof/v1:{role}").into_bytes(),
            ),
            1 => (
                FrameType::Data,
                (0..16_387).map(|n| (n % 251) as u8).collect(),
            ),
            _ => (
                FrameType::Proof,
                Sha256::digest(frame(role, 1).payload()).to_vec(),
            ),
        };
        extensions(
            Frame::new(ProtocolVersion::CURRENT, kind, payload).unwrap(),
            role,
        )
    }

    fn extensions(mut frame: Frame, role: &str) -> Frame {
        frame
            .header
            .extensions
            .insert(u16::MAX, role.as_bytes().to_vec());
        frame
            .header
            .extensions
            .insert(64, b"opaque-extension".to_vec());
        frame.header.extensions.insert(0, Vec::new());
        frame
    }

    fn outgoing(frame: &Frame, historical: bool) -> Vec<u8> {
        if historical {
            legacy_wire(frame)
        } else {
            frame.to_wire_bytes().unwrap()
        }
    }

    fn received(wire: &[u8], historical: bool) -> Frame {
        let frame = decode_fragmented(wire);
        assert_eq!(
            wire,
            if historical {
                legacy_wire(&frame)
            } else {
                canonical_fixture(&frame)
            },
            "peer must exercise its declared wire order"
        );
        frame
    }

    fn varint(wire: &mut BytesMut, value: u64) {
        VarInt::new(value).unwrap().encode(wire).unwrap();
    }

    fn raw_frame(frame: &Frame, entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut wire = BytesMut::new();
        for value in [
            u64::from(frame.version().0),
            frame.frame_type() as u64,
            frame.payload().len() as u64,
            entries.len() as u64,
        ] {
            varint(&mut wire, value);
        }
        for (id, value) in entries {
            varint(&mut wire, u64::from(*id));
            varint(&mut wire, value.len() as u64);
            wire.extend_from_slice(value);
        }
        wire.extend_from_slice(frame.payload());
        wire.to_vec()
    }

    fn legacy_wire(frame: &Frame) -> Vec<u8> {
        let entries = [u16::MAX, 64, 0].map(|id| (id, frame.header.extensions[&id].as_slice()));
        raw_frame(frame, &entries)
    }

    fn canonical_fixture(frame: &Frame) -> Vec<u8> {
        let entries = [0, 64, u16::MAX].map(|id| (id, frame.header.extensions[&id].as_slice()));
        raw_frame(frame, &entries)
    }

    fn canonical_oracle(observed: &[u8], expected: &[u8]) -> Result<(), &'static str> {
        if observed == expected {
            Ok(())
        } else {
            Err("noncanonical_extension_order")
        }
    }

    fn duplicate_oracle(result: Result<Option<Frame>, FrameError>) -> Result<(), &'static str> {
        match result {
            Err(FrameError::InvalidFormat(message))
                if message.starts_with("Duplicate extension ID ") =>
            {
                Ok(())
            }
            Ok(_) => Err("duplicate_extension_admitted"),
            Err(_) => Err("incorrect_duplicate_refusal"),
        }
    }

    fn malformed() -> Vec<(&'static str, Vec<u8>)> {
        let frame = Frame::new(ProtocolVersion::CURRENT, FrameType::Data, b"p".to_vec()).unwrap();
        let mut cases = vec![
            (
                "duplicate",
                raw_frame(&frame, &[(64, b"same"), (64, b"same")]),
            ),
            (
                "duplicate",
                raw_frame(&frame, &[(64, b"first"), (64, b"changed")]),
            ),
        ];
        for (code, count, length) in [
            ("extension_limit", 1, MAX_EXTENSION_SIZE + 1),
            ("extension_limit", MAX_EXTENSION_COUNT + 1, 0),
        ] {
            let mut wire = BytesMut::new();
            for value in [0, FrameType::Data as u64, 1, count, 64, length] {
                varint(&mut wire, value);
            }
            cases.push((code, wire.to_vec()));
        }
        let value = vec![7; MAX_EXTENSION_SIZE as usize];
        let entries: Vec<_> = (0..8).map(|id| (id, value.as_slice())).collect();
        let oversized = raw_frame(&frame, &entries);
        assert!(oversized.len() > MAX_HEADER_SIZE as usize);
        cases.push(("header_limit", oversized));
        cases
    }

    fn rejection(error: &FrameError) -> &'static str {
        match error {
            FrameError::InvalidFormat(message)
                if message.starts_with("Duplicate extension ID ") =>
            {
                "duplicate"
            }
            FrameError::ExtensionTooLarge { .. } => "extension_limit",
            FrameError::FrameTooLarge { .. } => "header_limit",
            other => panic!("unexpected refusal: {other:?}"),
        }
    }

    fn decode_fragmented(wire: &[u8]) -> Frame {
        let mut codec = AtpFrameCodec::new();
        let mut pending = BytesMut::new();
        let mut decoded = None;
        for chunk in wire.chunks(7) {
            assert!(
                decoded.is_none(),
                "frame completed before the supplied wire ended"
            );
            pending.extend_from_slice(chunk);
            decoded = codec.decode(&mut pending).unwrap();
        }
        assert!(pending.is_empty());
        decoded.expect("nonempty wire must contain a complete frame")
    }

    #[test]
    fn extension_incremental_refusals_and_h3_adapter() {
        let fixture = frame("sender", 0);
        let canonical = canonical_fixture(&fixture);
        let legacy = legacy_wire(&fixture);
        assert_eq!(
            canonical_oracle(&fixture.to_wire_bytes().unwrap(), &canonical),
            Ok(())
        );
        assert_eq!(
            canonical_oracle(&legacy, &canonical),
            Err("noncanonical_extension_order")
        );
        for wire in [&canonical, &legacy] {
            for split in 0..wire.len() {
                let mut codec = AtpFrameCodec::new();
                let mut pending = BytesMut::from(&wire[..split]);
                assert!(
                    codec.decode(&mut pending).unwrap().is_none(),
                    "split={split}"
                );
                pending.extend_from_slice(&wire[split..]);
                assert_eq!(codec.decode(&mut pending).unwrap().unwrap(), fixture);
                assert!(pending.is_empty());
            }
        }
        let h3 = H3FrameCodec::new();
        let envelope = h3.encode_atp_frame(&fixture).unwrap();
        assert_eq!(h3.decode_atp_frame(&envelope).unwrap(), fixture);
        let mut historical_envelope = envelope[..5].to_vec();
        historical_envelope.extend_from_slice(&legacy);
        assert_eq!(h3.decode_atp_frame(&historical_envelope).unwrap(), fixture);
        for split in 0..envelope.len() {
            assert!(h3.decode_atp_frame(&envelope[..split]).is_err());
        }
        let cases = malformed();
        for (expected, wire) in &cases {
            let mut h3_wire = vec![2]; // WebTransport Data frame envelope.
            h3_wire.extend_from_slice(&u32::try_from(wire.len()).unwrap().to_be_bytes());
            h3_wire.extend_from_slice(wire);
            assert!(
                h3.decode_atp_frame(&h3_wire).is_err(),
                "H3 must reach the same {expected} refusal"
            );
            // Every split for short malformed headers; byte boundaries around
            // the bounded large-header limit without a quadratic 32KiB sweep.
            let splits: Vec<_> = if wire.len() < 128 {
                (0..=wire.len()).collect()
            } else {
                vec![0, 1, 4, 4095, 4096, 32767, 32768, wire.len()]
            };
            for split in splits {
                let mut codec = AtpFrameCodec::new();
                let mut pending = BytesMut::from(&wire[..split]);
                let mut available = split;
                match codec.decode(&mut pending) {
                    Err(error) => assert_eq!(rejection(&error), *expected),
                    Ok(None) => {
                        assert_eq!(pending.as_ref(), &wire[..split]);
                        pending.extend_from_slice(&wire[split..]);
                        available = wire.len();
                        assert_eq!(
                            rejection(&codec.decode(&mut pending).unwrap_err()),
                            *expected
                        );
                    }
                    Ok(Some(_)) => {
                        panic!("malformed input was admitted: {expected}, split={split}")
                    }
                }
                assert_eq!(
                    pending.as_ref(),
                    &wire[..available],
                    "refusal consumed source"
                );
                let mut recovery = BytesMut::from(canonical.as_slice());
                assert_eq!(codec.decode(&mut recovery).unwrap().unwrap(), fixture);
            }
        }
        // Deliberately reproduce last-value-wins in a separate fixture. Its
        // accepted result fails the duplicate-refusal oracle; this is never the
        // production decoder or a replacement for exercising its error path.
        let mut overwritten =
            Frame::new(ProtocolVersion::CURRENT, FrameType::Data, b"p".to_vec()).unwrap();
        for value in [b"same", b"same"] {
            overwritten.header.extensions.insert(64, value.to_vec());
        }
        let mut mutant = BytesMut::from(overwritten.to_wire_bytes().unwrap().as_slice());
        assert_eq!(
            duplicate_oracle(AtpFrameCodec::new().decode(&mut mutant)),
            Err("duplicate_extension_admitted")
        );
        assert_eq!(
            duplicate_oracle(
                AtpFrameCodec::new().decode(&mut BytesMut::from(cases[0].1.as_slice()))
            ),
            Ok(())
        );
        println!(
            "{}",
            json!({"bead_id": BEAD, "scenario_id": "extension_incremental_refusals_and_h3_adapter", "malformed_cases": cases.len(), "historical_encoder": "explicit_unsorted_fixture", "h3_scope": "codec_only_no_live_h3"})
        );
    }

    #[derive(Debug)]
    struct CertificateClock;

    impl TimeProvider for CertificateClock {
        fn current_time(&self) -> Option<UnixTime> {
            Some(UnixTime::since_unix_epoch(Duration::from_secs(
                CERTIFICATE_TEST_TIME,
            )))
        }
    }

    fn certificate() -> CertificateDer<'static> {
        rustls_pemfile::certs(&mut &include_bytes!("fixtures/tls/server.crt")[..])
            .next()
            .unwrap()
            .unwrap()
    }

    fn private_key() -> PrivateKeyDer<'static> {
        rustls_pemfile::private_key(&mut &include_bytes!("fixtures/tls/server.key")[..])
            .unwrap()
            .unwrap()
    }

    fn tls_configs() -> (TlsConnector, TlsAcceptor) {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots.clone()),
            Arc::clone(&provider),
        )
        .build()
        .unwrap();
        let mut server = rustls::ServerConfig::builder_with_details(
            Arc::clone(&provider),
            Arc::new(CertificateClock),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![certificate()], private_key())
        .unwrap();
        let mut client =
            rustls::ClientConfig::builder_with_details(provider, Arc::new(CertificateClock))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(vec![certificate()], private_key())
                .unwrap();
        client.alpn_protocols = vec![ALPN.to_vec()];
        server.alpn_protocols = vec![ALPN.to_vec()];
        (TlsConnector::new(client), TlsAcceptor::new(server))
    }

    async fn send_blob(stream: &mut TlsStream<TcpStream>, wire: &[u8]) {
        // The test peer envelope bounds malformed cases independently of the
        // ATP parser. The enclosed bytes are the actual ATP wire under test.
        stream
            .write_all(&u32::try_from(wire.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        for part in wire.chunks(97) {
            stream.write_all(part).await.unwrap();
        }
        stream.flush().await.unwrap();
    }

    async fn recv_blob(stream: &mut TlsStream<TcpStream>) -> Vec<u8> {
        let mut length = [0; 4];
        stream.read_exact(&mut length).await.unwrap();
        let length = u32::from_be_bytes(length) as usize;
        assert!(
            length <= MAX_FRAME_SIZE as usize,
            "test envelope exceeded bound"
        );
        let mut wire = vec![0; length];
        for part in wire.chunks_mut(31) {
            stream.read_exact(part).await.unwrap();
        }
        wire
    }

    fn write_json(path: &Path, value: &Value) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        writeln!(file, "{value}").unwrap();
    }

    async fn exchange(role: &str, scenario: &str, root: &Path) -> Value {
        let (connector, acceptor) = tls_configs();
        let mut stream = if role == "receiver" {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            write_json(
                &root.join("ready.json"),
                &json!({"address": listener.local_addr().unwrap().to_string()}),
            );
            let (tcp, _) = listener.accept().await.unwrap();
            acceptor
                .accept(tcp)
                .await
                .expect("mutually authenticated server handshake")
        } else {
            let ready: Value =
                serde_json::from_slice(&std::fs::read(root.join("ready.json")).unwrap()).unwrap();
            let address: std::net::SocketAddr = ready["address"].as_str().unwrap().parse().unwrap();
            let tcp = TcpStream::connect(address).await.unwrap();
            connector
                .connect("localhost", tcp)
                .await
                .expect("chain/hostname/time verified client handshake")
        };
        assert_eq!(stream.alpn_protocol(), Some(ALPN));
        assert_eq!(
            stream.protocol_version(),
            Some(rustls::ProtocolVersion::TLSv1_3)
        );
        let peer_certificate = stream
            .peer_leaf_certificate_der()
            .expect("mutual authentication certificate");
        assert_eq!(peer_certificate.as_slice(), certificate().as_ref());
        println!(
            "{}",
            json!({"bead_id": BEAD, "scenario_id": scenario, "role": role,
            "stage": "mutual_tls_established", "pid": std::process::id(),
            "peer_certificate_sha256": digest(&peer_certificate), "certificate_test_clock_unix": CERTIFICATE_TEST_TIME})
        );
        let historical = (scenario == "historical_sender") == (role == "sender");
        let mut transcript = TranscriptHasher::new();
        let supported = [AtpFeature::EncryptionPolicy, AtpFeature::ProofBundles];
        let mut session_policy = policy(
            peer("receiver"),
            SessionContextKind::Direct,
            CapabilityAction::Write,
            &supported,
        )
        .require_manifest_binding();
        let manifest_root: [u8; 32] = Sha256::digest(frame("sender", 1).payload()).into();
        // Received issuer fields are assertions, not signed authority. The
        // acceptor independently provisions this exact grant and compares the
        // decoded value before passing the received hello to policy evaluation.
        let pinned_grant = grant(
            peer("receiver"),
            peer("sender"),
            CapabilityAction::Write,
            SessionContextKind::Direct,
        );
        // This test's two roles use locally provisioned ATP identities and one
        // shared TLS fixture certificate. It is not a certificate-to-ATP-identity
        // enrollment protocol. Each role checks its configured remote identity.
        let (
            client_frame,
            server_frame,
            server_hello,
            proof,
            state,
            client_hash,
            local_wire,
            incoming,
        ) = if role == "sender" {
            let hello = ClientHello::new(
                peer("sender"),
                peer("receiver"),
                TransferNonce::from_seed("native-extension-negotiation"),
                SessionContextKind::Direct,
                SessionTraceId::new(4301),
            )
            .with_features(&[
                AtpFeature::EncryptionPolicy,
                AtpFeature::ProofBundles,
                AtpFeature::Compression,
            ])
            .with_manifest_root(manifest_root)
            .with_requested_actions(&[CapabilityAction::Write])
            .with_grants(vec![grant(
                peer("receiver"),
                peer("sender"),
                CapabilityAction::Write,
                SessionContextKind::Direct,
            )]);
            let mut negotiator = SessionNegotiator::client(peer("sender"));
            let client_frame = extensions(negotiator.start_client_hello(&hello).unwrap(), role);
            assert_eq!(
                negotiator.state(),
                &SessionNegotiationState::ClientHelloSent
            );
            let local_wire = outgoing(&client_frame, historical);
            send_blob(&mut stream, &local_wire).await;
            let incoming = recv_blob(&mut stream).await;
            let server_frame = received(&incoming, !historical);
            let server_hello =
                ServerHello::from_frame(&server_frame).expect("decode actual received ack");
            let (session, proof) = negotiator
                .finish_client(&hello, &server_hello, &session_policy)
                .expect("received server ack establishes client session");
            assert_eq!(
                negotiator.state(),
                &SessionNegotiationState::Established(session.session_id)
            );
            assert_eq!(session.local_peer, peer("sender"));
            assert_eq!(session.remote_peer, peer("receiver"));
            assert_eq!(session.nonce, hello.nonce);
            assert_eq!(session.context, SessionContextKind::Direct);
            (
                client_frame,
                server_frame,
                server_hello,
                proof,
                "Established",
                Some(session.transcript_hash),
                local_wire,
                incoming,
            )
        } else {
            let incoming = recv_blob(&mut stream).await;
            let client_frame = received(&incoming, !historical);
            let hello =
                ClientHello::from_frame(&client_frame).expect("decode actual received hello");
            assert_eq!(hello.initiator, peer("sender"));
            assert_eq!(hello.responder, peer("receiver"));
            assert_eq!(hello.manifest_root, Some(manifest_root));
            assert_eq!(
                hello.grants,
                vec![pinned_grant.clone()],
                "received grant must match the server's locally provisioned authority"
            );
            let mut negotiator = SessionNegotiator::server(peer("receiver"));
            let (server_hello, server_frame, proof) = negotiator
                .accept_client_hello(&hello, &mut session_policy)
                .expect("received client hello passes real capability policy");
            assert_eq!(
                negotiator.state(),
                &SessionNegotiationState::ServerHelloSent
            );
            assert!(session_policy.seen_nonces.contains(&hello.nonce));
            let server_frame = extensions(server_frame, role);
            let local_wire = outgoing(&server_frame, historical);
            send_blob(&mut stream, &local_wire).await;
            (
                client_frame,
                server_frame,
                server_hello,
                proof,
                "ServerHelloSent",
                None,
                local_wire,
                incoming,
            )
        };
        assert_eq!(
            server_hello.selected_features,
            supported.into_iter().collect()
        );
        assert_eq!(
            server_hello.accepted_grants,
            vec![super::CapabilityGrantId::from_label("write")]
        );
        assert_eq!(server_hello.downgrade_warnings.len(), 1);
        assert_eq!(
            server_hello.downgrade_warnings[0].feature,
            AtpFeature::Compression
        );
        assert_eq!(proof.rejected_reason, None);
        let mut policy_transcript = TranscriptHasher::new();
        for actual_frame in [&client_frame, &server_frame] {
            transcript.update_frame(actual_frame);
            // SessionNegotiator's existing typed transcript covers the hello
            // payloads. Preserve that contract and separately hash extensions.
            let mut typed_frame = actual_frame.clone();
            typed_frame.header.extensions.clear();
            policy_transcript.update_frame(&typed_frame);
        }
        let policy_hash = policy_transcript.finalize();
        assert_eq!(proof.transcript_hash, policy_hash.to_hex()[..24]);
        if let Some(client_hash) = client_hash {
            assert_eq!(client_hash, policy_hash);
        }
        if role == "sender" {
            send_blob(&mut stream, policy_hash.as_bytes()).await;
            assert_eq!(recv_blob(&mut stream).await, policy_hash.as_bytes());
        } else {
            assert_eq!(recv_blob(&mut stream).await, policy_hash.as_bytes());
            send_blob(&mut stream, policy_hash.as_bytes()).await;
        }
        let negotiation = json!({"state": state, "session_id": hex::encode(server_hello.session_id.as_bytes()),
            "local_peer": proof.local_peer, "remote_peer": proof.remote_peer,
            "selected_features": proof.selected_features, "accepted_grants": server_hello.accepted_grants.len(),
            "context": server_hello.context.code(), "trace_id": server_hello.trace_id.get(),
            "policy_transcript_sha256": policy_hash.to_hex(), "manifest_sha256": hex::encode(manifest_root),
            "incoming_handshake_wire_sha256": digest(&incoming),
            "grant_admission": "exact_server_local_grant_pin_no_signed_grant_claim",
            "configured_grant_sha256": digest(&serde_json::to_vec(&pinned_grant).unwrap()),
            "identity_scope": "configured_atp_role_ids_shared_mutual_tls_fixture_certificate"});
        println!(
            "{}",
            json!({"bead_id": BEAD, "scenario_id": scenario, "role": role,
            "stage": "session_negotiated", "negotiation": negotiation})
        );
        let mut max_wire_bytes = local_wire.len().max(incoming.len());
        let mut wire_hashes = vec![json!({"index": 0, "sent": digest(&local_wire),
            "received": digest(&incoming), "payload_sha256": digest(decode_fragmented(&incoming).payload())})];
        let mut received_payload_hash = None;
        for index in 1..3 {
            let local = frame(role, index);
            let local_wire = if historical {
                legacy_wire(&local)
            } else {
                local.to_wire_bytes().unwrap()
            };
            let remote_role = if role == "sender" {
                "receiver"
            } else {
                "sender"
            };
            let incoming = if role == "sender" {
                transcript.update_frame(&local);
                send_blob(&mut stream, &local_wire).await;
                recv_blob(&mut stream).await
            } else {
                recv_blob(&mut stream).await
            };
            let decoded = decode_fragmented(&incoming);
            assert_eq!(decoded, frame(remote_role, index));
            if index == 1 {
                let actual: [u8; 32] = Sha256::digest(decoded.payload()).into();
                assert_eq!(actual, manifest_root);
                received_payload_hash = Some(actual);
            } else {
                assert_eq!(decoded.payload(), received_payload_hash.as_ref().unwrap());
            }
            let expected_incoming = if historical {
                canonical_fixture(&decoded)
            } else {
                legacy_wire(&decoded)
            };
            assert_eq!(
                incoming, expected_incoming,
                "peer must exercise its declared wire order"
            );
            transcript.update_frame(&decoded);
            if role == "receiver" {
                transcript.update_frame(&local);
                send_blob(&mut stream, &local_wire).await;
            }
            max_wire_bytes = max_wire_bytes.max(incoming.len()).max(local_wire.len());
            wire_hashes.push(json!({"index": index, "sent": digest(&local_wire), "received": digest(&incoming), "payload_sha256": digest(decoded.payload())}));
            println!(
                "{}",
                json!({"bead_id": BEAD, "scenario_id": scenario, "role": role,
                "stage": "frame_verified", "frame_index": index, "received_bytes": incoming.len(),
                "wire_sha256": digest(&incoming), "payload_sha256": digest(decoded.payload())})
            );
        }
        let cases = malformed();
        for (index, (code, wire)) in cases.iter().enumerate() {
            if role == "sender" {
                send_blob(&mut stream, wire).await;
                assert_eq!(recv_blob(&mut stream).await, code.as_bytes());
            } else {
                let incoming = recv_blob(&mut stream).await;
                assert_eq!(
                    &incoming, wire,
                    "malformed fixture {index} must reach the authenticated peer"
                );
                let mut pending = BytesMut::from(incoming.as_slice());
                let error = AtpFrameCodec::new().decode(&mut pending).unwrap_err();
                assert_eq!(rejection(&error), *code);
                assert_eq!(pending.as_ref(), incoming.as_slice());
                send_blob(&mut stream, code.as_bytes()).await;
            }
            max_wire_bytes = max_wire_bytes.max(wire.len());
            println!(
                "{}",
                json!({"bead_id": BEAD, "scenario_id": scenario, "role": role,
                "stage": "malformed_refused", "case_index": index, "refusal_code": code, "wire_bytes": wire.len()})
            );
        }
        let hash = transcript.finalize();
        if role == "sender" {
            send_blob(&mut stream, hash.as_bytes()).await;
            assert_eq!(recv_blob(&mut stream).await, hash.as_bytes());
        } else {
            assert_eq!(recv_blob(&mut stream).await, hash.as_bytes());
            send_blob(&mut stream, hash.as_bytes()).await;
        }
        drop(stream);
        json!({"bead_id": BEAD, "scenario_id": scenario, "role": role,
            "pid": std::process::id(), "transport": "native_tcp_mutual_tls13",
            "peer_certificate_sha256": digest(&peer_certificate), "certificate_test_clock_unix": CERTIFICATE_TEST_TIME,
            "historical_encoder": if historical { "explicit_unsorted_fixture" } else { "current_public_codec" },
            "valid_frames_sent": 3, "valid_frames_received": 3, "rejected_frames": cases.len(),
            "transcript_sha256": hash.to_hex(), "wire_hashes": wire_hashes,
            "negotiation": negotiation,
            "max_wire_bytes": max_wire_bytes, "stream_dropped": true,
            "package_version": env!("CARGO_PKG_VERSION"), "features": ["tls"],
            "codec_source_sha256": digest(include_bytes!("../src/net/atp/protocol/codec.rs")),
            "session_source_sha256": digest(include_bytes!("../src/net/atp/protocol/session.rs")),
            "test_source_sha256": digest(include_bytes!("atp_session_negotiation.rs")),
            "scope": "authenticated_session_negotiation_and_frames_not_released_binary_or_daemon_transfer"})
    }

    #[test]
    #[ignore = "child entry point; executed only by native_two_process_extension_exchange"]
    fn native_extension_peer() {
        let role = std::env::var("ASUPERSYNC_EXTENSION_ROLE").expect("parent-provided role");
        assert!(matches!(role.as_str(), "sender" | "receiver"));
        let scenario = std::env::var("ASUPERSYNC_EXTENSION_SCENARIO").unwrap();
        let root = PathBuf::from(std::env::var_os("ASUPERSYNC_EXTENSION_ROOT").unwrap());
        let runtime = RuntimeBuilder::multi_thread()
            .worker_threads(2)
            .build()
            .unwrap();
        let report = runtime.block_on(
            runtime
                .handle()
                .spawn(async move { exchange(&role, &scenario, &root).await }),
        );
        drop(runtime);
        let role = std::env::var("ASUPERSYNC_EXTENSION_ROLE").unwrap();
        let root = PathBuf::from(std::env::var_os("ASUPERSYNC_EXTENSION_ROOT").unwrap());
        println!("{report}");
        write_json(&root.join(format!("{role}.json")), &report);
    }

    struct OwnedPeer(Child);

    impl Drop for OwnedPeer {
        fn drop(&mut self) {
            // Only children created by this test; preserve all log/artifact files.
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn start_peer(root: &Path, role: &str, scenario: &str) -> OwnedPeer {
        let log = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(format!("{role}.log")))
            .unwrap();
        OwnedPeer(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    CHILD_TEST,
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ASUPERSYNC_EXTENSION_ROLE", role)
                .env("ASUPERSYNC_EXTENSION_ROOT", root)
                .env("ASUPERSYNC_EXTENSION_SCENARIO", scenario)
                .stdout(Stdio::from(log.try_clone().unwrap()))
                .stderr(Stdio::from(log))
                .spawn()
                .unwrap(),
        )
    }

    fn await_peer(peer: &mut OwnedPeer, deadline: Instant, root: &Path, role: &str) {
        loop {
            if let Some(status) = peer.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "{role}: {status}; artifacts={}\n{}",
                    root.display(),
                    std::fs::read_to_string(root.join(format!("{role}.log"))).unwrap()
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "child watchdog: {role}; artifacts={}",
                root.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn native_two_process_extension_exchange() {
        let base = std::env::var_os("ASUPERSYNC_TEST_ARTIFACTS_DIR").map_or_else(
            || PathBuf::from("target/e2e-results/atp-session-negotiation"),
            PathBuf::from,
        );
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let artifact_root = base.join(format!("extensions-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&artifact_root).unwrap();
        let mut reports = Vec::new();
        for scenario in ["canonical_sender", "historical_sender"] {
            let root = artifact_root.join(scenario);
            std::fs::create_dir(&root).unwrap();
            let deadline = Instant::now() + Duration::from_secs(40);
            let mut receiver = start_peer(&root, "receiver", scenario);
            while std::fs::read(root.join("ready.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_none()
            {
                assert!(
                    receiver.0.try_wait().unwrap().is_none(),
                    "receiver exited before bind; artifacts={}",
                    root.display()
                );
                assert!(
                    Instant::now() < deadline,
                    "receiver bind watchdog; artifacts={}",
                    root.display()
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let mut sender = start_peer(&root, "sender", scenario);
            await_peer(&mut sender, deadline, &root, "sender");
            await_peer(&mut receiver, deadline, &root, "receiver");
            let sender: Value =
                serde_json::from_reader(File::open(root.join("sender.json")).unwrap()).unwrap();
            let receiver: Value =
                serde_json::from_reader(File::open(root.join("receiver.json")).unwrap()).unwrap();
            assert_ne!(sender["pid"], receiver["pid"]);
            assert_ne!(sender["pid"], std::process::id());
            assert_ne!(receiver["pid"], std::process::id());
            assert_eq!(sender["transcript_sha256"], receiver["transcript_sha256"]);
            assert_eq!(sender["negotiation"]["state"], "Established");
            assert_eq!(receiver["negotiation"]["state"], "ServerHelloSent");
            for key in [
                "session_id",
                "policy_transcript_sha256",
                "manifest_sha256",
                "selected_features",
                "configured_grant_sha256",
            ] {
                assert_eq!(
                    sender["negotiation"][key], receiver["negotiation"][key],
                    "{key}"
                );
            }
            assert_eq!(
                sender["negotiation"]["local_peer"],
                receiver["negotiation"]["remote_peer"]
            );
            assert_eq!(
                sender["negotiation"]["remote_peer"],
                receiver["negotiation"]["local_peer"]
            );
            for index in 0..3 {
                assert_eq!(
                    sender["wire_hashes"][index]["sent"],
                    receiver["wire_hashes"][index]["received"]
                );
                assert_eq!(
                    receiver["wire_hashes"][index]["sent"],
                    sender["wire_hashes"][index]["received"]
                );
            }
            for report in [&sender, &receiver] {
                assert_eq!(report["valid_frames_received"], 3);
                assert_eq!(report["rejected_frames"], 5);
                assert_eq!(report["stream_dropped"], true);
            }
            reports.push(json!({"scenario": scenario, "sender": sender, "receiver": receiver}));
        }
        assert_eq!(
            reports[0]["sender"]["transcript_sha256"], reports[1]["sender"]["transcript_sha256"],
            "changing only extension wire order must preserve the observed semantic transcript"
        );
        let summary = json!({"bead_id": BEAD, "scenario_id": "native_two_process_extension_exchange",
            "result": "pass", "child_processes": 4, "negotiated_sessions": 2, "scenarios": reports,
            "test_binary_sha256": digest(&std::fs::read(std::env::current_exe().unwrap()).unwrap()),
            "historical_released_binary_executed": false, "artifact_root": artifact_root});
        write_json(&artifact_root.join("summary.json"), &summary);
        println!("{summary}");
    }
}
