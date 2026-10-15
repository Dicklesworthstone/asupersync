//! ATP native-QUIC packet-protection provider contract tests.
//!
//! These tests use the deterministic lab provider, not production cryptography.
//! The contract under test is the boundary: QUIC owns packet-space and key-phase
//! state while the provider owns primitive operations, redacted proofs, key
//! discard, header protection, and transcript binding.

use asupersync::net::quic_native::{
    DeterministicQuicCryptoProvider, PacketProtectionRequest, PacketProtectionSpace,
    QuicHandshakeTranscript, QuicPacketProtectionProvider, QuicTlsError,
};
#[cfg(feature = "tls")]
use asupersync::net::quic_native::{RustlsQuicCryptoProvider, RustlsQuicProviderSide};

fn transcript() -> QuicHandshakeTranscript {
    let mut transcript = QuicHandshakeTranscript::new();
    transcript.record("client_initial", b"client hello");
    transcript.record("server_handshake", b"server hello");
    transcript
}

fn derive_default_keys(provider: &mut DeterministicQuicCryptoProvider) -> QuicHandshakeTranscript {
    let transcript = transcript();
    for space in [
        PacketProtectionSpace::Initial,
        PacketProtectionSpace::Handshake,
        PacketProtectionSpace::OneRtt,
    ] {
        provider
            .derive_keys(space, &transcript, b"deterministic test secret")
            .unwrap();
    }
    transcript
}

#[test]
fn deterministic_provider_roundtrips_initial_handshake_and_1rtt_packets() {
    let mut provider = DeterministicQuicCryptoProvider::new();
    let transcript = derive_default_keys(&mut provider);
    provider.verify_transcript(transcript.digest()).unwrap();

    for (space, packet_number, payload) in [
        (
            PacketProtectionSpace::Initial,
            0,
            b"initial payload".as_slice(),
        ),
        (
            PacketProtectionSpace::Handshake,
            7,
            b"handshake payload".as_slice(),
        ),
        (
            PacketProtectionSpace::OneRtt,
            42,
            b"1rtt payload".as_slice(),
        ),
    ] {
        let protected = provider
            .protect_packet(PacketProtectionRequest {
                space,
                key_phase: false,
                packet_number,
                associated_data: b"header",
                payload,
            })
            .unwrap();

        assert_ne!(protected.ciphertext, payload);
        assert_eq!(protected.proof.provider_kind, "deterministic-lab");
        assert_eq!(protected.proof.space, space);
        assert_eq!(protected.proof.failure_code, None);

        let unprotected = provider.unprotect_packet(&protected, b"header").unwrap();
        assert_eq!(unprotected.plaintext, payload);
        assert_eq!(unprotected.proof.transcript_hash, transcript.digest());
    }
}

#[test]
fn header_protection_is_deterministic_and_rejects_short_samples() {
    let mut provider = DeterministicQuicCryptoProvider::new();
    derive_default_keys(&mut provider);

    let sample = b"0123456789abcdefextra";
    let first = provider
        .header_protection_mask(PacketProtectionSpace::Initial, sample)
        .unwrap();
    let second = provider
        .header_protection_mask(PacketProtectionSpace::Initial, sample)
        .unwrap();
    assert_eq!(first, second);
    assert_ne!(first.bytes, [0u8; 5]);

    let err = provider
        .header_protection_mask(PacketProtectionSpace::Initial, b"too-short")
        .unwrap_err();
    assert_eq!(err.code(), "header_sample_too_short");
}

#[test]
fn provider_failures_are_stable_redacted_and_fail_closed() {
    let mut provider = DeterministicQuicCryptoProvider::new();
    let transcript = transcript();

    let empty_seed = provider
        .derive_keys(PacketProtectionSpace::Initial, &transcript, b"")
        .unwrap_err();
    assert_eq!(empty_seed.code(), "empty_secret_seed");
    assert!(
        empty_seed
            .to_string()
            .contains("provider=deterministic-lab")
    );

    let missing = provider
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::Initial,
            key_phase: false,
            packet_number: 1,
            associated_data: b"header",
            payload: b"payload",
        })
        .unwrap_err();
    assert_eq!(missing.code(), "missing_keys");

    provider
        .derive_keys(
            PacketProtectionSpace::Initial,
            &transcript,
            b"deterministic test secret",
        )
        .unwrap();
    let wrong_phase = provider
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::Initial,
            key_phase: true,
            packet_number: 1,
            associated_data: b"header",
            payload: b"payload",
        })
        .unwrap_err();
    assert_eq!(wrong_phase.code(), "wrong_key_phase");

    provider
        .discard_keys(PacketProtectionSpace::Initial)
        .unwrap();
    let discarded = provider
        .key_snapshot(PacketProtectionSpace::Initial, false)
        .unwrap_err();
    assert_eq!(discarded.code(), "key_discarded");
}

#[test]
fn bad_tags_and_transcript_confusion_are_rejected() {
    let mut provider = DeterministicQuicCryptoProvider::new();
    let transcript = derive_default_keys(&mut provider);

    let mut protected = provider
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::OneRtt,
            key_phase: false,
            packet_number: 9,
            associated_data: b"header",
            payload: b"payload",
        })
        .unwrap();
    protected.tag[0] ^= 0x55;
    let err = provider
        .unprotect_packet(&protected, b"header")
        .unwrap_err();
    assert_eq!(
        err,
        QuicTlsError::BadPacketTag {
            space: PacketProtectionSpace::OneRtt,
        }
    );

    let mut other = QuicHandshakeTranscript::new();
    other.record("different", b"transcript");
    let transcript_err = provider.verify_transcript(other.digest()).unwrap_err();
    assert_eq!(transcript_err.code(), "transcript_mismatch");
    assert!(
        transcript_err
            .to_string()
            .contains(&transcript.digest().short_hex())
    );
}

#[test]
fn key_update_installs_next_phase_without_losing_old_key_material() {
    let mut provider = DeterministicQuicCryptoProvider::new();
    derive_default_keys(&mut provider);

    let old_key = provider
        .key_snapshot(PacketProtectionSpace::OneRtt, false)
        .unwrap();
    let next_key = provider
        .update_key(PacketProtectionSpace::OneRtt, true)
        .unwrap();

    assert_eq!(next_key.space, PacketProtectionSpace::OneRtt);
    assert!(next_key.key_phase);
    assert_eq!(next_key.generation, old_key.generation + 1);
    assert_ne!(next_key.key_id, old_key.key_id);

    let protected = provider
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::OneRtt,
            key_phase: true,
            packet_number: 10,
            associated_data: b"header",
            payload: b"next phase payload",
        })
        .unwrap();
    let unprotected = provider.unprotect_packet(&protected, b"header").unwrap();
    assert_eq!(unprotected.plaintext, b"next phase payload");

    let old_phase = provider
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::OneRtt,
            key_phase: false,
            packet_number: 11,
            associated_data: b"header",
            payload: b"old phase still readable until discard",
        })
        .unwrap();
    assert_eq!(
        provider
            .unprotect_packet(&old_phase, b"header")
            .unwrap()
            .plaintext,
        b"old phase still readable until discard"
    );
}

#[cfg(feature = "tls")]
#[test]
fn rustls_provider_roundtrips_initial_packets_between_client_and_server() {
    let transcript = transcript();
    let dcid = b"client destination cid";
    let mut client = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Client).unwrap();
    let mut server = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Server).unwrap();

    let client_initial = client
        .derive_keys(PacketProtectionSpace::Initial, &transcript, dcid)
        .unwrap();
    let server_initial = server
        .derive_keys(PacketProtectionSpace::Initial, &transcript, dcid)
        .unwrap();

    assert_eq!(client_initial.space, PacketProtectionSpace::Initial);
    assert_eq!(server_initial.space, PacketProtectionSpace::Initial);
    assert!(!client_initial.key_phase);
    client.verify_transcript(transcript.digest()).unwrap();
    server.verify_transcript(transcript.digest()).unwrap();

    let from_client = client
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::Initial,
            key_phase: false,
            packet_number: 0,
            associated_data: b"client initial header",
            payload: b"client initial payload",
        })
        .unwrap();
    assert_eq!(from_client.proof.provider_kind, "rustls-quic-ring");
    assert_eq!(from_client.proof.transcript_hash, transcript.digest());

    let client_plain = server
        .unprotect_packet(&from_client, b"client initial header")
        .unwrap();
    assert_eq!(client_plain.plaintext, b"client initial payload");

    let from_server = server
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::Initial,
            key_phase: false,
            packet_number: 1,
            associated_data: b"server initial header",
            payload: b"server initial payload",
        })
        .unwrap();
    let server_plain = client
        .unprotect_packet(&from_server, b"server initial header")
        .unwrap();
    assert_eq!(server_plain.plaintext, b"server initial payload");
}

#[cfg(feature = "tls")]
#[test]
fn rustls_provider_rejects_wrong_initial_dcid_and_reports_header_sample_limits() {
    let transcript = transcript();
    let mut sender = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Client).unwrap();
    let mut receiver = RustlsQuicCryptoProvider::new_v1(RustlsQuicProviderSide::Server).unwrap();

    sender
        .derive_keys(PacketProtectionSpace::Initial, &transcript, b"right-dcid")
        .unwrap();
    receiver
        .derive_keys(PacketProtectionSpace::Initial, &transcript, b"wrong-dcid")
        .unwrap();

    let protected = sender
        .protect_packet(PacketProtectionRequest {
            space: PacketProtectionSpace::Initial,
            key_phase: false,
            packet_number: 22,
            associated_data: b"header",
            payload: b"payload",
        })
        .unwrap();
    let err = receiver
        .unprotect_packet(&protected, b"header")
        .unwrap_err();
    assert_eq!(err.code(), "bad_packet_tag");

    let sample = b"0123456789abcdef";
    let first = sender
        .header_protection_mask(PacketProtectionSpace::Initial, sample)
        .unwrap();
    let second = sender
        .header_protection_mask(PacketProtectionSpace::Initial, sample)
        .unwrap();
    assert_eq!(first, second);

    let short = sender
        .header_protection_mask(PacketProtectionSpace::Initial, b"too short")
        .unwrap_err();
    assert_eq!(short.code(), "header_sample_too_short");
}
