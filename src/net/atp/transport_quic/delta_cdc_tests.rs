//! Adversarial contracts for authenticated QUIC content-defined deltas.

use super::*;
use super::super::{
    ATP_DELTA_CHUNK_MANIFEST_SCHEMA, ATP_QUIC_PROTOCOL, AtpFrameCodec, BytesMut,
    CasChunkRef, CompressionMode, ContentId, DeltaChunkWire, DeltaManifestWire,
    DeltaObjectRequest, DeltaWireMode, Digest, EntryDigest, Frame, FrameType,
    ManifestEntry, PersistentChunkManifest, QuicConfig, QuicDeltaSessionContext,
    QuicHello, QuicHelloAck, QuicReceiveOptions, QuicSendOptions, SecurityContext,
    SessionId, Sha256, TransferManifest, TransferNonce, flat_merkle_root_from_digests,
    hex_encode, json_frame, parse_json, quic_decode_delta_root,
};
use crate::codec::Decoder;
use crate::net::atp::transport_common::delta::cdc;
use crate::security::AuthMode;

fn handshake() -> (QuicHello, QuicHelloAck) {
    let hello = QuicHello {
        protocol: ATP_QUIC_PROTOCOL,
        role: "sender".to_string(),
        peer_id: "cdc-sender".to_string(),
        symbol_size: 1024,
        max_block_size: 64 * 1024,
        symbol_auth: true,
        source_stream: true,
        source_stream_id: Some(4),
        total_bytes: 4 * 1024 * 1024,
        delta_transfer_nonce: Some(TransferNonce::new([3; 32])),
    };
    let ack = QuicHelloAck {
        accepted: true,
        peer_id: "cdc-receiver".to_string(),
        source_stream: true,
        source_stream_recv_window: Some(256 * 1024),
        reason: None,
        delta_transfer_nonce: hello.delta_transfer_nonce,
        delta_receiver_nonce: Some(TransferNonce::new([5; 32])),
        delta_destination_root: Some([7; 32]),
    };
    (hello, ack)
}

fn authenticated_frames(
    context: &SecurityContext,
    hello: &QuicHello,
    ack: &QuicHelloAck,
) -> (Frame, Frame) {
    let mut offer = json_frame(FrameType::Handshake, hello).unwrap();
    let mut response = json_frame(FrameType::HandshakeAck, ack).unwrap();
    advertise_cdc(&mut offer, context, hello).unwrap();
    acknowledge_cdc(&mut response, context, hello, ack).unwrap();
    (offer, response)
}

#[test]
fn cdc_options_are_default_off_and_cannot_bypass_delta_authority() {
    let defaults = QuicSendOptions::new();
    assert_eq!(defaults, QuicSendOptions::default());
    assert!(!defaults.cdc_delta() && !defaults.delta_chunks());
    let sender = defaults.with_cdc_delta(true).with_delta_chunks(false);
    assert!(sender.cdc_delta() && sender.delta_chunks());
    assert_eq!(sender.with_cdc_delta(false), defaults);

    let defaults = QuicReceiveOptions::new();
    assert_eq!(defaults, QuicReceiveOptions::default());
    assert!(!defaults.cdc_delta() && !defaults.delta_chunks());
    let receiver = defaults.with_cdc_delta(true).with_delta_chunks(false);
    assert!(receiver.cdc_delta() && receiver.delta_chunks());
    assert_eq!(receiver.with_cdc_delta(false), defaults);
    assert!(receiver.validate_detached().is_err());

    let mut config = QuicConfig::default();
    assert!(sender.validate(&config).is_err());
    config.enable_delta = true;
    assert!(sender.validate(&config).is_err());
    config = config.with_delta_control_auth(SecurityContext::for_testing(138));
    sender.validate(&config).unwrap();
    assert!(sender.with_compression(CompressionMode::Zstd).validate(&config).is_err());
    config.enable_delta = false;
    assert!(sender.validate(&config).is_err());
}

#[test]
fn cdc_negotiation_preserves_legacy_json_and_requires_an_actual_offer() {
    let context = SecurityContext::for_testing(138);
    let (hello, ack) = handshake();
    let legacy_offer = json_frame(FrameType::Handshake, &hello).unwrap();
    let legacy_response = json_frame(FrameType::HandshakeAck, &ack).unwrap();
    assert!(!cdc_offered(&legacy_offer, &context, &hello).unwrap());
    assert!(!cdc_acknowledged(&legacy_response, None, &hello, &ack, false).unwrap());
    let (offer, response) = authenticated_frames(&context, &hello, &ack);
    assert_eq!(offer.payload, legacy_offer.payload);
    assert_eq!(response.payload, legacy_response.payload);
    assert!(cdc_offered(&offer, &context, &hello).unwrap());
    assert!(cdc_acknowledged(&response, Some(&context), &hello, &ack, true).unwrap());
    assert!(cdc_acknowledged(&response, Some(&context), &hello, &ack, false).is_err());
    assert!(cdc_acknowledged(&response, None, &hello, &ack, true).is_err());

    for (frame, expected_type) in [(&offer, FrameType::Handshake), (&response, FrameType::HandshakeAck)] {
        let wire = frame.to_wire_bytes().unwrap();
        let decoded = AtpFrameCodec::new()
            .decode(&mut BytesMut::from(wire.as_slice())).unwrap().unwrap();
        assert_eq!(decoded.frame_type(), expected_type);
        assert_eq!(decoded.payload, frame.payload);
        if expected_type == FrameType::Handshake {
            assert_eq!(parse_json::<QuicHello>(&decoded).unwrap(), hello);
            assert!(cdc_offered(&decoded, &context, &hello).unwrap());
        } else {
            assert_eq!(parse_json::<QuicHelloAck>(&decoded).unwrap(), ack);
            assert!(cdc_acknowledged(&decoded, Some(&context), &hello, &ack, true).unwrap());
        }
    }
}

#[test]
fn cdc_capabilities_bind_both_nonces_destination_peer_identity_and_transport_geometry() {
    let context = SecurityContext::for_testing(138);
    let (hello, ack) = handshake();
    let (offer, response) = authenticated_frames(&context, &hello, &ack);
    for mutation in 0..10 {
        let mut changed = hello.clone();
        match mutation {
            0 => changed.protocol += 1,
            1 => changed.role = "receiver".to_string(),
            2 => changed.peer_id.push('x'),
            3 => changed.symbol_size += 1,
            4 => changed.max_block_size += 1,
            5 => changed.symbol_auth = false,
            6 => changed.source_stream = false,
            7 => changed.source_stream_id = Some(8),
            8 => changed.total_bytes += 1,
            9 => changed.delta_transfer_nonce = Some(TransferNonce::new([4; 32])),
            _ => unreachable!(),
        }
        assert!(cdc_offered(&offer, &context, &changed).is_err(), "unbound Hello field {mutation}");
        assert!(cdc_acknowledged(&response, Some(&context), &changed, &ack, true).is_err(),
            "acknowledgement accepted another Hello field {mutation}");
    }
    for mutation in 0..8 {
        let mut changed = ack.clone();
        match mutation {
            0 => changed.accepted = false,
            1 => changed.peer_id.push('x'),
            2 => changed.source_stream = false,
            3 => changed.source_stream_recv_window = Some(512 * 1024),
            4 => changed.reason = Some("altered response".to_string()),
            5 => changed.delta_transfer_nonce = Some(TransferNonce::new([4; 32])),
            6 => changed.delta_receiver_nonce = Some(TransferNonce::new([6; 32])),
            7 => changed.delta_destination_root = Some([8; 32]),
            _ => unreachable!(),
        }
        assert!(cdc_acknowledged(&response, Some(&context), &hello, &changed, true).is_err(),
            "unbound acknowledgement field {mutation}");
    }
}

#[test]
fn cdc_authentication_rejects_malformed_reflected_and_wrong_key_tags() {
    let context = SecurityContext::for_testing(138);
    let (hello, ack) = handshake();
    let (offer, response) = authenticated_frames(&context, &hello, &ack);
    let wrong_key = SecurityContext::for_testing(139);
    assert!(cdc_offered(&offer, &wrong_key, &hello).is_err());
    assert!(cdc_acknowledged(&response, Some(&wrong_key), &hello, &ack, true).is_err());
    for bytes in [Vec::new(), vec![0; 1], vec![0; 31], vec![0; 32], vec![0; 33]] {
        let mut bad_offer = offer.clone();
        bad_offer.header.extensions.insert(CDC_HELLO_EXTENSION, bytes.clone());
        assert!(cdc_offered(&bad_offer, &context, &hello).is_err());
        let mut bad_response = response.clone();
        bad_response.header.extensions.insert(CDC_ACK_EXTENSION, bytes);
        assert!(cdc_acknowledged(&bad_response, Some(&context), &hello, &ack, true).is_err());
    }
    let mut reflected_response = response.clone();
    reflected_response.header.extensions.insert(CDC_ACK_EXTENSION,
        offer.header.extensions.get(&CDC_HELLO_EXTENSION).unwrap().clone());
    assert!(cdc_acknowledged(&reflected_response, Some(&context), &hello, &ack, true).is_err());
    let mut reflected_offer = offer;
    reflected_offer.header.extensions.insert(CDC_HELLO_EXTENSION,
        response.header.extensions.get(&CDC_ACK_EXTENSION).unwrap().clone());
    assert!(cdc_offered(&reflected_offer, &context, &hello).is_err());

    for mode in [AuthMode::Permissive, AuthMode::Disabled] {
        let weak = SecurityContext::for_testing_with_mode(138, mode);
        let mut bare_offer = json_frame(FrameType::Handshake, &hello).unwrap();
        let mut bare_response = json_frame(FrameType::HandshakeAck, &ack).unwrap();
        assert!(advertise_cdc(&mut bare_offer, &weak, &hello).is_err());
        assert!(acknowledge_cdc(&mut bare_response, &weak, &hello, &ack).is_err());
        let (offer, response) = authenticated_frames(&context, &hello, &ack);
        assert!(cdc_offered(&offer, &weak, &hello).is_err());
        assert!(cdc_acknowledged(&response, Some(&weak), &hello, &ack, true).is_err());
    }
}

#[test]
fn cdc_requires_complete_fresh_challenges_even_with_the_correct_key() {
    let context = SecurityContext::for_testing(138);
    let (hello, ack) = handshake();
    for nonce in [None, Some(TransferNonce::new([0; 32]))] {
        let mut invalid = hello.clone();
        invalid.delta_transfer_nonce = nonce;
        let mut frame = json_frame(FrameType::Handshake, &invalid).unwrap();
        assert!(advertise_cdc(&mut frame, &context, &invalid).is_err());
    }
    for mutation in 0..9 {
        let mut invalid = ack.clone();
        match mutation {
            0 => invalid.accepted = false,
            1 => invalid.delta_transfer_nonce = None,
            2 => invalid.delta_receiver_nonce = None,
            3 => invalid.delta_destination_root = None,
            4 => invalid.delta_transfer_nonce = Some(TransferNonce::new([4; 32])),
            5 => invalid.delta_receiver_nonce = Some(TransferNonce::new([0; 32])),
            6 => invalid.delta_receiver_nonce = hello.delta_transfer_nonce,
            7 => invalid.delta_destination_root = Some([0; 32]),
            8 => {
                invalid.delta_transfer_nonce = None;
                invalid.delta_receiver_nonce = None;
                invalid.delta_destination_root = None;
            }
            _ => unreachable!(),
        }
        let mut frame = json_frame(FrameType::HandshakeAck, &invalid).unwrap();
        assert!(acknowledge_cdc(&mut frame, &context, &hello, &invalid).is_err(),
            "signed unusable delta handshake {mutation}");
    }
}

fn manifest_with_lengths(lengths: &[usize], content_defined: bool) -> TransferManifest {
    let mut bytes = Vec::new();
    let mut chunks = Vec::new();
    for (index, &len) in lengths.iter().enumerate() {
        let offset = bytes.len();
        bytes.extend(std::iter::repeat_n(u8::try_from(index % 251).unwrap(), len));
        chunks.push(DeltaChunkWire {
            index: u32::try_from(index).unwrap(),
            entry_index: 0,
            rel_path: "payload.bin".to_string(),
            entry_offset: u64::try_from(offset).unwrap(),
            stream_offset: u64::try_from(offset).unwrap(),
            size_bytes: u64::try_from(len).unwrap(),
            content_id_hex: ContentId::from_bytes(&bytes[offset..]).to_hex(),
        });
    }
    let size = u64::try_from(bytes.len()).unwrap();
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let outer = flat_merkle_root_from_digests(&[EntryDigest {
        rel_path: "payload.bin".to_string(), size,
        content_id: crate::atp::object::ObjectId::content(ContentId::from_bytes(&bytes)),
        content_sha256: sha256,
    }]);
    let planner = PersistentChunkManifest::new(outer.clone(), chunks.iter().map(|chunk| {
        CasChunkRef {
            index: chunk.index, byte_offset: chunk.stream_offset, size_bytes: chunk.size_bytes,
            content_id: ContentId::new(quic_decode_delta_root(&chunk.content_id_hex, "test id").unwrap()),
        }
    }).collect()).unwrap();
    TransferManifest {
        transfer_id: "ab".repeat(32), root_name: "payload.bin".to_string(),
        is_directory: false, total_bytes: size, merkle_root_hex: outer.clone(),
        metadata_root_hex: None, directory_metadata: None,
        entries: vec![ManifestEntry {
            index: 0, rel_path: "payload.bin".to_string(), size,
            sha256_hex: hex_encode(&sha256), metadata: None, members: Vec::new(),
        }],
        delta_manifest: Some(DeltaManifestWire {
            schema: if content_defined { MANIFEST_SCHEMA } else { ATP_DELTA_CHUNK_MANIFEST_SCHEMA }.to_string(),
            tree_id: outer,
            chunk_size: if content_defined { cdc::MAX_CHUNK_BYTES } else { lengths[0] },
            total_size_bytes: size, merkle_root_hex: planner.merkle_root.to_hex(), chunks,
        }),
    }
}

fn session() -> QuicDeltaSessionContext {
    QuicDeltaSessionContext { session_id: SessionId::from_digest([11; 32]), destination_root: [13; 32] }
}

#[test]
fn cdc_manifest_capability_and_request_selector_cannot_be_substituted_for_fixed() {
    let context = SecurityContext::for_testing(138);
    let fixed = manifest_with_lengths(&[cdc::MAX_CHUNK_BYTES, cdc::MAX_CHUNK_BYTES], false);
    let mut content_defined = fixed.clone();
    content_defined.delta_manifest.as_mut().unwrap().schema = MANIFEST_SCHEMA.to_string();
    let mut fixed_frame = json_frame(FrameType::ObjectManifest, &fixed).unwrap();
    let mut cdc_frame = json_frame(FrameType::ObjectManifest, &content_defined).unwrap();
    super::super::delta_chunks::advertise(&mut fixed_frame, &context, session(), &fixed).unwrap();
    super::super::delta_chunks::advertise(&mut cdc_frame, &context, session(), &content_defined).unwrap();
    assert!(super::super::delta_chunks::offered(&fixed_frame, &context, session(), &fixed).unwrap());
    assert!(super::super::delta_chunks::offered(&cdc_frame, &context, session(), &content_defined).unwrap());
    assert!(super::super::delta_chunks::offered(&fixed_frame, &context, session(), &content_defined).is_err());
    assert!(super::super::delta_chunks::offered(&cdc_frame, &context, session(), &fixed).is_err());
    // Sign the exact CDC body with the old capability key: manifest binding
    // alone must not make this a valid CDC capability.
    let symbol = super::super::quic_delta_manifest_auth_symbol(session(), &content_defined).unwrap();
    let mut wrong_domain = cdc_frame;
    wrong_domain.header.extensions.insert(super::super::delta_chunks::OFFER_EXTENSION,
        context.derive_context(b"atp-quic-fixed-delta-chunks-256k-v1")
            .sign_symbol_tag(&symbol).as_bytes().to_vec());
    assert!(super::super::delta_chunks::offered(&wrong_domain, &context, session(), &content_defined).is_err());
    let delta = content_defined.delta_manifest.as_ref().unwrap();
    let mut request = DeltaObjectRequest {
        mode: DeltaWireMode::DeltaChunks,
        fallback_reason: Some(SELECTOR.to_string()),
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some("cd".repeat(32)),
        missing_bytes: delta.chunks[1].size_bytes,
        shared_chunks: 1, stale_chunks: 0, missing_chunks: vec![delta.chunks[1].clone()],
    };
    super::super::delta_chunks::validate_request(&content_defined, &request).unwrap();
    assert!(super::super::delta_chunks::validate_request(&fixed, &request).is_err());
    request.fallback_reason = Some("authenticated_fixed_delta_chunks_v1".to_string());
    assert!(super::super::delta_chunks::validate_request(&content_defined, &request).is_err());
    super::super::delta_chunks::validate_request(&fixed, &request).unwrap();
}

#[test]
fn cdc_policy_upper_bound_is_independent_of_remote_geometry() {
    let cap = super::super::QUIC_DELTA_MAX_MANIFEST_CHUNKS
        * u64::try_from(cdc::MAX_CHUNK_BYTES).unwrap();
    assert!(size_may_fit(cap));
    assert!(!size_may_fit(cap + 1));
    assert!(!size_may_fit(u64::MAX));
}


#[test]
fn cdc_manifest_acceptance_requires_negotiation_and_exact_local_chunk_geometry() {
    let valid = manifest_with_lengths(&[cdc::MIN_CHUNK_BYTES + 173, cdc::MAX_CHUNK_BYTES - 17, 17], true);
    let config = QuicConfig::default();
    super::super::validate_quic_manifest_with_cdc(&valid, &config, true).unwrap();
    assert!(super::super::validate_quic_manifest(&valid, &config).is_err());
    assert!(super::super::validate_quic_manifest_with_cdc(&valid, &config, false).is_err());

    // Each fixture has a freshly computed inner root and exact total. Rejection
    // must follow local geometry rather than an accidentally stale checksum.
    for sizes in [
        vec![cdc::MIN_CHUNK_BYTES - 1, 17],
        vec![cdc::MAX_CHUNK_BYTES + 1, 17],
        vec![cdc::MIN_CHUNK_BYTES, cdc::MAX_CHUNK_BYTES + 1],
    ] {
        let malformed = manifest_with_lengths(&sizes, true);
        assert!(super::super::validate_quic_manifest_with_cdc(&malformed, &config, true).is_err());
    }
    let short_final = manifest_with_lengths(&[cdc::MIN_CHUNK_BYTES, 1], true);
    super::super::validate_quic_manifest_with_cdc(&short_final, &config, true).unwrap();
    let short_only = manifest_with_lengths(&[1], true);
    super::super::validate_quic_manifest_with_cdc(&short_only, &config, true).unwrap();

    for mutation in 0..10 {
        let mut malformed = valid.clone();
        let delta = malformed.delta_manifest.as_mut().unwrap();
        match mutation {
            0 => delta.chunk_size = 1,
            1 => delta.chunk_size = cdc::MAX_CHUNK_BYTES + 1,
            2 => delta.schema.push('x'),
            3 => delta.chunks[0].size_bytes = 0,
            4 => delta.chunks[1].index = 0,
            5 => delta.chunks[1].entry_offset += 1,
            6 => delta.chunks[1].stream_offset += 1,
            7 => delta.chunks[1].entry_index = 1,
            8 => delta.chunks[1].rel_path = "elsewhere.bin".to_string(),
            9 => delta.tree_id = "cd".repeat(32),
            _ => unreachable!(),
        }
        assert!(super::super::validate_quic_manifest_with_cdc(&malformed, &config, true).is_err(),
            "accepted malformed CDC layout {mutation}");
    }
    let mut oversized = valid;
    let delta = oversized.delta_manifest.as_mut().unwrap();
    delta.chunks.resize(
        usize::try_from(super::super::QUIC_DELTA_MAX_MANIFEST_CHUNKS + 1).unwrap(),
        delta.chunks[0].clone(),
    );
    let error = super::super::validate_quic_delta_manifest_with_cdc(&oversized, true).unwrap_err();
    assert!(error.to_string().contains("too many chunks"), "{error}");
    let fixed = manifest_with_lengths(&[1024, 1024, 17], false);
    super::super::validate_quic_manifest(&fixed, &config).unwrap();
    super::super::validate_quic_manifest_with_cdc(&fixed, &config, true).unwrap();
}

fn source_config() -> QuicConfig {
    QuicConfig {
        chunk_size: cdc::MAX_CHUNK_BYTES,
        enable_delta: true,
        metadata_policy: super::super::MetadataPolicy::portable(),
        ..QuicConfig::default()
    }
    .with_symbol_auth(SecurityContext::for_testing(140))
    .with_delta_control_auth(SecurityContext::for_testing(138))
}

fn source_bytes(size: usize) -> Vec<u8> {
    let mut seed = 0x6a09_e667_f3bc_c909_u64;
    (0..size).map(|_| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed.to_le_bytes()[3]
    }).collect()
}

#[test]
fn selected_cdc_layout_revalidates_source_and_live_noop_destination() {
    use futures_lite::future::block_on;
    let cx = super::super::Cx::for_testing();
    let scratch = tempfile::tempdir().unwrap();
    let root = scratch.path().canonicalize().unwrap();
    let source = root.join("payload.bin");
    let dest = root.join("dest");
    std::fs::create_dir(&dest).unwrap();
    let bytes = source_bytes(512 * 1024 + 37);
    std::fs::write(&source, &bytes).unwrap();
    std::fs::write(dest.join("payload.bin"), &bytes).unwrap();
    let config = source_config();
    let mut prepared = block_on(super::super::prepare_source_manifest(&cx, &source, &config)).unwrap();
    assert!(!is_cdc(&prepared.manifest));
    block_on(select_manifest(&cx, &mut prepared)).unwrap();
    assert!(is_cdc(&prepared.manifest));
    block_on(super::super::validate_quic_prepared_delta_source_unchanged(&cx, &prepared, &config)).unwrap();

    let request = block_on(super::super::build_quic_receiver_delta_request(
        &cx, &dest, &config, session(), &prepared.manifest,
    )).unwrap();
    assert_eq!(request.request.mode, DeltaWireMode::AlreadyInSync);
    let mut altered = bytes.clone();
    altered[123_457] ^= 0x80;
    std::fs::write(dest.join("payload.bin"), &altered).unwrap();
    let request = block_on(super::super::build_quic_receiver_delta_request(
        &cx, &dest, &config, session(), &prepared.manifest,
    )).unwrap();
    assert_eq!(request.request.mode, DeltaWireMode::FullObject,
        "same-length destination changes cannot produce a no-op receipt");

    std::fs::write(&source, &altered).unwrap();
    assert!(block_on(super::super::validate_quic_prepared_delta_source_unchanged(
        &cx, &prepared, &config,
    )).is_err(), "same-length source edits must invalidate the prepared CDC snapshot");
}

#[test]
fn layout_builder_enforces_actual_count_and_rejects_growth_before_returning_a_manifest() {
    use futures_lite::future::block_on;
    let cx = super::super::Cx::for_testing();
    let scratch = tempfile::tempdir().unwrap();
    let source = scratch.path().join("payload.bin");
    let count = usize::try_from(super::super::QUIC_DELTA_MAX_MANIFEST_CHUNKS).unwrap();
    let bytes = source_bytes(count + 1);
    std::fs::write(&source, &bytes).unwrap();
    let config = source_config();
    let prepared = block_on(super::super::prepare_source_manifest(&cx, &source, &config)).unwrap();
    let entry = &prepared.manifest.entries[0];
    let build = |chunk_size| super::super::build_quic_delta_manifest_with_layout(
        &cx, &prepared.manifest.merkle_root_hex, &source, entry.index,
        &entry.rel_path, entry.size, &entry.sha256_hex, chunk_size, false,
    );
    assert!(block_on(build(1)).unwrap().is_none(), "4097 real chunks must hit the policy cap");
    assert!(block_on(build(2)).unwrap().is_some());
    let mut grown = bytes;
    grown.push(7);
    std::fs::write(&source, &grown).unwrap();
    assert!(block_on(build(2)).is_err(), "a grown source must not become a valid delta manifest");
}
