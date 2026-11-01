//! Protocol regressions for opt-in authenticated QUIC changed chunks.

use super::*;
use super::super::{
    AtpFrameCodec, BytesMut, CasChunkRef, DeltaManifestWire, Digest, EntryDigest,
    ManifestEntry, PersistentChunkManifest, QuicConfig, QuicDeltaManifestEnvelope,
    QuicReceiveOptions, QuicSendOptions, SessionId, Sha256, flat_merkle_root_from_digests,
    make_quic_delta_manifest_envelope, make_quic_delta_proof, make_quic_delta_request,
    validate_quic_delta_request,
};
use crate::codec::Decoder;

fn session() -> QuicDeltaSessionContext {
    QuicDeltaSessionContext {
        session_id: SessionId::from_digest([7; 32]),
        destination_root: [91; 32],
    }
}

fn chunk(index: u32, offset: u64, bytes: &[u8]) -> DeltaChunkWire {
    DeltaChunkWire {
        index,
        entry_index: 0,
        rel_path: "payload.bin".to_string(),
        entry_offset: offset,
        stream_offset: offset,
        size_bytes: bytes.len() as u64,
        content_id_hex: ContentId::from_bytes(bytes).to_hex(),
    }
}

fn manifest() -> TransferManifest {
    let bytes = b"aaaabbbbcccc";
    let chunks = vec![chunk(0, 0, &bytes[..4]), chunk(1, 4, &bytes[4..8]), chunk(2, 8, &bytes[8..])];
    let sha256: [u8; 32] = Sha256::digest(bytes).into();
    let outer = flat_merkle_root_from_digests(&[EntryDigest {
        rel_path: "payload.bin".to_string(),
        size: bytes.len() as u64,
        content_id: crate::atp::object::ObjectId::content(ContentId::from_bytes(bytes)),
        content_sha256: sha256,
    }]);
    let planner = PersistentChunkManifest::new(
        outer.clone(),
        chunks.iter().map(|chunk| CasChunkRef {
            index: chunk.index,
            byte_offset: chunk.stream_offset,
            size_bytes: chunk.size_bytes,
            content_id: ContentId::new(quic_decode_delta_root(&chunk.content_id_hex, "test id").unwrap()),
        }).collect(),
    ).unwrap();
    TransferManifest {
        transfer_id: "ab".repeat(32),
        root_name: "payload.bin".to_string(),
        is_directory: false,
        total_bytes: bytes.len() as u64,
        merkle_root_hex: outer.clone(),
        metadata_root_hex: None,
        directory_metadata: None,
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: "payload.bin".to_string(),
            size: bytes.len() as u64,
            sha256_hex: super::super::hex_encode(&sha256),
            metadata: None,
            members: Vec::new(),
        }],
        delta_manifest: Some(DeltaManifestWire {
            schema: super::super::ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
            tree_id: outer,
            chunk_size: 4,
            total_size_bytes: bytes.len() as u64,
            merkle_root_hex: planner.merkle_root.to_hex(),
            chunks,
        }),
    }
}

fn request(manifest: &TransferManifest) -> DeltaObjectRequest {
    let delta = manifest.delta_manifest.as_ref().unwrap();
    DeltaObjectRequest {
        mode: DeltaWireMode::DeltaChunks,
        fallback_reason: Some(SELECTOR.to_string()),
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some("cd".repeat(32)),
        missing_bytes: 4,
        shared_chunks: 2,
        stale_chunks: 1,
        missing_chunks: vec![delta.chunks[1].clone()],
    }
}

#[test]
fn changed_chunks_are_explicit_and_require_strict_delta_authority() {
    assert!(!QuicSendOptions::default().delta_chunks());
    assert!(!QuicReceiveOptions::default().delta_chunks());
    assert!(QuicSendOptions::new().with_delta_chunks(true).delta_chunks());
    assert!(QuicReceiveOptions::new().with_delta_chunks(true).delta_chunks());
    let mut config = QuicConfig::default();
    assert!(super::super::validate_quic_delta_chunks_option(false, &config).is_ok());
    assert!(super::super::validate_quic_delta_chunks_option(true, &config).is_err());
    config.enable_delta = true;
    assert!(super::super::validate_quic_delta_chunks_option(true, &config).is_err());
    config = config.with_delta_control_auth(SecurityContext::for_testing(138));
    assert!(super::super::validate_quic_delta_chunks_option(true, &config).is_ok());
    assert!(QuicSendOptions::new().with_delta_chunks(true)
        .with_compression(super::super::CompressionMode::Zstd).validate(&config).is_err());
    assert!(QuicReceiveOptions::new().validate_detached().is_ok());
    assert!(QuicReceiveOptions::new().with_delta_chunks(true).validate_detached().is_err());
    config.enable_delta = false;
    assert!(super::super::validate_quic_delta_chunks_option(true, &config).is_err());
}

#[test]
fn capability_preserves_legacy_payload_and_authenticates_exact_session_manifest() {
    let context = SecurityContext::for_testing(138);
    let manifest = manifest();
    let envelope = make_quic_delta_manifest_envelope(&context, session(), &manifest).unwrap();
    let mut frame = super::super::json_frame(FrameType::ObjectManifest, &envelope).unwrap();
    let old_payload = frame.payload.clone();
    assert!(!offered(&frame, &context, session(), &manifest).unwrap());
    advertise(&mut frame, &context, session(), &manifest).unwrap();
    let wire = frame.to_wire_bytes().unwrap();
    let decoded = AtpFrameCodec::new().decode(&mut BytesMut::from(wire.as_slice())).unwrap().unwrap();
    assert_eq!(decoded.payload, old_payload);
    // The existing payload decoder accepts the new extension without any new
    // serde fields, exactly as an old peer's manifest path does.
    assert_eq!(super::super::parse_json::<QuicDeltaManifestEnvelope>(&decoded).unwrap(), envelope);
    assert!(offered(&decoded, &context, session(), &manifest).unwrap());
    assert!(offered(&decoded, &SecurityContext::for_testing(139), session(), &manifest).is_err());
    let mut wrong_session = session();
    wrong_session.session_id = SessionId::from_digest([8; 32]);
    assert!(offered(&decoded, &context, wrong_session, &manifest).is_err());
    let mut wrong_manifest = manifest.clone();
    wrong_manifest.root_name = "other.bin".to_string();
    assert!(offered(&decoded, &context, session(), &wrong_manifest).is_err());
    let mut malformed = decoded;
    malformed.header.extensions.insert(OFFER_EXTENSION, vec![0; 31]);
    assert!(offered(&malformed, &context, session(), &manifest).is_err());
}

#[test]
fn requests_are_exact_ordered_subsets_with_complete_accounting() {
    let manifest = manifest();
    let request = request(&manifest);
    let bound = make_quic_delta_request(session(), &manifest, request.clone());
    assert_eq!(validate_quic_delta_request(&bound, session(), &manifest).unwrap(), DeltaWireMode::DeltaChunks);
    let mut bad = Vec::new();
    let mut r = request.clone(); r.missing_bytes += 1; bad.push(r);
    let mut r = request.clone(); r.shared_chunks += 1; bad.push(r);
    let mut r = request.clone(); r.shared_chunks = u64::MAX; bad.push(r);
    let mut r = request.clone(); r.stale_chunks = QUIC_DELTA_MAX_MANIFEST_CHUNKS + 1; bad.push(r);
    let mut r = request.clone(); r.fallback_reason = None; bad.push(r);
    let mut r = request.clone(); r.receiver_merkle_root_hex = None; bad.push(r);
    let mut r = request.clone(); r.receiver_merkle_root_hex = Some("not-a-root".to_string()); bad.push(r);
    let mut r = request.clone(); r.sender_merkle_root_hex = "ef".repeat(32); bad.push(r);
    let mut r = request.clone(); r.missing_chunks[0].entry_index = 1; bad.push(r);
    let mut r = request.clone(); r.missing_chunks[0].rel_path = "other.bin".to_string(); bad.push(r);
    let mut r = request.clone(); r.missing_chunks[0].entry_offset += 1; bad.push(r);
    let mut r = request.clone(); r.missing_chunks[0].stream_offset += 1; bad.push(r);
    let mut r = request.clone(); r.missing_chunks[0].size_bytes += 1; bad.push(r);
    let mut r = request.clone(); r.missing_chunks[0].content_id_hex = "ef".repeat(32); bad.push(r);
    let mut r = request.clone(); r.missing_chunks[0].index = 99; bad.push(r);
    let mut r = request.clone(); r.missing_chunks.push(r.missing_chunks[0].clone());
    r.missing_bytes = 8; r.shared_chunks = 1; bad.push(r);
    let mut r = request.clone();
    r.missing_chunks = vec![manifest.delta_manifest.as_ref().unwrap().chunks[2].clone(), r.missing_chunks[0].clone()];
    r.missing_bytes = 8; r.shared_chunks = 1; bad.push(r);
    for (index, request) in bad.into_iter().enumerate() {
        assert!(validate_request(&manifest, &request).is_err(), "accepted invalid subset {index}");
    }
    let mut replay = bound.clone(); replay.control_seq = 1;
    assert!(validate_quic_delta_request(&replay, session(), &manifest).is_err());
    let mut replay = bound.clone(); replay.destination_root = [0; 32];
    assert!(validate_quic_delta_request(&replay, session(), &manifest).is_err());
    let mut all_reused = request;
    all_reused.missing_chunks.clear(); all_reused.missing_bytes = 0; all_reused.shared_chunks = 3;
    assert!(validate_request(&manifest, &all_reused).is_ok());
}

#[test]
fn changed_frames_reject_wrong_range_length_replays_and_codec_extensions() {
    let bytes = vec![23; DATA_FRAGMENT_BYTES + 7];
    let chunk = chunk(9, 131_072, &bytes);
    let frame = data_frame(&chunk, 0, &bytes[..DATA_FRAGMENT_BYTES]).unwrap();
    assert_eq!(checked_data(&frame, &chunk, 0).unwrap(), &bytes[..DATA_FRAGMENT_BYTES]);
    let tail = data_frame(&chunk, DATA_FRAGMENT_BYTES as u64, &bytes[DATA_FRAGMENT_BYTES..]).unwrap();
    assert_eq!(checked_data(&tail, &chunk, DATA_FRAGMENT_BYTES as u64).unwrap(), &bytes[DATA_FRAGMENT_BYTES..]);
    assert!(checked_data(&frame, &chunk, DATA_FRAGMENT_BYTES as u64).is_err());
    let mut bad = frame.clone(); bad.payload[3] ^= 1;
    assert!(checked_data(&bad, &chunk, 0).is_err());
    let mut bad = frame.clone(); bad.payload[11] ^= 1;
    assert!(checked_data(&bad, &chunk, 0).is_err());
    let mut bad = frame.clone(); bad.payload.pop();
    assert!(checked_data(&bad, &chunk, 0).is_err());
    let mut bad = frame.clone(); bad.payload.push(0);
    assert!(checked_data(&bad, &chunk, 0).is_err());
    let mut bad = frame; bad.header.extensions.insert(1, vec![1]);
    assert!(checked_data(&bad, &chunk, 0).is_err());
    assert!(verify_bytes(&chunk, &bytes, "fixture").is_ok());
    let mut corrupt = bytes; corrupt[0] ^= 1;
    assert!(verify_bytes(&chunk, &corrupt, "fixture").is_err());
}

#[test]
fn complete_and_proof_must_account_for_only_requested_payload_after_commit() {
    let manifest = manifest();
    let request = request(&manifest);
    let complete = Complete { bytes_sent: 4, chunks_sent: 1 };
    assert!(validate_complete(&complete, &request).is_ok());
    assert!(validate_complete(&Complete { bytes_sent: 12, chunks_sent: 1 }, &request).is_err());
    assert!(validate_complete(&Complete { bytes_sent: 4, chunks_sent: 2 }, &request).is_err());
    let receipt = ReceiveReceipt {
        committed: true, bytes_received: 4, files: 1, sha_ok: true, merkle_ok: true,
        symbols_accepted: 0, feedback_rounds: 0, decode_count: 0, decode_micros: 0,
        reason: None, committed_paths: vec!["/dest/payload.bin".to_string()],
    };
    let proof = make_quic_delta_proof(session(), &manifest, receipt);
    assert!(validate_proof(proof.clone(), session(), &manifest, &request).is_ok());
    assert!(super::super::validate_quic_delta_refusal(proof.clone(), session(), &manifest).is_err());
    let mut bad = Vec::new();
    let mut p = proof.clone(); p.receipt.bytes_received = 12; bad.push(p);
    let mut p = proof.clone(); p.receipt.committed = false; bad.push(p);
    let mut p = proof.clone(); p.receipt.sha_ok = false; bad.push(p);
    let mut p = proof.clone(); p.receipt.merkle_ok = false; bad.push(p);
    let mut p = proof.clone(); p.receipt.symbols_accepted = 1; bad.push(p);
    let mut p = proof.clone(); p.receipt.feedback_rounds = 1; bad.push(p);
    let mut p = proof.clone(); p.receipt.decode_count = 1; bad.push(p);
    let mut p = proof.clone(); p.receipt.decode_micros = 1; bad.push(p);
    let mut p = proof.clone(); p.receipt.reason = Some("unexpected".to_string()); bad.push(p);
    let mut p = proof.clone(); p.receipt.committed_paths.clear(); bad.push(p);
    let mut p = proof.clone(); p.control_seq = 0; bad.push(p);
    let mut p = proof; p.session_id = SessionId::from_digest([8; 32]); bad.push(p);
    for (index, proof) in bad.into_iter().enumerate() {
        assert!(validate_proof(proof, session(), &manifest, &request).is_err(), "accepted proof {index}");
    }
}
