//! Focused regressions for negotiated fixed-chunk delivery and its bounds.

use super::*;
use super::super::{
    AtpFrameCodec, AuthenticatedControl, BytesMut, ControlRole, ManifestEntry,
    RqDeltaManifestEnvelope, RqMetadataManifest, make_rq_delta_manifest_envelope,
    rq_metadata_commitment, validate_manifest,
};
use crate::codec::Decoder;
use crate::net::atp::protocol::frames::MAX_FRAME_SIZE;
use crate::net::atp::transport_common::delta::{
    ATP_DELTA_CHUNK_MANIFEST_SCHEMA, DeltaManifestWire,
};

fn session() -> RqDeltaSessionContext {
    RqDeltaSessionContext {
        session_id: [7; 32],
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
    let chunks = vec![
        chunk(0, 0, &bytes[..4]),
        chunk(1, 4, &bytes[4..8]),
        chunk(2, 8, &bytes[8..]),
    ];
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
            content_id: ContentId::new(
                rq_decode_delta_root(&chunk.content_id_hex, "test chunk").unwrap(),
            ),
        }).collect(),
    ).unwrap();
    TransferManifest {
        transfer_id: "ab".repeat(32),
        root_name: "payload.bin".to_string(),
        is_directory: false,
        total_bytes: bytes.len() as u64,
        merkle_root_hex: outer.clone(),
        metadata: Some(RqMetadataManifest {
            version: 1,
            commitment_hex: rq_metadata_commitment(&[(
                "payload.bin",
                &super::super::EntryMetadata::default(),
            )]),
            entries: Vec::new(),
            directories: None,
        }),
        delta_manifest: Some(DeltaManifestWire {
            schema: ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(),
            tree_id: outer,
            chunk_size: 4,
            total_size_bytes: bytes.len() as u64,
            merkle_root_hex: planner.merkle_root.to_hex(),
            chunks,
        }),
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: "payload.bin".to_string(),
            size: bytes.len() as u64,
            sha256_hex: super::super::hex_encode(&sha256),
            members: Vec::new(),
            fragment: None,
        }],
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
fn changed_chunk_request_requires_an_exact_ordered_subset_and_conserved_counts() {
    let manifest = manifest();
    validate_manifest(&manifest, &RqConfig::default()).unwrap();
    let valid = request(&manifest);
    validate_request(&manifest, &valid, 0, &[], false).unwrap();
    for mutation in 0..12 {
        let mut invalid = valid.clone();
        match mutation {
            0 => invalid.fallback_reason = Some("full_object_required".to_string()),
            1 => invalid.sender_merkle_root_hex = "00".repeat(32),
            2 => invalid.receiver_merkle_root_hex = None,
            3 => invalid.receiver_merkle_root_hex = Some("not a root".to_string()),
            4 => invalid.missing_chunks[0].index = 99,
            5 => invalid.missing_chunks[0].entry_offset += 1,
            6 => invalid.missing_chunks[0].content_id_hex = "00".repeat(32),
            7 => invalid.missing_bytes += 1,
            8 => invalid.shared_chunks += 1,
            9 => invalid.stale_chunks = RQ_DELTA_MAX_MANIFEST_CHUNKS + 1,
            10 => {
                invalid.missing_chunks.push(invalid.missing_chunks[0].clone());
                invalid.missing_bytes = 8;
                invalid.shared_chunks = 1;
            }
            11 => {
                let delta = manifest.delta_manifest.as_ref().unwrap();
                invalid.missing_chunks = vec![delta.chunks[2].clone(), delta.chunks[0].clone()];
                invalid.missing_bytes = 8;
                invalid.shared_chunks = 1;
            }
            _ => unreachable!(),
        }
        assert!(validate_request(&manifest, &invalid, 0, &[], false).is_err(), "mutation {mutation}");
    }
    for (port, ports, source_stream) in [(1, vec![], false), (0, vec![1], false), (0, vec![], true)] {
        assert!(validate_request(&manifest, &valid, port, &ports, source_stream).is_err());
    }
    // Reordering/repeating existing content can require atomic reconstruction
    // even when no byte needs to cross the network.
    let mut all_reused = valid.clone();
    all_reused.missing_chunks.clear();
    all_reused.missing_bytes = 0;
    all_reused.shared_chunks = 3;
    validate_request(&manifest, &all_reused, 0, &[], false).unwrap();
    let mut full = valid;
    full.missing_chunks = manifest.delta_manifest.as_ref().unwrap().chunks.clone();
    full.missing_bytes = manifest.total_bytes;
    full.shared_chunks = 0;
    assert!(validate_request(&manifest, &full, 0, &[], false).is_err());
}

#[test]
fn capability_offer_is_session_bound_without_changing_the_existing_manifest_payload() {
    let manifest = manifest();
    let context = SecurityContext::for_testing(138);
    let envelope = make_rq_delta_manifest_envelope(&context, session(), &manifest).unwrap();
    let mut frame = json_frame(FrameType::ObjectManifest, &envelope).unwrap();
    let original_payload = frame.payload.clone();
    assert!(!offered(&frame, &context, session(), &manifest).unwrap());
    advertise(&mut frame, &context, session(), &manifest).unwrap();
    assert!(offered(&frame, &context, session(), &manifest).unwrap());
    assert_eq!(frame.payload, original_payload);
    let wire = frame.to_wire_bytes().unwrap();
    let decoded = AtpFrameCodec::new()
        .decode(&mut BytesMut::from(wire.as_slice())).unwrap().unwrap();
    // A prior delta receiver still sees its exact deny_unknown_fields JSON.
    let old: RqDeltaManifestEnvelope = parse_json(&decoded).unwrap();
    assert_eq!(old.manifest, manifest);
    super::super::validate_rq_delta_manifest_envelope(&context, session(), &old).unwrap();

    for altered in [
        RqDeltaSessionContext { session_id: [8; 32], ..session() },
        RqDeltaSessionContext { destination_root: [92; 32], ..session() },
    ] {
        assert!(matches!(offered(&frame, &context, altered, &manifest), Err(RqError::Authentication(_))));
    }
    let mut other = manifest.clone();
    other.transfer_id = "different transfer".to_string();
    assert!(offered(&frame, &context, session(), &other).is_err());
    let mut tampered = frame.clone();
    tampered.header.extensions.get_mut(&OFFER_EXTENSION).unwrap()[0] ^= 1;
    assert!(matches!(offered(&tampered, &context, session(), &manifest), Err(RqError::Authentication(_))));
    tampered.header.extensions.insert(OFFER_EXTENSION, vec![0; 31]);
    assert!(offered(&tampered, &context, session(), &manifest).is_err());
    frame.header.extensions.remove(&OFFER_EXTENSION);
    assert!(!offered(&frame, &context, session(), &manifest).unwrap());
}

#[test]
fn near_maximum_manifest_chunk_uses_bounded_authenticated_frames() {
    let bytes: Vec<u8> = (0..super::super::RQ_DELTA_CHUNK_SIZE)
        .map(|index| (index.wrapping_mul(73) >> 7) as u8).collect();
    let chunk = chunk(3, 99, &bytes);
    let context = SecurityContext::for_testing(138);
    let mut sender = AuthenticatedControl::new(
        &context, session(), "transfer", ControlRole::Sender,
    ).unwrap();
    let mut receiver = AuthenticatedControl::new(
        &context, session(), "transfer", ControlRole::Receiver,
    ).unwrap();
    let mut assembled = Vec::new();
    let mut frames = 0;
    for (part, bytes) in bytes.chunks(DATA_FRAGMENT_BYTES).enumerate() {
        let offset = (part * DATA_FRAGMENT_BYTES) as u64;
        let frame = data_frame(&chunk, offset, bytes).unwrap();
        let wire = sender.prepare_send(&frame).unwrap();
        sender.finish_write();
        assert!(wire.len() as u64 <= MAX_FRAME_SIZE);
        let decoded = AtpFrameCodec::new()
            .decode(&mut BytesMut::from(wire.as_slice())).unwrap().unwrap();
        let verified = receiver.verify_received(decoded).unwrap();
        assembled.extend_from_slice(checked_data(&verified, &chunk, offset).unwrap());
        frames += 1;
    }
    assert!(frames > 1, "the manifest chunk cannot fit one authenticated frame");
    assert_eq!(assembled, bytes);
    verify_chunk_bytes(&chunk, &assembled, "assembled test chunk").unwrap();
}

#[test]
fn fragments_refuse_duplicate_reordered_truncated_and_excess_data() {
    let bytes = vec![0x5A; DATA_FRAGMENT_BYTES + 17];
    let chunk = chunk(2, 23, &bytes);
    let first = data_frame(&chunk, 0, &bytes[..DATA_FRAGMENT_BYTES]).unwrap();
    let last = data_frame(&chunk, DATA_FRAGMENT_BYTES as u64, &bytes[DATA_FRAGMENT_BYTES..]).unwrap();
    assert_eq!(checked_data(&first, &chunk, 0).unwrap().len(), DATA_FRAGMENT_BYTES);
    assert_eq!(checked_data(&last, &chunk, DATA_FRAGMENT_BYTES as u64).unwrap().len(), 17);
    assert!(checked_data(&first, &chunk, DATA_FRAGMENT_BYTES as u64).is_err());
    assert!(checked_data(&last, &chunk, 0).is_err());
    assert!(checked_data(&last, &chunk, chunk.size_bytes).is_err());
    for mutation in 0..5 {
        let mut malformed = first.clone();
        match mutation {
            0 => malformed.payload[3] ^= 1,
            1 => malformed.payload[11] ^= 1,
            2 => { malformed.payload.pop(); }
            3 => malformed.payload.push(0),
            4 => malformed.header.frame_type = FrameType::ObjectComplete,
            _ => unreachable!(),
        }
        assert!(checked_data(&malformed, &chunk, 0).is_err(), "mutation {mutation}");
    }
    let truncated_header = Frame::new(ProtocolVersion::CURRENT, FrameType::ObjectData, vec![0; 11]).unwrap();
    assert!(checked_data(&truncated_header, &chunk, 0).is_err());
}

#[test]
fn every_reused_sent_and_received_chunk_requires_its_actual_content_id_and_length() {
    let bytes = b"committed bytes";
    let chunk = chunk(0, 0, bytes);
    verify_chunk_bytes(&chunk, bytes, "source").unwrap();
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    for label in ["source", "baseline", "received"] {
        assert!(matches!(verify_chunk_bytes(&chunk, &changed, label), Err(RqError::Integrity(_))));
        assert!(verify_chunk_bytes(&chunk, &bytes[..bytes.len() - 1], label).is_err());
        let mut extended = bytes.to_vec();
        extended.push(0);
        assert!(verify_chunk_bytes(&chunk, &extended, label).is_err());
    }
}

#[test]
fn enabling_chunk_reuse_cannot_disable_authenticated_fallback() {
    assert!(!RqReceiveOptions::default().delta_chunks());
    assert!(!RqReceiveOptions::default().authenticated_control());
    let options = RqReceiveOptions::new().with_delta_chunks(true).with_authenticated_control(false);
    assert!(options.delta_chunks());
    assert!(options.authenticated_control());
    let disabled = options.with_delta_chunks(false);
    assert!(!disabled.authenticated_control());
    assert!(RqReceiveOptions::new().with_authenticated_control(true).with_delta_chunks(false).authenticated_control());
}
