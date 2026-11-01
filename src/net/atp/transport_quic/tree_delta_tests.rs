//! Protocol, geometry and live source contracts for whole-file tree reuse.

use super::*;
use super::super::{
    DeltaObjectRequest, DeltaWireMode, QuicDeltaSessionContext, QuicReceiveOptions,
    QuicSendOptions, ReceiveReceipt, SessionId, json_frame,
};
use futures_lite::future::block_on;

fn config() -> QuicConfig {
    QuicConfig {
        enable_delta: true,
        chunk_size: DATA_FRAGMENT_BYTES,
        metadata_policy: super::super::MetadataPolicy::portable(),
        ..QuicConfig::default()
    }.with_delta_control_auth(SecurityContext::for_testing(173))
}

fn handshake() -> (QuicHello, QuicHelloAck, TransferNonce) {
    let nonce = TransferNonce::new([31; 32]);
    let hello = super::super::sender_hello_with_source_stream(
        "tree-sender", &config(), false, None, 10 * 1024 * 1024, None,
    );
    let ack = QuicHelloAck {
        accepted: true, peer_id: "tree-receiver".to_string(),
        source_stream: false, source_stream_recv_window: None, reason: None,
        delta_transfer_nonce: Some(nonce),
        delta_receiver_nonce: Some(TransferNonce::new([37; 32])),
        delta_destination_root: Some([41; 32]),
    };
    (hello, ack, nonce)
}

fn fixture() -> (tempfile::TempDir, Cx, QuicConfig, QuicPreparedSource) {
    let scratch = tempfile::tempdir().unwrap();
    let source = scratch.path().join("tree");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("a-large.bin"), vec![0x51; 1024 * 1024 + 17]).unwrap();
    std::fs::write(source.join("b-small.bin"), vec![0x62; 4096]).unwrap();
    std::fs::write(source.join("c-small.bin"), vec![0x73; 8192]).unwrap();
    std::fs::write(source.join("d-empty.bin"), b"").unwrap();
    std::fs::create_dir(source.join("empty-directory")).unwrap();
    let cx = Cx::for_testing();
    let config = config();
    let mut prepared = block_on(super::super::prepare_source_manifest(&cx, &source, &config)).unwrap();
    assert!(prepared.manifest.delta_manifest.is_none());
    assert!(may_offer(&prepared));
    assert!(block_on(select_manifest(&cx, &mut prepared, &config)).unwrap());
    (scratch, cx, config, prepared)
}

fn session() -> QuicDeltaSessionContext {
    QuicDeltaSessionContext {
        session_id: SessionId::from_digest([43; 32]), destination_root: [47; 32],
    }
}

fn missing_first(manifest: &TransferManifest) -> DeltaObjectRequest {
    let delta = manifest.delta_manifest.as_ref().unwrap();
    DeltaObjectRequest {
        mode: DeltaWireMode::DeltaChunks, fallback_reason: Some(SELECTOR.to_string()),
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some("ab".repeat(32)),
        missing_bytes: delta.chunks[0].size_bytes,
        shared_chunks: delta.chunks.len() as u64 - 1, stale_chunks: 0,
        missing_chunks: vec![delta.chunks[0].clone()],
    }
}

#[test]
fn tree_options_preserve_defaults_and_cannot_bypass_delta_authority() {
    let send = QuicSendOptions::new();
    let receive = QuicReceiveOptions::new();
    assert!(!send.tree_delta() && !receive.tree_delta());
    assert_eq!(send, QuicSendOptions::default());
    assert_eq!(receive, QuicReceiveOptions::default());
    let send = send.with_tree_delta(true).with_delta_chunks(false);
    let receive = receive.with_tree_delta(true).with_delta_chunks(false);
    assert!(send.tree_delta() && send.delta_chunks() && !send.cdc_delta());
    assert!(receive.tree_delta() && receive.delta_chunks() && !receive.cdc_delta());
    assert!(send.validate(&QuicConfig::default()).is_err());
    send.validate(&config()).unwrap();
    assert!(receive.validate_detached().is_err());
    assert!(send.with_compression(super::super::CompressionMode::Zstd).validate(&config()).is_err());
}

#[test]
fn tree_capability_keeps_legacy_json_nonce_absent_and_binds_fresh_ack() {
    let context = SecurityContext::for_testing(173);
    let (hello, ack, nonce) = handshake();
    let mut offer = json_frame(FrameType::Handshake, &hello).unwrap();
    let legacy = offer.payload.clone();
    assert_eq!(offered(&offer, &context, &hello).unwrap(), None);
    advertise(&mut offer, &context, &hello, nonce).unwrap();
    assert_eq!(offer.payload, legacy);
    assert!(hello.delta_transfer_nonce.is_none());
    assert_eq!(offered(&offer, &context, &hello).unwrap(), Some(nonce));
    let mut response = json_frame(FrameType::HandshakeAck, &ack).unwrap();
    assert!(!acknowledged(&response, None, &hello, &ack, None).unwrap());
    acknowledge(&mut response, &context, &hello, &ack, nonce).unwrap();
    assert!(acknowledged(&response, Some(&context), &hello, &ack, Some(nonce)).unwrap());
    assert!(acknowledged(&response, Some(&context), &hello, &ack, None).is_err());
    assert!(acknowledged(&response, None, &hello, &ack, Some(nonce)).is_err());
    assert!(acknowledged(&response, Some(&context), &hello, &ack,
        Some(TransferNonce::new([53; 32]))).is_err());

    for mutation in 0..5 {
        let mut changed = ack.clone();
        match mutation {
            0 => changed.delta_receiver_nonce = Some(TransferNonce::new([59; 32])),
            1 => changed.delta_destination_root = Some([61; 32]),
            2 => changed.peer_id.push('x'),
            3 => changed.delta_receiver_nonce = None,
            4 => changed.delta_receiver_nonce = Some(nonce),
            _ => unreachable!(),
        }
        assert!(acknowledged(&response, Some(&context), &hello, &changed, Some(nonce)).is_err());
    }
    let mut changed = hello.clone();
    changed.total_bytes += 1;
    assert!(offered(&offer, &context, &changed).is_err());
    assert!(acknowledged(&response, Some(&context), &changed, &ack, Some(nonce)).is_err());
    changed = hello.clone();
    changed.delta_transfer_nonce = Some(nonce);
    assert!(advertise(&mut offer, &context, &changed, nonce).is_err());
    assert!(advertise(&mut offer, &context, &hello, TransferNonce::new([0; 32])).is_err());
}

#[test]
fn tree_capability_rejects_malformed_wrong_key_and_reflected_tags() {
    let context = SecurityContext::for_testing(173);
    let wrong = SecurityContext::for_testing(174);
    let (hello, ack, nonce) = handshake();
    let mut offer = json_frame(FrameType::Handshake, &hello).unwrap();
    advertise(&mut offer, &context, &hello, nonce).unwrap();
    assert!(offered(&offer, &wrong, &hello).is_err());
    for bytes in [vec![], vec![0; 32], vec![0; 63], vec![0; 64], vec![0; 65]] {
        let mut changed = offer.clone();
        changed.header.extensions.insert(HELLO_EXTENSION, bytes);
        assert!(offered(&changed, &context, &hello).is_err());
    }
    let mut response = json_frame(FrameType::HandshakeAck, &ack).unwrap();
    acknowledge(&mut response, &context, &hello, &ack, nonce).unwrap();
    assert!(acknowledged(&response, Some(&wrong), &hello, &ack, Some(nonce)).is_err());
    response.header.extensions.insert(ACK_EXTENSION,
        offer.header.extensions.get(&HELLO_EXTENSION).unwrap()[32..].to_vec());
    assert!(acknowledged(&response, Some(&context), &hello, &ack, Some(nonce)).is_err());
    for mode in [AuthMode::Disabled, AuthMode::Permissive] {
        let weak = SecurityContext::for_testing_with_mode(173, mode);
        assert!(advertise(&mut offer, &weak, &hello, nonce).is_err());
        assert!(offered(&offer, &weak, &hello).is_err());
    }
}

#[test]
fn tree_manifest_preserves_packed_offsets_and_cannot_bypass_negotiation() {
    let (_scratch, _cx, config, prepared) = fixture();
    let manifest = &prepared.manifest;
    let delta = manifest.delta_manifest.as_ref().unwrap();
    assert_eq!(delta.chunks.len(), 3, "empty files and directories carry no object bytes");
    assert!(delta.chunks.iter().any(|chunk| chunk.size_bytes > DATA_FRAGMENT_BYTES as u64));
    assert!(delta.chunks.iter().any(|chunk| chunk.entry_offset != 0));
    for chunk in &delta.chunks {
        let (path, offset) = source_for_chunk(&prepared, chunk).unwrap();
        assert_eq!(offset, chunk.entry_offset);
        assert_eq!(path, prepared.entries[chunk.entry_index as usize].abs_path.as_path());
    }
    super::super::validate_quic_manifest_with_layouts(manifest, &config, false, true).unwrap();
    assert!(super::super::validate_quic_manifest(manifest, &config).is_err());
    assert!(super::super::validate_quic_manifest_with_cdc(manifest, &config, true).is_err());
    for mutation in 0..8 {
        let mut changed = manifest.clone();
        let delta = changed.delta_manifest.as_mut().unwrap();
        match mutation {
            0 => delta.chunk_size += 1,
            1 => delta.chunks[1].entry_offset += 1,
            2 => delta.chunks[1].entry_index += 1,
            3 => delta.chunks[1].rel_path.push('x'),
            4 => delta.chunks[1].stream_offset += 1,
            5 => delta.chunks[1].size_bytes += 1,
            6 => delta.chunks[1].index = 0,
            7 => delta.total_size_bytes += 1,
            _ => unreachable!(),
        }
        assert!(super::super::validate_quic_manifest_with_layouts(&changed, &config, false, true).is_err());
    }
    let mut excessive = manifest.clone();
    let delta = excessive.delta_manifest.as_mut().unwrap();
    delta.chunks.resize(QUIC_DELTA_MAX_MANIFEST_CHUNKS as usize + 1, delta.chunks[0].clone());
    assert!(validate_manifest(&excessive).is_err());
}

#[test]
fn tree_requests_require_exact_missing_files_and_never_use_noop_shortcut() {
    let (_scratch, _cx, _config, prepared) = fixture();
    let manifest = &prepared.manifest;
    let request = missing_first(manifest);
    super::super::delta_chunks::validate_request(manifest, &request).unwrap();
    let mut changed = request.clone();
    changed.missing_bytes -= 1;
    assert!(super::super::delta_chunks::validate_request(manifest, &changed).is_err());
    changed = request.clone();
    changed.fallback_reason = Some("authenticated_fixed_delta_chunks_v1".to_string());
    assert!(super::super::delta_chunks::validate_request(manifest, &changed).is_err());
    changed = request;
    changed.missing_chunks[0].entry_offset += 1;
    assert!(super::super::delta_chunks::validate_request(manifest, &changed).is_err());
    let delta = manifest.delta_manifest.as_ref().unwrap();
    let noop = DeltaObjectRequest {
        mode: DeltaWireMode::AlreadyInSync, fallback_reason: None,
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some(delta.merkle_root_hex.clone()),
        missing_bytes: 0, missing_chunks: Vec::new(), shared_chunks: delta.chunks.len() as u64, stale_chunks: 0,
    };
    let envelope = super::super::make_quic_delta_request(session(), manifest, noop);
    assert!(super::super::validate_quic_delta_request(&envelope, session(), manifest).is_err());
}

#[test]
fn tree_proof_requires_every_logical_path_once() {
    let (_scratch, _cx, _config, prepared) = fixture();
    let manifest = &prepared.manifest;
    let request = missing_first(manifest);
    let files = super::super::manifest_logical_files(manifest);
    let receipt = ReceiveReceipt {
        committed: true, bytes_received: request.missing_bytes, files,
        sha_ok: true, merkle_ok: true, symbols_accepted: 0, feedback_rounds: 0,
        decode_count: 0, decode_micros: 0, reason: None,
        committed_paths: (0..files).map(|index| format!("/receiver/tree/{index}")).collect(),
    };
    let proof = super::super::make_quic_delta_proof(session(), manifest, receipt);
    super::super::delta_chunks::validate_proof(proof.clone(), session(), manifest, &request).unwrap();
    let mut duplicate = proof.clone();
    duplicate.receipt.committed_paths[1] = duplicate.receipt.committed_paths[0].clone();
    assert!(super::super::delta_chunks::validate_proof(duplicate, session(), manifest, &request).is_err());
    let mut missing = proof;
    missing.receipt.committed_paths.pop();
    assert!(super::super::delta_chunks::validate_proof(missing, session(), manifest, &request).is_err());
}

#[test]
fn tree_revalidation_rejects_same_length_prepared_source_mutation() {
    let (_scratch, cx, config, prepared) = fixture();
    block_on(revalidate_source(&cx, &prepared, &config)).unwrap();
    let delta = prepared.manifest.delta_manifest.as_ref().unwrap();
    let chunk = delta.chunks.iter().find(|chunk| chunk.entry_offset != 0).unwrap();
    let (path, offset) = source_for_chunk(&prepared, chunk).unwrap();
    let mut bytes = std::fs::read(path).unwrap();
    bytes[offset as usize + 13] ^= 0x80;
    std::fs::write(path, bytes).unwrap();
    assert!(block_on(revalidate_source(&cx, &prepared, &config)).is_err(),
        "the owned packed source is a snapshot and must remain hash-identical");
}

#[test]
fn tree_revalidation_rejects_same_length_plain_source_mutation() {
    let (_scratch, cx, config, prepared) = fixture();
    block_on(revalidate_source(&cx, &prepared, &config)).unwrap();
    let delta = prepared.manifest.delta_manifest.as_ref().unwrap();
    let chunk = delta.chunks.iter().find(|chunk| chunk.size_bytes > 1024 * 1024).unwrap();
    let (path, _) = source_for_chunk(&prepared, chunk).unwrap();
    let mut bytes = std::fs::read(path).unwrap();
    bytes[97] ^= 0x80;
    std::fs::write(path, bytes).unwrap();
    assert!(block_on(revalidate_source(&cx, &prepared, &config)).is_err());
}

#[test]
fn oversized_tree_candidate_falls_back_before_reading_or_changing_the_manifest() {
    let (_scratch, cx, config, prepared) = fixture();
    let entry = prepared.manifest.entries.iter().find(|entry| entry.members.is_empty() && entry.size != 0).unwrap().clone();
    let source = prepared.entries[entry.index as usize].clone();
    let mut candidate = prepared;
    candidate.manifest.delta_manifest = None;
    candidate.manifest.entries.clear();
    candidate.entries.clear();
    for index in 0..QUIC_DELTA_MAX_MANIFEST_CHUNKS {
        let mut next_entry = entry.clone();
        next_entry.index = index as u32;
        next_entry.rel_path = format!("file-{index}.bin");
        let mut next_source = source.clone();
        next_source.index = next_entry.index;
        next_source.rel_path = next_entry.rel_path.clone();
        candidate.manifest.entries.push(next_entry);
        candidate.entries.push(next_source);
    }
    assert!(may_offer(&candidate), "the cheap admission predicate permits exactly 4096 refs");
    let mut next_entry = entry;
    next_entry.index = QUIC_DELTA_MAX_MANIFEST_CHUNKS as u32;
    next_entry.rel_path = "one-too-many.bin".to_string();
    let mut next_source = source;
    next_source.index = next_entry.index;
    next_source.rel_path = next_entry.rel_path.clone();
    candidate.manifest.entries.push(next_entry);
    candidate.entries.push(next_source);
    assert!(!may_offer(&candidate));
    let before = candidate.manifest.clone();
    assert!(!block_on(select_manifest(&cx, &mut candidate, &config)).unwrap());
    assert_eq!(candidate.manifest, before);
}

#[cfg(feature = "tls")]
#[test]
fn tree_have_set_reuses_target_files_and_stages_even_a_zero_byte_transfer() {
    let (scratch, cx, config, prepared) = fixture();
    let source = scratch.path().join("tree");
    let dest = scratch.path().join("received");
    let base = dest.join("tree");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::copy(source.join("a-large.bin"), base.join("a-large.bin")).unwrap();
    let extra = base.join("receiver-only.bin");
    std::fs::write(&extra, b"private receiver data").unwrap();
    let partial = block_on(plan(&cx, &dest, &config, &prepared.manifest)).unwrap().unwrap();
    assert_eq!(partial.request.shared_chunks, 1);
    assert_eq!(partial.request.missing_bytes, 4096 + 8192);
    assert!(partial.reusable.values().all(|range| range.path != extra));
    for name in ["b-small.bin", "c-small.bin"] {
        std::fs::copy(source.join(name), base.join(name)).unwrap();
    }
    let complete = block_on(plan(&cx, &dest, &config, &prepared.manifest)).unwrap().unwrap();
    assert_eq!(complete.request.mode, DeltaWireMode::DeltaChunks);
    assert_eq!(complete.request.missing_bytes, 0);
    assert!(complete.request.missing_chunks.is_empty());
    assert_eq!(complete.request.shared_chunks, 3);
    assert!(!base.join("d-empty.bin").exists(), "zero-byte files still need staged reconstruction");
    assert_eq!(std::fs::read(extra).unwrap(), b"private receiver data");
}
