//! Authentication and request contracts for opt-in durable QUIC continuation.

use super::{advertise, offered, selected, supported, CHUNK_BYTES, SELECTOR};
use super::super::{
    CasChunkRef, CompressionMode, ContentId, DeltaChunkWire, DeltaManifestWire,
    DeltaObjectRequest, DeltaWireMode, Digest, EntryDigest, FrameType, ManifestEntry,
    PersistentChunkManifest, QuicConfig, QuicDeltaSessionContext, QuicReceiveOptions,
    QuicSendOptions, SecurityContext, SessionId, Sha256, TransferManifest,
    delta_chunks, flat_merkle_root_from_digests, hex_encode, json_frame,
    make_quic_delta_manifest_envelope, quic_decode_delta_root,
};

fn session() -> QuicDeltaSessionContext {
    QuicDeltaSessionContext {
        session_id: SessionId::from_digest([7; 32]), destination_root: [91; 32],
    }
}

pub(super) fn manifest() -> (TransferManifest, Vec<u8>) {
    let bytes: Vec<u8> = [0x11, 0x35, 0xa9].into_iter()
        .flat_map(|value| std::iter::repeat_n(value, CHUNK_BYTES)).collect();
    let chunks: Vec<_> = bytes.chunks(CHUNK_BYTES).enumerate().map(|(index, bytes)| {
        let offset = (index * CHUNK_BYTES) as u64;
        DeltaChunkWire {
            index: index as u32, entry_index: 0, rel_path: "payload.bin".to_string(),
            entry_offset: offset, stream_offset: offset, size_bytes: bytes.len() as u64,
            content_id_hex: ContentId::from_bytes(bytes).to_hex(),
        }
    }).collect();
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    let root = flat_merkle_root_from_digests(&[EntryDigest {
        rel_path: "payload.bin".to_string(), size: bytes.len() as u64,
        content_id: crate::atp::object::ObjectId::content(ContentId::from_bytes(&bytes)),
        content_sha256: sha256,
    }]);
    let persistent = PersistentChunkManifest::new(root.clone(), chunks.iter().map(|chunk| {
        CasChunkRef {
            index: chunk.index, byte_offset: chunk.stream_offset, size_bytes: chunk.size_bytes,
            content_id: ContentId::new(quic_decode_delta_root(&chunk.content_id_hex, "fixture").unwrap()),
        }
    }).collect()).unwrap();
    (TransferManifest {
        transfer_id: "ab".repeat(32), root_name: "payload.bin".to_string(),
        is_directory: false, total_bytes: bytes.len() as u64, merkle_root_hex: root.clone(),
        metadata_root_hex: None, directory_metadata: None,
        entries: vec![ManifestEntry {
            index: 0, rel_path: "payload.bin".to_string(), size: bytes.len() as u64,
            sha256_hex: hex_encode(&sha256), metadata: None, members: Vec::new(),
        }],
        delta_manifest: Some(DeltaManifestWire {
            schema: super::super::ATP_DELTA_CHUNK_MANIFEST_SCHEMA.to_string(), tree_id: root,
            chunk_size: CHUNK_BYTES, total_size_bytes: bytes.len() as u64,
            merkle_root_hex: persistent.merkle_root.to_hex(), chunks,
        }),
    }, bytes)
}

fn first_request(manifest: &TransferManifest) -> DeltaObjectRequest {
    let delta = manifest.delta_manifest.as_ref().unwrap();
    DeltaObjectRequest {
        mode: DeltaWireMode::DeltaChunks, fallback_reason: Some(SELECTOR.to_string()),
        sender_merkle_root_hex: delta.merkle_root_hex.clone(),
        receiver_merkle_root_hex: Some("cd".repeat(32)), missing_bytes: manifest.total_bytes,
        shared_chunks: 0, stale_chunks: 0, missing_chunks: delta.chunks.clone(),
    }
}

#[test]
fn resume_is_explicit_strict_fixed_and_incompatible_with_other_selectors() {
    assert!(!QuicSendOptions::default().resume());
    assert!(!QuicReceiveOptions::default().resume());
    let send = QuicSendOptions::new().with_resume(true);
    let receive = QuicReceiveOptions::new().with_resume(true);
    assert!(send.resume() && send.delta_chunks());
    assert!(receive.resume() && receive.delta_chunks());
    assert_eq!(send.with_resume(false), QuicSendOptions::new());
    assert_eq!(receive.with_resume(false), QuicReceiveOptions::new());
    assert!(receive.validate_detached().is_err());
    assert!(send.validate(&QuicConfig::default()).is_err());
    let config = QuicConfig {
        enable_delta: true,
        ..QuicConfig::default().with_delta_control_auth(SecurityContext::for_testing(138))
    };
    send.validate(&config).unwrap();
    assert!(send.with_compression(CompressionMode::Zstd).validate(&config).is_err());
    for invalid in [send.with_delta_chunks(true), send.with_cdc_delta(true), send.with_tree_delta(true)] {
        assert!(invalid.validate(&config).is_err());
    }
    for invalid in [receive.with_delta_chunks(true), receive.with_cdc_delta(true), receive.with_tree_delta(true)] {
        assert!(invalid.validate().is_err());
    }
    let (mut manifest, _) = manifest();
    assert!(supported(&manifest));
    manifest.is_directory = true;
    assert!(!supported(&manifest));
    manifest.is_directory = false;
    manifest.delta_manifest.as_mut().unwrap().chunk_size = 64 * 1024;
    assert!(!supported(&manifest));
}

#[test]
fn resume_capability_binds_fresh_session_manifest_and_secret_key() {
    let context = SecurityContext::for_testing(138);
    let (manifest, _) = manifest();
    let envelope = make_quic_delta_manifest_envelope(&context, session(), &manifest).unwrap();
    let mut frame = json_frame(FrameType::ObjectManifest, &envelope).unwrap();
    let original_payload = frame.payload.clone();
    assert!(!offered(&frame, &context, session(), &manifest).unwrap());
    advertise(&mut frame, &context, session(), &manifest).unwrap();
    assert_eq!(frame.payload, original_payload, "legacy JSON remains unchanged");
    assert!(offered(&frame, &context, session(), &manifest).unwrap());
    assert!(offered(&frame, &SecurityContext::for_testing(139), session(), &manifest).is_err());
    let mut replay = session();
    replay.session_id = SessionId::from_digest([8; 32]);
    assert!(offered(&frame, &context, replay, &manifest).is_err());
    let mut changed = manifest.clone();
    changed.transfer_id = "cd".repeat(32);
    assert!(offered(&frame, &context, session(), &changed).is_err());
    let mut malformed = frame.clone();
    malformed.header.extensions.insert(super::OFFER_EXTENSION, vec![0; 31]);
    assert!(offered(&malformed, &context, session(), &manifest).is_err());
    let mut reflected = frame;
    delta_chunks::advertise(&mut reflected, &context, session(), &manifest).unwrap();
    reflected.header.extensions.insert(super::OFFER_EXTENSION,
        reflected.header.extensions[&delta_chunks::OFFER_EXTENSION].clone());
    assert!(offered(&reflected, &context, session(), &manifest).is_err());
}

#[test]
fn resume_admits_all_missing_without_weakening_legacy_delta_accounting() {
    let (manifest, _) = manifest();
    let request = first_request(&manifest);
    assert!(selected(&request));
    delta_chunks::validate_request(&manifest, &request).unwrap();
    let mut legacy = request.clone();
    legacy.fallback_reason = Some("authenticated_fixed_delta_chunks_v1".to_string());
    assert!(delta_chunks::validate_request(&manifest, &legacy).is_err());
    let mut wrong_count = request.clone();
    wrong_count.shared_chunks = 1;
    assert!(delta_chunks::validate_request(&manifest, &wrong_count).is_err());
    let mut wrong_bytes = request.clone();
    wrong_bytes.missing_bytes -= 1;
    assert!(delta_chunks::validate_request(&manifest, &wrong_bytes).is_err());
    let mut wrong_geometry = request.clone();
    wrong_geometry.missing_chunks[1].entry_offset += 1;
    assert!(delta_chunks::validate_request(&manifest, &wrong_geometry).is_err());
    let mut reordered = request.clone();
    reordered.missing_chunks.swap(0, 1);
    assert!(delta_chunks::validate_request(&manifest, &reordered).is_err());
    let mut all_reused = request;
    all_reused.missing_chunks.clear();
    all_reused.missing_bytes = 0;
    all_reused.shared_chunks = 3;
    delta_chunks::validate_request(&manifest, &all_reused).unwrap();
}

#[test]
fn resume_source_preparation_uses_explicit_authority_under_a_wider_poller() {
    use crate::cx::Cx;
    use crate::cx::cap::{CapSet, CapSetRuntimeMask};
    use crate::runtime::{RootDrainOutcome, RuntimeBuilder};
    use std::time::Duration;

    type NoIo = CapSet<true, true, true, false, true>;
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing-source.bin");
    let runtime = RuntimeBuilder::current_thread().build().unwrap();
    runtime.block_on(async {
        let restricted = {
            let _no_io = Cx::push_restriction(<NoIo as CapSetRuntimeMask>::MASK);
            Cx::current().expect("restricted root authority")
        };
        assert!(!restricted.capabilities().io);
        assert!(Cx::current().unwrap().capabilities().io);
        let config = QuicConfig {
            enable_delta: true,
            ..QuicConfig::default()
                .allow_unauthenticated_for_trusted_transport()
                .with_delta_control_auth(SecurityContext::for_testing(138))
        };
        // A missing source would ordinarily produce a filesystem error before
        // connecting. The explicit owner must refuse before that lookup, even
        // though the polling task itself could perform it.
        let error = super::super::send_path_with_options(
            &restricted,
            "127.0.0.1:9".parse().unwrap(),
            &missing,
            config,
            "resume-authority",
            QuicSendOptions::new().with_resume(true),
        )
        .await
        .expect_err("resume cannot borrow the poller's IO capability");
        assert!(error.to_string().contains("[ASUP-E009]"), "{error}");
        assert!(Cx::current().unwrap().capabilities().io);
    });
    let drained = runtime.shutdown_drained(Duration::from_secs(5));
    assert_eq!(drained.outcome, RootDrainOutcome::Quiescent, "{drained:?}");
}
