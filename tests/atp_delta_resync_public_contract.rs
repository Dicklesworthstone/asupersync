#![allow(missing_docs)]

use asupersync::atp::dedupe::build_canonical_dedup_payload_parts_if_smaller;
use asupersync::atp::delta::{
    ContentAddressedChunkStore, DeltaError, DeltaResyncFallbackReason, DeltaResyncMode,
    DeltaResyncSendItem, PersistentChunkManifest, ReceiverCasCoverage,
    apply_delta_resync_send_plan, apply_delta_resync_transmission, build_delta_resync_send_plan,
    build_delta_resync_transmission, build_receiver_subchunk_signatures, decode_subdelta_ops,
    encode_subdelta_ops, plan_incremental_resync, plan_incremental_resync_with_receiver_coverage,
    reconstruct_manifest_bytes,
};
use asupersync::atp::delta_subchunk;
use asupersync::atp::reconcile::{
    reconcile_canonical_dedup_parts_and_reconstruct,
    reconcile_existing_receiver_store_and_reconstruct,
};

fn pattern_bytes(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| ((idx * seed + idx / 7 + seed * 13) % 251) as u8)
        .collect()
}

fn fixed_chunks(bytes: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    bytes.chunks(chunk_size).collect()
}

fn manifest(
    store: &mut ContentAddressedChunkStore,
    tree_id: &str,
    chunks: Vec<&[u8]>,
) -> PersistentChunkManifest {
    let report = store
        .ingest_ordered_chunks(chunks)
        .expect("ingest ordered chunks");
    PersistentChunkManifest::new(tree_id, report.chunks).expect("persistent manifest")
}

#[test]
fn public_delta_transmission_keeps_scattered_one_percent_edits_on_wire_path() {
    let chunk_size = 64 * 1024;
    let old = pattern_bytes(8 * chunk_size, 37);
    let mut new = old.clone();
    for edit in 0..(new.len() / 100) {
        let pos = (edit * 7_919 + 104_729) % new.len();
        new[pos] ^= 0xa5;
    }

    let mut sender_store = ContentAddressedChunkStore::new();
    let mut receiver_store = ContentAddressedChunkStore::new();
    let sender = manifest(
        &mut sender_store,
        "scattered-one-percent",
        fixed_chunks(&new, chunk_size),
    );
    let receiver = manifest(
        &mut receiver_store,
        "scattered-one-percent",
        fixed_chunks(&old, chunk_size),
    );

    let transmission = build_delta_resync_transmission(
        &sender,
        &sender_store,
        Some(&receiver),
        &receiver_store,
        delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
    )
    .expect("build scattered-edit transmission");

    assert!(transmission.uses_delta_wire_payload());
    assert_eq!(transmission.plan.mode, DeltaResyncMode::DeltaChunks);
    let wire_payload = transmission
        .wire_payload
        .as_ref()
        .expect("delta wire payload");
    assert_eq!(wire_payload.subchunk_count, sender.chunks.len());
    assert_eq!(wire_payload.whole_chunk_count, 0);
    assert!(wire_payload.beats_full_object(sender.total_size_bytes));

    let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
        .expect("apply scattered-edit transmission")
        .expect("delta apply report");
    assert_eq!(applied.reconstructed_bytes, new);
    assert_eq!(applied.subchunk_count, sender.chunks.len());
    assert_eq!(applied.whole_chunk_count, 0);
    assert_eq!(applied.wire_payload_bytes, wire_payload.wire_payload_bytes);
}

#[test]
fn public_append_resync_uses_compact_whole_chunk_run_wire_overhead() {
    let base = pattern_bytes(64 * 1024, 17);
    let append_a = pattern_bytes(32 * 1024, 23);
    let append_b = pattern_bytes(32 * 1024, 29);
    let append_c = pattern_bytes(16 * 1024, 31);

    let mut sender_store = ContentAddressedChunkStore::new();
    let mut receiver_store = ContentAddressedChunkStore::new();
    let sender = manifest(
        &mut sender_store,
        "append-file",
        vec![
            base.as_slice(),
            append_a.as_slice(),
            append_b.as_slice(),
            append_c.as_slice(),
        ],
    );
    let receiver = manifest(&mut receiver_store, "append-file", vec![base.as_slice()]);

    let transmission = build_delta_resync_transmission(
        &sender,
        &sender_store,
        Some(&receiver),
        &receiver_store,
        delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
    )
    .expect("build append transmission");

    assert!(transmission.uses_delta_wire_payload());
    let wire_payload = transmission
        .wire_payload
        .as_ref()
        .expect("append delta wire payload");
    assert_eq!(wire_payload.whole_chunk_count, 3);
    assert_eq!(wire_payload.subchunk_count, 0);
    assert_eq!(wire_payload.payload_bytes, wire_payload.whole_chunk_bytes);
    assert!(
        wire_payload.wire_payload_bytes <= wire_payload.payload_bytes + 192,
        "append whole-chunk runs should not reintroduce per-chunk framing overhead"
    );

    let applied = apply_delta_resync_transmission(&sender, &receiver_store, &transmission)
        .expect("apply append transmission")
        .expect("delta apply report");
    assert_eq!(
        applied.reconstructed_bytes,
        [
            base.as_slice(),
            append_a.as_slice(),
            append_b.as_slice(),
            append_c.as_slice()
        ]
        .concat()
    );
    assert_eq!(applied.whole_chunk_count, 3);
    assert_eq!(applied.subchunk_count, 0);
}

#[test]
fn public_delta_transmission_falls_back_when_wire_envelope_exceeds_full_object() {
    let shared = pattern_bytes(32, 13);
    let missing = pattern_bytes(4 * 1024, 41);

    let mut sender_store = ContentAddressedChunkStore::new();
    let mut receiver_store = ContentAddressedChunkStore::new();
    let sender = manifest(
        &mut sender_store,
        "wire-envelope-accounting",
        vec![shared.as_slice(), missing.as_slice()],
    );
    let receiver = manifest(
        &mut receiver_store,
        "wire-envelope-accounting",
        vec![shared.as_slice()],
    );

    let chunk_level_plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
    assert_eq!(chunk_level_plan.mode, DeltaResyncMode::DeltaChunks);
    assert!(chunk_level_plan.missing_bytes < sender.total_size_bytes);

    let transmission = build_delta_resync_transmission(
        &sender,
        &sender_store,
        Some(&receiver),
        &receiver_store,
        delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
    )
    .expect("build fallback transmission");

    assert!(transmission.requires_full_object_fallback());
    assert!(!transmission.uses_delta_wire_payload());
    assert_eq!(transmission.full_object_bytes, sender.total_size_bytes);
    assert_eq!(
        transmission.plan.fallback_reason,
        Some(DeltaResyncFallbackReason::DeltaNotSmallerThanFullObject)
    );
}

#[test]
fn public_rename_reorder_resync_reconstructs_from_existing_receiver_store_without_payload() {
    let alpha = pattern_bytes(32 * 1024, 11);
    let beta = pattern_bytes(24 * 1024, 19);
    let gamma = pattern_bytes(40 * 1024, 47);

    let mut sender_store = ContentAddressedChunkStore::new();
    let mut receiver_store = ContentAddressedChunkStore::new();
    let receiver = manifest(
        &mut receiver_store,
        "tree-before-rename",
        vec![alpha.as_slice(), beta.as_slice(), gamma.as_slice()],
    );
    let sender = manifest(
        &mut sender_store,
        "tree-after-rename",
        vec![gamma.as_slice(), alpha.as_slice(), beta.as_slice()],
    );

    let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
    assert_eq!(plan.mode, DeltaResyncMode::DeltaChunks);
    assert!(plan.missing_chunks.is_empty());
    assert_eq!(plan.missing_bytes, 0);

    let report = reconcile_existing_receiver_store_and_reconstruct(&sender, &receiver_store, &plan)
        .expect("zero-payload reorder reconcile");
    assert_eq!(report.compact_wire_bytes, 0);
    assert_eq!(
        report.reconstructed_bytes,
        [gamma.as_slice(), alpha.as_slice(), beta.as_slice()].concat()
    );

    let rebuilt = reconstruct_manifest_bytes(&sender, &report.store).expect("rebuild target");
    assert_eq!(rebuilt, report.reconstructed_bytes);
}

#[test]
fn public_dedup_canonical_parts_send_repeated_missing_payloads_once() {
    let alpha = pattern_bytes(96 * 1024, 41);
    let beta = pattern_bytes(80 * 1024, 43);
    let gamma = pattern_bytes(64 * 1024, 47);
    let expected = [
        alpha.as_slice(),
        beta.as_slice(),
        alpha.as_slice(),
        gamma.as_slice(),
        beta.as_slice(),
        alpha.as_slice(),
    ]
    .concat();

    let mut sender_store = ContentAddressedChunkStore::new();
    let mut receiver_store = ContentAddressedChunkStore::new();
    let sender = manifest(
        &mut sender_store,
        "repeated-missing-file",
        vec![
            alpha.as_slice(),
            beta.as_slice(),
            alpha.as_slice(),
            gamma.as_slice(),
            beta.as_slice(),
            alpha.as_slice(),
        ],
    );
    let receiver = manifest(&mut receiver_store, "repeated-missing-file", Vec::new());

    let plan = plan_incremental_resync(&sender, Some(&receiver), &receiver_store);
    assert_eq!(plan.missing_chunks.len(), 6);
    assert_eq!(plan.missing_bytes, sender.total_size_bytes);

    let parts = build_canonical_dedup_payload_parts_if_smaller(&plan, &sender_store, 128)
        .expect("dedupe parts decision")
        .expect("repeated missing chunks should beat full missing bytes");
    assert_eq!(parts.duplicate_missing_chunks, 3);
    assert_eq!(
        parts.unique_payload_wire_bytes,
        u64::try_from(alpha.len() + beta.len() + gamma.len()).expect("unique payload bytes fit")
    );
    assert!(parts.saves_bytes());
    assert!(
        parts
            .saved_bytes_with_outer_overhead(128)
            .expect("saved bytes")
            > 0
    );

    let payload_set = parts
        .decode_payload_set(&plan)
        .expect("decode canonical parts");
    assert_eq!(payload_set.unique_payload_count(), 3);
    assert_eq!(payload_set.send_set.logical_missing_chunk_count(), 6);

    let report =
        reconcile_canonical_dedup_parts_and_reconstruct(&sender, &receiver_store, &plan, &parts)
            .expect("dedupe canonical reconcile");
    assert_eq!(report.reconstructed_bytes, expected);
    assert_eq!(
        report.unique_payload_wire_bytes,
        parts.unique_payload_wire_bytes
    );
    assert_eq!(report.duplicate_missing_chunks, 3);
    assert_eq!(report.reconcile.unique_payloads, 3);
    assert_eq!(report.reconcile.duplicate_logical_chunks, 3);
}

/// A peer's op count that the stream cannot hold is refused before allocating.
/// It used to reach `Vec::with_capacity` and panic ("capacity overflow"), or
/// abort the process for a count near 2^32 (br-asupersync-w6fnfy F1).
#[test]
fn public_subdelta_decode_refuses_an_op_count_the_bytes_cannot_hold() {
    use delta_subchunk::SubDeltaOp;

    let empty = encode_subdelta_ops(&[]).expect("encode an empty op stream");
    let count_at = empty.len() - 8;
    let mut huge = empty;
    huge[count_at..].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(
        decode_subdelta_ops(&huge),
        Err(DeltaError::TruncatedManifest)
    );

    // Two ops declared, room for one.
    let mut short = encode_subdelta_ops(&[SubDeltaOp::Literal(Vec::new())]).expect("encode");
    short[count_at..count_at + 8].copy_from_slice(&2_u64.to_be_bytes());
    assert_eq!(
        decode_subdelta_ops(&short),
        Err(DeltaError::TruncatedManifest)
    );

    // The smallest ops at the boundary still decode.
    let ops = vec![SubDeltaOp::Literal(Vec::new()); 3];
    let encoded = encode_subdelta_ops(&ops).expect("encode");
    assert_eq!(decode_subdelta_ops(&encoded).expect("decode"), ops);
}

/// Sub-delta ops that build more than the target chunk are refused before
/// they run, even when the peer's target hash matches the oversized output:
/// a few op bytes could otherwise make the receiver build and store
/// gigabytes per item (br-asupersync-w6fnfy F2).
#[test]
fn public_subdelta_output_must_be_exactly_the_target_chunk_size() {
    use delta_subchunk::SubDeltaOp;
    use sha2::{Digest, Sha256};

    let old = pattern_bytes(64 * 1024, 17);
    let mut new = old.clone();
    for byte in &mut new[24 * 1024..25 * 1024] {
        *byte ^= 0x5a;
    }
    let mut sender_store = ContentAddressedChunkStore::new();
    let mut receiver_store = ContentAddressedChunkStore::new();
    let sender = manifest(&mut sender_store, "tree-a", vec![new.as_slice()]);
    let receiver = manifest(&mut receiver_store, "tree-a", vec![old.as_slice()]);
    let base_plan = plan_incremental_resync_with_receiver_coverage(
        &sender,
        Some(&receiver),
        &ReceiverCasCoverage::from_manifest(&receiver),
    );
    let signatures = build_receiver_subchunk_signatures(
        &receiver,
        &receiver_store,
        delta_subchunk::DEFAULT_SUBBLOCK_BYTES,
    )
    .expect("receiver signatures");
    let mut send_plan =
        build_delta_resync_send_plan(&base_plan, &sender_store, &receiver, &signatures)
            .expect("send plan");
    let Some(DeltaResyncSendItem::SubchunkOps {
        target_chunk,
        base_chunk,
        target_sha256,
        encoded_ops,
    }) = send_plan.items.first_mut()
    else {
        panic!("expected a sub-chunk op stream");
    };
    let target_index = target_chunk.index;
    let target_size = target_chunk.size_bytes;
    let base_len = u32::try_from(base_chunk.size_bytes).expect("base chunk length");
    let ops = vec![
        SubDeltaOp::Copy {
            old_offset: 0,
            len: base_len,
        };
        3
    ];
    *encoded_ops = encode_subdelta_ops(&ops).expect("encode oversized ops");
    *target_sha256 = Sha256::digest(old.repeat(3)).into();

    assert_eq!(
        apply_delta_resync_send_plan(&sender, &receiver_store, &send_plan),
        Err(DeltaError::ChunkPayloadSizeMismatch {
            index: target_index,
            expected: target_size,
            actual: 3 * u64::from(base_len),
        })
    );
}

/// A peer's signature can give every block one weak checksum. diff tested
/// every such block for every byte window of matching content, so a crafted
/// signature made a sender spend O(windows x blocks). It now finds the
/// contiguous and positional blocks by offset and keeps at most a few others
/// per weak value (br-asupersync-w6fnfy F4).
#[test]
fn public_subchunk_diff_bounds_a_crafted_signatures_weak_fan_out() {
    use delta_subchunk::{SubBlockSignature, SubDeltaOp};
    use std::time::Duration;

    let block = delta_subchunk::DEFAULT_SUBBLOCK_BYTES;
    let honest = serde_json::to_value(delta_subchunk::signature(&vec![0_u8; block], block))
        .expect("serialize a signature");
    let zero_block = honest["blocks"][0].clone();
    let blocks = 200_000_usize;
    let crafted = serde_json::json!({
        "block_size": block,
        "total_len": block * blocks,
        "blocks": (0..blocks)
            .map(|index| {
                let mut entry = zero_block.clone();
                entry["strong"] = serde_json::json!(vec![0xee_u8; 16]);
                entry["offset"] = serde_json::json!(index * block);
                entry
            })
            .collect::<Vec<_>>(),
    });
    let signature: SubBlockSignature = serde_json::from_value(crafted).expect("crafted signature");
    let new = vec![0_u8; 256 * 1024];
    let expected = vec![SubDeltaOp::Literal(new.clone())];

    let (done, finished) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let ops = delta_subchunk::diff(&new, &signature);
        let _ = done.send(());
        ops
    });
    finished
        .recv_timeout(Duration::from_secs(20))
        .expect("diff against the crafted signature finishes within 20 s");
    assert_eq!(worker.join().expect("diff thread"), expected);
}
