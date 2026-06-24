#![allow(missing_docs)]

use asupersync::atp::delta::{
    ContentAddressedChunkStore, DeltaResyncMode, PersistentChunkManifest,
    apply_delta_resync_transmission, build_delta_resync_transmission, plan_incremental_resync,
    reconstruct_manifest_bytes,
};
use asupersync::atp::delta_subchunk;
use asupersync::atp::reconcile::reconcile_existing_receiver_store_and_reconstruct;

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
