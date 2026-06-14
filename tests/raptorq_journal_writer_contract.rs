//! End-to-end contract test for the RaptorQ encode side of the durable trace
//! journal (br-asupersync-raptorq-leverage-3bb2pl.2): real `EncodingPipeline`
//! encode -> journal serialize -> recover, confirming a checkpoint round-trips
//! through the on-disk striped format and is reported recoverable.

#![allow(missing_docs)]

use asupersync::config::EncodingConfig;
use asupersync::trace::raptorq_journal::{epoch_is_complete, latest_complete_epoch, scan_frames};
use asupersync::trace::raptorq_journal_writer::{
    encode_and_serialize_epoch, encode_checkpoint_blocks,
};

#[test]
fn real_raptorq_encode_serialize_recover_round_trips() {
    let data = vec![0xABu8; 2000];
    let config = EncodingConfig::default(); // symbol_size 256
    let (stripes, manifest) = encode_and_serialize_epoch(42, &data, config, 4, 3, 0)
        .expect("encode ok")
        .expect("nonzero stripe count");
    assert_eq!(stripes.len(), 3);

    // Concatenate every stripe, scan back the frames, and confirm the epoch is
    // fully recoverable per its manifest (every declared block has >= K' symbols).
    let mut all = Vec::new();
    for stripe in &stripes {
        all.extend_from_slice(stripe);
    }
    let (frames, consumed) = scan_frames(&all);
    assert_eq!(consumed, all.len());
    assert!(!frames.is_empty());
    assert!(epoch_is_complete(&frames, manifest));
    assert_eq!(latest_complete_epoch(&frames, &[manifest]), Some(42));
}

#[test]
fn encode_checkpoint_blocks_emits_source_and_repair_symbols() {
    let data = vec![7u8; 1500];
    let blocks =
        encode_checkpoint_blocks(9, &data, EncodingConfig::default(), 3).expect("encode ok");
    assert!(!blocks.is_empty());

    for block in &blocks {
        // K' source symbols are required to decode; total carries repair on top.
        assert!(block.source_symbol_count >= 1);
        assert!(block.symbols.len() as u32 >= block.source_symbol_count);
        // repair_count = 3 was requested, so total exceeds the source count.
        assert!(block.symbols.len() as u32 > block.source_symbol_count);
        // Every emitted symbol carries a payload.
        assert!(block.symbols.iter().all(|(_, payload)| !payload.is_empty()));
    }
}
