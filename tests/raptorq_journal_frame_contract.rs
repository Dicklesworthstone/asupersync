//! Contract tests for the crash-durable RaptorQ trace-journal frame format
//! (br-asupersync-raptorq-leverage-3bb2pl.2).
//!
//! Kept as a focused integration test (not inline lib unit tests) so it links
//! only the asupersync lib and not the conformance dev-dependency, giving a
//! reliable remote proof lane for this slice.

#![allow(missing_docs)]

use asupersync::trace::raptorq_journal::{
    BlockKey, BlockSymbols, EpochManifest, JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
    JOURNAL_FRAME_HEADER_LEN, JOURNAL_FRAME_MAGIC, JOURNAL_FRAME_VERSION, JournalFrame,
    JournalFrameError, StripePlan, crc32, decodable_blocks, epoch_is_complete,
    latest_complete_epoch, latest_recoverable_epoch, scan_frames, serialize_epoch,
    serialize_striped, summarize_blocks,
};

fn sample_frame() -> JournalFrame {
    JournalFrame::new(
        7,
        2,
        5,
        10,
        64,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
        b"checkpoint-symbol-payload".to_vec(),
    )
}

#[test]
fn crc32_matches_canonical_check_vector() {
    // The standard CRC-32/ISO-HDLC check value for the ASCII string "123456789".
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn frame_roundtrips() {
    let frame = sample_frame();
    let encoded = frame.encode();
    assert_eq!(encoded.len(), frame.encoded_len());
    let (decoded, consumed) = JournalFrame::decode(&encoded).expect("decode");
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded, frame);
    assert!(decoded.header.is_checkpoint_boundary());
    assert_eq!(decoded.header.payload_len as usize, frame.payload.len());
}

#[test]
fn scan_recovers_multiple_frames_and_stops_at_a_torn_tail() {
    let mut buf = Vec::new();
    sample_frame().encode_into(&mut buf);
    sample_frame().encode_into(&mut buf);
    let intact = buf.len();
    // Simulate a torn final write: a partial third header.
    buf.extend_from_slice(&JOURNAL_FRAME_MAGIC[..4]);

    let (frames, scanned) = scan_frames(&buf);
    assert_eq!(frames.len(), 2);
    assert_eq!(
        scanned, intact,
        "scanning must stop at the torn tail boundary"
    );
}

#[test]
fn flipped_payload_byte_is_caught() {
    let mut encoded = sample_frame().encode();
    let idx = JOURNAL_FRAME_HEADER_LEN + 1;
    encoded[idx] ^= 0xFF;
    assert_eq!(
        JournalFrame::decode(&encoded),
        Err(JournalFrameError::PayloadChecksumMismatch)
    );
}

#[test]
fn flipped_header_byte_is_caught() {
    let mut encoded = sample_frame().encode();
    encoded[12] ^= 0xFF; // a byte inside the epoch field
    assert_eq!(
        JournalFrame::decode(&encoded),
        Err(JournalFrameError::HeaderChecksumMismatch)
    );
}

#[test]
fn truncated_and_bad_magic_are_rejected() {
    assert_eq!(JournalFrame::decode(&[]), Err(JournalFrameError::Truncated));
    assert_eq!(
        JournalFrame::decode(&[0u8; JOURNAL_FRAME_HEADER_LEN]),
        Err(JournalFrameError::BadMagic)
    );

    let mut short_payload = sample_frame().encode();
    short_payload.truncate(short_payload.len() - 1);
    assert_eq!(
        JournalFrame::decode(&short_payload),
        Err(JournalFrameError::PayloadTruncated)
    );
}

#[test]
fn unsupported_future_version_is_rejected() {
    let mut encoded = sample_frame().encode();
    // Bump the version field (offset 8..10) past the current one and repair the
    // header CRC so the version gate — not the CRC — is what rejects it.
    encoded[8..10].copy_from_slice(&(JOURNAL_FRAME_VERSION + 1).to_be_bytes());
    let fixed = crc32(&encoded[0..40]);
    encoded[40..44].copy_from_slice(&fixed.to_be_bytes());
    assert_eq!(
        JournalFrame::decode(&encoded),
        Err(JournalFrameError::UnsupportedVersion(
            JOURNAL_FRAME_VERSION + 1
        ))
    );
}

fn symbol_frame(epoch: u64, sbn: u32, esi: u32, source_symbol_count: u32) -> JournalFrame {
    JournalFrame::new(
        epoch,
        sbn,
        esi,
        source_symbol_count,
        64,
        0,
        vec![esi as u8; 8],
    )
}

#[test]
fn summarize_and_decodable_blocks_track_symbol_thresholds() {
    let frames = vec![
        // epoch 5, block 0: K'=2, two distinct symbols -> decodable.
        symbol_frame(5, 0, 0, 2),
        symbol_frame(5, 0, 1, 2),
        // epoch 5, block 1: K'=3, only one symbol -> not decodable.
        symbol_frame(5, 1, 0, 3),
        // a duplicate ESI must not inflate the distinct count.
        symbol_frame(5, 0, 1, 2),
    ];

    let summaries = summarize_blocks(&frames);
    assert_eq!(summaries.len(), 2);

    let block0 = summaries
        .iter()
        .find(|b| {
            b.key
                == BlockKey {
                    epoch: 5,
                    source_block_number: 0,
                }
        })
        .expect("block 0 summary");
    assert_eq!(block0.distinct_symbols, 2);
    assert!(block0.is_decodable());

    let block1 = summaries
        .iter()
        .find(|b| {
            b.key
                == BlockKey {
                    epoch: 5,
                    source_block_number: 1,
                }
        })
        .expect("block 1 summary");
    assert_eq!(block1.distinct_symbols, 1);
    assert!(!block1.is_decodable());

    assert_eq!(
        decodable_blocks(&frames),
        vec![BlockKey {
            epoch: 5,
            source_block_number: 0,
        }]
    );
}

#[test]
fn latest_recoverable_epoch_picks_the_highest_fully_recoverable_epoch() {
    let frames = vec![
        // epoch 4: single block fully decodable.
        symbol_frame(4, 0, 0, 1),
        // epoch 7: single block fully decodable (2 of K'=2).
        symbol_frame(7, 0, 0, 2),
        symbol_frame(7, 0, 5, 2),
        // epoch 9: highest epoch, but its block is one symbol short of K'=3.
        symbol_frame(9, 0, 0, 3),
    ];
    // 9 is highest but incomplete; 7 is the highest fully-recoverable epoch.
    assert_eq!(latest_recoverable_epoch(&frames), Some(7));
    assert_eq!(latest_recoverable_epoch(&[]), None);
}

#[test]
fn summarize_blocks_is_deterministically_ordered() {
    // Frames inserted out of order; output must be sorted by (epoch, sbn).
    let frames = vec![
        symbol_frame(9, 3, 0, 1),
        symbol_frame(4, 1, 0, 1),
        symbol_frame(4, 0, 0, 1),
        symbol_frame(9, 1, 0, 1),
    ];
    let keys: Vec<BlockKey> = summarize_blocks(&frames)
        .into_iter()
        .map(|b| b.key)
        .collect();
    assert_eq!(
        keys,
        vec![
            BlockKey {
                epoch: 4,
                source_block_number: 0,
            },
            BlockKey {
                epoch: 4,
                source_block_number: 1,
            },
            BlockKey {
                epoch: 9,
                source_block_number: 1,
            },
            BlockKey {
                epoch: 9,
                source_block_number: 3,
            },
        ]
    );
}

#[test]
fn stripe_plan_round_robins_symbols_evenly() {
    let plan = StripePlan::new(10, 4).expect("nonzero stripes");
    assert_eq!(plan.stripe_count(), 4);
    // Round-robin assignment by encoding position.
    assert_eq!(plan.stripe_of(0), 0);
    assert_eq!(plan.stripe_of(4), 0);
    assert_eq!(plan.stripe_of(9), 1);
    // 10 over 4 -> stripes 0,1 carry 3; stripes 2,3 carry 2.
    assert_eq!(plan.symbols_on_stripe(0), 3);
    assert_eq!(plan.symbols_on_stripe(1), 3);
    assert_eq!(plan.symbols_on_stripe(2), 2);
    assert_eq!(plan.symbols_on_stripe(3), 2);
    assert_eq!(plan.symbols_on_stripe(4), 0); // out of range
    let total: usize = (0..plan.stripe_count())
        .map(|s| plan.symbols_on_stripe(s))
        .sum();
    assert_eq!(total, 10);

    assert_eq!(StripePlan::new(5, 0), None);
}

#[test]
fn stripe_plan_models_worst_case_failure_domain_loss() {
    let plan = StripePlan::new(10, 4).expect("nonzero stripes");
    // Worst case loses the fullest stripes first (the ceil-sized ones).
    assert_eq!(plan.symbols_surviving_loss(0), 10);
    assert_eq!(plan.symbols_surviving_loss(1), 7); // lose one size-3 stripe
    assert_eq!(plan.symbols_surviving_loss(2), 4); // lose both size-3 stripes
    assert_eq!(plan.symbols_surviving_loss(3), 2); // + one size-2 stripe
    assert_eq!(plan.symbols_surviving_loss(4), 0); // all stripes gone

    // With K'=4, the block still decodes after losing any 2 stripes (4 survive)
    // but not after losing 3 (only 2 survive).
    assert!(plan.survives_stripe_loss(4, 2));
    assert!(!plan.survives_stripe_loss(4, 3));
}

#[test]
fn stripe_plan_handles_fewer_symbols_than_stripes() {
    let plan = StripePlan::new(2, 4).expect("nonzero stripes");
    assert_eq!(plan.symbols_on_stripe(0), 1);
    assert_eq!(plan.symbols_on_stripe(1), 1);
    assert_eq!(plan.symbols_on_stripe(2), 0);
    assert_eq!(plan.symbols_surviving_loss(1), 1);
    assert_eq!(plan.symbols_surviving_loss(2), 0);
    assert!(plan.survives_stripe_loss(1, 1));
}

#[test]
fn epoch_manifest_detects_missing_and_undersymboled_blocks() {
    // Epoch 5 declared 3 blocks. Block 0 decodable (K'=1), block 1 decodable
    // (K'=2 with 2 symbols), block 2 wholly missing -> NOT complete.
    let frames = vec![
        symbol_frame(5, 0, 0, 1),
        symbol_frame(5, 1, 0, 2),
        symbol_frame(5, 1, 7, 2),
    ];
    let manifest = EpochManifest {
        epoch: 5,
        source_block_count: 3,
    };
    // latest_recoverable_epoch is satisfied (every *present* block decodes)...
    assert_eq!(latest_recoverable_epoch(&frames), Some(5));
    // ...but the manifest catches the wholly-missing block 2.
    assert!(!epoch_is_complete(&frames, manifest));

    // Drop the manifest's block count to 2 -> now complete.
    assert!(epoch_is_complete(
        &frames,
        EpochManifest {
            epoch: 5,
            source_block_count: 2,
        }
    ));

    // An under-symboled present block also fails completeness.
    let undersymboled = vec![symbol_frame(5, 0, 0, 1), symbol_frame(5, 1, 0, 2)];
    assert!(!epoch_is_complete(
        &undersymboled,
        EpochManifest {
            epoch: 5,
            source_block_count: 2,
        }
    ));
}

#[test]
fn latest_complete_epoch_uses_manifests() {
    let frames = vec![
        // epoch 7: both declared blocks decodable.
        symbol_frame(7, 0, 0, 1),
        symbol_frame(7, 1, 0, 1),
        // epoch 9: only block 0 present; block 1 missing.
        symbol_frame(9, 0, 0, 1),
    ];
    let manifests = [
        EpochManifest {
            epoch: 7,
            source_block_count: 2,
        },
        EpochManifest {
            epoch: 9,
            source_block_count: 2,
        },
    ];
    // 9 is higher but incomplete (missing block 1); 7 is the latest complete.
    assert_eq!(latest_complete_epoch(&frames, &manifests), Some(7));
    assert_eq!(latest_complete_epoch(&frames, &[]), None);
}

fn block_symbols(sbn: u32, k: u32, count: u32) -> BlockSymbols {
    BlockSymbols {
        source_block_number: sbn,
        source_symbol_count: k,
        symbol_size: 8,
        symbols: (0..count).map(|esi| (esi, vec![esi as u8; 8])).collect(),
    }
}

#[test]
fn serialize_epoch_round_trips_multi_block_with_manifest() {
    // Two source blocks: block 0 (K'=2, 3 symbols), block 1 (K'=2, 2 symbols).
    let blocks = [block_symbols(0, 2, 3), block_symbols(1, 2, 2)];
    let (stripes, manifest) =
        serialize_epoch(20, 3, JOURNAL_FLAG_CHECKPOINT_BOUNDARY, &blocks).expect("nonzero stripes");
    assert_eq!(stripes.len(), 3);
    assert_eq!(
        manifest,
        EpochManifest {
            epoch: 20,
            source_block_count: 2,
        }
    );

    // Full recovery: concatenate every stripe, scan, and confirm both declared
    // blocks are complete per the manifest.
    let mut all = Vec::new();
    for stripe in &stripes {
        all.extend_from_slice(stripe);
    }
    let (frames, consumed) = scan_frames(&all);
    assert_eq!(consumed, all.len());
    assert_eq!(frames.len(), 5);
    assert!(epoch_is_complete(&frames, manifest));
    assert_eq!(latest_complete_epoch(&frames, &[manifest]), Some(20));
    assert_eq!(decodable_blocks(&frames).len(), 2);

    assert_eq!(serialize_epoch(20, 0, 0, &blocks), None);
}

#[test]
fn serialize_epoch_incomplete_after_losing_too_many_stripes() {
    // Block 0 has K'=3 with exactly 3 symbols across 3 stripes (one symbol each):
    // losing any stripe drops it below K', so the epoch is no longer complete.
    let blocks = [block_symbols(0, 3, 3)];
    let (stripes, manifest) = serialize_epoch(21, 3, 0, &blocks).expect("nonzero stripes");

    // All stripes -> complete.
    let mut all = Vec::new();
    for stripe in &stripes {
        all.extend_from_slice(stripe);
    }
    let (frames, _) = scan_frames(&all);
    assert!(epoch_is_complete(&frames, manifest));

    // Drop one stripe -> only 2 symbols survive (< K'=3) -> incomplete.
    let mut survivors = Vec::new();
    for stripe in &stripes[1..] {
        survivors.extend_from_slice(stripe);
    }
    let (survivor_frames, _) = scan_frames(&survivors);
    assert!(!epoch_is_complete(&survivor_frames, manifest));
    assert_eq!(latest_complete_epoch(&survivor_frames, &[manifest]), None);
}

#[test]
fn serialize_striped_round_trips_and_survives_stripe_loss() {
    // 5 encoding symbols for one block, K'=3, striped across 3 files.
    let symbols: Vec<(u32, Vec<u8>)> = (0..5u32).map(|esi| (esi, vec![esi as u8; 8])).collect();
    let plan = StripePlan::new(symbols.len(), 3).expect("nonzero stripes");
    let stripes = serialize_striped(
        11,
        0,
        3,
        8,
        JOURNAL_FLAG_CHECKPOINT_BOUNDARY,
        &symbols,
        &plan,
    );
    assert_eq!(stripes.len(), 3);

    // Full round-trip: concatenate all stripes, scan, recover the block.
    let mut all = Vec::new();
    for stripe in &stripes {
        all.extend_from_slice(stripe);
    }
    let (frames, consumed) = scan_frames(&all);
    assert_eq!(consumed, all.len());
    assert_eq!(frames.len(), 5);
    assert_eq!(
        decodable_blocks(&frames),
        vec![BlockKey {
            epoch: 11,
            source_block_number: 0,
        }]
    );

    // Lose stripe 0 (a fullest stripe): the remaining stripes must still carry
    // exactly the worst-case survivor count the plan predicts, and >= K'.
    let mut survivors = Vec::new();
    for stripe in &stripes[1..] {
        survivors.extend_from_slice(stripe);
    }
    let (survivor_frames, _) = scan_frames(&survivors);
    assert_eq!(survivor_frames.len(), plan.symbols_surviving_loss(1));
    assert!(plan.survives_stripe_loss(3, 1));
    let surviving_block = &summarize_blocks(&survivor_frames)[0];
    assert!(surviving_block.is_decodable());
}
