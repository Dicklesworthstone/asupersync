//! Byte-level RaptorQ encode/decode round-trip for the erasure channel
//! (`asupersync-raptorq-leverage-3bb2pl.1`, AC1 byte-level loss tolerance).
//!
//! Closes the gap above the symbol-intake layer: a message is erasure-encoded
//! into `source + repair` [`SymbolFrame`]s via the runtime RaptorQ encoder, a
//! subset is lost, the survivors are collected through a [`MessageReassembler`],
//! and the original bytes are reconstructed byte-identically through the runtime
//! RaptorQ decoder — recovery up to the repair budget, fail-closed below it.
#![allow(missing_docs)]

use asupersync::channel::erasure::{EcConfig, MessageReassembler, SymbolFrame, decode_message};

fn config() -> EcConfig {
    EcConfig {
        symbol_size: 64,
        repair_overhead: 8,
        max_message_size: 1 << 20,
    }
}

#[test]
fn encode_decode_roundtrip_lossless() {
    let cfg = config();
    let message: Vec<u8> = (0..1000u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();

    let enc = cfg.encode_message(0xABCD, &message).expect("encode");
    assert!(
        enc.header.total_symbols > enc.header.source_symbols,
        "encoding must carry repair symbols beyond the source set"
    );
    assert_eq!(enc.frames.len(), enc.header.total_symbols as usize);

    let decoded = decode_message(&enc.header, &enc.frames).expect("decode");
    assert_eq!(
        decoded, message,
        "lossless round-trip must be byte-identical"
    );
}

#[test]
fn encode_decode_recovers_after_loss_within_repair() {
    let cfg = config();
    let message: Vec<u8> = (0..1500u32)
        .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
        .collect();

    let enc = cfg.encode_message(0x55, &message).expect("encode");
    // Drop two distinct symbols — well within the repair budget of 8, leaving
    // ample decode overhead.
    let mut delivered = enc.frames.clone();
    delivered.remove(5);
    delivered.remove(0);
    assert!(delivered.len() >= usize::from(enc.header.source_symbols) + 2);

    let decoded = decode_message(&enc.header, &delivered).expect("decode within margin");
    assert_eq!(
        decoded, message,
        "a message must survive losing symbols within the repair budget"
    );
}

#[test]
fn intake_then_decode_full_receive_path() {
    // The full receive path: lossy/reordered frames -> MessageReassembler
    // (dedup + reorder) -> ready -> decode the held set -> original bytes.
    let cfg = config();
    let message: Vec<u8> = (0..800u32).map(|i| (i % 251) as u8).collect();

    let enc = cfg.encode_message(0x99, &message).expect("encode");
    let mut delivered = enc.frames.clone();
    delivered.remove(2); // lose one symbol
    delivered.reverse(); // deliver out of order

    let mut ra = MessageReassembler::new(&enc.header);
    for frame in &delivered {
        let _ = ra.accept_frame(frame);
    }
    assert!(ra.is_ready(), "survivors past K must be decodable");

    let held: Vec<SymbolFrame> = ra
        .symbols()
        .map(|(esi, bytes)| SymbolFrame::new(enc.header.message_id, esi, bytes.to_vec()))
        .collect();
    let decoded = decode_message(&enc.header, &held).expect("decode the reassembled set");
    assert_eq!(
        decoded, message,
        "the reassembled survivors must decode exactly"
    );
}

#[test]
fn beyond_repair_budget_fails_closed() {
    // Fewer than K symbols can never reconstruct the block: decode must fail
    // closed with a typed error, never return wrong bytes.
    let cfg = EcConfig {
        symbol_size: 64,
        repair_overhead: 2,
        max_message_size: 1 << 20,
    };
    let message: Vec<u8> = (0..2000u32)
        .map(|i| (i.wrapping_mul(13).wrapping_add(1)) as u8)
        .collect();

    let enc = cfg.encode_message(0x11, &message).expect("encode");
    let k = usize::from(enc.header.source_symbols);
    // Keep only K-1 source frames — provably undecodable.
    let too_few: Vec<SymbolFrame> = enc.frames.iter().take(k - 1).cloned().collect();

    let result = decode_message(&enc.header, &too_few);
    assert!(
        result.is_err(),
        "decode must fail closed below K symbols, got {result:?}"
    );
}
