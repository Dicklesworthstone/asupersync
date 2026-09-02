//! Independent RaptorQ vectors: the reference `raptorq` crate encodes, we
//! decode (br-asupersync-gap-raptorq-k2048-interop-creh6g).
//!
//! The RFC 6330 vectors under `scripts/generate_rfc6330_vectors.rs` are
//! self-generated from our own encoder, so a symmetric encoder/decoder bug
//! would pass them. Here the repair symbols come from an implementation we
//! do not control, for K in {10, 100, 1000} (K=2048 is covered by
//! `raptorq_encoder_k2048_differential` in the other direction, at 300+ s).
//!
//! What green proves, per K:
//! - byte-for-byte equality between our `repair_symbol(esi)` and the
//!   reference encoder's repair packet for the same ESI;
//! - our `InactivationDecoder` recovers the original source block from the
//!   surviving reference source packets plus reference repair packets after
//!   dropping `loss` source symbols;
//! - planted negative: flipping one byte of one reference repair packet makes
//!   the decode either fail or recover the wrong bytes (never silently
//!   "succeed" with the right bytes).
//!
//! No-claim: K=10000 and the RFC MUST-list re-verification stay open on the
//! bead; sub-block/alignment variants are not exercised (one source block,
//! alignment 1).

use std::collections::BTreeSet;

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use raptorq::{
    ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
    SourceBlockEncoder as RaptorqRsSourceBlockEncoder,
};

fn make_source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|symbol_idx| {
            (0..symbol_size)
                .map(|byte_idx| ((symbol_idx * 131 + byte_idx * 17 + 5) % 256) as u8)
                .collect()
        })
        .collect()
}

/// Deterministic, spread-out drop set: every `stride`-th symbol until `loss`.
fn drop_set(k: usize, loss: usize) -> BTreeSet<usize> {
    let stride = (k / loss).max(1);
    (0..k).step_by(stride).take(loss).collect()
}

struct ReferenceBlock {
    source: Vec<Vec<u8>>,
    repairs: Vec<(u32, Vec<u8>)>,
}

fn reference_block(k: usize, symbol_size: usize, repair_count: u32) -> ReferenceBlock {
    let source = make_source_symbols(k, symbol_size);
    let bytes = source.concat();
    let config = RaptorqRsObjectTransmissionInformation::new(
        u64::try_from(bytes.len()).expect("transfer length fits u64"),
        u16::try_from(symbol_size).expect("symbol size fits u16"),
        1,
        1,
        1,
    );
    let encoder = RaptorqRsSourceBlockEncoder::new(0, &config, &bytes);
    let repairs = encoder
        .repair_packets(0, repair_count)
        .into_iter()
        .map(|packet| {
            (
                packet.payload_id().encoding_symbol_id(),
                packet.data().to_vec(),
            )
        })
        .collect();
    ReferenceBlock { source, repairs }
}

/// Decode with our decoder from reference packets; returns the recovered
/// source symbols, or `None` when the decoder reports failure.
fn decode_ours(
    k: usize,
    symbol_size: usize,
    seed: u64,
    source: &[Vec<u8>],
    dropped: &BTreeSet<usize>,
    repairs: &[(u32, Vec<u8>)],
) -> Option<Vec<Vec<u8>>> {
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let mut received = decoder.constraint_symbols();
    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(
                u32::try_from(esi).expect("esi fits u32"),
                data.clone(),
            ));
        }
    }
    for (esi, data) in repairs {
        let (cols, coefs) = decoder
            .repair_equation(*esi)
            .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"));
        received.push(ReceivedSymbol::repair(*esi, cols, coefs, data.clone()));
    }
    decoder.decode(&received).ok().map(|decoded| decoded.source)
}

fn check_k(k: usize, symbol_size: usize, loss: usize, seed: u64) {
    let repair_count = u32::try_from(loss + 4).expect("repair count fits u32");
    let block = reference_block(k, symbol_size, repair_count);
    assert_eq!(block.repairs.len(), loss + 4);

    // 1. Our encoder emits the same repair bytes as the reference encoder.
    let ours = SystematicEncoder::new(&block.source, symbol_size, seed)
        .expect("our encoder must accept the block");
    let k_u32 = u32::try_from(k).expect("K fits u32");
    for (offset, (esi, data)) in block.repairs.iter().enumerate() {
        assert_eq!(
            *esi,
            k_u32 + u32::try_from(offset).expect("offset fits u32"),
            "reference repair ESIs start at K"
        );
        assert_eq!(
            &ours.repair_symbol(*esi),
            data,
            "K={k}: repair symbol {esi} differs from the reference encoder"
        );
    }

    // 2. Our decoder recovers the block from reference packets.
    let dropped = drop_set(k, loss);
    assert_eq!(dropped.len(), loss);
    let recovered = decode_ours(
        k,
        symbol_size,
        seed,
        &block.source,
        &dropped,
        &block.repairs,
    )
    .unwrap_or_else(|| panic!("K={k}: decode from reference packets must succeed"));
    assert_eq!(
        recovered, block.source,
        "K={k}: decoded block must equal the original"
    );

    // 3. Planted negative: one corrupted reference repair byte must not
    //    decode to the right bytes.
    let mut corrupted = block.repairs.clone();
    corrupted[loss / 2].1[symbol_size / 2] ^= 0x5A;
    match decode_ours(k, symbol_size, seed, &block.source, &dropped, &corrupted) {
        None => {}
        Some(bytes) => assert_ne!(
            bytes, block.source,
            "K={k}: a corrupted repair symbol must not yield the original block"
        ),
    }
}

#[test]
fn reference_encoder_vectors_k10() {
    check_k(10, 32, 3, 0x6330_0010);
}

#[test]
fn reference_encoder_vectors_k100() {
    check_k(100, 32, 12, 0x6330_0100);
}

#[test]
fn reference_encoder_vectors_k1000() {
    check_k(1000, 16, 40, 0x6330_1000);
}
