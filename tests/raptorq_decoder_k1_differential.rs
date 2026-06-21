//! Differential coverage for the K=1 RaptorQ decoder path.
//!
//! The tests compare asupersync's inactivation decoder against the
//! `raptorq` crate for one-symbol source blocks plus repair-symbol
//! recovery paths.

use std::collections::BTreeSet;

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::rfc6330::rand as rfc_rand;
use asupersync::raptorq::systematic::SystematicEncoder;
use raptorq::{
    Decoder as RaptorqRsDecoder, EncodingPacket as RaptorqRsEncodingPacket,
    ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
    PayloadId as RaptorqRsPayloadId,
};

#[derive(Clone, Copy)]
enum PacketSelection {
    Source(usize),
    Repair(u32),
}

fn make_source_data(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|symbol_idx| {
            (0..symbol_size)
                .map(|byte_idx| (((symbol_idx + 1) * 73 + byte_idx * 29 + 11) % 256) as u8)
                .collect()
        })
        .collect()
}

fn pick_unique_drop_indices_from_draws(
    k: usize,
    draw_count: usize,
    unique_target: usize,
    seed: u32,
) -> Vec<usize> {
    assert!(
        unique_target <= k,
        "drop target must fit inside the source block"
    );
    let limit = u32::try_from(k).expect("K must fit in u32");
    let mut drops = BTreeSet::new();
    for draw in 0..draw_count {
        let draw_u32 = u32::try_from(draw).expect("draw index must fit in u32");
        let idx = usize::try_from(rfc_rand(
            seed.wrapping_add(draw_u32),
            (draw % 251) as u8,
            limit,
        ))
        .expect("drop draw must fit in usize");
        drops.insert(idx);
        if drops.len() == unique_target {
            break;
        }
    }
    assert_eq!(
        drops.len(),
        unique_target,
        "draw schedule must produce the requested number of unique drops"
    );
    drops.into_iter().collect()
}

fn build_received_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    drop_indices: &[usize],
    repair_count: usize,
) -> Vec<ReceivedSymbol> {
    let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();
    let mut received = decoder.constraint_symbols();

    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            received.push(ReceivedSymbol::source(
                u32::try_from(esi).expect("source ESI must fit in u32"),
                data.clone(),
            ));
        }
    }

    let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");
    for repair_offset in 0..repair_count {
        let esi = k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
        let (cols, coefs) = decoder
            .repair_equation(esi)
            .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"));
        received.push(ReceivedSymbol::repair(
            esi,
            cols,
            coefs,
            encoder.repair_symbol(esi),
        ));
    }

    received
}

fn reference_decode_with_raptorq_rs(
    source: &[Vec<u8>],
    encoder: &SystematicEncoder,
    drop_indices: &[usize],
    repair_count: usize,
) -> Vec<u8> {
    let transfer_length = source
        .len()
        .checked_mul(source[0].len())
        .expect("transfer length overflow");
    let symbol_size =
        u16::try_from(source[0].len()).expect("symbol size must fit in u16 for raptorq-rs");
    let config =
        RaptorqRsObjectTransmissionInformation::new(transfer_length as u64, symbol_size, 1, 1, 1);
    let mut decoder = RaptorqRsDecoder::new(config);
    let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();
    for (esi, data) in source.iter().enumerate() {
        if !dropped.contains(&esi) {
            let esi_u32 = u32::try_from(esi).expect("source ESI must fit in u32");
            let packet =
                RaptorqRsEncodingPacket::new(RaptorqRsPayloadId::new(0, esi_u32), data.clone());
            if let Some(decoded) = decoder.decode(packet) {
                return decoded;
            }
        }
    }

    let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");
    for repair_offset in 0..repair_count {
        let esi = k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
        let packet = RaptorqRsEncodingPacket::new(
            RaptorqRsPayloadId::new(0, esi),
            encoder.repair_symbol(esi),
        );
        if let Some(decoded) = decoder.decode(packet) {
            return decoded;
        }
    }

    panic!("raptorq-rs reference decode must succeed for this differential repair case");
}

fn build_received_symbols_from_selection(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    selection: &[PacketSelection],
) -> Vec<ReceivedSymbol> {
    let mut received = decoder.constraint_symbols();

    for packet in selection {
        match *packet {
            PacketSelection::Source(esi) => {
                received.push(ReceivedSymbol::source(
                    u32::try_from(esi).expect("source ESI must fit in u32"),
                    source[esi].clone(),
                ));
            }
            PacketSelection::Repair(esi) => {
                let (cols, coefs) = decoder
                    .repair_equation(esi)
                    .unwrap_or_else(|err| panic!("repair equation for esi={esi} failed: {err:?}"));
                received.push(ReceivedSymbol::repair(
                    esi,
                    cols,
                    coefs,
                    encoder.repair_symbol(esi),
                ));
            }
        }
    }

    received
}

fn reference_decode_with_raptorq_rs_from_selection(
    source: &[Vec<u8>],
    encoder: &SystematicEncoder,
    selection: &[PacketSelection],
) -> Vec<u8> {
    let transfer_length = source
        .len()
        .checked_mul(source[0].len())
        .expect("transfer length overflow");
    let symbol_size =
        u16::try_from(source[0].len()).expect("symbol size must fit in u16 for raptorq-rs");
    let config =
        RaptorqRsObjectTransmissionInformation::new(transfer_length as u64, symbol_size, 1, 1, 1);
    let mut decoder = RaptorqRsDecoder::new(config);

    for packet in selection {
        let encoding_packet = match *packet {
            PacketSelection::Source(esi) => RaptorqRsEncodingPacket::new(
                RaptorqRsPayloadId::new(0, u32::try_from(esi).expect("source ESI must fit in u32")),
                source[esi].clone(),
            ),
            PacketSelection::Repair(esi) => RaptorqRsEncodingPacket::new(
                RaptorqRsPayloadId::new(0, esi),
                encoder.repair_symbol(esi),
            ),
        };
        if let Some(decoded) = decoder.decode(encoding_packet) {
            return decoded;
        }
    }

    panic!("raptorq-rs reference decode must succeed for this selected packet case");
}

fn assert_case_matches_raptorq_rs(
    k: usize,
    symbol_size: usize,
    seed: u64,
    drop_indices: &[usize],
    repair_count: usize,
    case_name: &str,
) {
    let source = make_source_data(k, symbol_size);
    let encoder =
        SystematicEncoder::new(&source, symbol_size, seed).expect("encoder setup must succeed");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_received_symbols(&decoder, &encoder, &source, drop_indices, repair_count);

    let ours = decoder
        .decode(&received)
        .unwrap_or_else(|err| panic!("{case_name} differential decode must succeed: {err:?}"));
    let reference = reference_decode_with_raptorq_rs(&source, &encoder, drop_indices, repair_count);

    assert_eq!(
        ours.source.concat(),
        reference,
        "our decoder must match raptorq-rs for {case_name}"
    );
    assert_eq!(
        ours.source, source,
        "{case_name} must recover the original source symbols"
    );
}

fn assert_selected_packets_match_raptorq_rs(
    k: usize,
    symbol_size: usize,
    seed: u64,
    selection: &[PacketSelection],
    case_name: &str,
) {
    let source = make_source_data(k, symbol_size);
    let encoder =
        SystematicEncoder::new(&source, symbol_size, seed).expect("encoder setup must succeed");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_received_symbols_from_selection(&decoder, &encoder, &source, selection);

    let ours = decoder
        .decode(&received)
        .unwrap_or_else(|err| panic!("{case_name} differential decode must succeed: {err:?}"));
    let reference = reference_decode_with_raptorq_rs_from_selection(&source, &encoder, selection);

    assert_eq!(
        ours.source.concat(),
        reference,
        "our decoder must match raptorq-rs for {case_name}"
    );
    assert_eq!(
        ours.source, source,
        "{case_name} must recover the original source symbols"
    );
}

#[test]
fn k1_single_repair_matches_raptorq_rs() {
    assert_case_matches_raptorq_rs(
        1,
        32,
        0x6330_0001_u64,
        &[0usize],
        1,
        "the degenerate K=1 single-repair case",
    );
}

#[test]
fn k2_single_erasure_single_repair_matches_raptorq_rs() {
    for missing_symbol in 0..2 {
        let case_name = format!(
            "the degenerate K=2 single-erasure single-repair case with source ESI {missing_symbol} dropped"
        );
        assert_case_matches_raptorq_rs(2, 32, 0x6330_0002_u64, &[missing_symbol], 1, &case_name);
    }
}

#[test]
fn k2_systematic_only_matches_raptorq_rs() {
    assert_selected_packets_match_raptorq_rs(
        2,
        32,
        0x6330_0002_u64,
        &[PacketSelection::Source(0), PacketSelection::Source(1)],
        "the K=2 systematic-only recovery case",
    );
}

#[test]
fn k2_repair_only_matches_raptorq_rs() {
    assert_selected_packets_match_raptorq_rs(
        2,
        32,
        0x6330_0002_u64,
        &[
            PacketSelection::Repair(2),
            PacketSelection::Repair(3),
            PacketSelection::Repair(4),
        ],
        "the K=2 repair-only recovery case",
    );
}

#[test]
fn k10_thirty_percent_loss_matches_raptorq_rs() {
    assert_case_matches_raptorq_rs(
        10,
        64,
        0x6330_0010_u64,
        &[1usize, 4usize, 8usize],
        7,
        "the K=10 mixed source+repair case at 30% packet loss",
    );
}

#[test]
fn k42_thirty_percent_loss_matches_raptorq_rs() {
    let k = 42usize;
    let loss_count = (k * 30).div_ceil(100);
    let repair_count = loss_count + 4;
    let draw_count = k.saturating_mul(16).max(loss_count.saturating_mul(4));
    let drop_indices =
        pick_unique_drop_indices_from_draws(k, draw_count, loss_count, 0xA1B2_C342_u32);
    assert_case_matches_raptorq_rs(
        k,
        64,
        0x6330_042A_u64,
        &drop_indices,
        repair_count,
        "the canonical K=42 mixed source+repair case at 30% packet loss",
    );
}

#[test]
fn k512_five_percent_loss_matches_raptorq_rs() {
    let k = 512usize;
    let loss_count = (k * 5).div_ceil(100);
    let repair_count = loss_count + 24;
    let draw_count = loss_count.saturating_mul(8);
    let drop_indices =
        pick_unique_drop_indices_from_draws(k, draw_count, loss_count, 0xA1B2_C384_u32);
    assert_case_matches_raptorq_rs(
        k,
        4,
        0x6330_4000_u64,
        &drop_indices,
        repair_count,
        "the large K=512 mixed source+repair case at 5% packet loss",
    );
}
