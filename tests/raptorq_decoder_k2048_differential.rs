//! Differential decoder conformance for a default-suite large-K case.
//!
//! K=2048 is still covered here as a fast RFC parameter boundary check. The
//! decode differential stays smaller because the full K=2048 reference decoder
//! path is expensive enough to belong in an explicit stress lane, not every
//! release-prep test run.

use std::collections::BTreeSet;

use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::rfc6330::rand as rfc_rand;
use asupersync::raptorq::systematic::SystematicEncoder;
use raptorq::{
    Decoder as RaptorqRsDecoder, EncodingPacket as RaptorqRsEncodingPacket,
    ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
    PayloadId as RaptorqRsPayloadId,
};

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

    panic!("raptorq-rs reference decode must succeed for the large-K case");
}

#[test]
fn k2048_parameters_are_pinned() {
    let k = 2048usize;
    let symbol_size = 16usize;
    let seed = 0x6330_2048_u64;
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let params = decoder.params();
    assert_eq!(params.k, 2048, "K=2048 decoder must preserve K");
    assert_eq!(
        params.k_prime, 2070,
        "K=2048 decoder must pin the rounded RFC row"
    );
    assert_eq!(params.j, 506, "K=2048 decoder must pin the RFC J(K') value");
    assert_eq!(params.s, 89, "K=2048 decoder must pin the RFC S(K') value");
    assert_eq!(params.h, 11, "K=2048 decoder must pin the RFC H(K') value");
    assert_eq!(
        params.w, 2099,
        "K=2048 decoder must pin the RFC W(K') value"
    );
    assert_eq!(params.l, 2170, "K=2048 decoder must pin the RFC L value");
    assert_eq!(params.b, 2010, "K=2048 decoder must pin the RFC B value");
}

#[test]
fn k512_large_k_matches_raptorq_rs() {
    let k = 512usize;
    let symbol_size = 16usize;
    let seed = 0x6330_0512_u64;
    let loss_count = 16usize;
    let repair_count = loss_count + 8;
    let draw_count = loss_count.saturating_mul(16);
    let drop_indices =
        pick_unique_drop_indices_from_draws(k, draw_count, loss_count, 0xA1B2_C248_u32);

    let source = make_source_data(k, symbol_size);
    let encoder =
        SystematicEncoder::new(&source, symbol_size, seed).expect("encoder setup must succeed");
    let decoder = InactivationDecoder::new(k, symbol_size, seed);
    let received = build_received_symbols(&decoder, &encoder, &source, &drop_indices, repair_count);
    let ours = decoder
        .decode(&received)
        .unwrap_or_else(|err| panic!("K=512 large-K decode must succeed: {err:?}"));
    let reference =
        reference_decode_with_raptorq_rs(&source, &encoder, &drop_indices, repair_count);

    assert_eq!(
        ours.source.concat(),
        reference,
        "our decoder must match raptorq-rs for the K=512 large-K differential case"
    );
    assert_eq!(
        ours.source, source,
        "the K=512 large-K differential case must recover the original source symbols"
    );
}
