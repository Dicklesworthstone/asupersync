//! Differential encoder conformance at the K=2048 large-K boundary.

use std::collections::BTreeSet;

use asupersync::raptorq::rfc6330::rand as rfc_rand;
use asupersync::raptorq::systematic::SystematicEncoder;
use raptorq::{
    Decoder as RaptorqRsDecoder, EncodingPacket as RaptorqRsEncodingPacket,
    ObjectTransmissionInformation as RaptorqRsObjectTransmissionInformation,
    PayloadId as RaptorqRsPayloadId,
};

fn make_source_symbols(k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|symbol_idx| {
            (0..symbol_size)
                .map(|byte_idx| {
                    let value =
                        ((symbol_idx + 1) * 73 + byte_idx * 29 + 11) % (usize::from(u8::MAX) + 1);
                    u8::try_from(value).expect("fixture byte must fit in u8")
                })
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
        let rand_i = u8::try_from(draw % 251).expect("draw selector must fit in u8");
        let idx = usize::try_from(rfc_rand(seed.wrapping_add(draw_u32), rand_i, limit))
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

#[test]
#[ignore = "current blocker: raptorq-rs 1.8.1 does not decode these K=2048 asupersync emissions"]
fn k2048_encoder_emissions_decode_with_raptorq_rs() {
    let k = 2048usize;
    let symbol_size = 16usize;
    let seed = 0x6330_2048_u64;
    let loss_count = 16usize;
    let repair_count = loss_count + 8;
    let draw_count = loss_count.saturating_mul(16);
    let drop_indices =
        pick_unique_drop_indices_from_draws(k, draw_count, loss_count, 0xA1B2_C248_u32);

    let source = make_source_symbols(k, symbol_size);
    let mut encoder =
        SystematicEncoder::new(&source, symbol_size, seed).expect("encoder setup must succeed");
    let params = encoder.params().clone();
    assert_eq!(params.k, k, "K=2048 encoder must preserve source K");
    assert_eq!(
        params.k_prime, 2070,
        "K=2048 encoder must pin the rounded RFC row"
    );
    assert_eq!(params.j, 506, "K=2048 encoder must pin the RFC J(K') value");
    assert_eq!(params.s, 89, "K=2048 encoder must pin the RFC S(K') value");
    assert_eq!(params.h, 11, "K=2048 encoder must pin the RFC H(K') value");
    assert_eq!(
        params.w, 2099,
        "K=2048 encoder must pin the RFC W(K') value"
    );
    assert_eq!(params.l, 2170, "K=2048 encoder must pin the RFC L value");
    assert_eq!(params.b, 2010, "K=2048 encoder must pin the RFC B value");

    let source_bytes = source.concat();
    let transfer_length = u64::try_from(source_bytes.len()).expect("transfer length fits u64");
    let symbol_size_u16 =
        u16::try_from(symbol_size).expect("symbol size must fit in u16 for raptorq-rs");
    let reference_config =
        RaptorqRsObjectTransmissionInformation::new(transfer_length, symbol_size_u16, 1, 1, 1);
    let mut reference_decoder = RaptorqRsDecoder::new(reference_config);

    let systematic = encoder.emit_systematic();
    assert_eq!(
        systematic.len(),
        k,
        "asupersync must emit every K=2048 systematic source symbol"
    );
    let mut decoded = None;
    for symbol in systematic {
        let esi = usize::try_from(symbol.esi).expect("source ESI must fit in usize");
        if drop_indices.contains(&esi) {
            continue;
        }
        assert!(symbol.is_source, "systematic lane must emit source symbols");
        let packet =
            RaptorqRsEncodingPacket::new(RaptorqRsPayloadId::new(0, symbol.esi), symbol.data);
        decoded = reference_decoder.decode(packet);
        if decoded.is_some() {
            break;
        }
    }

    let public_repair_esi_start = u32::try_from(k).expect("K must fit in u32");
    let emitted_repairs = encoder.emit_repair(repair_count);
    assert_eq!(
        emitted_repairs.len(),
        repair_count,
        "asupersync must emit the requested repair count"
    );
    for (offset, symbol) in emitted_repairs.into_iter().enumerate() {
        let offset_u32 = u32::try_from(offset).expect("repair offset must fit in u32");
        assert_eq!(
            symbol.esi,
            public_repair_esi_start + offset_u32,
            "asupersync repair ESI should stay in public K-based ESI space at offset {offset}"
        );
        assert!(
            !symbol.is_source,
            "K=2048 repair emission at offset {offset} must not be marked as source"
        );
        let packet =
            RaptorqRsEncodingPacket::new(RaptorqRsPayloadId::new(0, symbol.esi), symbol.data);
        decoded = reference_decoder.decode(packet);
        if decoded.is_some() {
            break;
        }
    }

    let decoded = decoded.expect("raptorq-rs must decode asupersync K=2048 encoder emissions");
    assert_eq!(
        decoded, source_bytes,
        "raptorq-rs must recover the original K=2048 source bytes from asupersync emissions"
    );
}
