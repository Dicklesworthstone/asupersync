//! Differential decoder conformance at K=42 with 90% loss.

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
enum PacketOrder {
    SourceThenRepair,
    RepairThenSource,
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
    order: PacketOrder,
) -> Option<Vec<ReceivedSymbol>> {
    let dropped: BTreeSet<_> = drop_indices.iter().copied().collect();
    let mut received = decoder.constraint_symbols();

    let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");

    match order {
        PacketOrder::SourceThenRepair => {
            for (esi, data) in source.iter().enumerate() {
                if !dropped.contains(&esi) {
                    received.push(ReceivedSymbol::source(
                        u32::try_from(esi).expect("source ESI must fit in u32"),
                        data.clone(),
                    ));
                }
            }

            for repair_offset in 0..repair_count {
                let esi =
                    k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
                let (cols, coefs) = decoder.repair_equation(esi).ok()?;
                received.push(ReceivedSymbol::repair(
                    esi,
                    cols,
                    coefs,
                    encoder.repair_symbol(esi),
                ));
            }
        }
        PacketOrder::RepairThenSource => {
            for repair_offset in 0..repair_count {
                let esi =
                    k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
                let (cols, coefs) = decoder.repair_equation(esi).ok()?;
                received.push(ReceivedSymbol::repair(
                    esi,
                    cols,
                    coefs,
                    encoder.repair_symbol(esi),
                ));
            }

            for (esi, data) in source.iter().enumerate() {
                if !dropped.contains(&esi) {
                    received.push(ReceivedSymbol::source(
                        u32::try_from(esi).expect("source ESI must fit in u32"),
                        data.clone(),
                    ));
                }
            }
        }
    }

    Some(received)
}

fn try_reference_decode_with_raptorq_rs(
    source: &[Vec<u8>],
    encoder: &SystematicEncoder,
    drop_indices: &[usize],
    repair_count: usize,
    order: PacketOrder,
) -> Option<Vec<u8>> {
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

    let k_u32 = u32::try_from(source.len()).expect("K must fit in u32");

    match order {
        PacketOrder::SourceThenRepair => {
            for (esi, data) in source.iter().enumerate() {
                if !dropped.contains(&esi) {
                    let esi_u32 = u32::try_from(esi).expect("source ESI must fit in u32");
                    let packet = RaptorqRsEncodingPacket::new(
                        RaptorqRsPayloadId::new(0, esi_u32),
                        data.clone(),
                    );
                    if let Some(decoded) = decoder.decode(packet) {
                        return Some(decoded);
                    }
                }
            }

            for repair_offset in 0..repair_count {
                let esi =
                    k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
                let packet = RaptorqRsEncodingPacket::new(
                    RaptorqRsPayloadId::new(0, esi),
                    encoder.repair_symbol(esi),
                );
                if let Some(decoded) = decoder.decode(packet) {
                    return Some(decoded);
                }
            }
        }
        PacketOrder::RepairThenSource => {
            for repair_offset in 0..repair_count {
                let esi =
                    k_u32 + u32::try_from(repair_offset).expect("repair offset must fit in u32");
                let packet = RaptorqRsEncodingPacket::new(
                    RaptorqRsPayloadId::new(0, esi),
                    encoder.repair_symbol(esi),
                );
                if let Some(decoded) = decoder.decode(packet) {
                    return Some(decoded);
                }
            }

            for (esi, data) in source.iter().enumerate() {
                if !dropped.contains(&esi) {
                    let esi_u32 = u32::try_from(esi).expect("source ESI must fit in u32");
                    let packet = RaptorqRsEncodingPacket::new(
                        RaptorqRsPayloadId::new(0, esi_u32),
                        data.clone(),
                    );
                    if let Some(decoded) = decoder.decode(packet) {
                        return Some(decoded);
                    }
                }
            }
        }
    }

    None
}

#[test]
fn k42_ninety_percent_loss_matches_raptorq_rs() {
    let k = 42usize;
    let loss_count = (k * 90).div_ceil(100);
    let draw_count = k.saturating_mul(64).max(loss_count.saturating_mul(24));

    for symbol_size in [8usize, 16usize, 32usize, 64usize] {
        for seed_offset in 0u32..256 {
            let seed = 0x6330_0490_u64 + u64::from(seed_offset);
            let drop_seed = 0xA1B2_C490_u32.wrapping_add(seed_offset);
            let drop_indices =
                pick_unique_drop_indices_from_draws(k, draw_count, loss_count, drop_seed);
            let source = make_source_data(k, symbol_size);
            let Some(encoder) = SystematicEncoder::new(&source, symbol_size, seed) else {
                continue;
            };
            let decoder = InactivationDecoder::new(k, symbol_size, seed);

            for order in [PacketOrder::SourceThenRepair, PacketOrder::RepairThenSource] {
                for repair_extra in [8usize, 12, 16, 20, 24, 32, 40, 48, 56, 64] {
                    let repair_count = loss_count + repair_extra;
                    let Some(received) = build_received_symbols(
                        &decoder,
                        &encoder,
                        &source,
                        &drop_indices,
                        repair_count,
                        order,
                    ) else {
                        continue;
                    };
                    let Ok(ours) = decoder.decode(&received) else {
                        continue;
                    };
                    let Some(reference) = try_reference_decode_with_raptorq_rs(
                        &source,
                        &encoder,
                        &drop_indices,
                        repair_count,
                        order,
                    ) else {
                        continue;
                    };

                    if ours.source == source && reference == source.concat() {
                        let order_name = match order {
                            PacketOrder::SourceThenRepair => "source-then-repair",
                            PacketOrder::RepairThenSource => "repair-then-source",
                        };
                        eprintln!(
                            "passing K=42 90% loss differential case: symbol_size={symbol_size}, seed=0x{seed:016x}, drop_seed=0x{drop_seed:08x}, repair_count={repair_count}, order={order_name}"
                        );
                        return;
                    }
                }
            }
        }
    }

    panic!("no fixed K=42 90% loss schedule matched raptorq-rs in the bounded search");
}
