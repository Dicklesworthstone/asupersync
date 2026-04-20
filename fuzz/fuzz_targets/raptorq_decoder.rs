//! Fuzz target for RaptorQ decoder encoded packet corruption.
//!
//! The harness builds a valid, decodable source block first, then mutates the
//! received source/repair packets at the byte and metadata levels. Corrupted
//! packets must never panic the decoder, and all decode entry points must agree
//! on either:
//! - successful recovery of the original source block, or
//! - the same decode error.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;

const MAX_K: usize = 32;
const MAX_SYMBOL_SIZE: usize = 256;
const MAX_MUTATIONS: usize = 32;
const MAX_PACKET_BYTES: usize = 4096;
const MAX_EXTRA_REPAIRS: usize = 8;

#[derive(Debug, Arbitrary)]
struct DecoderPacketInput {
    k: u8,
    symbol_size: u16,
    seed: u64,
    extra_repairs: u8,
    missing_sources: Vec<u8>,
    packet_bytes: Vec<u8>,
    mutations: Vec<PacketMutation>,
    reorder: PacketReorder,
    wavefront_batch: u8,
    object_id: u128,
}

#[derive(Debug, Clone, Arbitrary)]
struct PacketMutation {
    target: u8,
    kind: MutationKind,
}

#[derive(Debug, Clone, Arbitrary)]
enum MutationKind {
    FlipPayload { offset: u16, mask: u8 },
    TruncatePayload { keep: u16 },
    ExtendPayload { extra: u8, fill: u8 },
    TogglePacketKind,
    ForceOversizedEsi { high_bits: u8 },
    ShiftEsi { delta: u16 },
    CorruptSourceEquation { column: u16 },
    CorruptRepairColumn { add: u16 },
    DropCoefficient,
    AddCoefficient { coefficient: u8 },
    DropAllColumns,
    DuplicatePacket,
    DuplicateWithPayloadCorruption { offset: u16, mask: u8 },
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum PacketReorder {
    Preserve,
    Reverse,
    Rotate { by: u8 },
    SortByEsi,
}

impl DecoderPacketInput {
    fn normalize(&mut self) {
        self.k = ((self.k as usize % MAX_K) + 1) as u8;
        self.symbol_size = ((self.symbol_size as usize % MAX_SYMBOL_SIZE) + 1) as u16;
        self.extra_repairs = (self.extra_repairs as usize % (MAX_EXTRA_REPAIRS + 1)) as u8;
        self.packet_bytes.truncate(MAX_PACKET_BYTES);
        self.mutations.truncate(MAX_MUTATIONS);
    }
}

fn build_source_block(
    packet_bytes: &[u8],
    k: usize,
    symbol_size: usize,
    seed: u64,
) -> Vec<Vec<u8>> {
    let mut source = Vec::with_capacity(k);
    let salt = seed.to_le_bytes();

    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let patterned = ((row * 37 + col * 13 + 0x5A) & 0xFF) as u8;
            let mixed = if packet_bytes.is_empty() {
                patterned ^ salt[(row + col) % salt.len()]
            } else {
                let idx = (row * symbol_size + col) % packet_bytes.len();
                packet_bytes[idx] ^ patterned ^ salt[(idx + row + col) % salt.len()]
            };
            symbol.push(mixed);
        }
        source.push(symbol);
    }

    source
}

fn build_valid_packets(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    missing_sources: &[u8],
    extra_repairs: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut missing = vec![false; k];
    let missing_cap = (k / 2).max(1);

    for &index in missing_sources.iter().take(missing_cap) {
        missing[index as usize % k] = true;
    }

    let missing_count = missing.iter().filter(|&&is_missing| is_missing).count();
    let repair_count = missing_count.max(1).saturating_add(extra_repairs);

    let mut packets = Vec::with_capacity(k + repair_count);
    for (esi, data) in source.iter().enumerate() {
        if !missing[esi] {
            packets.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }

    for repair_offset in 0..repair_count {
        let esi = k as u32 + repair_offset as u32;
        let (columns, coefficients) = decoder.repair_equation(esi);
        let data = encoder.repair_symbol(esi);
        packets.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }

    packets
}

fn apply_reorder(packets: &mut [ReceivedSymbol], reorder: PacketReorder) {
    match reorder {
        PacketReorder::Preserve => {}
        PacketReorder::Reverse => packets.reverse(),
        PacketReorder::Rotate { by } => {
            let len = packets.len();
            if len > 0 {
                packets.rotate_left(by as usize % len);
            }
        }
        PacketReorder::SortByEsi => packets.sort_by_key(|packet| (packet.esi, packet.is_source)),
    }
}

fn apply_mutations(packets: &mut Vec<ReceivedSymbol>, mutations: &[PacketMutation]) {
    for mutation in mutations {
        if packets.is_empty() {
            return;
        }
        let idx = mutation.target as usize % packets.len();

        match mutation.kind.clone() {
            MutationKind::FlipPayload { offset, mask } => {
                let packet = &mut packets[idx];
                if !packet.data.is_empty() {
                    let byte = offset as usize % packet.data.len();
                    packet.data[byte] ^= mask;
                }
            }
            MutationKind::TruncatePayload { keep } => {
                let packet = &mut packets[idx];
                let new_len = keep as usize % (packet.data.len().saturating_add(1));
                packet.data.truncate(new_len);
            }
            MutationKind::ExtendPayload { extra, fill } => {
                let packet = &mut packets[idx];
                let growth = (extra as usize % 16).saturating_add(1);
                packet
                    .data
                    .extend(std::iter::repeat_n(fill, growth));
            }
            MutationKind::TogglePacketKind => {
                let packet = &mut packets[idx];
                packet.is_source = !packet.is_source;
            }
            MutationKind::ForceOversizedEsi { high_bits } => {
                let packet = &mut packets[idx];
                packet.esi |= (1u32 << 24) | ((high_bits as u32) << 16);
            }
            MutationKind::ShiftEsi { delta } => {
                let packet = &mut packets[idx];
                packet.esi = packet.esi.wrapping_add(delta as u32 + 1);
            }
            MutationKind::CorruptSourceEquation { column } => {
                let packet = &mut packets[idx];
                packet.columns = vec![column as usize];
                packet.coefficients = vec![Gf256::ONE];
            }
            MutationKind::CorruptRepairColumn { add } => {
                let packet = &mut packets[idx];
                if let Some(first) = packet.columns.first_mut() {
                    *first = first.saturating_add(add as usize + 1);
                } else {
                    packet.columns.push(add as usize + 1);
                    packet.coefficients.push(Gf256::ONE);
                }
            }
            MutationKind::DropCoefficient => {
                let packet = &mut packets[idx];
                let _ = packet.coefficients.pop();
            }
            MutationKind::AddCoefficient { coefficient } => {
                let packet = &mut packets[idx];
                packet.coefficients.push(Gf256(coefficient));
            }
            MutationKind::DropAllColumns => {
                let packet = &mut packets[idx];
                packet.columns.clear();
                packet.coefficients.clear();
            }
            MutationKind::DuplicatePacket => {
                let duplicate = packets[idx].clone();
                packets.push(duplicate);
            }
            MutationKind::DuplicateWithPayloadCorruption { offset, mask } => {
                let mut duplicate = packets[idx].clone();
                if duplicate.data.is_empty() {
                    duplicate.data.push(mask);
                } else {
                    let byte = offset as usize % duplicate.data.len();
                    duplicate.data[byte] ^= mask;
                }
                packets.push(duplicate);
            }
        }
    }
}

fn combine_symbols(
    decoder: &InactivationDecoder,
    payload_packets: &[ReceivedSymbol],
) -> Vec<ReceivedSymbol> {
    let mut received = decoder.constraint_symbols();
    received.extend_from_slice(payload_packets);
    received
}

fn assert_decode_consensus(
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
    expected_source: &[Vec<u8>],
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    let direct = decoder.decode(received);
    let wavefront = decoder.decode_wavefront(received, wavefront_batch);
    let proof = decoder.decode_with_proof(received, object_id, 0);

    match (&direct, &wavefront) {
        (Ok(lhs), Ok(rhs)) => {
            assert_eq!(
                lhs.source, rhs.source,
                "wavefront decode diverged from direct decode"
            );
        }
        (Err(lhs), Err(rhs)) => {
            assert_eq!(lhs, rhs, "wavefront decode diverged from direct error");
        }
        _ => {
            panic!("wavefront decode disagreed on success vs error");
        }
    }

    match (&direct, &proof) {
        (Ok(lhs), Ok(rhs)) => {
            assert_eq!(
                lhs.source, rhs.result.source,
                "proof decode diverged from direct decode"
            );
        }
        (Err(lhs), Err((rhs, _proof))) => {
            assert_eq!(lhs, rhs, "proof decode diverged from direct error");
        }
        _ => {
            panic!("proof decode disagreed on success vs error");
        }
    }

    if let Ok(decoded) = direct {
        assert_eq!(
            decoded.source, expected_source,
            "decoder returned incorrect source data after packet corruption"
        );
    }
}

fn assert_recoverable_or_unrecoverable(err: &DecodeError) {
    assert!(
        err.is_recoverable() || err.is_unrecoverable(),
        "decode error must have a failure class"
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 200_000 {
        return;
    }

    let mut unstructured = Unstructured::new(data);
    let Ok(mut input) = DecoderPacketInput::arbitrary(&mut unstructured) else {
        return;
    };
    input.normalize();

    let k = input.k as usize;
    let symbol_size = input.symbol_size as usize;
    let source = build_source_block(&input.packet_bytes, k, symbol_size, input.seed);
    let Some(encoder) = SystematicEncoder::new(&source, symbol_size, input.seed) else {
        return;
    };
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);

    let baseline_packets = build_valid_packets(
        &decoder,
        &encoder,
        &source,
        &input.missing_sources,
        input.extra_repairs as usize,
    );
    let baseline_received = combine_symbols(&decoder, &baseline_packets);
    let baseline_batch = if baseline_received.is_empty() {
        0
    } else {
        input.wavefront_batch as usize % (baseline_received.len() + 1)
    };
    let object_id = ObjectId::from_u128(input.object_id);

    assert_decode_consensus(&decoder, &baseline_received, &source, baseline_batch, object_id);

    let baseline_result = decoder
        .decode(&baseline_received)
        .expect("baseline received packets must remain decodable");
    assert_eq!(
        baseline_result.source, source,
        "baseline encoded packets must round-trip before corruption"
    );

    let mut corrupted_packets = baseline_packets.clone();
    apply_reorder(&mut corrupted_packets, input.reorder);
    apply_mutations(&mut corrupted_packets, &input.mutations);

    let corrupted_received = combine_symbols(&decoder, &corrupted_packets);
    let corrupted_batch = if corrupted_received.is_empty() {
        0
    } else {
        input.wavefront_batch as usize % (corrupted_received.len() + 1)
    };

    let direct = decoder.decode(&corrupted_received);
    let wavefront = decoder.decode_wavefront(&corrupted_received, corrupted_batch);
    let proof = decoder.decode_with_proof(&corrupted_received, object_id, 0);

    match (&direct, &wavefront) {
        (Ok(lhs), Ok(rhs)) => assert_eq!(
            lhs.source, rhs.source,
            "direct and wavefront decode disagreed on corrupted packets"
        ),
        (Err(lhs), Err(rhs)) => {
            assert_recoverable_or_unrecoverable(lhs);
            assert_recoverable_or_unrecoverable(rhs);
            assert_eq!(
                lhs, rhs,
                "direct and wavefront decode disagreed on corrupted packet error"
            );
        }
        _ => panic!("direct and wavefront decode disagreed on corrupted packet outcome"),
    }

    match (&direct, &proof) {
        (Ok(lhs), Ok(rhs)) => assert_eq!(
            lhs.source, rhs.result.source,
            "direct and proof decode disagreed on corrupted packets"
        ),
        (Err(lhs), Err((rhs, _proof))) => {
            assert_recoverable_or_unrecoverable(lhs);
            assert_recoverable_or_unrecoverable(rhs);
            assert_eq!(
                lhs, rhs,
                "direct and proof decode disagreed on corrupted packet error"
            );
        }
        _ => panic!("direct and proof decode disagreed on corrupted packet outcome"),
    }

    if let Ok(decoded) = direct {
        assert_eq!(
            decoded.source, source,
            "corrupted packets may not decode to incorrect source output"
        );
    }
});

#[cfg(test)]
mod tests {
    use super::{MutationKind, PacketMutation, apply_mutations};
    use asupersync::raptorq::decoder::ReceivedSymbol;

    #[test]
    fn duplicate_with_payload_corruption_keeps_metadata_and_changes_payload() {
        let original = ReceivedSymbol::source(3, vec![0xAA, 0x55, 0x11]);
        let mut packets = vec![original.clone()];

        apply_mutations(
            &mut packets,
            &[PacketMutation {
                target: 0,
                kind: MutationKind::DuplicateWithPayloadCorruption {
                    offset: 1,
                    mask: 0x0F,
                },
            }],
        );

        assert_eq!(packets.len(), 2, "mutation should append a duplicate packet");
        assert_eq!(packets[0].esi, packets[1].esi);
        assert_eq!(packets[0].is_source, packets[1].is_source);
        assert_eq!(packets[0].columns, packets[1].columns);
        assert_eq!(packets[0].coefficients, packets[1].coefficients);
        assert_ne!(
            packets[0].data, packets[1].data,
            "duplicate corruption must actually perturb payload bytes"
        );
        assert_eq!(packets[1].data, vec![0xAA, 0x5A, 0x11]);
    }
}
