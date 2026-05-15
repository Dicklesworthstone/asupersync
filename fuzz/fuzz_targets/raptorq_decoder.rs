//! Fuzz target for RaptorQ decoder packet corruption and burst-loss recovery.
//!
//! The harness builds a valid, decodable source block first, then mutates the
//! received source/repair packets at the byte and metadata levels. Corrupted
//! packets must never panic the decoder, and all decode entry points must agree
//! on either:
//! - successful recovery of the original source block, or
//! - the same decode error.
//!
//! The same structured input also drives contiguous loss bursts over valid
//! source+repair packets. Whenever at least `K` payload packets survive, decode
//! must still recover the original source block. Dedicated large-K lanes pin
//! exact RFC rows and assert successful recovery from exact `K+overhead`
//! payload budgets under dense and sparse repair schedules. The K=512 lane
//! pins packet-order invariance under a nontrivial reorder before decode.

#![no_main]
#![allow(clippy::too_many_arguments)]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;

use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;

const MAX_SOURCE_BYTES: usize = 64 * 1024;
const LARGE_K_THRESHOLD: usize = 842;
const SMALL_K_CANDIDATES: &[usize] = &[1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33];
const MEDIUM_K_CANDIDATES: &[usize] =
    &[42, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513];
const LARGE_K_CANDIDATES: &[usize] = &[842, 1023, 1024, 1025, 2047, 2048, 2049, 4096, 8192, 16384];
const SMALL_SYMBOL_SIZE_CANDIDATES: &[usize] =
    &[1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256];
const LARGE_SYMBOL_SIZE_CANDIDATES: &[usize] = &[1, 2, 3, 4, 8, 16, 32];
const MAX_MUTATIONS: usize = 32;
const MAX_PACKET_BYTES: usize = 4096;
const MAX_EXTRA_REPAIRS: usize = 8;
const MAX_BURST_WINDOWS: usize = 8;
const MAX_MISSING_SOURCES: usize = 64;
const MAX_REPAIR_SIZE_SELECTORS: usize = 32;

#[derive(Debug, Arbitrary)]
struct DecoderPacketInput {
    k_selector: u16,
    symbol_size_selector: u16,
    seed: u64,
    extra_repairs: u8,
    burst_repair_overhead: u8,
    repair_distribution: RepairDistribution,
    missing_sources: Vec<u8>,
    loss_windows: Vec<LossWindow>,
    packet_bytes: Vec<u8>,
    repair_size_selectors: Vec<u16>,
    mutations: Vec<PacketMutation>,
    reorder: PacketReorder,
    wavefront_batch: u8,
    object_id: u128,
}

#[derive(Debug, Clone, Arbitrary)]
struct LossWindow {
    start: u16,
    len: u16,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum RepairDistribution {
    Dense,
    Sparse { gap_raw: u8 },
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
        let k = select_k_candidate(self.k_selector as usize);
        self.k_selector = u16::try_from(k).expect("fuzz K candidates fit in u16");

        let symbol_size =
            select_symbol_size_candidate(self.symbol_size_selector as usize, k, MAX_SOURCE_BYTES);
        self.symbol_size_selector =
            u16::try_from(symbol_size).expect("fuzz symbol-size candidates fit in u16");

        self.extra_repairs = (self.extra_repairs as usize % (MAX_EXTRA_REPAIRS + 1)) as u8;
        self.burst_repair_overhead =
            (self.burst_repair_overhead as usize % (MAX_EXTRA_REPAIRS + 1)) as u8;
        self.packet_bytes.truncate(MAX_PACKET_BYTES);
        self.repair_size_selectors
            .truncate(MAX_REPAIR_SIZE_SELECTORS);
        self.loss_windows.truncate(MAX_BURST_WINDOWS);
        self.mutations.truncate(MAX_MUTATIONS);
        self.missing_sources.truncate(MAX_MISSING_SOURCES);
    }
}

fn select_k_candidate(selector: usize) -> usize {
    let candidates = match selector % 8 {
        0 | 1 => LARGE_K_CANDIDATES,
        2..=4 => MEDIUM_K_CANDIDATES,
        _ => SMALL_K_CANDIDATES,
    };
    candidates[(selector / 8) % candidates.len()]
}

fn clamp_symbol_size_to_source_budget(
    candidates: &[usize],
    selected: usize,
    k: usize,
    max_source_bytes: usize,
) -> usize {
    let max_symbol_size = (max_source_bytes / k.max(1)).max(1);
    if selected <= max_symbol_size {
        return selected;
    }

    candidates
        .iter()
        .copied()
        .filter(|candidate| *candidate <= max_symbol_size)
        .max()
        .unwrap_or(1)
}

fn select_symbol_size_candidate(selector: usize, k: usize, max_source_bytes: usize) -> usize {
    let candidates = if k >= LARGE_K_THRESHOLD {
        LARGE_SYMBOL_SIZE_CANDIDATES
    } else {
        SMALL_SYMBOL_SIZE_CANDIDATES
    };
    let selected = candidates[selector % candidates.len()];
    clamp_symbol_size_to_source_budget(candidates, selected, k, max_source_bytes)
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
    repair_distribution: RepairDistribution,
) -> Option<Vec<ReceivedSymbol>> {
    let k = source.len();
    let mut missing = vec![false; k];
    let missing_cap = (k / 8).clamp(1, MAX_MISSING_SOURCES);

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

    for esi in build_repair_esi_sequence(k, repair_count, repair_distribution) {
        let Ok((columns, coefficients)) = decoder.repair_equation(esi) else {
            return None;
        };
        let data = encoder.repair_symbol(esi);
        packets.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }

    Some(packets)
}

fn spread_missing_columns(
    seed: u64,
    missing_sources: &[u8],
    k: usize,
    fallback_count: usize,
) -> Vec<usize> {
    let target_count = if missing_sources.is_empty() {
        fallback_count.clamp(1, k)
    } else {
        missing_sources.len().min(k)
    };
    spread_missing_columns_exact_count(seed, missing_sources, k, target_count)
}

fn spread_missing_columns_exact_count(
    seed: u64,
    missing_sources: &[u8],
    k: usize,
    target_count: usize,
) -> Vec<usize> {
    if k == 0 {
        return Vec::new();
    }

    let target_count = target_count.clamp(1, k);
    let start = seed as usize % k;
    let stride = (((seed.rotate_left(17) as usize) | 1) % k.max(2)).max(1);
    let mut used = vec![false; k];
    let mut columns = Vec::with_capacity(target_count);

    for offset in 0..target_count {
        let raw = if missing_sources.is_empty() {
            seed.wrapping_add(offset as u64) as u8
        } else {
            missing_sources[offset % missing_sources.len()]
        };
        let mut candidate =
            (start + offset.saturating_mul(stride) + usize::from(raw).saturating_mul(17)) % k;
        while used[candidate] {
            candidate = (candidate + stride) % k;
        }
        used[candidate] = true;
        columns.push(candidate);
    }

    columns
}

fn build_exact_overhead_packets(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    missing_columns: &[usize],
    ec_overhead: usize,
    repair_distribution: RepairDistribution,
) -> Option<Vec<ReceivedSymbol>> {
    let k = source.len();
    let mut missing = vec![false; k];
    for &column in missing_columns {
        missing[column % k] = true;
    }

    let missing_count = missing.iter().filter(|&&is_missing| is_missing).count();
    let repair_count = missing_count.saturating_add(ec_overhead);
    let mut packets = Vec::with_capacity(k.saturating_add(ec_overhead));

    for (esi, data) in source.iter().enumerate() {
        if !missing[esi] {
            packets.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }

    for esi in build_repair_esi_sequence(k, repair_count, repair_distribution) {
        let Ok((columns, coefficients)) = decoder.repair_equation(esi) else {
            return None;
        };
        let data = encoder.repair_symbol(esi);
        packets.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }

    assert_eq!(
        packets.len(),
        k.saturating_add(ec_overhead),
        "exact-overhead packet builder must preserve the K+overhead payload budget"
    );
    Some(packets)
}

fn sparse_repair_stride(k: usize, gap_raw: u8) -> u32 {
    let base = (k / 64).clamp(2, 32) as u32;
    base + u32::from(gap_raw % 29)
}

fn build_repair_esi_sequence(
    k: usize,
    repair_count: usize,
    repair_distribution: RepairDistribution,
) -> Vec<u32> {
    match repair_distribution {
        RepairDistribution::Dense => (0..repair_count)
            .map(|repair_offset| k as u32 + repair_offset as u32)
            .collect(),
        RepairDistribution::Sparse { gap_raw } => {
            let stride = sparse_repair_stride(k, gap_raw);
            (0..repair_count)
                .map(|repair_offset| k as u32 + repair_offset as u32 * stride)
                .collect()
        }
    }
}

fn repair_stress_missing_sources(missing_sources: &[u8], seed: u64) -> Vec<u8> {
    if !missing_sources.is_empty() {
        return missing_sources.iter().copied().take(16).collect();
    }

    let start = seed as u8;
    (0..16)
        .map(|offset| start.wrapping_add(offset as u8))
        .collect()
}

fn k4_transition_missing_sources(seed: u64, missing_count: usize) -> Vec<u8> {
    let k = 4usize;
    let start = seed as usize % k;
    (0..missing_count.min(k))
        .map(|offset| ((start + offset) % k) as u8)
        .collect()
}

fn k8_low_intermediate_missing_sources(seed: u64, missing_count: usize) -> Vec<u8> {
    let k = 8usize;
    let start = seed as usize % k;
    (0..missing_count.min(k))
        .map(|offset| ((start + offset) % k) as u8)
        .collect()
}

fn k16_low_intermediate_missing_sources(seed: u64, missing_count: usize) -> Vec<u8> {
    let k = 16usize;
    let start = seed as usize % k;
    (0..missing_count.min(k))
        .map(|offset| ((start + offset) % k) as u8)
        .collect()
}

fn burst_repair_count(loss_windows: &[LossWindow], extra_repairs: usize, k: usize) -> usize {
    let requested_loss = loss_windows.iter().fold(0usize, |sum, window| {
        sum.saturating_add(window.len as usize + 1)
    });
    requested_loss.min(k).saturating_add(extra_repairs).max(1)
}

fn apply_contiguous_loss_windows(packets: &mut Vec<ReceivedSymbol>, loss_windows: &[LossWindow]) {
    for window in loss_windows {
        if packets.is_empty() {
            return;
        }

        let start = window.start as usize % packets.len();
        let len = (window.len as usize % packets.len()).saturating_add(1);
        let end = start.saturating_add(len).min(packets.len());
        packets.drain(start..end);
    }
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

fn nontrivial_reorder(reorder: PacketReorder, seed: u64) -> PacketReorder {
    match reorder {
        PacketReorder::Preserve | PacketReorder::SortByEsi => {
            PacketReorder::Rotate { by: seed as u8 | 1 }
        }
        PacketReorder::Rotate { by: 0 } => PacketReorder::Rotate { by: 1 },
        other => other,
    }
}

fn append_duplicate_packets(packets: &mut Vec<ReceivedSymbol>, seed: u64, duplicate_count: usize) {
    if packets.is_empty() {
        return;
    }

    let original_len = packets.len();
    let target = duplicate_count.clamp(1, 8).min(original_len);
    let mut duplicate_indices = Vec::with_capacity(target);

    if let Some(index) = packets.iter().position(|packet| packet.is_source) {
        duplicate_indices.push(index);
    }
    if let Some(index) = packets.iter().position(|packet| !packet.is_source)
        && !duplicate_indices.contains(&index)
        && duplicate_indices.len() < target
    {
        duplicate_indices.push(index);
    }

    let stride = (((seed.rotate_left(9) as usize) | 1) % original_len.max(2)).max(1);
    let mut candidate = seed as usize % original_len;
    while duplicate_indices.len() < target {
        if !duplicate_indices.contains(&candidate) {
            duplicate_indices.push(candidate);
        }
        candidate = (candidate + stride) % original_len;
    }

    for index in duplicate_indices {
        packets.push(packets[index].clone());
    }
}

fn count_duplicate_packets(packets: &[ReceivedSymbol]) -> usize {
    let mut seen = std::collections::BTreeMap::<(u32, bool), usize>::new();
    for packet in packets {
        *seen.entry((packet.esi, packet.is_source)).or_default() += 1;
    }
    seen.values().filter(|count| **count > 1).count()
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
                packet.data.extend(std::iter::repeat_n(fill, growth));
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
                drop_last_coefficient_observed(packet);
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

fn drop_last_coefficient_observed(packet: &mut ReceivedSymbol) {
    let before = packet.coefficients.clone();
    let removed = packet.coefficients.pop();

    if before.is_empty() {
        assert!(
            removed.is_none(),
            "empty coefficient vector should not yield a removed value"
        );
        assert!(
            packet.coefficients.is_empty(),
            "DropCoefficient should leave empty coefficient vectors empty"
        );
        return;
    }

    let expected_removed = before[before.len() - 1];
    assert!(
        removed.is_some_and(|coefficient| coefficient == expected_removed),
        "DropCoefficient should remove the previous last coefficient"
    );
    assert_eq!(
        packet.coefficients.len(),
        before.len() - 1,
        "DropCoefficient should remove exactly one coefficient"
    );
    assert!(
        packet.coefficients.as_slice() == &before[..before.len() - 1],
        "DropCoefficient should preserve the coefficient prefix"
    );
}

fn max_repair_payload_len(symbol_size: usize) -> usize {
    symbol_size
        .saturating_mul(2)
        .saturating_add(1)
        .clamp(1, MAX_PACKET_BYTES)
}

fn select_repair_payload_len(selector: u16, symbol_size: usize, repair_index: usize) -> usize {
    let limit = max_repair_payload_len(symbol_size);
    (usize::from(selector).wrapping_add(repair_index.saturating_mul(symbol_size.saturating_add(1))))
        % (limit.saturating_add(1))
}

fn resize_packet_data(packet: &mut ReceivedSymbol, new_len: usize, fill: u8) {
    if packet.data.len() > new_len {
        packet.data.truncate(new_len);
    } else if packet.data.len() < new_len {
        packet
            .data
            .extend(std::iter::repeat_n(fill, new_len - packet.data.len()));
    }
}

fn apply_mixed_repair_packet_sizes(
    packets: &mut [ReceivedSymbol],
    symbol_size: usize,
    size_selectors: &[u16],
    packet_bytes: &[u8],
    seed: u64,
) -> std::collections::BTreeSet<usize> {
    let repair_indices: Vec<_> = packets
        .iter()
        .enumerate()
        .filter_map(|(idx, packet)| (!packet.is_source).then_some(idx))
        .collect();
    if repair_indices.is_empty() {
        return std::collections::BTreeSet::new();
    }

    for (repair_index, packet_index) in repair_indices.iter().copied().enumerate() {
        let selector = size_selectors
            .get(repair_index)
            .copied()
            .unwrap_or_else(|| {
                seed.wrapping_add((repair_index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)) as u16
            });
        let fill = packet_bytes
            .get(repair_index % packet_bytes.len().max(1))
            .copied()
            .unwrap_or_else(|| seed.rotate_left((repair_index % 63) as u32) as u8);
        let target_len = select_repair_payload_len(selector, symbol_size, repair_index);
        resize_packet_data(&mut packets[packet_index], target_len, fill);
    }

    let mut lengths: std::collections::BTreeSet<_> = repair_indices
        .iter()
        .map(|&idx| packets[idx].data.len())
        .collect();

    if repair_indices.len() > 1 && lengths.len() == 1 {
        let forced_index = repair_indices[1];
        let forced_fill = packet_bytes
            .get(1 % packet_bytes.len().max(1))
            .copied()
            .unwrap_or_else(|| seed.rotate_left(11) as u8);
        let current = packets[forced_index].data.len();
        let limit = max_repair_payload_len(symbol_size);
        let forced_len = if current == 0 {
            1
        } else if current >= limit {
            current.saturating_sub(1)
        } else {
            current + 1
        };
        resize_packet_data(&mut packets[forced_index], forced_len, forced_fill);
        lengths = repair_indices
            .iter()
            .map(|&idx| packets[idx].data.len())
            .collect();
    }

    lengths
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

fn assert_burst_loss_recovers_when_received_at_least_k(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    loss_windows: &[LossWindow],
    extra_repairs: usize,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    let k = source.len();
    let repair_count = burst_repair_count(loss_windows, extra_repairs, k);
    let Some(mut payload_packets) = build_valid_packets(
        decoder,
        encoder,
        source,
        &[],
        repair_count.saturating_sub(1),
        RepairDistribution::Dense,
    ) else {
        return;
    };

    apply_contiguous_loss_windows(&mut payload_packets, loss_windows);
    if payload_packets.len() < k {
        return;
    }

    let received = combine_symbols(decoder, &payload_packets);
    let batch = if received.is_empty() {
        0
    } else {
        wavefront_batch % (received.len() + 1)
    };

    assert_decode_consensus(decoder, &received, source, batch, object_id);
    let decoded = decoder
        .decode(&received)
        .expect("burst-loss payload with at least K surviving packets must decode");
    assert_eq!(
        decoded.source, source,
        "burst-loss payload with at least K surviving packets must recover original source"
    );
}

fn assert_k42_burst_loss_recovers(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 42 {
        return;
    }

    let params = decoder.params();
    assert_eq!(params.k, 42, "K=42 burst oracle must preserve the public K");
    assert_eq!(
        params.k_prime, 42,
        "K=42 burst oracle must stay on the exact RFC boundary row"
    );

    let scenarios = [
        (
            vec![LossWindow {
                start: seed as u16,
                len: 0,
            }],
            1usize,
        ),
        (
            vec![LossWindow {
                start: seed.rotate_left(7) as u16,
                len: 5,
            }],
            2usize,
        ),
        (
            vec![LossWindow {
                start: seed.rotate_left(13) as u16,
                len: 11,
            }],
            3usize,
        ),
        (
            vec![
                LossWindow {
                    start: seed.rotate_left(19) as u16,
                    len: 7,
                },
                LossWindow {
                    start: seed.rotate_left(23) as u16,
                    len: 3,
                },
            ],
            2usize,
        ),
        (
            vec![LossWindow {
                start: seed.rotate_left(29) as u16,
                len: 20,
            }],
            4usize,
        ),
    ];

    for (loss_windows, extra_repairs) in scenarios {
        assert_burst_loss_recovers_when_received_at_least_k(
            decoder,
            encoder,
            source,
            &loss_windows,
            extra_repairs,
            wavefront_batch,
            object_id,
        );
    }
}

fn assert_k42_mixed_repair_packet_sizes_handled(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    missing_sources: &[u8],
    extra_repairs: usize,
    repair_distribution: RepairDistribution,
    repair_size_selectors: &[u16],
    packet_bytes: &[u8],
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 42 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 42,
        "K=42 mixed-size oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 42,
        "K=42 mixed-size oracle must stay on the exact RFC boundary row"
    );

    let effective_missing_sources = repair_stress_missing_sources(missing_sources, seed);
    let Some(mut payload_packets) = build_valid_packets(
        decoder,
        encoder,
        source,
        &effective_missing_sources,
        extra_repairs.saturating_add(4),
        repair_distribution,
    ) else {
        return;
    };

    let repair_count = payload_packets
        .iter()
        .filter(|packet| !packet.is_source)
        .count();
    assert!(
        repair_count > 1,
        "K=42 mixed-size oracle must exercise multiple repair packets"
    );

    let repair_lengths = apply_mixed_repair_packet_sizes(
        &mut payload_packets,
        source[0].len(),
        repair_size_selectors,
        packet_bytes,
        seed,
    );
    assert!(
        repair_lengths.len() > 1,
        "K=42 mixed-size oracle must exercise multiple repair payload lengths"
    );

    let received = combine_symbols(decoder, &payload_packets);
    let batch = if received.is_empty() {
        0
    } else {
        wavefront_batch % (received.len() + 1)
    };

    assert_decode_consensus(decoder, &received, source, batch, object_id);
    if let Err(err) = decoder.decode(&received) {
        assert_recoverable_or_unrecoverable(&err);
    }
}

fn assert_k512_reorder_exact_overhead_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    missing_sources: &[u8],
    ec_overhead: usize,
    repair_distribution: RepairDistribution,
    reorder: PacketReorder,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 512 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 512,
        "K=512 reorder oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 526,
        "K=512 reorder oracle must pin the rounded RFC row"
    );
    assert_eq!(
        params.j, 923,
        "K=512 reorder oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 41,
        "K=512 reorder oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 10,
        "K=512 reorder oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 541,
        "K=512 reorder oracle must pin the RFC W(K') value"
    );
    assert_eq!(
        params.l, 577,
        "K=512 reorder oracle must pin the RFC L value"
    );
    assert_eq!(
        params.b, 500,
        "K=512 reorder oracle must pin the RFC B value"
    );
    assert!(
        params.k_prime > params.k,
        "K=512 reorder oracle must exercise rounded K..K' synthesis"
    );

    let ec_overhead = ec_overhead.saturating_add(8);
    let missing_columns = spread_missing_columns(seed.rotate_left(5), missing_sources, 512, 12);
    let Some(mut payload_packets) = build_exact_overhead_packets(
        decoder,
        encoder,
        source,
        &missing_columns,
        ec_overhead,
        repair_distribution,
    ) else {
        return;
    };

    let repair_count = payload_packets
        .iter()
        .filter(|packet| !packet.is_source)
        .count();
    assert_eq!(
        repair_count,
        missing_columns.len().saturating_add(ec_overhead),
        "K=512 reorder oracle must emit one repair per erasure plus EC overhead"
    );
    assert_eq!(
        payload_packets.len(),
        source.len().saturating_add(ec_overhead),
        "K=512 reorder oracle must keep the received payload budget at K+overhead"
    );

    apply_reorder(
        &mut payload_packets,
        nontrivial_reorder(reorder, seed.rotate_left(31)),
    );
    let received = combine_symbols(decoder, &payload_packets);
    let batch = if received.is_empty() {
        0
    } else {
        wavefront_batch % (received.len() + 1)
    };
    assert_decode_consensus(decoder, &received, source, batch, object_id);
    let decoded = decoder
        .decode(&received)
        .expect("K=512 reordered exact-overhead repair patterns must remain decodable");
    assert_eq!(
        decoded.source, source,
        "K=512 reordered exact-overhead repair patterns must recover original source"
    );
}

fn assert_k4096_burst_loss_recovers(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 4096 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 4096,
        "K=4096 burst oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 4112,
        "K=4096 burst oracle must pin the rounded RFC row"
    );
    assert_eq!(
        params.j, 726,
        "K=4096 burst oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 137,
        "K=4096 burst oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 11,
        "K=4096 burst oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 4159,
        "K=4096 burst oracle must pin the RFC W(K') value"
    );
    assert_eq!(
        params.l, 4260,
        "K=4096 burst oracle must pin the RFC L value"
    );
    assert_eq!(
        params.b, 4022,
        "K=4096 burst oracle must pin the RFC B value"
    );

    let scenarios = [
        (
            vec![LossWindow {
                start: seed as u16,
                len: 0,
            }],
            2usize,
        ),
        (
            vec![LossWindow {
                start: seed.rotate_left(5) as u16,
                len: 31,
            }],
            6usize,
        ),
        (
            vec![LossWindow {
                start: seed.rotate_left(11) as u16,
                len: 255,
            }],
            12usize,
        ),
        (
            vec![LossWindow {
                start: seed.rotate_left(17) as u16,
                len: 511,
            }],
            20usize,
        ),
        (
            vec![
                LossWindow {
                    start: seed.rotate_left(23) as u16,
                    len: 383,
                },
                LossWindow {
                    start: seed.rotate_left(29) as u16,
                    len: 191,
                },
            ],
            24usize,
        ),
    ];

    for (loss_windows, extra_repairs) in scenarios {
        assert_burst_loss_recovers_when_received_at_least_k(
            decoder,
            encoder,
            source,
            &loss_windows,
            extra_repairs,
            wavefront_batch,
            object_id,
        );
    }
}

fn assert_k8192_tail_burst_loss_recovers(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 8192 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 8192,
        "K=8192 burst oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 8194,
        "K=8192 burst oracle must pin the rounded RFC row"
    );
    assert_eq!(
        params.j, 212,
        "K=8192 burst oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 211,
        "K=8192 burst oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 11,
        "K=8192 burst oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 8273,
        "K=8192 burst oracle must pin the RFC W(K') value"
    );
    assert_eq!(
        params.l, 8416,
        "K=8192 burst oracle must pin the RFC L value"
    );
    assert_eq!(
        params.b, 8062,
        "K=8192 burst oracle must pin the RFC B value"
    );

    let tail_start = |tail_offset: usize, jitter: u16| -> u16 {
        source
            .len()
            .saturating_sub(tail_offset)
            .saturating_sub(usize::from(jitter))
            .min(usize::from(u16::MAX)) as u16
    };

    let scenarios = [
        (
            vec![LossWindow {
                start: tail_start(1, seed as u16 % 32),
                len: 0,
            }],
            2usize,
        ),
        (
            vec![LossWindow {
                start: tail_start(64, seed.rotate_left(5) as u16 % 32),
                len: 31,
            }],
            6usize,
        ),
        (
            vec![LossWindow {
                start: tail_start(512, seed.rotate_left(11) as u16 % 64),
                len: 255,
            }],
            12usize,
        ),
        (
            vec![LossWindow {
                start: tail_start(1024, seed.rotate_left(17) as u16 % 128),
                len: 511,
            }],
            20usize,
        ),
        (
            vec![
                LossWindow {
                    start: tail_start(1536, seed.rotate_left(23) as u16 % 128),
                    len: 767,
                },
                LossWindow {
                    start: tail_start(256, seed.rotate_left(29) as u16 % 64),
                    len: 127,
                },
            ],
            28usize,
        ),
    ];

    for (loss_windows, extra_repairs) in scenarios {
        assert_burst_loss_recovers_when_received_at_least_k(
            decoder,
            encoder,
            source,
            &loss_windows,
            extra_repairs,
            wavefront_batch,
            object_id,
        );
    }
}

fn assert_k8192_reorder_and_duplicates_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    missing_sources: &[u8],
    extra_repairs: usize,
    repair_distribution: RepairDistribution,
    reorder: PacketReorder,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 8192 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 8192,
        "K=8192 duplicate oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 8194,
        "K=8192 duplicate oracle must pin the rounded RFC row"
    );
    assert_eq!(
        params.j, 212,
        "K=8192 duplicate oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 211,
        "K=8192 duplicate oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 11,
        "K=8192 duplicate oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 8273,
        "K=8192 duplicate oracle must pin the RFC W(K') value"
    );
    assert_eq!(
        params.l, 8416,
        "K=8192 duplicate oracle must pin the RFC L value"
    );
    assert_eq!(
        params.b, 8062,
        "K=8192 duplicate oracle must pin the RFC B value"
    );

    let ec_overhead = extra_repairs.saturating_add(12);
    let missing_columns =
        spread_missing_columns(seed.rotate_left(7), missing_sources, source.len(), 24);
    let Some(mut payload_packets) = build_exact_overhead_packets(
        decoder,
        encoder,
        source,
        &missing_columns,
        ec_overhead,
        repair_distribution,
    ) else {
        return;
    };

    let duplicate_count = missing_columns.len().clamp(2, 8);
    let baseline_len = payload_packets.len();
    append_duplicate_packets(&mut payload_packets, seed, duplicate_count);
    assert_eq!(
        payload_packets.len(),
        baseline_len.saturating_add(duplicate_count),
        "K=8192 duplicate oracle must append the requested duplicate budget"
    );
    assert!(
        count_duplicate_packets(&payload_packets) >= 2,
        "K=8192 duplicate oracle must include duplicate source and repair packets"
    );

    apply_reorder(&mut payload_packets, nontrivial_reorder(reorder, seed));
    let received = combine_symbols(decoder, &payload_packets);
    let batch = if received.is_empty() {
        0
    } else {
        wavefront_batch % (received.len() + 1)
    };
    assert_decode_consensus(decoder, &received, source, batch, object_id);
    let decoded = decoder
        .decode(&received)
        .expect("K=8192 reordered duplicate packets must remain decodable");
    assert_eq!(
        decoded.source, source,
        "K=8192 reordered duplicate packets must recover original source"
    );
}

fn assert_k842_sparse_vs_dense_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    missing_sources: &[u8],
    extra_repairs: usize,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 842 {
        return;
    }

    let effective_missing_sources = repair_stress_missing_sources(missing_sources, seed);
    let sparse_gap_raw = seed as u8;
    let distribution_extra_repairs = extra_repairs.saturating_add(4);
    for repair_distribution in [
        RepairDistribution::Dense,
        RepairDistribution::Sparse {
            gap_raw: sparse_gap_raw,
        },
    ] {
        let Some(payload_packets) = build_valid_packets(
            decoder,
            encoder,
            source,
            &effective_missing_sources,
            distribution_extra_repairs,
            repair_distribution,
        ) else {
            return;
        };
        let received = combine_symbols(decoder, &payload_packets);
        let batch = if received.is_empty() {
            0
        } else {
            wavefront_batch % (received.len() + 1)
        };
        assert_decode_consensus(decoder, &received, source, batch, object_id);
        let decoded = decoder
            .decode(&received)
            .expect("K=842 sparse/dense repair distributions must remain decodable");
        assert_eq!(
            decoded.source, source,
            "K=842 sparse/dense repair distributions must recover original source"
        );
    }
}

fn assert_k2048_exact_overhead_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    missing_sources: &[u8],
    ec_overhead: usize,
    repair_distribution: RepairDistribution,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 2048 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 2048,
        "K=2048 decoder oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 2070,
        "K=2048 decoder oracle must pin the rounded RFC row"
    );
    assert_eq!(
        params.j, 506,
        "K=2048 decoder oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 89,
        "K=2048 decoder oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 11,
        "K=2048 decoder oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 2099,
        "K=2048 decoder oracle must pin the RFC W(K') value"
    );
    assert_eq!(
        params.l, 2170,
        "K=2048 decoder oracle must pin the RFC L value"
    );
    assert_eq!(
        params.b, 2010,
        "K=2048 decoder oracle must pin the RFC B value"
    );
    assert!(
        params.k_prime > params.k,
        "K=2048 decoder oracle must exercise rounded K..K' synthesis"
    );

    // Large-K repair schedules are only expected to decode once they have some
    // real overhead beyond the raw erasure count.
    let ec_overhead = ec_overhead.saturating_add(4);
    let missing_columns = spread_missing_columns(seed, missing_sources, source.len(), 16);
    let Some(payload_packets) = build_exact_overhead_packets(
        decoder,
        encoder,
        source,
        &missing_columns,
        ec_overhead,
        repair_distribution,
    ) else {
        return;
    };

    let repair_count = payload_packets
        .iter()
        .filter(|packet| !packet.is_source)
        .count();
    assert_eq!(
        repair_count,
        missing_columns.len().saturating_add(ec_overhead),
        "K=2048 exact-overhead oracle must emit one repair per erasure plus EC overhead"
    );
    assert_eq!(
        payload_packets.len(),
        source.len().saturating_add(ec_overhead),
        "K=2048 exact-overhead oracle must keep the received payload budget at K+overhead"
    );

    let received = combine_symbols(decoder, &payload_packets);
    let batch = if received.is_empty() {
        0
    } else {
        wavefront_batch % (received.len() + 1)
    };
    assert_decode_consensus(decoder, &received, source, batch, object_id);
    let decoded = decoder
        .decode(&received)
        .expect("K=2048 exact-overhead repair patterns must remain decodable");
    assert_eq!(
        decoded.source, source,
        "K=2048 exact-overhead repair patterns must recover original source"
    );
}

fn assert_k4096_exact_overhead_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    missing_sources: &[u8],
    ec_overhead: usize,
    repair_distribution: RepairDistribution,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 4096 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 4096,
        "K=4096 decoder oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 4112,
        "K=4096 decoder oracle must pin the rounded RFC row"
    );
    assert_eq!(
        params.j, 726,
        "K=4096 decoder oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 137,
        "K=4096 decoder oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 11,
        "K=4096 decoder oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 4159,
        "K=4096 decoder oracle must pin the RFC W(K') value"
    );
    assert_eq!(
        params.l, 4260,
        "K=4096 decoder oracle must pin the RFC L value"
    );
    assert_eq!(
        params.b, 4022,
        "K=4096 decoder oracle must pin the RFC B value"
    );
    assert!(
        params.k_prime > params.k,
        "K=4096 decoder oracle must exercise rounded K..K' synthesis"
    );

    // This much larger row needs a slightly wider recovery margin to keep the
    // arbitrary repair schedule decodable while still pinning an exact budget.
    let ec_overhead = ec_overhead.saturating_add(8);
    let missing_columns = spread_missing_columns(seed, missing_sources, source.len(), 24);
    let Some(payload_packets) = build_exact_overhead_packets(
        decoder,
        encoder,
        source,
        &missing_columns,
        ec_overhead,
        repair_distribution,
    ) else {
        return;
    };

    let repair_count = payload_packets
        .iter()
        .filter(|packet| !packet.is_source)
        .count();
    assert_eq!(
        repair_count,
        missing_columns.len().saturating_add(ec_overhead),
        "K=4096 exact-overhead oracle must emit one repair per erasure plus EC overhead"
    );
    assert_eq!(
        payload_packets.len(),
        source.len().saturating_add(ec_overhead),
        "K=4096 exact-overhead oracle must keep the received payload budget at K+overhead"
    );

    let received = combine_symbols(decoder, &payload_packets);
    let batch = if received.is_empty() {
        0
    } else {
        wavefront_batch % (received.len() + 1)
    };
    assert_decode_consensus(decoder, &received, source, batch, object_id);
    let decoded = decoder
        .decode(&received)
        .expect("K=4096 exact-overhead repair patterns must remain decodable");
    assert_eq!(
        decoded.source, source,
        "K=4096 exact-overhead repair patterns must recover original source"
    );
}

fn assert_k16384_half_loss_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    missing_sources: &[u8],
    extra_repairs: usize,
    repair_distribution: RepairDistribution,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 16384 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 16384,
        "K=16384 decoder oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 16505,
        "K=16384 decoder oracle must pin the rounded RFC row"
    );
    assert_eq!(
        params.j, 732,
        "K=16384 decoder oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 347,
        "K=16384 decoder oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 12,
        "K=16384 decoder oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 16661,
        "K=16384 decoder oracle must pin the RFC W(K') value"
    );
    assert_eq!(
        params.l, 16864,
        "K=16384 decoder oracle must pin the RFC L value"
    );
    assert_eq!(
        params.b, 16314,
        "K=16384 decoder oracle must pin the RFC B value"
    );
    assert!(
        params.k_prime > params.k,
        "K=16384 decoder oracle must exercise rounded K..K' synthesis"
    );

    let missing_count = source.len() / 2;
    let ec_overhead = extra_repairs.saturating_add(16);
    let missing_columns =
        spread_missing_columns_exact_count(seed, missing_sources, source.len(), missing_count);
    let Some(payload_packets) = build_exact_overhead_packets(
        decoder,
        encoder,
        source,
        &missing_columns,
        ec_overhead,
        repair_distribution,
    ) else {
        return;
    };

    let repair_count = payload_packets
        .iter()
        .filter(|packet| !packet.is_source)
        .count();
    assert_eq!(
        missing_columns.len(),
        missing_count,
        "K=16384 oracle must hold the source loss rate at exactly 50%"
    );
    assert_eq!(
        repair_count,
        missing_count.saturating_add(ec_overhead),
        "K=16384 oracle must emit one repair per erasure plus EC overhead"
    );
    assert_eq!(
        payload_packets.len(),
        source.len().saturating_add(ec_overhead),
        "K=16384 oracle must keep the received payload budget at K+overhead"
    );
    assert!(
        payload_packets.len() >= source.len(),
        "K=16384 oracle must only assert decode once total received payload is at least K"
    );

    let received = combine_symbols(decoder, &payload_packets);
    let batch = if received.is_empty() {
        0
    } else {
        wavefront_batch % (received.len() + 1)
    };
    assert_decode_consensus(decoder, &received, source, batch, object_id);
    let decoded = decoder
        .decode(&received)
        .expect("K=16384 half-loss repair patterns must remain decodable");
    assert_eq!(
        decoded.source, source,
        "K=16384 half-loss repair patterns must recover original source"
    );
}

fn assert_k4_transition_sparse_vs_dense_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    extra_repairs: usize,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 4 {
        return;
    }

    let sparse_gap_raw = seed.rotate_left(11) as u8;
    let transition_extra_repairs = extra_repairs.saturating_add(2);
    for missing_count in 0..=source.len() {
        let missing_sources = k4_transition_missing_sources(seed, missing_count);
        for repair_distribution in [
            RepairDistribution::Dense,
            RepairDistribution::Sparse {
                gap_raw: sparse_gap_raw,
            },
        ] {
            let Some(payload_packets) = build_valid_packets(
                decoder,
                encoder,
                source,
                &missing_sources,
                transition_extra_repairs,
                repair_distribution,
            ) else {
                return;
            };
            let received = combine_symbols(decoder, &payload_packets);
            let batch = if received.is_empty() {
                0
            } else {
                wavefront_batch % (received.len() + 1)
            };
            assert_decode_consensus(decoder, &received, source, batch, object_id);
            let decoded = decoder
                .decode(&received)
                .expect("K=4 transition dense/sparse repair mixes must remain decodable");
            assert_eq!(
                decoded.source, source,
                "K=4 transition dense/sparse repair mixes must recover original source"
            );
        }
    }
}

fn assert_k8_low_intermediate_sparse_vs_dense_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    extra_repairs: usize,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 8 {
        return;
    }

    let params = decoder.params();
    assert_eq!(params.k, 8, "K=8 decoder oracle must preserve the public K");
    assert_eq!(
        params.k_prime, 10,
        "K=8 decoder oracle must stay on the first padded RFC row"
    );
    assert!(
        params.k_prime > params.k,
        "K=8 decoder oracle must exercise padded K..K' synthesis"
    );

    let sparse_gap_raw = seed.rotate_left(19) as u8;
    let low_intermediate_extra_repairs = extra_repairs.saturating_add(2);
    for missing_count in [0usize, 1, 4, 8] {
        let missing_sources = k8_low_intermediate_missing_sources(seed, missing_count);
        for repair_distribution in [
            RepairDistribution::Dense,
            RepairDistribution::Sparse {
                gap_raw: sparse_gap_raw,
            },
        ] {
            let Some(payload_packets) = build_valid_packets(
                decoder,
                encoder,
                source,
                &missing_sources,
                low_intermediate_extra_repairs,
                repair_distribution,
            ) else {
                return;
            };
            let received = combine_symbols(decoder, &payload_packets);
            let batch = if received.is_empty() {
                0
            } else {
                wavefront_batch % (received.len() + 1)
            };
            assert_decode_consensus(decoder, &received, source, batch, object_id);
            let decoded = decoder
                .decode(&received)
                .expect("K=8 low-intermediate dense/sparse repair mixes must remain decodable");
            assert_eq!(
                decoded.source, source,
                "K=8 low-intermediate dense/sparse repair mixes must recover original source"
            );
        }
    }
}

fn assert_k16_low_intermediate_sparse_vs_dense_repairs_recover(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    seed: u64,
    extra_repairs: usize,
    wavefront_batch: usize,
    object_id: ObjectId,
) {
    if source.len() != 16 {
        return;
    }

    let params = decoder.params();
    assert_eq!(
        params.k, 16,
        "K=16 decoder oracle must preserve the public K"
    );
    assert_eq!(
        params.k_prime, 18,
        "K=16 decoder oracle must stay on the second padded RFC row"
    );
    assert_eq!(
        params.j, 682,
        "K=16 decoder oracle must pin the RFC J(K') value"
    );
    assert_eq!(
        params.s, 11,
        "K=16 decoder oracle must pin the RFC S(K') value"
    );
    assert_eq!(
        params.h, 10,
        "K=16 decoder oracle must pin the RFC H(K') value"
    );
    assert_eq!(
        params.w, 29,
        "K=16 decoder oracle must pin the RFC W(K') value"
    );
    assert_eq!(params.l, 39, "K=16 decoder oracle must pin the RFC L value");
    assert_eq!(params.b, 18, "K=16 decoder oracle must pin the RFC B value");
    assert!(
        params.k_prime > params.k,
        "K=16 decoder oracle must exercise padded K..K' synthesis"
    );

    let sparse_gap_raw = seed.rotate_left(23) as u8;
    let low_intermediate_extra_repairs = extra_repairs.saturating_add(4);
    for missing_count in [0usize, 1, 8, 16] {
        let missing_sources = k16_low_intermediate_missing_sources(seed, missing_count);
        for repair_distribution in [
            RepairDistribution::Dense,
            RepairDistribution::Sparse {
                gap_raw: sparse_gap_raw,
            },
        ] {
            let Some(payload_packets) = build_valid_packets(
                decoder,
                encoder,
                source,
                &missing_sources,
                low_intermediate_extra_repairs,
                repair_distribution,
            ) else {
                return;
            };
            let received = combine_symbols(decoder, &payload_packets);
            let batch = if received.is_empty() {
                0
            } else {
                wavefront_batch % (received.len() + 1)
            };
            assert_decode_consensus(decoder, &received, source, batch, object_id);
            let decoded = decoder
                .decode(&received)
                .expect("K=16 low-intermediate dense/sparse repair mixes must remain decodable");
            assert_eq!(
                decoded.source, source,
                "K=16 low-intermediate dense/sparse repair mixes must recover original source"
            );
        }
    }
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

    let k = input.k_selector as usize;
    let symbol_size = input.symbol_size_selector as usize;
    let source = build_source_block(&input.packet_bytes, k, symbol_size, input.seed);
    let Some(encoder) = SystematicEncoder::new(&source, symbol_size, input.seed) else {
        return;
    };
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);

    let Some(baseline_packets) = build_valid_packets(
        &decoder,
        &encoder,
        &source,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.repair_distribution,
    ) else {
        return;
    };
    let baseline_received = combine_symbols(&decoder, &baseline_packets);
    let baseline_batch = if baseline_received.is_empty() {
        0
    } else {
        input.wavefront_batch as usize % (baseline_received.len() + 1)
    };
    let object_id = ObjectId::from_u128(input.object_id);

    if !input.loss_windows.is_empty() {
        assert_burst_loss_recovers_when_received_at_least_k(
            &decoder,
            &encoder,
            &source,
            &input.loss_windows,
            input.burst_repair_overhead as usize,
            input.wavefront_batch as usize,
            object_id,
        );
    }

    assert_k42_burst_loss_recovers(
        &decoder,
        &encoder,
        &source,
        input.seed,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k42_mixed_repair_packet_sizes_handled(
        &decoder,
        &encoder,
        &source,
        input.seed,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.repair_distribution,
        &input.repair_size_selectors,
        &input.packet_bytes,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k512_reorder_exact_overhead_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.repair_distribution,
        input.reorder,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k4096_burst_loss_recovers(
        &decoder,
        &encoder,
        &source,
        input.seed,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k8192_tail_burst_loss_recovers(
        &decoder,
        &encoder,
        &source,
        input.seed,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k8192_reorder_and_duplicates_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.repair_distribution,
        input.reorder,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k4_transition_sparse_vs_dense_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        input.extra_repairs as usize,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k8_low_intermediate_sparse_vs_dense_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        input.extra_repairs as usize,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k16_low_intermediate_sparse_vs_dense_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        input.extra_repairs as usize,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k842_sparse_vs_dense_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k2048_exact_overhead_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.repair_distribution,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k4096_exact_overhead_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.repair_distribution,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_k16384_half_loss_repairs_recover(
        &decoder,
        &encoder,
        &source,
        input.seed,
        &input.missing_sources,
        input.extra_repairs as usize,
        input.repair_distribution,
        input.wavefront_batch as usize,
        object_id,
    );

    assert_decode_consensus(
        &decoder,
        &baseline_received,
        &source,
        baseline_batch,
        object_id,
    );

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
    use super::{
        LARGE_K_CANDIDATES, LARGE_K_THRESHOLD, LARGE_SYMBOL_SIZE_CANDIDATES, LossWindow,
        MEDIUM_K_CANDIDATES, MutationKind, PacketMutation, PacketReorder, RepairDistribution,
        SMALL_K_CANDIDATES, SMALL_SYMBOL_SIZE_CANDIDATES, append_duplicate_packets,
        apply_contiguous_loss_windows, apply_mixed_repair_packet_sizes, apply_mutations,
        assert_k512_reorder_exact_overhead_repairs_recover, build_repair_esi_sequence,
        build_source_block, burst_repair_count, count_duplicate_packets,
        k4_transition_missing_sources, k8_low_intermediate_missing_sources,
        k16_low_intermediate_missing_sources, max_repair_payload_len, nontrivial_reorder,
        repair_stress_missing_sources, select_k_candidate, select_repair_payload_len,
        select_symbol_size_candidate, sparse_repair_stride, spread_missing_columns,
        spread_missing_columns_exact_count,
    };
    use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
    use asupersync::raptorq::gf256::Gf256;
    use asupersync::raptorq::systematic::SystematicEncoder;
    use asupersync::types::ObjectId;

    #[test]
    fn k_selector_can_reach_large_rfc_boundary_profiles() {
        let k = select_k_candidate(0);
        assert!(k >= LARGE_K_THRESHOLD);
        assert!(LARGE_K_CANDIDATES.contains(&k));
    }

    #[test]
    fn k_selector_includes_large_k_842_edge_case() {
        assert!(
            LARGE_K_CANDIDATES.contains(&842),
            "large-K candidate set must include the canonical K=842 edge"
        );
        let selector = 8 * LARGE_K_CANDIDATES
            .iter()
            .position(|&candidate| candidate == 842)
            .expect("K=842 must be selectable");
        assert_eq!(
            select_k_candidate(selector),
            842,
            "selector normalization must be able to reach K=842"
        );
    }

    #[test]
    fn k_selector_includes_large_k_2048_edge_case() {
        assert!(
            LARGE_K_CANDIDATES.contains(&2048),
            "large-K candidate set must include the canonical K=2048 edge"
        );
        let selector = 8 * LARGE_K_CANDIDATES
            .iter()
            .position(|&candidate| candidate == 2048)
            .expect("K=2048 must be selectable");
        assert_eq!(
            select_k_candidate(selector),
            2048,
            "selector normalization must be able to reach K=2048"
        );
    }

    #[test]
    fn k_selector_includes_large_k_4096_edge_case() {
        assert!(
            LARGE_K_CANDIDATES.contains(&4096),
            "large-K candidate set must include the canonical K=4096 edge"
        );
        let selector = 8 * LARGE_K_CANDIDATES
            .iter()
            .position(|&candidate| candidate == 4096)
            .expect("K=4096 must be selectable");
        assert_eq!(
            select_k_candidate(selector),
            4096,
            "selector normalization must be able to reach K=4096"
        );
    }

    #[test]
    fn k_selector_includes_large_k_8192_edge_case() {
        assert!(
            LARGE_K_CANDIDATES.contains(&8192),
            "large-K candidate set must include the canonical K=8192 edge"
        );
        let selector = 8 * LARGE_K_CANDIDATES
            .iter()
            .position(|&candidate| candidate == 8192)
            .expect("K=8192 must be selectable");
        assert_eq!(
            select_k_candidate(selector),
            8192,
            "selector normalization must be able to reach K=8192"
        );
    }

    #[test]
    fn k_selector_includes_large_k_16384_edge_case() {
        assert!(
            LARGE_K_CANDIDATES.contains(&16384),
            "large-K candidate set must include the K=16384 half-loss profile"
        );
        let selector = 8 * LARGE_K_CANDIDATES
            .iter()
            .position(|&candidate| candidate == 16384)
            .expect("K=16384 must be selectable");
        assert_eq!(
            select_k_candidate(selector),
            16384,
            "selector normalization must be able to reach K=16384"
        );
    }

    #[test]
    fn k_selector_includes_k42_burst_profile() {
        assert!(
            MEDIUM_K_CANDIDATES.contains(&42),
            "medium-K candidate set must include the canonical K=42 burst profile"
        );
        let selector = 8 * MEDIUM_K_CANDIDATES
            .iter()
            .position(|&candidate| candidate == 42)
            .expect("K=42 must be selectable")
            + 2;
        assert_eq!(
            select_k_candidate(selector),
            42,
            "selector normalization must be able to reach K=42"
        );
    }

    #[test]
    fn k_selector_includes_k512_reorder_profile() {
        assert!(
            MEDIUM_K_CANDIDATES.contains(&512),
            "medium-K candidate set must include the K=512 reorder profile"
        );
        let selector = 8 * MEDIUM_K_CANDIDATES
            .iter()
            .position(|&candidate| candidate == 512)
            .expect("K=512 must be selectable")
            + 2;
        assert_eq!(
            select_k_candidate(selector),
            512,
            "selector normalization must be able to reach K=512"
        );
    }

    #[test]
    fn mixed_repair_payload_length_selector_stays_within_k42_limit() {
        let symbol_size = 64usize;
        let limit = max_repair_payload_len(symbol_size);
        assert_eq!(limit, 129);
        let len = select_repair_payload_len(u16::MAX, symbol_size, 7);
        assert!(len <= limit);
    }

    #[test]
    fn symbol_size_selector_keeps_large_k_targets_within_budget() {
        let symbol_size = select_symbol_size_candidate(6, 2048, 64 * 1024);
        assert!(symbol_size <= 32);
        assert!(LARGE_SYMBOL_SIZE_CANDIDATES.contains(&symbol_size));
        assert!(2048usize.saturating_mul(symbol_size) <= 64 * 1024);
    }

    #[test]
    fn symbol_size_selector_keeps_k4096_targets_within_budget() {
        let symbol_size = select_symbol_size_candidate(6, 4096, 64 * 1024);
        assert_eq!(symbol_size, 16);
        assert!(LARGE_SYMBOL_SIZE_CANDIDATES.contains(&symbol_size));
        assert!(4096usize.saturating_mul(symbol_size) <= 64 * 1024);
    }

    #[test]
    fn symbol_size_selector_keeps_k8192_targets_within_budget() {
        let symbol_size = select_symbol_size_candidate(4, 8192, 64 * 1024);
        assert_eq!(symbol_size, 8);
        assert!(LARGE_SYMBOL_SIZE_CANDIDATES.contains(&symbol_size));
        assert!(8192usize.saturating_mul(symbol_size) <= 64 * 1024);
    }

    #[test]
    fn symbol_size_selector_keeps_k16384_targets_within_budget() {
        let symbol_size = select_symbol_size_candidate(6, 16384, 64 * 1024);
        assert_eq!(symbol_size, 4);
        assert!(LARGE_SYMBOL_SIZE_CANDIDATES.contains(&symbol_size));
        assert!(16384usize.saturating_mul(symbol_size) <= 64 * 1024);
    }

    #[test]
    fn symbol_size_selector_preserves_small_block_edge_sizes() {
        let symbol_size = select_symbol_size_candidate(15, 16, 64 * 1024);
        assert_eq!(symbol_size, 256);
        assert!(SMALL_SYMBOL_SIZE_CANDIDATES.contains(&symbol_size));
        assert!(SMALL_K_CANDIDATES.contains(&select_k_candidate(63)));
    }

    #[test]
    fn symbol_size_selector_treats_k842_as_large_k_profile() {
        let symbol_size = select_symbol_size_candidate(6, 842, 64 * 1024);
        assert!(symbol_size <= 32);
        assert!(LARGE_SYMBOL_SIZE_CANDIDATES.contains(&symbol_size));
        assert!(842usize.saturating_mul(symbol_size) <= 64 * 1024);
    }

    #[test]
    fn burst_repair_budget_caps_requested_loss_at_k() {
        let repair_count = burst_repair_count(
            &[
                LossWindow {
                    start: 0,
                    len: u16::MAX,
                },
                LossWindow {
                    start: 17,
                    len: u16::MAX,
                },
            ],
            3,
            842,
        );
        assert_eq!(repair_count, 845);
    }

    #[test]
    fn burst_repair_budget_scales_to_k4096_windows() {
        let repair_count = burst_repair_count(
            &[
                LossWindow { start: 0, len: 511 },
                LossWindow {
                    start: 17,
                    len: 255,
                },
            ],
            12,
            4096,
        );
        assert_eq!(repair_count, 780);
    }

    #[test]
    fn burst_repair_budget_scales_to_k8192_tail_windows() {
        let repair_count = burst_repair_count(
            &[
                LossWindow { start: 0, len: 767 },
                LossWindow {
                    start: 31,
                    len: 127,
                },
            ],
            28,
            8192,
        );
        assert_eq!(repair_count, 924);
    }

    #[test]
    fn nontrivial_reorder_promotes_preserve_to_rotation() {
        match nontrivial_reorder(PacketReorder::Preserve, 0x22) {
            PacketReorder::Rotate { by } => assert_ne!(by, 0),
            other => panic!("expected preserve to promote to rotate, got {other:?}"),
        }
        match nontrivial_reorder(PacketReorder::SortByEsi, 0) {
            PacketReorder::Rotate { by } => assert_ne!(by, 0),
            other => panic!("expected sorted order to promote to rotate, got {other:?}"),
        }
        assert!(matches!(
            nontrivial_reorder(PacketReorder::Rotate { by: 0 }, 7),
            PacketReorder::Rotate { by: 1 }
        ));
        assert!(matches!(
            nontrivial_reorder(PacketReorder::Reverse, 7),
            PacketReorder::Reverse
        ));
    }

    #[test]
    fn append_duplicate_packets_covers_source_and_repair_groups() {
        let mut packets = vec![
            ReceivedSymbol::source(0, vec![1, 2]),
            ReceivedSymbol::source(1, vec![3, 4]),
            ReceivedSymbol::repair(8, vec![0, 1], vec![Gf256::ONE, Gf256(7)], vec![9, 9]),
        ];

        append_duplicate_packets(&mut packets, 0x55AA, 2);

        assert_eq!(packets.len(), 5);
        assert_eq!(count_duplicate_packets(&packets), 2);
        assert!(packets.iter().filter(|packet| packet.is_source).count() >= 3);
        assert!(packets.iter().filter(|packet| !packet.is_source).count() >= 2);
    }

    #[test]
    fn mixed_repair_packet_sizes_create_multiple_lengths_without_touching_sources() {
        let mut packets = vec![
            ReceivedSymbol::source(0, vec![1, 2, 3, 4]),
            ReceivedSymbol::repair(42, vec![0], vec![Gf256::ONE], vec![9, 9, 9, 9]),
            ReceivedSymbol::repair(43, vec![1], vec![Gf256::ONE], vec![8, 8, 8, 8]),
            ReceivedSymbol::repair(44, vec![2], vec![Gf256::ONE], vec![7, 7, 7, 7]),
        ];

        let repair_lengths =
            apply_mixed_repair_packet_sizes(&mut packets, 4, &[0, 1, 2], &[0xAA, 0xBB], 0x42);

        assert_eq!(packets[0].data.len(), 4);
        assert!(repair_lengths.len() > 1);
        assert!(
            packets
                .iter()
                .filter(|packet| !packet.is_source)
                .all(|packet| packet.data.len() <= max_repair_payload_len(4))
        );
    }

    #[test]
    fn dense_repair_sequence_is_contiguous_at_k842() {
        let sequence = build_repair_esi_sequence(842, 4, RepairDistribution::Dense);
        assert_eq!(sequence, vec![842, 843, 844, 845]);
    }

    #[test]
    fn sparse_repair_sequence_spreads_k842_symbols() {
        let stride = sparse_repair_stride(842, 7);
        let sequence = build_repair_esi_sequence(842, 4, RepairDistribution::Sparse { gap_raw: 7 });
        assert!(stride > 1);
        assert_eq!(sequence[0], 842);
        assert_eq!(sequence[1], 842 + stride);
        assert_eq!(sequence[2], 842 + stride * 2);
        assert_eq!(sequence[3], 842 + stride * 3);
    }

    #[test]
    fn repair_stress_missing_sources_falls_back_to_nonempty_k842_window() {
        let fallback = repair_stress_missing_sources(&[], 2026);
        assert_eq!(fallback.len(), 16);
        assert_eq!(fallback[0], 2026u64 as u8);
        assert_eq!(fallback[15], (2026u64 as u8).wrapping_add(15));
    }

    #[test]
    fn spread_missing_columns_reaches_full_k2048_space() {
        let columns = spread_missing_columns(0xDEADBEEF, &[1, 2, 3, 4, 5, 6], 2048, 16);
        assert_eq!(columns.len(), 6);
        assert!(columns.iter().all(|column| *column < 2048));
        assert!(
            columns.iter().any(|column| *column >= 256),
            "large-K missing-column spread should reach beyond the first byte-sized prefix"
        );
    }

    #[test]
    fn spread_missing_columns_reaches_full_k512_space() {
        let columns = spread_missing_columns(0x512BAD, &[1, 2, 3, 4, 5, 6], 512, 12);
        assert_eq!(columns.len(), 6);
        assert!(columns.iter().all(|column| *column < 512));
        assert!(
            columns.iter().any(|column| *column >= 256),
            "K=512 missing-column spread should reach beyond byte-sized source indices"
        );
    }

    #[test]
    fn spread_missing_columns_reaches_full_k4096_space() {
        let columns = spread_missing_columns(0xBADC0FFE, &[8, 9, 10, 11, 12, 13], 4096, 24);
        assert_eq!(columns.len(), 6);
        assert!(columns.iter().all(|column| *column < 4096));
        assert!(
            columns.iter().any(|column| *column >= 1024),
            "very-large-K missing-column spread should reach well beyond the early prefix"
        );
    }

    #[test]
    fn spread_missing_columns_exact_count_reaches_half_of_k16384() {
        let columns = spread_missing_columns_exact_count(0x16384BAD, &[1, 2, 3, 4], 16384, 8192);
        let unique: std::collections::BTreeSet<_> = columns.iter().copied().collect();
        assert_eq!(columns.len(), 8192);
        assert_eq!(unique.len(), 8192);
        assert!(columns.iter().all(|column| *column < 16384));
        assert!(
            columns.iter().any(|column| *column >= 8192),
            "K=16384 half-loss spread must reach beyond the first half of the block"
        );
    }

    #[test]
    fn k4_transition_missing_sources_wraps_contiguously() {
        assert_eq!(k4_transition_missing_sources(0, 0), Vec::<u8>::new());
        assert_eq!(k4_transition_missing_sources(0, 3), vec![0, 1, 2]);
        assert_eq!(k4_transition_missing_sources(3, 4), vec![3, 0, 1, 2]);
        assert_eq!(k4_transition_missing_sources(7, 5), vec![3, 0, 1, 2]);
    }

    #[test]
    fn k8_low_intermediate_missing_sources_wraps_contiguously() {
        assert_eq!(k8_low_intermediate_missing_sources(0, 0), Vec::<u8>::new());
        assert_eq!(k8_low_intermediate_missing_sources(0, 4), vec![0, 1, 2, 3]);
        assert_eq!(
            k8_low_intermediate_missing_sources(7, 8),
            vec![7, 0, 1, 2, 3, 4, 5, 6]
        );
        assert_eq!(
            k8_low_intermediate_missing_sources(13, 9),
            vec![5, 6, 7, 0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn k16_low_intermediate_missing_sources_wraps_contiguously() {
        assert_eq!(k16_low_intermediate_missing_sources(0, 0), Vec::<u8>::new());
        assert_eq!(k16_low_intermediate_missing_sources(0, 4), vec![0, 1, 2, 3]);
        assert_eq!(
            k16_low_intermediate_missing_sources(15, 16),
            vec![15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        );
        assert_eq!(
            k16_low_intermediate_missing_sources(21, 18),
            vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn contiguous_loss_windows_remove_packet_runs_in_order() {
        let mut packets = vec![
            ReceivedSymbol::source(0, vec![0]),
            ReceivedSymbol::source(1, vec![1]),
            ReceivedSymbol::source(2, vec![2]),
            ReceivedSymbol::source(3, vec![3]),
            ReceivedSymbol::source(4, vec![4]),
        ];

        apply_contiguous_loss_windows(
            &mut packets,
            &[
                LossWindow { start: 1, len: 0 },
                LossWindow { start: 2, len: 0 },
            ],
        );

        let surviving_esis: Vec<u32> = packets.iter().map(|packet| packet.esi).collect();
        assert_eq!(surviving_esis, vec![0, 2, 4]);
    }

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

        assert_eq!(
            packets.len(),
            2,
            "mutation should append a duplicate packet"
        );
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

    #[test]
    fn k512_reorder_oracle_decodes_rotated_exact_overhead_payload() {
        let k = 512usize;
        let symbol_size = 4usize;
        let seed = 0x5120_1800_u64;
        let source = build_source_block(&[0x51, 0x20, 0x18], k, symbol_size, seed);
        let encoder =
            SystematicEncoder::new(&source, symbol_size, seed).expect("K=512 encoder builds");
        let decoder = InactivationDecoder::new(k, symbol_size, seed);

        assert_k512_reorder_exact_overhead_repairs_recover(
            &decoder,
            &encoder,
            &source,
            seed,
            &[3, 17, 29, 43, 101, 211],
            0,
            RepairDistribution::Dense,
            PacketReorder::Preserve,
            7,
            ObjectId::from_u128(512),
        );
    }
}
