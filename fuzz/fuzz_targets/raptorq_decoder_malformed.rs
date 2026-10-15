//! Structure-aware fuzz target for malformed RaptorQ source-block handling.
//!
//! Builds a valid source block from fuzzed source bytes, then injects
//! malformed source-symbol metadata and adversarial repair packets into the
//! direct decoder API. The decoder must reject malformed input cleanly and
//! never panic across its direct, wavefront, or proof entrypoints.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;

const MAX_K: usize = 64;
const MAX_SYMBOL_SIZE: usize = 128;
const MAX_SOURCE_BYTES: usize = MAX_K * MAX_SYMBOL_SIZE;
const MAX_REPAIR_PACKETS: usize = 24;
const MAX_SOURCE_MUTATIONS: usize = 16;
const MAX_PACKET_BYTES: usize = 256;
const MAX_EXTREME_FEC_PACKETS: usize = 12;
const MAX_EXTREME_PAYLOAD_BYTES: usize = 8 * 1024;
const MAX_EXTREME_COLUMNS: usize = 96;

#[derive(Arbitrary, Debug)]
struct MalformedSourceBlockInput {
    k: u8,
    symbol_size: u8,
    seed: u64,
    object_id: u128,
    wavefront_batch: u8,
    source_bytes: Vec<u8>,
    repair_packets: Vec<RepairPacketInput>,
    extreme_fec_packets: Vec<ExtremeFecPayloadInput>,
    source_mutations: Vec<SourceMutation>,
}

#[derive(Arbitrary, Debug, Clone)]
struct RepairPacketInput {
    esi_offset: u8,
    data: Vec<u8>,
    mutation: RepairPacketMutation,
}

#[derive(Arbitrary, Debug, Clone)]
enum RepairPacketMutation {
    Keep,
    TruncateData { keep: u8 },
    ExtendData { extra: u8, fill: u8 },
    DropLastCoefficient,
    AppendOutOfRangeColumn { extra: u8 },
    ZeroFirstCoefficient,
    DuplicateFirstColumn,
    PretendSource,
}

#[derive(Arbitrary, Debug, Clone)]
struct ExtremeFecPayloadInput {
    esi_seed: u32,
    payload_seed: u8,
    column_seed: u16,
    coefficient_seed: u8,
    mode: ExtremeFecMode,
}

#[derive(Arbitrary, Debug, Clone)]
enum ExtremeFecMode {
    HugeRepairEsi,
    HugeSourceEsi,
    MaxColumnIndex,
    ColumnArityExplosion { count: u8 },
    CoefficientArityExplosion { count: u8 },
    OversizedPayload { multiplier: u8 },
    EmptyPayload,
    SourceFlagOnRepairEquation,
}

#[derive(Arbitrary, Debug, Clone)]
enum SourceMutation {
    WrongEsi {
        index: u8,
        claimed_esi: u16,
    },
    WrongEquation {
        index: u8,
        column: u16,
        coefficient: u8,
        extra_column: Option<u16>,
    },
    TruncateData {
        index: u8,
        keep: u8,
    },
    ExtendData {
        index: u8,
        extra: u8,
        fill: u8,
    },
    ToggleSourceFlag {
        index: u8,
    },
    Duplicate {
        index: u8,
    },
    Drop {
        index: u8,
    },
}

impl MalformedSourceBlockInput {
    fn normalize(&mut self) {
        self.k = ((self.k as usize % MAX_K) + 1) as u8;
        self.symbol_size = ((self.symbol_size as usize % MAX_SYMBOL_SIZE) + 1) as u8;
        self.source_bytes.truncate(MAX_SOURCE_BYTES);
        self.repair_packets.truncate(MAX_REPAIR_PACKETS);
        self.extreme_fec_packets.truncate(MAX_EXTREME_FEC_PACKETS);
        self.source_mutations.truncate(MAX_SOURCE_MUTATIONS);
        for packet in &mut self.repair_packets {
            packet.data.truncate(MAX_PACKET_BYTES);
        }
    }
}

fn build_source_block(raw: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let salt = seed.to_le_bytes();
    let mut source = Vec::with_capacity(k);

    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let patterned = ((row * 31 + col * 17 + 0x5A) & 0xFF) as u8;
            let mixed = if raw.is_empty() {
                patterned ^ salt[(row + col) % salt.len()]
            } else {
                let idx = (row * symbol_size + col) % raw.len();
                raw[idx] ^ patterned ^ salt[(idx + row + col) % salt.len()]
            };
            symbol.push(mixed);
        }
        source.push(symbol);
    }

    source
}

fn build_source_symbols(source: &[Vec<u8>]) -> Vec<ReceivedSymbol> {
    source
        .iter()
        .enumerate()
        .map(|(esi, data)| {
            ReceivedSymbol::source(
                u32::try_from(esi).expect("bounded fuzz K must fit in u32"),
                data.clone(),
            )
        })
        .collect()
}

fn build_repair_payload(raw: &[u8], fallback: &[u8], symbol_size: usize) -> Vec<u8> {
    if raw.is_empty() {
        return fallback.to_vec();
    }

    let mut payload = vec![0u8; symbol_size];
    for (idx, byte) in payload.iter_mut().enumerate() {
        *byte = raw[idx % raw.len()] ^ fallback[idx];
    }
    payload
}

fn observe_drop_last_coefficient(columns_len: usize, coefficients: &mut Vec<Gf256>) {
    let coefficient_len_before = coefficients.len();
    assert_eq!(
        columns_len, coefficient_len_before,
        "repair equation must start with aligned column/coefficient arity"
    );

    let removed = coefficients.pop();
    assert!(
        removed.is_some(),
        "DropLastCoefficient mutation should remove a repair coefficient"
    );
    assert_eq!(
        coefficients.len() + 1,
        coefficient_len_before,
        "DropLastCoefficient mutation should shrink coefficient arity by one"
    );
    assert_eq!(
        columns_len,
        coefficients.len() + 1,
        "DropLastCoefficient mutation should leave one unmatched repair column"
    );
}

fn build_repair_packets(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    symbol_size: usize,
    packet_inputs: &[RepairPacketInput],
) -> Vec<ReceivedSymbol> {
    let mut packets = Vec::with_capacity(packet_inputs.len());
    let base_esi = u32::try_from(decoder.params().k).expect("bounded fuzz K must fit in u32");

    for packet_input in packet_inputs {
        let esi = base_esi + u32::from(packet_input.esi_offset % 32);
        let Ok((mut columns, mut coefficients)) = decoder.repair_equation(esi) else {
            continue;
        };
        let valid_payload = encoder.repair_symbol(esi);
        let mut data = build_repair_payload(&packet_input.data, &valid_payload, symbol_size);
        let mut is_source = false;

        match packet_input.mutation {
            RepairPacketMutation::Keep => {}
            RepairPacketMutation::TruncateData { keep } => {
                let new_len = usize::from(keep) % (data.len().saturating_add(1));
                data.truncate(new_len);
            }
            RepairPacketMutation::ExtendData { extra, fill } => {
                let growth = (usize::from(extra) % 16).saturating_add(1);
                data.extend(std::iter::repeat_n(fill, growth));
            }
            RepairPacketMutation::DropLastCoefficient => {
                observe_drop_last_coefficient(columns.len(), &mut coefficients);
            }
            RepairPacketMutation::AppendOutOfRangeColumn { extra } => {
                columns.push(decoder.params().l + usize::from(extra) + 1);
                coefficients.push(Gf256::new(extra.saturating_add(1)));
            }
            RepairPacketMutation::ZeroFirstCoefficient => {
                if let Some(first) = coefficients.first_mut() {
                    *first = Gf256::ZERO;
                }
            }
            RepairPacketMutation::DuplicateFirstColumn => {
                if let Some(&first) = columns.first() {
                    columns.push(first);
                    coefficients.push(Gf256::new(2));
                }
            }
            RepairPacketMutation::PretendSource => {
                is_source = true;
            }
        }

        packets.push(ReceivedSymbol {
            esi,
            is_source,
            columns,
            coefficients,
            data,
        });
    }

    packets
}

fn repeated_payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|idx| seed.wrapping_add(idx as u8).rotate_left((idx % 7) as u32))
        .collect()
}

fn nonzero_coefficient(seed: u8) -> Gf256 {
    if seed == 0 {
        Gf256::ONE
    } else {
        Gf256::new(seed)
    }
}

fn push_extreme_fec_payloads(
    packets: &mut Vec<ReceivedSymbol>,
    decoder: &InactivationDecoder,
    symbol_size: usize,
    inputs: &[ExtremeFecPayloadInput],
) {
    let k = decoder.params().k;
    let l = decoder.params().l;
    let base_repair_esi = u32::try_from(k).expect("bounded fuzz K must fit in u32");

    for input in inputs {
        match input.mode {
            ExtremeFecMode::HugeRepairEsi => {
                packets.push(ReceivedSymbol::repair(
                    u32::MAX.saturating_sub(input.esi_seed % 16),
                    vec![usize::from(input.column_seed) % l.max(1)],
                    vec![nonzero_coefficient(input.coefficient_seed)],
                    repeated_payload(input.payload_seed, symbol_size),
                ));
            }
            ExtremeFecMode::HugeSourceEsi => {
                let mut symbol = ReceivedSymbol::source(
                    u32::MAX.saturating_sub(input.esi_seed % 16),
                    repeated_payload(input.payload_seed, symbol_size),
                );
                symbol.columns = vec![usize::from(input.column_seed) % l.max(1)];
                packets.push(symbol);
            }
            ExtremeFecMode::MaxColumnIndex => {
                packets.push(ReceivedSymbol::repair(
                    base_repair_esi.saturating_add(input.esi_seed % 32),
                    vec![usize::MAX, l.saturating_add(usize::from(input.column_seed))],
                    vec![Gf256::ONE, nonzero_coefficient(input.coefficient_seed)],
                    repeated_payload(input.payload_seed, symbol_size),
                ));
            }
            ExtremeFecMode::ColumnArityExplosion { count } => {
                let count = (usize::from(count) % MAX_EXTREME_COLUMNS).saturating_add(1);
                let columns: Vec<_> = (0..count)
                    .map(|idx| {
                        if idx % 5 == 0 {
                            l.saturating_add(idx)
                        } else {
                            (usize::from(input.column_seed) + idx) % l.max(1)
                        }
                    })
                    .collect();
                packets.push(ReceivedSymbol::repair(
                    base_repair_esi.saturating_add(input.esi_seed % 32),
                    columns,
                    vec![nonzero_coefficient(input.coefficient_seed)],
                    repeated_payload(input.payload_seed, symbol_size),
                ));
            }
            ExtremeFecMode::CoefficientArityExplosion { count } => {
                let count = (usize::from(count) % MAX_EXTREME_COLUMNS).saturating_add(1);
                let coefficients = (0..count)
                    .map(|idx| Gf256::new(input.coefficient_seed.wrapping_add(idx as u8)))
                    .collect();
                packets.push(ReceivedSymbol::repair(
                    base_repair_esi.saturating_add(input.esi_seed % 32),
                    vec![usize::from(input.column_seed) % l.max(1)],
                    coefficients,
                    repeated_payload(input.payload_seed, symbol_size),
                ));
            }
            ExtremeFecMode::OversizedPayload { multiplier } => {
                let payload_len = symbol_size
                    .saturating_mul(usize::from(multiplier).saturating_add(2))
                    .clamp(symbol_size.saturating_add(1), MAX_EXTREME_PAYLOAD_BYTES);
                packets.push(ReceivedSymbol::repair(
                    base_repair_esi.saturating_add(input.esi_seed % 32),
                    vec![usize::from(input.column_seed) % l.max(1)],
                    vec![nonzero_coefficient(input.coefficient_seed)],
                    repeated_payload(input.payload_seed, payload_len),
                ));
            }
            ExtremeFecMode::EmptyPayload => {
                packets.push(ReceivedSymbol::repair(
                    base_repair_esi.saturating_add(input.esi_seed % 32),
                    vec![usize::from(input.column_seed) % l.max(1)],
                    vec![nonzero_coefficient(input.coefficient_seed)],
                    Vec::new(),
                ));
            }
            ExtremeFecMode::SourceFlagOnRepairEquation => {
                let mut symbol = ReceivedSymbol::repair(
                    base_repair_esi.saturating_add(input.esi_seed % 32),
                    vec![usize::from(input.column_seed) % l.max(1)],
                    vec![nonzero_coefficient(input.coefficient_seed)],
                    repeated_payload(input.payload_seed, symbol_size),
                );
                symbol.is_source = true;
                packets.push(symbol);
            }
        }
    }
}

fn apply_source_mutations(
    source_symbols: &mut Vec<ReceivedSymbol>,
    mutations: &[SourceMutation],
    decoder: &InactivationDecoder,
) {
    for mutation in mutations {
        if source_symbols.is_empty() {
            return;
        }

        let idx = match mutation {
            SourceMutation::WrongEsi { index, .. }
            | SourceMutation::WrongEquation { index, .. }
            | SourceMutation::TruncateData { index, .. }
            | SourceMutation::ExtendData { index, .. }
            | SourceMutation::ToggleSourceFlag { index }
            | SourceMutation::Duplicate { index }
            | SourceMutation::Drop { index } => usize::from(*index) % source_symbols.len(),
        };

        match mutation.clone() {
            SourceMutation::WrongEsi { claimed_esi, .. } => {
                source_symbols[idx].esi = u32::from(claimed_esi);
            }
            SourceMutation::WrongEquation {
                column,
                coefficient,
                extra_column,
                ..
            } => {
                let mut columns = vec![usize::from(column) % (decoder.params().l + 8)];
                let mut coefficients = vec![Gf256::new(coefficient)];
                if let Some(extra) = extra_column {
                    columns.push(usize::from(extra) % (decoder.params().l + 8));
                    coefficients.push(Gf256::ONE);
                }

                let expected_column = usize::try_from(source_symbols[idx].esi)
                    .unwrap_or(usize::MAX)
                    .min(decoder.params().l.saturating_sub(1));
                if columns.len() == 1
                    && columns[0] == expected_column
                    && coefficients.len() == 1
                    && coefficients[0] == Gf256::ONE
                {
                    columns[0] = (expected_column + 1) % decoder.params().l.max(1);
                }

                source_symbols[idx].columns = columns;
                source_symbols[idx].coefficients = coefficients;
            }
            SourceMutation::TruncateData { keep, .. } => {
                let new_len =
                    usize::from(keep) % (source_symbols[idx].data.len().saturating_add(1));
                source_symbols[idx].data.truncate(new_len);
            }
            SourceMutation::ExtendData { extra, fill, .. } => {
                let growth = (usize::from(extra) % 16).saturating_add(1);
                source_symbols[idx]
                    .data
                    .extend(std::iter::repeat_n(fill, growth));
            }
            SourceMutation::ToggleSourceFlag { .. } => {
                source_symbols[idx].is_source = !source_symbols[idx].is_source;
            }
            SourceMutation::Duplicate { .. } => {
                source_symbols.push(source_symbols[idx].clone());
            }
            SourceMutation::Drop { .. } => {
                source_symbols.remove(idx);
            }
        }
    }
}

fn assert_failure_classified(error: &DecodeError) {
    assert!(
        error.is_recoverable() || error.is_unrecoverable(),
        "decode error must have a failure class"
    );
}

#[allow(clippy::result_large_err)]
fn assert_decode_entrypoints(
    input: &MalformedSourceBlockInput,
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
    batch_size: usize,
    object_id: ObjectId,
    expected_k: usize,
    expected_symbol_size: usize,
) {
    let direct = catch_unwind(AssertUnwindSafe(|| decoder.decode(received)))
        .unwrap_or_else(|_| panic!("decode panicked for malformed source-block input: {input:?}"));
    let wavefront = catch_unwind(AssertUnwindSafe(|| {
        decoder.decode_wavefront(received, batch_size)
    }))
    .unwrap_or_else(|_| {
        panic!("decode_wavefront panicked for malformed source-block input: {input:?}")
    });
    let proof = catch_unwind(AssertUnwindSafe(|| {
        decoder.decode_with_proof(received, object_id, 0)
    }))
    .unwrap_or_else(|_| {
        panic!("decode_with_proof panicked for malformed source-block input: {input:?}")
    });

    match (&direct, &wavefront) {
        (Ok(lhs), Ok(rhs)) => {
            assert_eq!(
                lhs.source, rhs.source,
                "decode and wavefront decode must agree on recovered source bytes"
            );
        }
        (Err(lhs), Err(rhs)) => {
            assert_failure_classified(lhs);
            assert_failure_classified(rhs);
            assert_eq!(
                lhs, rhs,
                "decode and wavefront decode must agree on malformed-input rejection"
            );
        }
        _ => panic!("decode and wavefront decode disagreed on success vs error"),
    }

    match (&direct, &proof) {
        (Ok(lhs), Ok(rhs)) => {
            assert_eq!(
                lhs.source, rhs.result.source,
                "decode and proof decode must agree on recovered source bytes"
            );
        }
        (Err(lhs), Err((rhs, _proof))) => {
            assert_failure_classified(lhs);
            assert_failure_classified(rhs);
            assert_eq!(
                lhs, rhs,
                "decode and proof decode must agree on malformed-input rejection"
            );
        }
        _ => panic!("decode and proof decode disagreed on success vs error"),
    }

    if let Ok(decoded) = direct {
        assert_eq!(
            decoded.source.len(),
            expected_k,
            "successful decode must return exactly K source symbols"
        );
        assert!(
            decoded
                .source
                .iter()
                .all(|symbol| symbol.len() == expected_symbol_size),
            "successful decode must preserve symbol_size"
        );
    }
}

fuzz_target!(|input: MalformedSourceBlockInput| {
    let mut input = input;
    input.normalize();

    let k = usize::from(input.k);
    let symbol_size = usize::from(input.symbol_size);
    let source = build_source_block(&input.source_bytes, k, symbol_size, input.seed);
    let Some(encoder) = SystematicEncoder::new(&source, symbol_size, input.seed) else {
        return;
    };
    let Ok(decoder) = InactivationDecoder::try_new(k, symbol_size, input.seed) else {
        return;
    };

    let mut source_symbols = build_source_symbols(&source);
    apply_source_mutations(&mut source_symbols, &input.source_mutations, &decoder);

    let mut received = decoder.constraint_symbols();
    received.extend(source_symbols);
    received.extend(build_repair_packets(
        &decoder,
        &encoder,
        symbol_size,
        &input.repair_packets,
    ));
    push_extreme_fec_payloads(
        &mut received,
        &decoder,
        symbol_size,
        &input.extreme_fec_packets,
    );

    let batch_size = if received.is_empty() {
        0
    } else {
        usize::from(input.wavefront_batch) % (received.len() + 1)
    };
    let object_id = ObjectId::from_u128(input.object_id);

    assert_decode_entrypoints(
        &input,
        &decoder,
        &received,
        batch_size,
        object_id,
        k,
        symbol_size,
    );
});
