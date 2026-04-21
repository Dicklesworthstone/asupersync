//! Fuzz target for RaptorQ decoder Gaussian-elimination matrix paths.
//!
//! This harness targets `src/raptorq/decoder.rs` through the public decoder API.
//! It drives structured rank-deficient and malformed symbol sets through:
//! - `decode`
//! - `decode_wavefront`
//! - `decode_with_proof`
//!
//! Coverage goals:
//! - duplicate-source and duplicate-repair rank-deficient systems return
//!   deterministic recoverable errors instead of panicking
//! - source-only decodes succeed across RFC 6330 systematic-table rollover
//!   boundaries
//! - malformed symbol equations map to the expected structural `DecodeError`
//! - corrupted source payloads disagreeing with valid repair rows are rejected
//!   as `CorruptDecodedOutput`

#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams};
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;

const MAX_K: usize = 24;
const MAX_SYMBOL_SIZE: usize = 128;
const MAX_EXTRA_REPAIRS: usize = 8;
const MAX_PAYLOAD_BYTES: usize = MAX_K * MAX_SYMBOL_SIZE;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Scenario {
    ValidRoundTrip,
    SystematicBoundaryRoundTrip,
    DuplicateSourceRankDeficient,
    DuplicateRepairRankDeficient,
    NearRankDeficientMixedSet,
    MalformedStructural,
    CorruptedSourcePayload,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum StructuralFault {
    ArityMismatch,
    ColumnOutOfRange,
    SourceEsiOutOfRange,
    InvalidSourceEquation,
    WrongSymbolSize,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    scenario: Scenario,
    fault: StructuralFault,
    k: u8,
    symbol_size: u16,
    seed: u64,
    payload: Vec<u8>,
    duplicate_basis: u8,
    missing_sources: u8,
    extra_repairs: u8,
    target_index: u8,
    corrupt_offset: u16,
    corrupt_mask: u8,
    bad_column: u16,
    wavefront_batch: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    InsufficientSymbols,
    SingularMatrix,
    SymbolSizeMismatch,
    SymbolEquationArityMismatch,
    ColumnIndexOutOfRange,
    SourceEsiOutOfRange,
    InvalidSourceSymbolEquation,
    CorruptDecodedOutput,
}

fuzz_target!(|input: FuzzInput| {
    let mut input = input;
    normalize(&mut input);
    execute(input);
});

fn normalize(input: &mut FuzzInput) {
    input.k = ((input.k as usize % (MAX_K - 1)) + 2) as u8;
    input.symbol_size = ((input.symbol_size as usize % MAX_SYMBOL_SIZE) + 1) as u16;
    input.payload.truncate(MAX_PAYLOAD_BYTES);
    input.extra_repairs = (input.extra_repairs as usize % (MAX_EXTRA_REPAIRS + 1)) as u8;
}

fn execute(input: FuzzInput) {
    let k = input.k as usize;
    let symbol_size = input.symbol_size as usize;
    let source = build_source_block(&input.payload, k, symbol_size, input.seed);
    let encoder =
        SystematicEncoder::new(&source, symbol_size, input.seed).expect("normalized encoder");
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);

    match input.scenario {
        Scenario::ValidRoundTrip => {
            let missing = 1 + (usize::from(input.missing_sources) % (k - 1));
            let payload = build_mixed_payload(
                &decoder,
                &encoder,
                &source,
                missing,
                usize::from(input.extra_repairs),
            );
            let mut received = decoder.constraint_symbols();
            received.extend(payload);
            assert_success_consensus(
                &decoder,
                &received,
                &source,
                effective_wavefront_batch(&input, received.len()),
            );
        }
        Scenario::SystematicBoundaryRoundTrip => {
            let (left_k, right_k) = select_systematic_boundary_pair(input.target_index);
            for (offset, boundary_k) in [left_k, right_k].into_iter().enumerate() {
                let boundary_seed = input.seed.wrapping_add(offset as u64);
                let boundary_source =
                    build_source_block(&input.payload, boundary_k, symbol_size, boundary_seed);
                let boundary_decoder = InactivationDecoder::new(boundary_k, symbol_size, boundary_seed);
                let mut received = boundary_decoder.constraint_symbols();
                received.extend(build_valid_source_symbols(&boundary_source));
                assert_success_consensus(
                    &boundary_decoder,
                    &received,
                    &boundary_source,
                    effective_wavefront_batch(&input, received.len()),
                );
            }
        }
        Scenario::DuplicateSourceRankDeficient => {
            let basis = 1 + (usize::from(input.duplicate_basis) % (k - 1));
            let mut received = decoder.constraint_symbols();
            for i in 0..k {
                let duplicate = i % basis;
                received.push(ReceivedSymbol::source(
                    duplicate as u32,
                    source[duplicate].clone(),
                ));
            }
            assert_failure_consensus(
                &decoder,
                &received,
                effective_wavefront_batch(&input, received.len()),
                FailureKind::SingularMatrix,
                true,
            );
        }
        Scenario::DuplicateRepairRankDeficient => {
            let basis = 1 + (usize::from(input.duplicate_basis) % (k - 1).min(3));
            let base_repairs = build_repairs(&decoder, &encoder, basis);
            let mut received = decoder.constraint_symbols();
            for i in 0..k {
                received.push(base_repairs[i % basis].clone());
            }
            assert_failure_consensus(
                &decoder,
                &received,
                effective_wavefront_batch(&input, received.len()),
                FailureKind::SingularMatrix,
                true,
            );
        }
        Scenario::NearRankDeficientMixedSet => {
            let missing = 1 + (usize::from(input.missing_sources) % (k - 1));
            let source_payload =
                build_mixed_payload(&decoder, &encoder, &source, missing, 0);
            let source_symbols = k - missing;
            let repair_symbols = source_payload.len() - source_symbols;
            let duplicate_repairs = repair_symbols.max(2);
            let repair_basis = duplicate_repairs - 1;
            let base_repairs = build_repairs(&decoder, &encoder, repair_basis);

            let mut received = decoder.constraint_symbols();
            received.extend(source_payload.into_iter().take(source_symbols));
            for i in 0..duplicate_repairs {
                received.push(base_repairs[i % repair_basis].clone());
            }

            debug_assert_eq!(received.len(), decoder.constraint_symbols().len() + k);
            assert_failure_consensus(
                &decoder,
                &received,
                effective_wavefront_batch(&input, received.len()),
                FailureKind::SingularMatrix,
                true,
            );
        }
        Scenario::MalformedStructural => {
            let mut received = decoder.constraint_symbols();
            received.extend(build_valid_source_symbols(&source));
            let target = decoder.constraint_symbols().len() + (usize::from(input.target_index) % k);
            mutate_structural_fault(&decoder, &mut received[target], input.fault, input.bad_column);
            let expected = match input.fault {
                StructuralFault::ArityMismatch => FailureKind::SymbolEquationArityMismatch,
                StructuralFault::ColumnOutOfRange => FailureKind::ColumnIndexOutOfRange,
                StructuralFault::SourceEsiOutOfRange => FailureKind::SourceEsiOutOfRange,
                StructuralFault::InvalidSourceEquation => FailureKind::InvalidSourceSymbolEquation,
                StructuralFault::WrongSymbolSize => FailureKind::SymbolSizeMismatch,
            };
            assert_failure_consensus(
                &decoder,
                &received,
                effective_wavefront_batch(&input, received.len()),
                expected,
                false,
            );
        }
        Scenario::CorruptedSourcePayload => {
            let mut received = decoder.constraint_symbols();
            received.extend(build_valid_source_symbols(&source));
            received.extend(build_repairs(
                &decoder,
                &encoder,
                1 + usize::from(input.extra_repairs).max(1),
            ));
            let source_offset = decoder.constraint_symbols().len() + (usize::from(input.target_index) % k);
            let byte_offset = usize::from(input.corrupt_offset) % symbol_size;
            let mask = if input.corrupt_mask == 0 {
                1
            } else {
                input.corrupt_mask
            };
            received[source_offset].data[byte_offset] ^= mask;
            assert_failure_consensus(
                &decoder,
                &received,
                effective_wavefront_batch(&input, received.len()),
                FailureKind::CorruptDecodedOutput,
                false,
            );
        }
    }
}

fn build_source_block(raw: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let salt = seed.to_le_bytes();
    let mut source = Vec::with_capacity(k);
    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let base = if raw.is_empty() {
                ((row * 29 + col * 17 + 0x5A) & 0xFF) as u8
            } else {
                raw[(row * symbol_size + col) % raw.len()]
            };
            let mix = base ^ salt[(row + col) % salt.len()] ^ ((row * 31 + col * 7) as u8);
            symbol.push(mix);
        }
        source.push(symbol);
    }
    source
}

fn select_systematic_boundary_pair(selector: u8) -> (usize, usize) {
    let mut pairs = Vec::new();
    let mut previous_k_prime = SystematicParams::for_source_block(1, 1).k_prime;
    for k in 2..=MAX_K {
        let current_k_prime = SystematicParams::for_source_block(k, 1).k_prime;
        if current_k_prime != previous_k_prime {
            pairs.push((k - 1, k));
        }
        previous_k_prime = current_k_prime;
    }
    let idx = usize::from(selector) % pairs.len();
    pairs[idx]
}

fn build_valid_source_symbols(source: &[Vec<u8>]) -> Vec<ReceivedSymbol> {
    source
        .iter()
        .enumerate()
        .map(|(esi, data)| ReceivedSymbol::source(esi as u32, data.clone()))
        .collect()
}

fn build_repairs(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    count: usize,
) -> Vec<ReceivedSymbol> {
    let start_esi = decoder.params().k as u32;
    (0..count)
        .map(|offset| {
            let esi = start_esi + offset as u32;
            let (columns, coefficients) = decoder.repair_equation(esi);
            let data = encoder.repair_symbol(esi);
            ReceivedSymbol::repair(esi, columns, coefficients, data)
        })
        .collect()
}

fn build_mixed_payload(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    missing_sources: usize,
    extra_repairs: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut payload = Vec::new();
    for (esi, data) in source.iter().enumerate() {
        if esi >= missing_sources {
            payload.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }
    let repair_count = missing_sources + extra_repairs.max(1);
    payload.extend(build_repairs(decoder, encoder, repair_count));
    debug_assert!(payload.len() >= k);
    payload
}

fn mutate_structural_fault(
    decoder: &InactivationDecoder,
    symbol: &mut ReceivedSymbol,
    fault: StructuralFault,
    bad_column: u16,
) {
    match fault {
        StructuralFault::ArityMismatch => {
            let _ = symbol.coefficients.pop();
        }
        StructuralFault::ColumnOutOfRange => {
            symbol.columns[0] = decoder.params().l + usize::from(bad_column) + 1;
        }
        StructuralFault::SourceEsiOutOfRange => {
            symbol.esi = decoder.params().k as u32 + u32::from(bad_column) + 1;
        }
        StructuralFault::InvalidSourceEquation => {
            symbol.columns[0] = (symbol.esi as usize + 1) % decoder.params().k.max(1);
            if symbol.columns[0] == symbol.esi as usize {
                symbol.coefficients[0] = Gf256::new(2);
            }
        }
        StructuralFault::WrongSymbolSize => {
            if symbol.data.len() > 1 {
                symbol.data.pop();
            } else {
                symbol.data.push(0);
            }
        }
    }
}

fn effective_wavefront_batch(input: &FuzzInput, symbol_count: usize) -> usize {
    usize::from(input.wavefront_batch) % (symbol_count + 1)
}

fn failure_kind(error: &DecodeError) -> FailureKind {
    match error {
        DecodeError::InsufficientSymbols { .. } => FailureKind::InsufficientSymbols,
        DecodeError::SingularMatrix { .. } => FailureKind::SingularMatrix,
        DecodeError::SymbolSizeMismatch { .. } => FailureKind::SymbolSizeMismatch,
        DecodeError::SymbolEquationArityMismatch { .. } => FailureKind::SymbolEquationArityMismatch,
        DecodeError::ColumnIndexOutOfRange { .. } => FailureKind::ColumnIndexOutOfRange,
        DecodeError::SourceEsiOutOfRange { .. } => FailureKind::SourceEsiOutOfRange,
        DecodeError::InvalidSourceSymbolEquation { .. } => {
            FailureKind::InvalidSourceSymbolEquation
        }
        DecodeError::CorruptDecodedOutput { .. } => FailureKind::CorruptDecodedOutput,
    }
}

fn assert_success_consensus(
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
    expected_source: &[Vec<u8>],
    wavefront_batch: usize,
) {
    let direct = decoder.decode(received).expect("direct decode should succeed");
    let wavefront = decoder
        .decode_wavefront(received, wavefront_batch)
        .expect("wavefront decode should succeed");
    let proof = decoder
        .decode_with_proof(received, ObjectId::new_for_test(9001), 0)
        .expect("proof decode should succeed");

    assert_eq!(direct.source, expected_source);
    assert_eq!(wavefront.source, expected_source);
    assert_eq!(proof.result.source, expected_source);
    assert_eq!(direct.source, wavefront.source);
    assert_eq!(direct.source, proof.result.source);
}

fn assert_failure_consensus(
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
    wavefront_batch: usize,
    expected: FailureKind,
    recoverable: bool,
) {
    let direct = decoder.decode(received).expect_err("direct decode should fail");
    let wavefront = decoder
        .decode_wavefront(received, wavefront_batch)
        .expect_err("wavefront decode should fail");
    let (proof, _artifact) = decoder
        .decode_with_proof(received, ObjectId::new_for_test(9002), 0)
        .expect_err("proof decode should fail");

    assert_eq!(failure_kind(&direct), expected);
    assert_eq!(failure_kind(&wavefront), expected);
    assert_eq!(failure_kind(&proof), expected);
    assert_eq!(direct.is_recoverable(), recoverable);
    assert_eq!(wavefront.is_recoverable(), recoverable);
    assert_eq!(proof.is_recoverable(), recoverable);
}
