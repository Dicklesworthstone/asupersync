#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{DecodeError, InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use asupersync::types::ObjectId;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const K_CANDIDATES: &[usize] = &[1, 2, 3, 4, 7, 10, 17, 33, 42, 64, 128];
const SYMBOL_SIZE_CANDIDATES: &[usize] = &[1, 2, 3, 4, 8, 16, 32, 64];

#[derive(Debug, Arbitrary)]
struct TruncatedDecodeInput {
    k_selector: u8,
    symbol_size_selector: u8,
    seed: u64,
    received_count_selector: u16,
    source_start: u16,
    source_stride: u16,
    repair_start: u16,
    repair_stride: u16,
    order: PacketOrder,
    wavefront_batch: u8,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum PacketOrder {
    SourcesOnly,
    RepairsOnly,
    SourcesThenRepairs,
    RepairsThenSources,
    AlternatingSourcesFirst,
    AlternatingRepairsFirst,
}

fuzz_target!(|input: TruncatedDecodeInput| {
    let k = select_k(input.k_selector);
    let symbol_size = select_symbol_size(input.symbol_size_selector);
    let source = build_source_block(&input.payload, k, symbol_size, input.seed);
    let Some(encoder) = SystematicEncoder::new(&source, symbol_size, input.seed) else {
        return;
    };
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);
    let received_count = usize::from(input.received_count_selector) % k;
    let received = build_truncated_symbols(&input, &decoder, &encoder, &source, received_count);

    assert!(
        received.len() < k,
        "truncated RaptorQ fuzz input must contain fewer than K symbols"
    );
    assert_truncated_decode_errors(&input, &decoder, &received, k);
});

fn select_k(selector: u8) -> usize {
    K_CANDIDATES[usize::from(selector) % K_CANDIDATES.len()]
}

fn select_symbol_size(selector: u8) -> usize {
    SYMBOL_SIZE_CANDIDATES[usize::from(selector) % SYMBOL_SIZE_CANDIDATES.len()]
}

fn build_source_block(payload: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let salt = seed.to_le_bytes();
    (0..k)
        .map(|row| {
            (0..symbol_size)
                .map(|col| {
                    let pattern =
                        (row as u8).wrapping_mul(37) ^ (col as u8).wrapping_mul(19) ^ 0xA5;
                    payload
                        .get((row * symbol_size + col) % payload.len().max(1))
                        .copied()
                        .unwrap_or(pattern)
                        ^ pattern
                        ^ salt[(row + col) % salt.len()]
                })
                .collect()
        })
        .collect()
}

fn build_truncated_symbols(
    input: &TruncatedDecodeInput,
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    received_count: usize,
) -> Vec<ReceivedSymbol> {
    let source_budget = match input.order {
        PacketOrder::SourcesOnly => received_count,
        PacketOrder::RepairsOnly => 0,
        PacketOrder::SourcesThenRepairs | PacketOrder::AlternatingSourcesFirst => {
            received_count.div_ceil(2)
        }
        PacketOrder::RepairsThenSources | PacketOrder::AlternatingRepairsFirst => {
            received_count / 2
        }
    };
    let repair_budget = received_count.saturating_sub(source_budget);
    let sources = build_source_symbols(
        source,
        source_budget,
        input.source_start,
        input.source_stride,
    );
    let repairs = build_repair_symbols(
        decoder,
        encoder,
        repair_budget,
        input.repair_start,
        input.repair_stride,
    );

    order_symbols(sources, repairs, input.order, received_count)
}

fn build_source_symbols(
    source: &[Vec<u8>],
    count: usize,
    start: u16,
    stride: u16,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let stride = normalized_stride(stride, k);
    (0..count)
        .map(|offset| {
            let esi = (usize::from(start) + offset * stride) % k;
            ReceivedSymbol::source(
                u32::try_from(esi).expect("bounded fuzz K fits in u32"),
                source[esi].clone(),
            )
        })
        .collect()
}

fn build_repair_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    count: usize,
    start: u16,
    stride: u16,
) -> Vec<ReceivedSymbol> {
    let k = decoder.params().k;
    let stride = normalized_stride(stride, k.max(1));
    let base = u32::try_from(k).expect("bounded fuzz K fits in u32");

    (0..count)
        .filter_map(|offset| {
            let repair_offset = usize::from(start).saturating_add(offset.saturating_mul(stride));
            let esi = base.saturating_add(u32::try_from(repair_offset).ok()?);
            let (columns, coefficients) = decoder.repair_equation(esi).ok()?;
            Some(ReceivedSymbol::repair(
                esi,
                columns,
                coefficients,
                encoder.repair_symbol(esi),
            ))
        })
        .collect()
}

fn normalized_stride(raw: u16, modulus: usize) -> usize {
    if modulus <= 1 {
        return 1;
    }
    (usize::from(raw) % (modulus - 1)) + 1
}

fn order_symbols(
    sources: Vec<ReceivedSymbol>,
    repairs: Vec<ReceivedSymbol>,
    order: PacketOrder,
    limit: usize,
) -> Vec<ReceivedSymbol> {
    let mut received = Vec::with_capacity(limit);
    match order {
        PacketOrder::SourcesOnly | PacketOrder::SourcesThenRepairs => {
            received.extend(sources);
            received.extend(repairs);
        }
        PacketOrder::RepairsOnly | PacketOrder::RepairsThenSources => {
            received.extend(repairs);
            received.extend(sources);
        }
        PacketOrder::AlternatingSourcesFirst => {
            interleave(&mut received, sources, repairs);
        }
        PacketOrder::AlternatingRepairsFirst => {
            interleave(&mut received, repairs, sources);
        }
    }
    received.truncate(limit);
    received
}

fn interleave(
    out: &mut Vec<ReceivedSymbol>,
    first: Vec<ReceivedSymbol>,
    second: Vec<ReceivedSymbol>,
) {
    let mut first = first.into_iter();
    let mut second = second.into_iter();
    loop {
        let mut progressed = false;
        if let Some(symbol) = first.next() {
            out.push(symbol);
            progressed = true;
        }
        if let Some(symbol) = second.next() {
            out.push(symbol);
            progressed = true;
        }
        if !progressed {
            break;
        }
    }
}

fn assert_truncated_decode_errors(
    input: &TruncatedDecodeInput,
    decoder: &InactivationDecoder,
    received: &[ReceivedSymbol],
    k: usize,
) {
    let direct = catch_unwind(AssertUnwindSafe(|| decoder.decode(received)))
        .unwrap_or_else(|_| panic!("decode panicked on truncated RaptorQ input: {input:?}"));
    let wavefront = catch_unwind(AssertUnwindSafe(|| {
        decoder.decode_wavefront(received, usize::from(input.wavefront_batch))
    }))
    .unwrap_or_else(|_| panic!("decode_wavefront panicked on truncated RaptorQ input: {input:?}"));
    let proof = catch_unwind(AssertUnwindSafe(|| {
        decoder.decode_with_proof(received, ObjectId::new_for_test(input.seed), 0)
    }))
    .unwrap_or_else(|_| panic!("decode_with_proof panicked on truncated RaptorQ input: {input:?}"));

    assert_insufficient("decode", direct, received.len(), k);
    assert_insufficient("decode_wavefront", wavefront, received.len(), k);
    match proof {
        Ok(_) => panic!("decode_with_proof unexpectedly decoded truncated input"),
        Err((error, _proof)) => {
            assert_insufficient_error("decode_with_proof", error, received.len(), k)
        }
    }
}

fn assert_insufficient<T>(
    label: &str,
    result: Result<T, DecodeError>,
    received_len: usize,
    k: usize,
) {
    match result {
        Ok(_) => panic!("{label} unexpectedly decoded {received_len} symbols for K={k}"),
        Err(error) => assert_insufficient_error(label, error, received_len, k),
    }
}

fn assert_insufficient_error(label: &str, error: DecodeError, received_len: usize, k: usize) {
    match error {
        DecodeError::InsufficientSymbols { received, required } => {
            assert_eq!(
                received, received_len,
                "{label} reported the wrong received symbol count"
            );
            assert!(
                received < k,
                "{label} must be exercising the < K truncated-symbol path"
            );
            assert!(
                required >= k,
                "{label} required-symbol threshold must be at least K"
            );
        }
        other => {
            panic!("{label} must reject truncated input with InsufficientSymbols, got {other:?}")
        }
    }
}
