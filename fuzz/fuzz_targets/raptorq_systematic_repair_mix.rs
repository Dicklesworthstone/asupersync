#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

const K_CANDIDATES: &[usize] = &[10, 20, 40, 42, 64, 80, 100, 128, 160, 200, 256];
const SYMBOL_SIZE_CANDIDATES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128];
const MAX_SOURCE_BYTES: usize = 32 * 1024;
const MAX_EXTRA_AVAILABLE: usize = 64;
const REPAIR_SPAN_PADDING: usize = 32;

const MIX_RATIOS: [MixRatio; 3] = [
    MixRatio {
        name: "50/50",
        source_parts: 1,
        repair_parts: 1,
    },
    MixRatio {
        name: "90/10",
        source_parts: 9,
        repair_parts: 1,
    },
    MixRatio {
        name: "10/90",
        source_parts: 1,
        repair_parts: 9,
    },
];

#[derive(Debug, Arbitrary)]
struct RepairMixInput {
    k_selector: u16,
    symbol_size_selector: u16,
    seed: u64,
    extra_available_selector: u8,
    source_start: u16,
    source_stride: u16,
    repair_start: u16,
    repair_stride: u16,
    rotate_by: u16,
    order: SymbolOrder,
    source_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum SymbolOrder {
    SourcesThenRepairs,
    RepairsThenSources,
    AlternatingSourcesFirst,
    AlternatingRepairsFirst,
    Rotated,
}

#[derive(Debug, Clone, Copy)]
struct MixRatio {
    name: &'static str,
    source_parts: usize,
    repair_parts: usize,
}

fuzz_target!(|input: RepairMixInput| {
    let k = select_k(input.k_selector);
    let symbol_size = select_symbol_size(input.symbol_size_selector, k);
    let source = build_source_block(&input.source_bytes, k, symbol_size, input.seed);
    let Some(encoder) = SystematicEncoder::new(&source, symbol_size, input.seed) else {
        return;
    };
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);

    for ratio in MIX_RATIOS {
        assert_ratio_decodes(&input, ratio, &decoder, &encoder, &source);
    }
});

fn select_k(selector: u16) -> usize {
    K_CANDIDATES[usize::from(selector) % K_CANDIDATES.len()]
}

fn select_symbol_size(selector: u16, k: usize) -> usize {
    let selected = SYMBOL_SIZE_CANDIDATES[usize::from(selector) % SYMBOL_SIZE_CANDIDATES.len()];
    let max_symbol_size = (MAX_SOURCE_BYTES / k).max(1);
    if selected <= max_symbol_size {
        return selected;
    }

    SYMBOL_SIZE_CANDIDATES
        .iter()
        .copied()
        .filter(|candidate| *candidate <= max_symbol_size)
        .max()
        .unwrap_or(1)
}

fn build_source_block(payload: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let salt = seed.to_le_bytes();
    (0..k)
        .map(|row| {
            (0..symbol_size)
                .map(|col| {
                    let pattern =
                        (row as u8).wrapping_mul(31) ^ (col as u8).wrapping_mul(17) ^ 0xA5;
                    let payload_byte = payload
                        .get((row * symbol_size + col) % payload.len().max(1))
                        .copied()
                        .unwrap_or(0);
                    payload_byte ^ pattern ^ salt[(row + col) % salt.len()]
                })
                .collect()
        })
        .collect()
}

fn assert_ratio_decodes(
    input: &RepairMixInput,
    ratio: MixRatio,
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
) {
    let k = source.len();
    let total_available = total_available_for_ratio(k, ratio, input.extra_available_selector);
    let source_count = source_count_for_ratio(total_available, k, ratio);
    let repair_count = total_available - source_count;

    assert!(
        total_available >= k,
        "{} total available symbols must be >= K",
        ratio.name
    );
    assert!(
        source_count <= k,
        "{} source count must not exceed K",
        ratio.name
    );
    assert!(
        repair_count > 0,
        "{} mix must include at least one repair symbol",
        ratio.name
    );

    let source_symbols = build_source_symbols(
        source,
        source_count,
        input.source_start,
        input.source_stride,
    );
    let repair_symbols = build_repair_symbols(
        decoder,
        encoder,
        repair_count,
        input.repair_start,
        input.repair_stride,
    );
    let mixed_symbols = order_symbols(source_symbols, repair_symbols, input.order, input.rotate_by);

    assert_eq!(
        mixed_symbols.len(),
        total_available,
        "{} mixed symbol count must match the requested availability",
        ratio.name
    );

    let mut received = decoder.constraint_symbols();
    received.extend(mixed_symbols);

    let decoded = decoder.decode(&received).unwrap_or_else(|err| {
        panic!(
            "{} systematic/repair mix must decode when total available={} >= K={}: {err:?}",
            ratio.name, total_available, k
        )
    });

    assert_eq!(
        decoded.source, source,
        "{} systematic/repair mix must reconstruct the original source block",
        ratio.name
    );
}

fn total_available_for_ratio(k: usize, ratio: MixRatio, selector: u8) -> usize {
    let denominator = ratio.source_parts + ratio.repair_parts;
    let max_total_by_sources = k.saturating_mul(denominator) / ratio.source_parts;
    let max_total = max_total_by_sources.min(k + MAX_EXTRA_AVAILABLE).max(k);
    let extra_span = max_total - k;
    k + (usize::from(selector) % (extra_span + 1))
}

fn source_count_for_ratio(total_available: usize, k: usize, ratio: MixRatio) -> usize {
    let denominator = ratio.source_parts + ratio.repair_parts;
    let rounded = (total_available * ratio.source_parts + denominator / 2) / denominator;
    let mut source_count = rounded.clamp(1, k.min(total_available));
    if ratio.repair_parts > 0 && source_count == total_available {
        source_count -= 1;
    }
    source_count
}

fn build_source_symbols(
    source: &[Vec<u8>],
    source_count: usize,
    start: u16,
    stride: u16,
) -> Vec<ReceivedSymbol> {
    select_unique_indices(source.len(), source_count, start, stride)
        .into_iter()
        .map(|esi| ReceivedSymbol::source(esi as u32, source[esi].clone()))
        .collect()
}

fn build_repair_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    repair_count: usize,
    start: u16,
    stride: u16,
) -> Vec<ReceivedSymbol> {
    let k = decoder.params().k as u32;
    let repair_span = repair_count
        .saturating_mul(2)
        .saturating_add(REPAIR_SPAN_PADDING);

    select_unique_indices(repair_span, repair_count, start, stride)
        .into_iter()
        .map(|offset| {
            let esi = k + offset as u32;
            let (columns, coefficients) = decoder
                .repair_equation(esi)
                .expect("bounded repair ESI must have an RFC equation");
            let data = encoder.repair_symbol(esi);
            ReceivedSymbol::repair(esi, columns, coefficients, data)
        })
        .collect()
}

fn select_unique_indices(domain: usize, count: usize, start: u16, stride: u16) -> Vec<usize> {
    let target = count.min(domain);
    if target == 0 {
        return Vec::new();
    }

    let mut selected = Vec::with_capacity(target);
    let mut used = vec![false; domain];
    let step = (usize::from(stride) % domain).max(1);
    let mut candidate = usize::from(start) % domain;

    while selected.len() < target {
        if !used[candidate] {
            used[candidate] = true;
            selected.push(candidate);
        }

        candidate = (candidate + step) % domain;
        if used[candidate]
            && let Some(next) = used.iter().position(|is_used| !*is_used)
        {
            candidate = next;
        }
    }

    selected
}

fn order_symbols(
    mut sources: Vec<ReceivedSymbol>,
    mut repairs: Vec<ReceivedSymbol>,
    order: SymbolOrder,
    rotate_by: u16,
) -> Vec<ReceivedSymbol> {
    match order {
        SymbolOrder::SourcesThenRepairs => {
            sources.extend(repairs);
            sources
        }
        SymbolOrder::RepairsThenSources => {
            repairs.extend(sources);
            repairs
        }
        SymbolOrder::AlternatingSourcesFirst => interleave_symbols(sources, repairs),
        SymbolOrder::AlternatingRepairsFirst => interleave_symbols(repairs, sources),
        SymbolOrder::Rotated => {
            sources.extend(repairs);
            if !sources.is_empty() {
                let by = usize::from(rotate_by) % sources.len();
                sources.rotate_left(by);
            }
            sources
        }
    }
}

fn interleave_symbols(
    first: Vec<ReceivedSymbol>,
    second: Vec<ReceivedSymbol>,
) -> Vec<ReceivedSymbol> {
    let mut first = first.into_iter();
    let mut second = second.into_iter();
    let mut mixed = Vec::with_capacity(first.len() + second.len());

    loop {
        let mut progressed = false;
        if let Some(symbol) = first.next() {
            mixed.push(symbol);
            progressed = true;
        }
        if let Some(symbol) = second.next() {
            mixed.push(symbol);
            progressed = true;
        }
        if !progressed {
            return mixed;
        }
    }
}
