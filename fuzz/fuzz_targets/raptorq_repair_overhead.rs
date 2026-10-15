//! Structure-aware fuzz target for RaptorQ repair-symbol overhead decoding.
//!
//! The receiver is given fewer than K source symbols plus several repair
//! symbols. Whenever the received payload budget reaches at least K symbols,
//! direct decode must recover the original source block.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

const K_CANDIDATES: &[usize] = &[4, 8, 12, 16, 24, 32, 42, 64, 96, 128];
const SYMBOL_SIZE_CANDIDATES: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 96, 128];
const MAX_SOURCE_BYTES: usize = 128 * 128;
const MAX_MISSING_SELECTORS: usize = 64;
const MIN_REPAIR_OVERHEAD: usize = 2;
const MAX_EXTRA_REPAIR_OVERHEAD: usize = 8;

#[derive(Debug, Arbitrary)]
struct RepairOverheadInput {
    k_selector: u8,
    symbol_size_selector: u8,
    seed: u64,
    missing_count: u8,
    missing_selectors: Vec<u16>,
    extra_repair_overhead: u8,
    source_bytes: Vec<u8>,
    order: SymbolOrder,
}

#[derive(Debug, Clone, Copy, Arbitrary)]
enum SymbolOrder {
    SourcesThenRepairs,
    RepairsThenSources,
    Interleave,
    Reverse,
}

impl RepairOverheadInput {
    fn normalize(&mut self) {
        self.source_bytes.truncate(MAX_SOURCE_BYTES);
        self.missing_selectors.truncate(MAX_MISSING_SELECTORS);
    }
}

fn select_k(selector: u8) -> usize {
    K_CANDIDATES[usize::from(selector) % K_CANDIDATES.len()]
}

fn select_symbol_size(selector: u8) -> usize {
    SYMBOL_SIZE_CANDIDATES[usize::from(selector) % SYMBOL_SIZE_CANDIDATES.len()]
}

fn build_source_block(raw: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let salt = seed.to_le_bytes();
    let mut source = Vec::with_capacity(k);

    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let patterned = ((row * 41 + col * 19 + 0xA5) & 0xFF) as u8;
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

fn missing_source_indices(input: &RepairOverheadInput, k: usize) -> Vec<usize> {
    let target = (usize::from(input.missing_count) % (k - 1)).saturating_add(1);
    let mut missing = Vec::with_capacity(target);
    let mut used = vec![false; k];
    let stride = (((input.seed.rotate_left(11) as usize) | 1) % k.max(2)).max(1);
    let mut cursor = input.seed as usize % k;

    for offset in 0..target {
        let selector = input
            .missing_selectors
            .get(offset)
            .copied()
            .unwrap_or_else(|| input.seed.wrapping_add(offset as u64) as u16);
        let mut candidate = (cursor + usize::from(selector)) % k;
        while used[candidate] {
            candidate = (candidate + stride) % k;
        }
        used[candidate] = true;
        missing.push(candidate);
        cursor = (candidate + stride) % k;
    }

    missing
}

fn build_payload_symbols(
    decoder: &InactivationDecoder,
    encoder: &SystematicEncoder,
    source: &[Vec<u8>],
    missing: &[usize],
    repair_count: usize,
) -> Vec<ReceivedSymbol> {
    let k = source.len();
    let mut is_missing = vec![false; k];
    for &index in missing {
        is_missing[index] = true;
    }

    let mut symbols = Vec::with_capacity(k.saturating_sub(missing.len()) + repair_count);
    for (esi, data) in source.iter().enumerate() {
        if !is_missing[esi] {
            symbols.push(ReceivedSymbol::source(esi as u32, data.clone()));
        }
    }

    for repair_offset in 0..repair_count {
        let esi = k as u32 + repair_offset as u32;
        let (columns, coefficients) = decoder
            .repair_equation(esi)
            .expect("bounded repair ESI must produce an equation");
        let data = encoder.repair_symbol(esi);
        symbols.push(ReceivedSymbol::repair(esi, columns, coefficients, data));
    }

    symbols
}

fn apply_order(symbols: &mut Vec<ReceivedSymbol>, order: SymbolOrder) {
    match order {
        SymbolOrder::SourcesThenRepairs => {}
        SymbolOrder::RepairsThenSources => {
            symbols.sort_by_key(|symbol| symbol.is_source);
        }
        SymbolOrder::Interleave => {
            let (sources, repairs): (Vec<_>, Vec<_>) =
                symbols.drain(..).partition(|symbol| symbol.is_source);
            let mut sources = sources.into_iter();
            let mut repairs = repairs.into_iter();
            while let Some(repair) = repairs.next() {
                symbols.push(repair);
                if let Some(source) = sources.next() {
                    symbols.push(source);
                }
            }
            symbols.extend(sources);
        }
        SymbolOrder::Reverse => symbols.reverse(),
    }
}

fn exercise_repair_overhead(mut input: RepairOverheadInput) {
    input.normalize();

    let k = select_k(input.k_selector);
    let symbol_size = select_symbol_size(input.symbol_size_selector);
    let source = build_source_block(&input.source_bytes, k, symbol_size, input.seed);
    let encoder = SystematicEncoder::new(&source, symbol_size, input.seed)
        .expect("bounded source block must be encodable");
    let decoder = InactivationDecoder::new(k, symbol_size, input.seed);
    let missing = missing_source_indices(&input, k);
    let repair_overhead = MIN_REPAIR_OVERHEAD
        + usize::from(input.extra_repair_overhead % (MAX_EXTRA_REPAIR_OVERHEAD as u8 + 1));
    let repair_count = missing.len().saturating_add(repair_overhead);
    let mut payload_symbols =
        build_payload_symbols(&decoder, &encoder, &source, &missing, repair_count);
    apply_order(&mut payload_symbols, input.order);

    let received_sources = payload_symbols
        .iter()
        .filter(|symbol| symbol.is_source)
        .count();
    let received_repairs = payload_symbols
        .iter()
        .filter(|symbol| !symbol.is_source)
        .count();

    assert!(
        received_sources < k,
        "repair-overhead target must exercise fewer-than-K source symbols"
    );
    assert!(
        received_repairs >= 3,
        "repair-overhead target must exercise several repair symbols"
    );
    assert!(
        payload_symbols.len() >= k,
        "repair-overhead target must only assert decode when total payload symbols >= K"
    );

    let mut received = decoder.constraint_symbols();
    received.extend(payload_symbols);
    let decoded = decoder
        .decode(&received)
        .expect("fewer-than-K source symbols plus repair overhead should decode when total >= K");
    assert_eq!(
        decoded.source, source,
        "repair-overhead decode must recover the original source block"
    );
}

fuzz_target!(|input: RepairOverheadInput| {
    exercise_repair_overhead(input);
});
