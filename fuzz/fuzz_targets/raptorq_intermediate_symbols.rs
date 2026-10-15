#![no_main]

//! Fuzz target for deterministic RaptorQ intermediate-symbol generation.
//!
//! The live low-level encoder surface is `raptorq::systematic::SystematicEncoder`.
//! Its constructor solves the precode system and exposes the resulting
//! intermediate symbols through `intermediate_symbol(i)`. This target drives
//! that path for K=10, K=100, and K=1000 source-block configurations and
//! asserts that rebuilding with the same source block and seed is byte-stable.

use arbitrary::Arbitrary;
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const K_VALUES: [usize; 3] = [10, 100, 1000];
const MAX_SMALL_SYMBOL_SIZE: usize = 64;
const MAX_MEDIUM_SYMBOL_SIZE: usize = 16;
const MAX_LARGE_SYMBOL_SIZE: usize = 4;
const REPAIR_PROBES: usize = 4;

#[derive(Arbitrary, Debug)]
struct IntermediateInput {
    symbol_size_selector: u16,
    seed: u64,
    source: Vec<u8>,
    perturb_source: bool,
}

fuzz_target!(|input: IntermediateInput| {
    for &k in &K_VALUES {
        exercise_k(k, &input);
    }
});

fn exercise_k(k: usize, input: &IntermediateInput) {
    let symbol_size = select_symbol_size(k, input.symbol_size_selector);
    let source_symbols = build_source_symbols(&input.source, k, symbol_size, input.seed);

    let first = build_encoder(&source_symbols, symbol_size, input.seed, k);
    let second = build_encoder(&source_symbols, symbol_size, input.seed, k);
    let (first, second) = match (first, second) {
        (Some(first), Some(second)) => (first, second),
        (None, None) => return,
        (left, right) => panic!(
            "encoder construction must be deterministic for K={k}, T={symbol_size}: left_some={}, right_some={}",
            left.is_some(),
            right.is_some()
        ),
    };

    assert_eq!(first.params().k, k, "encoder params must preserve public K");
    assert_eq!(
        first.params().symbol_size,
        symbol_size,
        "encoder params must preserve symbol size"
    );
    assert_eq!(
        first.params().l,
        first.stats().intermediate_symbol_count,
        "stats must report the full intermediate-symbol count"
    );
    assert_eq!(
        first.params().l,
        second.params().l,
        "same K/source/seed must derive the same intermediate-symbol count"
    );

    for index in 0..first.params().l {
        let left = first.intermediate_symbol(index);
        let right = second.intermediate_symbol(index);
        assert_eq!(
            left.len(),
            symbol_size,
            "intermediate symbol {index} must preserve symbol_size for K={k}"
        );
        assert_eq!(
            left, right,
            "intermediate symbol {index} must be deterministic for fixed seed K={k}"
        );
    }

    for offset in 0..REPAIR_PROBES {
        let esi = u32::try_from(k + offset).expect("bounded K fits in u32");
        assert_eq!(
            first.repair_symbol(esi),
            second.repair_symbol(esi),
            "repair output derived from intermediate symbols must be deterministic for K={k}, ESI={esi}"
        );
    }

    if input.perturb_source {
        let mut altered = source_symbols.clone();
        altered[0][0] ^= 0xA5;
        let altered_encoder = build_encoder(&altered, symbol_size, input.seed, k);
        if let Some(altered_encoder) = altered_encoder {
            assert_eq!(
                altered_encoder.params().l,
                first.params().l,
                "source-byte perturbation must not alter K-derived parameter shape"
            );
            assert_eq!(
                altered_encoder.intermediate_symbol(0).len(),
                symbol_size,
                "altered source block intermediate width must stay stable"
            );
        }
    }
}

fn build_encoder(
    source_symbols: &[Vec<u8>],
    symbol_size: usize,
    seed: u64,
    k: usize,
) -> Option<SystematicEncoder> {
    catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(source_symbols, symbol_size, seed)
    }))
    .unwrap_or_else(|_| {
        panic!("SystematicEncoder::new panicked for K={k}, T={symbol_size}, seed={seed}")
    })
}

fn select_symbol_size(k: usize, selector: u16) -> usize {
    let max = match k {
        10 => MAX_SMALL_SYMBOL_SIZE,
        100 => MAX_MEDIUM_SYMBOL_SIZE,
        1000 => MAX_LARGE_SYMBOL_SIZE,
        _ => unreachable!("target only exercises pinned K values"),
    };
    (usize::from(selector) % max) + 1
}

fn build_source_symbols(raw: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let seed_bytes = seed.to_le_bytes();
    let mut symbols = Vec::with_capacity(k);

    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let patterned = ((row * 31 + col * 17 + 0x63) & 0xFF) as u8;
            let byte = if raw.is_empty() {
                patterned ^ seed_bytes[(row + col) % seed_bytes.len()]
            } else {
                let raw_index = (row * symbol_size + col) % raw.len();
                raw[raw_index] ^ patterned ^ seed_bytes[(raw_index + row + col) % seed_bytes.len()]
            };
            symbol.push(byte);
        }
        symbols.push(symbol);
    }

    symbols
}
