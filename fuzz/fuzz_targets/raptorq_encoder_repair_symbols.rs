//! Fuzz target for RaptorQ systematic repair-symbol generation.
//!
//! Exercises `SystematicEncoder::emit_repair` and `repair_symbol` across
//! fixed K rows, including large RFC parameter rows.

#![no_main]

use std::panic::{AssertUnwindSafe, catch_unwind};

use arbitrary::Arbitrary;
use asupersync::raptorq::systematic::{EmittedSymbol, SystematicEncoder};
use libfuzzer_sys::fuzz_target;

const K_VALUES: [usize; 6] = [1, 2, 10, 100, 1024, 8192];
const MAX_SOURCE_BYTES: usize = 4096;

#[derive(Debug, Arbitrary)]
struct RepairSymbolInput {
    k_selector: u8,
    symbol_size_selector: u8,
    repair_count_selector: u8,
    seed: u64,
    source_bytes: Vec<u8>,
    split_emit: bool,
}

fuzz_target!(|mut input: RepairSymbolInput| {
    input.source_bytes.truncate(MAX_SOURCE_BYTES);

    let k = K_VALUES[usize::from(input.k_selector) % K_VALUES.len()];
    let symbol_size = select_symbol_size(k, input.symbol_size_selector);
    let repair_count = select_repair_count(k, input.repair_count_selector);
    let source_symbols = build_source_symbols(&input.source_bytes, k, symbol_size, input.seed);

    let encoder_result = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source_symbols, symbol_size, input.seed)
    }));
    let mut encoder = match encoder_result {
        Ok(Some(encoder)) => encoder,
        Ok(None) => return,
        Err(_) => panic!("SystematicEncoder::new panicked for K={k}, T={symbol_size}"),
    };

    let emitted = catch_unwind(AssertUnwindSafe(|| {
        emit_requested_repairs(&mut encoder, repair_count, input.split_emit)
    }))
    .unwrap_or_else(|_| {
        panic!("emit_repair panicked for K={k}, T={symbol_size}, repair_count={repair_count}")
    });

    assert_eq!(
        emitted.len(),
        repair_count,
        "emit_repair must emit exactly the requested repair count"
    );

    for (offset, symbol) in emitted.iter().enumerate() {
        let expected_esi = u32::try_from(k + offset).expect("bounded fuzz K fits in u32");
        assert_repair_symbol(symbol, expected_esi, symbol_size);

        let direct = catch_unwind(AssertUnwindSafe(|| encoder.repair_symbol(expected_esi)))
            .unwrap_or_else(|_| {
                panic!("repair_symbol panicked for K={k}, T={symbol_size}, ESI={expected_esi}")
            });
        assert!(
            !direct.is_empty(),
            "repair_symbol must never produce zero-length payloads"
        );
        assert_eq!(
            direct.len(),
            symbol_size,
            "repair_symbol must preserve symbol_size"
        );
    }
});

fn emit_requested_repairs(
    encoder: &mut SystematicEncoder,
    repair_count: usize,
    split_emit: bool,
) -> Vec<EmittedSymbol> {
    if !split_emit || repair_count <= 1 {
        return encoder.emit_repair(repair_count);
    }

    let first_count = repair_count / 2;
    let mut emitted = encoder.emit_repair(first_count);
    emitted.extend(encoder.emit_repair(repair_count - first_count));
    emitted
}

fn assert_repair_symbol(symbol: &EmittedSymbol, expected_esi: u32, symbol_size: usize) {
    assert!(
        !symbol.is_source,
        "emit_repair must stay on the repair-symbol lane"
    );
    assert_eq!(
        symbol.esi, expected_esi,
        "emit_repair must emit contiguous repair ESIs"
    );
    assert!(
        !symbol.data.is_empty(),
        "emit_repair must never produce zero-length payloads"
    );
    assert_eq!(
        symbol.data.len(),
        symbol_size,
        "emit_repair must preserve symbol_size"
    );
    assert!(symbol.degree > 0, "repair symbols must have nonzero degree");
}

fn select_symbol_size(k: usize, selector: u8) -> usize {
    let max = match k {
        8192 => 1,
        1024 => 4,
        100 => 16,
        _ => 64,
    };
    (usize::from(selector) % max) + 1
}

fn select_repair_count(k: usize, selector: u8) -> usize {
    let max = match k {
        8192 => 4,
        1024 => 8,
        100 => 16,
        _ => 32,
    };
    (usize::from(selector) % max) + 1
}

fn build_source_symbols(raw: &[u8], k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    let salt = seed.to_le_bytes();
    let mut source_symbols = Vec::with_capacity(k);

    for row in 0..k {
        let mut symbol = Vec::with_capacity(symbol_size);
        for col in 0..symbol_size {
            let patterned = ((row * 37 + col * 13 + 0x5A) & 0xFF) as u8;
            let byte = if raw.is_empty() {
                patterned ^ salt[(row + col) % salt.len()]
            } else {
                let idx = (row * symbol_size + col) % raw.len();
                raw[idx] ^ patterned ^ salt[(idx + row + col) % salt.len()]
            };
            symbol.push(byte);
        }
        source_symbols.push(symbol);
    }

    source_symbols
}
