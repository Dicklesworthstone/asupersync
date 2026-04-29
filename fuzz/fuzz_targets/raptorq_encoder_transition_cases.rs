#![no_main]

//! Cargo-fuzz target for low-K RaptorQ encoder transition cases.
//!
//! Focuses on the smallest valid source-block sizes (`K=1`, `K=2`, `K=3`,
//! `K=4`), where the encoder crosses from the degenerate single-symbol lane
//! into the first genuinely non-degenerate multi-symbol ladder entries. For
//! arbitrary source bytes and repair counts we assert:
//!
//! 1. `SystematicEncoder::new` never panics and succeeds for valid low-K
//!    source blocks.
//! 2. `emit_all(repair_count)` returns exactly `K + repair_count` symbols.
//! 3. The emitted source prefix stays contiguous at ESIs `0..K-1` and
//!    preserves the original source payload bytes.
//! 4. The emitted repair suffix stays contiguous at ESIs `K..K+repair_count-1`.
//! 5. Every emitted repair payload matches `repair_symbol(esi)` exactly, so
//!    `emit_all` and the on-demand repair lane stay coherent.
//! 6. Every emitted payload stays exactly `symbol_size` bytes wide and the
//!    repair cursor advances by exactly `repair_count`.

use arbitrary::Arbitrary;
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

const MAX_SYMBOL_SIZE: usize = 128;
const MAX_REPAIR_COUNT: usize = 32;

#[derive(Arbitrary, Debug, Clone, Copy)]
enum TransitionK {
    K1,
    K2,
    K3,
    K4,
}

#[derive(Arbitrary, Debug)]
struct TransitionInput {
    k_case: TransitionK,
    symbol_size: u16,
    repair_count: u8,
    seed: u64,
    source: Vec<u8>,
}

fn chunk_source_bytes(source: &[u8], k: usize, symbol_size: usize) -> Vec<Vec<u8>> {
    let mut source_symbols = Vec::with_capacity(k);
    for i in 0..k {
        let start = i.saturating_mul(symbol_size);
        let end = start.saturating_add(symbol_size);
        let mut symbol = vec![0u8; symbol_size];
        if start < source.len() {
            let available_end = end.min(source.len());
            let copy_len = available_end - start;
            symbol[..copy_len].copy_from_slice(&source[start..available_end]);
        }
        source_symbols.push(symbol);
    }
    source_symbols
}

fuzz_target!(|input: TransitionInput| {
    let k = match input.k_case {
        TransitionK::K1 => 1,
        TransitionK::K2 => 2,
        TransitionK::K3 => 3,
        TransitionK::K4 => 4,
    };
    let symbol_size = (usize::from(input.symbol_size) % MAX_SYMBOL_SIZE) + 1;
    let repair_count = usize::from(input.repair_count) % (MAX_REPAIR_COUNT + 1);
    let source_symbols = chunk_source_bytes(&input.source, k, symbol_size);

    let mut encoder = SystematicEncoder::new(&source_symbols, symbol_size, input.seed)
        .unwrap_or_else(|| {
            panic!("low-K encoder construction must succeed for K={k}, T={symbol_size}")
        });

    let emitted = encoder.emit_all(repair_count);
    assert_eq!(
        emitted.len(),
        k + repair_count,
        "emit_all must return exactly K + repair_count symbols for K={k}"
    );

    for (expected_esi, symbol) in emitted.iter().take(k).enumerate() {
        assert!(
            symbol.is_source,
            "systematic prefix must stay on source lane"
        );
        assert_eq!(
            symbol.esi, expected_esi as u32,
            "systematic prefix must use contiguous ESIs for K={k}"
        );
        assert_eq!(
            symbol.data.len(),
            symbol_size,
            "systematic payload width must stay equal to symbol_size"
        );
        assert_eq!(
            symbol.data, source_symbols[expected_esi],
            "systematic prefix must preserve original source bytes for K={k}"
        );
        assert_eq!(
            symbol.degree, 1,
            "systematic symbols must retain degree=1 identity equations"
        );
    }

    for (offset, symbol) in emitted.iter().skip(k).enumerate() {
        let expected_esi = (k + offset) as u32;
        assert!(
            !symbol.is_source,
            "repair suffix must stay on repair lane for K={k}"
        );
        assert_eq!(
            symbol.esi, expected_esi,
            "repair suffix must use contiguous ESIs for K={k}"
        );
        assert_eq!(
            symbol.data.len(),
            symbol_size,
            "repair payload width must stay equal to symbol_size"
        );
        assert!(
            symbol.degree > 0,
            "repair suffix must expose a non-zero LT degree for K={k}"
        );
        assert_eq!(
            symbol.data,
            encoder.repair_symbol(expected_esi),
            "emit_all repair payload must match repair_symbol(esi) for K={k}, esi={expected_esi}"
        );
    }

    assert_eq!(
        encoder.next_repair_esi(),
        (k + repair_count) as u32,
        "repair cursor must advance by the emitted repair count for K={k}"
    );
});
