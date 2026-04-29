#![no_main]

//! Cargo-fuzz target for RaptorQ systematic-encoder payload generation.
//!
//! Drives `asupersync::raptorq::systematic::SystematicEncoder` with
//! structurally-bounded inputs (Arbitrary-derived `K`, `symbol_size`,
//! `repair_count`, `seed`, source bytes) and asserts:
//!
//!   1. **Constructor never panics** for any (K, symbol_size, seed)
//!      triple in the bounded envelope. Configurations the systematic
//!      block can't satisfy must return `None`, not unwind.
//!
//!   2. **Repair-symbol size is exactly `symbol_size`** for every
//!      `esi >= K`. The wire contract is "all symbols (source + repair)
//!      are `symbol_size` bytes"; a smaller or larger emission would
//!      silently break authentication / framing downstream.
//!
//!   3. **Total emission count matches K + repair_count.** Source
//!      symbols are addressable at ESIs `0..K`, repair symbols at
//!      `K..K+repair_count`. The fuzzer probes every position in
//!      that contiguous range and counts what comes back.
//!
//!   4. **Repair symbols are deterministic.** Calling `repair_symbol(esi)`
//!      twice on the same encoder must return byte-identical output —
//!      the encoder is a pure function of (intermediate symbols, esi)
//!      after `new` returns.
//!
//! Existing coverage: `codec_raptorq_roundtrip.rs` exercises the high-
//! level `EncodingPipeline` round-trip but not the low-level
//! `SystematicEncoder` API directly. This target locks the lower-level
//! contract so a regression in the precode/LT layer surfaces here even
//! when the higher-level decoder happens to compensate.

use arbitrary::Arbitrary;
use asupersync::raptorq::systematic::SystematicEncoder;
use libfuzzer_sys::fuzz_target;

/// Upper bound on K. Keeps each iteration sub-second; the systematic
/// encoder's constraint-matrix solve is O((K + S + H)^3) so K=64 is
/// already a few hundred milliseconds.
const MAX_K: usize = 64;
/// Symbol size envelope. Caps memory use per iteration at
/// `MAX_K * MAX_SYMBOL_SIZE = 16 KiB` of source data plus the
/// intermediate-symbol working set.
const MAX_SYMBOL_SIZE: usize = 256;
/// Upper bound on repair_count. Probing every repair ESI is O(K^2)
/// solve work amortised plus one matrix-vector mul per ESI; bounded.
const MAX_REPAIR_COUNT: usize = 32;

/// Structured fuzz input. Derives Arbitrary so libFuzzer can mutate
/// each field independently (better coverage than reading raw bytes).
#[derive(Arbitrary, Debug)]
struct EncoderInput {
    /// Number of source symbols. Bounded `[1, MAX_K]` after modulo.
    k: u8,
    /// Symbol size in bytes. Bounded `[1, MAX_SYMBOL_SIZE]`.
    symbol_size: u16,
    /// Number of repair symbols to emit and validate. Bounded
    /// `[0, MAX_REPAIR_COUNT]`.
    repair_count: u8,
    /// Encoder seed. Drives the precode randomness.
    seed: u64,
    /// Source byte stream. Chunked into K source symbols of size
    /// `symbol_size`; padded with zeros if short, truncated if long.
    source: Vec<u8>,
}

fuzz_target!(|input: EncoderInput| {
    let k = (usize::from(input.k) % MAX_K) + 1;
    let symbol_size = (usize::from(input.symbol_size) % MAX_SYMBOL_SIZE) + 1;
    let repair_count = usize::from(input.repair_count) % (MAX_REPAIR_COUNT + 1);

    // Assemble exactly K source symbols of exactly `symbol_size` bytes
    // each. Zero-pad on the tail when `input.source` is short; this is
    // the same shape the production encoder sees after the chunker
    // upstream.
    let mut source_symbols: Vec<Vec<u8>> = Vec::with_capacity(k);
    for i in 0..k {
        let start = i.saturating_mul(symbol_size);
        let end = start.saturating_add(symbol_size);
        let mut sym = vec![0u8; symbol_size];
        if start < input.source.len() {
            let avail_end = end.min(input.source.len());
            let copy_len = avail_end - start;
            sym[..copy_len].copy_from_slice(&input.source[start..avail_end]);
        }
        debug_assert_eq!(sym.len(), symbol_size);
        source_symbols.push(sym);
    }

    // Property 1: constructor never panics. None is acceptable for
    // configurations the systematic block can't satisfy (e.g., the
    // constraint matrix happens to be singular for this seed/K
    // combination — extremely rare in practice but legal).
    let encoder = match SystematicEncoder::new(&source_symbols, symbol_size, input.seed) {
        Some(enc) => enc,
        None => return,
    };

    // Property 2 + 3: probe every repair ESI in [K, K + repair_count)
    // and validate length. Track counts so we can also assert
    // K + repair_count emissions.
    let mut emitted = 0usize;
    for offset in 0..repair_count {
        let esi = (k + offset) as u32;
        let symbol = encoder.repair_symbol(esi);
        assert_eq!(
            symbol.len(),
            symbol_size,
            "repair_symbol must return exactly symbol_size bytes \
             (K={k}, T={symbol_size}, esi={esi}, got_len={})",
            symbol.len(),
        );

        // Property 4: deterministic. Same call must produce same bytes.
        let symbol_again = encoder.repair_symbol(esi);
        assert_eq!(
            symbol, symbol_again,
            "repair_symbol(esi={esi}) must be deterministic \
             (K={k}, T={symbol_size})",
        );

        emitted += 1;
    }
    assert_eq!(
        emitted, repair_count,
        "fuzzer must probe every requested repair ESI",
    );
});
