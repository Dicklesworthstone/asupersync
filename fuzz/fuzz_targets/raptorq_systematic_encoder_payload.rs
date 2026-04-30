#![no_main]

//! Cargo-fuzz target for RaptorQ systematic-encoder payload edge handling.
//!
//! Drives `asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams}`
//! across four explicit K-edge cases: `K=1`, `K=42`, `K=2048`, and `K=8192`.
//! The first three run the real encoder/emission path; the `K=8192` lane
//! stays on parameter / repair-equation math so the fuzzer can keep making
//! forward progress instead of spending its budget inside the cubic solve.
//!
//!   1. **Constructor never panics** for any (K, symbol_size, seed)
//!      triple in the small/medium edge lanes. Configurations the systematic
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
//!   5. **Large-K rows stay coherent.** The tractable `K=2048` lane must
//!      build the real encoder, pin the live RFC row (`K'=2070`), and keep
//!      emission/order invariants intact. The `K=8192` lane must keep its
//!      parameter ladder, source chunking, and RFC repair-equation math
//!      coherent without relying on the full encoder solve on every fuzz
//!      iteration.
//!
//! Existing coverage: `codec_raptorq_roundtrip.rs` exercises the high-
//! level `EncodingPipeline` round-trip but not the low-level
//! `SystematicEncoder` API directly. This target locks the lower-level
//! contract so a regression in the precode/LT layer surfaces here even
//! when the higher-level decoder happens to compensate.

use arbitrary::Arbitrary;
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams};
use libfuzzer_sys::fuzz_target;

const SMALL_MEDIUM_MAX_SYMBOL_SIZE: usize = 256;
const TRACTABLE_LARGE_K_MAX_SYMBOL_SIZE: usize = 16;
const LARGE_K_MAX_SYMBOL_SIZE: usize = 8;
const SMALL_MEDIUM_MAX_REPAIR_COUNT: usize = 32;
const TRACTABLE_LARGE_K_MAX_REPAIR_COUNT: usize = 8;
const LARGE_K_MAX_REPAIR_COUNT: usize = 4;

/// Structured fuzz input. Derives Arbitrary so libFuzzer can mutate
/// each field independently (better coverage than reading raw bytes).
#[derive(Arbitrary, Debug, Clone, Copy)]
enum KEdge {
    K1,
    K42,
    K2048,
    K8192,
}

#[derive(Arbitrary, Debug)]
struct EncoderInput {
    /// Explicit edge-case K selector.
    k_edge: KEdge,
    /// Symbol size in bytes. Tightened further for K=2048 and K=8192.
    symbol_size: u16,
    /// Number of repair symbols to emit and validate.
    repair_count: u8,
    /// Encoder seed. Drives the precode randomness.
    seed: u64,
    /// Extra repair ESI probe offset for large-K parameter checks.
    probe_offset: u8,
    /// Source byte stream. Chunked into K source symbols of size
    /// `symbol_size`; padded with zeros if short, truncated if long.
    source: Vec<u8>,
}

fuzz_target!(|input: EncoderInput| {
    let k = match input.k_edge {
        KEdge::K1 => 1,
        KEdge::K42 => 42,
        KEdge::K2048 => 2048,
        KEdge::K8192 => 8192,
    };
    let symbol_size = match input.k_edge {
        KEdge::K2048 => {
            (usize::from(input.symbol_size) % TRACTABLE_LARGE_K_MAX_SYMBOL_SIZE) + 1
        }
        KEdge::K8192 => (usize::from(input.symbol_size) % LARGE_K_MAX_SYMBOL_SIZE) + 1,
        KEdge::K1 | KEdge::K42 => {
            (usize::from(input.symbol_size) % SMALL_MEDIUM_MAX_SYMBOL_SIZE) + 1
        }
    };
    let repair_count = match input.k_edge {
        KEdge::K2048 => {
            usize::from(input.repair_count) % (TRACTABLE_LARGE_K_MAX_REPAIR_COUNT + 1)
        }
        KEdge::K8192 => usize::from(input.repair_count) % (LARGE_K_MAX_REPAIR_COUNT + 1),
        KEdge::K1 | KEdge::K42 => {
            usize::from(input.repair_count) % (SMALL_MEDIUM_MAX_REPAIR_COUNT + 1)
        }
    };
    let params = SystematicParams::for_source_block(k, symbol_size);
    assert_eq!(params.k, k, "SystematicParams must preserve K");
    assert!(
        params.k_prime >= k,
        "SystematicParams must choose K' >= K (K={}, K'={})",
        k,
        params.k_prime
    );
    assert_eq!(
        params.l,
        params.k_prime + params.s + params.h,
        "L must equal K' + S + H"
    );
    if matches!(input.k_edge, KEdge::K2048) {
        assert_eq!(params.k_prime, 2070, "K=2048 must round up to the live RFC row");
        assert_eq!(params.j, 506, "K=2048 must pin the RFC J(K') value");
        assert_eq!(params.s, 89, "K=2048 must pin the RFC S(K') value");
        assert_eq!(params.h, 11, "K=2048 must pin the RFC H(K') value");
        assert_eq!(params.w, 2099, "K=2048 must pin the RFC W(K') value");
        assert_eq!(params.l, 2170, "K=2048 must pin the RFC L value");
        assert_eq!(params.b, 2010, "K=2048 must pin the RFC B value");
        assert!(
            params.k_prime > k,
            "K=2048 must exercise a rounded-up large-K systematic row"
        );
    }

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
    assert_eq!(
        source_symbols.len(),
        k,
        "source chunking must yield exactly K source symbols"
    );

    if matches!(input.k_edge, KEdge::K8192) {
        let repair_esi = (k as u32).saturating_add(u32::from(input.probe_offset % 4));
        let (columns, coefficients) = params
            .rfc_repair_equation(repair_esi)
            .expect("large-K repair equation generation must succeed");
        assert!(
            !columns.is_empty(),
            "large-K repair equations must reference at least one intermediate symbol"
        );
        assert_eq!(
            columns.len(),
            coefficients.len(),
            "large-K repair equation arity must stay matched"
        );
        assert!(
            columns.iter().all(|&column| column < params.l),
            "large-K repair equations must stay within intermediate-symbol bounds"
        );
        return;
    }

    // Property 1: constructor never panics. None is acceptable for
    // configurations the systematic block can't satisfy (e.g., the
    // constraint matrix happens to be singular for this seed/K
    // combination — extremely rare in practice but legal).
    let mut encoder = match SystematicEncoder::new(&source_symbols, symbol_size, input.seed) {
        Some(enc) => enc,
        None => return,
    };

    let emitted_systematic = encoder.emit_systematic();
    assert_eq!(
        emitted_systematic.len(),
        k,
        "emit_systematic must emit exactly K source symbols at edge K={k}"
    );
    for (esi, symbol) in emitted_systematic.iter().enumerate() {
        assert!(
            symbol.is_source,
            "systematic emission must stay on source lane"
        );
        assert_eq!(
            symbol.esi, esi as u32,
            "systematic ESI order must stay contiguous"
        );
        assert_eq!(
            symbol.data.len(),
            symbol_size,
            "systematic payload length must stay equal to symbol_size"
        );
        assert_eq!(
            symbol.data,
            source_symbols[esi],
            "systematic emission must preserve source payload bytes"
        );
    }

    // Property 2 + 3: probe every repair ESI in [K, K + repair_count)
    // and validate length. Track counts so we can also assert
    // K + repair_count emissions.
    let emitted_repairs = encoder.emit_repair(repair_count);
    assert_eq!(
        emitted_repairs.len(),
        repair_count,
        "emit_repair must emit the requested count"
    );
    let mut emitted = 0usize;
    for (offset, emitted_symbol) in emitted_repairs.iter().enumerate() {
        let esi = (k + offset) as u32;
        assert!(
            !emitted_symbol.is_source,
            "repair emission must stay on repair lane"
        );
        assert_eq!(
            emitted_symbol.esi, esi,
            "repair ESI order must stay contiguous"
        );
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
    assert_eq!(
        encoder.next_repair_esi(),
        (k + repair_count) as u32,
        "repair cursor must advance by the emitted repair count"
    );
});
