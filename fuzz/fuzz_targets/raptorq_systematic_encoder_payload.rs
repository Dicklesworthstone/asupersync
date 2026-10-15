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
//!   6. **Extreme symbol sizes stay width-stable.** A dedicated small-K lane
//!      probes 1-byte through 4096-byte symbols so systematic emission,
//!      on-demand repair, buffered repair, and cursor-based repair emission all
//!      preserve the configured `symbol_size` exactly.
//!
//!   7. **K=10 all-zero source stays algebraically zero.** The first exact RFC
//!      row (`K'=10`) gets a dedicated all-zero source block lane. Systematic,
//!      on-demand repair, buffered repair, and stream repair outputs must all
//!      stay exactly zero and exactly `symbol_size` bytes wide.
//!
//! Existing coverage: `codec_raptorq_roundtrip.rs` exercises the high-
//! level `EncodingPipeline` round-trip but not the low-level
//! `SystematicEncoder` API directly. This target locks the lower-level
//! contract so a regression in the precode/LT layer surfaces here even
//! when the higher-level decoder happens to compensate.

use arbitrary::Arbitrary;
use asupersync::raptorq::systematic::{SystematicEncoder, SystematicParams};
use libfuzzer_sys::fuzz_target;
use std::panic::{AssertUnwindSafe, catch_unwind};

const SMALL_MEDIUM_MAX_SYMBOL_SIZE: usize = 256;
const TRACTABLE_LARGE_K_MAX_SYMBOL_SIZE: usize = 16;
const LARGE_K_MAX_SYMBOL_SIZE: usize = 8;
const SMALL_MEDIUM_MAX_REPAIR_COUNT: usize = 32;
const TRACTABLE_LARGE_K_MAX_REPAIR_COUNT: usize = 8;
const LARGE_K_MAX_REPAIR_COUNT: usize = 4;
const MAX_MALFORMED_SOURCE_SYMBOLS: usize = 32;
const MAX_MALFORMED_SYMBOL_BYTES: usize = 512;
const EXTREME_MAX_SYMBOL_SIZE: usize = 4096;
const EXTREME_REPAIR_PROBES: usize = 3;
const K10_ALL_ZERO_K: usize = 10;
const K10_MAX_REPAIR_COUNT: usize = 8;

/// Structured fuzz input. Derives Arbitrary so libFuzzer can mutate
/// each field independently (better coverage than reading raw bytes).
#[derive(Arbitrary, Debug, Clone, Copy)]
enum KEdge {
    K1,
    K42,
    K2048,
    K8192,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum MalformedSourceBlockKind {
    Empty,
    ShortFirst,
    LongFirst,
    MixedLengths,
    ZeroSymbolSize,
    WellFormedControl,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ExtremeSymbolK {
    K1,
    K2,
    K8,
    K17,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum ExtremeSymbolSize {
    OneByte,
    TwoBytes,
    ThreeBytes,
    ThirtyOneBytes,
    ThirtyTwoBytes,
    ThirtyThreeBytes,
    TwoFiftyFiveBytes,
    TwoFiftySixBytes,
    TwoFiftySevenBytes,
    FiveElevenBytes,
    FiveTwelveBytes,
    OneKiB,
    TwoKiB,
    FourKiB,
    Raw { value: u16 },
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct SymbolSizeExtremeInput {
    k_case: ExtremeSymbolK,
    symbol_size: ExtremeSymbolSize,
    seed: u64,
    source_seed: u64,
    repair_offset: u8,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
struct K10AllZeroInput {
    symbol_size: ExtremeSymbolSize,
    repair_count: u8,
    seed: u64,
    repair_offset: u8,
    emit_all_first: bool,
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
    /// Independent valid-lane probe for very small and very large symbol
    /// sizes. Kept on small K values so the fuzzer can exercise wide payloads
    /// without spending the whole budget in the matrix solve.
    symbol_size_extreme: SymbolSizeExtremeInput,
    /// Dedicated valid-input oracle for the first exact RFC row: K=10 with an
    /// all-zero source block.
    k10_all_zero: K10AllZeroInput,
    /// Explicit malformed source-block lane. This is independent of the
    /// well-formed source chunker above so fuzzing can hit constructor
    /// precondition failures directly.
    malformed_kind: MalformedSourceBlockKind,
    malformed_symbol_size: u16,
    malformed_symbols: Vec<Vec<u8>>,
}

fn truncate_malformed_symbols(symbols: &mut Vec<Vec<u8>>) {
    symbols.truncate(MAX_MALFORMED_SOURCE_SYMBOLS);
    for symbol in symbols {
        symbol.truncate(MAX_MALFORMED_SYMBOL_BYTES);
    }
}

fn build_malformed_source_block(
    kind: MalformedSourceBlockKind,
    symbol_size: usize,
    mut symbols: Vec<Vec<u8>>,
) -> (Vec<Vec<u8>>, usize, bool) {
    truncate_malformed_symbols(&mut symbols);

    match kind {
        MalformedSourceBlockKind::Empty => (Vec::new(), symbol_size.max(1), true),
        MalformedSourceBlockKind::ShortFirst => {
            if symbols.is_empty() {
                symbols.push(vec![0u8; symbol_size.max(1)]);
            }
            let malformed_symbol_size = symbol_size.max(2);
            symbols[0].truncate(malformed_symbol_size - 1);
            for symbol in symbols.iter_mut().skip(1) {
                symbol.resize(malformed_symbol_size, 0x5A);
            }
            (symbols, malformed_symbol_size, true)
        }
        MalformedSourceBlockKind::LongFirst => {
            if symbols.is_empty() {
                symbols.push(vec![0u8; symbol_size.max(1)]);
            }
            let malformed_symbol_size = symbol_size.max(1);
            symbols[0].resize(malformed_symbol_size.saturating_add(1), 0xA5);
            for symbol in symbols.iter_mut().skip(1) {
                symbol.resize(malformed_symbol_size, 0x5A);
            }
            (symbols, malformed_symbol_size, true)
        }
        MalformedSourceBlockKind::MixedLengths => {
            if symbols.len() < 2 {
                symbols.resize_with(2, Vec::new);
            }
            let malformed_symbol_size = symbol_size.max(1);
            symbols[0].resize(malformed_symbol_size, 0x11);
            symbols[1].resize(malformed_symbol_size.saturating_add(1), 0x22);
            for symbol in symbols.iter_mut().skip(2) {
                symbol.resize(malformed_symbol_size, 0x33);
            }
            (symbols, malformed_symbol_size, true)
        }
        MalformedSourceBlockKind::ZeroSymbolSize => {
            if symbols.is_empty() {
                symbols.push(Vec::new());
            }
            for symbol in &mut symbols {
                symbol.clear();
            }
            (symbols, 0, false)
        }
        MalformedSourceBlockKind::WellFormedControl => {
            if symbols.is_empty() {
                symbols.push(Vec::new());
            }
            let control_symbol_size = symbol_size.max(1);
            for symbol in &mut symbols {
                symbol.resize(control_symbol_size, 0xC3);
            }
            (symbols, control_symbol_size, false)
        }
    }
}

fn resolve_extreme_k(k_case: ExtremeSymbolK) -> usize {
    match k_case {
        ExtremeSymbolK::K1 => 1,
        ExtremeSymbolK::K2 => 2,
        ExtremeSymbolK::K8 => 8,
        ExtremeSymbolK::K17 => 17,
    }
}

fn resolve_extreme_symbol_size(symbol_size: ExtremeSymbolSize) -> usize {
    match symbol_size {
        ExtremeSymbolSize::OneByte => 1,
        ExtremeSymbolSize::TwoBytes => 2,
        ExtremeSymbolSize::ThreeBytes => 3,
        ExtremeSymbolSize::ThirtyOneBytes => 31,
        ExtremeSymbolSize::ThirtyTwoBytes => 32,
        ExtremeSymbolSize::ThirtyThreeBytes => 33,
        ExtremeSymbolSize::TwoFiftyFiveBytes => 255,
        ExtremeSymbolSize::TwoFiftySixBytes => 256,
        ExtremeSymbolSize::TwoFiftySevenBytes => 257,
        ExtremeSymbolSize::FiveElevenBytes => 511,
        ExtremeSymbolSize::FiveTwelveBytes => 512,
        ExtremeSymbolSize::OneKiB => 1024,
        ExtremeSymbolSize::TwoKiB => 2048,
        ExtremeSymbolSize::FourKiB => EXTREME_MAX_SYMBOL_SIZE,
        ExtremeSymbolSize::Raw { value } => (usize::from(value) % EXTREME_MAX_SYMBOL_SIZE) + 1,
    }
}

fn build_seeded_source_symbols(k: usize, symbol_size: usize, seed: u64) -> Vec<Vec<u8>> {
    (0..k)
        .map(|row| {
            let row_seed = seed.wrapping_add(
                u64::try_from(row)
                    .expect("bounded fuzz row must fit in u64")
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15),
            );
            (0..symbol_size)
                .map(|col| {
                    let rotation = u32::try_from(col % 63).expect("rotation must fit in u32");
                    let mixed = row_seed.rotate_left(rotation)
                        ^ u64::try_from(col)
                            .expect("bounded fuzz column must fit in u64")
                            .wrapping_mul(0xD1B5_4A32_D192_ED03);
                    u8::try_from(mixed & 0xFF).expect("masked byte must fit in u8")
                })
                .collect()
        })
        .collect()
}

fn assert_symbol_size_extreme_lane(input: SymbolSizeExtremeInput) {
    let k = resolve_extreme_k(input.k_case);
    let symbol_size = resolve_extreme_symbol_size(input.symbol_size);
    let source_symbols = build_seeded_source_symbols(k, symbol_size, input.source_seed);

    let constructed = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source_symbols, symbol_size, input.seed)
    }))
    .unwrap_or_else(|_| {
        panic!(
            "encoder construction panicked for symbol-size extreme lane: \
             K={k}, T={symbol_size}"
        )
    });
    let Some(mut encoder) = constructed else {
        return;
    };

    assert_eq!(
        encoder.params().symbol_size,
        symbol_size,
        "encoder params must preserve the configured symbol_size"
    );

    let systematic = encoder.emit_systematic();
    assert_eq!(
        systematic.len(),
        k,
        "extreme symbol-size lane must emit every source symbol"
    );
    for (expected_esi, symbol) in systematic.iter().enumerate() {
        assert!(symbol.is_source, "source lane must stay systematic");
        assert_eq!(
            symbol.esi, expected_esi as u32,
            "source lane must preserve contiguous ESIs"
        );
        assert_eq!(
            symbol.data.len(),
            symbol_size,
            "systematic payload must preserve extreme symbol_size"
        );
        assert_eq!(
            symbol.data, source_symbols[expected_esi],
            "systematic payload must preserve source bytes"
        );
    }

    let k_u32 = u32::try_from(k).expect("bounded fuzz K must fit in u32");
    let repair_start = k_u32.saturating_add(u32::from(input.repair_offset % 4));
    for offset in 0..EXTREME_REPAIR_PROBES {
        let esi = repair_start.saturating_add(u32::try_from(offset).expect("offset fits"));
        let repair = encoder.repair_symbol(esi);
        assert_eq!(
            repair.len(),
            symbol_size,
            "repair_symbol must preserve extreme symbol_size \
             (K={k}, T={symbol_size}, esi={esi})"
        );

        let mut buffered =
            vec![0xA5; symbol_size.saturating_add(usize::from(input.repair_offset % 3))];
        encoder.repair_symbol_into(esi, &mut buffered);
        assert_eq!(
            &buffered[..symbol_size],
            repair.as_slice(),
            "repair_symbol_into must match repair_symbol for extreme symbol_size"
        );
    }

    let emitted_repairs = encoder.emit_repair(EXTREME_REPAIR_PROBES);
    assert_eq!(
        emitted_repairs.len(),
        EXTREME_REPAIR_PROBES,
        "extreme symbol-size lane must emit requested repairs"
    );
    for (offset, symbol) in emitted_repairs.iter().enumerate() {
        assert!(
            !symbol.is_source,
            "repair lane must not emit source symbols"
        );
        assert_eq!(
            symbol.esi,
            k_u32.saturating_add(u32::try_from(offset).expect("offset fits")),
            "repair lane must start at K after source emission"
        );
        assert_eq!(
            symbol.data.len(),
            symbol_size,
            "emit_repair payload must preserve extreme symbol_size"
        );
    }
    assert_eq!(
        encoder.next_repair_esi(),
        k_u32.saturating_add(
            u32::try_from(EXTREME_REPAIR_PROBES).expect("repair probe count must fit in u32")
        ),
        "repair cursor must advance by emitted repair count in the extreme lane"
    );
}

fn assert_all_zero_emitted_symbol(
    symbol: &asupersync::raptorq::systematic::EmittedSymbol,
    expected_esi: u32,
    expected_is_source: bool,
    symbol_size: usize,
) {
    assert_eq!(
        symbol.is_source, expected_is_source,
        "K=10 all-zero lane emitted symbol on the wrong source/repair lane"
    );
    assert_eq!(
        symbol.esi, expected_esi,
        "K=10 all-zero lane emitted unexpected ESI"
    );
    assert_eq!(
        symbol.data.len(),
        symbol_size,
        "K=10 all-zero lane emitted wrong payload width"
    );
    assert!(
        symbol.data.iter().all(|&byte| byte == 0),
        "K=10 all-zero source must only emit all-zero payloads"
    );
}

fn assert_k10_all_zero_lane(input: K10AllZeroInput) {
    let symbol_size = resolve_extreme_symbol_size(input.symbol_size);
    let repair_count = usize::from(input.repair_count) % (K10_MAX_REPAIR_COUNT + 1);
    let source_symbols = vec![vec![0u8; symbol_size]; K10_ALL_ZERO_K];

    let constructed = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source_symbols, symbol_size, input.seed)
    }))
    .unwrap_or_else(|_| {
        panic!("K=10 all-zero encoder construction panicked for symbol_size={symbol_size}")
    });
    let Some(mut encoder) = constructed else {
        panic!("K=10 all-zero encoder construction must succeed");
    };

    let params = encoder.params();
    assert_eq!(params.k, K10_ALL_ZERO_K, "K=10 lane must preserve K");
    assert_eq!(params.k_prime, 10, "K=10 must pin the first exact RFC row");
    assert_eq!(params.j, 254, "K=10 must pin the RFC J(K') value");
    assert_eq!(params.s, 7, "K=10 must pin the RFC S(K') value");
    assert_eq!(params.h, 10, "K=10 must pin the RFC H(K') value");
    assert_eq!(params.w, 17, "K=10 must pin the RFC W(K') value");
    assert_eq!(params.l, 27, "K=10 must pin the RFC L value");
    assert_eq!(
        params.symbol_size, symbol_size,
        "K=10 lane must preserve symbol_size"
    );

    let k_u32 = u32::try_from(K10_ALL_ZERO_K).expect("K=10 must fit in u32");
    let repair_start = k_u32.saturating_add(u32::from(input.repair_offset % 4));
    for offset in 0..EXTREME_REPAIR_PROBES {
        let esi = repair_start.saturating_add(u32::try_from(offset).expect("offset fits"));
        let repair = encoder.repair_symbol(esi);
        assert_eq!(
            repair.len(),
            symbol_size,
            "K=10 all-zero repair_symbol must preserve symbol_size"
        );
        assert!(
            repair.iter().all(|&byte| byte == 0),
            "K=10 all-zero repair_symbol must remain all-zero"
        );

        let mut buffered = vec![0x5A; symbol_size];
        encoder.repair_symbol_into(esi, &mut buffered);
        assert_eq!(
            buffered, repair,
            "K=10 all-zero repair_symbol_into must match repair_symbol"
        );
    }

    if input.emit_all_first {
        let emitted = encoder.emit_all(repair_count);
        assert_eq!(
            emitted.len(),
            K10_ALL_ZERO_K + repair_count,
            "K=10 all-zero emit_all must return K + repair_count symbols"
        );
        for (offset, symbol) in emitted.iter().enumerate() {
            let expected_esi = u32::try_from(offset).expect("bounded ESI must fit in u32");
            assert_all_zero_emitted_symbol(
                symbol,
                expected_esi,
                offset < K10_ALL_ZERO_K,
                symbol_size,
            );
        }
    } else {
        let systematic = encoder.emit_systematic();
        assert_eq!(
            systematic.len(),
            K10_ALL_ZERO_K,
            "K=10 all-zero systematic lane must emit all source symbols"
        );
        for (offset, symbol) in systematic.iter().enumerate() {
            assert_all_zero_emitted_symbol(
                symbol,
                u32::try_from(offset).expect("bounded ESI must fit in u32"),
                true,
                symbol_size,
            );
        }

        let repairs = encoder.emit_repair(repair_count);
        assert_eq!(
            repairs.len(),
            repair_count,
            "K=10 all-zero repair lane must emit requested repairs"
        );
        for (offset, symbol) in repairs.iter().enumerate() {
            assert_all_zero_emitted_symbol(
                symbol,
                k_u32.saturating_add(u32::try_from(offset).expect("offset fits")),
                false,
                symbol_size,
            );
        }
    }

    assert_eq!(
        encoder.next_repair_esi(),
        k_u32.saturating_add(u32::try_from(repair_count).expect("repair count must fit in u32")),
        "K=10 all-zero repair cursor must advance by emitted repair count"
    );
}

fn assert_malformed_source_block_boundary(input: &EncoderInput) {
    let symbol_size = (usize::from(input.malformed_symbol_size) % SMALL_MEDIUM_MAX_SYMBOL_SIZE) + 1;
    let (source_symbols, constructor_symbol_size, is_malformed) = build_malformed_source_block(
        input.malformed_kind,
        symbol_size,
        input.malformed_symbols.clone(),
    );
    let shape_is_well_formed = !source_symbols.is_empty()
        && source_symbols
            .iter()
            .all(|symbol| symbol.len() == constructor_symbol_size);

    let constructed = catch_unwind(AssertUnwindSafe(|| {
        SystematicEncoder::new(&source_symbols, constructor_symbol_size, input.seed)
    }));

    match constructed {
        Ok(Some(mut encoder)) => {
            assert!(
                shape_is_well_formed,
                "malformed source blocks must not construct an encoder"
            );
            let emitted = encoder.emit_systematic();
            assert_eq!(
                emitted.len(),
                source_symbols.len(),
                "well-formed control source block must emit every source symbol"
            );
        }
        Ok(None) => {}
        Err(_) => {
            assert!(
                is_malformed || !shape_is_well_formed,
                "well-formed source-block controls must not panic"
            );
        }
    }
}

fuzz_target!(|input: EncoderInput| {
    assert_symbol_size_extreme_lane(input.symbol_size_extreme);
    assert_k10_all_zero_lane(input.k10_all_zero);
    assert_malformed_source_block_boundary(&input);

    let k = match input.k_edge {
        KEdge::K1 => 1,
        KEdge::K42 => 42,
        KEdge::K2048 => 2048,
        KEdge::K8192 => 8192,
    };
    let symbol_size = match input.k_edge {
        KEdge::K2048 => (usize::from(input.symbol_size) % TRACTABLE_LARGE_K_MAX_SYMBOL_SIZE) + 1,
        KEdge::K8192 => (usize::from(input.symbol_size) % LARGE_K_MAX_SYMBOL_SIZE) + 1,
        KEdge::K1 | KEdge::K42 => {
            (usize::from(input.symbol_size) % SMALL_MEDIUM_MAX_SYMBOL_SIZE) + 1
        }
    };
    let repair_count = match input.k_edge {
        KEdge::K2048 => usize::from(input.repair_count) % (TRACTABLE_LARGE_K_MAX_REPAIR_COUNT + 1),
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
        assert_eq!(
            params.k_prime, 2070,
            "K=2048 must round up to the live RFC row"
        );
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
            symbol.data, source_symbols[esi],
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
