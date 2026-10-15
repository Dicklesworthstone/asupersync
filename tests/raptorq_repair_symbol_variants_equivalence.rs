//! RFC 6330 systematic encoder — repair-symbol API variant equivalence + fail-closed.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC2/AC3. The encoder exposes four ways to
//! synthesize one repair symbol for an ESI:
//!   - `repair_symbol(esi) -> Vec<u8>`            (allocating, panics on bad ESI)
//!   - `try_repair_symbol(esi) -> Result<Vec<u8>>`(allocating, fallible)
//!   - `repair_symbol_into(esi, &mut buf)`        (in-place, panics on bad ESI)
//!   - `try_repair_symbol_into(esi, &mut buf)`    (in-place, fallible)
//!
//! Three of those four (`try_repair_symbol`, `try_repair_symbol_into`,
//! `repair_symbol_into`) had ZERO test coverage, so nothing pinned that the
//! allocating / in-place / fallible / panicking variants all agree byte-for-byte
//! or share one fail-closed contract.
//!
//! Pinned here via the public API only:
//!   1. VARIANT EQUIVALENCE — for valid ESIs (>= K), all four variants produce
//!      identical bytes, and the result is deterministic across calls.
//!   2. emit_repair PARITY — `repair_symbol(K+i)` equals the data the streaming
//!      `emit_repair(n)` path emits for the i-th repair symbol.
//!   3. FALLIBLE FAIL-CLOSED — for source ESIs (0..K) the fallible variants
//!      return `SystematicError::RepairEsiBelowK { esi, k: K }`.
//!   4. PANIC CONTRACT — the panicking variants (`repair_symbol`,
//!      `repair_symbol_into`) panic on a source ESI, and `try_repair_symbol_into`
//!      panics when the caller buffer is shorter than the symbol size.
//!   5. OVERSIZED BUFFER — a buffer larger than the symbol writes only
//!      `buf[..symbol_size]` and leaves the tail untouched.
//!
//! Repro: `cargo test --test raptorq_repair_symbol_variants_equivalence`

use std::panic::{self, AssertUnwindSafe};

use asupersync::raptorq::systematic::{SystematicEncoder, SystematicError};

const SYMBOL_SIZE: usize = 8;

fn make_source(k: usize) -> Vec<Vec<u8>> {
    (0..k)
        .map(|i| {
            (0..SYMBOL_SIZE)
                .map(|b| ((i * 17 + b * 5 + 11) & 0xFF) as u8)
                .collect()
        })
        .collect()
}

fn new_encoder(k: usize) -> SystematicEncoder {
    SystematicEncoder::new(&make_source(k), SYMBOL_SIZE, 0xABCD_1234_u64)
        .unwrap_or_else(|| panic!("encoder construction failed for K={k}"))
}

/// Run `f`, expecting it to panic; keeps the test output clean by muting the
/// panic hook for the duration. Returns whether a panic was caught.
fn caught_panic<F: FnOnce()>(f: F) -> bool {
    let prev = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));
    let result = panic::catch_unwind(AssertUnwindSafe(f));
    panic::set_hook(prev);
    result.is_err()
}

#[test]
fn all_variants_agree_byte_for_byte() {
    for &k in &[1usize, 4, 10, 42] {
        let enc = new_encoder(k);
        let k_u32 = k as u32;
        for off in 0..6u32 {
            let esi = k_u32 + off;

            let alloc = enc.repair_symbol(esi);
            assert_eq!(
                alloc.len(),
                SYMBOL_SIZE,
                "repair symbol must be symbol_size"
            );

            let try_alloc = enc
                .try_repair_symbol(esi)
                .unwrap_or_else(|e| panic!("try_repair_symbol({esi}) errored: {e:?}"));
            assert_eq!(
                try_alloc, alloc,
                "try_repair_symbol != repair_symbol (K={k} esi={esi})"
            );

            let mut into_buf = vec![0u8; SYMBOL_SIZE];
            enc.repair_symbol_into(esi, &mut into_buf);
            assert_eq!(
                into_buf, alloc,
                "repair_symbol_into != repair_symbol (K={k} esi={esi})"
            );

            let mut try_into_buf = vec![0u8; SYMBOL_SIZE];
            enc.try_repair_symbol_into(esi, &mut try_into_buf)
                .unwrap_or_else(|e| panic!("try_repair_symbol_into({esi}) errored: {e:?}"));
            assert_eq!(
                try_into_buf, alloc,
                "try_repair_symbol_into != repair_symbol (K={k} esi={esi})"
            );

            // Determinism: a second allocating call is byte-identical.
            assert_eq!(
                enc.repair_symbol(esi),
                alloc,
                "non-deterministic repair symbol"
            );
        }
    }
}

#[test]
fn repair_symbol_matches_emit_repair_stream() {
    for &k in &[1usize, 4, 10, 42] {
        let mut enc = new_encoder(k);
        let k_u32 = k as u32;
        let n = 5usize;

        // repair_symbol is &self and does not advance the streaming cursor, so
        // we can snapshot the expected data before driving emit_repair.
        let expected: Vec<Vec<u8>> = (0..n)
            .map(|i| enc.repair_symbol(k_u32 + i as u32))
            .collect();

        let emitted = enc.emit_repair(n);
        assert_eq!(emitted.len(), n, "emit_repair must emit n symbols (K={k})");
        for (i, sym) in emitted.iter().enumerate() {
            assert_eq!(sym.esi, k_u32 + i as u32, "stream ESI must be K+i (K={k})");
            assert_eq!(
                sym.data, expected[i],
                "emit_repair data must match repair_symbol(K+{i}) (K={k})"
            );
        }
    }
}

#[test]
fn fallible_variants_reject_source_esi() {
    for &k in &[1usize, 4, 10, 42] {
        let enc = new_encoder(k);
        let k_u32 = k as u32;
        for esi in 0..k_u32 {
            assert_eq!(
                enc.try_repair_symbol(esi),
                Err(SystematicError::RepairEsiBelowK { esi, k: k_u32 }),
                "try_repair_symbol must reject source ESI {esi} (K={k})"
            );

            let mut buf = vec![0u8; SYMBOL_SIZE];
            assert_eq!(
                enc.try_repair_symbol_into(esi, &mut buf),
                Err(SystematicError::RepairEsiBelowK { esi, k: k_u32 }),
                "try_repair_symbol_into must reject source ESI {esi} (K={k})"
            );
        }
    }
}

#[test]
fn panicking_variants_uphold_panic_contract() {
    let enc = new_encoder(10);
    // Source ESI (< K) panics for both panicking variants.
    assert!(
        caught_panic(|| {
            let _ = enc.repair_symbol(0);
        }),
        "repair_symbol(esi<K) must panic"
    );
    assert!(
        caught_panic(|| {
            let mut buf = vec![0u8; SYMBOL_SIZE];
            enc.repair_symbol_into(3, &mut buf);
        }),
        "repair_symbol_into(esi<K) must panic"
    );
    // Buffer shorter than symbol_size panics (assert! in try_repair_symbol_into).
    assert!(
        caught_panic(|| {
            let mut tiny = vec![0u8; SYMBOL_SIZE - 1];
            let _ = enc.try_repair_symbol_into(10, &mut tiny);
        }),
        "try_repair_symbol_into must panic on undersized buffer"
    );
    // Sanity: a valid call into a correctly sized buffer does NOT panic.
    assert!(
        !caught_panic(|| {
            let mut buf = vec![0u8; SYMBOL_SIZE];
            enc.repair_symbol_into(10, &mut buf);
        }),
        "valid repair_symbol_into must not panic"
    );
}

#[test]
fn oversized_buffer_writes_only_symbol_prefix() {
    let enc = new_encoder(10);
    let esi = 10u32;
    let canonical = enc.repair_symbol(esi);

    // Buffer twice the symbol size, tail pre-filled with a sentinel.
    const SENTINEL: u8 = 0x5A;
    let mut buf = vec![SENTINEL; SYMBOL_SIZE * 2];
    enc.try_repair_symbol_into(esi, &mut buf)
        .expect("valid esi");

    assert_eq!(
        &buf[..SYMBOL_SIZE],
        &canonical[..],
        "prefix must be the canonical symbol"
    );
    assert!(
        buf[SYMBOL_SIZE..].iter().all(|&b| b == SENTINEL),
        "bytes past symbol_size must be left untouched"
    );
}
