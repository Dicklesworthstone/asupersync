//! RFC 6330 §5.3.5 — decoder `repair_equation_rfc6330` conformance proof.
//!
//! bd-3uox5 (RAPTORQ-RFC6330) AC2 (RFC-aligned parameter derivation /
//! equation generation) + AC3 (differential + metamorphic / property checks).
//!
//! `InactivationDecoder::repair_equation_rfc6330(esi)` is the documented RFC
//! conformance alias that the decoder exposes for repair-row construction
//! (decoder.rs). It delegates to `repair_equation(esi).ok()`, which in turn is
//! `params.rfc_repair_equation(esi)`. The alias had ZERO integration-test
//! coverage — the only checks living in `#[cfg(test)] mod tests` inside the
//! 297 KB `decoder.rs`, which never runs green as the lib-unittest binary. This
//! crate re-proves and extends those guarantees through the PUBLIC surface so
//! they actually execute.
//!
//! The harness is oracle-free: it pins RFC structural laws and a differential
//! identity against the shared `SystematicParams::rfc_repair_equation` source of
//! truth, never hard-coding concrete tuple indices (which vary by K').
//!
//! Guarantees pinned:
//!   1. Determinism — same instance, repeated calls are byte-identical.
//!   2. Seed-independence — the repair equation is a pure function of
//!      (K, symbol_size, ESI); the decoder seed is never consulted. Two
//!      decoders built with different seeds emit identical equations.
//!   3. Differential parity — decoder output == the shared
//!      `SystematicParams::rfc_repair_equation(esi).ok()` (the one source of
//!      truth that keeps encoder/decoder rows in lockstep).
//!   4. Alias faithfulness — `repair_equation_rfc6330(esi)` is exactly the
//!      `Ok` projection of `repair_equation(esi)` (`is_some <=> is_ok`, equal
//!      payload).
//!   5. RFC structure — every coefficient is `Gf256::ONE`, lengths agree, rows
//!      are non-empty, all columns are `< L`, and the PI domain (`>= W`) is
//!      exercised within a repair sweep.
//!   6. Error paths — source-domain ESIs (`< K`) yield `None`, and a padded
//!      block rejects the ESI-overflow extreme (`u32::MAX`) as `None`.
//!
//! Repro: `cargo test --test raptorq_repair_equation_rfc6330_conformance`

use asupersync::raptorq::decoder::InactivationDecoder;
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::SystematicParams;

/// Representative (K, symbol_size) source blocks spanning small/medium K' rows.
const BLOCKS: &[(usize, usize)] = &[(8, 32), (10, 32), (12, 64), (16, 64), (32, 128)];

/// A wide repair-ESI sweep starting just past the first valid repair index.
fn repair_sweep(k: usize) -> impl Iterator<Item = u32> {
    let start = u32::try_from(k).expect("K fits in u32");
    start..start + 96
}

#[test]
fn determinism_same_instance() {
    for &(k, symbol_size) in BLOCKS {
        let decoder = InactivationDecoder::new(k, symbol_size, 42);
        for esi in repair_sweep(k) {
            let first = decoder.repair_equation_rfc6330(esi);
            let second = decoder.repair_equation_rfc6330(esi);
            assert_eq!(
                first, second,
                "RQ-DEC-REPEQ-DET-001 K={k} sz={symbol_size} esi={esi} replay mismatch"
            );
        }
    }
}

#[test]
fn seed_independence() {
    // The repair equation derives purely from (K', W, P) and the ESI; the
    // decoder's RNG seed governs pivot selection, NOT row construction. Build
    // decoders over a spread of seeds and require byte-identical equations.
    for &(k, symbol_size) in BLOCKS {
        let baseline = InactivationDecoder::new(k, symbol_size, 0);
        for seed in [1u64, 7, 99, 1234, u64::MAX] {
            let other = InactivationDecoder::new(k, symbol_size, seed);
            for esi in repair_sweep(k) {
                assert_eq!(
                    baseline.repair_equation_rfc6330(esi),
                    other.repair_equation_rfc6330(esi),
                    "RQ-DEC-REPEQ-SEED-001 K={k} sz={symbol_size} esi={esi} seed={seed} \
                     equation varied with seed"
                );
            }
        }
    }
}

#[test]
fn differential_parity_with_shared_params() {
    // The decoder alias must agree with the single shared source of truth that
    // also drives the encoder, or encoder/decoder repair rows could diverge.
    for &(k, symbol_size) in BLOCKS {
        let decoder = InactivationDecoder::new(k, symbol_size, 7);
        let params = SystematicParams::for_source_block(k, symbol_size);
        for esi in repair_sweep(k) {
            let decoder_eq = decoder.repair_equation_rfc6330(esi);
            let shared_eq = params.rfc_repair_equation(esi).ok();
            assert_eq!(
                decoder_eq, shared_eq,
                "RQ-DEC-REPEQ-PARITY-001 K={k} sz={symbol_size} esi={esi} \
                 decoder/shared-params equation mismatch"
            );
        }
    }
}

#[test]
fn alias_is_ok_projection_of_repair_equation() {
    // `repair_equation_rfc6330` must be EXACTLY `repair_equation(..).ok()`:
    // Some iff Ok, with an identical payload, and None iff Err.
    for &(k, symbol_size) in BLOCKS {
        let decoder = InactivationDecoder::new(k, symbol_size, 13);
        // Include source-domain ESIs (< K) so the Err branch is exercised too.
        for esi in 0..u32::try_from(k).expect("K fits in u32") + 96 {
            let alias = decoder.repair_equation_rfc6330(esi);
            let result = decoder.repair_equation(esi);
            assert_eq!(
                alias.is_some(),
                result.is_ok(),
                "RQ-DEC-REPEQ-ALIAS-001 K={k} sz={symbol_size} esi={esi} \
                 some/ok disagreement"
            );
            if let Ok(payload) = result {
                assert_eq!(
                    alias.as_ref(),
                    Some(&payload),
                    "RQ-DEC-REPEQ-ALIAS-002 K={k} sz={symbol_size} esi={esi} \
                     alias payload differs from Ok payload"
                );
            }
        }
    }
}

#[test]
fn rfc_row_structure_coefficients_lengths_and_bounds() {
    for &(k, symbol_size) in BLOCKS {
        let decoder = InactivationDecoder::new(k, symbol_size, 99);
        let params = decoder.params();
        let l = params.l;
        let mut saw_pi_domain = false;
        for esi in repair_sweep(k) {
            let (cols, coefs) = decoder
                .repair_equation_rfc6330(esi)
                .unwrap_or_else(|| panic!("RQ-DEC-REPEQ-STRUCT-000 missing eq K={k} esi={esi}"));
            assert!(
                !cols.is_empty(),
                "RQ-DEC-REPEQ-STRUCT-001 K={k} sz={symbol_size} esi={esi} empty repair row"
            );
            assert_eq!(
                cols.len(),
                coefs.len(),
                "RQ-DEC-REPEQ-STRUCT-002 K={k} sz={symbol_size} esi={esi} col/coef length mismatch"
            );
            assert!(
                cols.iter().all(|&c| c < l),
                "RQ-DEC-REPEQ-STRUCT-003 K={k} sz={symbol_size} esi={esi} column >= L={l}"
            );
            assert!(
                coefs.iter().all(|&c| c == Gf256::ONE),
                "RQ-DEC-REPEQ-STRUCT-004 K={k} sz={symbol_size} esi={esi} \
                 non-unit coefficient (RFC systematic rows are XOR rows)"
            );
            if cols.iter().any(|&c| c >= params.w) {
                saw_pi_domain = true;
            }
        }
        assert!(
            saw_pi_domain,
            "RQ-DEC-REPEQ-STRUCT-005 K={k} sz={symbol_size} repair sweep never touched PI domain (>= W={})",
            params.w
        );
    }
}

#[test]
fn source_domain_esis_yield_none() {
    // ESIs below K name source symbols, not repair symbols: the RFC repair
    // alias must fail closed (None) rather than fabricate a row.
    for &(k, symbol_size) in BLOCKS {
        let decoder = InactivationDecoder::new(k, symbol_size, 5);
        for esi in 0..u32::try_from(k).expect("K fits in u32") {
            assert_eq!(
                decoder.repair_equation_rfc6330(esi),
                None,
                "RQ-DEC-REPEQ-SRC-001 K={k} sz={symbol_size} esi={esi} \
                 source-domain ESI should not produce a repair equation"
            );
        }
    }
}

#[test]
fn esi_overflow_extreme_fails_closed_when_padded() {
    // When K' > K the repair ISI translation is `ESI + (K' - K)`, so the
    // u32::MAX extreme overflows and must fail closed (None). For blocks where
    // K == K' (no padding) the extreme is a valid ISI, so only assert the
    // overflow rejection on a genuinely padded block.
    let mut exercised_padded = false;
    for &(k, symbol_size) in BLOCKS {
        let decoder = InactivationDecoder::new(k, symbol_size, 1);
        let params = decoder.params();
        if params.k_prime > params.k {
            exercised_padded = true;
            assert_eq!(
                decoder.repair_equation_rfc6330(u32::MAX),
                None,
                "RQ-DEC-REPEQ-OVF-001 K={k} K'={} sz={symbol_size} \
                 padded block must reject the ESI-overflow extreme",
                params.k_prime
            );
        }
    }
    assert!(
        exercised_padded,
        "RQ-DEC-REPEQ-OVF-002 test fixture must include at least one padded (K' > K) block"
    );
}
