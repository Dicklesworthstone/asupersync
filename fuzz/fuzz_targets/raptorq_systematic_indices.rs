#![no_main]

use arbitrary::Arbitrary;
use asupersync::raptorq::gf256::Gf256;
use asupersync::raptorq::systematic::{SystematicError, SystematicParams};
use libfuzzer_sys::fuzz_target;
use std::collections::BTreeSet;

const MAX_FUZZ_K: usize = 16_384;
const MAX_SYMBOL_SIZE: usize = 4096;

#[derive(Debug, Clone, Arbitrary)]
struct SystematicIndexInput {
    raw_k: u16,
    symbol_size: u16,
    esi_seed: u32,
    window: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParamFingerprint {
    k: usize,
    k_prime: usize,
    j: usize,
    s: usize,
    h: usize,
    l: usize,
    w: usize,
    p: usize,
    b: usize,
    symbol_size: usize,
}

impl From<&SystematicParams> for ParamFingerprint {
    fn from(params: &SystematicParams) -> Self {
        Self {
            k: params.k,
            k_prime: params.k_prime,
            j: params.j,
            s: params.s,
            h: params.h,
            l: params.l,
            w: params.w,
            p: params.p,
            b: params.b,
            symbol_size: params.symbol_size,
        }
    }
}

fuzz_target!(|input: SystematicIndexInput| {
    let symbol_size = normalize_symbol_size(input.symbol_size);
    for k in systematic_index_candidates(input.raw_k, input.window) {
        assert_systematic_lookup(k, symbol_size, input.esi_seed);
    }
});

fn normalize_symbol_size(raw: u16) -> usize {
    usize::from(raw).clamp(1, MAX_SYMBOL_SIZE)
}

fn normalize_k(raw: u16) -> usize {
    usize::from(raw) % MAX_FUZZ_K + 1
}

fn systematic_index_candidates(raw_k: u16, window: u8) -> Vec<usize> {
    let k = normalize_k(raw_k);
    let window = usize::from(window).min(64);
    let mut candidates = BTreeSet::from([
        1,
        2,
        9,
        10,
        11,
        12,
        18,
        19,
        20,
        21,
        42,
        43,
        44,
        255,
        256,
        257,
        1023,
        1024,
        1025,
        4095,
        4096,
        4097,
        8191,
        8192,
        8193,
        16_383,
        16_384,
        k,
        k.saturating_sub(1).max(1),
        k.saturating_add(1).min(MAX_FUZZ_K),
        k.saturating_sub(window).max(1),
        k.saturating_add(window).min(MAX_FUZZ_K),
    ]);
    candidates.retain(|candidate| (1..=MAX_FUZZ_K).contains(candidate));
    candidates.into_iter().collect()
}

fn assert_systematic_lookup(k: usize, symbol_size: usize, esi_seed: u32) {
    let params = SystematicParams::try_for_source_block(k, symbol_size)
        .expect("K in 1..=16384 must be covered by the RFC 6330 table");
    let repeat = SystematicParams::try_for_source_block(k, symbol_size)
        .expect("repeated lookup for the same K must stay covered");

    assert_eq!(
        ParamFingerprint::from(&params),
        ParamFingerprint::from(&repeat),
        "systematic parameter lookup must be deterministic for fixed K"
    );

    assert_eq!(params.k, k, "lookup must preserve caller K");
    assert_eq!(
        params.symbol_size, symbol_size,
        "lookup must preserve caller symbol size"
    );
    assert!(
        params.k_prime >= params.k,
        "K' must not be below K: K={} K'={}",
        params.k,
        params.k_prime
    );
    assert_eq!(
        params.l,
        params.k_prime + params.s + params.h,
        "L must equal K' + S + H"
    );
    assert!(
        params.w >= params.s,
        "W must not be below S: W={} S={}",
        params.w,
        params.s
    );
    assert!(
        params.l >= params.w,
        "L must not be below W: L={} W={}",
        params.l,
        params.w
    );
    assert_eq!(params.b, params.w - params.s, "B must equal W - S");
    assert_eq!(params.p, params.l - params.w, "P must equal L - W");
    assert!(
        u32::try_from(params.j).is_ok(),
        "systematic index J must fit RFC tuple arithmetic"
    );

    for esi in repair_esi_candidates(&params, esi_seed) {
        assert_repair_equation_is_bounded(&params, esi);
    }
}

fn repair_esi_candidates(params: &SystematicParams, esi_seed: u32) -> Vec<u32> {
    let mut candidates = BTreeSet::from([
        0,
        1,
        esi_seed,
        params.k.saturating_sub(1) as u32,
        params.k as u32,
        params.k_prime.saturating_sub(1) as u32,
        params.k_prime as u32,
        params.l.saturating_sub(1) as u32,
        params.l as u32,
        u32::MAX,
    ]);
    candidates.insert(esi_seed.wrapping_add(params.j as u32));
    candidates.insert(esi_seed.wrapping_add(params.w as u32));
    candidates.into_iter().collect()
}

fn assert_repair_equation_is_bounded(params: &SystematicParams, esi: u32) {
    let first = params.rfc_repair_equation(esi);
    let second = params.rfc_repair_equation(esi);
    assert_eq!(
        first, second,
        "repair equation expansion must be deterministic for fixed K and ESI"
    );

    match first {
        Ok((indices, coefficients)) => {
            assert_eq!(
                indices.len(),
                coefficients.len(),
                "repair equation columns and coefficients must stay paired"
            );
            assert!(
                coefficients
                    .iter()
                    .all(|coefficient| *coefficient == Gf256::ONE),
                "repair equation coefficients must stay deterministic unit weights"
            );
            for index in indices {
                assert!(
                    index < params.l,
                    "repair equation produced out-of-bounds index {index} for L={}",
                    params.l
                );
            }
        }
        Err(SystematicError::EsiOverflow {
            esi: overflow_esi,
            padding_delta,
        }) => {
            assert_eq!(
                overflow_esi, esi,
                "overflow error must report the queried ESI"
            );
            assert!(
                padding_delta > 0,
                "overflow requires a non-zero systematic padding delta"
            );
        }
    }
}
