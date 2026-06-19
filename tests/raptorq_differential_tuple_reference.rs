//! RFC 6330 differential harness: production tuple/equation construction
//! vs a fully independent in-test reference oracle.
//!
//! bd-3uox5 AC3 (differential checks) — advances Track-D D2 (bd-136cm,
//! "Differential Harness Against Independent Reference Implementation";
//! that bead is currently tracker-blocked behind Track-B/C, so this
//! slice lands under the unblocked parent epic).
//!
//! The production encode path derives a symbol's intermediate-symbol
//! equation from `tuple()` (§5.3.5.4 tuple generator) followed by
//! `tuple_indices()` (§5.3.5.3 index walk). This test re-implements BOTH
//! algorithms independently, directly from the RFC 6330 pseudocode,
//! sharing nothing with production except the byte-exact-pinned V0..V3
//! constants and the (separately tested) systematic parameter table.
//! It then diffs the two implementations across a broad (K, ISI) sweep
//! and, on any mismatch, labels the root-cause class (degree / LT-step /
//! LT-start / PI-degree / PI-step / PI-start / index-walk) per D2 AC2.
//!
//! Independent reference scope:
//!   - `ref_rand`   — §5.3.5.1 Rand[y,i,m] formula (re-derived)
//!   - `ref_deg`    — §5.3.5.2 Deg[v] with the W-2 cap (re-derived)
//!   - `ref_tuple`  — §5.3.5.4 (d,a,b,d1,a1,b1) generator (re-derived)
//!   - `ref_walk`   — §5.3.5.3 intermediate-symbol index walk (re-derived)
//!
//! Repro: `cargo test --test raptorq_differential_tuple_reference`

use std::fmt::Write as _;
use std::fs;

use asupersync::raptorq::rfc6330::{LtTuple, V0, V1, V2, V3, next_prime_ge, tuple, tuple_indices};
use asupersync::raptorq::systematic::SystematicParams;

// ---- independent reference implementation (RFC 6330 pseudocode) ----

/// §5.3.5.1 Rand[y, i, m].
fn ref_rand(y: u32, i: u8, m: u32) -> u32 {
    let idx = |shift: u32| ((y >> shift).wrapping_add(u32::from(i)) & 0xFF) as usize;
    (V0[idx(0)] ^ V1[idx(8)] ^ V2[idx(16)] ^ V3[idx(24)]) % m
}

/// §5.3.5.2 Deg[v] cumulative thresholds f[0..=30].
const F: [u32; 31] = [
    0, 5243, 529531, 704294, 791675, 844104, 879057, 904023, 922747, 937311, 948962, 958494,
    966438, 973160, 978921, 983914, 988283, 992138, 995565, 998631, 1001391, 1003887, 1006157,
    1008229, 1010129, 1011876, 1013490, 1014983, 1016370, 1017662, 1048576,
];

/// §5.3.5.2 Deg[v] with the RFC W-2 cap applied at tuple generation.
fn ref_deg(v: u32, w: usize) -> usize {
    let mut degree = 30usize;
    for (threshold_degree, threshold) in F.iter().enumerate().skip(1) {
        if v < *threshold {
            degree = threshold_degree;
            break;
        }
    }
    degree.min(w - 2)
}

/// §5.3.5.4 Tuple[K', X] generator. `j` is the systematic index J(K').
fn ref_tuple(systematic_index: usize, width: usize, prime_p1: usize, isi: u32) -> LtTuple {
    let systematic_index = systematic_index as u32;
    let mut lt_seed_multiplier = 53_591u32.wrapping_add(997u32.wrapping_mul(systematic_index));
    if lt_seed_multiplier % 2 == 0 {
        lt_seed_multiplier = lt_seed_multiplier.wrapping_add(1);
    }
    let lt_seed_offset = 10_267u32.wrapping_mul(systematic_index.wrapping_add(1));
    let tuple_seed = lt_seed_offset.wrapping_add(isi.wrapping_mul(lt_seed_multiplier));

    let degree_sample = ref_rand(tuple_seed, 0, 1 << 20);
    let degree = ref_deg(degree_sample, width);
    let lt_step = 1 + ref_rand(tuple_seed, 1, (width as u32) - 1) as usize;
    let lt_start = ref_rand(tuple_seed, 2, width as u32) as usize;
    let pi_degree = if degree < 4 {
        2 + ref_rand(isi, 3, 2) as usize
    } else {
        2
    };
    let pi_step = 1 + ref_rand(isi, 4, (prime_p1 as u32) - 1) as usize;
    let pi_start = ref_rand(isi, 5, prime_p1 as u32) as usize;

    LtTuple {
        d: degree,
        a: lt_step,
        b: lt_start,
        d1: pi_degree,
        a1: pi_step,
        b1: pi_start,
    }
}

/// §5.3.5.3 intermediate-symbol index walk.
fn ref_walk(t: LtTuple, w: usize, p: usize, p1: usize) -> Vec<usize> {
    let mut out = Vec::with_capacity(t.d + t.d1);
    let mut x = t.b % w;
    out.push(x);
    for _ in 1..t.d {
        x = (x + t.a) % w;
        out.push(x);
    }
    let mut x1 = t.b1 % p1;
    while x1 >= p {
        x1 = (x1 + t.a1) % p1;
    }
    out.push(w + x1);
    for _ in 1..t.d1 {
        x1 = (x1 + t.a1) % p1;
        while x1 >= p {
            x1 = (x1 + t.a1) % p1;
        }
        out.push(w + x1);
    }
    out
}

/// Classify the first divergent field for triage (D2 AC2).
fn tuple_mismatch_class(a: LtTuple, b: LtTuple) -> &'static str {
    if a.d != b.d {
        "LT-degree(d)"
    } else if a.a != b.a {
        "LT-step(a)"
    } else if a.b != b.b {
        "LT-start(b)"
    } else if a.d1 != b.d1 {
        "PI-degree(d1)"
    } else if a.a1 != b.a1 {
        "PI-step(a1)"
    } else if a.b1 != b.b1 {
        "PI-start(b1)"
    } else {
        "none"
    }
}

const K_SWEEP: &[usize] = &[
    1, 2, 4, 8, 10, 11, 26, 42, 50, 100, 101, 200, 500, 1000, 2048, 10000,
];

#[test]
fn differential_tuple_and_equation_vs_independent_reference() {
    let mut log = String::new();
    let mut compared: u64 = 0;
    let mut tuple_mismatches: u64 = 0;
    let mut walk_mismatches: u64 = 0;

    for &k in K_SWEEP {
        let params = SystematicParams::for_source_block(k, 64);
        let (j, w, p, kp) = (params.j, params.w, params.p, params.k_prime);
        let p1 = next_prime_ge(p)
            .unwrap_or_else(|| panic!("K={k}: next_prime_ge(P={p}) must fit in usize"));

        let esi_max = (kp as u32).saturating_add(128);
        for esi in 0..esi_max {
            let prod_t = tuple(j, w, p, p1, esi);
            let ref_t = ref_tuple(j, w, p1, esi);
            compared += 1;

            if prod_t != ref_t {
                tuple_mismatches += 1;
                let _ = writeln!(
                    log,
                    "{{\"scenario_id\":\"RQ-D2-DIFF-TUPLE\",\"k\":{k},\"k_prime\":{kp},\
                     \"isi\":{esi},\"w\":{w},\"p\":{p},\"p1\":{p1},\"outcome\":\"mismatch\",\
                     \"class\":\"{}\",\"production\":\"{prod_t:?}\",\"reference\":\"{ref_t:?}\"}}",
                    tuple_mismatch_class(prod_t, ref_t)
                );
            }
            assert_eq!(
                prod_t,
                ref_t,
                "K={k} K'={kp} ISI={esi} W={w} P={p} P1={p1}: tuple diverges from \
                 independent RFC §5.3.5.4 reference [class={}]; \
                 repro='cargo test --test raptorq_differential_tuple_reference'",
                tuple_mismatch_class(prod_t, ref_t)
            );

            // Equation construction (index walk) — diff both expanded
            // from the SAME (now-agreed) tuple so a divergence isolates
            // the §5.3.5.3 walk, not the generator.
            let prod_idx = tuple_indices(prod_t, w, p, p1);
            let ref_idx = ref_walk(ref_t, w, p, p1);
            if prod_idx != ref_idx {
                walk_mismatches += 1;
                let _ = writeln!(
                    log,
                    "{{\"scenario_id\":\"RQ-D2-DIFF-WALK\",\"k\":{k},\"isi\":{esi},\
                     \"outcome\":\"mismatch\",\"class\":\"index-walk\",\
                     \"production\":\"{prod_idx:?}\",\"reference\":\"{ref_idx:?}\"}}"
                );
            }
            assert_eq!(
                prod_idx, ref_idx,
                "K={k} ISI={esi}: index walk diverges from independent RFC §5.3.5.3 \
                 reference [class=index-walk]; \
                 repro='cargo test --test raptorq_differential_tuple_reference'"
            );
        }
    }

    assert!(
        compared > 10_000,
        "differential sweep too small: {compared} points"
    );
    assert_eq!(tuple_mismatches, 0, "tuple mismatches found");
    assert_eq!(walk_mismatches, 0, "index-walk mismatches found");

    // Structured-log artifact (D2 AC5/AC6). Written to a temp path so it
    // never pollutes the working tree; the path is echoed for triage.
    let summary = format!(
        "{{\"schema_version\":\"raptorq-differential-v1\",\
         \"scenario_id\":\"RQ-D2-DIFF\",\"seed\":\"deterministic\",\
         \"k_sweep\":{K_SWEEP:?},\"points_compared\":{compared},\
         \"tuple_mismatches\":{tuple_mismatches},\"walk_mismatches\":{walk_mismatches},\
         \"outcome\":\"pass\",\
         \"repro\":\"cargo test --test raptorq_differential_tuple_reference\"}}\n{log}"
    );
    let mut path = std::env::temp_dir();
    path.push("raptorq_differential_tuple_reference.jsonl");
    if fs::write(&path, &summary).is_ok() {
        println!("artifact_path={}", path.display());
    }
    println!(
        "RQ-D2-DIFF: compared={compared} tuple_mismatches={tuple_mismatches} \
         walk_mismatches={walk_mismatches}"
    );
}
