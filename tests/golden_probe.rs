//! Temporary probe to capture golden vector values for conformance suite.
//! Run: cargo test --test golden_probe -- --nocapture

use asupersync::raptorq::decoder::InactivationDecoder;
use asupersync::raptorq::rfc6330::{deg, next_prime_ge, rand, tuple, tuple_indices};
use asupersync::raptorq::systematic::{ConstraintMatrix, SystematicEncoder, SystematicParams};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[test]
fn probe_systematic_params() {
    for k in [1, 2, 4, 8, 10, 16, 20, 32, 50, 64, 100, 128, 256, 500, 1000] {
        let params = SystematicParams::for_source_block(k, 64);
        eprintln!(
            "K={k}: K'={}, J={}, S={}, H={}, W={}, L={}, B={}, P={}",
            params.k_prime,
            params.j,
            params.s,
            params.h,
            params.w,
            params.l,
            params.b,
            params.l - params.w
        );
    }
}

#[test]
fn probe_rand_values() {
    let test_cases: Vec<(u32, u8, u32)> = vec![
        (0, 0, 256),
        (0, 0, 1000),
        (1, 0, 256),
        (1, 0, 1000),
        (42, 0, 1_048_576),
        (42, 1, 100),
        (42, 2, 100),
        (0xDEAD_BEEF, 0, 256),
        (0xDEAD_BEEF, 0, 1000),
        (0xCAFE_BABE, 3, 500),
        (12345, 0, 1_048_576),
        (12345, 1, 65536),
    ];

    for (y, i, m) in test_cases {
        eprintln!("Rand({y}, {i}, {m}) = {}", rand(y, i, m));
    }
}

#[test]
fn probe_degree_values() {
    let v_values = [
        0, 1, 5242, 5243, 100_000, 529_530, 529_531, 704_293, 704_294, 1_000_000, 1_017_661,
        1_017_662, 1_048_575,
    ];

    for v in v_values {
        eprintln!("deg({v}) = {}", deg(v));
    }
}

#[test]
fn probe_tuple_golden() {
    // Additional tuples beyond the 3 existing in rfc6330.rs
    let cases: Vec<(usize, usize, usize, u32)> = vec![
        // (J, W, P, ESI)
        (254, 17, 10, 0),    // K=10 params, ESI=0
        (254, 17, 10, 1),    // K=10 params, ESI=1
        (254, 17, 10, 10),   // K=10 params, first repair
        (254, 17, 10, 100),  // K=10 params, ESI=100
        (293, 31, 10, 0),    // K=20 params, ESI=0
        (293, 31, 10, 50),   // K=20 params, ESI=50
        (562, 113, 15, 0),   // K=100 params, ESI=0
        (562, 113, 15, 200), // K=100 params, ESI=200
    ];

    for (j, w, p, x) in cases {
        let p1 = next_prime_ge(p);
        let t = tuple(j, w, p, p1, x);
        let indices = tuple_indices(t, w, p, p1);
        eprintln!(
            "tuple(J={j}, W={w}, P={p}, X={x}): d={}, a={}, b={}, d1={}, a1={}, b1={} | indices={:?}",
            t.d, t.a, t.b, t.d1, t.a1, t.b1, indices
        );
    }
}

#[test]
fn probe_constraint_matrix_structure() {
    // For K=10, seed=42, sample first few LDPC/HDPC row structures
    let k = 10;
    let seed = 42u64;
    let params = SystematicParams::for_source_block(k, 64);
    let constraints = ConstraintMatrix::build(&params, seed);

    eprintln!(
        "K={k}: rows={}, cols={}, S={}, H={}",
        constraints.rows, constraints.cols, params.s, params.h
    );

    // Sample LDPC rows (0..S)
    for row in 0..params.s.min(3) {
        let mut nonzero = Vec::new();
        for col in 0..constraints.cols {
            let coeff = constraints.get(row, col);
            if !coeff.is_zero() {
                nonzero.push((col, coeff.raw()));
            }
        }
        eprintln!("LDPC row {row}: nonzero={nonzero:?}");
    }

    // Sample HDPC rows (S..S+H)
    for row in params.s..params.s + params.h.min(3) {
        let mut nonzero = Vec::new();
        for col in 0..constraints.cols {
            let coeff = constraints.get(row, col);
            if !coeff.is_zero() {
                nonzero.push((col, coeff.raw()));
            }
        }
        eprintln!("HDPC row {}: nonzero_count={}", row, nonzero.len());
    }
}

#[test]
fn probe_e2e_fingerprint() {
    // Fixed test vectors for E2E encode/decode
    let cases: Vec<(usize, usize, u64)> =
        vec![(8, 64, 42), (10, 32, 123), (16, 64, 789), (32, 128, 456)];

    for (k, symbol_size, seed) in cases {
        let source: Vec<Vec<u8>> = (0..k)
            .map(|i| {
                (0..symbol_size)
                    .map(|j| ((i * 37 + j * 13 + 7) % 256) as u8)
                    .collect()
            })
            .collect();

        let encoder = SystematicEncoder::new(&source, symbol_size, seed).unwrap();
        let params = encoder.params();

        // Hash intermediate symbols
        let mut intermediate_hasher = DefaultHasher::new();
        for i in 0..params.l {
            let sym = encoder.intermediate_symbol(i);
            sym.hash(&mut intermediate_hasher);
        }
        let intermediate_hash = intermediate_hasher.finish();

        // Hash first 5 repair symbols
        let mut repair_hasher = DefaultHasher::new();
        for esi in (k as u32)..((k + 5) as u32) {
            encoder.repair_symbol(esi).hash(&mut repair_hasher);
        }
        let repair_hash = repair_hasher.finish();

        // Decode and verify
        let decoder = InactivationDecoder::new(k, symbol_size, seed);
        let l = decoder.params().l;

        let base_rows = params.s + params.h;
        let constraints = ConstraintMatrix::build(params, seed);
        let mut received = decoder.constraint_symbols();
        for (i, data) in source.iter().enumerate() {
            let row = base_rows + i;
            let mut columns = Vec::new();
            let mut coefficients = Vec::new();
            for col in 0..constraints.cols {
                let coeff = constraints.get(row, col);
                if !coeff.is_zero() {
                    columns.push(col);
                    coefficients.push(coeff);
                }
            }
            received.push(asupersync::raptorq::decoder::ReceivedSymbol {
                esi: i as u32,
                is_source: true,
                columns,
                coefficients,
                data: data.clone(),
            });
        }
        for esi in (k as u32)..l as u32 {
            let (cols, coefs) = decoder.repair_equation(esi);
            let repair_data = encoder.repair_symbol(esi);
            received.push(asupersync::raptorq::decoder::ReceivedSymbol::repair(
                esi,
                cols,
                coefs,
                repair_data,
            ));
        }

        let result = decoder.decode(&received);
        let decode_ok = result.is_ok();
        let stats_str = if let Ok(ref r) = result {
            format!(
                "peeled={} inactivated={} gauss_ops={}",
                r.stats.peeled, r.stats.inactivated, r.stats.gauss_ops
            )
        } else {
            format!("FAIL: {:?}", result.err())
        };

        eprintln!(
            "E2E K={k} sym={symbol_size} seed={seed}: intermediate_hash={intermediate_hash:#018x} \
             repair_hash={repair_hash:#018x} decode_ok={decode_ok} {stats_str}"
        );
    }
}
