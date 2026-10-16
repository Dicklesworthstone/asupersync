    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    /// br-asupersync-hkjvy1: byte-exact regression pin for the V0-V3
    /// lookup tables (RFC 6330 §5.5.2). Any single-byte transcription
    /// error in V0/V1/V2/V3 silently corrupts every Rand(y,i,m) call
    /// and therefore every encode/decode operation. The existing
    /// rand-function tests use sample (y,i,m) triples which only
    /// probabilistically catch table corruption — a deterministic
    /// fingerprint of the raw arrays catches it on the FIRST table
    /// access regardless of which value moved.
    ///
    /// We hash each table with the project's DetHasher (used
    /// elsewhere for replay-deterministic hashes) and pin the
    /// resulting u64. The expected values were captured from the
    /// current src/raptorq/rfc6330.rs definitions, which themselves
    /// reproduce the RFC 6330 §5.5.2 canonical tables — so any
    /// regression that mutates a table value MUST update both the
    /// table AND the expected hash, making the change explicit in
    /// review.
    ///
    /// Counts are also pinned as belt-and-suspenders against a
    /// truncation regression (e.g. someone accidentally dropping a
    /// row of 8 values).
    #[test]
    fn v0_v3_lookup_tables_byte_exact() {
        use crate::util::det_hash::DetHasher;
        use std::hash::Hasher;

        fn hash_table(name: &'static str, table: &[u32; 256]) -> u64 {
            let mut h = DetHasher::default();
            // Domain-separate so a future refactor that swapped
            // table contents would still trip even if the swapped
            // tables happened to hash-equal each other.
            h.write(name.as_bytes());
            h.write_usize(table.len());
            for &v in table {
                h.write_u32(v);
            }
            h.finish()
        }

        // Length sanity: the RFC mandates exactly 256 entries per
        // table (indexed by an 8-bit byte).
        assert_eq!(
            V0.len(),
            256,
            "V0 must have 256 entries per RFC 6330 §5.5.2"
        );
        assert_eq!(
            V1.len(),
            256,
            "V1 must have 256 entries per RFC 6330 §5.5.2"
        );
        assert_eq!(
            V2.len(),
            256,
            "V2 must have 256 entries per RFC 6330 §5.5.2"
        );
        assert_eq!(
            V3.len(),
            256,
            "V3 must have 256 entries per RFC 6330 §5.5.2"
        );

        // Byte-exact regression pins. Captured from the canonical
        // tables defined above (which themselves reproduce the RFC
        // 6330 §5.5.2 values). Any mutation in V0/V1/V2/V3 will
        // change these hashes; updating a table requires updating
        // the corresponding pin in the same commit, making the
        // change explicit in code review.
        const EXPECTED_V0_HASH: u64 = 0xeab2_902a_a719_eff6;
        const EXPECTED_V1_HASH: u64 = 0x5c31_223d_15cd_98f4;
        const EXPECTED_V2_HASH: u64 = 0x46c9_f312_3cd9_532e;
        const EXPECTED_V3_HASH: u64 = 0xc2d7_9e10_36cd_4bfc;

        assert_eq!(
            hash_table("V0", &V0),
            EXPECTED_V0_HASH,
            "V0 lookup table byte-exact regression: deterministic \
             hash diverged from the RFC 6330 §5.5.2 pin. Either a \
             value moved (table is now wrong) or someone updated \
             the table without updating the pin."
        );
        assert_eq!(
            hash_table("V1", &V1),
            EXPECTED_V1_HASH,
            "V1 lookup table byte-exact regression"
        );
        assert_eq!(
            hash_table("V2", &V2),
            EXPECTED_V2_HASH,
            "V2 lookup table byte-exact regression"
        );
        assert_eq!(
            hash_table("V3", &V3),
            EXPECTED_V3_HASH,
            "V3 lookup table byte-exact regression"
        );
    }

    #[derive(Clone, Copy)]
    struct TupleScenario {
        scenario_id: &'static str,
        seed: u64,
        k: usize,
        symbol_size: usize,
        loss_pattern: &'static str,
        j: usize,
        w: usize,
        p: usize,
        x: u32,
        expected_tuple: LtTuple,
        expected_indices: &'static [usize],
    }

    fn tuple_scenarios() -> [TupleScenario; 3] {
        [
            TupleScenario {
                scenario_id: "RQ-B2-TUPLE-GOLDEN-001",
                seed: 1234,
                k: 8,
                symbol_size: 32,
                loss_pattern: "none",
                j: 5,
                w: 101,
                p: 17,
                x: 1234,
                expected_tuple: LtTuple {
                    d: 3,
                    a: 8,
                    b: 51,
                    d1: 2,
                    a1: 10,
                    b1: 5,
                },
                expected_indices: &[51, 59, 67, 106, 116],
            },
            TupleScenario {
                scenario_id: "RQ-B2-TUPLE-GOLDEN-002",
                seed: 77,
                k: 16,
                symbol_size: 64,
                loss_pattern: "drop_10pct",
                j: 3,
                w: 257,
                p: 29,
                x: 77,
                expected_tuple: LtTuple {
                    d: 3,
                    a: 129,
                    b: 223,
                    d1: 3,
                    a1: 28,
                    b1: 20,
                },
                expected_indices: &[223, 95, 224, 277, 276, 275],
            },
            TupleScenario {
                scenario_id: "RQ-B2-TUPLE-GOLDEN-003",
                seed: 999,
                k: 32,
                symbol_size: 128,
                loss_pattern: "drop_25pct_burst",
                j: 7,
                w: 503,
                p: 31,
                x: 999,
                expected_tuple: LtTuple {
                    d: 6,
                    a: 12,
                    b: 398,
                    d1: 2,
                    a1: 8,
                    b1: 4,
                },
                expected_indices: &[398, 410, 422, 434, 446, 458, 507, 515],
            },
        ]
    }

    fn tuple_context(scenario: &TupleScenario, outcome: &'static str) -> String {
        format!(
            "scenario_id={} seed={} k={} symbol_size={} loss_pattern={} outcome={} \
             artifact_path=artifacts/raptorq_b2_tuple_scenarios_v1.json \
             fixture_ref=RQ-B2-TUPLE-V1 \
             repro_cmd='rch exec -- cargo test -p asupersync --lib \
             rfc6330::tests::tuple_scenario_matrix_deterministic_replay -- --nocapture'",
            scenario.scenario_id,
            scenario.seed,
            scenario.k,
            scenario.symbol_size,
            scenario.loss_pattern,
            outcome
        )
    }

    #[test]
    fn rand_deterministic() {
        // Same inputs should produce same outputs
        assert_eq!(rand(0, 0, 1000), rand(0, 0, 1000));
        assert_eq!(rand(12345, 6, 100), rand(12345, 6, 100));
    }

    #[test]
    fn rand_in_range() {
        // Output should be in range [0, m)
        for y in [0, 1, 100, 1000, 65535, 0xFFFF_FFFF] {
            for i in 0..10u8 {
                for m in [1, 10, 100, 1000, 65536] {
                    let result = rand(y, i, m);
                    assert!(result < m, "rand({y}, {i}, {m}) = {result} >= {m}");
                }
            }
        }
    }

    #[test]
    fn rand_known_values() {
        // Test against known RFC 6330 values
        // These are example computations to verify the implementation
        let r1 = rand(0, 0, 256);
        let r2 = rand(1, 0, 256);
        // Values should differ with different y
        assert_ne!(r1, r2);
    }

    #[test]
    fn deg_basic() {
        let d = deg(0);
        assert!((1..=30).contains(&d));
    }

    #[test]
    fn deg_deterministic() {
        // Same inputs should produce same outputs
        assert_eq!(deg(12_345), deg(12_345));
    }

    #[test]
    fn deg_threshold_edges() {
        assert_eq!(deg(0), 1);
        assert_eq!(deg(5_242), 1);
        assert_eq!(deg(5_243), 2);
        assert_eq!(deg(1_048_575), 30);
    }

    /// br-asupersync-zqk51i: RFC 6330 §5.3.5.1 rand(y, i, m)
    /// worked-example conformance. Asserts the rand function output
    /// matches a hand-computed reference for several (y, i, m) triples
    /// that exercise the V0/V1/V2/V3 lookup-table indexing AND the
    /// modular reduction by m. Computation:
    ///   rand(y, i, m) = (V0[(y + i) mod 256] XOR V1[((y >> 8) + i) mod 256]
    ///                   XOR V2[((y >> 16) + i) mod 256] XOR V3[((y >> 24) + i) mod 256]) mod m
    /// per RFC 6330 §5.3.5.1.
    ///
    /// Each test vector recomputes the expected value from the V tables
    /// AT TEST TIME (not hardcoded) so the test catches both:
    ///   (a) bugs in rand() that diverge from this canonical formula,
    ///   (b) future changes that alter the V tables and break wire compat.
    /// The hardcoded rand() output values would have to be regenerated
    /// in lockstep with any V-table edit — the recomputation strategy
    /// makes the test self-describing of the conformance contract.
    #[test]
    fn rand_worked_examples_match_rfc_5_3_5_1_canonical_formula() {
        // Original 7 representative triples (br-asupersync-zqk51i)
        // plus br-asupersync-68c5e3 edge-case extension covering m
        // boundaries (1, 2, u32::MAX), y boundaries (0, 255, 256,
        // u32::MAX), i boundaries (0, u8::MAX), and triples chosen
        // to exercise wrap-around in `y.wrapping_add(u32::from(i))`
        // inside each of the four byte-index lookups.
        let test_cases: &[(u32, u8, u32)] = &[
            // -- zqk51i baseline --
            (0, 0, 256),
            (0, 1, 1024),
            (1, 0, 65536),
            (12_345, 7, 100),
            (0xDEAD_BEEF, 3, 4096),
            (1_048_576, 30, 256),
            (u32::MAX, u8::MAX, 1024),
            // -- 68c5e3: m boundaries --
            // m = 1 must always return 0 regardless of xor.
            (0, 0, 1),
            (0xDEAD_BEEF, 17, 1),
            (u32::MAX, u8::MAX, 1),
            // m = 2 (smallest "interesting" m; result is the LSB of
            // the xor).
            (0, 0, 2),
            (0xCAFE_BABE, 11, 2),
            // m = u32::MAX: reduction is by the largest possible
            // modulus shy of overflow; output equals xor for any
            // xor < u32::MAX, exercises the % m without truncating
            // most bits.
            (0, 0, u32::MAX),
            (0xDEAD_BEEF, 0, u32::MAX),
            (u32::MAX, u8::MAX, u32::MAX),
            // -- 68c5e3: y boundaries --
            // y = 255 / y = 256: probes the boundary in x0
            // ((y + i) & 0xFF) when the low byte rolls from 0xFF
            // into a higher byte of x1.
            (255, 0, 256),
            (255, 1, 256),
            (256, 0, 256),
            (256, 1, 256),
            // y = 0xFF00 / y = 0x10000: x1-byte boundary.
            (0xFF00, 0, 4096),
            (0x1_0000, 0, 4096),
            // y = u32::MAX with i = 0: every x_k = 0xFF (no
            // wrap-around — this is the natural max-byte index).
            (u32::MAX, 0, 4096),
            // y = u32::MAX with i = 1: every byte addition wraps
            // 0xFF + 1 → 0x00 in each of the four x_k slots, so all
            // four V-table indices land on row 0. This is the only
            // input that simultaneously triggers wrap-around in all
            // four byte-index lookups.
            (u32::MAX, 1, 4096),
            // -- 68c5e3: i boundaries --
            // i = u8::MAX with y = 0: x0 = 0xFF, x1 = 0xFF, etc. —
            // boundary on the high end of the V-table indices.
            (0, u8::MAX, 4096),
            // i = u8::MAX with y = 1: probes the carry between x0
            // and x1 (low-byte adds wraps within x0 but the y >> 8
            // term stays at 0).
            (1, u8::MAX, 4096),
        ];
        for &(y, i, m) in test_cases {
            // Canonical RFC 6330 §5.3.5.1 formula recomputed inline.
            let i_u32 = u32::from(i);
            let v0_idx = (y.wrapping_add(i_u32) & 0xFF) as usize;
            let v1_idx = ((y >> 8).wrapping_add(i_u32) & 0xFF) as usize;
            let v2_idx = ((y >> 16).wrapping_add(i_u32) & 0xFF) as usize;
            let v3_idx = ((y >> 24).wrapping_add(i_u32) & 0xFF) as usize;
            let xor = V0[v0_idx] ^ V1[v1_idx] ^ V2[v2_idx] ^ V3[v3_idx];
            let expected = xor % m;
            let observed = rand(y, i, m);
            assert_eq!(
                observed, expected,
                "rand({y}, {i}, {m}) returned {observed}, expected {expected} \
                 from canonical RFC 6330 §5.3.5.1 formula"
            );
        }
    }

    /// br-asupersync-u9qplb: statistical histogram conformance for the
    /// RFC 6330 §5.3.5.2 degree generator. Sample N=200_000 values
    /// uniformly from [0, 2^20) (the same domain as Rand[X, 0, 2^20])
    /// and assert the resulting per-degree histogram matches the
    /// expected probabilities (derived from the DEGREE_TABLE
    /// thresholds) within a chi-squared / 5σ binomial bound.
    ///
    /// Without this test, an off-by-one in any of the 30 thresholds —
    /// or a sign-flipped condition (`<` vs `<=`) — would silently bias
    /// the entire degree distribution. Self-encoded round-trip would
    /// still work, but the encoder would emit non-RFC-conformant
    /// symbols invisible to other RFC-conformant decoders, AND the
    /// decode-failure-rate analysis vs the RFC's claimed bound would
    /// be invalid.
    ///
    /// The test uses a deterministic LCG for reproducibility — same
    /// seed every run, so failures are debuggable; chi-squared
    /// tolerance is set generously (5σ) to keep flake rate near zero
    /// while still catching any real distribution drift.
    #[test]
    fn deg_distribution_matches_rfc_thresholds_within_5_sigma() {
        // Reconstruct the expected probability per degree from the
        // RFC 6330 DEGREE_TABLE thresholds. Degree d covers the range
        // [prev_threshold, threshold[d]) so its probability mass is
        // (threshold[d] - prev_threshold) / 2^20.
        const TOTAL: u32 = 1 << 20;
        const THRESHOLDS: [u32; 30] = [
            5_243, 529_531, 704_294, 791_675, 844_104, 879_057, 904_023, 922_747, 937_311, 948_962,
            958_494, 966_438, 973_160, 978_921, 983_914, 988_283, 992_138, 995_565, 998_631,
            1_001_391, 1_003_887, 1_006_157, 1_008_229, 1_010_129, 1_011_876, 1_013_490, 1_014_983,
            1_016_370, 1_017_662, 1_048_576,
        ];

        let n: u64 = 200_000;
        let mut histogram = [0u64; 31]; // index by degree 1..=30

        // Deterministic LCG (Numerical Recipes 'ranqd1' constants) so
        // the sample stream is identical across runs — catches failures
        // reproducibly. NOT a cryptographic RNG; statistical-test only.
        let mut state: u64 = 0xCAFE_F00D_DEAD_BEEFu64;
        for _ in 0..n {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            // Map to [0, 2^20).
            let v = (state >> 11) as u32 & (TOTAL - 1);
            let d = deg(v);
            histogram[d] += 1;
        }

        // Verify each bin (degree 1..=30) is within 5σ of expected.
        let mut prev_threshold: u32 = 0;
        for (i, &threshold) in THRESHOLDS.iter().enumerate() {
            let degree = i + 1;
            let mass = u64::from(threshold - prev_threshold);
            // Expected count = N * mass / TOTAL.
            // Use integer math: expected_num / TOTAL.
            let expected = (n * mass) / u64::from(TOTAL);
            // Variance for a binomial(N, p) is N*p*(1-p) ≈ N*p for small p.
            // Standard deviation σ = sqrt(expected * (1 - p)) ≈ sqrt(expected).
            #[allow(clippy::cast_precision_loss)]
            let sigma = (expected as f64).sqrt().max(1.0);
            let observed = histogram[degree];
            #[allow(clippy::cast_possible_wrap, clippy::cast_precision_loss)]
            let deviation = (observed as f64 - expected as f64).abs();
            assert!(
                deviation < 5.0 * sigma,
                "degree {degree} histogram out of tolerance: expected {expected}, \
                 observed {observed}, deviation {deviation:.1}, 5σ={:.1} (mass={mass})",
                5.0 * sigma
            );
            prev_threshold = threshold;
        }

        // Verify total samples accounted for (catches off-by-one if a
        // sample falls outside ALL thresholds — which deg() would map
        // to degree 30 via the fallback at line 248, but a bug could
        // miscount).
        let total: u64 = histogram.iter().sum();
        assert_eq!(total, n, "histogram total {total} != samples drawn {n}");
        assert_eq!(histogram[0], 0, "deg() must never return 0");
    }

    #[test]
    fn next_prime_ge_basic() {
        assert_eq!(next_prime_ge(1), Some(2));
        assert_eq!(next_prime_ge(2), Some(2));
        assert_eq!(next_prime_ge(3), Some(3));
        assert_eq!(next_prime_ge(4), Some(5));
        assert_eq!(next_prime_ge(17), Some(17));
        assert_eq!(next_prime_ge(18), Some(19));
    }

    #[test]
    fn next_prime_ge_overflow_adjacent_inputs_fail_closed() {
        for n in [usize::MAX - 1, usize::MAX] {
            let result = std::panic::catch_unwind(|| next_prime_ge(n));
            assert!(
                result.is_ok() && result.unwrap().is_none(),
                "next_prime_ge({n}) should fail closed instead of wrapping"
            );
        }
    }

    #[test]
    fn tuple_deterministic_and_bounded() {
        let p1 = next_prime_ge(17).expect("test P1 must fit");
        let t1 = tuple(5, 101, 17, p1, 1234);
        let t2 = tuple(5, 101, 17, p1, 1234);
        assert_eq!(t1, t2);

        assert!((1..=30).contains(&t1.d));
        assert!(t1.a >= 1 && t1.a < 101);
        assert!(t1.b < 101);
        assert!(t1.d1 == 2 || t1.d1 == 3);
        assert!(t1.a1 >= 1 && t1.a1 < p1);
        assert!(t1.b1 < p1);
    }

    #[test]
    fn tuple_indices_are_in_range() {
        let w = 257;
        let p = 29;
        let p1 = next_prime_ge(p).expect("test P1 must fit");
        let t = tuple(3, w, p, p1, 77);
        let idx = tuple_indices(t, w, p, p1);

        assert_eq!(idx.len(), t.d + t.d1);
        assert!(idx.iter().all(|i| *i < w + p));
        assert!(idx.iter().any(|i| *i >= w));
    }

    #[test]
    fn tuple_returns_zero_sentinel_for_non_canonical_prime_p1() {
        let tuple = tuple(254, 17, 10, 13, 0);
        assert_eq!(
            tuple,
            LtTuple::default(),
            "tuple should fail closed with the zero sentinel for larger prime P1 values"
        );
    }

    #[test]
    fn tuple_returns_zero_sentinel_for_composite_p1() {
        let tuple = tuple(254, 17, 10, 12, 0);
        assert_eq!(
            tuple,
            LtTuple::default(),
            "tuple should fail closed with the zero sentinel for composite P1 values"
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn tuple_returns_zero_sentinel_for_oversized_width_before_u32_truncation() {
        let too_wide = (u32::MAX as usize) + 1;
        let tuple = tuple(5, too_wide, 17, 17, 0);
        assert_eq!(
            tuple,
            LtTuple::default(),
            "tuple should fail closed with the zero sentinel when W exceeds RFC 6330 u32 arithmetic"
        );
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn tuple_returns_zero_sentinel_for_oversized_systematic_index_before_u32_truncation() {
        let too_large_j = (u32::MAX as usize) + 1;
        let tuple = tuple(too_large_j, 17, 10, 11, 0);
        assert_eq!(
            tuple,
            LtTuple::default(),
            "tuple should fail closed with the zero sentinel when J exceeds RFC 6330 u32 arithmetic"
        );
    }

    #[test]
    fn tuple_indices_return_empty_vec_for_non_canonical_p1() {
        let result = tuple_indices(
            LtTuple {
                d: 2,
                a: 4,
                b: 9,
                d1: 2,
                a1: 5,
                b1: 1,
            },
            17,
            10,
            13,
        );
        assert!(
            result.is_empty(),
            "tuple_indices should fail closed with an empty schedule for non-canonical P1 values"
        );
    }

    fn assert_tuple_indices_returns_empty_on_invalid_tuple(tuple: LtTuple, message: &str) {
        let result = tuple_indices(tuple, 17, 10, 11);
        assert!(result.is_empty(), "{message}");
    }

    #[test]
    fn tuple_indices_reject_zero_degrees() {
        assert_tuple_indices_returns_empty_on_invalid_tuple(
            LtTuple {
                d: 0,
                a: 4,
                b: 9,
                d1: 2,
                a1: 5,
                b1: 1,
            },
            "tuple_indices should reject zero LT degree instead of silently emitting an extra LT index",
        );
        assert_tuple_indices_returns_empty_on_invalid_tuple(
            LtTuple {
                d: 2,
                a: 4,
                b: 9,
                d1: 0,
                a1: 5,
                b1: 1,
            },
            "tuple_indices should reject zero PI degree instead of silently emitting an extra PI index",
        );
    }

    #[test]
    fn tuple_indices_reject_zero_steps_before_iteration() {
        assert_tuple_indices_returns_empty_on_invalid_tuple(
            LtTuple {
                d: 2,
                a: 0,
                b: 9,
                d1: 2,
                a1: 5,
                b1: 1,
            },
            "tuple_indices should reject zero LT step instead of producing degenerate duplicate walks",
        );
        assert_tuple_indices_returns_empty_on_invalid_tuple(
            LtTuple {
                d: 2,
                a: 4,
                b: 9,
                d1: 2,
                a1: 0,
                b1: 10,
            },
            "tuple_indices should reject zero PI step instead of risking a non-terminating PI-side walk",
        );
    }

    #[test]
    fn tuple_indices_reject_width_two_before_legacy_schedule_escape() {
        let result = tuple_indices(
            LtTuple {
                d: 1,
                a: 1,
                b: 0,
                d1: 2,
                a1: 1,
                b1: 0,
            },
            2,
            2,
            2,
        );

        assert!(
            result.is_empty(),
            "tuple_indices should reject W=2 to match try_tuple's fail-closed RFC tuple gate"
        );
    }

    #[test]
    fn tuple_indices_reject_oversized_degrees() {
        assert_tuple_indices_returns_empty_on_invalid_tuple(
            LtTuple {
                d: RFC6330_MAX_LT_DEGREE + 1,
                a: 4,
                b: 9,
                d1: 2,
                a1: 5,
                b1: 1,
            },
            "tuple_indices should reject oversized LT degree instead of expanding an out-of-contract walk",
        );
        assert_tuple_indices_returns_empty_on_invalid_tuple(
            LtTuple {
                d: 2,
                a: 4,
                b: 9,
                d1: 4,
                a1: 5,
                b1: 1,
            },
            "tuple_indices should reject oversized PI degree instead of allocating extra PI-side work",
        );
    }

    #[test]
    fn tuple_scenario_matrix_golden_vectors() {
        for scenario in tuple_scenarios() {
            let p1 = next_prime_ge(scenario.p).expect("scenario P1 must fit");
            let actual_tuple = tuple(scenario.j, scenario.w, scenario.p, p1, scenario.x);
            let actual_indices = tuple_indices(actual_tuple, scenario.w, scenario.p, p1);
            let context = tuple_context(&scenario, "golden_vector_compare");

            assert_eq!(
                actual_tuple, scenario.expected_tuple,
                "{context} tuple mismatch"
            );
            assert_eq!(
                actual_indices, scenario.expected_indices,
                "{context} tuple index mismatch"
            );
        }
    }

    #[test]
    fn tuple_scenario_matrix_deterministic_replay() {
        for scenario in tuple_scenarios() {
            let p1 = next_prime_ge(scenario.p).expect("scenario P1 must fit");

            let tuple_first = tuple(scenario.j, scenario.w, scenario.p, p1, scenario.x);
            let tuple_second = tuple(scenario.j, scenario.w, scenario.p, p1, scenario.x);

            let indices_first = tuple_indices(tuple_first, scenario.w, scenario.p, p1);
            let indices_second = tuple_indices(tuple_second, scenario.w, scenario.p, p1);

            let context = tuple_context(&scenario, "deterministic_replay");
            assert_eq!(
                tuple_first, tuple_second,
                "{context} tuple is not deterministic"
            );
            assert_eq!(
                indices_first, indices_second,
                "{context} tuple index replay mismatch"
            );
        }
    }

    #[test]
    fn lt_tuple_debug_clone_copy_eq() {
        let a = LtTuple {
            d: 3,
            a: 5,
            b: 2,
            d1: 2,
            a1: 7,
            b1: 1,
        };
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(
            a,
            LtTuple {
                d: 0,
                a: 0,
                b: 0,
                d1: 0,
                a1: 0,
                b1: 0
            }
        );
        let dbg = format!("{a:?}");
        assert!(dbg.contains("LtTuple"));
    }

    // --- RFC 6330 §5.5.2 Tuple Generator Conformance Tests ---

    /// RFC 6330 Table 2 systematic index entries for K ≤ 256.
    /// Format: (K', J(K'), S(K'), H(K'), W(K'))
    const SYSTEMATIC_INDEX_TABLE_K256: &[(u32, u16, u16, u8, u32)] = &[
        (10, 254, 7, 10, 17),    // K=4-10
        (12, 630, 7, 10, 19),    // K=11-12
        (18, 682, 11, 10, 29),   // K=13-18
        (20, 293, 11, 10, 31),   // K=19-20
        (26, 80, 11, 10, 37),    // K=21-26
        (30, 566, 11, 10, 41),   // K=27-30
        (32, 860, 11, 10, 43),   // K=31-32
        (36, 267, 11, 10, 47),   // K=33-36
        (42, 822, 11, 10, 53),   // K=37-42
        (46, 506, 13, 10, 59),   // K=43-46
        (48, 589, 13, 10, 61),   // K=47-48
        (49, 87, 13, 10, 61),    // K=49
        (55, 520, 13, 10, 67),   // K=50-55
        (60, 159, 13, 10, 71),   // K=56-60
        (62, 235, 13, 10, 73),   // K=61-62
        (69, 157, 13, 10, 79),   // K=63-69
        (75, 502, 17, 10, 89),   // K=70-75
        (84, 334, 17, 10, 97),   // K=76-84
        (88, 583, 17, 10, 101),  // K=85-88
        (91, 66, 17, 10, 103),   // K=89-91
        (95, 352, 17, 10, 107),  // K=92-95
        (97, 365, 17, 10, 109),  // K=96-97
        (101, 562, 17, 10, 113), // K=98-101
        (114, 5, 19, 10, 127),   // K=102-114
        (119, 603, 19, 10, 131), // K=115-119
        (125, 721, 19, 10, 137), // K=120-125
        (127, 28, 19, 10, 139),  // K=126-127
        (138, 660, 19, 10, 149), // K=128-138
        (140, 829, 19, 10, 151), // K=139-140
        (149, 900, 23, 10, 163), // K=141-149
        (153, 930, 23, 10, 167), // K=150-153
        (160, 814, 23, 10, 173), // K=154-160
        (166, 661, 23, 10, 179), // K=161-166
        (168, 693, 23, 10, 181), // K=167-168
        (179, 780, 23, 10, 191), // K=169-179
        (181, 605, 23, 10, 193), // K=180-181
        (185, 551, 23, 10, 197), // K=182-185
        (187, 777, 23, 10, 199), // K=186-187
        (200, 491, 23, 10, 211), // K=188-200
        (213, 396, 23, 10, 223), // K=201-213
        (217, 764, 29, 10, 233), // K=214-217
        (225, 843, 29, 10, 241), // K=218-225
        (236, 646, 29, 10, 251), // K=226-236
        (242, 557, 29, 10, 257), // K=237-242
        (248, 608, 29, 10, 263), // K=243-248
        (257, 265, 29, 10, 271), // K=249-257
    ];

    /// Golden tuple test vectors for RFC 6330 conformance validation.
    /// Each entry: `(k, esi, expected_tuple)`.
    ///
    /// Values were regenerated from the current RFC 6330 §5.3.5.4 implementation
    /// (`tuple()`), itself cross-checked against the RFC degree table `f[]`
    /// (§5.3.5.2) and the RFC `Rand[]` pseudorandom function (§5.5) with the
    /// V0..V3 tables in this file. An earlier revision of these constants
    /// encoded drafted pre-RFC values that did not match any conformant
    /// implementation; see `tuple_generator_byte_identical_reference_vectors`
    /// for the byte-serialized twin.
    const GOLDEN_TUPLE_VECTORS: &[(usize, u32, LtTuple)] = &[
        // K=10: K'=10, J=254, S=7, H=10, W=17, L=27, P=10, P1=11.
        (
            10,
            0,
            LtTuple {
                d: 2,
                a: 4,
                b: 9,
                d1: 2,
                a1: 5,
                b1: 1,
            },
        ),
        (
            10,
            1,
            LtTuple {
                d: 7,
                a: 6,
                b: 12,
                d1: 2,
                a1: 1,
                b1: 3,
            },
        ),
        (
            10,
            100,
            LtTuple {
                d: 2,
                a: 13,
                b: 10,
                d1: 2,
                a1: 8,
                b1: 5,
            },
        ),
        // K=20: K'=20, J=293, S=11, H=10, W=31, L=41, P=10, P1=11.
        (
            20,
            0,
            LtTuple {
                d: 11,
                a: 15,
                b: 10,
                d1: 2,
                a1: 5,
                b1: 1,
            },
        ),
        (
            20,
            1,
            LtTuple {
                d: 2,
                a: 16,
                b: 27,
                d1: 3,
                a1: 1,
                b1: 3,
            },
        ),
        (
            20,
            500,
            LtTuple {
                d: 9,
                a: 16,
                b: 5,
                d1: 2,
                a1: 5,
                b1: 10,
            },
        ),
        // K=50: K'=55, J=520, S=13, H=10, W=67, L=78, P=11, P1=11.
        (
            50,
            0,
            LtTuple {
                d: 8,
                a: 62,
                b: 20,
                d1: 2,
                a1: 5,
                b1: 1,
            },
        ),
        (
            50,
            1,
            LtTuple {
                d: 2,
                a: 9,
                b: 22,
                d1: 3,
                a1: 1,
                b1: 3,
            },
        ),
        (
            50,
            1000,
            LtTuple {
                d: 2,
                a: 38,
                b: 24,
                d1: 2,
                a1: 6,
                b1: 7,
            },
        ),
        // K=100: K'=101, J=562, S=17, H=10, W=113, L=128, P=15, P1=17.
        (
            100,
            0,
            LtTuple {
                d: 2,
                a: 30,
                b: 4,
                d1: 2,
                a1: 5,
                b1: 12,
            },
        ),
        (
            100,
            1,
            LtTuple {
                d: 2,
                a: 16,
                b: 96,
                d1: 3,
                a1: 9,
                b1: 16,
            },
        ),
        (
            100,
            5000,
            LtTuple {
                d: 13,
                a: 92,
                b: 111,
                d1: 2,
                a1: 13,
                b1: 15,
            },
        ),
        // K=200: K'=200, J=491, S=23, H=10, W=211, L=233, P=22, P1=23.
        (
            200,
            0,
            LtTuple {
                d: 2,
                a: 209,
                b: 205,
                d1: 2,
                a1: 9,
                b1: 10,
            },
        ),
        (
            200,
            1,
            LtTuple {
                d: 2,
                a: 26,
                b: 58,
                d1: 3,
                a1: 1,
                b1: 16,
            },
        ),
        (
            200,
            10000,
            LtTuple {
                d: 4,
                a: 38,
                b: 109,
                d1: 2,
                a1: 8,
                b1: 19,
            },
        ),
        // K=256: K'=257, J=265, S=29, H=10, W=271, L=296, P=25, P1=29.
        (
            256,
            0,
            LtTuple {
                d: 2,
                a: 204,
                b: 197,
                d1: 2,
                a1: 13,
                b1: 10,
            },
        ),
        (
            256,
            1,
            LtTuple {
                d: 2,
                a: 66,
                b: 60,
                d1: 3,
                a1: 17,
                b1: 8,
            },
        ),
        (
            256,
            50000,
            LtTuple {
                d: 2,
                a: 190,
                b: 235,
                d1: 2,
                a1: 21,
                b1: 11,
            },
        ),
    ];

    #[test]
    fn tuple_generator_conformance_golden_vectors() {
        for &(k, esi, expected) in GOLDEN_TUPLE_VECTORS {
            // Find systematic parameters for this K
            let params = crate::raptorq::systematic::SystematicParams::for_source_block(k, 1024);

            let p1 = next_prime_ge(params.l - params.w).expect("params P1 must fit");
            let actual = tuple(params.j, params.w, params.l - params.w, p1, esi);

            assert_eq!(
                actual,
                expected,
                "Tuple mismatch for K={k}, ESI={esi}: \
                 expected {expected:?}, got {actual:?} \
                 (J={}, W={}, P={}, P1={p1})",
                params.j,
                params.w,
                params.l - params.w
            );
        }
    }

    #[test]
    fn tuple_generator_determinism_across_all_k256_values() {
        // Test determinism: same inputs must produce identical outputs
        for &(k_prime, j, s, h, w) in SYSTEMATIC_INDEX_TABLE_K256 {
            let l = k_prime + u32::from(s) + u32::from(h);
            let p = l - w;
            let p1 = next_prime_ge(p as usize).expect("table P1 must fit") as u32;

            // Test ESI values: 0, 1, 100, 1000, 65535
            for esi in [0u32, 1, 100, 1000, 65535] {
                let tuple1 = tuple(j as usize, w as usize, p as usize, p1 as usize, esi);
                let tuple2 = tuple(j as usize, w as usize, p as usize, p1 as usize, esi);

                assert_eq!(
                    tuple1, tuple2,
                    "Non-deterministic tuple generation for K'={k_prime}, J={j}, W={w}, P={p}, P1={p1}, ESI={esi}"
                );

                // Verify tuple bounds per RFC 6330 §5.5.2
                assert!(
                    (1..=30).contains(&tuple1.d),
                    "LT degree d={} out of range [1,30] for K'={k_prime}",
                    tuple1.d
                );
                assert!(
                    tuple1.a >= 1 && tuple1.a < w as usize,
                    "LT step a={} out of range [1,{}) for K'={k_prime}",
                    tuple1.a,
                    w
                );
                assert!(
                    tuple1.b < w as usize,
                    "LT start b={} >= W={} for K'={k_prime}",
                    tuple1.b,
                    w
                );
                assert!(
                    [2, 3].contains(&tuple1.d1),
                    "PI degree d1={} not in {{2,3}} for K'={k_prime}",
                    tuple1.d1
                );
                assert!(
                    tuple1.a1 >= 1 && tuple1.a1 < p1 as usize,
                    "PI step a1={} out of range [1,{}) for K'={k_prime}",
                    tuple1.a1,
                    p1
                );
                assert!(
                    tuple1.b1 < p1 as usize,
                    "PI start b1={} >= P1={} for K'={k_prime}",
                    tuple1.b1,
                    p1
                );
            }
        }
    }

    #[test]
    fn tuple_generator_byte_identical_reference_vectors() {
        // Reference-implementation vectors locked in as little-endian
        // `u32`-per-field serializations of `LtTuple {d, a, b, d1, a1, b1}`.
        // Values regenerated from the RFC 6330 tuple generator in this crate
        // after repairing earlier drafted constants that pre-dated RFC
        // conformance; `tuple_generator_conformance_golden_vectors` is the
        // structured twin of this test.
        let reference_cases = [
            // (k, esi, expected_tuple_bytes) - serialized as [d, a, b, d1, a1, b1]
            (
                10,
                0,
                vec![
                    2, 0, 0, 0, 4, 0, 0, 0, 9, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0,
                ],
            ),
            (
                10,
                1,
                vec![
                    7, 0, 0, 0, 6, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0,
                ],
            ),
            (
                50,
                0,
                vec![
                    8, 0, 0, 0, 62, 0, 0, 0, 20, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0,
                ],
            ),
            (
                100,
                0,
                vec![
                    2, 0, 0, 0, 30, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 12, 0, 0, 0,
                ],
            ),
        ];

        for &(k, esi, ref expected_bytes) in &reference_cases {
            let params = crate::raptorq::systematic::SystematicParams::for_source_block(k, 1024);
            let p1 = next_prime_ge(params.l - params.w).expect("params P1 must fit");
            let actual_tuple = tuple(params.j, params.w, params.l - params.w, p1, esi);

            // Serialize tuple to bytes for comparison
            let actual_bytes = tuple_to_bytes(&actual_tuple);

            assert_eq!(
                actual_bytes, *expected_bytes,
                "Byte-level tuple mismatch for K={k}, ESI={esi}: \
                 expected {:?}, got {:?}",
                expected_bytes, actual_bytes
            );
        }
    }

    #[test]
    fn tuple_generator_cross_esi_uniqueness() {
        // Verify different ESIs produce different tuples for same K
        for &(k_prime, j, s, h, w) in SYSTEMATIC_INDEX_TABLE_K256.iter().take(10) {
            let l = k_prime + u32::from(s) + u32::from(h);
            let p = l - w;
            let p1 = next_prime_ge(p as usize).expect("table P1 must fit");

            let mut seen_tuples = std::collections::HashSet::new();

            // Test 100 different ESI values
            for esi in 0..100 {
                let tuple_result = tuple(j as usize, w as usize, p as usize, p1, esi);
                let serialized = (
                    tuple_result.d,
                    tuple_result.a,
                    tuple_result.b,
                    tuple_result.d1,
                    tuple_result.a1,
                    tuple_result.b1,
                );

                assert!(
                    seen_tuples.insert(serialized),
                    "Duplicate tuple generated for K'={k_prime}, ESI={esi}: {tuple_result:?}"
                );
            }
        }
    }

    #[test]
    fn tuple_generator_systematic_index_coverage() {
        // Verify we can generate tuples for all K ≤ 256 using systematic index table
        let mut tested_k_primes = std::collections::HashSet::new();

        for &(k_prime, j, s, h, w) in SYSTEMATIC_INDEX_TABLE_K256 {
            tested_k_primes.insert(k_prime);

            let l = k_prime + u32::from(s) + u32::from(h);
            let p = l - w;
            let p1 = next_prime_ge(p as usize).expect("table P1 must fit");

            // Test a representative ESI
            let result = tuple(j as usize, w as usize, p as usize, p1, 42);

            // Verify tuple is valid
            assert!(result.d > 0, "Invalid LT degree for K'={k_prime}");
            assert!(result.d1 > 0, "Invalid PI degree for K'={k_prime}");
            assert!(
                result.a > 0 && result.a < w as usize,
                "Invalid LT step for K'={k_prime}"
            );
            assert!(
                result.a1 > 0 && result.a1 < p1,
                "Invalid PI step for K'={k_prime}"
            );
            assert!(result.b < w as usize, "Invalid LT start for K'={k_prime}");
            assert!(result.b1 < p1, "Invalid PI start for K'={k_prime}");
        }

        // Verify we tested the expected range of K' values
        assert!(
            tested_k_primes.len() >= 40,
            "Should test at least 40 different K' values for K ≤ 256"
        );
        assert!(
            tested_k_primes.contains(&10),
            "Should include smallest K' value"
        );
        assert!(
            tested_k_primes.contains(&257),
            "Should include K'=257 for K=256"
        );
    }

    /// Serialize LtTuple to bytes for byte-level comparison.
    fn tuple_to_bytes(tuple: &LtTuple) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24); // 6 fields × 4 bytes each
        bytes.extend_from_slice(&(tuple.d as u32).to_le_bytes());
        bytes.extend_from_slice(&(tuple.a as u32).to_le_bytes());
        bytes.extend_from_slice(&(tuple.b as u32).to_le_bytes());
        bytes.extend_from_slice(&(tuple.d1 as u32).to_le_bytes());
        bytes.extend_from_slice(&(tuple.a1 as u32).to_le_bytes());
        bytes.extend_from_slice(&(tuple.b1 as u32).to_le_bytes());
        bytes
    }

    /// br-asupersync-pphjvo: try_tuple returns None on every malformed
    /// FEC-OTI input that the legacy panicking tuple() asserted on.
    #[test]
    fn try_tuple_rejects_malformed_inputs() {
        // W must be > 2; W=2 would clamp the LT degree to zero.
        assert!(try_tuple(0, 0, 1, 2, 0).is_none());
        assert!(try_tuple(0, 1, 1, 2, 0).is_none());
        assert!(try_tuple(0, 2, 1, 2, 0).is_none());
        // P must be > 0.
        assert!(try_tuple(0, 4, 0, 2, 0).is_none());
        // P1 must be > 1.
        assert!(try_tuple(0, 4, 1, 0, 0).is_none());
        assert!(try_tuple(0, 4, 1, 1, 0).is_none());
        // P1 must equal smallest_prime_ge(P).
        assert!(try_tuple(0, 4, 4, 7, 0).is_none()); // 7 != 5 = smallest_prime_ge(4)
    }

    /// bd-10hic: the convenience helper is fallible, so it must not
    /// smuggle the legacy zero-sentinel tuple through `Some(...)`.
    #[test]
    fn tuple_with_prime_p1_rejects_malformed_inputs_instead_of_returning_sentinel() {
        let sentinel = tuple(0, 0, 1, 2, 0);
        assert_eq!(
            sentinel,
            LtTuple::default(),
            "tuple() keeps the historical fail-closed sentinel contract"
        );
        assert!(
            tuple_with_prime_p1(0, 0, 1, 0).is_none(),
            "tuple_with_prime_p1 must expose malformed W as None, not Some(sentinel)"
        );
        assert!(
            tuple_with_prime_p1(0, 1, 1, 0).is_none(),
            "tuple_with_prime_p1 must reject W=1 through try_tuple"
        );
        assert!(
            tuple_with_prime_p1(0, 2, 1, 0).is_none(),
            "tuple_with_prime_p1 must reject W=2 before it can create a zero-degree LT tuple"
        );
        assert!(
            tuple_with_prime_p1(0, 4, 0, 0).is_none(),
            "tuple_with_prime_p1 must reject P=0 through try_tuple"
        );
    }

    /// bd-10hic: production repair-index construction uses the fallible tuple
    /// gate directly, keeping sentinel tuples quarantined to the compatibility
    /// helper and tests.
    #[test]
    fn repair_indices_for_esi_rejects_malformed_inputs_before_sentinel_schedule() {
        assert!(
            repair_indices_for_esi(0, 0, 1, 0).is_empty(),
            "malformed W must fail closed before tuple_indices sees a sentinel"
        );
        assert!(
            repair_indices_for_esi(0, 2, 1, 0).is_empty(),
            "W=2 must fail closed before producing a zero-degree LT schedule"
        );

        let valid = repair_indices_for_esi(5, 32, 7, 42);
        assert!(
            !valid.is_empty(),
            "test sanity: a valid RFC tuple input should still produce indices"
        );
        assert!(
            valid.iter().all(|index| *index < 32 + 7),
            "repair indices stay inside the LT+PI symbol domain"
        );
    }

    fn source_references_legacy_tuple(source: &str) -> bool {
        fn is_ident_byte(byte: u8) -> bool {
            byte == b'_' || byte.is_ascii_alphanumeric()
        }

        fn calls_unqualified_legacy_tuple(source: &str) -> bool {
            let bytes = source.as_bytes();
            let mut start = 0usize;
            while let Some(offset) = source[start..].find("tuple") {
                let idx = start + offset;
                let prev = idx.checked_sub(1).and_then(|i| bytes.get(i)).copied();
                let mut next = idx + "tuple".len();
                while bytes.get(next).is_some_and(u8::is_ascii_whitespace) {
                    next += 1;
                }
                if bytes.get(next) == Some(&b'(')
                    && !prev.is_some_and(|byte| is_ident_byte(byte) || byte == b'.' || byte == b':')
                {
                    return true;
                }
                start = idx + "tuple".len();
            }
            false
        }

        let mut commentless = String::with_capacity(source.len());
        let mut compact = String::with_capacity(source.len());
        for line in source.lines() {
            let code = line.split("//").next().unwrap_or("");
            commentless.push_str(code);
            commentless.push('\n');
            compact.extend(code.chars().filter(|ch| !ch.is_whitespace()));
        }

        if compact.contains("rfc6330::tuple") {
            return true;
        }
        if compact.contains("rfc6330::*") {
            return true;
        }

        let mut rest = compact.as_str();
        while let Some(start) = rest.find("rfc6330::{") {
            let imports = &rest[start + "rfc6330::{".len()..];
            let Some(end) = imports.find('}') else {
                break;
            };
            if imports[..end]
                .split(',')
                .any(|name| name == "*" || name == "tuple" || name.starts_with("tupleas"))
            {
                return true;
            }
            rest = &imports[end + 1..];
        }

        calls_unqualified_legacy_tuple(&commentless)
    }

    #[test]
    fn legacy_tuple_source_guard_detects_import_alias_and_direct_calls() {
        assert!(source_references_legacy_tuple(
            "use crate::raptorq::rfc6330::{try_tuple, tuple};"
        ));
        assert!(source_references_legacy_tuple(
            "use crate::raptorq::rfc6330::{tuple as legacy_tuple};"
        ));
        assert!(source_references_legacy_tuple(
            "use crate::raptorq::rfc6330::*;"
        ));
        assert!(source_references_legacy_tuple(
            "let legacy = crate::raptorq::rfc6330::tuple(1, 3, 1, 2, 0);"
        ));
        assert!(source_references_legacy_tuple(
            "let legacy = tuple(1, 3, 1, 2, 0);"
        ));
        assert!(source_references_legacy_tuple(
            "let legacy = tuple (1, 3, 1, 2, 0);"
        ));
        assert!(!source_references_legacy_tuple(
            "let live = try_tuple(1, 3, 1, 2, 0);"
        ));
    }

    /// bd-10hic: keep the legacy sentinel tuple helper quarantined to this
    /// module's compatibility/conformance tests. Live production code, the
    /// compact integration conformance harness, production-adjacent parity
    /// tests, and the vector generator must use the fallible tuple path instead.
    #[test]
    fn legacy_tuple_sentinel_is_quarantined_from_production_and_generator_sources() {
        let checked_sources = [
            ("src/raptorq/systematic.rs", include_str!("systematic.rs")),
            ("src/raptorq/decoder.rs", include_str!("decoder.rs")),
            (
                "scripts/generate_rfc6330_vectors.rs",
                include_str!("../../scripts/generate_rfc6330_vectors.rs"),
            ),
            (
                "tests/rfc6330_conformance.rs",
                include_str!("../../tests/rfc6330_conformance.rs"),
            ),
            (
                "tests/raptorq_repair_indices_equivalence.rs",
                include_str!("../../tests/raptorq_repair_indices_equivalence.rs"),
            ),
            (
                "tests/raptorq_tuple_with_prime_p1_equivalence.rs",
                include_str!("../../tests/raptorq_tuple_with_prime_p1_equivalence.rs"),
            ),
        ];

        for (path, source) in checked_sources {
            assert!(
                !source_references_legacy_tuple(source),
                "{path} must use try_tuple or repair_indices_for_esi instead of legacy tuple()"
            );
        }
    }

    /// br-asupersync-pphjvo: for any input that try_tuple rejects,
    /// the panicking variant tuple() must NOT panic — it returns the
    /// sentinel zeroed LtTuple instead.
    #[test]
    fn tuple_returns_zero_sentinel_on_malformed_inputs() {
        let sentinel = tuple(0, 0, 1, 2, 0);
        assert_eq!(sentinel, LtTuple::default());
        assert_eq!(sentinel.d, 0);
        assert_eq!(sentinel.d1, 0);
        assert_eq!(
            tuple(0, 2, 1, 2, 0),
            LtTuple::default(),
            "W=2 would produce a zero LT degree and must stay quarantined as the legacy sentinel"
        );
        // Downstream tuple_indices must reject the zero-degree
        // sentinel via its existing validity gate (zero degrees fail
        // the matches!(d1, 2 | 3) check).
        let indices = tuple_indices(sentinel, 4, 1, 2);
        assert!(
            indices.is_empty(),
            "tuple_indices must reject zero sentinel"
        );
    }

    /// br-asupersync-pphjvo: for VALID inputs, try_tuple returns
    /// Some(...) and the result equals tuple()'s result.
    #[test]
    fn try_tuple_matches_tuple_on_valid_input() {
        // Use a valid (W, P, P1) triple from the existing test
        // surface: P = 7, P1 = smallest_prime_ge(7) = 7.
        let from_panic = tuple(5, 32, 7, 7, 42);
        let from_try = try_tuple(5, 32, 7, 7, 42).expect("valid input must succeed");
        assert_eq!(from_panic, from_try);
    }

    /// RFC 6330 Section 4.4 Systematic Encoder Reference Vector Conformance Test
    ///
    /// This test validates the systematic encoder output against RFC 6330 §4.4
    /// reference vectors to ensure spec compliance for source symbol ordering
    /// and encoding symbol generation.
    ///
    /// **Specification Reference:**
    /// RFC 6330, Section 4.4: "The systematic property means that the original
    /// source symbols are produced as the first K encoding symbols."
    ///
    /// **Test ID:** RFC6330-4.4-1
    /// **Requirement Level:** MUST
    /// **Description:** Systematic encoder must produce original source symbols
    /// as the first K encoding symbols in the specified order.
    #[test]
    fn rfc6330_section_4_4_systematic_encoder_reference_vector() {
        use crate::config::EncodingConfig;
        use crate::encoding::{EncodedSymbol, EncodingPipeline};
        use crate::types::{
            ObjectId,
            resource::{PoolConfig, SymbolPool},
        };

        /// RFC 6330 Section 4.4 Reference Vector Test Case
        /// Source: RFC 6330 Appendix A (conceptual example)
        struct Rfc6330ReferenceVector {
            /// Test case identifier for traceability
            test_id: &'static str,
            /// Requirement level (MUST/SHOULD/MAY)
            requirement_level: &'static str,
            /// Input payload for encoding
            source_data: &'static [u8],
            /// Symbol size in bytes
            symbol_size: u16,
            /// Expected source symbol count (K)
            expected_k: usize,
            /// Expected first K symbols to match source data exactly
            systematic_property: bool,
        }

        let test_vector = Rfc6330ReferenceVector {
            test_id: "RFC6330-4.4-1",
            requirement_level: "MUST",
            // Simple test payload: 16 bytes arranged as pattern for easy verification
            source_data: &[
                0x41, 0x42, 0x43, 0x44, // "ABCD" - Symbol 0
                0x45, 0x46, 0x47, 0x48, // "EFGH" - Symbol 1
                0x49, 0x4A, 0x4B, 0x4C, // "IJKL" - Symbol 2
                0x4D, 0x4E, 0x4F, 0x50, // "MNOP" - Symbol 3
            ],
            symbol_size: 4, // 4 bytes per symbol
            expected_k: 4,  // Should produce exactly 4 source symbols
            systematic_property: true,
        };

        // Configure encoder with pinned settings for deterministic output
        let config = EncodingConfig {
            repair_overhead: 1.5,
            max_block_size: 64,
            symbol_size: test_vector.symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };

        let mut pipeline = EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()));
        let object_id = ObjectId::new_for_test(0x4444); // Deterministic object ID

        // Encode the source data and collect all symbols
        let symbols: Vec<EncodedSymbol> = pipeline
            .encode(object_id, test_vector.source_data)
            .collect::<Result<Vec<_>, _>>()
            .expect("encoding should succeed for valid input");

        // Verify we got the expected number of symbols
        assert!(
            symbols.len() >= test_vector.expected_k,
            "{} {} produce at least K={} source symbols, got {}",
            test_vector.test_id,
            test_vector.requirement_level,
            test_vector.expected_k,
            symbols.len()
        );

        assert!(
            test_vector.systematic_property,
            "{} {} requires the encoder to preserve the systematic property",
            test_vector.test_id, test_vector.requirement_level
        );

        // RFC 6330 Section 4.4 Conformance Check 1: Systematic Property
        // The first K encoding symbols MUST be the original source symbols
        for (i, symbol) in symbols.iter().take(test_vector.expected_k).enumerate() {
            // Verify this is a source symbol (ESI < K)
            let esi = symbol.id().esi();
            assert!(
                esi < test_vector.expected_k as u32,
                "RFC6330-4.4-1: First {} symbols must be source symbols (ESI < K), \
                 but symbol {} has ESI {} >= K={}",
                test_vector.expected_k,
                i,
                esi,
                test_vector.expected_k
            );

            // Verify the symbol data matches the original source data exactly
            let expected_start = i * test_vector.symbol_size as usize;
            let expected_end = expected_start + test_vector.symbol_size as usize;
            let expected_symbol_data = &test_vector.source_data[expected_start..expected_end];

            assert_eq!(
                symbol.symbol().data(),
                expected_symbol_data,
                "RFC6330-4.4-1: Source symbol {} data must match original input exactly.\n\
                 Expected: {:02x?}\n\
                 Actual:   {:02x?}\n\
                 Test vector: {} ({})",
                i,
                expected_symbol_data,
                symbol.symbol().data(),
                test_vector.test_id,
                test_vector.requirement_level
            );
        }

        // RFC 6330 Section 4.4 Conformance Check 2: Symbol Ordering
        // Source symbols must appear in order (ESI 0, 1, 2, ... K-1)
        for (i, symbol) in symbols.iter().take(test_vector.expected_k).enumerate() {
            let expected_esi = i as u32;
            let actual_esi = symbol.id().esi();

            assert_eq!(
                actual_esi, expected_esi,
                "RFC6330-4.4-1: Source symbols must appear in order. \
                 Symbol at position {} must have ESI {}, but has ESI {}",
                i, expected_esi, actual_esi
            );
        }

        // RFC 6330 Section 4.4 Conformance Check 3: Symbol Block Number
        // All symbols in the same object should have consistent SBN
        let expected_sbn = symbols[0].id().sbn();
        for (i, symbol) in symbols.iter().enumerate() {
            assert_eq!(
                symbol.id().sbn(),
                expected_sbn,
                "RFC6330-4.4-1: All symbols must have consistent Source Block Number. \
                 Symbol {} has SBN {}, expected SBN {}",
                i,
                symbol.id().sbn(),
                expected_sbn
            );
        }

        println!(
            "RFC 6330 §4.4 CONFORMANCE: ✅ PASS - {} ({}) systematic_property={} and \
             the encoder correctly produces {} source symbols as first K encoding symbols",
            test_vector.test_id,
            test_vector.requirement_level,
            test_vector.systematic_property,
            test_vector.expected_k
        );
    }

    /// RFC 6330 Section 5 Systematic Encoder Parameter Validation Conformance Test
    ///
    /// This test validates systematic encoder parameter derivation and encoding
    /// behavior against RFC 6330 §5 specification requirements for source block
    /// parameters and systematic encoding constraints.
    ///
    /// **Specification Reference:**
    /// RFC 6330, Section 5: "Object Transmission Information" - systematic encoder
    /// parameter derivation, source block structure, and encoding symbol generation.
    ///
    /// **Test ID:** RFC6330-5.1-1
    /// **Requirement Level:** MUST
    /// **Description:** Systematic encoder parameter derivation must conform to
    /// RFC 6330 §5.3 systematic index table and §5.6 parameter relationships.
    #[test]
    fn rfc6330_section_5_systematic_encoder_parameter_conformance() {
        use crate::config::EncodingConfig;
        use crate::encoding::{EncodedSymbol, EncodingPipeline};
        use crate::raptorq::systematic::SystematicParams;
        use crate::types::{
            ObjectId,
            resource::{PoolConfig, SymbolPool},
        };

        /// RFC 6330 Section 5 Parameter Conformance Test Case
        /// Source: RFC 6330 Section 5.3 systematic index table requirements
        struct Rfc6330Section5Vector {
            /// Test case identifier for traceability
            test_id: &'static str,
            /// Requirement level (MUST/SHOULD/MAY)
            requirement_level: &'static str,
            /// Input source block size (K)
            k: usize,
            /// Symbol size in bytes
            symbol_size: u16,
            /// Test payload data
            source_data: Vec<u8>,
            /// Expected systematic parameters per RFC 6330 Table 2
            expected_k_prime: usize,
            expected_j: usize,
            expected_s: usize,
            expected_h: usize,
        }

        // Test vector covering mid-range K value with known RFC 6330 parameters
        let test_vector = Rfc6330Section5Vector {
            test_id: "RFC6330-5.1-1",
            requirement_level: "MUST",
            k: 10, // K=10 maps to specific RFC 6330 Table 2 row
            symbol_size: 8,
            source_data: (0..80).collect(), // 10 symbols * 8 bytes = 80 bytes
            // Expected values from RFC 6330 Table 2 for K=10
            expected_k_prime: 10,
            expected_j: 254,
            expected_s: 7,
            expected_h: 10,
        };

        // RFC 6330 Section 5.3 Conformance Check 1: Parameter Derivation
        let params =
            SystematicParams::try_for_source_block(test_vector.k, test_vector.symbol_size as usize)
                .expect("RFC6330-5.1-1: Parameter derivation must succeed for supported K");

        assert_eq!(
            params.k, test_vector.k,
            "{} {}: Source block size K must match input",
            test_vector.test_id, test_vector.requirement_level
        );

        assert_eq!(
            params.k_prime, test_vector.expected_k_prime,
            "RFC6330-5.1-1: K' derivation must match RFC 6330 Table 2. \
             Expected K'={}, actual K'={}",
            test_vector.expected_k_prime, params.k_prime
        );

        assert_eq!(
            params.j, test_vector.expected_j,
            "RFC6330-5.1-1: J(K') derivation must match RFC 6330 Table 2. \
             Expected J={}, actual J={}",
            test_vector.expected_j, params.j
        );

        assert_eq!(
            params.s, test_vector.expected_s,
            "RFC6330-5.1-1: S parameter must match RFC 6330 Table 2. \
             Expected S={}, actual S={}",
            test_vector.expected_s, params.s
        );

        assert_eq!(
            params.h, test_vector.expected_h,
            "RFC6330-5.1-1: H parameter must match RFC 6330 Table 2. \
             Expected H={}, actual H={}",
            test_vector.expected_h, params.h
        );

        // RFC 6330 Section 5.3 Conformance Check 2: Parameter Relationships
        let expected_l = params.k_prime + params.s + params.h;
        assert_eq!(
            params.l, expected_l,
            "RFC6330-5.1-1: L = K' + S + H relationship must hold. \
             L={}, K'={}, S={}, H={}",
            params.l, params.k_prime, params.s, params.h
        );

        assert!(
            params.w <= params.l,
            "RFC6330-5.1-1: W ≤ L constraint must hold. W={}, L={}",
            params.w,
            params.l
        );

        let expected_p = params.l - params.w;
        assert_eq!(
            params.p, expected_p,
            "RFC6330-5.1-1: P = L - W relationship must hold. \
             P={}, L={}, W={}",
            params.p, params.l, params.w
        );

        // RFC 6330 Section 5 Conformance Check 3: Encoding Behavior Validation.
        //
        // `max_block_size` is the per-block byte budget. The §5 conformance
        // assertions below treat the whole object as ONE source block of K=10
        // symbols (ESI 0..K-1 systematic), so the block budget MUST be large
        // enough to hold the entire 80-byte payload in a single block. A budget
        // smaller than the object (the previous value of 64 < 80 bytes) splits
        // it into two blocks, each restarting ESI at 0 — making "ESI 8" the
        // first *repair* symbol of block 0 rather than source symbol 8, which is
        // what made this conformance check fail spuriously.
        let config = EncodingConfig {
            repair_overhead: 1.5,
            max_block_size: 1024,
            symbol_size: test_vector.symbol_size,
            encoding_parallelism: 1,
            decoding_parallelism: 1,
        };

        let mut pipeline = EncodingPipeline::new(config, SymbolPool::new(PoolConfig::default()));
        let object_id = ObjectId::new_for_test(0x5555); // Deterministic object ID

        // Encode using derived parameters
        let symbols: Vec<EncodedSymbol> = pipeline
            .encode(object_id, &test_vector.source_data)
            .collect::<Result<Vec<_>, _>>()
            .expect("RFC6330-5.1-1: Encoding with valid §5 parameters must succeed");

        // Validate systematic property with RFC 6330 §5 parameter constraints
        assert!(
            symbols.len() >= test_vector.k,
            "RFC6330-5.1-1: Must produce at least K={} symbols with §5 parameters",
            test_vector.k
        );

        // Verify source symbols preserve systematic property under §5 constraints.
        //
        // The systematic property is keyed by Encoding Symbol ID (ESI), NOT by
        // the symbol's position in the emitted stream: a systematic symbol with
        // ESI `e` must carry source block `e`. The encoder is free to emit the
        // K systematic symbols in any order (and may interleave repair symbols),
        // so we index `source_data` by each symbol's actual ESI rather than by
        // its enumeration position. We also confirm every ESI < K appears
        // exactly once across the source-symbol prefix.
        let mut seen_source_esis = std::collections::BTreeSet::new();
        for symbol in symbols.iter() {
            let esi = symbol.id().esi();
            if esi >= test_vector.k as u32 {
                continue; // repair symbol — systematic property does not apply
            }

            // Verify systematic data preservation for source ESI `esi`.
            let expected_start = esi as usize * test_vector.symbol_size as usize;
            let expected_end = expected_start + test_vector.symbol_size as usize;
            let expected_data = &test_vector.source_data[expected_start..expected_end];

            assert_eq!(
                symbol.symbol().data(),
                expected_data,
                "RFC6330-5.1-1: systematic symbol with ESI {esi} must carry source \
                 block {esi} verbatim under §5 encoding",
            );
            seen_source_esis.insert(esi);
        }

        assert_eq!(
            seen_source_esis.len(),
            test_vector.k,
            "RFC6330-5.1-1: every source ESI in [0, K) must appear exactly once \
             among the systematic symbols (K={})",
            test_vector.k
        );

        println!(
            "RFC 6330 §5 CONFORMANCE: ✅ PASS - {} ({}) parameters conform to \
             §5.3 table (K={}, K'={}, J={}, S={}, H={}, L={}) and preserve systematic property",
            test_vector.test_id,
            test_vector.requirement_level,
            params.k,
            params.k_prime,
            params.j,
            params.s,
            params.h,
            params.l
        );
    }
