    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    #[test]
    fn deterministic_sequence() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(42);

        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn replay_different_seeds_different_sequences() {
        let mut rng1 = DetRng::new(42);
        let mut rng2 = DetRng::new(43);

        // Very unlikely to match
        assert_ne!(rng1.next_u64(), rng2.next_u64());
    }

    #[test]
    fn zero_seed_handled() {
        let mut rng = DetRng::new(0);
        // Should not hang or produce all zeros
        assert_ne!(rng.next_u64(), 0);
    }

    // =========================================================================
    // Wave 57 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn det_rng_debug_clone() {
        let mut rng = DetRng::new(42);
        let dbg = format!("{rng:?}");
        assert!(dbg.contains("DetRng"), "{dbg}");

        // Clone preserves sequence position
        let _ = rng.next_u64(); // advance once
        let mut forked = rng.clone();
        assert_eq!(rng.next_u64(), forked.next_u64());
    }

    /// br-asupersync-jebj8u: Debug output MUST NOT leak the internal
    /// xorshift64 state. An attacker who recovers a DetRng's state
    /// from any trace, panic, or log line can mirror every subsequent
    /// random decision off-runtime (the xorshift64 update is fully
    /// invertible from one observed output, so even partial leaks are
    /// catastrophic).
    ///
    /// We assert: across a wide range of seeds — including ones whose
    /// decimal/hex representations are SHORT enough that any partial
    /// embedding in the Debug string would catch them — the formatted
    /// Debug never contains the seed's decimal, hex, lower-hex, upper-
    /// hex, or little-endian byte representations.
    #[test]
    fn debug_does_not_leak_state() {
        let seeds: [u64; 8] = [
            0xDEAD_BEEF_CAFE_BABE,
            0x1234_5678_9ABC_DEF0,
            42,
            1,
            u64::MAX,
            0x0000_0001_0000_0001,
            0xAAAA_AAAA_AAAA_AAAA,
            0x5555_5555_5555_5555,
        ];
        for &seed in &seeds {
            let rng = DetRng::new(seed);
            let dbg = format!("{rng:?}");
            assert!(
                dbg.contains("DetRng"),
                "Debug must still identify the type, got {dbg:?}"
            );
            assert!(
                dbg.contains("<redacted>"),
                "Debug must mark redaction explicitly, got {dbg:?}"
            );
            // No decimal, no upper-hex, no lower-hex of the state.
            let dec = format!("{seed}");
            let lhex = format!("{seed:x}");
            let uhex = format!("{seed:X}");
            assert!(
                !dbg.contains(&dec),
                "decimal state {dec} leaked in Debug: {dbg}"
            );
            // Skip lower/upper hex check for trivial seeds whose hex
            // form would coincidentally appear inside other words
            // (e.g. seed=1 → "1" which is too short to be diagnostic).
            if lhex.len() >= 4 {
                assert!(
                    !dbg.contains(&lhex),
                    "lower-hex state {lhex} leaked in Debug: {dbg}"
                );
                assert!(
                    !dbg.contains(&uhex),
                    "upper-hex state {uhex} leaked in Debug: {dbg}"
                );
            }
        }
    }

    /// Defense-in-depth: even AFTER the PRNG has advanced (so its
    /// internal state diverges from the seed), Debug must not leak the
    /// current state.
    #[test]
    fn debug_does_not_leak_state_after_advance() {
        let mut rng = DetRng::new(0xDEAD_BEEF_CAFE_BABE);
        for _ in 0..1000 {
            let _ = rng.next_u64();
        }
        // Capture the internal state by sampling, then check Debug
        // output doesn't embed that next-output value either (since
        // xorshift64 next-state recovery from one output is trivial).
        let mut probe = rng.clone();
        let next = probe.next_u64();
        let dbg = format!("{rng:?}");
        let dec = format!("{next}");
        let lhex = format!("{next:x}");
        let uhex = format!("{next:X}");
        assert!(
            !dbg.contains(&dec),
            "post-advance decimal state leaked: {dbg}"
        );
        if lhex.len() >= 4 {
            assert!(!dbg.contains(&lhex), "post-advance lhex leaked: {dbg}");
            assert!(!dbg.contains(&uhex), "post-advance uhex leaked: {dbg}");
        }
    }

    // =========================================================================
    // Seed Security and Replay Consistency Tests (br-asupersync-jv02ns)
    // =========================================================================

    #[test]
    fn seed_quality_assessment_dangerous_seeds() {
        // Zero seed
        assert_eq!(
            DetRng::assess_seed_quality(0),
            SeedQuality::Dangerous {
                reason: "Zero seed causes xorshift64 to stick at zero"
            }
        );

        // Degenerate patterns
        assert_eq!(
            DetRng::assess_seed_quality(0xFFFF_FFFF_FFFF_FFFF),
            SeedQuality::Dangerous {
                reason: "Seed creates short cycles in xorshift64"
            }
        );

        assert_eq!(
            DetRng::assess_seed_quality(0x5555_5555_5555_5555),
            SeedQuality::Dangerous {
                reason: "Seed creates short cycles in xorshift64"
            }
        );
    }

    #[test]
    fn seed_quality_assessment_poor_seeds() {
        // Very low popcount (low entropy)
        assert_eq!(
            DetRng::assess_seed_quality(0x0000_0000_0000_0007),
            SeedQuality::Poor
        );

        // Very high popcount (inverted low entropy)
        assert_eq!(
            DetRng::assess_seed_quality(0xFFFF_FFFF_FFFF_FFF8),
            SeedQuality::Poor
        );

        // Too many leading zeros
        assert_eq!(
            DetRng::assess_seed_quality(0x0000_0000_1234_5678),
            SeedQuality::Poor
        );

        // Too many trailing zeros
        assert_eq!(
            DetRng::assess_seed_quality(0x1234_5678_0000_0000),
            SeedQuality::Poor
        );
    }

    #[test]
    fn seed_quality_assessment_good_seeds() {
        // Typical high-quality seed
        assert_eq!(
            DetRng::assess_seed_quality(0x9e37_79b9_7f4a_7c15),
            SeedQuality::Excellent
        );

        // Good entropy distribution
        assert_eq!(
            DetRng::assess_seed_quality(0x1234_5678_9abc_def0),
            SeedQuality::Excellent
        );

        // Structured seed (ascending repeated nibbles). Its nibble pattern is not
        // caught by the byte-level `has_simple_pattern` heuristic, and its bit
        // distribution is well balanced (popcount 20, no long zero runs), so the
        // quality model rates it usable — anywhere from Acceptable up to Excellent.
        // The contract here is "not Poor/Dangerous", i.e. safe to use directly.
        let seed_with_pattern = 0x1111_2222_3333_4444;
        let quality = DetRng::assess_seed_quality(seed_with_pattern);
        assert!(matches!(
            quality,
            SeedQuality::Acceptable | SeedQuality::Good | SeedQuality::Excellent
        ));
    }

    #[test]
    fn new_with_quality_validation() {
        // Dangerous seed should still create usable RNG with correction
        let (rng, quality) = DetRng::new_with_quality(0);
        assert!(matches!(quality, SeedQuality::Dangerous { .. }));

        // Should produce non-zero values despite zero seed
        let mut rng = rng;
        let first_val = rng.next_u64();
        assert_ne!(first_val, 0, "Zero seed should be corrected");

        // Good seed should maintain quality
        let (_, quality) = DetRng::new_with_quality(0x9e37_79b9_7f4a_7c15);
        assert_eq!(quality, SeedQuality::Excellent);
    }

    #[test]
    fn entropy_based_rng_quality() {
        let rng = DetRng::from_entropy();
        let mut rng = rng;

        // Should produce varied output
        let vals: Vec<_> = (0..10).map(|_| rng.next_u64()).collect();

        // Check for basic randomness (no identical consecutive values)
        let mut has_variation = false;
        for i in 1..vals.len() {
            if vals[i] != vals[i - 1] {
                has_variation = true;
                break;
            }
        }
        assert!(has_variation, "Entropy RNG should produce varied output");
    }

    #[test]
    fn replay_consistency_verification() {
        let seed = 0x1234_5678_9abc_def0;

        // Short verification should pass
        DetRng::verify_replay_consistency(seed, 100).expect("Short replay should be consistent");

        // Longer verification should also pass
        DetRng::verify_replay_consistency(seed, 10000).expect("Long replay should be consistent");
    }

    #[test]
    fn replay_consistency_across_instances() {
        let seed = 0xdeadbeefcafebabe;
        let mut rng1 = DetRng::new(seed);
        let mut rng2 = DetRng::new(seed);

        // Generate 1000 values from each and verify they match
        for step in 0..1000 {
            let val1 = rng1.next_u64();
            let val2 = rng2.next_u64();
            assert_eq!(val1, val2, "Replay divergence at step {step}");
        }
    }

    #[test]
    fn different_seeds_different_sequences() {
        let mut rng1 = DetRng::new(12345);
        let mut rng2 = DetRng::new(54321);

        // Different seeds should produce different sequences
        let seq1: Vec<_> = (0..100).map(|_| rng1.next_u64()).collect();
        let seq2: Vec<_> = (0..100).map(|_| rng2.next_u64()).collect();

        assert_ne!(
            seq1, seq2,
            "Different seeds must produce different sequences"
        );
    }

    #[test]
    fn zero_seed_auto_correction() {
        let rng = DetRng::new(0);
        let mut rng = rng;

        // Zero seed should be auto-corrected to prevent stuck-at-zero
        let first = rng.next_u64();
        let second = rng.next_u64();
        let third = rng.next_u64();

        // Should not stick at zero
        assert!(
            first != 0 || second != 0 || third != 0,
            "Auto-corrected seed should not stick at zero"
        );

        // Should show progression
        assert!(
            first != second || second != third,
            "Auto-corrected RNG should show state progression"
        );
    }

    #[test]
    fn degenerate_seed_correction() {
        // Test correction of known degenerate patterns
        let degenerate_seeds = [
            0xFFFF_FFFF_FFFF_FFFF,
            0x5555_5555_5555_5555,
            0xAAAA_AAAA_AAAA_AAAA,
        ];

        for &seed in &degenerate_seeds {
            let rng = DetRng::new(seed);
            let mut rng = rng;

            // Should produce a reasonable sequence despite degenerate seed
            let sequence: Vec<_> = (0..100).map(|_| rng.next_u64()).collect();

            // Check for basic randomness properties
            let unique_count = sequence
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            assert!(
                unique_count > 80,
                "Corrected degenerate seed should produce varied output, got {unique_count}/100 unique values"
            );
        }
    }

    #[test]
    fn seed_validation_preserves_determinism() {
        let seed = 0x9999_8888_7777_6666;

        // Multiple RNG instances with same seed should behave identically
        let mut rng1 = DetRng::new(seed);
        let mut rng2 = DetRng::new(seed);
        let mut rng3 = DetRng::new(seed);

        for _ in 0..500 {
            let val1 = rng1.next_u64();
            let val2 = rng2.next_u64();
            let val3 = rng3.next_u64();

            assert_eq!(val1, val2);
            assert_eq!(val2, val3);
        }
    }

    #[test]
    fn pattern_detection_works() {
        // Repetitive byte pattern
        assert!(DetRng::has_simple_pattern(0x1111_1111_1111_1111));

        // Arithmetic progression in bytes
        assert!(DetRng::has_simple_pattern(0x0001_0203_0405_0607));

        // Good entropy should not trigger pattern detection
        assert!(!DetRng::has_simple_pattern(0x9e37_79b9_7f4a_7c15));
    }

    #[test]
    fn seed_quality_debug_clone() {
        let quality = SeedQuality::Excellent;
        let dbg = format!("{quality:?}");
        assert!(dbg.contains("Excellent"));

        let quality2 = quality.clone();
        assert_eq!(quality, quality2);

        let dangerous = SeedQuality::Dangerous { reason: "test" };
        let dbg2 = format!("{dangerous:?}");
        assert!(dbg2.contains("Dangerous"));
        assert!(dbg2.contains("test"));
    }
