    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    fn failure_context(
        scenario_id: &str,
        seed: u64,
        parameter_set: &str,
        replay_ref: &str,
    ) -> String {
        format!(
            "scenario_id={scenario_id} seed={seed} parameter_set={parameter_set} replay_ref={replay_ref}"
        )
    }

    fn deterministic_bytes(seed: u64, len: usize, salt: u64) -> Vec<u8> {
        let mut state = seed ^ salt ^ ((len as u64) << 32);
        (0..len)
            .map(|index| {
                state = state
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(0xBF58_476D_1CE4_E5B9 ^ index as u64);
                (state.rotate_left((index % 64) as u32) >> 56) as u8
            })
            .collect()
    }

    fn profile_pack_metadata_fixture(
        profile_pack: Gf256ProfilePackId,
    ) -> &'static Gf256ProfilePackMetadata {
        profile_pack_metadata(profile_pack)
            .expect("profile pack fixture should exist in deterministic catalog")
    }

    fn x86_profile_pack_policy_fixture() -> DualKernelPolicy {
        let metadata = profile_pack_metadata_fixture(Gf256ProfilePackId::X86Avx2BalancedV1);
        DualKernelPolicy {
            profile_pack: metadata.profile_pack,
            architecture_class: metadata.architecture_class,
            tuning_corpus_id: metadata.tuning_corpus_id,
            selected_tuning_candidate_id: metadata.selected_tuning_candidate_id,
            rejected_tuning_candidate_ids: metadata.rejected_tuning_candidate_ids,
            fallback_reason: None,
            rejected_candidates: REJECTED_PROFILE_SELECTED_X86_AVX2,
            replay_pointer: metadata.replay_pointer,
            command_bundle: metadata.command_bundle,
            mode: DualKernelOverride::Auto,
            mode_fallback_reason: None,
            override_mask: DualKernelOverrideMask::empty(),
            mul_min_total: metadata.mul_min_total,
            mul_max_total: metadata.mul_max_total,
            addmul_min_total: metadata.addmul_min_total,
            addmul_max_total: metadata.addmul_max_total,
            addmul_min_lane: metadata.addmul_min_lane,
            max_lane_ratio: metadata.max_lane_ratio,
        }
    }

    fn policy_fixture_from_selection(selection: ProfilePackSelection) -> DualKernelPolicy {
        let metadata = profile_pack_metadata_fixture(selection.profile_pack);
        DualKernelPolicy {
            profile_pack: metadata.profile_pack,
            architecture_class: selection.architecture_class,
            tuning_corpus_id: metadata.tuning_corpus_id,
            selected_tuning_candidate_id: metadata.selected_tuning_candidate_id,
            rejected_tuning_candidate_ids: metadata.rejected_tuning_candidate_ids,
            fallback_reason: selection.fallback_reason,
            rejected_candidates: selection.rejected_candidates,
            replay_pointer: metadata.replay_pointer,
            command_bundle: metadata.command_bundle,
            mode: DualKernelOverride::Auto,
            mode_fallback_reason: None,
            override_mask: DualKernelOverrideMask::empty(),
            mul_min_total: metadata.mul_min_total,
            mul_max_total: metadata.mul_max_total,
            addmul_min_total: metadata.addmul_min_total,
            addmul_max_total: metadata.addmul_max_total,
            addmul_min_lane: metadata.addmul_min_lane,
            max_lane_ratio: metadata.max_lane_ratio,
        }
    }

    const GF256_ENV_KEYS: [&str; 8] = [
        "ASUPERSYNC_GF256_DUAL_POLICY",
        "ASUPERSYNC_GF256_PROFILE_PACK",
        "ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL",
        "ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL",
        "ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL",
        "ASUPERSYNC_GF256_DUAL_ADDMUL_MAX_TOTAL",
        "ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_LANE",
        "ASUPERSYNC_GF256_DUAL_MAX_LANE_RATIO",
    ];

    #[allow(unsafe_code)]
    fn with_clean_gf256_env<F, R>(f: F) -> R
    where
        F: FnOnce() -> R,
    {
        let _guard = crate::test_utils::env_lock();
        let saved = GF256_ENV_KEYS
            .iter()
            .map(|key| (*key, std::env::var(key).ok()))
            .collect::<Vec<_>>();

        for key in GF256_ENV_KEYS {
            // SAFETY: tests serialize environment mutation with env_lock.
            unsafe { std::env::remove_var(key) };
        }

        let result = f();

        for (key, value) in saved {
            match value {
                Some(value) => {
                    // SAFETY: tests serialize environment mutation with env_lock.
                    unsafe { std::env::set_var(key, value) };
                }
                None => {
                    // SAFETY: tests serialize environment mutation with env_lock.
                    unsafe { std::env::remove_var(key) };
                }
            }
        }

        result
    }

    #[allow(unsafe_code)]
    fn with_gf256_env<F, R>(key: &str, value: &str, f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_gf256_env(|| {
            // SAFETY: tests serialize environment mutation with env_lock.
            unsafe { std::env::set_var(key, value) };
            f()
        })
    }

    #[allow(unsafe_code)]
    fn with_gf256_envs<F, R>(vars: &[(&str, &str)], f: F) -> R
    where
        F: FnOnce() -> R,
    {
        with_clean_gf256_env(|| {
            for (key, value) in vars {
                // SAFETY: tests serialize environment mutation with env_lock.
                unsafe { std::env::set_var(key, value) };
            }
            f()
        })
    }

    fn unsupported_profile_pack_env_value_for_kernel(kernel: Gf256Kernel) -> &'static str {
        match architecture_class_for_kernel(kernel) {
            Gf256ArchitectureClass::GenericScalar | Gf256ArchitectureClass::Aarch64Neon => {
                "x86-avx2-balanced-v1"
            }
            Gf256ArchitectureClass::X86Avx2 => "aarch64-neon-balanced-v1",
        }
    }

    fn default_profile_metadata_for_kernel(
        kernel: Gf256Kernel,
    ) -> &'static Gf256ProfilePackMetadata {
        profile_pack_metadata_fixture(default_profile_pack_for_arch(
            architecture_class_for_kernel(kernel),
        ))
    }

    fn assert_supported_profile_request_scrubs_provenance_while_preserving_profile_truth(
        policy: &DualKernelPolicy,
        snapshot: &DualKernelPolicySnapshot,
        manifest: &Gf256ProfilePackManifestSnapshot,
        kernel: Gf256Kernel,
    ) {
        let host_architecture = architecture_class_for_kernel(kernel);
        let expected_profile =
            profile_pack_metadata_fixture(Gf256ProfilePackId::ScalarConservativeV1);

        assert_eq!(
            policy.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(policy.architecture_class, host_architecture);
        assert_eq!(policy.fallback_reason, None);
        assert!(policy.override_mask.profile_pack_env_requested());
        assert!(!policy_uses_canonical_selection_contract(policy));
        assert_eq!(policy.rejected_candidates, REJECTED_PROFILE_SELECTED_SCALAR);
        assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
        assert_eq!(
            policy.selected_tuning_candidate_id,
            MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
        );
        assert!(policy.rejected_tuning_candidate_ids.is_empty());
        assert_eq!(policy.replay_pointer, MANUAL_OVERRIDE_REPLAY_POINTER);
        assert_eq!(policy.command_bundle, MANUAL_OVERRIDE_COMMAND_BUNDLE);
        assert_eq!(
            tuning_candidate_metadata(policy.selected_tuning_candidate_id),
            None
        );

        assert_eq!(
            snapshot.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(snapshot.architecture_class, host_architecture);
        assert_eq!(snapshot.fallback_reason, None);
        assert_eq!(
            snapshot.selected_tuning_candidate_id,
            MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
        );
        assert!(snapshot.rejected_tuning_candidate_ids.is_empty());
        assert_eq!(
            snapshot.rejected_candidates,
            REJECTED_PROFILE_SELECTED_SCALAR
        );
        assert_eq!(
            snapshot.decision_artifact_id,
            MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
        );
        assert_eq!(snapshot.decision_role, MANUAL_OVERRIDE_DECISION_ROLE);
        assert_eq!(
            snapshot.decision_evidence_status,
            MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
        );

        assert_eq!(manifest.active_policy, *snapshot);
        assert_eq!(
            manifest.active_profile_metadata.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            manifest.active_profile_metadata.architecture_class,
            expected_profile.architecture_class
        );
        assert_eq!(
            manifest.active_profile_metadata.tuning_corpus_id,
            MANUAL_OVERRIDE_TUNING_CORPUS_ID
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .selected_tuning_candidate_id,
            MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
        );
        assert_eq!(
            manifest.active_profile_metadata.decision_artifact_id,
            MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
        );
        assert_eq!(
            manifest.active_profile_metadata.decision_role,
            MANUAL_OVERRIDE_DECISION_ROLE
        );
        assert_eq!(
            manifest.active_profile_metadata.decision_evidence_status,
            MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
        );
        assert_eq!(
            manifest.active_profile_metadata.selected_candidate_summary,
            MANUAL_OVERRIDE_SELECTED_CANDIDATE_SUMMARY
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .rejected_candidate_set_summary,
            MANUAL_OVERRIDE_REJECTED_CANDIDATE_SET_SUMMARY
        );
        assert_eq!(manifest.active_selected_tuning_candidate, None);
    }

    // -- Table sanity --

    #[test]
    fn exp_table_generates_all_nonzero() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "exp_table_generates_all_nonzero",
            replay_ref,
        );
        let mut visited = [false; 256];
        for (i, &v) in EXP.iter().enumerate().take(255) {
            assert!(!visited[v as usize], "duplicate EXP[{i}] = {v}; {context}");
            visited[v as usize] = true;
        }
        // Zero should not appear in EXP[0..255]
        assert!(
            !visited[0],
            "zero should not be generated by EXP table; {context}"
        );
    }

    #[test]
    fn log_exp_roundtrip() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "log_exp_roundtrip", replay_ref);
        for a in 1u16..=255 {
            let log_a = LOG[a as usize];
            assert_eq!(
                EXP[log_a as usize], a as u8,
                "roundtrip failed for {a}; {context}"
            );
        }
    }

    #[test]
    fn exp_wraps_at_255() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "exp_wraps_at_255", replay_ref);
        // EXP[i] == EXP[i + 255] for i in 0..255
        for i in 0..255 {
            assert_eq!(EXP[i], EXP[i + 255], "mirror mismatch at {i}; {context}");
        }
    }

    // -- Field axioms --

    #[test]
    fn additive_identity() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "additive_identity", replay_ref);
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa + Gf256::ZERO, fa, "{context}");
            assert_eq!(Gf256::ZERO + fa, fa, "{context}");
        }
    }

    #[test]
    fn additive_inverse() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "additive_inverse", replay_ref);
        // In GF(2^n), every element is its own additive inverse.
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa + fa, Gf256::ZERO, "{context}");
        }
    }

    #[test]
    fn multiplicative_identity() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplicative_identity",
            replay_ref,
        );
        for a in 0u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa * Gf256::ONE, fa, "{context}");
            assert_eq!(Gf256::ONE * fa, fa, "{context}");
        }
    }

    #[test]
    fn multiplicative_inverse_all_nonzero() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplicative_inverse_all_nonzero",
            replay_ref,
        );
        for a in 1u8..=255 {
            let fa = Gf256(a);
            let inv = fa.inv();
            assert_eq!(
                fa * inv,
                Gf256::ONE,
                "a={a}, inv={}, product={}; {context}",
                inv.0,
                (fa * inv).0
            );
            assert_eq!(inv * fa, Gf256::ONE, "{context}");
        }
    }

    #[test]
    #[should_panic(expected = "cannot invert zero")]
    fn inverse_of_zero_panics() {
        let _ = Gf256::ZERO.inv();
    }

    #[test]
    fn multiplication_commutative() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplication_commutative",
            replay_ref,
        );
        // Spot check: all pairs would be 65k, so test a representative sample.
        for a in (0u8..=255).step_by(7) {
            for b in (0u8..=255).step_by(11) {
                let fa = Gf256(a);
                let fb = Gf256(b);
                assert_eq!(
                    fa * fb,
                    fb * fa,
                    "commutativity failed: {a} * {b}; {context}"
                );
            }
        }
    }

    #[test]
    fn multiplication_associative() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "multiplication_associative",
            replay_ref,
        );
        let triples = [
            (3u8, 7, 11),
            (0, 100, 200),
            (1, 255, 128),
            (37, 42, 199),
            (255, 255, 255),
        ];
        for (a, b, c) in triples {
            let fa = Gf256(a);
            let fb = Gf256(b);
            let fc = Gf256(c);
            assert_eq!(
                (fa * fb) * fc,
                fa * (fb * fc),
                "associativity failed: {a} * {b} * {c}; {context}"
            );
        }
    }

    #[test]
    fn distributive_law() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "distributive_law", replay_ref);
        let triples = [(3u8, 7, 11), (100, 200, 50), (255, 1, 0), (37, 42, 199)];
        for (a, b, c) in triples {
            let fa = Gf256(a);
            let fb = Gf256(b);
            let fc = Gf256(c);
            assert_eq!(
                fa * (fb + fc),
                fa * fb + fa * fc,
                "distributive law failed: {a} * ({b} + {c}); {context}"
            );
        }
    }

    #[test]
    fn zero_annihilates() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "zero_annihilates", replay_ref);
        for a in 0u8..=255 {
            assert_eq!(Gf256(a) * Gf256::ZERO, Gf256::ZERO, "{context}");
        }
    }

    // -- Exponentiation --

    #[test]
    fn pow_basic() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "pow_basic", replay_ref);
        let g = Gf256::ALPHA; // generator = 2
        assert_eq!(g.pow(0), Gf256::ONE, "{context}");
        assert_eq!(g.pow(1), g, "{context}");
        // g^8 should equal the reduction of x^8 = x^4 + x^3 + x^2 + 1 = 0x1D = 29
        assert_eq!(g.pow(8), Gf256(POLY as u8), "{context}");
    }

    #[test]
    fn pow_fermats_little() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "pow_fermats_little", replay_ref);
        // a^255 = 1 for all nonzero a in GF(256)
        for a in 1u8..=255 {
            assert_eq!(
                Gf256(a).pow(255),
                Gf256::ONE,
                "Fermat's little theorem failed for {a}; {context}"
            );
        }
    }

    // -- Division --

    #[test]
    fn division_is_mul_inverse() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "division_is_mul_inverse",
            replay_ref,
        );
        let pairs = [(6u8, 3), (255, 1), (100, 200), (42, 37)];
        for (a, b) in pairs {
            let fa = Gf256(a);
            let fb = Gf256(b);
            assert_eq!(fa / fb, fa * fb.inv(), "{context}");
        }
    }

    #[test]
    fn div_self_is_one() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "div_self_is_one", replay_ref);
        for a in 1u8..=255 {
            let fa = Gf256(a);
            assert_eq!(fa / fa, Gf256::ONE, "{context}");
        }
    }

    // -- Bulk slice operations --

    #[test]
    fn add_slice_xors() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "add_slice_xors", replay_ref);
        let mut dst = vec![0x00, 0xFF, 0xAA];
        let src = vec![0xFF, 0xFF, 0x55];
        gf256_add_slice(&mut dst, &src);
        assert_eq!(dst, vec![0xFF, 0x00, 0xFF], "{context}");
    }

    #[test]
    fn mul_slice_by_one_is_noop() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slice_by_one_is_noop",
            replay_ref,
        );
        let original = vec![1, 2, 3, 100, 255];
        let mut data = original.clone();
        gf256_mul_slice(&mut data, Gf256::ONE);
        assert_eq!(data, original, "{context}");
    }

    #[test]
    fn mul_slice_by_zero_clears() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slice_by_zero_clears",
            replay_ref,
        );
        let mut data = vec![1, 2, 3, 100, 255];
        gf256_mul_slice(&mut data, Gf256::ZERO);
        assert_eq!(data, vec![0, 0, 0, 0, 0], "{context}");
    }

    #[test]
    fn mul_slice_large_inputs() {
        // Exercise the `mul_with_table_wide` path (>= MUL_TABLE_THRESHOLD bytes).
        const LEN: usize = 64 + 7; // 71 bytes: crosses the 64-byte threshold
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slice_large_inputs",
            replay_ref,
        );
        let original: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(37)) as u8).collect();
        let c = Gf256(13);
        let expected: Vec<u8> = original.iter().map(|&s| (Gf256(s) * c).0).collect();
        let mut data = original;
        gf256_mul_slice(&mut data, c);
        assert_eq!(data, expected, "{context}");
    }

    #[test]
    fn addmul_slice_correctness() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "addmul_slice_correctness",
            replay_ref,
        );
        let src = vec![1u8, 2, 3, 0, 255];
        let c = Gf256(7);
        let mut dst = vec![0u8; 5];
        gf256_addmul_slice(&mut dst, &src, c);
        // Verify element-wise
        for i in 0..5 {
            assert_eq!(dst[i], (Gf256(src[i]) * c).0, "{context}");
        }
    }

    #[test]
    fn addmul_accumulates() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context("RQ-U-GF256-ALGEBRA", seed, "addmul_accumulates", replay_ref);
        let src = vec![10u8, 20, 30];
        let c = Gf256(5);
        let mut dst = vec![1u8, 2, 3]; // nonzero initial
        let expected: Vec<u8> = dst
            .iter()
            .zip(src.iter())
            .map(|(&d, &s)| d ^ (Gf256(s) * c).0)
            .collect();
        gf256_addmul_slice(&mut dst, &src, c);
        assert_eq!(dst, expected, "{context}");
    }

    #[test]
    fn addmul_slice_large_inputs() {
        const LEN: usize = 64 + 7;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "addmul_slice_large_inputs",
            replay_ref,
        );
        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(37)) as u8).collect();
        let c = Gf256(13);
        let mut dst = vec![0u8; LEN];
        let expected: Vec<u8> = src.iter().map(|&s| (Gf256(s) * c).0).collect();
        gf256_addmul_slice(&mut dst, &src, c);
        assert_eq!(dst, expected, "{context}");
    }

    #[test]
    fn mul_slices2_matches_two_independent_mul_slice_calls() {
        const LEN_A: usize = 73;
        const LEN_B: usize = 131;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slices2_matches_two_independent_mul_slice_calls",
            replay_ref,
        );
        let c = Gf256(29);

        let mut a_fused: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let mut b_fused: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(11)) as u8).collect();
        let mut a_seq = a_fused.clone();
        let mut b_seq = b_fused.clone();

        gf256_mul_slices2(&mut a_fused, &mut b_fused, c);
        gf256_mul_slice(&mut a_seq, c);
        gf256_mul_slice(&mut b_seq, c);

        assert_eq!(a_fused, a_seq, "{context}");
        assert_eq!(b_fused, b_seq, "{context}");
    }

    #[test]
    fn mul_slices2_handles_empty_and_asymmetric_lane_pairs() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let c = Gf256(173);

        for &(len_a, len_b, scenario) in &[
            (0usize, 65usize, "left-empty"),
            (65usize, 0usize, "right-empty"),
            (1usize, 95usize, "left-byte-right-wide-plus-byte"),
            (95usize, 1usize, "left-wide-plus-byte-right-byte"),
            (31usize, 95usize, "left-subwide-right-wide"),
            (95usize, 31usize, "left-wide-right-subwide"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "mul_slices2_handles_empty_and_asymmetric_lane_pairs",
                replay_ref,
            );
            let mut actual_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(7)) as u8).collect();
            let mut actual_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(11)) as u8).collect();
            let mut expected_a = actual_a.clone();
            let mut expected_b = actual_b.clone();

            gf256_mul_slices2(&mut actual_a, &mut actual_b, c);
            gf256_mul_slice(&mut expected_a, c);
            gf256_mul_slice(&mut expected_b, c);

            assert_eq!(actual_a, expected_a, "{scenario}: {context}");
            assert_eq!(actual_b, expected_b, "{scenario}: {context}");
        }
    }

    #[test]
    fn mul_slices2_shorter_lane_below_simd_width_matches_two_independent_mul_slice_calls() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let c = Gf256(173);

        for &(len_a, len_b, scenario) in &[
            (7usize, 95usize, "left-short-tiny"),
            (95usize, 7usize, "right-short-tiny"),
            (31usize, 95usize, "left-short-avx2-window"),
            (95usize, 31usize, "right-short-avx2-window"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "mul_slices2_shorter_lane_below_simd_width_matches_two_independent_mul_slice_calls",
                replay_ref,
            );
            let mut actual_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(7)) as u8).collect();
            let mut actual_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(11)) as u8).collect();
            let mut expected_a = actual_a.clone();
            let mut expected_b = actual_b.clone();

            gf256_mul_slices2(&mut actual_a, &mut actual_b, c);
            gf256_mul_slice(&mut expected_a, c);
            gf256_mul_slice(&mut expected_b, c);

            assert_eq!(actual_a, expected_a, "{scenario}: {context}");
            assert_eq!(actual_b, expected_b, "{scenario}: {context}");
        }
    }

    #[test]
    fn addmul_slices2_matches_two_independent_addmul_slice_calls() {
        const LEN_A: usize = 79;
        const LEN_B: usize = 149;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "addmul_slices2_matches_two_independent_addmul_slice_calls",
            replay_ref,
        );
        let c = Gf256(71);

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut accum_left: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut accum_right: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_left = accum_left.clone();
        let mut expected_right = accum_right.clone();

        gf256_addmul_slices2(&mut accum_left, &src_a, &mut accum_right, &src_b, c);
        gf256_addmul_slice(&mut expected_left, &src_a, c);
        gf256_addmul_slice(&mut expected_right, &src_b, c);

        assert_eq!(accum_left, expected_left, "{context}");
        assert_eq!(accum_right, expected_right, "{context}");
    }

    #[test]
    fn addmul_slices2_handles_empty_and_asymmetric_lane_pairs() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let c = Gf256(181);

        for &(len_a, len_b, scenario) in &[
            (0usize, 65usize, "left-empty"),
            (65usize, 0usize, "right-empty"),
            (1usize, 95usize, "left-byte-right-wide-plus-byte"),
            (95usize, 1usize, "left-wide-plus-byte-right-byte"),
            (31usize, 95usize, "left-subwide-right-wide"),
            (95usize, 31usize, "left-wide-right-subwide"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "addmul_slices2_handles_empty_and_asymmetric_lane_pairs",
                replay_ref,
            );
            let src_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(13)) as u8).collect();
            let src_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(17)) as u8).collect();
            let mut actual_left: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(19)) as u8).collect();
            let mut actual_right: Vec<u8> =
                (0..len_b).map(|i| (i.wrapping_mul(23)) as u8).collect();
            let mut expected_left = actual_left.clone();
            let mut expected_right = actual_right.clone();

            gf256_addmul_slices2(&mut actual_left, &src_a, &mut actual_right, &src_b, c);
            gf256_addmul_slice(&mut expected_left, &src_a, c);
            gf256_addmul_slice(&mut expected_right, &src_b, c);

            assert_eq!(actual_left, expected_left, "{scenario}: {context}");
            assert_eq!(actual_right, expected_right, "{scenario}: {context}");
        }
    }

    #[test]
    fn addmul_slices2_shorter_lane_below_simd_width_matches_two_independent_addmul_slice_calls() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let c = Gf256(181);

        for &(len_a, len_b, scenario) in &[
            (7usize, 95usize, "left-short-tiny"),
            (95usize, 7usize, "right-short-tiny"),
            (31usize, 95usize, "left-short-avx2-window"),
            (95usize, 31usize, "right-short-avx2-window"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "addmul_slices2_shorter_lane_below_simd_width_matches_two_independent_addmul_slice_calls",
                replay_ref,
            );
            let src_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(13)) as u8).collect();
            let src_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(17)) as u8).collect();
            let mut actual_left: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(19)) as u8).collect();
            let mut actual_right: Vec<u8> =
                (0..len_b).map(|i| (i.wrapping_mul(23)) as u8).collect();
            let mut expected_left = actual_left.clone();
            let mut expected_right = actual_right.clone();

            gf256_addmul_slices2(&mut actual_left, &src_a, &mut actual_right, &src_b, c);
            gf256_addmul_slice(&mut expected_left, &src_a, c);
            gf256_addmul_slice(&mut expected_right, &src_b, c);

            assert_eq!(actual_left, expected_left, "{scenario}: {context}");
            assert_eq!(actual_right, expected_right, "{scenario}: {context}");
        }
    }

    #[test]
    fn mul_with_table_wide2_matches_two_independent_single_lane_paths() {
        const LEN_A: usize = 47;
        const LEN_B: usize = 89;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_with_table_wide2_matches_two_independent_single_lane_paths",
            replay_ref,
        );
        let c = Gf256(157);
        let nib = NibbleTables::for_scalar(c);
        let table = mul_table_for(c);

        let mut actual_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let mut actual_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(11)) as u8).collect();
        let mut expected_a = actual_a.clone();
        let mut expected_b = actual_b.clone();

        mul_with_table_wide2(&mut actual_a, &mut actual_b, &nib, table);
        mul_with_table_wide(&mut expected_a, &nib, table);
        mul_with_table_wide(&mut expected_b, &nib, table);

        assert_eq!(actual_a, expected_a, "{context}");
        assert_eq!(actual_b, expected_b, "{context}");
    }

    #[test]
    fn mul_slices2_sequential_shared_setup_matches_two_independent_mul_slice_calls() {
        const LEN_A: usize = 4127;
        const LEN_B: usize = 1089;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "mul_slices2_sequential_shared_setup_matches_two_independent_mul_slice_calls",
            replay_ref,
        );
        let c = Gf256(113);

        let mut actual_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let mut actual_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(11)) as u8).collect();
        let mut expected_a = actual_a.clone();
        let mut expected_b = actual_b.clone();
        let dispatch = dispatch();

        mul_slices2_sequential_with_shared_setup(&mut actual_a, &mut actual_b, c, dispatch);
        (dispatch.mul_slice)(&mut expected_a, c);
        (dispatch.mul_slice)(&mut expected_b, c);

        assert_eq!(actual_a, expected_a, "{context}");
        assert_eq!(actual_b, expected_b, "{context}");
    }

    #[test]
    fn addmul_with_table_wide2_matches_two_independent_single_lane_paths() {
        const LEN_A: usize = 55;
        const LEN_B: usize = 93;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "addmul_with_table_wide2_matches_two_independent_single_lane_paths",
            replay_ref,
        );
        let c = Gf256(181);
        let nib = NibbleTables::for_scalar(c);
        let table = mul_table_for(c);

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut actual_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut actual_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_a = actual_a.clone();
        let mut expected_b = actual_b.clone();

        addmul_with_table_wide2(&mut actual_a, &src_a, &mut actual_b, &src_b, &nib, table);
        addmul_with_table_wide(&mut expected_a, &src_a, &nib, table);
        addmul_with_table_wide(&mut expected_b, &src_b, &nib, table);

        assert_eq!(actual_a, expected_a, "{context}");
        assert_eq!(actual_b, expected_b, "{context}");
    }

    #[test]
    fn addmul_slices2_with_one_matches_two_independent_add_slice_calls() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &(len_a, len_b, scenario) in &[
            (7usize, 95usize, "left-short-tiny"),
            (95usize, 31usize, "right-short-avx2-window"),
            (79usize, 149usize, "wide-fused-window"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "addmul_slices2_with_one_matches_two_independent_add_slice_calls",
                replay_ref,
            );

            let src_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(13)) as u8).collect();
            let src_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(17)) as u8).collect();
            let mut accum_left: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(19)) as u8).collect();
            let mut accum_right: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(23)) as u8).collect();
            let mut expected_left = accum_left.clone();
            let mut expected_right = accum_right.clone();

            gf256_addmul_slices2(
                &mut accum_left,
                &src_a,
                &mut accum_right,
                &src_b,
                Gf256::ONE,
            );
            gf256_add_slice(&mut expected_left, &src_a);
            gf256_add_slice(&mut expected_right, &src_b);

            assert_eq!(accum_left, expected_left, "{scenario}: {context}");
            assert_eq!(accum_right, expected_right, "{scenario}: {context}");
        }
    }

    #[test]
    fn addmul_slices2_with_one_handles_empty_lane_pairs() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &(len_a, len_b, scenario) in &[
            (0usize, 65usize, "left-empty"),
            (65usize, 0usize, "right-empty"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "addmul_slices2_with_one_handles_empty_lane_pairs",
                replay_ref,
            );

            let src_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(13)) as u8).collect();
            let src_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(17)) as u8).collect();
            let mut actual_left: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(19)) as u8).collect();
            let mut actual_right: Vec<u8> =
                (0..len_b).map(|i| (i.wrapping_mul(23)) as u8).collect();
            let mut expected_left = actual_left.clone();
            let mut expected_right = actual_right.clone();

            gf256_addmul_slices2(
                &mut actual_left,
                &src_a,
                &mut actual_right,
                &src_b,
                Gf256::ONE,
            );
            gf256_add_slice(&mut expected_left, &src_a);
            gf256_add_slice(&mut expected_right, &src_b);

            assert_eq!(actual_left, expected_left, "{scenario}: {context}");
            assert_eq!(actual_right, expected_right, "{scenario}: {context}");
        }
    }

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    #[test]
    fn avx2_add_slice_matches_scalar_with_remainders() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        const LEN: usize = 95;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "avx2_add_slice_matches_scalar_with_remainders",
            replay_ref,
        );

        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let mut actual: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut expected = actual.clone();

        unsafe {
            gf256_add_slice_x86_avx2_impl(&mut actual, &src);
        }
        gf256_add_slice_scalar(&mut expected, &src);

        assert_eq!(actual, expected, "{context}");
    }

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    #[test]
    fn avx2_add_slices2_matches_single_lane_impl_with_remainders() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        const LEN_A: usize = 95;
        const LEN_B: usize = 157;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "avx2_add_slices2_matches_single_lane_impl_with_remainders",
            replay_ref,
        );

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut actual_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut actual_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_a = actual_a.clone();
        let mut expected_b = actual_b.clone();

        unsafe {
            gf256_add_slices2_x86_avx2_impl(&mut actual_a, &src_a, &mut actual_b, &src_b);
            gf256_add_slice_x86_avx2_impl(&mut expected_a, &src_a);
            gf256_add_slice_x86_avx2_impl(&mut expected_b, &src_b);
        }

        assert_eq!(actual_a, expected_a, "{context}");
        assert_eq!(actual_b, expected_b, "{context}");
    }

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    #[test]
    fn avx2_dual_mul_tables_matches_single_lane_impl_with_remainders() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        const LEN_A: usize = 97;
        const LEN_B: usize = 161;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "avx2_dual_mul_tables_matches_single_lane_impl_with_remainders",
            replay_ref,
        );

        let c = Gf256(113);
        let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);
        let table = mul_table_for(c);

        let mut a_actual: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let mut b_actual: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(11)) as u8).collect();
        let mut a_expected = a_actual.clone();
        let mut b_expected = b_actual.clone();

        unsafe {
            gf256_mul_slices2_x86_avx2_impl_tables(
                &mut a_actual,
                &mut b_actual,
                low_tbl_arr,
                high_tbl_arr,
                table,
            );
            gf256_mul_slice_x86_avx2_impl_tables(&mut a_expected, low_tbl_arr, high_tbl_arr, table);
            gf256_mul_slice_x86_avx2_impl_tables(&mut b_expected, low_tbl_arr, high_tbl_arr, table);
        }

        assert_eq!(a_actual, a_expected, "{context}");
        assert_eq!(b_actual, b_expected, "{context}");
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    #[test]
    fn neon_add_slice_matches_scalar_with_remainders() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }

        const LEN: usize = 47;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "neon_add_slice_matches_scalar_with_remainders",
            replay_ref,
        );

        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let mut actual: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut expected = actual.clone();

        unsafe {
            gf256_add_slice_aarch64_neon_impl(&mut actual, &src);
        }
        gf256_add_slice_scalar(&mut expected, &src);

        assert_eq!(actual, expected, "{context}");
    }

    #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
    #[test]
    fn neon_add_slices2_matches_single_lane_impl_with_remainders() {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }

        const LEN_A: usize = 47;
        const LEN_B: usize = 79;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "neon_add_slices2_matches_single_lane_impl_with_remainders",
            replay_ref,
        );

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut actual_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut actual_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_a = actual_a.clone();
        let mut expected_b = actual_b.clone();

        unsafe {
            gf256_add_slices2_aarch64_neon_impl(&mut actual_a, &src_a, &mut actual_b, &src_b);
            gf256_add_slice_aarch64_neon_impl(&mut expected_a, &src_a);
            gf256_add_slice_aarch64_neon_impl(&mut expected_b, &src_b);
        }

        assert_eq!(actual_a, expected_a, "{context}");
        assert_eq!(actual_b, expected_b, "{context}");
    }

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    #[test]
    fn avx2_dual_addmul_tables_matches_single_lane_impl_with_remainders() {
        if !std::is_x86_feature_detected!("avx2") {
            return;
        }

        const LEN_A: usize = 95;
        const LEN_B: usize = 157;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "avx2_dual_addmul_tables_matches_single_lane_impl_with_remainders",
            replay_ref,
        );

        let c = Gf256(173);
        let (low_tbl_arr, high_tbl_arr) = mul_nibble_tables(c);
        let table = mul_table_for(c);

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut a_actual: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut b_actual: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut a_expected = a_actual.clone();
        let mut b_expected = b_actual.clone();

        unsafe {
            gf256_addmul_slices2_x86_avx2_impl_tables(
                &mut a_actual,
                &src_a,
                &mut b_actual,
                &src_b,
                low_tbl_arr,
                high_tbl_arr,
                table,
            );
            gf256_addmul_slice_x86_avx2_impl_tables(
                &mut a_expected,
                &src_a,
                low_tbl_arr,
                high_tbl_arr,
                table,
            );
            gf256_addmul_slice_x86_avx2_impl_tables(
                &mut b_expected,
                &src_b,
                low_tbl_arr,
                high_tbl_arr,
                table,
            );
        }

        assert_eq!(a_actual, a_expected, "{context}");
        assert_eq!(b_actual, b_expected, "{context}");
    }

    #[test]
    fn add_slices2_matches_two_independent_add_slice_calls() {
        const LEN_A: usize = 83;
        const LEN_B: usize = 141;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "add_slices2_matches_two_independent_add_slice_calls",
            replay_ref,
        );

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut accum_left: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut accum_right: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_left = accum_left.clone();
        let mut expected_right = accum_right.clone();

        gf256_add_slices2(&mut accum_left, &src_a, &mut accum_right, &src_b);
        gf256_add_slice(&mut expected_left, &src_a);
        gf256_add_slice(&mut expected_right, &src_b);

        assert_eq!(accum_left, expected_left, "{context}");
        assert_eq!(accum_right, expected_right, "{context}");
    }

    #[test]
    fn add_slices2_tiny_pairs_match_two_independent_add_slice_calls() {
        const LEN_A: usize = 7;
        const LEN_B: usize = 11;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "add_slices2_tiny_pairs_match_two_independent_add_slice_calls",
            replay_ref,
        );

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(3)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(5)) as u8).collect();
        let mut accum_left: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let mut accum_right: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(11)) as u8).collect();
        let mut expected_left = accum_left.clone();
        let mut expected_right = accum_right.clone();

        gf256_add_slices2(&mut accum_left, &src_a, &mut accum_right, &src_b);
        gf256_add_slice(&mut expected_left, &src_a);
        gf256_add_slice(&mut expected_right, &src_b);

        assert_eq!(accum_left, expected_left, "{context}");
        assert_eq!(accum_right, expected_right, "{context}");
    }

    #[test]
    fn add_slices2_shorter_lane_below_simd_width_matches_two_independent_add_slice_calls() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &(len_a, len_b, scenario) in &[
            (7usize, 95usize, "left-short-tiny"),
            (95usize, 7usize, "right-short-tiny"),
            (31usize, 95usize, "left-short-avx2-window"),
            (95usize, 31usize, "right-short-avx2-window"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "add_slices2_shorter_lane_below_simd_width_matches_two_independent_add_slice_calls",
                replay_ref,
            );

            let src_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(3)) as u8).collect();
            let src_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(5)) as u8).collect();
            let mut accum_left: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(7)) as u8).collect();
            let mut accum_right: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(11)) as u8).collect();
            let mut expected_left = accum_left.clone();
            let mut expected_right = accum_right.clone();

            gf256_add_slices2(&mut accum_left, &src_a, &mut accum_right, &src_b);
            gf256_add_slice(&mut expected_left, &src_a);
            gf256_add_slice(&mut expected_right, &src_b);

            assert_eq!(accum_left, expected_left, "{scenario}: {context}");
            assert_eq!(accum_right, expected_right, "{scenario}: {context}");
        }
    }

    #[test]
    fn add_slices2_scalar_matches_two_independent_single_lane_paths() {
        const LEN_A: usize = 47;
        const LEN_B: usize = 89;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "add_slices2_scalar_matches_two_independent_single_lane_paths",
            replay_ref,
        );

        let src_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let src_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(17)) as u8).collect();
        let mut actual_a: Vec<u8> = (0..LEN_A).map(|i| (i.wrapping_mul(19)) as u8).collect();
        let mut actual_b: Vec<u8> = (0..LEN_B).map(|i| (i.wrapping_mul(23)) as u8).collect();
        let mut expected_a = actual_a.clone();
        let mut expected_b = actual_b.clone();

        gf256_add_slices2_scalar(&mut actual_a, &src_a, &mut actual_b, &src_b);
        gf256_add_slice_scalar(&mut expected_a, &src_a);
        gf256_add_slice_scalar(&mut expected_b, &src_b);

        assert_eq!(actual_a, expected_a, "{context}");
        assert_eq!(actual_b, expected_b, "{context}");
    }

    #[test]
    fn add_slices2_scalar_handles_empty_lane_pairs() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &(len_a, len_b, scenario) in &[
            (0usize, 65usize, "left-empty"),
            (65usize, 0usize, "right-empty"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "add_slices2_scalar_handles_empty_lane_pairs",
                replay_ref,
            );

            let src_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(29)) as u8).collect();
            let src_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(31)) as u8).collect();
            let mut actual_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(37)) as u8).collect();
            let mut actual_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(41)) as u8).collect();
            let mut expected_a = actual_a.clone();
            let mut expected_b = actual_b.clone();

            gf256_add_slices2_scalar(&mut actual_a, &src_a, &mut actual_b, &src_b);
            gf256_add_slice_scalar(&mut expected_a, &src_a);
            gf256_add_slice_scalar(&mut expected_b, &src_b);

            assert_eq!(actual_a, expected_a, "{scenario}: {context}");
            assert_eq!(actual_b, expected_b, "{scenario}: {context}");
        }
    }

    #[test]
    fn add_slices2_scalar_handles_boundary_crossovers_and_uneven_tails() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &(len_a, len_b, scenario) in &[
            (1usize, 33usize, "left-byte-right-wide-plus-byte"),
            (33usize, 1usize, "left-wide-plus-byte-right-byte"),
            (8usize, 41usize, "left-word-right-wide-plus-word-plus-byte"),
            (41usize, 8usize, "left-wide-plus-word-plus-byte-right-word"),
            (31usize, 32usize, "left-subwide-right-wide"),
            (32usize, 31usize, "left-wide-right-subwide"),
            (
                39usize,
                72usize,
                "left-wide-plus-word-minus-byte-right-two-wide-plus-word",
            ),
            (
                72usize,
                39usize,
                "left-two-wide-plus-word-right-wide-plus-word-minus-byte",
            ),
            (63usize, 64usize, "left-two-wide-minus-byte-right-two-wide"),
            (64usize, 63usize, "left-two-wide-right-two-wide-minus-byte"),
            (65usize, 96usize, "left-two-wide-plus-byte-right-three-wide"),
            (96usize, 65usize, "left-three-wide-right-two-wide-plus-byte"),
        ] {
            let context = failure_context(
                "RQ-U-GF256-ALGEBRA",
                seed,
                "add_slices2_scalar_handles_boundary_crossovers_and_uneven_tails",
                replay_ref,
            );

            let src_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(43)) as u8).collect();
            let src_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(47)) as u8).collect();
            let mut actual_a: Vec<u8> = (0..len_a).map(|i| (i.wrapping_mul(53)) as u8).collect();
            let mut actual_b: Vec<u8> = (0..len_b).map(|i| (i.wrapping_mul(59)) as u8).collect();
            let mut expected_a = actual_a.clone();
            let mut expected_b = actual_b.clone();

            gf256_add_slices2_scalar(&mut actual_a, &src_a, &mut actual_b, &src_b);
            gf256_add_slice_scalar(&mut expected_a, &src_a);
            gf256_add_slice_scalar(&mut expected_b, &src_b);

            assert_eq!(actual_a, expected_a, "{scenario}: {context}");
            assert_eq!(actual_b, expected_b, "{scenario}: {context}");
        }
    }

    #[test]
    fn active_kernel_is_stable_within_process() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-core-laws-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "active_kernel_is_stable_within_process",
            replay_ref,
        );
        let first = active_kernel();
        for _ in 0..16 {
            assert_eq!(active_kernel(), first, "{context}");
        }
    }

    // -- SIMD nibble decomposition verification --

    #[cfg(feature = "simd-intrinsics")]
    #[test]
    fn nibble_tables_exhaustive() {
        // Verify nibble decomposition for all 256×256 (c, x) pairs.
        let replay_ref = "replay:rq-u-gf256-nibble-table-v1";
        for c in 0u16..=255 {
            let gc = Gf256(c as u8);
            let nib = NibbleTables::for_scalar(gc);
            for x in 0u16..=255 {
                let context = failure_context(
                    "RQ-U-GF256-ALGEBRA",
                    u64::from(c),
                    &format!("nibble_table,c={c},x={x}"),
                    replay_ref,
                );
                let expected = (gc * Gf256(x as u8)).0;
                let v = Simd::<u8, 16>::splat(x as u8);
                let result = nib.mul16(v);
                assert_eq!(
                    result[0], expected,
                    "nibble decomp mismatch: c={c}, x={x}, got={}, expected={expected}; {context}",
                    result[0],
                );
            }
        }
    }

    #[test]
    fn simd_vs_scalar_mul_equivalence() {
        // Compare SIMD and scalar mul paths at various sizes.
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &len in &[16usize, 17, 31, 64, 71, 128, 1024] {
            for &c_val in &[2u8, 13, 127, 255] {
                let context = failure_context(
                    "RQ-U-GF256-ALGEBRA",
                    seed,
                    &format!("simd_vs_scalar_mul,len={len},c={c_val}"),
                    replay_ref,
                );
                let c = Gf256(c_val);
                let original: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(37)) as u8)
                    .collect();
                let table = mul_table_for(c);

                let mut simd_dst = original.clone();
                let nib = NibbleTables::for_scalar(c);
                mul_with_table_wide(&mut simd_dst, &nib, table);

                let mut scalar_dst = original;
                mul_with_table_scalar(&mut scalar_dst, table);

                assert_eq!(
                    simd_dst, scalar_dst,
                    "mul mismatch: len={len}, c={c_val}; {context}"
                );
            }
        }
    }

    #[test]
    fn simd_vs_scalar_addmul_equivalence() {
        // Compare SIMD and scalar addmul paths at various sizes.
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        for &len in &[16usize, 17, 31, 64, 71, 128, 1024] {
            for &c_val in &[2u8, 13, 127, 255] {
                let context = failure_context(
                    "RQ-U-GF256-ALGEBRA",
                    seed,
                    &format!("simd_vs_scalar_addmul,len={len},c={c_val}"),
                    replay_ref,
                );
                let c = Gf256(c_val);
                let src: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(37)) as u8)
                    .collect();
                let dst_init: Vec<u8> = (0..len)
                    .map(|i: usize| (i.wrapping_mul(53)) as u8)
                    .collect();
                let table = mul_table_for(c);

                let mut simd_dst = dst_init.clone();
                let nib = NibbleTables::for_scalar(c);
                addmul_with_table_wide(&mut simd_dst, &src, &nib, table);

                let mut scalar_dst = dst_init;
                addmul_with_table_scalar(&mut scalar_dst, &src, table);

                assert_eq!(
                    simd_dst, scalar_dst,
                    "addmul mismatch: len={len}, c={c_val}; {context}"
                );
            }
        }
    }

    #[test]
    fn deterministic_corpus_mul_addmul_matches_scalar_reference() {
        let replay_ref = "replay:rq-u-gf256-simd-scalar-corpus-v1";
        let seeds = [0u64, 1, 0x5EED_F00D, 0xA5A5_5A5A_D3C1_B2E0];
        let lengths = [
            0usize, 1, 2, 7, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
            511, 512, 513, 1024, 1537,
        ];
        let scalars = [0u8, 1, 2, 3, 5, 7, 11, 29, 127, 128, 199, 255];

        for seed in seeds {
            for len in lengths {
                let original = deterministic_bytes(seed, len, 0x0C01_1EC7);
                let src = deterministic_bytes(seed, len, 0xADD0_4D17);
                for scalar in scalars {
                    let context = failure_context(
                        "RQ-U-GF256-SIMD-SCALAR-CORPUS",
                        seed,
                        &format!("len={len},scalar={scalar}"),
                        replay_ref,
                    );
                    let c = Gf256(scalar);
                    let table = mul_table_for(c);
                    let nib = NibbleTables::for_scalar(c);

                    let mut dispatch_mul = original.clone();
                    let mut scalar_mul = original.clone();
                    let mut wide_mul = original.clone();
                    gf256_mul_slice(&mut dispatch_mul, c);
                    gf256_mul_slice_scalar(&mut scalar_mul, c);
                    mul_with_table_wide(&mut wide_mul, &nib, table);
                    assert_eq!(dispatch_mul, scalar_mul, "dispatch mul mismatch; {context}");
                    assert_eq!(wide_mul, scalar_mul, "wide mul mismatch; {context}");

                    let mut dispatch_addmul = original.clone();
                    let mut scalar_addmul = original.clone();
                    let mut wide_addmul = original.clone();
                    gf256_addmul_slice(&mut dispatch_addmul, &src, c);
                    gf256_addmul_slice_scalar(&mut scalar_addmul, &src, c);
                    addmul_with_table_wide(&mut wide_addmul, &src, &nib, table);
                    assert_eq!(
                        dispatch_addmul, scalar_addmul,
                        "dispatch addmul mismatch; {context}"
                    );
                    assert_eq!(
                        wide_addmul, scalar_addmul,
                        "wide addmul mismatch; {context}"
                    );
                }
            }
        }
    }

    #[test]
    fn dispatched_paths_match_scalar_reference() {
        const LEN: usize = 96;
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-simd-scalar-equivalence-v1";
        let context = failure_context(
            "RQ-U-GF256-ALGEBRA",
            seed,
            "dispatched_paths_match_scalar_reference",
            replay_ref,
        );

        let src: Vec<u8> = (0..LEN).map(|i| (i.wrapping_mul(13)) as u8).collect();
        let original: Vec<u8> = (0..LEN).map(|i| (255u16 - i as u16) as u8).collect();
        let c = Gf256(29);

        let mut add_dispatch = original.clone();
        let mut add_scalar = original.clone();
        gf256_add_slice(&mut add_dispatch, &src);
        gf256_add_slice_scalar(&mut add_scalar, &src);
        assert_eq!(add_dispatch, add_scalar, "{context}");

        let mut mul_dispatch = original.clone();
        let mut mul_scalar = original.clone();
        gf256_mul_slice(&mut mul_dispatch, c);
        gf256_mul_slice_scalar(&mut mul_scalar, c);
        assert_eq!(mul_dispatch, mul_scalar, "{context}");

        let mut addmul_dispatch = original.clone();
        let mut addmul_scalar = original;
        gf256_addmul_slice(&mut addmul_dispatch, &src, c);
        gf256_addmul_slice_scalar(&mut addmul_scalar, &src, c);
        assert_eq!(addmul_dispatch, addmul_scalar, "{context}");
    }

    #[test]
    fn dual_policy_ratio_gate_behaves_as_expected() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v1";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_ratio_gate_behaves_as_expected",
            replay_ref,
        );
        assert!(lane_ratio_within(1024, 1024, 1), "{context}");
        assert!(lane_ratio_within(1024, 4096, 4), "{context}");
        assert!(!lane_ratio_within(1024, 4097, 4), "{context}");
        assert!(!lane_ratio_within(0, 1024, 8), "{context}");
    }

    #[test]
    fn dual_policy_window_gate_behaves_as_expected() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v1";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_window_gate_behaves_as_expected",
            replay_ref,
        );
        assert!(in_window(8192, 8192, 16384), "{context}");
        assert!(in_window(12000, 8192, 16384), "{context}");
        assert!(!in_window(4096, 8192, 16384), "{context}");
        assert!(!in_window(20000, 8192, 16384), "{context}");
        assert!(!in_window(12000, 20000, 10000), "{context}");
    }

    #[test]
    fn dual_policy_addmul_lane_floor_gate_behaves_as_expected() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v3";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_addmul_lane_floor_gate_behaves_as_expected",
            replay_ref,
        );
        let policy = x86_profile_pack_policy_fixture();
        let eligible_small = policy.addmul_min_lane;
        let eligible_large = policy.addmul_min_total - eligible_small;
        let below_floor_small = policy.addmul_min_lane - 1;
        let below_floor_large = policy.addmul_min_total - below_floor_small;
        assert_eq!(
            dual_addmul_decision_detail_with_policy(&policy, below_floor_large, below_floor_small)
                .decision,
            DualKernelDecision::Sequential,
            "{context}"
        );
        assert_eq!(
            dual_addmul_decision_detail_with_policy(&policy, eligible_large, eligible_small)
                .decision,
            DualKernelDecision::Fused,
            "{context}"
        );
    }

    #[test]
    fn dual_policy_decision_reasons_cover_forced_and_gate_failures() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v4";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_decision_reasons_cover_forced_and_gate_failures",
            replay_ref,
        );
        let base = x86_profile_pack_policy_fixture();
        let eligible_small = base.addmul_min_lane;
        let eligible_large = base.addmul_min_total - eligible_small;
        let below_floor_small = base.addmul_min_lane - 1;
        let below_floor_large = base.addmul_min_total - below_floor_small;

        let eligible =
            dual_addmul_decision_detail_with_policy(&base, eligible_large, eligible_small);
        assert_eq!(eligible.decision, DualKernelDecision::Fused, "{context}");
        assert_eq!(
            eligible.reason,
            DualKernelDecisionReason::EligibleAutoWindow,
            "{context}"
        );

        let below_floor =
            dual_addmul_decision_detail_with_policy(&base, below_floor_large, below_floor_small);
        assert_eq!(
            below_floor.decision,
            DualKernelDecision::Sequential,
            "{context}"
        );
        assert_eq!(
            below_floor.reason,
            DualKernelDecisionReason::LaneBelowMinFloor,
            "{context}"
        );

        let below_window = dual_addmul_decision_detail_with_policy(&base, 4096, 4096);
        assert_eq!(
            below_window.reason,
            DualKernelDecisionReason::TotalBelowWindow,
            "{context}"
        );

        let above_window = dual_addmul_decision_detail_with_policy(
            &base,
            base.addmul_max_total,
            base.addmul_min_lane,
        );
        assert_eq!(
            above_window.reason,
            DualKernelDecisionReason::TotalAboveWindow,
            "{context}"
        );

        let ratio_policy = DualKernelPolicy {
            addmul_min_lane: 2 * 1024,
            ..base
        };
        let ratio_exceeded =
            dual_addmul_decision_detail_with_policy(&ratio_policy, 28 * 1024, 2 * 1024);
        assert_eq!(
            ratio_exceeded.reason,
            DualKernelDecisionReason::LaneRatioExceeded,
            "{context}"
        );

        let force_seq = DualKernelPolicy {
            mode: DualKernelOverride::ForceSequential,
            ..base
        };
        let force_seq_detail =
            dual_addmul_decision_detail_with_policy(&force_seq, eligible_large, eligible_small);
        assert_eq!(
            force_seq_detail.reason,
            DualKernelDecisionReason::ForcedSequentialMode,
            "{context}"
        );

        let force_fused = DualKernelPolicy {
            mode: DualKernelOverride::ForceFused,
            ..base
        };
        let force_fused_detail = dual_mul_decision_detail_with_policy(&force_fused, 4096, 4096);
        assert_eq!(
            force_fused_detail.reason,
            DualKernelDecisionReason::ForcedFusedMode,
            "{context}"
        );
    }

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn dual_execution_paths_preserve_fused_contract_below_arch_pair_floor() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v4";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_execution_paths_preserve_fused_contract_below_arch_pair_floor",
            replay_ref,
        );

        let forced = DualKernelPolicy {
            mode: DualKernelOverride::ForceFused,
            ..x86_profile_pack_policy_fixture()
        };

        #[cfg(all(
            feature = "simd-intrinsics",
            any(target_arch = "x86", target_arch = "x86_64")
        ))]
        {
            assert_eq!(
                dual_mul_execution_path_with_policy(&forced, Gf256Kernel::X86Avx2, 31, 95),
                DualExecutionPath::FusedSharedSetup,
                "{context}"
            );
            assert_eq!(
                dual_addmul_execution_path_with_policy(&forced, Gf256Kernel::X86Avx2, 31, 95),
                DualExecutionPath::FusedSharedSetup,
                "{context}"
            );
            assert_eq!(
                dual_mul_execution_path_with_policy(&forced, Gf256Kernel::X86Avx2, 32, 95),
                DualExecutionPath::FusedArchWide,
                "{context}"
            );
            assert_eq!(
                dual_addmul_execution_path_with_policy(&forced, Gf256Kernel::X86Avx2, 32, 95),
                DualExecutionPath::FusedArchWide,
                "{context}"
            );
        }

        #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
        {
            assert_eq!(
                dual_mul_execution_path_with_policy(&forced, Gf256Kernel::Aarch64Neon, 15, 95),
                DualExecutionPath::FusedSharedSetup,
                "{context}"
            );
            assert_eq!(
                dual_addmul_execution_path_with_policy(&forced, Gf256Kernel::Aarch64Neon, 15, 95),
                DualExecutionPath::FusedSharedSetup,
                "{context}"
            );
            assert_eq!(
                dual_mul_execution_path_with_policy(&forced, Gf256Kernel::Aarch64Neon, 16, 95),
                DualExecutionPath::FusedArchWide,
                "{context}"
            );
            assert_eq!(
                dual_addmul_execution_path_with_policy(&forced, Gf256Kernel::Aarch64Neon, 16, 95),
                DualExecutionPath::FusedArchWide,
                "{context}"
            );
        }
    }

    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn add_pair_execution_path_preserves_per_lane_dispatch_below_arch_pair_floor() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v4";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "add_pair_execution_path_preserves_per_lane_dispatch_below_arch_pair_floor",
            replay_ref,
        );

        #[cfg(all(
            feature = "simd-intrinsics",
            any(target_arch = "x86", target_arch = "x86_64")
        ))]
        {
            assert_eq!(
                add_pair_execution_path(Gf256Kernel::X86Avx2, 31, 95),
                AddPairExecutionPath::PerLaneDispatch,
                "{context}"
            );
            assert_eq!(
                add_pair_execution_path(Gf256Kernel::X86Avx2, 32, 95),
                AddPairExecutionPath::FusedArchWide,
                "{context}"
            );
        }

        #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
        {
            assert_eq!(
                add_pair_execution_path(Gf256Kernel::Aarch64Neon, 15, 95),
                AddPairExecutionPath::PerLaneDispatch,
                "{context}"
            );
            assert_eq!(
                add_pair_execution_path(Gf256Kernel::Aarch64Neon, 16, 95),
                AddPairExecutionPath::FusedArchWide,
                "{context}"
            );
        }
    }

    #[test]
    fn single_mul_execution_path_respects_single_lane_thresholds() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v4";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "single_mul_execution_path_respects_single_lane_thresholds",
            replay_ref,
        );

        assert_eq!(
            single_mul_execution_path(Gf256Kernel::Scalar, MUL_TABLE_THRESHOLD - 1),
            SingleMulExecutionPath::ScalarTable,
            "{context}"
        );
        assert_eq!(
            single_mul_execution_path(Gf256Kernel::Scalar, MUL_TABLE_THRESHOLD),
            SingleMulExecutionPath::WideTable,
            "{context}"
        );

        #[cfg(all(
            feature = "simd-intrinsics",
            any(target_arch = "x86", target_arch = "x86_64")
        ))]
        {
            assert_eq!(
                single_mul_execution_path(Gf256Kernel::X86Avx2, 31),
                SingleMulExecutionPath::ScalarTable,
                "{context}"
            );
            assert_eq!(
                single_mul_execution_path(Gf256Kernel::X86Avx2, 32),
                SingleMulExecutionPath::ArchWide,
                "{context}"
            );
        }

        #[cfg(all(feature = "simd-intrinsics", target_arch = "aarch64"))]
        {
            assert_eq!(
                single_mul_execution_path(Gf256Kernel::Aarch64Neon, 15),
                SingleMulExecutionPath::ScalarTable,
                "{context}"
            );
            assert_eq!(
                single_mul_execution_path(Gf256Kernel::Aarch64Neon, 16),
                SingleMulExecutionPath::ArchWide,
                "{context}"
            );
        }
    }

    #[test]
    fn dual_policy_window_reason_classification_and_strings_are_stable() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v4";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_window_reason_classification_and_strings_are_stable",
            replay_ref,
        );
        assert_eq!(
            window_gate_reason(8192, usize::MAX, 0),
            Some(DualKernelDecisionReason::WindowDisabledByProfile),
            "{context}"
        );
        assert_eq!(
            window_gate_reason(8192, 16384, 1024),
            Some(DualKernelDecisionReason::InvalidWindowConfiguration),
            "{context}"
        );
        assert_eq!(
            DualKernelDecisionReason::WindowDisabledByProfile.as_str(),
            "window-disabled-by-profile",
            "{context}"
        );

        assert_eq!(
            DualKernelDecisionReason::LaneBelowMinFloor.as_str(),
            "lane-below-min-floor",
            "{context}"
        );
    }

    #[test]
    fn disabled_windows_report_explicit_profile_reason() {
        let metadata = profile_pack_metadata_fixture(Gf256ProfilePackId::ScalarConservativeV1);
        let policy = DualKernelPolicy {
            profile_pack: metadata.profile_pack,
            architecture_class: metadata.architecture_class,
            tuning_corpus_id: metadata.tuning_corpus_id,
            selected_tuning_candidate_id: metadata.selected_tuning_candidate_id,
            rejected_tuning_candidate_ids: metadata.rejected_tuning_candidate_ids,
            fallback_reason: None,
            rejected_candidates: REJECTED_PROFILE_SELECTED_SCALAR,
            replay_pointer: metadata.replay_pointer,
            command_bundle: metadata.command_bundle,
            mode: DualKernelOverride::Auto,
            mode_fallback_reason: None,
            override_mask: DualKernelOverrideMask::empty(),
            mul_min_total: metadata.mul_min_total,
            mul_max_total: metadata.mul_max_total,
            addmul_min_total: metadata.addmul_min_total,
            addmul_max_total: metadata.addmul_max_total,
            addmul_min_lane: metadata.addmul_min_lane,
            max_lane_ratio: metadata.max_lane_ratio,
        };

        let mul = dual_mul_decision_detail_with_policy(&policy, 4096, 4096);
        assert_eq!(mul.decision, DualKernelDecision::Sequential);
        assert_eq!(
            mul.reason,
            DualKernelDecisionReason::WindowDisabledByProfile
        );

        let addmul = dual_addmul_decision_detail_with_policy(&policy, 4096, 4096);
        assert_eq!(addmul.decision, DualKernelDecision::Sequential);
        assert_eq!(
            addmul.reason,
            DualKernelDecisionReason::WindowDisabledByProfile
        );
    }

    #[test]
    fn dual_policy_snapshot_is_consistent_with_decision_helpers() {
        let snapshot = dual_kernel_policy_snapshot();
        let mode = snapshot.mode;
        assert!(
            matches!(
                mode,
                DualKernelMode::Auto | DualKernelMode::Sequential | DualKernelMode::Fused
            ),
            "snapshot mode should be a valid public dual-kernel mode",
        );

        for (len_a, len_b) in [
            (0, 0),
            (64, 64),
            (512, 4096),
            (4096, 4096),
            (16384, 2048),
            (16385, 8191),
        ] {
            let mul_decision = dual_mul_kernel_decision(len_a, len_b);
            let addmul_decision = dual_addmul_kernel_decision(len_a, len_b);
            let expected_mul = expected_decision_detail_from_snapshot(
                snapshot.mode,
                snapshot.mul_min_total,
                snapshot.mul_max_total,
                0,
                snapshot.max_lane_ratio,
                len_a,
                len_b,
            );
            let expected_addmul = expected_decision_detail_from_snapshot(
                snapshot.mode,
                snapshot.addmul_min_total,
                snapshot.addmul_max_total,
                snapshot.addmul_min_lane,
                snapshot.max_lane_ratio,
                len_a,
                len_b,
            );
            assert_eq!(
                mul_decision, expected_mul.decision,
                "public mul decision helper should match snapshot-derived policy contract",
            );
            assert_eq!(
                addmul_decision, expected_addmul.decision,
                "public addmul decision helper should match snapshot-derived policy contract",
            );
        }
    }

    fn expected_decision_detail_from_snapshot(
        mode: DualKernelMode,
        min_total: usize,
        max_total: usize,
        min_lane: usize,
        max_lane_ratio: usize,
        len_a: usize,
        len_b: usize,
    ) -> DualKernelDecisionDetail {
        match mode {
            DualKernelMode::Sequential => DualKernelDecisionDetail {
                decision: DualKernelDecision::Sequential,
                reason: DualKernelDecisionReason::ForcedSequentialMode,
            },
            DualKernelMode::Fused => DualKernelDecisionDetail {
                decision: DualKernelDecision::Fused,
                reason: DualKernelDecisionReason::ForcedFusedMode,
            },
            DualKernelMode::Auto => {
                let total = len_a.saturating_add(len_b);
                if let Some(reason) = window_gate_reason(total, min_total, max_total) {
                    return DualKernelDecisionDetail {
                        decision: DualKernelDecision::Sequential,
                        reason,
                    };
                }
                if len_a.min(len_b) < min_lane {
                    return DualKernelDecisionDetail {
                        decision: DualKernelDecision::Sequential,
                        reason: DualKernelDecisionReason::LaneBelowMinFloor,
                    };
                }
                if !lane_ratio_within(len_a, len_b, max_lane_ratio) {
                    return DualKernelDecisionDetail {
                        decision: DualKernelDecision::Sequential,
                        reason: DualKernelDecisionReason::LaneRatioExceeded,
                    };
                }
                DualKernelDecisionDetail {
                    decision: DualKernelDecision::Fused,
                    reason: DualKernelDecisionReason::EligibleAutoWindow,
                }
            }
        }
    }

    #[test]
    fn dual_policy_decision_matrix_matches_snapshot_contract() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v3";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_decision_matrix_matches_snapshot_contract",
            replay_ref,
        );
        let snapshot = dual_kernel_policy_snapshot();

        // Mirrors the benchmark policy-probe matrix used in benches/raptorq_benchmark.rs.
        let scenarios = [
            ("RQ-E-GF256-DUAL-001", 4096usize, 4096usize),
            ("RQ-E-GF256-DUAL-002", 7168usize, 1024usize),
            ("RQ-E-GF256-DUAL-003", 7424usize, 768usize),
            ("RQ-E-GF256-DUAL-004", 12288usize, 12288usize),
            ("RQ-E-GF256-DUAL-005", 15360usize, 15360usize),
            ("RQ-E-GF256-DUAL-006", 16384usize, 16384usize),
            ("RQ-E-GF256-DUAL-007", 12288usize, 1536usize),
            ("RQ-E-GF256-DUAL-008", 16385usize, 8191usize),
        ];

        for (scenario_id, len_a, len_b) in scenarios {
            let expected_mul = expected_decision_detail_from_snapshot(
                snapshot.mode,
                snapshot.mul_min_total,
                snapshot.mul_max_total,
                0,
                snapshot.max_lane_ratio,
                len_a,
                len_b,
            );
            let expected_addmul = expected_decision_detail_from_snapshot(
                snapshot.mode,
                snapshot.addmul_min_total,
                snapshot.addmul_max_total,
                snapshot.addmul_min_lane,
                snapshot.max_lane_ratio,
                len_a,
                len_b,
            );
            let mul_actual = dual_mul_kernel_decision_detail(len_a, len_b);
            let addmul_actual = dual_addmul_kernel_decision_detail(len_a, len_b);
            assert_eq!(
                mul_actual, expected_mul,
                "{context}; scenario_id={scenario_id}; mul mismatch for lane_a={len_a}, lane_b={len_b}"
            );
            assert_eq!(
                addmul_actual, expected_addmul,
                "{context}; scenario_id={scenario_id}; addmul mismatch for lane_a={len_a}, lane_b={len_b}"
            );
        }
    }

    // =========================================================================
    // Pure data-type tests (wave 40 – CyanBarn)
    // =========================================================================

    #[test]
    fn gf256_debug_display_format() {
        let elem = Gf256(42);
        assert_eq!(format!("{elem:?}"), "GF(42)");
        assert_eq!(format!("{elem}"), "42");
        let zero = Gf256::ZERO;
        assert_eq!(format!("{zero:?}"), "GF(0)");
        assert_eq!(format!("{zero}"), "0");
    }

    #[test]
    fn gf256_default_is_zero() {
        let def = Gf256::default();
        assert_eq!(def, Gf256::ZERO);
        assert_eq!(def.0, 0);
    }

    #[test]
    fn gf256_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let a = Gf256(100);
        let b = a; // Copy
        let c = a;
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(a, Gf256(101));

        let mut set = HashSet::new();
        set.insert(Gf256(1));
        set.insert(Gf256(2));
        set.insert(Gf256(1)); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn gf256_kernel_debug_clone_copy_eq() {
        let k = Gf256Kernel::Scalar;
        let copied = k;
        let cloned = k;
        assert_eq!(copied, cloned);
        assert_eq!(copied, Gf256Kernel::Scalar);
        let dbg = format!("{k:?}");
        assert!(dbg.contains("Scalar"));
    }

    #[test]
    fn dual_kernel_mode_debug_clone_copy_eq() {
        for mode in [
            DualKernelMode::Auto,
            DualKernelMode::Sequential,
            DualKernelMode::Fused,
        ] {
            let copied = mode;
            let cloned = mode;
            assert_eq!(copied, cloned);
            let dbg = format!("{mode:?}");
            assert!(!dbg.is_empty());
        }
        assert_ne!(DualKernelMode::Auto, DualKernelMode::Sequential);
        assert_ne!(DualKernelMode::Sequential, DualKernelMode::Fused);
    }

    #[test]
    fn dual_kernel_decision_debug_clone_copy_eq() {
        let seq = DualKernelDecision::Sequential;
        let fused = DualKernelDecision::Fused;
        assert_ne!(seq, fused);
        assert_eq!(seq, DualKernelDecision::Sequential);
        assert!(fused.is_fused());
        assert!(!seq.is_fused());
        let dbg = format!("{seq:?}");
        assert!(dbg.contains("Sequential"));
    }

    #[test]
    fn dual_kernel_policy_snapshot_debug_clone_copy_eq() {
        let metadata = profile_pack_metadata_fixture(Gf256ProfilePackId::X86Avx2BalancedV1);
        let snap = DualKernelPolicySnapshot {
            profile_schema_version: metadata.schema_version,
            profile_pack: metadata.profile_pack,
            architecture_class: metadata.architecture_class,
            kernel: Gf256Kernel::Scalar,
            tuning_corpus_id: metadata.tuning_corpus_id,
            selected_tuning_candidate_id: metadata.selected_tuning_candidate_id,
            rejected_tuning_candidate_ids: metadata.rejected_tuning_candidate_ids,
            fallback_reason: None,
            rejected_candidates: REJECTED_PROFILE_SELECTED_X86_AVX2,
            replay_pointer: metadata.replay_pointer,
            command_bundle: metadata.command_bundle,
            decision_artifact_id: metadata.decision_artifact_id,
            decision_role: metadata.decision_role,
            decision_evidence_status: metadata.decision_evidence_status,
            mode: DualKernelMode::Auto,
            mode_fallback_reason: None,
            override_mask: DualKernelOverrideMask::empty(),
            mul_min_total: metadata.mul_min_total,
            mul_max_total: metadata.mul_max_total,
            addmul_min_total: metadata.addmul_min_total,
            addmul_max_total: metadata.addmul_max_total,
            addmul_min_lane: metadata.addmul_min_lane,
            max_lane_ratio: metadata.max_lane_ratio,
        };
        let copied = snap;
        let cloned = snap;
        assert_eq!(copied, cloned);
        let dbg = format!("{snap:?}");
        assert!(dbg.contains("DualKernelPolicySnapshot"));
    }

    #[test]
    fn profile_pack_request_parser_handles_known_and_unknown_values() {
        assert_eq!(
            parse_profile_pack_request("auto"),
            Some(ProfilePackRequest::Auto)
        );
        assert_eq!(
            parse_profile_pack_request(" auto "),
            Some(ProfilePackRequest::Auto)
        );
        assert_eq!(
            parse_profile_pack_request("scalar-conservative-v1"),
            Some(ProfilePackRequest::ScalarConservativeV1)
        );
        assert_eq!(
            parse_profile_pack_request("x86-avx2-balanced-v1"),
            Some(ProfilePackRequest::X86Avx2BalancedV1)
        );
        assert_eq!(
            parse_profile_pack_request(" x86-avx2-balanced-v1 "),
            Some(ProfilePackRequest::X86Avx2BalancedV1)
        );
        assert_eq!(
            parse_profile_pack_request("aarch64-neon-balanced-v1"),
            Some(ProfilePackRequest::Aarch64NeonBalancedV1)
        );
        assert_eq!(
            parse_profile_pack_request("\naarch64-neon\n"),
            Some(ProfilePackRequest::Aarch64NeonBalancedV1)
        );
        assert_eq!(parse_profile_pack_request("unknown-pack"), None);
        assert_eq!(parse_profile_pack_request("   "), None);
    }

    #[test]
    fn dual_policy_request_parser_handles_known_and_unknown_values() {
        assert_eq!(
            parse_dual_policy_request("auto"),
            Some(DualKernelOverride::Auto)
        );
        assert_eq!(
            parse_dual_policy_request(" sequential "),
            Some(DualKernelOverride::ForceSequential)
        );
        assert_eq!(
            parse_dual_policy_request("off"),
            Some(DualKernelOverride::ForceSequential)
        );
        assert_eq!(
            parse_dual_policy_request(" never "),
            Some(DualKernelOverride::ForceSequential)
        );
        assert_eq!(
            parse_dual_policy_request("fused"),
            Some(DualKernelOverride::ForceFused)
        );
        assert_eq!(
            parse_dual_policy_request(" force_fused "),
            Some(DualKernelOverride::ForceFused)
        );
        assert_eq!(parse_dual_policy_request("invalid-mode"), None);
        assert_eq!(parse_dual_policy_request("   "), None);
    }

    #[test]
    fn profile_pack_catalog_is_deterministic_and_versioned() {
        let catalog = gf256_profile_pack_catalog();
        assert_eq!(catalog.len(), 3);
        assert_eq!(
            catalog[0].profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            catalog[1].profile_pack,
            Gf256ProfilePackId::X86Avx2BalancedV1
        );
        assert_eq!(
            catalog[2].profile_pack,
            Gf256ProfilePackId::Aarch64NeonBalancedV1
        );
        for metadata in catalog {
            assert_eq!(metadata.schema_version, GF256_PROFILE_PACK_SCHEMA_VERSION);
            assert_eq!(metadata.replay_pointer, GF256_PROFILE_PACK_REPLAY_POINTER);
            assert_eq!(metadata.tuning_corpus_id, GF256_PROFILE_TUNING_CORPUS_ID);
            assert!(!metadata.selected_tuning_candidate_id.is_empty());
            for rejected_id in metadata.rejected_tuning_candidate_ids {
                assert_ne!(metadata.selected_tuning_candidate_id, *rejected_id);
                assert!(!rejected_id.is_empty());
            }
            assert!(!metadata.command_bundle.is_empty());
            assert!(metadata.command_bundle.contains("rch exec --"));
            assert!(!metadata.decision_artifact_id.is_empty());
            assert!(!metadata.decision_role.is_empty());
            assert!(!metadata.decision_evidence_status.as_str().is_empty());
            assert!(!metadata.selected_candidate_summary.is_empty());
            assert!(!metadata.rejected_candidate_set_summary.is_empty());
        }
    }

    #[test]
    fn simd_profile_packs_raise_addmul_floor_for_small_lane_regression_guard() {
        let catalog = gf256_profile_pack_catalog();
        assert_eq!(catalog[0].addmul_min_lane, 0);
        let x86 = catalog
            .iter()
            .find(|metadata| metadata.profile_pack == Gf256ProfilePackId::X86Avx2BalancedV1)
            .expect("x86 profile pack must exist");
        assert_eq!(x86.addmul_min_total, 24 * 1024);
        assert_eq!(x86.addmul_max_total, 32 * 1024);
        assert_eq!(x86.addmul_min_lane, 8 * 1024);
        assert!(x86.addmul_min_total > (4096 + 4096));
        assert!(x86.addmul_min_lane > 1536);

        let neon = catalog
            .iter()
            .find(|metadata| metadata.profile_pack == Gf256ProfilePackId::Aarch64NeonBalancedV1)
            .expect("aarch64 profile pack must exist");
        assert_eq!(neon.addmul_min_total, 12 * 1024);
        assert_eq!(neon.addmul_max_total, 16 * 1024);
        assert_eq!(neon.addmul_min_lane, 2 * 1024);
    }

    #[test]
    fn x86_profile_pack_prefers_split_candidate_and_disables_mul_auto_window() {
        let x86 = gf256_profile_pack_catalog()
            .iter()
            .find(|metadata| metadata.profile_pack == Gf256ProfilePackId::X86Avx2BalancedV1)
            .expect("x86 profile pack must exist");
        assert_eq!(
            x86.selected_tuning_candidate_id,
            X86_SELECTED_TUNING_CANDIDATE
        );
        assert_ne!(
            x86.selected_tuning_candidate_id,
            X86_REJECTED_TUNING_CANDIDATES[0]
        );
        assert!(
            x86.mul_min_total > x86.mul_max_total,
            "x86 dual-mul auto window should be disabled by default",
        );
        assert_eq!(x86.addmul_min_total, 24 * 1024);
        assert_eq!(x86.addmul_max_total, 32 * 1024);
        assert_eq!(x86.addmul_min_lane, 8 * 1024);
    }

    #[test]
    fn tuning_candidate_catalog_is_deterministic_and_profile_aligned() {
        let catalog = gf256_tuning_candidate_catalog();
        assert_eq!(catalog.len(), 8);
        for candidate in catalog {
            assert!(!candidate.candidate_id.is_empty());
            assert!(candidate.tile_bytes > 0);
            assert!(candidate.unroll > 0);
            assert!(
                gf256_profile_pack_catalog()
                    .iter()
                    .any(|pack| pack.profile_pack == candidate.profile_pack),
                "candidate {} references unknown profile pack",
                candidate.candidate_id
            );
        }
    }

    #[test]
    fn profile_pack_selection_exposes_non_selected_profile_candidates() {
        let selected = select_profile_pack(Gf256Kernel::Scalar, None);
        assert_eq!(
            selected.rejected_candidates,
            REJECTED_PROFILE_SELECTED_SCALAR
        );
    }

    #[test]
    fn profile_pack_selection_falls_back_when_host_does_not_support_request() {
        let selected = select_profile_pack(
            Gf256Kernel::Scalar,
            Some(ProfilePackRequest::X86Avx2BalancedV1),
        );
        assert_eq!(
            selected.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            selected.architecture_class,
            Gf256ArchitectureClass::GenericScalar
        );
        assert_eq!(
            selected.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost)
        );
        assert_eq!(
            selected.rejected_candidates,
            REJECTED_PROFILE_SELECTED_SCALAR
        );
    }

    #[test]
    fn profile_pack_catalog_covers_every_known_profile_id_exactly_once() {
        let expected_profiles = [
            Gf256ProfilePackId::ScalarConservativeV1,
            Gf256ProfilePackId::X86Avx2BalancedV1,
            Gf256ProfilePackId::Aarch64NeonBalancedV1,
        ];
        let observed_profiles = GF256_PROFILE_PACK_CATALOG
            .iter()
            .map(|metadata| metadata.profile_pack.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let expected_profile_set = expected_profiles
            .iter()
            .map(|profile_pack| profile_pack.as_str())
            .collect::<std::collections::BTreeSet<_>>();

        assert_eq!(
            GF256_PROFILE_PACK_CATALOG.len(),
            expected_profiles.len(),
            "deterministic profile-pack catalog must contain exactly one entry per known profile id"
        );
        assert_eq!(
            observed_profiles, expected_profile_set,
            "deterministic profile-pack catalog must cover every known profile id"
        );

        for profile_pack in expected_profiles {
            assert_eq!(
                profile_pack_metadata_fixture(profile_pack).profile_pack,
                profile_pack,
                "profile-pack lookup must resolve to its exact metadata entry"
            );
        }
    }

    #[test]
    fn profile_pack_env_request_keeps_canonical_metadata_when_selection_stays_canonical() {
        let kernel = dispatch().kind;
        let architecture_class = architecture_class_for_kernel(kernel);
        let selection = select_profile_pack(kernel, Some(ProfilePackRequest::ScalarConservativeV1));
        let mut policy = policy_fixture_from_selection(selection);
        let catalog_profile = profile_pack_metadata_fixture(policy.profile_pack);
        policy.override_mask.set_profile_pack_env_requested();

        apply_effective_selection_contract(&mut policy);
        let metadata = effective_profile_pack_metadata(&policy);

        assert!(policy.override_mask.profile_pack_env_requested());
        assert_eq!(
            policy.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(policy.architecture_class, architecture_class);
        assert_eq!(policy.fallback_reason, None);
        assert_eq!(policy.rejected_candidates, REJECTED_PROFILE_SELECTED_SCALAR);
        assert!(
            policy_uses_canonical_selection_contract(&policy),
            "supported profile-pack env requests in Auto mode must keep canonical provenance"
        );
        assert_eq!(
            policy.selected_tuning_candidate_id,
            catalog_profile.selected_tuning_candidate_id
        );
        assert_eq!(
            policy.rejected_tuning_candidate_ids,
            catalog_profile.rejected_tuning_candidate_ids
        );
        assert_eq!(policy.replay_pointer, catalog_profile.replay_pointer);
        assert_eq!(policy.command_bundle, catalog_profile.command_bundle);
        assert_eq!(
            metadata.decision_artifact_id,
            catalog_profile.decision_artifact_id
        );
        assert_eq!(metadata.decision_role, catalog_profile.decision_role);
        assert_eq!(
            metadata.decision_evidence_status,
            catalog_profile.decision_evidence_status
        );
        assert_eq!(
            metadata.selected_candidate_summary,
            catalog_profile.selected_candidate_summary
        );
        assert_eq!(
            metadata.rejected_candidate_set_summary,
            catalog_profile.rejected_candidate_set_summary
        );
        assert_eq!(
            metadata.selected_mul_delta_vs_baseline_pct,
            catalog_profile.selected_mul_delta_vs_baseline_pct
        );
        assert_eq!(
            metadata.selected_addmul_delta_vs_baseline_pct,
            catalog_profile.selected_addmul_delta_vs_baseline_pct
        );
        assert_eq!(
            metadata.selected_targeted_addmul_average_delta_pct,
            catalog_profile.selected_targeted_addmul_average_delta_pct
        );
    }

    #[test]
    fn unsupported_profile_pack_env_request_falls_back_without_scrubbing_canonical_metadata() {
        let selection = select_profile_pack(
            Gf256Kernel::Scalar,
            Some(ProfilePackRequest::X86Avx2BalancedV1),
        );
        let mut policy = policy_fixture_from_selection(selection);
        let catalog_profile = profile_pack_metadata_fixture(policy.profile_pack);
        policy.override_mask.set_profile_pack_env_requested();

        apply_effective_selection_contract(&mut policy);
        let metadata = effective_profile_pack_metadata(&policy);

        assert!(policy.override_mask.profile_pack_env_requested());
        assert_eq!(
            policy.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost)
        );
        assert!(
            policy_uses_canonical_selection_contract(&policy),
            "unsupported profile-pack env requests should fall back to the canonical host profile"
        );
        assert_eq!(
            policy.selected_tuning_candidate_id,
            catalog_profile.selected_tuning_candidate_id
        );
        assert_eq!(
            metadata.decision_artifact_id,
            catalog_profile.decision_artifact_id
        );
        assert_eq!(metadata.decision_role, catalog_profile.decision_role);
        assert_eq!(
            metadata.decision_evidence_status,
            catalog_profile.decision_evidence_status
        );
        assert_eq!(
            metadata.selected_candidate_summary,
            catalog_profile.selected_candidate_summary
        );
        assert_eq!(
            metadata.rejected_candidate_set_summary,
            catalog_profile.rejected_candidate_set_summary
        );
        assert_eq!(
            metadata.selected_mul_delta_vs_baseline_pct,
            catalog_profile.selected_mul_delta_vs_baseline_pct
        );
        assert_eq!(
            metadata.selected_addmul_delta_vs_baseline_pct,
            catalog_profile.selected_addmul_delta_vs_baseline_pct
        );
        assert_eq!(
            metadata.selected_targeted_addmul_average_delta_pct,
            catalog_profile.selected_targeted_addmul_average_delta_pct
        );
    }

    #[test]
    fn unknown_profile_pack_env_request_falls_back_without_scrubbing_canonical_metadata() {
        let kernel = dispatch().kind;
        let architecture_class = architecture_class_for_kernel(kernel);
        let selection = select_profile_pack(kernel, None);
        let mut policy = policy_fixture_from_selection(selection);
        let catalog_profile = profile_pack_metadata_fixture(policy.profile_pack);
        policy.override_mask.set_profile_pack_env_requested();
        policy.fallback_reason = Some(Gf256ProfileFallbackReason::UnknownRequestedProfile);

        apply_effective_selection_contract(&mut policy);
        let metadata = effective_profile_pack_metadata(&policy);

        assert!(policy.override_mask.profile_pack_env_requested());
        assert_eq!(
            policy.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnknownRequestedProfile)
        );
        assert_eq!(policy.architecture_class, architecture_class);
        assert_eq!(
            policy.profile_pack,
            default_profile_pack_for_arch(architecture_class)
        );
        assert!(
            policy_uses_canonical_selection_contract(&policy),
            "unknown profile-pack env requests should fall back to the canonical host profile"
        );
        assert_eq!(
            policy.selected_tuning_candidate_id,
            catalog_profile.selected_tuning_candidate_id
        );
        assert_eq!(
            policy.rejected_tuning_candidate_ids,
            catalog_profile.rejected_tuning_candidate_ids
        );
        assert_eq!(
            metadata.decision_artifact_id,
            catalog_profile.decision_artifact_id
        );
        assert_eq!(metadata.decision_role, catalog_profile.decision_role);
        assert_eq!(
            metadata.decision_evidence_status,
            catalog_profile.decision_evidence_status
        );
        assert_eq!(
            metadata.selected_candidate_summary,
            catalog_profile.selected_candidate_summary
        );
        assert_eq!(
            metadata.rejected_candidate_set_summary,
            catalog_profile.rejected_candidate_set_summary
        );
        assert_eq!(
            metadata.selected_mul_delta_vs_baseline_pct,
            catalog_profile.selected_mul_delta_vs_baseline_pct
        );
        assert_eq!(
            metadata.selected_addmul_delta_vs_baseline_pct,
            catalog_profile.selected_addmul_delta_vs_baseline_pct
        );
        assert_eq!(
            metadata.selected_targeted_addmul_average_delta_pct,
            catalog_profile.selected_targeted_addmul_average_delta_pct
        );
    }

    #[test]
    fn unknown_dual_policy_env_request_falls_back_without_scrubbing_canonical_metadata() {
        let selection = select_profile_pack(dispatch().kind, None);
        let mut policy = policy_fixture_from_selection(selection);
        let catalog_profile = profile_pack_metadata_fixture(policy.profile_pack);
        policy.override_mask.set_dual_policy_env_requested();
        policy.mode_fallback_reason = Some(DualKernelModeFallbackReason::UnknownRequestedMode);

        apply_effective_selection_contract(&mut policy);
        let metadata = effective_profile_pack_metadata(&policy);

        assert!(policy.override_mask.dual_policy_env_requested());
        assert_eq!(policy.mode, DualKernelOverride::Auto);
        assert_eq!(
            policy.mode_fallback_reason,
            Some(DualKernelModeFallbackReason::UnknownRequestedMode)
        );
        assert!(
            policy_uses_canonical_selection_contract(&policy),
            "unknown dual-policy env requests should fall back to the canonical host policy"
        );
        assert_eq!(
            policy.selected_tuning_candidate_id,
            catalog_profile.selected_tuning_candidate_id
        );
        assert_eq!(
            policy.rejected_tuning_candidate_ids,
            catalog_profile.rejected_tuning_candidate_ids
        );
        assert_eq!(
            metadata.decision_artifact_id,
            catalog_profile.decision_artifact_id
        );
        assert_eq!(metadata.decision_role, catalog_profile.decision_role);
        assert_eq!(
            metadata.decision_evidence_status,
            catalog_profile.decision_evidence_status
        );
    }

    #[test]
    fn malformed_dual_policy_env_request_preserves_canonical_manifest_provenance() {
        with_gf256_env(
            "ASUPERSYNC_GF256_DUAL_POLICY",
            "definitely-not-valid",
            || {
                let kernel = dispatch().kind;
                let policy = detect_dual_policy();
                let expected_profile = profile_pack_metadata_fixture(policy.profile_pack);
                let snapshot = dual_kernel_policy_snapshot_for(&policy, kernel);
                let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, kernel);

                assert_eq!(policy.mode, DualKernelOverride::Auto);
                assert!(policy_uses_canonical_selection_contract(&policy));
                assert!(snapshot.override_mask.dual_policy_env_requested());
                assert_eq!(snapshot.mode, DualKernelMode::Auto);
                assert_eq!(
                    snapshot.mode_fallback_reason,
                    Some(DualKernelModeFallbackReason::UnknownRequestedMode)
                );
                assert_eq!(snapshot.profile_pack, expected_profile.profile_pack);
                assert_eq!(snapshot.replay_pointer, expected_profile.replay_pointer);
                assert_eq!(snapshot.command_bundle, expected_profile.command_bundle);
                assert_eq!(
                    snapshot.selected_tuning_candidate_id,
                    expected_profile.selected_tuning_candidate_id
                );
                assert_eq!(
                    snapshot.rejected_tuning_candidate_ids,
                    expected_profile.rejected_tuning_candidate_ids
                );
                assert_eq!(
                    snapshot.decision_artifact_id,
                    expected_profile.decision_artifact_id
                );
                assert_eq!(snapshot.decision_role, expected_profile.decision_role);
                assert_eq!(
                    snapshot.decision_evidence_status,
                    expected_profile.decision_evidence_status
                );
                assert_eq!(
                    manifest.active_policy.mode_fallback_reason,
                    Some(DualKernelModeFallbackReason::UnknownRequestedMode)
                );
                assert!(
                    manifest
                        .active_policy
                        .override_mask
                        .dual_policy_env_requested()
                );
                assert_eq!(manifest.active_profile_metadata, *expected_profile);
                assert_eq!(
                    manifest.active_profile_metadata.profile_pack,
                    expected_profile.profile_pack
                );
                assert_eq!(
                    manifest.active_profile_metadata.architecture_class,
                    expected_profile.architecture_class
                );
                assert_eq!(
                    manifest
                        .active_profile_metadata
                        .selected_tuning_candidate_id,
                    expected_profile.selected_tuning_candidate_id
                );
                assert_eq!(
                    manifest.active_profile_metadata.decision_artifact_id,
                    expected_profile.decision_artifact_id
                );
                assert_eq!(
                    manifest.active_selected_tuning_candidate,
                    tuning_candidate_metadata(expected_profile.selected_tuning_candidate_id)
                );
            },
        );
    }

    #[test]
    fn unsupported_profile_request_with_forced_mode_preserves_fallback_reason_while_scrubbing_provenance()
     {
        with_gf256_envs(
            &[
                (
                    "ASUPERSYNC_GF256_PROFILE_PACK",
                    unsupported_profile_pack_env_value_for_kernel(dispatch().kind),
                ),
                ("ASUPERSYNC_GF256_DUAL_POLICY", "fused"),
            ],
            || {
                let kernel = dispatch().kind;
                let expected_profile = default_profile_metadata_for_kernel(kernel);

                let policy = detect_dual_policy();
                let snapshot = dual_kernel_policy_snapshot_for(&policy, kernel);
                let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, kernel);

                assert_eq!(policy.profile_pack, expected_profile.profile_pack);
                assert_eq!(
                    policy.fallback_reason,
                    Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost)
                );
                assert_eq!(policy.mode, DualKernelOverride::ForceFused);
                assert!(policy.override_mask.profile_pack_env_requested());
                assert!(policy.override_mask.dual_policy_env_requested());
                assert!(!policy_uses_canonical_selection_contract(&policy));
                assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
                assert_eq!(
                    policy.selected_tuning_candidate_id,
                    MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
                );

                assert_eq!(snapshot.profile_pack, expected_profile.profile_pack);
                assert_eq!(
                    snapshot.fallback_reason,
                    Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost)
                );
                assert_eq!(snapshot.mode, DualKernelMode::Fused);
                assert_eq!(
                    snapshot.decision_artifact_id,
                    MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
                );
                assert_eq!(snapshot.decision_role, MANUAL_OVERRIDE_DECISION_ROLE);
                assert_eq!(
                    snapshot.decision_evidence_status,
                    MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
                );

                assert_eq!(manifest.active_policy, snapshot);
                assert_eq!(
                    manifest.active_profile_metadata.profile_pack,
                    expected_profile.profile_pack
                );
                assert_eq!(
                    manifest.active_profile_metadata.architecture_class,
                    expected_profile.architecture_class
                );
                assert_eq!(
                    manifest.active_profile_metadata.decision_artifact_id,
                    MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
                );
                assert_eq!(manifest.active_selected_tuning_candidate, None);
            },
        );
    }

    #[test]
    fn unknown_profile_request_with_numeric_override_preserves_fallback_reason_while_scrubbing_provenance()
     {
        with_gf256_envs(
            &[
                ("ASUPERSYNC_GF256_PROFILE_PACK", "definitely-not-a-profile"),
                ("ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL", "16384"),
            ],
            || {
                let kernel = dispatch().kind;
                let expected_profile = default_profile_metadata_for_kernel(kernel);

                let policy = detect_dual_policy();
                let snapshot = dual_kernel_policy_snapshot_for(&policy, kernel);
                let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, kernel);

                assert_eq!(policy.profile_pack, expected_profile.profile_pack);
                assert_eq!(
                    policy.fallback_reason,
                    Some(Gf256ProfileFallbackReason::UnknownRequestedProfile)
                );
                assert_eq!(policy.mode, DualKernelOverride::Auto);
                assert!(policy.override_mask.profile_pack_env_requested());
                assert!(policy.override_mask.addmul_min_total_env_override());
                assert!(!policy_uses_canonical_selection_contract(&policy));
                assert_eq!(policy.addmul_min_total, 16 * 1024);
                assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
                assert_eq!(
                    policy.selected_tuning_candidate_id,
                    MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
                );

                assert_eq!(snapshot.profile_pack, expected_profile.profile_pack);
                assert_eq!(
                    snapshot.fallback_reason,
                    Some(Gf256ProfileFallbackReason::UnknownRequestedProfile)
                );
                assert_eq!(snapshot.mode, DualKernelMode::Auto);
                assert_eq!(
                    snapshot.decision_artifact_id,
                    MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
                );
                assert_eq!(snapshot.decision_role, MANUAL_OVERRIDE_DECISION_ROLE);
                assert_eq!(
                    snapshot.decision_evidence_status,
                    MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
                );

                assert_eq!(manifest.active_policy, snapshot);
                assert_eq!(
                    manifest.active_profile_metadata.profile_pack,
                    expected_profile.profile_pack
                );
                assert_eq!(
                    manifest.active_profile_metadata.architecture_class,
                    expected_profile.architecture_class
                );
                assert_eq!(manifest.active_profile_metadata.addmul_min_total, 16 * 1024);
                assert_eq!(
                    manifest.active_profile_metadata.decision_artifact_id,
                    MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
                );
                assert_eq!(manifest.active_selected_tuning_candidate, None);
            },
        );
    }

    #[test]
    fn supported_profile_pack_env_request_keeps_host_and_profile_architectures_truthful() {
        let selection = ProfilePackSelection {
            profile_pack: Gf256ProfilePackId::ScalarConservativeV1,
            architecture_class: Gf256ArchitectureClass::X86Avx2,
            fallback_reason: None,
            rejected_candidates: REJECTED_PROFILE_SELECTED_SCALAR,
        };
        let mut policy = policy_fixture_from_selection(selection);
        policy.override_mask.set_profile_pack_env_requested();

        apply_effective_selection_contract(&mut policy);
        let metadata = effective_profile_pack_metadata(&policy);
        let candidate = tuning_candidate_metadata(policy.selected_tuning_candidate_id)
            .expect("supported scalar profile request should keep catalog tuning metadata");

        assert!(policy_uses_canonical_selection_contract(&policy));
        assert!(policy.override_mask.profile_pack_env_requested());
        assert_eq!(policy.architecture_class, Gf256ArchitectureClass::X86Avx2);
        assert_eq!(
            policy.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            metadata.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            metadata.architecture_class,
            Gf256ArchitectureClass::GenericScalar
        );
        assert_ne!(policy.architecture_class, metadata.architecture_class);
        assert_eq!(
            metadata.selected_tuning_candidate_id,
            policy.selected_tuning_candidate_id
        );
        assert_eq!(
            candidate.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            candidate.architecture_class,
            Gf256ArchitectureClass::GenericScalar
        );
        assert_eq!(metadata.decision_artifact_id, SCALAR_DECISION_ARTIFACT_ID);
        assert_eq!(metadata.decision_role, SCALAR_DECISION_ROLE);
        assert_eq!(
            metadata.decision_evidence_status,
            SCALAR_DECISION_EVIDENCE_STATUS
        );
        assert_eq!(
            metadata.selected_candidate_summary,
            SCALAR_SELECTED_CANDIDATE_SUMMARY
        );
        assert_eq!(
            metadata.rejected_candidate_set_summary,
            SCALAR_REJECTED_CANDIDATE_SET_SUMMARY
        );
        assert_eq!(
            metadata.selected_mul_delta_vs_baseline_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert_eq!(
            metadata.selected_addmul_delta_vs_baseline_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert_eq!(
            metadata.selected_targeted_addmul_average_delta_pct,
            NA_PROFILE_DELTA_PCT
        );
    }

    #[test]
    fn supported_profile_request_with_forced_mode_scrubs_provenance_while_preserving_profile_truth()
    {
        with_gf256_envs(
            &[
                ("ASUPERSYNC_GF256_PROFILE_PACK", "scalar-conservative-v1"),
                ("ASUPERSYNC_GF256_DUAL_POLICY", "fused"),
            ],
            || {
                let kernel = dispatch().kind;
                let policy = detect_dual_policy();
                let snapshot = dual_kernel_policy_snapshot_for(&policy, kernel);
                let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, kernel);

                assert_eq!(policy.mode, DualKernelOverride::ForceFused);
                assert!(policy.override_mask.dual_policy_env_requested());
                assert_eq!(snapshot.mode, DualKernelMode::Fused);
                assert_supported_profile_request_scrubs_provenance_while_preserving_profile_truth(
                    &policy, &snapshot, &manifest, kernel,
                );
            },
        );
    }

    #[test]
    fn supported_profile_request_with_numeric_override_scrubs_provenance_while_preserving_profile_truth()
     {
        with_gf256_envs(
            &[
                ("ASUPERSYNC_GF256_PROFILE_PACK", "scalar-conservative-v1"),
                ("ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL", "16384"),
            ],
            || {
                let kernel = dispatch().kind;
                let policy = detect_dual_policy();
                let snapshot = dual_kernel_policy_snapshot_for(&policy, kernel);
                let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, kernel);

                assert_eq!(policy.mode, DualKernelOverride::Auto);
                assert!(policy.override_mask.addmul_min_total_env_override());
                assert_eq!(policy.addmul_min_total, 16 * 1024);
                assert_eq!(snapshot.mode, DualKernelMode::Auto);
                assert_eq!(manifest.active_profile_metadata.addmul_min_total, 16 * 1024);
                assert_supported_profile_request_scrubs_provenance_while_preserving_profile_truth(
                    &policy, &snapshot, &manifest, kernel,
                );
            },
        );
    }

    #[test]
    fn manual_numeric_override_scrubs_canonical_selection_metadata() {
        let mut policy = DualKernelPolicy {
            profile_pack: Gf256ProfilePackId::X86Avx2BalancedV1,
            architecture_class: Gf256ArchitectureClass::X86Avx2,
            tuning_corpus_id: GF256_PROFILE_TUNING_CORPUS_ID,
            selected_tuning_candidate_id: X86_SELECTED_TUNING_CANDIDATE,
            rejected_tuning_candidate_ids: X86_REJECTED_TUNING_CANDIDATES,
            fallback_reason: None,
            rejected_candidates: REJECTED_PROFILE_SELECTED_X86_AVX2,
            replay_pointer: GF256_PROFILE_PACK_REPLAY_POINTER,
            command_bundle: GF256_PROFILE_PACK_COMMAND_BUNDLE,
            mode: DualKernelOverride::Auto,
            mode_fallback_reason: None,
            override_mask: DualKernelOverrideMask::empty(),
            mul_min_total: usize::MAX,
            mul_max_total: 0,
            addmul_min_total: 24 * 1024,
            addmul_max_total: 32 * 1024,
            addmul_min_lane: 8 * 1024,
            max_lane_ratio: 8,
        };
        policy.override_mask.set_addmul_min_total_env_override();
        policy.addmul_min_total = 16 * 1024;

        apply_effective_selection_contract(&mut policy);
        let metadata = effective_profile_pack_metadata(&policy);

        assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
        assert_eq!(
            policy.selected_tuning_candidate_id,
            MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
        );
        assert!(policy.rejected_tuning_candidate_ids.is_empty());
        assert_eq!(metadata.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
        assert_eq!(policy.replay_pointer, MANUAL_OVERRIDE_REPLAY_POINTER);
        assert_eq!(policy.command_bundle, MANUAL_OVERRIDE_COMMAND_BUNDLE);
        assert_eq!(
            metadata.decision_artifact_id,
            MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
        );
        assert_eq!(metadata.decision_role, MANUAL_OVERRIDE_DECISION_ROLE);
        assert_eq!(
            metadata.decision_evidence_status,
            MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
        );
        assert_eq!(
            metadata.selected_candidate_summary,
            MANUAL_OVERRIDE_SELECTED_CANDIDATE_SUMMARY
        );
        assert_eq!(
            metadata.rejected_candidate_set_summary,
            MANUAL_OVERRIDE_REJECTED_CANDIDATE_SET_SUMMARY
        );
        assert_eq!(metadata.addmul_min_total, 16 * 1024);
        assert_eq!(
            metadata.selected_mul_delta_vs_baseline_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert_eq!(
            metadata.selected_addmul_delta_vs_baseline_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert_eq!(
            metadata.selected_targeted_addmul_average_delta_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert!(metadata.rejected_tuning_candidate_ids.is_empty());
        assert_eq!(
            tuning_candidate_metadata(policy.selected_tuning_candidate_id),
            None
        );
    }

    // SECURITY (commit 4cca31a4): malformed numeric GF256 env overrides now
    // FAIL CLOSED with a panic rather than marking the override active while
    // silently retaining the catalog default. A malformed value that was
    // accepted-but-scrubbed could let an attacker flip `*_env_override()` to
    // `true` (suppressing the canonical-selection provenance) without supplying
    // a usable value — so `detect_dual_policy()` must reject it outright. These
    // tests pin that fail-closed contract for each numeric override key.
    #[test]
    #[should_panic(expected = "Invalid environment variable value for")]
    fn malformed_numeric_addmul_floor_request_scrubs_canonical_selection_metadata() {
        with_gf256_env(
            "ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL",
            "not-a-number",
            || {
                // Must panic before producing any policy — a malformed numeric
                // override cannot be allowed to scrub canonical provenance.
                let _ = detect_dual_policy();
            },
        );
    }

    #[test]
    #[should_panic(expected = "Invalid environment variable value for")]
    fn malformed_numeric_lane_ratio_request_preserves_catalog_value_but_scrubs_provenance() {
        with_gf256_env("ASUPERSYNC_GF256_DUAL_MAX_LANE_RATIO", "eight", || {
            let _ = detect_dual_policy();
        });
    }

    #[test]
    fn numeric_env_overrides_trim_surrounding_whitespace_before_parse() {
        let cases = [
            (
                "ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL",
                " 12345 ",
                12_345usize,
            ),
            (
                "ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL",
                "\n23456\t",
                23_456usize,
            ),
            (
                "ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL",
                " 34567\n",
                34_567usize,
            ),
            (
                "ASUPERSYNC_GF256_DUAL_ADDMUL_MAX_TOTAL",
                "\t45678 ",
                45_678usize,
            ),
            (
                "ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_LANE",
                " 5678 ",
                5_678usize,
            ),
            ("ASUPERSYNC_GF256_DUAL_MAX_LANE_RATIO", "\n3 ", 3usize),
        ];

        for (key, raw_value, expected) in cases {
            with_gf256_env(key, raw_value, || {
                let policy = detect_dual_policy();
                let metadata = effective_profile_pack_metadata(&policy);

                assert!(
                    !policy_uses_canonical_selection_contract(&policy),
                    "numeric env overrides should still scrub canonical provenance: {key}"
                );
                assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
                assert_eq!(policy.replay_pointer, MANUAL_OVERRIDE_REPLAY_POINTER);
                assert_eq!(policy.command_bundle, MANUAL_OVERRIDE_COMMAND_BUNDLE);
                assert_eq!(
                    metadata.decision_artifact_id,
                    MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
                );
                assert_eq!(metadata.decision_role, MANUAL_OVERRIDE_DECISION_ROLE);
                assert_eq!(
                    metadata.decision_evidence_status,
                    MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
                );

                match key {
                    "ASUPERSYNC_GF256_DUAL_MUL_MIN_TOTAL" => {
                        assert!(policy.override_mask.mul_min_total_env_override());
                        assert_eq!(policy.mul_min_total, expected);
                    }
                    "ASUPERSYNC_GF256_DUAL_MUL_MAX_TOTAL" => {
                        assert!(policy.override_mask.mul_max_total_env_override());
                        assert_eq!(policy.mul_max_total, expected);
                    }
                    "ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_TOTAL" => {
                        assert!(policy.override_mask.addmul_min_total_env_override());
                        assert_eq!(policy.addmul_min_total, expected);
                    }
                    "ASUPERSYNC_GF256_DUAL_ADDMUL_MAX_TOTAL" => {
                        assert!(policy.override_mask.addmul_max_total_env_override());
                        assert_eq!(policy.addmul_max_total, expected);
                    }
                    "ASUPERSYNC_GF256_DUAL_ADDMUL_MIN_LANE" => {
                        assert!(policy.override_mask.addmul_min_lane_env_override());
                        assert_eq!(policy.addmul_min_lane, expected);
                    }
                    "ASUPERSYNC_GF256_DUAL_MAX_LANE_RATIO" => {
                        assert!(policy.override_mask.max_lane_ratio_env_override());
                        assert_eq!(policy.max_lane_ratio, expected);
                    }
                    _ => unreachable!("unexpected numeric override key"),
                }
            });
        }
    }

    #[test]
    fn max_lane_ratio_numeric_override_clamps_zero_to_one() {
        with_gf256_env("ASUPERSYNC_GF256_DUAL_MAX_LANE_RATIO", "0", || {
            let policy = detect_dual_policy();
            let metadata = effective_profile_pack_metadata(&policy);

            assert!(policy.override_mask.max_lane_ratio_env_override());
            assert_eq!(policy.max_lane_ratio, 1);
            assert!(!policy_uses_canonical_selection_contract(&policy));
            assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
            assert_eq!(policy.replay_pointer, MANUAL_OVERRIDE_REPLAY_POINTER);
            assert_eq!(policy.command_bundle, MANUAL_OVERRIDE_COMMAND_BUNDLE);
            assert_eq!(
                metadata.decision_artifact_id,
                MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
            );
            assert_eq!(metadata.decision_role, MANUAL_OVERRIDE_DECISION_ROLE);
            assert_eq!(
                metadata.decision_evidence_status,
                MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
            );
        });
    }

    #[test]
    fn forced_mode_scrubs_canonical_selection_metadata() {
        let mut policy = DualKernelPolicy {
            profile_pack: Gf256ProfilePackId::X86Avx2BalancedV1,
            architecture_class: Gf256ArchitectureClass::X86Avx2,
            tuning_corpus_id: GF256_PROFILE_TUNING_CORPUS_ID,
            selected_tuning_candidate_id: X86_SELECTED_TUNING_CANDIDATE,
            rejected_tuning_candidate_ids: X86_REJECTED_TUNING_CANDIDATES,
            fallback_reason: None,
            rejected_candidates: REJECTED_PROFILE_SELECTED_X86_AVX2,
            replay_pointer: GF256_PROFILE_PACK_REPLAY_POINTER,
            command_bundle: GF256_PROFILE_PACK_COMMAND_BUNDLE,
            mode: DualKernelOverride::ForceSequential,
            mode_fallback_reason: None,
            override_mask: DualKernelOverrideMask::empty(),
            mul_min_total: usize::MAX,
            mul_max_total: 0,
            addmul_min_total: 24 * 1024,
            addmul_max_total: 32 * 1024,
            addmul_min_lane: 8 * 1024,
            max_lane_ratio: 8,
        };

        apply_effective_selection_contract(&mut policy);
        let metadata = effective_profile_pack_metadata(&policy);

        assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
        assert_eq!(
            policy.selected_tuning_candidate_id,
            MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
        );
        assert_eq!(metadata.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
        assert_eq!(metadata.decision_role, MANUAL_OVERRIDE_DECISION_ROLE);
        assert_eq!(
            metadata.decision_evidence_status,
            MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
        );
        assert_eq!(
            metadata.selected_candidate_summary,
            MANUAL_OVERRIDE_SELECTED_CANDIDATE_SUMMARY
        );
        assert_eq!(
            metadata.rejected_candidate_set_summary,
            MANUAL_OVERRIDE_REJECTED_CANDIDATE_SET_SUMMARY
        );
        assert_eq!(
            metadata.selected_mul_delta_vs_baseline_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert_eq!(
            metadata.selected_addmul_delta_vs_baseline_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert_eq!(
            metadata.selected_targeted_addmul_average_delta_pct,
            NA_PROFILE_DELTA_PCT
        );
        assert!(policy.rejected_tuning_candidate_ids.is_empty());
        assert!(metadata.rejected_tuning_candidate_ids.is_empty());
    }

    #[test]
    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn forced_scalar_profile_selection_reports_non_selected_simd_packs() {
        let selected = select_profile_pack(
            Gf256Kernel::X86Avx2,
            Some(ProfilePackRequest::ScalarConservativeV1),
        );
        assert_eq!(
            selected.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(selected.architecture_class, Gf256ArchitectureClass::X86Avx2);
        assert_eq!(selected.fallback_reason, None);
        assert_eq!(
            selected.rejected_candidates,
            REJECTED_PROFILE_SELECTED_SCALAR
        );
    }

    #[test]
    fn dual_policy_snapshot_exposes_profile_pack_metadata() {
        let snapshot = dual_kernel_policy_snapshot();
        let effective_profile = effective_profile_pack_metadata(dual_policy());
        assert_eq!(
            snapshot.profile_schema_version,
            GF256_PROFILE_PACK_SCHEMA_VERSION
        );
        assert_eq!(
            snapshot.architecture_class,
            architecture_class_for_kernel(snapshot.kernel)
        );
        assert_eq!(
            snapshot.tuning_corpus_id,
            effective_profile.tuning_corpus_id
        );
        assert!(!snapshot.selected_tuning_candidate_id.is_empty());
        assert!(!snapshot.command_bundle.is_empty());
        assert!(snapshot.command_bundle.contains("gf256_primitives"));
        assert!(!snapshot.command_bundle.contains("gf256_dual_policy"));
        assert_eq!(snapshot.replay_pointer, effective_profile.replay_pointer);
        assert!(!snapshot.decision_artifact_id.is_empty());
        assert!(!snapshot.decision_role.is_empty());
        assert!(!snapshot.decision_evidence_status.as_str().is_empty());
        assert_eq!(
            snapshot.decision_artifact_id,
            effective_profile.decision_artifact_id
        );
        assert_eq!(snapshot.decision_role, effective_profile.decision_role);
        assert_eq!(
            snapshot.decision_evidence_status,
            effective_profile.decision_evidence_status
        );
        assert!(!snapshot.profile_pack.as_str().is_empty());
        for rejected_id in snapshot.rejected_tuning_candidate_ids {
            assert_ne!(snapshot.selected_tuning_candidate_id, *rejected_id);
            assert!(!rejected_id.is_empty());
        }
        for rejected in snapshot.rejected_candidates {
            assert_ne!(*rejected, snapshot.profile_pack);
            assert!(!rejected.as_str().is_empty());
        }
        if let Some(reason) = snapshot.fallback_reason {
            assert!(!reason.as_str().is_empty());
        }
        if let Some(reason) = snapshot.mode_fallback_reason {
            assert!(!reason.as_str().is_empty());
        }
    }

    #[test]
    fn unsupported_profile_pack_snapshot_preserves_canonical_manifest_provenance() {
        let selection = select_profile_pack(
            Gf256Kernel::Scalar,
            Some(ProfilePackRequest::X86Avx2BalancedV1),
        );
        let mut policy = policy_fixture_from_selection(selection);
        let expected_profile = profile_pack_metadata_fixture(policy.profile_pack);
        policy.override_mask.set_profile_pack_env_requested();

        apply_effective_selection_contract(&mut policy);
        let snapshot = dual_kernel_policy_snapshot_for(&policy, Gf256Kernel::Scalar);
        let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, Gf256Kernel::Scalar);

        assert_eq!(
            snapshot.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost)
        );
        assert!(snapshot.override_mask.profile_pack_env_requested());
        assert_eq!(snapshot.kernel, Gf256Kernel::Scalar);
        assert_eq!(snapshot.profile_pack, expected_profile.profile_pack);
        assert_eq!(
            snapshot.selected_tuning_candidate_id,
            expected_profile.selected_tuning_candidate_id
        );
        assert_eq!(
            snapshot.decision_artifact_id,
            expected_profile.decision_artifact_id
        );
        assert_eq!(snapshot.decision_role, expected_profile.decision_role);
        assert_eq!(
            snapshot.decision_evidence_status,
            expected_profile.decision_evidence_status
        );
        assert_eq!(
            manifest.active_policy.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnsupportedProfileForHost)
        );
        assert_eq!(
            manifest.active_profile_metadata.profile_pack,
            expected_profile.profile_pack
        );
        assert_eq!(
            manifest.active_profile_metadata.architecture_class,
            expected_profile.architecture_class
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .selected_tuning_candidate_id,
            expected_profile.selected_tuning_candidate_id
        );
        assert_eq!(
            manifest.active_profile_metadata.decision_artifact_id,
            expected_profile.decision_artifact_id
        );
        assert_eq!(
            manifest.active_selected_tuning_candidate,
            tuning_candidate_metadata(expected_profile.selected_tuning_candidate_id)
        );
    }

    #[test]
    fn unknown_profile_pack_snapshot_preserves_canonical_manifest_provenance() {
        let selection = select_profile_pack(Gf256Kernel::Scalar, None);
        let mut policy = policy_fixture_from_selection(selection);
        let expected_profile = profile_pack_metadata_fixture(policy.profile_pack);
        policy.override_mask.set_profile_pack_env_requested();
        policy.fallback_reason = Some(Gf256ProfileFallbackReason::UnknownRequestedProfile);

        apply_effective_selection_contract(&mut policy);
        let snapshot = dual_kernel_policy_snapshot_for(&policy, Gf256Kernel::Scalar);
        let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, Gf256Kernel::Scalar);

        assert_eq!(
            snapshot.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnknownRequestedProfile)
        );
        assert!(snapshot.override_mask.profile_pack_env_requested());
        assert_eq!(snapshot.kernel, Gf256Kernel::Scalar);
        assert_eq!(snapshot.profile_pack, expected_profile.profile_pack);
        assert_eq!(
            snapshot.selected_tuning_candidate_id,
            expected_profile.selected_tuning_candidate_id
        );
        assert_eq!(
            snapshot.rejected_tuning_candidate_ids,
            expected_profile.rejected_tuning_candidate_ids
        );
        assert_eq!(
            manifest.active_policy.fallback_reason,
            Some(Gf256ProfileFallbackReason::UnknownRequestedProfile)
        );
        assert_eq!(
            manifest.active_profile_metadata.profile_pack,
            expected_profile.profile_pack
        );
        assert_eq!(
            manifest.active_profile_metadata.architecture_class,
            expected_profile.architecture_class
        );
        assert_eq!(
            manifest.active_profile_metadata.selected_candidate_summary,
            expected_profile.selected_candidate_summary
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .rejected_candidate_set_summary,
            expected_profile.rejected_candidate_set_summary
        );
        assert_eq!(
            manifest.active_selected_tuning_candidate,
            tuning_candidate_metadata(expected_profile.selected_tuning_candidate_id)
        );
    }

    #[test]
    #[cfg(all(
        feature = "simd-intrinsics",
        any(target_arch = "x86", target_arch = "x86_64")
    ))]
    fn supported_profile_pack_snapshot_keeps_host_and_selected_profile_architectures_distinct() {
        let selection = ProfilePackSelection {
            profile_pack: Gf256ProfilePackId::ScalarConservativeV1,
            architecture_class: Gf256ArchitectureClass::X86Avx2,
            fallback_reason: None,
            rejected_candidates: REJECTED_PROFILE_SELECTED_SCALAR,
        };
        let mut policy = policy_fixture_from_selection(selection);
        policy.override_mask.set_profile_pack_env_requested();

        apply_effective_selection_contract(&mut policy);
        let snapshot = dual_kernel_policy_snapshot_for(&policy, Gf256Kernel::X86Avx2);
        let manifest = gf256_profile_pack_manifest_snapshot_for(&policy, Gf256Kernel::X86Avx2);

        assert_eq!(snapshot.kernel, Gf256Kernel::X86Avx2);
        assert_eq!(snapshot.architecture_class, Gf256ArchitectureClass::X86Avx2);
        assert_eq!(
            snapshot.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            manifest.active_profile_metadata.profile_pack,
            Gf256ProfilePackId::ScalarConservativeV1
        );
        assert_eq!(
            manifest.active_profile_metadata.architecture_class,
            Gf256ArchitectureClass::GenericScalar
        );
        assert_ne!(
            snapshot.architecture_class,
            manifest.active_profile_metadata.architecture_class
        );
        assert_eq!(manifest.active_policy, snapshot);
        assert_eq!(
            manifest.active_selected_tuning_candidate,
            tuning_candidate_metadata(snapshot.selected_tuning_candidate_id)
        );
    }

    #[test]
    fn profile_pack_manifest_snapshot_debug_clone_copy_eq() {
        let manifest = gf256_profile_pack_manifest_snapshot();
        let copied = manifest;
        let cloned = manifest;
        assert_eq!(copied, cloned);
        let dbg = format!("{manifest:?}");
        assert!(dbg.contains("Gf256ProfilePackManifestSnapshot"));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn profile_pack_manifest_snapshot_is_deterministic_and_self_consistent() {
        let manifest = gf256_profile_pack_manifest_snapshot();
        let policy = manifest.active_policy;
        let canonical_selection = policy_uses_canonical_selection_contract(dual_policy());
        assert_eq!(
            manifest.schema_version,
            GF256_PROFILE_PACK_MANIFEST_SCHEMA_VERSION
        );
        assert_eq!(
            policy.profile_schema_version,
            GF256_PROFILE_PACK_SCHEMA_VERSION
        );
        assert_eq!(
            manifest.active_profile_metadata.profile_pack,
            policy.profile_pack
        );
        assert_eq!(
            manifest.active_profile_metadata.tuning_corpus_id,
            policy.tuning_corpus_id
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .selected_tuning_candidate_id,
            policy.selected_tuning_candidate_id
        );
        assert_eq!(
            manifest
                .active_profile_metadata
                .rejected_tuning_candidate_ids,
            policy.rejected_tuning_candidate_ids
        );
        assert_eq!(
            manifest.active_profile_metadata.addmul_min_lane,
            policy.addmul_min_lane
        );
        assert_eq!(
            manifest.active_profile_metadata.decision_artifact_id,
            policy.decision_artifact_id
        );
        assert_eq!(
            manifest.active_profile_metadata.decision_role,
            policy.decision_role
        );
        assert_eq!(
            manifest.active_profile_metadata.decision_evidence_status,
            policy.decision_evidence_status
        );
        assert!(
            manifest
                .profile_pack_catalog
                .iter()
                .any(|metadata| metadata.profile_pack == policy.profile_pack)
        );
        let catalog_profile = profile_pack_metadata_fixture(policy.profile_pack);
        assert_eq!(
            manifest.active_profile_metadata.architecture_class,
            catalog_profile.architecture_class
        );
        if canonical_selection {
            let selected = manifest
                .active_selected_tuning_candidate
                .expect("selected tuning candidate must exist in deterministic catalog");
            assert_eq!(selected.candidate_id, policy.selected_tuning_candidate_id);
            assert_eq!(selected.profile_pack, policy.profile_pack);
            assert_eq!(
                manifest.active_profile_metadata.decision_artifact_id,
                catalog_profile.decision_artifact_id
            );
            assert_eq!(
                manifest.active_profile_metadata.decision_evidence_status,
                catalog_profile.decision_evidence_status
            );
            assert_eq!(
                manifest.active_profile_metadata.tuning_corpus_id,
                catalog_profile.tuning_corpus_id
            );
        } else {
            assert_eq!(manifest.active_selected_tuning_candidate, None);
            assert_eq!(policy.tuning_corpus_id, MANUAL_OVERRIDE_TUNING_CORPUS_ID);
            assert_eq!(
                policy.selected_tuning_candidate_id,
                MANUAL_OVERRIDE_SELECTED_TUNING_CANDIDATE
            );
            assert_eq!(
                manifest.active_profile_metadata.tuning_corpus_id,
                MANUAL_OVERRIDE_TUNING_CORPUS_ID
            );
            assert_eq!(
                manifest.active_profile_metadata.decision_artifact_id,
                MANUAL_OVERRIDE_DECISION_ARTIFACT_ID
            );
            assert_eq!(
                manifest.active_profile_metadata.decision_evidence_status,
                MANUAL_OVERRIDE_DECISION_EVIDENCE_STATUS
            );
        }
        assert_eq!(
            manifest.environment_metadata.target_arch,
            std::env::consts::ARCH
        );
        assert_eq!(
            manifest.environment_metadata.target_os,
            std::env::consts::OS
        );
        assert!(!manifest.environment_metadata.target_env.is_empty());
        assert!(matches!(
            manifest.environment_metadata.target_endian,
            "little" | "big"
        ));
        assert!(matches!(
            manifest.environment_metadata.target_pointer_width_bits,
            16 | 32 | 64 | 128
        ));
        assert!(manifest.profile_pack_catalog.len() >= 3);
        assert!(manifest.tuning_candidate_catalog.len() >= 3);
    }

    #[test]
    fn x86_profile_pack_decision_metadata_matches_current_contract() {
        let x86 = gf256_profile_pack_catalog()
            .iter()
            .find(|metadata| metadata.profile_pack == Gf256ProfilePackId::X86Avx2BalancedV1)
            .expect("x86 profile-pack metadata must exist");

        assert_eq!(x86.decision_artifact_id, X86_DECISION_ARTIFACT_ID);
        assert_eq!(x86.decision_role, X86_DECISION_ROLE);
        assert_eq!(
            x86.selected_candidate_summary,
            X86_SELECTED_CANDIDATE_SUMMARY
        );
        assert_eq!(
            x86.rejected_candidate_set_summary,
            X86_REJECTED_CANDIDATE_SET_SUMMARY
        );
        assert_eq!(
            x86.selected_mul_delta_vs_baseline_pct,
            X86_SELECTED_MUL_DELTA_VS_BASELINE_PCT
        );
        assert_eq!(
            x86.selected_addmul_delta_vs_baseline_pct,
            X86_SELECTED_ADDMUL_DELTA_VS_BASELINE_PCT
        );
        assert_eq!(
            x86.selected_targeted_addmul_average_delta_pct,
            X86_SELECTED_TARGETED_ADDMUL_AVERAGE_DELTA_PCT
        );
        assert_eq!(x86.decision_evidence_status, X86_DECISION_EVIDENCE_STATUS);
    }

    #[test]
    fn aarch64_profile_pack_decision_metadata_is_explicitly_pending() {
        let neon = gf256_profile_pack_catalog()
            .iter()
            .find(|metadata| metadata.profile_pack == Gf256ProfilePackId::Aarch64NeonBalancedV1)
            .expect("aarch64 profile-pack metadata must exist");

        assert_eq!(
            neon.decision_artifact_id,
            PENDING_PROFILE_DECISION_ARTIFACT_ID
        );
        assert_eq!(neon.decision_role, PENDING_PROFILE_DECISION_ROLE);
        assert_eq!(
            neon.decision_evidence_status,
            PENDING_PROFILE_DECISION_EVIDENCE_STATUS
        );
        assert_eq!(
            neon.decision_evidence_status.as_str(),
            "pending-same-target-ablation"
        );
    }

    #[test]
    fn dual_policy_decisions_are_symmetric_under_lane_swap() {
        let seed = 0u64;
        let replay_ref = "replay:rq-u-gf256-dual-policy-v3";
        let context = failure_context(
            "RQ-U-GF256-DUAL-POLICY",
            seed,
            "dual_policy_decisions_are_symmetric_under_lane_swap",
            replay_ref,
        );

        for (len_a, len_b) in [
            (1usize, 1usize),
            (1024usize, 1024usize),
            (7168usize, 1024usize),
            (7424usize, 768usize),
            (12288usize, 12288usize),
            (12288usize, 1536usize),
            (16384usize, 16384usize),
            (16385usize, 8191usize),
        ] {
            assert_eq!(
                dual_mul_kernel_decision(len_a, len_b),
                dual_mul_kernel_decision(len_b, len_a),
                "{context}; mul decision was not symmetric for lane_a={len_a}, lane_b={len_b}"
            );
            assert_eq!(
                dual_addmul_kernel_decision(len_a, len_b),
                dual_addmul_kernel_decision(len_b, len_a),
                "{context}; addmul decision was not symmetric for lane_a={len_a}, lane_b={len_b}"
            );
        }
    }

    // Note: Validation tests are included via gf256_tests module
