    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;

    // br-asupersync-3wxmb3: regression for the clock-anchor +
    // deterministic-iteration fix.
    //   1. with_clock_anchor pins benchmark_timestamp to a fixed
    //      value across two independent runs of the same workload
    //      against the same architecture, so BenchmarkResult
    //      payloads are byte-identical.
    //   2. select_optimal_candidate breaks tied scores by
    //      lexicographic candidate_id ordering (BTreeMap
    //      iteration), so the chosen winner is deterministic.
    //   3. emit_profile_pack emits rejected_tuning_candidate_ids in
    //      sorted order (BTreeSet -> Vec), so the Vec is
    //      byte-identical across runs.
    // The first property is the user-facing contract; the others are
    // structural and verified by the BTreeMap/BTreeSet types
    // themselves — the test asserts the contract by running two
    // independent tuners and comparing their state.
    #[test]
    fn test_clock_anchor_pins_benchmark_timestamp_3wxmb3() {
        let anchor = Time::from_nanos(0xdead_beef_0000_0000);
        let make = || {
            OfflineTuner::new(
                Gf256ArchitectureClass::GenericScalar,
                OptimizationCriteria {
                    latency_weight: 0.5,
                    throughput_weight: 0.3,
                    bandwidth_weight: 0.2,
                    min_improvement_threshold: 5.0,
                },
            )
            .with_clock_anchor(anchor)
        };
        let t1 = make();
        let t2 = make();
        assert_eq!(t1.clock_anchor(), Some(anchor));
        assert_eq!(t2.clock_anchor(), Some(anchor));
        assert_eq!(t1.benchmark_clock(), anchor);
        assert_eq!(t2.benchmark_clock(), anchor);
    }

    #[test]
    fn test_no_clock_anchor_falls_back_to_wall_now_3wxmb3() {
        let tuner = OfflineTuner::new(
            Gf256ArchitectureClass::GenericScalar,
            OptimizationCriteria {
                latency_weight: 0.5,
                throughput_weight: 0.3,
                bandwidth_weight: 0.2,
                min_improvement_threshold: 5.0,
            },
        );
        assert!(tuner.clock_anchor().is_none());
        // benchmark_clock() returns wall_now() when no anchor is set.
        // wall_now() inside a non-lab process is the wall clock and is
        // therefore monotone-non-decreasing in nanoseconds. We only
        // assert that two consecutive calls are well-formed (no
        // panic, both produce a Time) — exact value comparison would
        // be flaky.
        let _t1 = tuner.benchmark_clock();
        let _t2 = tuner.benchmark_clock();
    }

    #[test]
    fn test_candidate_generation() {
        let tuner = OfflineTuner::new(
            Gf256ArchitectureClass::GenericScalar,
            OptimizationCriteria {
                latency_weight: 0.5,
                throughput_weight: 0.3,
                bandwidth_weight: 0.2,
                min_improvement_threshold: 5.0,
            },
        );

        let candidates = tuner.generate_candidates();
        assert!(!candidates.is_empty());

        // Verify candidate uniqueness
        let mut candidate_ids = std::collections::HashSet::new();
        for candidate in &candidates {
            assert!(candidate_ids.insert(&candidate.candidate_id));
        }
    }

    #[test]
    fn test_tuning_space_x86_avx2() {
        let space = OfflineTuner::default_tuning_space_for_arch(Gf256ArchitectureClass::X86Avx2);

        assert_eq!(space.architecture_class, Gf256ArchitectureClass::X86Avx2);
        assert!(space.tile_sizes.contains(&32));
        assert!(space.unroll_factors.contains(&4));
        assert!(space.prefetch_distances.contains(&64));
        assert!(space.fusion_shapes.contains(&FusionShape::Fused));
    }

    #[test]
    fn test_workload_generation() {
        let workloads = OfflineTuner::default_workloads_for_arch(Gf256ArchitectureClass::X86Avx2);

        assert!(!workloads.is_empty());
        assert!(workloads.iter().any(|w| w.operation == GF256Operation::Mul));
        assert!(
            workloads
                .iter()
                .any(|w| w.operation == GF256Operation::AddMul)
        );
    }

    fn test_criteria() -> OptimizationCriteria {
        OptimizationCriteria {
            latency_weight: 0.5,
            throughput_weight: 0.3,
            bandwidth_weight: 0.2,
            min_improvement_threshold: 5.0,
        }
    }

    #[test]
    fn benchmark_iterations_defaults_to_constant() {
        let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria());
        assert_eq!(tuner.benchmark_iterations(), DEFAULT_BENCHMARK_ITERATIONS);
    }

    #[test]
    fn benchmark_iterations_override_is_honored() {
        let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria())
            .with_benchmark_iterations(7);
        assert_eq!(tuner.benchmark_iterations(), 7);
    }

    #[test]
    fn benchmark_iterations_clamps_zero_to_one() {
        let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria())
            .with_benchmark_iterations(0);
        assert_eq!(
            tuner.benchmark_iterations(),
            1,
            "zero iterations would break median/p95 indexing"
        );
    }

    #[test]
    fn benchmark_result_reports_configured_iterations() {
        let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria())
            .with_benchmark_iterations(3);
        let candidates = tuner.generate_candidates();
        let candidate = candidates.first().expect("at least one candidate");
        let workload = tuner
            .workloads
            .first()
            .expect("default workloads non-empty");
        let result = tuner
            .benchmark_candidate(candidate, workload)
            .expect("benchmark runs");
        assert_eq!(result.iterations, 3);
    }

    #[test]
    fn benchmark_execution_uses_real_workload_kernel_inputs() {
        let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria());
        let workload = TuningWorkload {
            workload_id: "mul_oracle".to_string(),
            data_size: 64,
            multiplicand: 137,
            operation: GF256Operation::Mul,
            weight: 1.0,
        };
        let data = tuner.generate_test_data(&workload);

        let mut expected_mul = data.clone();
        gf256_mul_slice(&mut expected_mul, Gf256::new(workload.multiplicand));
        assert_eq!(
            tuner
                .execute_mul_kernel(&workload, &data)
                .expect("mul execution"),
            OfflineTuner::digest_kernel_output(&expected_mul)
        );

        let mut expected_addmul = vec![0u8; data.len()];
        gf256_addmul_slice(
            &mut expected_addmul,
            &data,
            Gf256::new(workload.multiplicand),
        );
        assert_eq!(
            tuner
                .execute_addmul_kernel(&workload, &data)
                .expect("addmul execution"),
            OfflineTuner::digest_kernel_output(&expected_addmul)
        );

        let mut expected_add = vec![0u8; data.len()];
        gf256_add_slice(&mut expected_add, &data);
        assert_eq!(
            tuner.execute_add_kernel(&data).expect("add execution"),
            OfflineTuner::digest_kernel_output(&expected_add)
        );
    }

    fn synthetic_bench(
        candidate: &KernelCandidate,
        workload_id: &str,
        median_ns: f64,
    ) -> BenchmarkResult {
        BenchmarkResult {
            candidate: candidate.clone(),
            workload_id: workload_id.to_string(),
            iterations: 100,
            latency_stats: LatencyStats {
                median_ns,
                p95_ns: median_ns * 1.2,
                p99_ns: median_ns * 1.5,
                stddev_ns: median_ns * 0.1,
                min_ns: median_ns * 0.8,
                max_ns: median_ns * 2.0,
            },
            throughput_ops_per_sec: 1.0e9 / median_ns,
            bandwidth_gbps: 0.0,
            bit_exactness_verified: true,
            benchmark_timestamp: "synthetic".to_string(),
        }
    }

    #[test]
    fn baseline_delta_reports_percentage_when_data_present() {
        let mut tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria());
        let candidates = tuner.generate_candidates();
        let baseline = candidates.first().expect("baseline").clone();
        let selected = candidates.last().expect("selected").clone();
        assert_ne!(
            baseline.candidate_id, selected.candidate_id,
            "baseline and selected must differ so the delta is non-trivial"
        );

        // Baseline runs each mul workload at 200ns; selected runs at 100ns
        // (2x faster => 50.000% delta aggregate and 50.000% per-workload avg).
        for wl in ["small_mul", "medium_mul", "large_mul"] {
            tuner
                .benchmark_results
                .push(synthetic_bench(&baseline, wl, 200.0));
            tuner
                .benchmark_results
                .push(synthetic_bench(&selected, wl, 100.0));
        }
        // AddMul workloads: selected 25% faster than baseline.
        for wl in ["small_addmul", "medium_addmul", "large_addmul"] {
            tuner
                .benchmark_results
                .push(synthetic_bench(&baseline, wl, 400.0));
            tuner
                .benchmark_results
                .push(synthetic_bench(&selected, wl, 300.0));
        }

        let pack = tuner.emit_profile_pack(&selected).expect("profile pack");
        assert_eq!(pack.selected_mul_delta_vs_baseline_pct, "50.000");
        assert_eq!(pack.selected_addmul_delta_vs_baseline_pct, "25.000");
        assert_eq!(pack.selected_targeted_addmul_average_delta_pct, "25.000");
    }

    #[test]
    fn baseline_delta_sentinel_when_no_benchmarks_run() {
        let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria());
        let selected = tuner
            .generate_candidates()
            .last()
            .expect("selected candidate")
            .clone();
        let pack = tuner.emit_profile_pack(&selected).expect("profile pack");
        // No benchmark results were fed in, so baseline data is missing.
        assert_eq!(pack.selected_mul_delta_vs_baseline_pct, "no_baseline_data");
        assert_eq!(
            pack.selected_addmul_delta_vs_baseline_pct,
            "no_baseline_data"
        );
        assert_eq!(
            pack.selected_targeted_addmul_average_delta_pct,
            "no_paired_workload_data"
        );
    }

    #[test]
    fn baseline_delta_zero_when_selected_equals_baseline() {
        let tuner = OfflineTuner::new(Gf256ArchitectureClass::GenericScalar, test_criteria());
        let baseline = tuner
            .generate_candidates()
            .first()
            .expect("baseline")
            .clone();
        let pack = tuner.emit_profile_pack(&baseline).expect("profile pack");
        assert_eq!(pack.selected_mul_delta_vs_baseline_pct, "0.000");
        assert_eq!(pack.selected_addmul_delta_vs_baseline_pct, "0.000");
        assert_eq!(pack.selected_targeted_addmul_average_delta_pct, "0.000");
    }
