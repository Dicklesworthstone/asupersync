    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use std::fmt::Write as _;

    fn render_spectral_health_report(report: &SpectralHealthReport) -> String {
        let mut rendered = format!("{report}");
        if report.bottlenecks.is_empty() {
            rendered.push_str("  bottleneck_nodes: []\n");
        } else {
            rendered.push_str("  bottleneck_nodes:\n");
            for node in &report.bottlenecks {
                let _ = writeln!(
                    rendered,
                    "    - node={} degree={} component={:.4} resistance={:.4}",
                    node.node_index, node.degree, node.fiedler_component, node.effective_resistance,
                );
            }
        }

        match &report.bifurcation {
            Some(bifurcation) => {
                let _ = writeln!(
                    rendered,
                    "  bifurcation_detail: trend={} severity={} confidence={:.2}",
                    bifurcation.trend, bifurcation.severity, bifurcation.confidence
                );
            }
            None => rendered.push_str("  bifurcation_detail: none\n"),
        }

        rendered
    }

    fn assert_spectral_health_snapshot(snapshot_name: &str, rendered: &str) {
        insta::with_settings!({
            snapshot_path => "../../tests/snapshots",
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_snapshot!(snapshot_name, rendered);
        });
    }

    fn render_eigenvalue_trace(label: &str, report: &SpectralHealthReport) -> String {
        let eigenvalues = report
            .decomposition
            .eigenvalues
            .iter()
            .map(|value| format!("{value:.6}"))
            .collect::<Vec<_>>()
            .join(", ");

        format!(
            "[{label}]\n  classification: {}\n  fiedler_value: {:.6}\n  spectral_gap: {:.6}\n  spectral_radius: {:.6}\n  iterations_used: {}\n  eigenvalues: [{eigenvalues}]\n",
            report.classification,
            report.decomposition.fiedler_value,
            report.decomposition.spectral_gap,
            report.decomposition.spectral_radius,
            report.decomposition.iterations_used,
        )
    }

    // -- Laplacian construction ------------------------------------------------

    #[test]
    fn empty_graph_laplacian() {
        let lap = DependencyLaplacian::new(0, &[]);
        assert_eq!(lap.size(), 0);
        assert_eq!(lap.edge_count(), 0);
    }

    #[test]
    fn single_node_laplacian() {
        let lap = DependencyLaplacian::new(1, &[]);
        assert_eq!(lap.size(), 1);
        assert_eq!(lap.edge_count(), 0);
        assert!((lap.degree[0] - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn edge_deduplication_and_self_loops() {
        // Duplicate edges and self-loops should be ignored.
        let edges = vec![(0, 1), (1, 0), (0, 0), (0, 1)];
        let lap = DependencyLaplacian::new(3, &edges);
        assert_eq!(lap.edge_count(), 1);
        assert!((lap.degree[0] - 1.0).abs() < f64::EPSILON);
        assert!((lap.degree[1] - 1.0).abs() < f64::EPSILON);
        assert!((lap.degree[2] - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn out_of_bounds_edges_ignored() {
        let edges = vec![(0, 1), (1, 5), (99, 0)];
        let lap = DependencyLaplacian::new(3, &edges);
        assert_eq!(lap.edge_count(), 1); // Only (0,1) is valid.
    }

    #[test]
    fn laplacian_multiply_path_graph() {
        // Path: 0 - 1 - 2
        // L = [[1, -1, 0], [-1, 2, -1], [0, -1, 1]]
        let lap = DependencyLaplacian::new(3, &[(0, 1), (1, 2)]);
        let x = [1.0, 0.0, -1.0];
        let mut y = [0.0; 3];
        lap.laplacian_multiply(&x, &mut y);
        // L * [1, 0, -1] = [1, -1+1, -1] = [1, 0, -1]? No:
        // y[0] = 1*1 - 0 = 1
        // y[1] = 2*0 - 1 - (-1) = 0
        // y[2] = 1*(-1) - 0 = -1
        // Wait: y[2] = degree[2]*x[2] - sum_j A[2,j]*x[j] = 1*(-1) - x[1] = -1 - 0 = -1
        assert!((y[0] - 1.0).abs() < 1e-10);
        assert!((y[1] - 0.0).abs() < 1e-10);
        assert!((y[2] - (-1.0)).abs() < 1e-10);
    }

    #[test]
    fn laplacian_multiply_constant_vector_is_zero() {
        // L * [1, 1, 1, 1] = 0 for any graph.
        let lap = DependencyLaplacian::new(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]);
        let x = [1.0, 1.0, 1.0, 1.0];
        let mut y = [0.0; 4];
        lap.laplacian_multiply(&x, &mut y);
        for yi in &y {
            assert!(yi.abs() < 1e-10, "L * 1 should be 0, got {yi}");
        }
    }

    // -- Connected components --------------------------------------------------

    #[test]
    fn connected_components_single_component() {
        let lap = DependencyLaplacian::new(4, &[(0, 1), (1, 2), (2, 3)]);
        let (count, labels) = lap.connected_components();
        assert_eq!(count, 1);
        // All nodes should have the same label.
        assert!(labels.iter().all(|&l| l == labels[0]));
    }

    #[test]
    fn connected_components_two_components() {
        // 0-1 and 2-3 are separate.
        let lap = DependencyLaplacian::new(4, &[(0, 1), (2, 3)]);
        let (count, labels) = lap.connected_components();
        assert_eq!(count, 2);
        assert_eq!(labels[0], labels[1]);
        assert_eq!(labels[2], labels[3]);
        assert_ne!(labels[0], labels[2]);
    }

    #[test]
    fn connected_components_isolated_nodes() {
        let lap = DependencyLaplacian::new(3, &[]);
        let (count, _) = lap.connected_components();
        assert_eq!(count, 3);
    }

    // -- Spectral decomposition: known spectra ---------------------------------

    #[test]
    fn complete_graph_k4_fiedler_value() {
        // K4: all edges present. Laplacian eigenvalues are [0, 4, 4, 4].
        // Fiedler value = 4.
        let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        assert!(
            (decomp.fiedler_value - 4.0).abs() < 0.1,
            "K4 Fiedler value should be ~4.0, got {}",
            decomp.fiedler_value
        );
        assert!(
            (decomp.spectral_radius - 4.0).abs() < 0.1,
            "K4 spectral radius should be ~4.0, got {}",
            decomp.spectral_radius
        );
    }

    #[test]
    fn path_graph_p4_fiedler_value() {
        // P4: 0-1-2-3. Laplacian eigenvalues: 0, 2-sqrt(2), 2, 2+sqrt(2).
        // Fiedler value = 2 - sqrt(2) ~ 0.5858.
        let edges = vec![(0, 1), (1, 2), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds {
            max_iterations: 500,
            convergence_tolerance: 1e-12,
            ..SpectralThresholds::default()
        };
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        let expected = 2.0 - std::f64::consts::SQRT_2; // ~0.5858
        assert!(
            (decomp.fiedler_value - expected).abs() < 0.05,
            "P4 Fiedler value should be ~{expected:.4}, got {:.4}",
            decomp.fiedler_value
        );
    }

    #[test]
    fn cycle_graph_c4_fiedler_value() {
        // C4: 0-1-2-3-0. Laplacian eigenvalues: 0, 2, 2, 4.
        // Fiedler value = 2.
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 0)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        assert!(
            (decomp.fiedler_value - 2.0).abs() < 0.1,
            "C4 Fiedler value should be ~2.0, got {}",
            decomp.fiedler_value
        );
        assert!(
            (decomp.spectral_radius - 4.0).abs() < 0.1,
            "C4 spectral radius should be ~4.0, got {}",
            decomp.spectral_radius
        );
    }

    #[test]
    fn star_graph_s5_fiedler_value() {
        // Star with center 0 and 4 leaves. Eigenvalues: 0, 1, 1, 1, 5.
        // Fiedler value = 1.
        let edges = vec![(0, 1), (0, 2), (0, 3), (0, 4)];
        let lap = DependencyLaplacian::new(5, &edges);
        let thresholds = SpectralThresholds {
            max_iterations: 500,
            convergence_tolerance: 1e-12,
            ..SpectralThresholds::default()
        };
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        assert!(
            (decomp.fiedler_value - 1.0).abs() < 0.1,
            "Star S5 Fiedler value should be ~1.0, got {}",
            decomp.fiedler_value
        );
        assert!(
            (decomp.spectral_radius - 5.0).abs() < 0.1,
            "Star S5 spectral radius should be ~5.0, got {}",
            decomp.spectral_radius
        );
    }

    #[test]
    fn disconnected_graph_fiedler_zero() {
        // Two isolated edges: 0-1 and 2-3.
        let edges = vec![(0, 1), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        assert!(
            decomp.fiedler_value < 1e-10,
            "Disconnected graph Fiedler should be ~0, got {}",
            decomp.fiedler_value
        );
    }

    #[test]
    fn empty_graph_decomposition() {
        let lap = DependencyLaplacian::new(0, &[]);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        assert!(decomp.eigenvalues.is_empty());
        assert!(decomp.fiedler_value.abs() < f64::EPSILON);
        assert!(decomp.spectral_radius.abs() < f64::EPSILON);
    }

    #[test]
    fn single_node_decomposition() {
        let lap = DependencyLaplacian::new(1, &[]);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        assert_eq!(decomp.eigenvalues.len(), 1);
        assert!(decomp.fiedler_value.abs() < f64::EPSILON);
    }

    #[test]
    fn two_node_edge_decomposition() {
        // K2: eigenvalues [0, 2]. Fiedler = 2.
        let lap = DependencyLaplacian::new(2, &[(0, 1)]);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        assert!(
            (decomp.fiedler_value - 2.0).abs() < 0.1,
            "K2 Fiedler should be ~2.0, got {}",
            decomp.fiedler_value
        );
    }

    // -- Fiedler vector properties ---------------------------------------------

    #[test]
    fn fiedler_vector_orthogonal_to_constant() {
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        // Fiedler vector should be approximately orthogonal to [1,1,...,1].
        let sum: f64 = decomp.fiedler_vector.iter().sum();
        assert!(
            sum.abs() < 0.1,
            "Fiedler vector should be orthogonal to constant vector, sum = {sum}"
        );
    }

    #[test]
    fn fiedler_vector_unit_norm() {
        let edges = vec![(0, 1), (1, 2), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        let norm: f64 = decomp
            .fiedler_vector
            .iter()
            .map(|x| x * x)
            .sum::<f64>()
            .sqrt();
        assert!(
            (norm - 1.0).abs() < 0.01,
            "Fiedler vector should have unit norm, got {norm}"
        );
    }

    // -- Health classification -------------------------------------------------

    #[test]
    fn classify_healthy_system() {
        let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        let health = classify_health(&decomp, &lap, &thresholds, false);

        assert!(
            matches!(health, HealthClassification::Healthy { .. }),
            "K4 should be healthy, got {health}"
        );
    }

    #[test]
    fn classify_fragmented_system() {
        let edges = vec![(0, 1), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        let health = classify_health(&decomp, &lap, &thresholds, false);

        assert!(
            matches!(health, HealthClassification::Fragmented { components: 2 }),
            "Disconnected graph should be fragmented, got {health}"
        );
    }

    #[test]
    fn classify_fragmented_system_despite_numerical_residual() {
        let lap = DependencyLaplacian::new(4, &[(0, 1), (2, 3)]);
        let thresholds = SpectralThresholds::default();
        let decomposition = SpectralDecomposition {
            eigenvalues: vec![0.0, 2e-5, 2.0],
            fiedler_value: 2e-5,
            fiedler_vector: vec![-0.5, -0.5, 0.5, 0.5],
            spectral_gap: 1e-5,
            spectral_radius: 2.0,
            iterations_used: thresholds.max_iterations,
        };

        let health = classify_health(&decomposition, &lap, &thresholds, false);

        assert!(
            matches!(health, HealthClassification::Fragmented { components: 2 }),
            "structural fragmentation must override a positive numerical residual, got {health}"
        );
    }

    #[test]
    fn classify_edge_free_graph_as_healthy() {
        let lap = DependencyLaplacian::new(3, &[]);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        let health = classify_health(&decomp, &lap, &thresholds, false);

        assert!(
            matches!(health, HealthClassification::Healthy { margin: 0.0 }),
            "Edge-free graph should not be treated as fragmented or deadlocked, got {health}"
        );
    }

    #[test]
    fn metamorphic_edge_addition_only_improves_connectivity_health() {
        fn health_rank(classification: &HealthClassification) -> u8 {
            match classification {
                HealthClassification::Fragmented { .. } => 0,
                HealthClassification::Critical { .. } => 1,
                HealthClassification::Degraded { .. } => 2,
                HealthClassification::Healthy { .. } => 3,
                HealthClassification::Deadlocked => 4,
            }
        }

        let thresholds = SpectralThresholds::default();

        let fragmented_edges = vec![(0, 1), (2, 3)];
        let fragmented_lap = DependencyLaplacian::new(4, &fragmented_edges);
        let fragmented_decomp = compute_spectral_decomposition(&fragmented_lap, &thresholds);
        let fragmented_health =
            classify_health(&fragmented_decomp, &fragmented_lap, &thresholds, false);

        let bridged_edges = vec![(0, 1), (1, 2), (2, 3)];
        let bridged_lap = DependencyLaplacian::new(4, &bridged_edges);
        let bridged_decomp = compute_spectral_decomposition(&bridged_lap, &thresholds);
        let bridged_health = classify_health(&bridged_decomp, &bridged_lap, &thresholds, false);

        let redundant_edges = vec![(0, 1), (1, 2), (2, 3), (0, 3)];
        let redundant_lap = DependencyLaplacian::new(4, &redundant_edges);
        let redundant_decomp = compute_spectral_decomposition(&redundant_lap, &thresholds);
        let redundant_health =
            classify_health(&redundant_decomp, &redundant_lap, &thresholds, false);

        assert!(
            matches!(fragmented_health, HealthClassification::Fragmented { .. }),
            "baseline graph should be fragmented, got {fragmented_health}"
        );
        assert!(
            bridged_decomp.fiedler_value + 1e-9 >= fragmented_decomp.fiedler_value,
            "adding a bridge edge must not reduce algebraic connectivity: fragmented={} bridged={}",
            fragmented_decomp.fiedler_value,
            bridged_decomp.fiedler_value
        );
        assert!(
            health_rank(&bridged_health) >= health_rank(&fragmented_health),
            "adding a bridge edge must not worsen health: fragmented={fragmented_health}, bridged={bridged_health}"
        );
        assert!(
            redundant_decomp.fiedler_value + 1e-9 >= bridged_decomp.fiedler_value,
            "adding a redundant edge must not reduce algebraic connectivity: bridged={} redundant={}",
            bridged_decomp.fiedler_value,
            redundant_decomp.fiedler_value
        );
        assert!(
            health_rank(&redundant_health) >= health_rank(&bridged_health),
            "adding a redundant edge must not worsen health: bridged={bridged_health}, redundant={redundant_health}"
        );
    }

    #[test]
    fn health_classification_display_all_variants() {
        let variants: Vec<HealthClassification> = vec![
            HealthClassification::Deadlocked,
            HealthClassification::Healthy { margin: 0.5 },
            HealthClassification::Degraded {
                fiedler: 0.05,
                bottleneck_nodes: vec![1, 2],
            },
            HealthClassification::Critical {
                fiedler: 0.005,
                approaching_disconnect: true,
            },
            HealthClassification::Fragmented { components: 3 },
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // -- Bottleneck identification ---------------------------------------------

    #[test]
    fn bottleneck_near_barbell_bridge() {
        // Barbell graph: two triangles connected by a single bridge edge.
        // 0-1-2 triangle, 3-4-5 triangle, bridge: 2-3.
        let edges = vec![
            (0, 1),
            (1, 2),
            (0, 2), // triangle 1
            (3, 4),
            (4, 5),
            (3, 5), // triangle 2
            (2, 3), // bridge
        ];
        let lap = DependencyLaplacian::new(6, &edges);
        let thresholds = SpectralThresholds {
            max_iterations: 500,
            convergence_tolerance: 1e-12,
            bottleneck_threshold: 0.5,
            ..SpectralThresholds::default()
        };
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        // Fiedler value should be small (weak connection through bridge).
        assert!(
            decomp.fiedler_value < 1.5,
            "Barbell Fiedler should be small, got {}",
            decomp.fiedler_value
        );

        // The Fiedler vector should change sign between the two triangles.
        // Nodes 2 and 3 (the bridge) should have Fiedler components near zero
        // (they are the bottleneck / cut vertices).
        let fv = &decomp.fiedler_vector;
        if fv.len() == 6 {
            // The two halves should have opposite signs.
            let side_a = fv[0].signum();
            let side_b = fv[5].signum();
            assert!(
                side_a * side_b < 0.0 || decomp.fiedler_value < 0.01,
                "Fiedler vector should partition barbell halves"
            );
        }
    }

    #[test]
    fn identify_bottlenecks_threshold() {
        let fv = vec![-0.5, -0.1, 0.05, 0.1, 0.5];
        let bottlenecks = identify_bottlenecks(&fv, 0.2);
        // Nodes within 20% of the largest magnitude: indices 1, 2, 3.
        assert_eq!(bottlenecks, vec![1, 2, 3]);
    }

    #[test]
    fn identify_bottlenecks_is_scale_invariant() {
        let fiedler = [-0.8, -0.2, 0.0, 0.2, 0.8];
        let scaled = fiedler.map(|component| component * 1e-300);

        assert_eq!(
            identify_bottlenecks(&fiedler, 0.3),
            identify_bottlenecks(&scaled, 0.3)
        );
        assert_eq!(identify_bottlenecks(&fiedler, 0.3), vec![1, 2, 3]);
    }

    #[test]
    fn identify_bottlenecks_all_zero_has_no_partition_signal() {
        assert!(identify_bottlenecks(&[0.0; 16], 0.4).is_empty());
    }

    #[test]
    fn identify_bottlenecks_empty() {
        let bottlenecks = identify_bottlenecks(&[], 0.5);
        assert!(bottlenecks.is_empty());
    }

    // -- Effective resistance --------------------------------------------------

    #[test]
    fn effective_resistance_adjacent_nodes() {
        let edges = vec![(0, 1), (1, 2), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        let r01 = effective_resistance_bound(&decomp, 0, 1);
        let r03 = effective_resistance_bound(&decomp, 0, 3);

        // Resistance between distant nodes should be larger.
        assert!(
            r03 > r01,
            "R(0,3) should exceed R(0,1): got R01={r01:.4}, R03={r03:.4}"
        );
    }

    #[test]
    fn effective_resistance_disconnected_infinite() {
        let edges = vec![(0, 1), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        let r02 = effective_resistance_bound(&decomp, 0, 2);
        assert!(
            r02.is_infinite(),
            "Resistance between disconnected nodes should be infinite, got {r02}"
        );
    }

    #[test]
    fn effective_resistance_out_of_bounds() {
        let decomp = SpectralDecomposition {
            eigenvalues: vec![0.0, 1.0],
            fiedler_value: 1.0,
            fiedler_vector: vec![0.5, -0.5],
            spectral_gap: 1.0,
            spectral_radius: 1.0,
            iterations_used: 0,
        };
        let r = effective_resistance_bound(&decomp, 0, 99);
        assert!(r.is_infinite());
    }

    // -- Spectral history and trend analysis -----------------------------------

    #[test]
    fn history_ring_buffer() {
        let mut history = SpectralHistory::new(4);
        assert!(history.is_empty());

        history.record(1.0);
        history.record(2.0);
        assert_eq!(history.len(), 2);

        history.record(3.0);
        history.record(4.0);
        assert_eq!(history.len(), 4);

        // Wrap around.
        history.record(5.0);
        assert_eq!(history.len(), 4);

        let vals = history.chronological();
        assert_eq!(vals, vec![2.0, 3.0, 4.0, 5.0]);
    }

    #[test]
    fn history_minimum_capacity() {
        let history = SpectralHistory::new(0);
        assert_eq!(history.capacity, 2); // Clamped to minimum.
    }

    #[test]
    fn trend_analysis_deteriorating() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        // Steadily decreasing Fiedler values.
        for i in 0..6_i32 {
            history.record(f64::from(i).mul_add(-0.15, 1.0));
        }

        let warning = history.analyze(&thresholds);
        assert!(warning.is_some());
        let warning = warning.unwrap();
        assert_eq!(
            warning.trend,
            SpectralTrend::Deteriorating,
            "trend should be deteriorating, got {:?}",
            warning.trend
        );
        assert!(warning.time_to_critical.is_some());
    }

    #[test]
    fn trend_analysis_improving() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        // Steadily increasing Fiedler values.
        for i in 0..6_i32 {
            history.record(f64::from(i).mul_add(0.15, 0.5));
        }

        let warning = history.analyze(&thresholds);
        assert!(warning.is_some());
        let warning = warning.unwrap();
        assert_eq!(
            warning.trend,
            SpectralTrend::Improving,
            "trend should be improving, got {:?}",
            warning.trend
        );
        assert!(warning.time_to_critical.is_none());
    }

    #[test]
    fn trend_analysis_oscillating() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(12);

        // Oscillating values.
        for i in 0..10 {
            let val = if i % 2 == 0 { 0.8 } else { 0.2 };
            history.record(val);
        }

        let warning = history.analyze(&thresholds);
        assert!(warning.is_some());
        let warning = warning.unwrap();
        assert_eq!(
            warning.trend,
            SpectralTrend::Oscillating,
            "trend should be oscillating, got {:?}",
            warning.trend
        );
    }

    #[test]
    fn trend_analysis_insufficient_data() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);
        history.record(1.0);
        history.record(0.9);

        let warning = history.analyze(&thresholds);
        assert!(warning.is_none(), "need at least 3 data points");
    }

    // -- Linear regression helpers ---------------------------------------------

    #[test]
    fn linear_regression_perfect_line() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let slope = linear_regression_slope(&values);
        assert!(
            (slope - 1.0).abs() < 1e-10,
            "slope of [1,2,3,4,5] should be 1.0, got {slope}"
        );

        let r2 = linear_regression_r_squared(&values);
        assert!(
            (r2 - 1.0).abs() < 1e-10,
            "R^2 of perfect line should be 1.0, got {r2}"
        );
    }

    #[test]
    fn linear_regression_constant() {
        let values = vec![3.0, 3.0, 3.0, 3.0];
        let slope = linear_regression_slope(&values);
        assert!(slope.abs() < 1e-10, "slope of constant should be 0");

        let r2 = linear_regression_r_squared(&values);
        assert!(
            (r2 - 1.0).abs() < 1e-10,
            "R^2 of constant should be 1.0 (perfect fit)"
        );
    }

    #[test]
    fn linear_regression_negative_slope() {
        let values = vec![5.0, 4.0, 3.0, 2.0, 1.0];
        let slope = linear_regression_slope(&values);
        assert!(
            (slope - (-1.0)).abs() < 1e-10,
            "slope should be -1.0, got {slope}"
        );
    }

    #[test]
    fn linear_regression_single_value() {
        assert!(linear_regression_slope(&[42.0]).abs() < f64::EPSILON);
        assert!(linear_regression_slope(&[]).abs() < f64::EPSILON);
    }

    #[test]
    fn variance_ratio_detects_growth_from_constant_baseline_ne8jdw() {
        let values = [1.0, 1.0, 1.0, 1.0, 0.5, 1.5, 0.75, 1.25];
        let ratio = variance_ratio_halves(&values).expect("positive second-half variance");
        assert!(ratio.is_infinite() && ratio.is_sign_positive());

        assert!(variance_ratio_halves(&[1.0; 8]).is_none());
        assert_eq!(
            variance_ratio_halves(&[0.0, 1.0, 0.0, 1.0, 1.0, 1.0, 1.0, 1.0]),
            Some(0.0)
        );
    }

    #[test]
    fn variance_growth_from_constant_baseline_raises_warning_ne8jdw() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);
        for value in [1.0, 1.0, 1.0, 1.0, 0.5, 1.5, 0.75, 1.25] {
            history.record(value);
        }

        let warning = history.analyze(&thresholds).expect("enough history");
        let ratio = warning.variance_ratio.expect("variance growth ratio");
        assert!(ratio.is_infinite() && ratio.is_sign_positive());
        assert!(warning.severity >= EarlyWarningSeverity::Watch);
    }

    // -- SpectralHealthMonitor integration -------------------------------------

    #[test]
    fn monitor_healthy_cycle() {
        let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 0)];
        let report = monitor.analyze(4, &edges);

        assert!(
            matches!(report.classification, HealthClassification::Healthy { .. }),
            "C4 should be healthy, got {}",
            report.classification
        );
        assert!(report.decomposition.fiedler_value > 0.0);
        assert_eq!(monitor.history_len(), 1);

        // Verify Display impl.
        let display = report.to_string();
        assert!(display.contains("SpectralHealthReport"));
        assert!(display.contains("classification"));
    }

    #[test]
    fn monitor_fragmented_disconnected() {
        let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        let edges = vec![(0, 1), (2, 3)];
        let report = monitor.analyze(4, &edges);

        assert!(
            matches!(
                report.classification,
                HealthClassification::Fragmented { components: 2 }
            ),
            "Disconnected graph should be fragmented, got {}",
            report.classification
        );
    }

    #[test]
    fn monitor_trapped_cycle_hint_reports_deadlocked() {
        let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        let report = monitor.analyze_with_trapped_cycle(2, &[], true);

        assert!(
            matches!(report.classification, HealthClassification::Deadlocked),
            "explicit trapped-cycle evidence should classify as deadlocked, got {}",
            report.classification
        );
    }

    #[test]
    fn monitor_tracks_history() {
        let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());

        let edges_strong = vec![(0, 1), (1, 2), (2, 3), (3, 0), (0, 2), (1, 3)];
        for _ in 0..5 {
            monitor.analyze(4, &edges_strong);
        }
        assert_eq!(monitor.history_len(), 5);

        monitor.reset_history();
        assert_eq!(monitor.history_len(), 0);
    }

    #[test]
    fn monitor_empty_graph() {
        let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        let report = monitor.analyze(0, &[]);

        assert!(report.decomposition.eigenvalues.is_empty());
        assert!(report.bottlenecks.is_empty());
    }

    // -- Spectral gap (normalized) ---------------------------------------------

    #[test]
    fn spectral_gap_normalized() {
        // C4: lambda_2 = 2, lambda_n = 4. Gap = 0.5.
        let edges = vec![(0, 1), (1, 2), (2, 3), (3, 0)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        assert!(
            (decomp.spectral_gap - 0.5).abs() < 0.1,
            "C4 spectral gap should be ~0.5, got {}",
            decomp.spectral_gap
        );
    }

    // -- Bottleneck analysis integration ---------------------------------------

    #[test]
    fn bottleneck_analysis_complete_graph() {
        // K4: no bottlenecks (all nodes equally connected).
        let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        let bottlenecks = analyze_bottlenecks(&decomp, &lap, 0.1);

        // For a complete graph, the Fiedler vector components are symmetric
        // and may all be near the threshold. The key property is that no node
        // is singled out as a unique bottleneck.
        // (The exact count depends on the Fiedler vector orientation.)
        let _ = bottlenecks; // Just ensure it doesn't panic.
    }

    #[test]
    fn bottleneck_analysis_empty() {
        let lap = DependencyLaplacian::new(0, &[]);
        let decomp = SpectralDecomposition {
            eigenvalues: Vec::new(),
            fiedler_value: 0.0,
            fiedler_vector: Vec::new(),
            spectral_gap: 0.0,
            spectral_radius: 0.0,
            iterations_used: 0,
        };
        let bottlenecks = analyze_bottlenecks(&decomp, &lap, 0.5);
        assert!(bottlenecks.is_empty());
    }

    // -- Display / Debug trait tests -------------------------------------------

    #[test]
    fn spectral_trend_display() {
        assert_eq!(SpectralTrend::Improving.to_string(), "improving");
        assert_eq!(SpectralTrend::Stable.to_string(), "stable");
        assert_eq!(SpectralTrend::Deteriorating.to_string(), "deteriorating");
        assert_eq!(SpectralTrend::Oscillating.to_string(), "oscillating");
    }

    #[test]
    fn bifurcation_warning_display() {
        let bw = BifurcationWarning {
            trend: SpectralTrend::Deteriorating,
            slope: -0.1,
            time_to_critical: Some(5.3),
            lag1_autocorrelation: Some(0.8),
            rolling_variance: Some(0.02),
            variance_ratio: Some(1.4),
            flicker_score: 0.2,
            kendall_tau: Some(-0.7),
            spearman_rho: Some(-0.85),
            hoeffding_d: Some(0.085),
            distance_corr: Some(0.72),
            skewness: Some(-0.3),
            return_rate: Some(0.2),
            conformal_lower_bound_next: Some(0.03),
            deterioration_e_value: 2.0,
            severity: EarlyWarningSeverity::Warning,
            confidence: 0.87,
        };
        let s = bw.to_string();
        assert!(s.contains("deteriorating"));
        assert!(s.contains("5.30"));
        assert!(s.contains("0.87"));
        assert!(s.contains("warning"));
        assert!(s.contains("return_rate"));
        assert!(s.contains("kendall_tau"));
        assert!(s.contains("spearman_rho"));
        assert!(s.contains("hoeffding_d"));
        assert!(s.contains("dcor"));

        let bw_no_ttc = BifurcationWarning {
            trend: SpectralTrend::Stable,
            slope: 0.0,
            time_to_critical: None,
            lag1_autocorrelation: None,
            rolling_variance: None,
            variance_ratio: None,
            flicker_score: 0.0,
            kendall_tau: None,
            spearman_rho: None,
            hoeffding_d: None,
            distance_corr: None,
            skewness: None,
            return_rate: None,
            conformal_lower_bound_next: None,
            deterioration_e_value: 1.0,
            severity: EarlyWarningSeverity::None,
            confidence: 0.5,
        };
        let s2 = bw_no_ttc.to_string();
        assert!(!s2.contains("time_to_critical"));
    }

    #[test]
    fn bottleneck_node_debug() {
        let bn = BottleneckNode {
            node_index: 3,
            fiedler_component: 0.05,
            degree: 2,
            effective_resistance: 1.5,
        };
        let dbg = format!("{bn:?}");
        assert!(dbg.contains("BottleneckNode"));
        assert!(dbg.contains("node_index: 3"));
    }

    #[test]
    fn spectral_decomposition_debug_clone() {
        let decomp = SpectralDecomposition {
            eigenvalues: vec![0.0, 2.0, 4.0],
            fiedler_value: 2.0,
            fiedler_vector: vec![0.5, -0.5, 0.0],
            spectral_gap: 0.5,
            spectral_radius: 4.0,
            iterations_used: 42,
        };
        assert!(format!("{decomp:?}").contains("SpectralDecomposition"));
        // Verify Clone produces equivalent value.
        let decomp2 = decomp.clone();
        assert_eq!(decomp.fiedler_vector, decomp2.fiedler_vector);
    }

    #[test]
    fn spectral_thresholds_debug_clone() {
        let t = SpectralThresholds::production();
        let t2 = t;
        assert!(format!("{t:?}").contains("SpectralThresholds"));
        assert!(format!("{t2:?}").contains("SpectralThresholds"));
    }

    #[test]
    fn spectral_health_report_debug_clone() {
        let report = SpectralHealthReport {
            classification: HealthClassification::Healthy { margin: 1.0 },
            decomposition: SpectralDecomposition {
                eigenvalues: vec![0.0, 1.0],
                fiedler_value: 1.0,
                fiedler_vector: vec![0.7, -0.7],
                spectral_gap: 1.0,
                spectral_radius: 1.0,
                iterations_used: 10,
            },
            bifurcation: None,
            bottlenecks: Vec::new(),
        };
        assert!(format!("{report:?}").contains("SpectralHealthReport"));
        // Verify Clone produces equivalent value.
        let report2 = report.clone();
        assert_eq!(
            report.decomposition.eigenvalues,
            report2.decomposition.eigenvalues
        );
    }

    #[test]
    fn monitor_debug_clone() {
        let monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        assert!(format!("{monitor:?}").contains("SpectralHealthMonitor"));
        // Verify Clone produces equivalent value.
        let monitor2 = monitor.clone();
        assert_eq!(monitor.history_len(), monitor2.history_len());
    }

    #[test]
    fn spectral_health_report_snapshot_scrubbed() {
        let mut healthy_monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        let healthy = healthy_monitor.analyze(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]);

        let degraded_thresholds = SpectralThresholds {
            critical_fiedler: 0.3,
            degraded_fiedler: 0.8,
            ..SpectralThresholds::default()
        };
        let mut degraded_monitor = SpectralHealthMonitor::new(degraded_thresholds);
        let degraded = degraded_monitor.analyze(4, &[(0, 1), (1, 2), (2, 3)]);

        let critical_thresholds = SpectralThresholds {
            critical_fiedler: 0.6,
            degraded_fiedler: 0.8,
            ..SpectralThresholds::default()
        };
        let mut critical_monitor = SpectralHealthMonitor::new(critical_thresholds);
        let critical = critical_monitor.analyze(4, &[(0, 1), (1, 2), (2, 3)]);

        let snapshot = format!(
            "[healthy]\n{}\n[degraded]\n{}\n[critical]\n{}",
            render_spectral_health_report(&healthy),
            render_spectral_health_report(&degraded),
            render_spectral_health_report(&critical),
        );

        assert_spectral_health_snapshot("observability_spectral_health_report_scrubbed", &snapshot);
    }

    #[test]
    fn eigenvalue_trace_scrubbed() {
        let mut stable_monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        let stable = stable_monitor.analyze(4, &[(0, 1), (1, 2), (2, 3), (3, 0)]);

        let degraded_thresholds = SpectralThresholds {
            critical_fiedler: 0.3,
            degraded_fiedler: 0.8,
            ..SpectralThresholds::default()
        };
        let mut degraded_monitor = SpectralHealthMonitor::new(degraded_thresholds);
        let degraded = degraded_monitor.analyze(4, &[(0, 1), (1, 2), (2, 3)]);

        let critical_thresholds = SpectralThresholds {
            critical_fiedler: 0.6,
            degraded_fiedler: 0.8,
            ..SpectralThresholds::default()
        };
        let mut critical_monitor = SpectralHealthMonitor::new(critical_thresholds);
        let critical = critical_monitor.analyze(4, &[(0, 1), (1, 2), (2, 3)]);

        let snapshot = format!(
            "{}{}{}",
            render_eigenvalue_trace("stable", &stable),
            render_eigenvalue_trace("degraded", &degraded),
            render_eigenvalue_trace("critical", &critical),
        );

        assert_spectral_health_snapshot("eigenvalue_trace_scrubbed", &snapshot);
    }

    // -- Stress / scale test ---------------------------------------------------

    #[test]
    fn large_path_graph_convergence() {
        // P100: a long path graph with 100 nodes.
        // lambda_2 ~ 2 * (1 - cos(pi/100)) ~ pi^2 / 100^2 ~ 0.000987
        let n = 100;
        let edges: Vec<(usize, usize)> = (0..n - 1).map(|i| (i, i + 1)).collect();
        let lap = DependencyLaplacian::new(n, &edges);
        let thresholds = SpectralThresholds {
            max_iterations: 1000,
            convergence_tolerance: 1e-8,
            ..SpectralThresholds::default()
        };
        let decomp = compute_spectral_decomposition(&lap, &thresholds);

        #[allow(clippy::cast_precision_loss)]
        let n_f = n as f64;
        let expected = 2.0 * (1.0 - (std::f64::consts::PI / n_f).cos());
        assert!(
            (decomp.fiedler_value - expected).abs() < 0.01,
            "P100 Fiedler should be ~{expected:.6}, got {:.6}",
            decomp.fiedler_value
        );

        // Spectral radius: lambda_n ~ 2 * (1 + cos(pi/100)) ~ 4 - expected
        let expected_radius = 2.0 * (1.0 + (std::f64::consts::PI / n_f).cos());
        assert!(
            (decomp.spectral_radius - expected_radius).abs() < 0.1,
            "P100 spectral radius should be ~{expected_radius:.4}, got {:.4}",
            decomp.spectral_radius
        );
    }

    // -- Kendall's tau --------------------------------------------------------

    #[test]
    fn kendall_tau_perfect_increasing() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let tau = kendall_tau(&values);
        assert!(tau.is_some());
        assert!(
            (tau.unwrap() - 1.0).abs() < 1e-10,
            "perfect increase should give tau = 1.0, got {tau:?}"
        );
    }

    #[test]
    fn kendall_tau_perfect_decreasing() {
        let values = vec![5.0, 4.0, 3.0, 2.0, 1.0];
        let tau = kendall_tau(&values);
        assert!(tau.is_some());
        assert!(
            (tau.unwrap() - (-1.0)).abs() < 1e-10,
            "perfect decrease should give tau = -1.0, got {tau:?}"
        );
    }

    #[test]
    fn kendall_tau_constant() {
        let values = vec![3.0, 3.0, 3.0, 3.0];
        let tau = kendall_tau(&values);
        assert!(tau.is_some());
        assert!(
            tau.unwrap().abs() < 1e-10,
            "constant series should give tau = 0, got {tau:?}"
        );
    }

    #[test]
    fn kendall_tau_b_penalizes_value_ties_ne8jdw() {
        let values = [1.0, 1.0, 2.0, 2.0];
        let tau = kendall_tau(&values).expect("tie-aware tau-b");
        let expected = (2.0_f64 / 3.0).sqrt();

        assert!(
            (tau - expected).abs() < 1e-12,
            "tau-b must include tied pairs in its denominator: expected {expected}, got {tau}"
        );
        assert!(
            tau < 1.0,
            "Goodman-Kruskal gamma would incorrectly report a perfect trend"
        );
    }

    #[test]
    fn kendall_tau_insufficient() {
        assert!(kendall_tau(&[1.0, 2.0]).is_none());
        assert!(kendall_tau(&[1.0]).is_none());
        assert!(kendall_tau(&[]).is_none());
    }

    #[test]
    fn kendall_tau_non_linear_decrease() {
        // Exponential decay: monotone but non-linear.
        // Kendall's tau should still detect this perfectly.
        let values: Vec<f64> = (0..10).map(|i| 100.0 * 0.7_f64.powi(i)).collect();
        let tau = kendall_tau(&values).unwrap();
        assert!(
            (tau - (-1.0)).abs() < 1e-10,
            "exponential decay is still monotone: tau should be -1.0, got {tau}"
        );
    }

    // -- Sample skewness ------------------------------------------------------

    #[test]
    fn skewness_symmetric() {
        // Symmetric distribution: skewness ≈ 0.
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let sk = sample_skewness(&values);
        assert!(sk.is_some());
        assert!(
            sk.unwrap().abs() < 1e-10,
            "symmetric series should have skewness ≈ 0, got {sk:?}"
        );
    }

    #[test]
    fn skewness_right_skewed() {
        // Right-skewed: most values low, one outlier high.
        let values = vec![1.0, 1.0, 1.0, 1.0, 10.0];
        let sk = sample_skewness(&values).unwrap();
        assert!(
            sk > 0.0,
            "right-skewed data should have positive skewness, got {sk}"
        );
    }

    #[test]
    fn skewness_left_skewed() {
        // Left-skewed: most values high, one outlier low.
        let values = vec![10.0, 10.0, 10.0, 10.0, 1.0];
        let sk = sample_skewness(&values).unwrap();
        assert!(
            sk < 0.0,
            "left-skewed data should have negative skewness, got {sk}"
        );
    }

    #[test]
    fn skewness_insufficient() {
        assert!(sample_skewness(&[1.0, 2.0]).is_none());
    }

    #[test]
    fn skewness_constant() {
        assert!(sample_skewness(&[5.0, 5.0, 5.0, 5.0]).is_none());
    }

    // -- Directional deterioration e-process --------------------------------

    #[test]
    fn deterioration_eprocess_is_scale_free_and_live() {
        let coarse = (0..32_i32)
            .map(|step| f64::from(31 - step) * (2.0 / 31.0))
            .collect::<Vec<_>>();
        let fine = coarse.iter().map(|value| value * 1e-9).collect::<Vec<_>>();

        let coarse_e = deterioration_eprocess(&coarse, 0.5);
        let fine_e = deterioration_eprocess(&fine, 0.5);
        assert_eq!(coarse_e, fine_e, "direction evidence must ignore units");
        assert!(
            coarse_e > 100.0,
            "a full monotone history window must activate strong evidence, got {coarse_e}"
        );
    }

    #[test]
    fn deterioration_eprocess_does_not_reward_stable_or_improving_history() {
        let stable = vec![1.0; 32];
        let improving = (0..32).map(f64::from).collect::<Vec<_>>();

        assert!(deterioration_eprocess(&stable, 0.5) <= 1.0);
        assert!(deterioration_eprocess(&improving, 0.5) <= 1.0);
    }

    // -- Return rate ----------------------------------------------------------

    #[test]
    fn return_rate_in_deteriorating_warning() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        // Steadily decreasing: high autocorrelation → low return rate.
        for i in 0..6_i32 {
            history.record(f64::from(i).mul_add(-0.15, 1.0));
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert!(warning.return_rate.is_some(), "should have return rate");
        let rr = warning.return_rate.unwrap();
        assert!(
            rr.is_finite() && rr >= 0.0,
            "return rate should be non-negative, got {rr}"
        );
    }

    // -- Early warning severity -----------------------------------------------

    #[test]
    fn severity_none_for_stable() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        // Constant values: no indicators active.
        for _ in 0..6 {
            history.record(0.5);
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert_eq!(
            warning.severity,
            EarlyWarningSeverity::None,
            "stable system should have severity None"
        );
    }

    #[test]
    fn severity_ordering() {
        // Severity levels should be ordered.
        assert!(EarlyWarningSeverity::None < EarlyWarningSeverity::Watch);
        assert!(EarlyWarningSeverity::Watch < EarlyWarningSeverity::Warning);
        assert!(EarlyWarningSeverity::Warning < EarlyWarningSeverity::Critical);
    }

    #[test]
    fn severity_display() {
        assert_eq!(EarlyWarningSeverity::None.to_string(), "none");
        assert_eq!(EarlyWarningSeverity::Watch.to_string(), "watch");
        assert_eq!(EarlyWarningSeverity::Warning.to_string(), "warning");
        assert_eq!(EarlyWarningSeverity::Critical.to_string(), "critical");
    }

    #[test]
    fn severity_elevated_for_strong_deterioration() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(16);

        // Rapidly deteriorating with high autocorrelation: should trigger
        // elevated severity.
        for i in 0..12_i32 {
            // Strong linear decline.
            history.record(f64::from(i).mul_add(-0.08, 1.0));
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert!(
            warning.severity >= EarlyWarningSeverity::Watch,
            "strong deterioration should elevate severity, got {:?}",
            warning.severity
        );
    }

    // -- Kendall in trend detection -------------------------------------------

    #[test]
    fn kendall_tau_in_warning() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        for i in 0..6_i32 {
            history.record(f64::from(i).mul_add(-0.15, 1.0));
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert!(
            warning.kendall_tau.is_some(),
            "should compute Kendall's tau"
        );
        let kt = warning.kendall_tau.unwrap();
        assert!(
            kt < -0.5,
            "monotone decrease should give strongly negative tau, got {kt}"
        );
    }

    // -- Skewness in warning --------------------------------------------------

    #[test]
    fn skewness_in_warning() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        // Slightly skewed deterioration.
        let values = [1.0, 0.9, 0.85, 0.82, 0.8, 0.3];
        for &v in &values {
            history.record(v);
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert!(warning.skewness.is_some(), "should compute skewness");
    }

    // -- Average rank ---------------------------------------------------------

    #[test]
    fn average_rank_no_ties() {
        let values = vec![3.0, 1.0, 4.0, 1.5, 5.0];
        let ranks = average_rank_f64(&values);
        // Sorted: 1.0(idx1)→1, 1.5(idx3)→2, 3.0(idx0)→3, 4.0(idx2)→4, 5.0(idx4)→5
        assert!((ranks[0] - 3.0).abs() < 1e-10);
        assert!((ranks[1] - 1.0).abs() < 1e-10);
        assert!((ranks[2] - 4.0).abs() < 1e-10);
        assert!((ranks[3] - 2.0).abs() < 1e-10);
        assert!((ranks[4] - 5.0).abs() < 1e-10);
    }

    #[test]
    fn average_rank_with_ties() {
        let values = vec![2.0, 1.0, 2.0, 3.0];
        let ranks = average_rank_f64(&values);
        // Sorted: 1.0(idx1)→1, 2.0(idx0)→2.5, 2.0(idx2)→2.5, 3.0(idx3)→4
        assert!((ranks[0] - 2.5).abs() < 1e-10);
        assert!((ranks[1] - 1.0).abs() < 1e-10);
        assert!((ranks[2] - 2.5).abs() < 1e-10);
        assert!((ranks[3] - 4.0).abs() < 1e-10);
    }

    // -- Hoeffding's D --------------------------------------------------------

    #[test]
    fn hoeffding_d_perfect_increasing() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let d = hoeffding_d(&values);
        assert!(d.is_some());
        assert!(
            d.unwrap() > 0.0,
            "monotone increase should show dependence, got {d:?}"
        );
    }

    #[test]
    fn hoeffding_d_perfect_decreasing() {
        let values = vec![5.0, 4.0, 3.0, 2.0, 1.0];
        let d = hoeffding_d(&values);
        assert!(d.is_some());
        assert!(
            d.unwrap() > 0.0,
            "monotone decrease should show dependence, got {d:?}"
        );
    }

    #[test]
    fn hoeffding_d_u_shape_detected() {
        // U-shaped pattern: Kendall's tau ≈ 0, but Hoeffding's D should
        // detect the non-monotone dependence.
        let values = vec![5.0, 3.0, 1.0, 0.5, 1.0, 3.0, 5.0];
        let d = hoeffding_d(&values);
        assert!(d.is_some());
        let d_val = d.unwrap();
        let tau = kendall_tau(&values);
        assert!(
            d_val > 0.0,
            "U-shape should show dependence in Hoeffding's D, got {d_val}"
        );
        // Kendall's tau should be weak for U-shape (near-zero monotone trend).
        assert!(
            tau.unwrap().abs() < 0.5,
            "U-shape should have weak Kendall's tau, got {tau:?}"
        );
    }

    #[test]
    fn hoeffding_d_insufficient() {
        assert!(hoeffding_d(&[1.0, 2.0, 3.0, 4.0]).is_none());
        assert!(hoeffding_d(&[1.0, 2.0, 3.0]).is_none());
        assert!(hoeffding_d(&[1.0]).is_none());
        assert!(hoeffding_d(&[]).is_none());
    }

    #[test]
    fn hoeffding_d_constant() {
        let values = vec![3.0, 3.0, 3.0, 3.0, 3.0];
        let d = hoeffding_d(&values);
        assert!(d.is_some());
        // Constant values → all ranks tied → D should be near 0.
        assert!(
            d.unwrap().abs() < 0.01,
            "constant series: D should be near 0, got {d:?}"
        );
    }

    #[test]
    fn hoeffding_d_symmetry_monotone() {
        // Increasing and decreasing should give the same D
        // (independence is direction-agnostic).
        let inc = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let dec = vec![6.0, 5.0, 4.0, 3.0, 2.0, 1.0];
        let d_inc = hoeffding_d(&inc).unwrap();
        let d_dec = hoeffding_d(&dec).unwrap();
        assert!(
            (d_inc - d_dec).abs() < 1e-10,
            "D should be symmetric: inc={d_inc}, dec={d_dec}"
        );
    }

    #[test]
    fn hoeffding_d_in_warning() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        for i in 0..6_i32 {
            history.record(f64::from(i).mul_add(-0.15, 1.0));
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert!(
            warning.hoeffding_d.is_some(),
            "should compute Hoeffding's D"
        );
        let d = warning.hoeffding_d.unwrap();
        assert!(
            d > 0.0,
            "monotone deterioration should show dependence, got {d}"
        );
    }

    #[test]
    fn hoeffding_d_stronger_than_tau_for_nonmonotone() {
        // Quadratic (parabola): strong non-monotone dependence.
        let values: Vec<f64> = (0..9)
            .map(|i| {
                let x = f64::from(i) - 4.0;
                x * x
            })
            .collect();
        let d = hoeffding_d(&values).unwrap();
        let tau = kendall_tau(&values).unwrap();
        // For a symmetric parabola, tau should be near 0.
        assert!(tau.abs() < 0.3, "parabola should have weak tau, got {tau}");
        // Hoeffding's D should detect the dependence.
        assert!(
            d > 0.0,
            "parabola should have positive Hoeffding's D, got {d}"
        );
    }

    // -- Spearman's rho -------------------------------------------------------

    #[test]
    fn spearman_rho_perfect_increasing() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let rho = spearman_rho(&values);
        assert!(rho.is_some());
        assert!(
            (rho.unwrap() - 1.0).abs() < 1e-10,
            "perfect increase: rho should be 1.0, got {rho:?}"
        );
    }

    #[test]
    fn spearman_rho_perfect_decreasing() {
        let values = vec![5.0, 4.0, 3.0, 2.0, 1.0];
        let rho = spearman_rho(&values);
        assert!(rho.is_some());
        assert!(
            (rho.unwrap() - (-1.0)).abs() < 1e-10,
            "perfect decrease: rho should be -1.0, got {rho:?}"
        );
    }

    #[test]
    fn spearman_rho_constant() {
        // Constant data yields zero variance in value ranks, so rho is undefined.
        let values = vec![3.0, 3.0, 3.0, 3.0, 3.0];
        assert!(spearman_rho(&values).is_none());
    }

    #[test]
    fn spearman_rho_insufficient() {
        assert!(spearman_rho(&[1.0, 2.0]).is_none());
        assert!(spearman_rho(&[1.0]).is_none());
        assert!(spearman_rho(&[]).is_none());
    }

    #[test]
    fn spearman_rho_agrees_with_kendall_direction() {
        // For monotone data, tau and rho should have the same sign.
        let dec = vec![1.0, 0.9, 0.85, 0.7, 0.5, 0.3];
        let tau = kendall_tau(&dec).unwrap();
        let rho = spearman_rho(&dec).unwrap();
        assert!(
            tau < 0.0 && rho < 0.0,
            "both should be negative: tau={tau}, rho={rho}"
        );
    }

    #[test]
    fn spearman_rho_in_warning() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        for i in 0..6_i32 {
            history.record(f64::from(i).mul_add(-0.15, 1.0));
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert!(
            warning.spearman_rho.is_some(),
            "should compute Spearman's rho"
        );
        let rho = warning.spearman_rho.unwrap();
        assert!(
            rho < -0.5,
            "monotone decrease should give strongly negative rho, got {rho}"
        );
    }

    #[test]
    fn spearman_rho_exponential_decay() {
        // Exponential decay is monotone: rho should be -1.0.
        let values: Vec<f64> = (0..10).map(|i| 100.0 * 0.7_f64.powi(i)).collect();
        let rho = spearman_rho(&values).unwrap();
        assert!(
            (rho - (-1.0)).abs() < 1e-10,
            "exponential decay is monotone: rho should be -1.0, got {rho}"
        );
    }

    // -- Distance correlation -------------------------------------------------

    #[test]
    fn distance_corr_perfect_linear_increasing() {
        let values: Vec<f64> = (0..10).map(f64::from).collect();
        let dc = distance_correlation(&values).unwrap();
        assert!(
            (dc - 1.0).abs() < 1e-10,
            "perfect linear increase: dCor should be 1.0, got {dc}"
        );
    }

    #[test]
    fn distance_corr_perfect_linear_decreasing() {
        let values: Vec<f64> = (0..10).rev().map(f64::from).collect();
        let dc = distance_correlation(&values).unwrap();
        assert!(
            (dc - 1.0).abs() < 1e-10,
            "perfect linear decrease: dCor should be 1.0, got {dc}"
        );
    }

    #[test]
    fn distance_corr_constant() {
        let values = vec![5.0; 10];
        let dc = distance_correlation(&values).unwrap();
        assert!(
            dc.abs() < 1e-10,
            "constant data: dCor should be 0.0, got {dc}"
        );
    }

    #[test]
    fn distance_corr_insufficient() {
        assert!(distance_correlation(&[1.0, 2.0, 3.0]).is_none());
        assert!(distance_correlation(&[1.0, 2.0]).is_none());
        assert!(distance_correlation(&[1.0]).is_none());
        assert!(distance_correlation(&[]).is_none());
    }

    #[test]
    fn distance_corr_quadratic_detects_nonmonotone() {
        // Quadratic: strong non-monotone dependence.
        // Rank-based methods struggle, but dCor should detect it.
        let values: Vec<f64> = (0..9)
            .map(|i| {
                let x = f64::from(i) - 4.0;
                x * x
            })
            .collect();
        let dc = distance_correlation(&values).unwrap();
        assert!(
            dc > 0.3,
            "quadratic should show dependence in dCor, got {dc}"
        );
    }

    #[test]
    fn distance_corr_linear_any_slope() {
        // dCor measures dependence strength, not slope magnitude.
        // Any perfectly linear series (regardless of slope) gives dCor = 1.0.
        let small_drop: Vec<f64> = (0..8).map(|i| f64::from(i).mul_add(-0.01, 1.0)).collect();
        let big_drop: Vec<f64> = (0..8).map(|i| f64::from(i).mul_add(-0.5, 1.0)).collect();

        let dc_small = distance_correlation(&small_drop).unwrap();
        let dc_big = distance_correlation(&big_drop).unwrap();

        assert!(
            dc_small > 0.99,
            "linear should give dCor~1.0, got {dc_small}"
        );
        assert!(dc_big > 0.99, "linear should give dCor~1.0, got {dc_big}");
    }

    #[test]
    fn distance_corr_in_warning() {
        let thresholds = SpectralThresholds::default();
        let mut history = SpectralHistory::new(8);

        for i in 0..6_i32 {
            history.record(f64::from(i).mul_add(-0.15, 1.0));
        }

        let warning = history.analyze(&thresholds).unwrap();
        assert!(
            warning.distance_corr.is_some(),
            "should compute distance correlation"
        );
        let dc = warning.distance_corr.unwrap();
        assert!(
            dc > 0.5,
            "monotone deterioration should show high dCor, got {dc}"
        );
    }

    #[test]
    fn distance_corr_range_0_to_1() {
        // Various patterns — dCor should always be in [0, 1].
        let patterns: Vec<Vec<f64>> = vec![
            (0..10).map(f64::from).collect(),
            (0..10).rev().map(f64::from).collect(),
            vec![1.0, 5.0, 2.0, 8.0, 3.0, 7.0, 4.0, 6.0],
            (0..9).map(|i| (f64::from(i) - 4.0).powi(2)).collect(),
        ];
        for (idx, vals) in patterns.iter().enumerate() {
            let dc = distance_correlation(vals).unwrap();
            assert!(
                (0.0..=1.0).contains(&dc),
                "pattern {idx}: dCor should be in [0,1], got {dc}"
            );
        }
    }

    // ================================================================
    // br-asupersync-r8pbrn / br-asupersync-k3aw0l
    // Replay-determinism regression tests
    // ================================================================

    /// `connected_components` must produce the same `(k, labels)` for
    /// the same input across repeated calls. Hashed-state leakage
    /// (e.g. via `std::collections::HashMap`'s RandomState) would
    /// historically be process-stable within a run but vary across
    /// processes; replacing the inner `label_map` with `BTreeMap`
    /// removes that surface entirely. We exercise the function many
    /// times in-process and assert byte-identical results.
    #[test]
    fn connected_components_is_deterministic_within_run() {
        // Two clusters: {0,1,2,3} and {4,5,6,7} with no bridge so we
        // exercise the multi-component label-assignment path.
        let edges = [(0, 1), (1, 2), (2, 3), (4, 5), (5, 6), (6, 7)];
        let lap = DependencyLaplacian::new(8, &edges);

        let (k, labels) = lap.connected_components();
        for _ in 0..16 {
            let (k2, labels2) = lap.connected_components();
            assert_eq!(k, k2, "component count must be stable across calls");
            assert_eq!(
                labels, labels2,
                "component labels must be stable across calls"
            );
        }
    }

    /// `connected_components` must assign labels in node-index order
    /// of first encounter. With the BTreeMap-backed label_map and the
    /// existing `for i in 0..size` loop, the first node visited is
    /// always 0, so its component (whatever the union-find root is)
    /// gets label 0. Likewise the next previously-unseen component
    /// gets label 1, etc. We assert this invariant directly.
    #[test]
    fn connected_components_labels_are_node_index_first_encounter_order() {
        let edges = [(0, 1), (2, 3), (4, 5)];
        let lap = DependencyLaplacian::new(6, &edges);
        let (k, labels) = lap.connected_components();
        assert_eq!(k, 3);
        // Nodes 0 and 1 share a component → label 0.
        assert_eq!(labels[0], 0);
        assert_eq!(labels[1], 0);
        // Nodes 2 and 3 share the second component → label 1.
        assert_eq!(labels[2], 1);
        assert_eq!(labels[3], 1);
        // Nodes 4 and 5 share the third → label 2.
        assert_eq!(labels[4], 2);
        assert_eq!(labels[5], 2);
    }

    /// `average_rank_f64` must produce identical rank vectors across
    /// repeated calls with the same input, even when ties are
    /// present. With the index tiebreak on the sort, the ordering
    /// inside tie groups is fully determined; without it, pdqsort's
    /// internal heuristics could rearrange ties differently between
    /// calls (especially after pattern-detection branches).
    #[test]
    fn average_rank_f64_is_deterministic_under_ties() {
        // Many tied values forcing the comparator into the Equal
        // branch repeatedly.
        let values = vec![1.0, 1.0, 2.0, 1.0, 3.0, 2.0, 1.0, 3.0, 2.0, 1.0];
        let r1 = average_rank_f64(&values);
        for _ in 0..16 {
            let r2 = average_rank_f64(&values);
            assert_eq!(r1, r2, "ranks must be stable across repeated calls");
        }
    }

    /// `average_rank_f64`'s tiebreak must NOT change the actual rank
    /// values for tie groups — tied entries still get the average
    /// midrank. Verify by computing ranks on a known input with two
    /// clear tie groups and asserting the assigned ranks match the
    /// midrank formula exactly.
    #[test]
    fn average_rank_f64_assigns_midrank_to_tie_groups() {
        // values: [10.0, 20.0, 20.0, 30.0]
        // sorted positions: 10 -> rank 1, two 20s tie at ranks 2 & 3
        // (avg = 2.5), 30 -> rank 4.
        let values = vec![10.0_f64, 20.0, 20.0, 30.0];
        let ranks = average_rank_f64(&values);
        assert_eq!(ranks[0], 1.0);
        assert!((ranks[1] - 2.5).abs() < f64::EPSILON);
        assert!((ranks[2] - 2.5).abs() < f64::EPSILON);
        assert_eq!(ranks[3], 4.0);
    }

    /// Three-way tie at the start: positions 1, 2, 3 in sorted order
    /// each get rank (1+2+3)/3 = 2.0 (using the (i+1+j)/2 midrank
    /// formula in the code: i=0, j=3 -> (1+3)/2 = 2.0).
    #[test]
    fn average_rank_f64_handles_three_way_tie() {
        let values = vec![5.0_f64, 5.0, 5.0, 99.0];
        let ranks = average_rank_f64(&values);
        assert_eq!(ranks[0], 2.0);
        assert_eq!(ranks[1], 2.0);
        assert_eq!(ranks[2], 2.0);
        assert_eq!(ranks[3], 4.0);
    }

    /// All-equal input: every entry gets the same average rank
    /// (n+1)/2.
    #[test]
    fn average_rank_f64_all_equal_input() {
        let values = vec![7.0_f64; 5];
        let ranks = average_rank_f64(&values);
        for &r in &ranks {
            assert_eq!(r, 3.0); // (1+5)/2 = 3.0
        }
    }
