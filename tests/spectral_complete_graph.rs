//! Spectral decomposition test for complete graphs.
use asupersync::observability::spectral_health::{
    DependencyLaplacian, HealthClassification, SpectralDecomposition, SpectralHealthMonitor,
    SpectralThresholds, classify_health, compute_spectral_decomposition, identify_bottlenecks,
};

#[test]
fn test_complete_graph() {
    let n = 4;
    let mut edges = Vec::new();
    for i in 0..n {
        for j in i + 1..n {
            edges.push((i, j));
        }
    }
    let laplacian = DependencyLaplacian::new(n, &edges);
    let thresholds = SpectralThresholds::default();
    let decomp = compute_spectral_decomposition(&laplacian, &thresholds);

    assert!(
        (decomp.fiedler_value - 4.0).abs() < f64::EPSILON,
        "Fiedler value is {}, expected 4.0",
        decomp.fiedler_value
    );
    // The Fiedler vector should be a unit vector
    let norm = decomp
        .fiedler_vector
        .iter()
        .map(|v| v * v)
        .sum::<f64>()
        .sqrt();
    assert!((norm - 1.0).abs() < 1e-5, "Norm is {norm}, expected 1.0");
}

#[test]
fn bottleneck_cutoff_is_relative_and_zero_safe() {
    let vector = [0.1, 0.4, -1.0];
    let scaled = vector.map(|component| component * 1e-300);

    assert_eq!(identify_bottlenecks(&vector, 0.4), vec![0, 1]);
    assert_eq!(identify_bottlenecks(&scaled, 0.4), vec![0, 1]);
    assert!(identify_bottlenecks(&[0.0, 0.0, 0.0], 0.4).is_empty());
}

#[test]
fn path_report_does_not_label_every_component_as_a_bottleneck() {
    let mut monitor = SpectralHealthMonitor::new(SpectralThresholds {
        critical_fiedler: 0.3,
        degraded_fiedler: 0.8,
        ..SpectralThresholds::default()
    });
    let report = monitor.analyze(4, &[(0, 1), (1, 2), (2, 3)]);

    assert!(
        matches!(
            &report.classification,
            HealthClassification::Degraded {
                bottleneck_nodes,
                ..
            } if bottleneck_nodes.is_empty()
        ),
        "P4 should have no component within 40% of the maximum magnitude: {report:?}"
    );
    assert!(report.bottlenecks.is_empty());
}

#[test]
fn exact_topology_overrides_a_positive_fiedler_residual() {
    let laplacian = DependencyLaplacian::new(4, &[(0, 1), (2, 3)]);
    let thresholds = SpectralThresholds::default();
    let decomposition = SpectralDecomposition {
        eigenvalues: vec![0.0, 2e-5, 2.0],
        fiedler_value: 2e-5,
        fiedler_vector: vec![-0.5, -0.5, 0.5, 0.5],
        spectral_gap: 1e-5,
        spectral_radius: 2.0,
        iterations_used: thresholds.max_iterations,
    };

    assert!(matches!(
        classify_health(&decomposition, &laplacian, &thresholds, false),
        HealthClassification::Fragmented { components: 2 }
    ));
}
