#![allow(warnings)]
#![allow(clippy::all)]
//! Spectral decomposition test for complete graphs.
use asupersync::observability::spectral_health::{
    DependencyLaplacian, SpectralThresholds, compute_spectral_decomposition,
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
