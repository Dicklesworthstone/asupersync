//! Spectral Runtime Health Monitor using graph Laplacian eigenvalue analysis.
//!
//! # Purpose
//!
//! Provides real-time health diagnostics by computing the spectral gap of the
//! task/region dependency graph. The spectral gap (the Fiedler value, the
//! second-smallest eigenvalue of the graph Laplacian) is a powerful indicator
//! of structural health:
//!
//! - The system is approaching deadlock when the Fiedler value approaches zero
//!   (the graph is about to disconnect).
//! - The system is healthy when the Fiedler value is large (the dependency
//!   graph is well-connected with redundant paths).
//! - Oscillatory eigenvalue trajectories indicate potential livelock (periodic
//!   behavior in the dependency structure).
//!
//! # Mathematical Foundation
//!
//! For a task dependency graph `G = (V, E)`:
//!
//! ```text
//! Degree matrix    D:  diagonal, D[i,i] = degree(node i)
//! Adjacency matrix A:  A[i,j] = 1 if edge (i,j) exists
//! Laplacian        L = D - A
//!
//! Eigenvalues:  0 = lambda_1 <= lambda_2 <= ... <= lambda_n
//! Fiedler value:  lambda_2 (algebraic connectivity; zero iff disconnected)
//! Spectral gap:   lambda_2 / lambda_n (normalized connectivity measure)
//! ```
//!
//! The Fiedler vector (eigenvector corresponding to `lambda_2`) identifies the
//! minimum graph cut -- the tasks that form the bottleneck separating the
//! dependency structure into weakly connected halves.
//!
//! # Cheeger Inequality
//!
//! The spectral gap relates to edge expansion via the Cheeger inequality:
//!
//! ```text
//! h(G) / 2  <=  lambda_2  <=  2 * h(G)
//! ```
//!
//! where `h(G)` is the Cheeger constant (edge expansion ratio). This provides
//! a graph-theoretic certificate that the runtime's dependency web has adequate
//! connectivity for healthy operation.
//!
//! # Bifurcation Early Warning
//!
//! By tracking the Fiedler value trajectory over time, we detect approach to
//! critical transitions (bifurcation points) where the system may abruptly
//! transition from healthy to degraded. The early warning signal uses:
//!
//! ```text
//! d(lambda_2)/dt  <  -threshold    =>    approaching critical transition
//! ```
//!
//! Combined with effective resistance measurements between key nodes, this
//! provides advance notice of impending structural failures.

use std::fmt;

// ============================================================================
// Configuration
// ============================================================================

/// Thresholds for health classification based on spectral properties.
#[derive(Debug, Clone, Copy)]
pub struct SpectralThresholds {
    /// Fiedler value below which the system is classified as critical.
    pub critical_fiedler: f64,
    /// Fiedler value below which the system is classified as degraded.
    pub degraded_fiedler: f64,
    /// Rate of Fiedler value decrease that triggers a bifurcation warning.
    pub bifurcation_rate_threshold: f64,
    /// Oscillation ratio threshold for classifying flicker/livelock behavior.
    pub oscillation_ratio_threshold: f64,
    /// Lag-1 autocorrelation threshold for critical slowing down detection.
    pub lag1_autocorr_threshold: f64,
    /// Variance growth ratio threshold between recent and earlier windows.
    pub variance_growth_ratio_threshold: f64,
    /// Absolute Fiedler component distance from zero used to identify nodes
    /// near the cut transition (`|component| <= threshold`).
    pub bottleneck_threshold: f64,
    /// Maximum number of power iteration steps.
    pub max_iterations: usize,
    /// Convergence tolerance for power iteration.
    pub convergence_tolerance: f64,
    /// Number of historical Fiedler values to retain for trend analysis.
    pub history_window: usize,
    /// Miscoverage for one-step split-conformal lower prediction bound.
    pub conformal_alpha: f64,
    /// E-process lambda for anytime-valid deterioration evidence.
    pub eprocess_lambda: f64,
}

impl SpectralThresholds {
    /// Creates default thresholds for runtime monitoring.
    ///
    /// These are starting values, not universal constants. Tune per workload.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            critical_fiedler: 0.01,
            degraded_fiedler: 0.1,
            bifurcation_rate_threshold: -0.05,
            oscillation_ratio_threshold: 0.5,
            lag1_autocorr_threshold: 0.7,
            variance_growth_ratio_threshold: 1.25,
            bottleneck_threshold: 0.4,
            max_iterations: 200,
            convergence_tolerance: 1e-10,
            history_window: 32,
            conformal_alpha: 0.1,
            eprocess_lambda: 0.5,
        }
    }
}

impl Default for SpectralThresholds {
    fn default() -> Self {
        Self::production()
    }
}

// ============================================================================
// Dependency Laplacian
// ============================================================================

/// Graph Laplacian for dependency analysis.
///
/// Represents an undirected graph as an adjacency list and precomputed degree
/// vector. The Laplacian `L = D - A` is applied implicitly via
/// [`laplacian_multiply`](Self::laplacian_multiply) to avoid materializing an
/// `n x n` matrix.
#[derive(Debug, Clone)]
pub struct DependencyLaplacian {
    /// Number of nodes in the graph.
    size: usize,
    /// Edges as `(u, v)` pairs with `u < v` (canonical form).
    edges: Vec<(usize, usize)>,
    /// Degree of each node (number of incident edges).
    degree: Vec<f64>,
    /// Adjacency list for efficient `L * x` multiplication.
    adjacency: Vec<Vec<usize>>,
}

/// Union-find: find with path compression.
fn uf_find(parent: &mut [usize], x: usize) -> usize {
    let mut root = x;
    while parent[root] != root {
        root = parent[root];
    }
    // Path compression.
    let mut cur = x;
    while parent[cur] != root {
        let next = parent[cur];
        parent[cur] = root;
        cur = next;
    }
    root
}

/// Union-find: union by rank.
fn uf_union(parent: &mut [usize], rank: &mut [u8], a: usize, b: usize) {
    let ra = uf_find(parent, a);
    let rb = uf_find(parent, b);
    if ra == rb {
        return;
    }
    match rank[ra].cmp(&rank[rb]) {
        std::cmp::Ordering::Less => parent[ra] = rb,
        std::cmp::Ordering::Greater => parent[rb] = ra,
        std::cmp::Ordering::Equal => {
            parent[rb] = ra;
            rank[ra] = rank[ra].saturating_add(1);
        }
    }
}

impl DependencyLaplacian {
    /// Constructs a Laplacian from a node count and edge list.
    ///
    /// Edges are deduplicated and stored in canonical form `(min, max)`.
    /// Self-loops are ignored.
    #[must_use]
    pub fn new(size: usize, edges: &[(usize, usize)]) -> Self {
        let mut adjacency = vec![Vec::new(); size];
        let mut degree = vec![0.0_f64; size];
        let mut canonical_edges = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for &(u, v) in edges {
            if u == v || u >= size || v >= size {
                continue;
            }
            let edge = if u < v { (u, v) } else { (v, u) };
            if seen.insert(edge) {
                canonical_edges.push(edge);
                adjacency[edge.0].push(edge.1);
                adjacency[edge.1].push(edge.0);
                degree[edge.0] += 1.0;
                degree[edge.1] += 1.0;
            }
        }

        Self {
            size,
            edges: canonical_edges,
            degree,
            adjacency,
        }
    }

    /// Returns the number of nodes.
    #[must_use]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the number of edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Returns a reference to the edge list.
    #[must_use]
    pub fn edges(&self) -> &[(usize, usize)] {
        &self.edges
    }

    /// Computes `y = L * x` where `L` is the graph Laplacian.
    ///
    /// This is `O(|V| + |E|)` and avoids materializing the full matrix.
    ///
    /// # Panics
    ///
    /// Panics if `x.len() != self.size` or `out.len() != self.size`.
    pub fn laplacian_multiply(&self, x: &[f64], out: &mut [f64]) {
        assert_eq!(x.len(), self.size, "input vector size mismatch");
        assert_eq!(out.len(), self.size, "output vector size mismatch");

        // L * x = D * x - A * x
        for i in 0..self.size {
            let mut sum = self.degree[i] * x[i]; // D * x
            for &j in &self.adjacency[i] {
                sum -= x[j]; // -A * x
            }
            out[i] = sum;
        }
    }

    /// Counts connected components using union-find.
    ///
    /// Returns `(component_count, component_labels)` where `component_labels[i]`
    /// is the component index for node `i`.
    #[must_use]
    pub fn connected_components(&self) -> (usize, Vec<usize>) {
        let mut parent: Vec<usize> = (0..self.size).collect();
        let mut rank = vec![0_u8; self.size];

        for &(u, v) in &self.edges {
            uf_union(&mut parent, &mut rank, u, v);
        }

        // Normalize labels to 0..k-1.
        let mut label_map = std::collections::HashMap::new();
        let mut labels = vec![0_usize; self.size];
        let mut next_label = 0_usize;
        for (i, label_slot) in labels.iter_mut().enumerate() {
            let root = uf_find(&mut parent, i);
            let label = *label_map.entry(root).or_insert_with(|| {
                let l = next_label;
                next_label += 1;
                l
            });
            *label_slot = label;
        }

        (next_label, labels)
    }
}

// ============================================================================
// Spectral Decomposition
// ============================================================================

/// Result of spectral decomposition of the graph Laplacian.
#[derive(Debug, Clone)]
pub struct SpectralDecomposition {
    /// Sorted eigenvalues `0 = lambda_1 <= lambda_2 <= ... <= lambda_n`.
    pub eigenvalues: Vec<f64>,
    /// Second-smallest eigenvalue (algebraic connectivity).
    pub fiedler_value: f64,
    /// Eigenvector corresponding to the Fiedler value.
    pub fiedler_vector: Vec<f64>,
    /// Normalized spectral gap `lambda_2 / lambda_n` (0 if `lambda_n == 0`).
    pub spectral_gap: f64,
    /// Largest eigenvalue (spectral radius of the Laplacian).
    pub spectral_radius: f64,
    /// Number of power iteration steps used for convergence.
    pub iterations_used: usize,
}

/// Computes spectral decomposition of a graph Laplacian using power iteration
/// with deflation.
///
/// # Algorithm
///
/// 1. **Largest eigenvalue** (`lambda_n`): Standard power iteration on `L`.
/// 2. **Fiedler value** (`lambda_2`): Inverse power iteration on `L` with
///    deflation of the constant eigenvector (null space of `L`).
///
/// For the Fiedler value we use shifted inverse iteration: we apply power
/// iteration to `(sigma * I - L)` where `sigma` is a shift near `lambda_n`.
/// This makes the smallest non-trivial eigenvalue the dominant one.
///
/// The Fiedler vector is the converged eigenvector, normalized to unit length
/// with the component corresponding to the uniform eigenvector projected out.
#[must_use]
pub fn compute_spectral_decomposition(
    laplacian: &DependencyLaplacian,
    thresholds: &SpectralThresholds,
) -> SpectralDecomposition {
    let n = laplacian.size();

    // Degenerate cases.
    if n == 0 {
        return SpectralDecomposition {
            eigenvalues: Vec::new(),
            fiedler_value: 0.0,
            fiedler_vector: Vec::new(),
            spectral_gap: 0.0,
            spectral_radius: 0.0,
            iterations_used: 0,
        };
    }
    if n == 1 {
        return SpectralDecomposition {
            eigenvalues: vec![0.0],
            fiedler_value: 0.0,
            fiedler_vector: vec![0.0],
            spectral_gap: 0.0,
            spectral_radius: 0.0,
            iterations_used: 0,
        };
    }

    // Step 1: Find largest eigenvalue (spectral radius) via power iteration.
    let (lambda_n, _) = power_iteration_largest(laplacian, thresholds);

    // Step 2: Find Fiedler value and vector via shifted power iteration.
    // We iterate on M = sigma*I - L, where sigma = lambda_n.
    // The eigenvalues of M are sigma - lambda_i.
    // The largest eigenvalue of M corresponds to the smallest lambda_i.
    // Since lambda_1 = 0, the largest eigenvalue of M is sigma.
    // The second-largest eigenvalue of M is sigma - lambda_2.
    // We deflate the constant eigenvector to skip lambda_1 = 0 and find lambda_2.
    let (fiedler_value, fiedler_vector, iterations_used) =
        find_fiedler(laplacian, lambda_n, thresholds);

    // Compute approximate eigenvalue list: [0, fiedler_value, ..., lambda_n].
    // For a full decomposition we would need O(n^2) work; we provide the
    // structurally important values.
    let mut eigenvalues = vec![0.0, fiedler_value];
    if n > 2 && lambda_n > fiedler_value + thresholds.convergence_tolerance {
        eigenvalues.push(lambda_n);
    }

    let spectral_gap = if lambda_n > thresholds.convergence_tolerance {
        fiedler_value / lambda_n
    } else {
        0.0
    };

    SpectralDecomposition {
        eigenvalues,
        fiedler_value,
        fiedler_vector,
        spectral_gap,
        spectral_radius: lambda_n,
        iterations_used,
    }
}

/// Standard power iteration for the largest eigenvalue of `L`.
///
/// Returns `(eigenvalue, eigenvector)`.
fn power_iteration_largest(
    laplacian: &DependencyLaplacian,
    thresholds: &SpectralThresholds,
) -> (f64, Vec<f64>) {
    let n = laplacian.size();
    let mut x = vec![0.0_f64; n];
    let mut y = vec![0.0_f64; n];

    // Initialize with a non-uniform vector to break symmetry.
    #[allow(clippy::cast_precision_loss)]
    for (i, xi) in x.iter_mut().enumerate() {
        *xi = (i as f64).mul_add(0.01, 1.0);
    }
    normalize(&mut x);

    let mut eigenvalue = 0.0_f64;

    for _ in 0..thresholds.max_iterations {
        laplacian.laplacian_multiply(&x, &mut y);
        let new_eigenvalue = dot(&x, &y);
        normalize(&mut y);

        if (new_eigenvalue - eigenvalue).abs() < thresholds.convergence_tolerance {
            return (new_eigenvalue.max(0.0), y);
        }

        eigenvalue = new_eigenvalue;
        std::mem::swap(&mut x, &mut y);
    }

    (eigenvalue.max(0.0), x)
}

/// Finds the Fiedler value and vector using shifted power iteration with
/// deflation of the constant eigenvector.
///
/// Returns `(fiedler_value, fiedler_vector, iterations)`.
fn find_fiedler(
    laplacian: &DependencyLaplacian,
    sigma: f64,
    thresholds: &SpectralThresholds,
) -> (f64, Vec<f64>, usize) {
    let n = laplacian.size();

    if n <= 1 {
        return (0.0, vec![0.0; n], 0);
    }

    // For a disconnected graph, the Fiedler value is 0 and the Fiedler vector
    // indicates the partition.
    let (components, labels) = laplacian.connected_components();
    if components > 1 {
        // Graph is disconnected: lambda_2 = 0.
        // Fiedler vector: +1 for component 0, -1 for others.
        let mut fv = vec![0.0_f64; n];
        for (i, &label) in labels.iter().enumerate() {
            fv[i] = if label == 0 { 1.0 } else { -1.0 };
        }
        normalize(&mut fv);
        return (0.0, fv, 0);
    }

    // Shifted power iteration: iterate on M = sigma*I - L.
    // The dominant eigenvector of M (after deflating the constant vector
    // corresponding to eigenvalue sigma - 0 = sigma) gives us the
    // eigenvector for sigma - lambda_2, i.e., the Fiedler vector.
    let mut x = vec![0.0_f64; n];
    let mut y = vec![0.0_f64; n];
    let mut lx = vec![0.0_f64; n]; // workspace for L*x

    // Initialize with a vector orthogonal to the constant vector.
    // Use alternating signs to ensure orthogonality after projection.
    #[allow(clippy::cast_precision_loss)]
    for (i, xi) in x.iter_mut().enumerate() {
        let sign = if i % 2 == 0 { 1.0 } else { -1.0 };
        // Add a slight gradient to help convergence for regular graphs.
        *xi = (i as f64).mul_add(0.001, sign);
    }
    project_out_constant(&mut x);
    normalize(&mut x);

    let mut eigenvalue_m = 0.0_f64;
    let mut iterations = 0_usize;

    for iter in 0..thresholds.max_iterations {
        // y = M * x = sigma * x - L * x
        laplacian.laplacian_multiply(&x, &mut lx);
        for (i, yi) in y.iter_mut().enumerate() {
            *yi = sigma.mul_add(x[i], -lx[i]);
        }

        // Deflate the constant eigenvector (project out the uniform component).
        project_out_constant(&mut y);

        let new_eigenvalue_m = dot(&x, &y);
        normalize(&mut y);

        iterations = iter + 1;
        if (new_eigenvalue_m - eigenvalue_m).abs() < thresholds.convergence_tolerance {
            // lambda_2 = sigma - eigenvalue_of_M
            let fiedler = (sigma - new_eigenvalue_m).max(0.0);
            return (fiedler, y, iterations);
        }

        eigenvalue_m = new_eigenvalue_m;
        std::mem::swap(&mut x, &mut y);
    }

    let fiedler = (sigma - eigenvalue_m).max(0.0);
    (fiedler, x, iterations)
}

/// Projects out the component along the constant vector `(1/sqrt(n), ..., 1/sqrt(n))`.
fn project_out_constant(v: &mut [f64]) {
    let n = v.len();
    if n == 0 {
        return;
    }
    #[allow(clippy::cast_precision_loss)]
    let mean = v.iter().sum::<f64>() / (n as f64);
    for vi in v.iter_mut() {
        *vi -= mean;
    }
}

/// Computes the dot product of two vectors.
#[must_use]
fn dot(a: &[f64], b: &[f64]) -> f64 {
    a.iter().zip(b.iter()).map(|(ai, bi)| ai * bi).sum()
}

/// Normalizes a vector to unit length. If the vector is zero, it is left unchanged.
fn normalize(v: &mut [f64]) {
    let norm = dot(v, v).sqrt();
    if norm > f64::EPSILON {
        for vi in v.iter_mut() {
            *vi /= norm;
        }
    }
}

// ============================================================================
// Health Classification
// ============================================================================

/// Health classification with evidence.
#[derive(Debug, Clone)]
pub enum HealthClassification {
    /// The dependency graph is well-connected.
    Healthy {
        /// Margin above the degraded threshold (fiedler - degraded_threshold).
        margin: f64,
    },
    /// The graph has concerning bottlenecks but is still connected.
    Degraded {
        /// Current Fiedler value.
        fiedler: f64,
        /// Node indices that form the bottleneck (large Fiedler vector components).
        bottleneck_nodes: Vec<usize>,
    },
    /// The graph is nearing disconnection.
    Critical {
        /// Current Fiedler value.
        fiedler: f64,
        /// Whether the trend indicates imminent disconnection.
        approaching_disconnect: bool,
    },
    /// The graph is disconnected (Fiedler value is zero).
    Deadlocked {
        /// Number of connected components.
        components: usize,
    },
}

impl fmt::Display for HealthClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy { margin } => {
                write!(f, "Healthy (margin={margin:.4})")
            }
            Self::Degraded {
                fiedler,
                bottleneck_nodes,
            } => {
                write!(
                    f,
                    "Degraded (fiedler={fiedler:.4}, bottleneck_nodes={})",
                    bottleneck_nodes.len()
                )
            }
            Self::Critical {
                fiedler,
                approaching_disconnect,
            } => {
                write!(
                    f,
                    "Critical (fiedler={fiedler:.4}, approaching_disconnect={approaching_disconnect})"
                )
            }
            Self::Deadlocked { components } => {
                write!(f, "Deadlocked (components={components})")
            }
        }
    }
}

/// Classifies system health based on spectral decomposition.
#[must_use]
pub fn classify_health(
    decomposition: &SpectralDecomposition,
    laplacian: &DependencyLaplacian,
    thresholds: &SpectralThresholds,
    approaching_disconnect: bool,
) -> HealthClassification {
    let fiedler = decomposition.fiedler_value;

    // Check for disconnected graph first.
    if fiedler < thresholds.convergence_tolerance {
        let (components, _) = laplacian.connected_components();
        if components > 1 {
            return HealthClassification::Deadlocked { components };
        }
    }

    if fiedler < thresholds.critical_fiedler {
        return HealthClassification::Critical {
            fiedler,
            approaching_disconnect,
        };
    }

    if fiedler < thresholds.degraded_fiedler {
        let bottleneck_nodes = identify_bottlenecks(
            &decomposition.fiedler_vector,
            thresholds.bottleneck_threshold,
        );
        return HealthClassification::Degraded {
            fiedler,
            bottleneck_nodes,
        };
    }

    HealthClassification::Healthy {
        margin: fiedler - thresholds.degraded_fiedler,
    }
}

/// Identifies bottleneck nodes from the Fiedler vector.
///
/// Nodes with Fiedler components near zero lie near the minimum-cut transition
/// and represent structural bottlenecks.
#[must_use]
pub fn identify_bottlenecks(fiedler_vector: &[f64], threshold: f64) -> Vec<usize> {
    let threshold = threshold.abs();
    // Find the transition region: nodes whose Fiedler vector component is
    // close to zero are near the cut. We identify these as bottlenecks.
    fiedler_vector
        .iter()
        .enumerate()
        .filter(|&(_, v)| v.abs() <= threshold)
        .map(|(i, _)| i)
        .collect()
}

// ============================================================================
// Bottleneck Analysis
// ============================================================================

/// A node identified as a structural bottleneck in the dependency graph.
#[derive(Debug, Clone)]
pub struct BottleneckNode {
    /// Node index in the graph.
    pub node_index: usize,
    /// Fiedler vector component for this node.
    pub fiedler_component: f64,
    /// Degree of this node (number of dependencies).
    pub degree: usize,
    /// Effective resistance to the graph centroid (higher = more isolated).
    pub effective_resistance: f64,
}

/// Computes effective resistance between two nodes using the spectral
/// decomposition.
///
/// ```text
/// R_eff(u, v) = sum_{i>=2} (phi_i(u) - phi_i(v))^2 / lambda_i
/// ```
///
/// Since we only have `lambda_2` and `lambda_n`, this provides a lower bound
/// on the true effective resistance.
#[must_use]
pub fn effective_resistance_bound(
    decomposition: &SpectralDecomposition,
    u: usize,
    v: usize,
) -> f64 {
    if decomposition.fiedler_value < f64::EPSILON {
        return f64::INFINITY;
    }

    let fv = &decomposition.fiedler_vector;
    if u >= fv.len() || v >= fv.len() {
        return f64::INFINITY;
    }

    let diff = fv[u] - fv[v];
    (diff * diff) / decomposition.fiedler_value
}

/// Computes detailed bottleneck analysis for the graph.
#[must_use]
pub fn analyze_bottlenecks(
    decomposition: &SpectralDecomposition,
    laplacian: &DependencyLaplacian,
    threshold: f64,
) -> Vec<BottleneckNode> {
    let n = laplacian.size();
    if n == 0 {
        return Vec::new();
    }

    let fv = &decomposition.fiedler_vector;
    let near_cut: Vec<usize> = identify_bottlenecks(fv, threshold);

    // Compute centroid node (closest to mean Fiedler component).
    #[allow(clippy::cast_precision_loss)]
    let mean = if fv.is_empty() {
        0.0
    } else {
        fv.iter().sum::<f64>() / (fv.len() as f64)
    };
    let centroid = fv
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| {
            let da = (*a - mean).abs();
            let db = (*b - mean).abs();
            da.partial_cmp(&db).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map_or(0, |(i, _)| i);

    near_cut
        .into_iter()
        .map(|idx| {
            let r_eff = effective_resistance_bound(decomposition, idx, centroid);
            BottleneckNode {
                node_index: idx,
                fiedler_component: if idx < fv.len() { fv[idx] } else { 0.0 },
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                degree: laplacian.degree[idx] as usize,
                effective_resistance: r_eff,
            }
        })
        .collect()
}

// ============================================================================
// Spectral Trend and Bifurcation Warning
// ============================================================================

/// Direction of spectral gap change over time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpectralTrend {
    /// The Fiedler value is increasing (improving connectivity).
    Improving,
    /// The Fiedler value is stable.
    Stable,
    /// The Fiedler value is decreasing (deteriorating connectivity).
    Deteriorating,
    /// The Fiedler value is oscillating (potential livelock signature).
    Oscillating,
}

impl fmt::Display for SpectralTrend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Improving => f.write_str("improving"),
            Self::Stable => f.write_str("stable"),
            Self::Deteriorating => f.write_str("deteriorating"),
            Self::Oscillating => f.write_str("oscillating"),
        }
    }
}

/// Severity level of the bifurcation early warning signal.
///
/// Combines all Scheffer et al. (2009) indicators — critical slowing down
/// (rising autocorrelation), variance amplification, flickering, and trend
/// slope — into a single actionable severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EarlyWarningSeverity {
    /// No indicators are active. System appears stable.
    None,
    /// One indicator is weakly active. Monitor but no action needed.
    Watch,
    /// Two or more indicators are active, or one is strongly active.
    Warning,
    /// Multiple indicators strongly active. Intervention recommended.
    Critical,
}

impl fmt::Display for EarlyWarningSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Watch => f.write_str("watch"),
            Self::Warning => f.write_str("warning"),
            Self::Critical => f.write_str("critical"),
        }
    }
}

/// Bifurcation early warning signal.
///
/// Detects approach to critical transitions in the dependency graph by
/// monitoring the rate of change and oscillation pattern of the Fiedler value.
/// Implements the full Scheffer et al. (2009) early warning toolkit:
///
/// 1. **Critical slowing down**: rising lag-1 autocorrelation (the system
///    recovers more slowly from perturbations as it approaches bifurcation).
/// 2. **Variance amplification**: increasing fluctuation magnitude in the
///    second half of the observation window vs the first.
/// 3. **Flickering**: rapid oscillation between states indicating proximity
///    to a bistable tipping point.
/// 4. **Skewness shift**: asymmetry growth as the system's potential landscape
///    becomes lopsided near the bifurcation.
/// 5. **Kendall's tau**: nonparametric monotone trend strength for robust
///    deterioration detection even with non-linear decline patterns.
/// 6. **Hoeffding's D**: nonparametric independence test that catches *any*
///    dependence structure — including U-shaped, oscillatory, and non-monotone
///    patterns that Kendall's tau would miss (Hoeffding, 1948).
/// 7. **Spearman's rho**: rank correlation that weights large rank displacements
///    quadratically, complementing Kendall's tau's pairwise concordance approach.
/// 8. **Distance correlation**: operates on raw metric distances rather than ranks,
///    capturing magnitude and acceleration information that rank transforms discard
///    (Székely, Rizzo & Bakirov, 2007). dCor = 0 iff independence.
#[derive(Debug, Clone)]
pub struct BifurcationWarning {
    /// Current spectral trend direction.
    pub trend: SpectralTrend,
    /// Linear-trend slope of Fiedler value history (per step).
    pub slope: f64,
    /// Estimated time steps until the Fiedler value crosses the critical
    /// threshold, based on linear extrapolation. `None` if the trend is not
    /// deteriorating or if the extrapolation is non-positive.
    pub time_to_critical: Option<f64>,
    /// Lag-1 autocorrelation (critical slowing-down indicator).
    pub lag1_autocorrelation: Option<f64>,
    /// Rolling sample variance of the current history window.
    pub rolling_variance: Option<f64>,
    /// Ratio of second-half variance to first-half variance.
    pub variance_ratio: Option<f64>,
    /// Ratio of sign changes in first differences (flicker score).
    pub flicker_score: f64,
    /// Kendall's tau rank correlation for nonparametric trend detection.
    /// Range `[-1, 1]`. Strong negative values indicate monotone deterioration.
    /// More robust than linear R² for non-linear monotone trends.
    pub kendall_tau: Option<f64>,
    /// Spearman's rho rank correlation coefficient.
    /// Range `[-1, 1]`. Weights large rank displacements more heavily than
    /// Kendall's tau (quadratic vs linear penalty), so it is more sensitive
    /// to a few extreme outlier shifts while tau is more robust to them.
    pub spearman_rho: Option<f64>,
    /// Hoeffding's D independence statistic.
    /// Range `[-0.5, 1]` where `0` means independence and positive values
    /// indicate dependence (of *any* form — monotone, U-shaped, oscillatory).
    /// Complements Kendall's tau by detecting non-monotone patterns.
    pub hoeffding_d: Option<f64>,
    /// Distance correlation between time index and observed values.
    /// Range `[0, 1]` where `0` means independence and `1` means perfect
    /// dependence. Unlike rank-based methods (Kendall, Spearman), this
    /// operates on raw metric distances, capturing magnitude and acceleration
    /// information that rank transforms discard.
    pub distance_corr: Option<f64>,
    /// Sample skewness of the Fiedler history window.
    /// Asymmetry growth near bifurcation points (Scheffer et al., 2009).
    pub skewness: Option<f64>,
    /// Estimated return rate: `1 - lag1_autocorrelation`.
    /// Approaches zero at critical transitions (critical slowing down).
    /// Directly interpretable as "recovery speed from perturbations."
    pub return_rate: Option<f64>,
    /// Split-conformal lower bound for the next Fiedler value.
    pub conformal_lower_bound_next: Option<f64>,
    /// Anytime-valid e-process against non-deteriorating null.
    pub deterioration_e_value: f64,
    /// Composite early warning severity level combining all indicators.
    pub severity: EarlyWarningSeverity,
    /// Confidence in the warning (based on consistency of the trend).
    /// Range `[0.0, 1.0]`.
    pub confidence: f64,
}

impl fmt::Display for BifurcationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BifurcationWarning(trend={}", self.trend)?;
        write!(f, ", severity={}", self.severity)?;
        write!(f, ", slope={:.5}", self.slope)?;
        if let Some(ttc) = self.time_to_critical {
            write!(f, ", time_to_critical={ttc:.2}")?;
        }
        if let Some(ac1) = self.lag1_autocorrelation {
            write!(f, ", ac1={ac1:.3}")?;
        }
        if let Some(rr) = self.return_rate {
            write!(f, ", return_rate={rr:.3}")?;
        }
        if let Some(vr) = self.variance_ratio {
            write!(f, ", var_ratio={vr:.3}")?;
        }
        if let Some(kt) = self.kendall_tau {
            write!(f, ", kendall_tau={kt:.3}")?;
        }
        if let Some(sr) = self.spearman_rho {
            write!(f, ", spearman_rho={sr:.3}")?;
        }
        if let Some(hd) = self.hoeffding_d {
            write!(f, ", hoeffding_d={hd:.4}")?;
        }
        if let Some(dc) = self.distance_corr {
            write!(f, ", dcor={dc:.4}")?;
        }
        if let Some(sk) = self.skewness {
            write!(f, ", skew={sk:.3}")?;
        }
        write!(
            f,
            ", flicker={:.3}, e_value={:.3}",
            self.flicker_score, self.deterioration_e_value
        )?;
        write!(f, ", confidence={:.2})", self.confidence)
    }
}

/// History tracker for spectral trend analysis.
#[derive(Debug, Clone)]
pub struct SpectralHistory {
    /// Ring buffer of recent Fiedler values.
    values: Vec<f64>,
    /// Write cursor into the ring buffer.
    cursor: usize,
    /// Number of values stored (up to `capacity`).
    count: usize,
    /// Maximum capacity.
    capacity: usize,
}

impl SpectralHistory {
    /// Creates a new history tracker with the given capacity.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(2);
        Self {
            values: vec![0.0; capacity],
            cursor: 0,
            count: 0,
            capacity,
        }
    }

    /// Records a new Fiedler value observation.
    pub fn record(&mut self, fiedler_value: f64) {
        self.values[self.cursor] = fiedler_value;
        self.cursor = (self.cursor + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
    }

    /// Returns the number of recorded observations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no observations have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns stored values in chronological order (oldest first).
    #[must_use]
    fn chronological(&self) -> Vec<f64> {
        if self.count < self.capacity {
            self.values[..self.count].to_vec()
        } else {
            let mut result = Vec::with_capacity(self.capacity);
            result.extend_from_slice(&self.values[self.cursor..]);
            result.extend_from_slice(&self.values[..self.cursor]);
            result
        }
    }

    /// Analyzes the trend and produces a bifurcation warning.
    ///
    /// Uses linear regression on the recent history to estimate the rate of
    /// change, and sign-change analysis for oscillation detection.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn analyze(&self, thresholds: &SpectralThresholds) -> Option<BifurcationWarning> {
        if self.count < 3 {
            return None;
        }

        let values = self.chronological();
        let n = values.len();

        // Linear regression: slope of Fiedler value over time steps.
        let slope = linear_regression_slope(&values);

        // Oscillation detection: count sign changes in first differences.
        let mut sign_changes = 0_usize;
        let mut prev_diff = 0.0_f64;
        for i in 1..n {
            let diff = values[i] - values[i - 1];
            if diff.abs() > thresholds.convergence_tolerance {
                if prev_diff.abs() > thresholds.convergence_tolerance
                    && diff.signum() != prev_diff.signum()
                {
                    sign_changes += 1;
                }
                prev_diff = diff;
            }
        }

        // Classify trend.
        #[allow(clippy::cast_precision_loss)]
        let oscillation_ratio = if n > 2 {
            sign_changes as f64 / (n - 2) as f64
        } else {
            0.0
        };
        // --- Scheffer et al. (2009) early warning indicators ---

        // (1) Critical slowing down: rising lag-1 autocorrelation.
        let lag1_autocorrelation = lag1_autocorrelation(&values);
        let critical_slowing = lag1_autocorrelation
            .is_some_and(|ac1| ac1 >= thresholds.lag1_autocorr_threshold && ac1.is_finite());

        // (2) Return rate: 1 - AC1. Approaches zero at tipping points.
        let return_rate = lag1_autocorrelation.map(|ac1| (1.0 - ac1).clamp(0.0, 2.0));

        // (3) Variance amplification.
        let rolling_variance = sample_variance(&values);
        let variance_ratio = variance_ratio_halves(&values);
        let variance_growth = variance_ratio
            .is_some_and(|vr| vr >= thresholds.variance_growth_ratio_threshold && vr.is_finite());

        // (4) Kendall's tau and Spearman's rho: nonparametric monotone trend tests.
        // Tau uses pairwise concordance (robust), rho uses squared rank differences
        // (sensitive to large displacements). Both provide corroborating evidence.
        let kendall_tau_val = kendall_tau(&values);
        let spearman_rho_val = spearman_rho(&values);

        // (5) Skewness: asymmetry growth near bifurcation.
        let skewness = sample_skewness(&values);

        // (5b) Hoeffding's D: nonparametric independence test.
        // Catches non-monotone dependence that Kendall's tau would miss.
        let hoeffding_d_val = hoeffding_d(&values);

        // (5c) Distance correlation: operates on raw metric distances, not ranks.
        // Captures magnitude/acceleration info that rank methods discard.
        let distance_corr_val = distance_correlation(&values);

        // (6) Conformal prediction + e-process.
        let conformal_lower_bound_next =
            split_conformal_lower_next(&values, thresholds.conformal_alpha);
        let deterioration_e_value = deterioration_eprocess(&values, thresholds.eprocess_lambda);

        // --- Trend classification ---
        // Uses Kendall's tau and Spearman's rho alongside slope for robust detection.
        let strong_kendall_decline = kendall_tau_val.is_some_and(|kt| kt < -0.5);
        let strong_spearman_decline = spearman_rho_val.is_some_and(|sr| sr < -0.5);
        let trend = if oscillation_ratio > thresholds.oscillation_ratio_threshold {
            SpectralTrend::Oscillating
        } else if slope < thresholds.bifurcation_rate_threshold
            || (slope < 0.0 && critical_slowing)
            || (slope < 0.0 && strong_kendall_decline)
            || (slope < 0.0 && strong_spearman_decline)
        {
            SpectralTrend::Deteriorating
        } else if slope > -thresholds.bifurcation_rate_threshold {
            SpectralTrend::Improving
        } else {
            SpectralTrend::Stable
        };

        // Time to critical: linear extrapolation.
        let last_value = values[n - 1];
        let time_to_critical =
            if trend == SpectralTrend::Deteriorating && slope < -thresholds.convergence_tolerance {
                let remaining = last_value - thresholds.critical_fiedler;
                if remaining > 0.0 {
                    Some(remaining / (-slope))
                } else {
                    Some(0.0) // Already below critical.
                }
            } else {
                None
            };

        // --- Composite severity classification ---
        // Count active warning indicators per Scheffer et al. framework.
        let mut active_indicators = 0_u32;
        let mut strong_indicators = 0_u32;

        if critical_slowing {
            active_indicators += 1;
            if lag1_autocorrelation.is_some_and(|ac1| ac1 > 0.85) {
                strong_indicators += 1;
            }
        }
        if variance_growth {
            active_indicators += 1;
            if variance_ratio.is_some_and(|vr| vr > 2.0) {
                strong_indicators += 1;
            }
        }
        if oscillation_ratio > thresholds.oscillation_ratio_threshold {
            active_indicators += 1;
        }
        if strong_kendall_decline {
            active_indicators += 1;
        }
        if strong_spearman_decline {
            active_indicators += 1;
        }
        if skewness.is_some_and(|sk| sk.abs() > 1.0) {
            active_indicators += 1;
        }
        if hoeffding_d_val.is_some_and(|d| d > 0.03) {
            active_indicators += 1;
            if hoeffding_d_val.is_some_and(|d| d > 0.10) {
                strong_indicators += 1;
            }
        }
        if distance_corr_val.is_some_and(|dc| dc > 0.5) {
            active_indicators += 1;
            if distance_corr_val.is_some_and(|dc| dc > 0.8) {
                strong_indicators += 1;
            }
        }
        if deterioration_e_value > 20.0 {
            active_indicators += 1;
            if deterioration_e_value > 100.0 {
                strong_indicators += 1;
            }
        }

        let severity = if strong_indicators >= 2 || active_indicators >= 4 {
            EarlyWarningSeverity::Critical
        } else if active_indicators >= 2 || strong_indicators >= 1 {
            EarlyWarningSeverity::Warning
        } else if active_indicators >= 1 {
            EarlyWarningSeverity::Watch
        } else {
            EarlyWarningSeverity::None
        };

        // Confidence blends linear fit consistency with all indicator signals.
        // All 10 indicators weighted equally at 0.10 → sum=1.00
        let r2 = linear_regression_r_squared(&values).clamp(0.0, 1.0);
        let slowing_signal = if critical_slowing { 1.0 } else { 0.0 };
        let variance_signal = if variance_growth { 1.0 } else { 0.0 };
        let e_signal = (deterioration_e_value.ln_1p() / 4.0).clamp(0.0, 1.0);
        let kendall_signal = kendall_tau_val.map_or(0.0, |kt| (-kt).clamp(0.0, 1.0));
        let spearman_signal = spearman_rho_val.map_or(0.0, |sr| (-sr).clamp(0.0, 1.0));
        let hoeffding_signal = hoeffding_d_val.map_or(0.0, |d| d.clamp(0.0, 1.0));
        let dcor_signal = distance_corr_val.map_or(0.0, |dc| dc.clamp(0.0, 1.0));
        let skewness_signal = skewness.map_or(0.0, |sk| (sk.abs() / 2.0).clamp(0.0, 1.0));
        let confidence = 0.10f64
            .mul_add(
                oscillation_ratio.min(1.0),
                0.10f64.mul_add(
                    e_signal,
                    0.10f64.mul_add(
                        skewness_signal,
                        0.10f64.mul_add(
                            dcor_signal,
                            0.10f64.mul_add(
                                hoeffding_signal,
                                0.10f64.mul_add(
                                    spearman_signal,
                                    0.10f64.mul_add(
                                        kendall_signal,
                                        0.10f64.mul_add(
                                            variance_signal,
                                            0.10f64.mul_add(slowing_signal, 0.10 * r2),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            )
            .clamp(0.0, 1.0);

        Some(BifurcationWarning {
            trend,
            slope,
            time_to_critical,
            lag1_autocorrelation,
            rolling_variance,
            variance_ratio,
            flicker_score: oscillation_ratio,
            kendall_tau: kendall_tau_val,
            spearman_rho: spearman_rho_val,
            hoeffding_d: hoeffding_d_val,
            distance_corr: distance_corr_val,
            skewness,
            return_rate,
            conformal_lower_bound_next,
            deterioration_e_value,
            severity,
            confidence,
        })
    }
}

/// Computes the slope of a simple linear regression on evenly-spaced values.
///
/// `x_i = i`, `y_i = values[i]`. Returns the OLS slope estimate.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn linear_regression_slope(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 2 {
        return 0.0;
    }

    let n_f = n as f64;
    let x_mean = (n_f - 1.0) / 2.0;
    let y_mean = values.iter().sum::<f64>() / n_f;

    let mut numerator = 0.0_f64;
    let mut denominator = 0.0_f64;
    for (i, &y) in values.iter().enumerate() {
        let x = i as f64;
        let dx = x - x_mean;
        let dy = y - y_mean;
        numerator = dx.mul_add(dy, numerator);
        denominator = dx.mul_add(dx, denominator);
    }

    if denominator.abs() < f64::EPSILON {
        0.0
    } else {
        numerator / denominator
    }
}

/// Computes R-squared for a simple linear regression on evenly-spaced values.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn linear_regression_r_squared(values: &[f64]) -> f64 {
    let n = values.len();
    if n < 3 {
        return 0.0;
    }

    let n_f = n as f64;
    let y_mean = values.iter().sum::<f64>() / n_f;
    let slope = linear_regression_slope(values);
    let x_mean = (n_f - 1.0) / 2.0;
    let intercept = slope.mul_add(-x_mean, y_mean);

    let ss_res: f64 = values
        .iter()
        .enumerate()
        .map(|(i, &y)| {
            let predicted = slope.mul_add(i as f64, intercept);
            (y - predicted).powi(2)
        })
        .sum();

    let ss_tot: f64 = values.iter().map(|&y| (y - y_mean).powi(2)).sum();

    if ss_tot < f64::EPSILON {
        1.0 // All values identical: perfect fit.
    } else {
        1.0 - ss_res / ss_tot
    }
}

/// Sample variance with Bessel correction.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn sample_variance(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 2 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let sum_sq: f64 = values.iter().map(|v| (v - mean).powi(2)).sum();
    Some(sum_sq / (n as f64 - 1.0))
}

/// Lag-1 autocorrelation for critical-slowing-down detection.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn lag1_autocorrelation(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 3 {
        return None;
    }
    let mean = values.iter().sum::<f64>() / n as f64;
    let mut cov = 0.0_f64;
    let mut var = 0.0_f64;
    for i in 1..n {
        cov += (values[i] - mean) * (values[i - 1] - mean);
    }
    for v in values {
        var += (v - mean).powi(2);
    }
    if var <= f64::EPSILON {
        None
    } else {
        Some((cov / var).clamp(-1.0, 1.0))
    }
}

/// Ratio of second-half variance to first-half variance.
#[must_use]
fn variance_ratio_halves(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 6 {
        return None;
    }
    let mid = n / 2;
    let v1 = sample_variance(&values[..mid])?;
    let v2 = sample_variance(&values[mid..])?;
    if v1 <= f64::EPSILON {
        None
    } else {
        Some(v2 / v1)
    }
}

/// Kendall's tau-b rank correlation coefficient.
///
/// Measures monotone trend strength nonparametrically. Returns a value
/// in `[-1, 1]` where `-1` means perfectly monotone decreasing, `+1` means
/// perfectly monotone increasing, and `0` means no trend.
///
/// This is the standard trend statistic in the Scheffer et al. (2009)
/// early warning literature because it is robust to outliers and does
/// not assume linearity — critical since pre-bifurcation trajectories
/// are typically non-linear.
///
/// Complexity: `O(n²)` pairwise comparisons. For our history windows
/// (≤ 64 values) this is negligible.
#[must_use]
fn kendall_tau(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 3 {
        return None;
    }

    let mut concordant = 0_i64;
    let mut discordant = 0_i64;

    for i in 0..n {
        for j in (i + 1)..n {
            let diff = values[j] - values[i];
            if diff > f64::EPSILON {
                concordant += 1;
            } else if diff < -f64::EPSILON {
                discordant += 1;
            }
            // Ties are excluded (tau-b with continuous data assumption).
        }
    }

    let total = concordant + discordant;
    if total == 0 {
        return Some(0.0);
    }

    #[allow(clippy::cast_precision_loss)]
    Some((concordant - discordant) as f64 / total as f64)
}

/// Spearman's rank correlation coefficient for time-series trend detection.
///
/// Measures the strength and direction of the monotone association between
/// time index and observed values using rank correlation. Range
/// `[-1, 1]` where `-1` means perfectly monotone decreasing and `+1` means
/// perfectly monotone increasing.
///
/// Compared to Kendall's tau:
/// - Spearman's rho is Pearson correlation on ranks, making it sensitive to
///   larger rank displacements.
/// - Kendall's tau counts concordant/discordant pairs uniformly, making it
///   more robust to isolated outliers.
/// - When both agree on direction and magnitude, the evidence is stronger
///   than either alone.
///
/// Complexity: `O(n log n)` (dominated by the sort in `average_rank_f64`).
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn spearman_rho(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 3 {
        return None;
    }

    let value_ranks = average_rank_f64(values);
    let n_f = n as f64;
    let mean_time_rank = (n_f + 1.0) * 0.5;
    let mean_value_rank = value_ranks.iter().sum::<f64>() / n_f;

    let mut covariance = 0.0_f64;
    let mut time_variance = 0.0_f64;
    let mut value_variance = 0.0_f64;

    for (idx, &value_rank) in value_ranks.iter().enumerate() {
        let time_rank = idx as f64 + 1.0;
        let dt = time_rank - mean_time_rank;
        let dv = value_rank - mean_value_rank;
        covariance += dt * dv;
        time_variance += dt * dt;
        value_variance += dv * dv;
    }

    if time_variance <= f64::EPSILON || value_variance <= f64::EPSILON {
        return None;
    }

    let rho = covariance / (time_variance.sqrt() * value_variance.sqrt());
    if rho.is_finite() {
        Some(rho.clamp(-1.0, 1.0))
    } else {
        None
    }
}

/// Computes 1-based average ranks (midrank method) for a slice of values.
///
/// Handles ties by assigning each member of a tie group the average of
/// the ranks the group spans. Used by [`hoeffding_d`].
#[must_use]
fn average_rank_f64(values: &[f64]) -> Vec<f64> {
    let n = values.len();
    let mut indexed: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut ranks = vec![0.0_f64; n];
    let mut i = 0;
    while i < n {
        let mut j = i + 1;
        while j < n && (indexed[j].1 - indexed[i].1).abs() <= f64::EPSILON {
            j += 1;
        }
        // Positions i..j in sorted order get 1-based ranks (i+1) through j.
        // Average rank = (i + 1 + j) / 2.
        #[allow(clippy::cast_precision_loss)]
        let avg = (i + 1 + j) as f64 / 2.0;
        for k in i..j {
            ranks[indexed[k].0] = avg;
        }
        i = j;
    }
    ranks
}

/// Hoeffding's D statistic for nonparametric independence testing.
///
/// Tests for *any* kind of dependence between time index and the
/// observed values — not just monotone association (which Kendall's
/// tau already captures). This detects U-shaped, oscillatory, and
/// other non-monotone deterioration patterns.
///
/// Range `[-0.5, 1]` where values near `0` indicate independence
/// and positive values indicate dependence. Requires at least 5
/// observations (the denominator involves `n(n−1)(n−2)(n−3)(n−4)`).
///
/// Complexity: `O(n²)`. For our history windows (≤ 64 values) this
/// is negligible.
///
/// Reference: Hoeffding, W. (1948). "A Non-Parametric Test of
/// Independence." *Annals of Mathematical Statistics*, 19(4), 546–557.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn hoeffding_d(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 5 {
        return None;
    }

    // x-axis is the time index [0, 1, ..., n-1]; ranks are r[i] = i + 1.
    // y-axis ranks are computed via average_rank_f64.
    let s = average_rank_f64(values);
    let n_f = n as f64;

    // Guard: if all values are identical (zero variance), the rank-based
    // formula degenerates. Return 0 — no dependence can be detected.
    let all_tied = s.windows(2).all(|w| (w[1] - w[0]).abs() <= f64::EPSILON);
    if all_tied {
        return Some(0.0);
    }

    // Bivariate ranks Q[i].
    // Since x-ranks are trivially r[i] = i+1 (all distinct), the formula
    // simplifies to: Q[i] = 1 + #{j < i : s[j] < s[i]}
    //                          + 0.5 * #{j < i : s[j] == s[i]}
    let mut q = vec![0.0_f64; n];
    for i in 0..n {
        let mut count = 0.0_f64;
        for j in 0..i {
            let diff = s[i] - s[j];
            if diff > f64::EPSILON {
                count += 1.0;
            } else if diff.abs() <= f64::EPSILON {
                count += 0.5;
            }
        }
        q[i] = 1.0 + count;
    }

    // D1 = sum_i (Q[i] - 1)(Q[i] - 2)
    let d1: f64 = q.iter().map(|&qi| (qi - 1.0) * (qi - 2.0)).sum();

    // D2 = sum_i (R[i]-1)(R[i]-2)(S[i]-1)(S[i]-2), with R[i] = i+1
    let d2: f64 = (0..n)
        .map(|i| {
            let ri = i as f64; // R[i] - 1
            ri * (ri - 1.0) * (s[i] - 1.0) * (s[i] - 2.0)
        })
        .sum();

    // D3 = sum_i (R[i]-2)(S[i]-2)(Q[i]-1), with R[i] = i+1
    let d3: f64 = (0..n)
        .map(|i| (i as f64 - 1.0) * (s[i] - 2.0) * (q[i] - 1.0))
        .sum();

    // D = 30 * ((n-2)(n-3)*D1 + D2 - 2(n-2)*D3) / (n(n-1)(n-2)(n-3)(n-4))
    let denom = n_f * (n_f - 1.0) * (n_f - 2.0) * (n_f - 3.0) * (n_f - 4.0);
    if denom.abs() < f64::EPSILON {
        return None;
    }

    let inner = (n_f - 3.0).mul_add(d1, -2.0 * d3);
    let numer = 30.0 * (n_f - 2.0).mul_add(inner, d2);

    Some(numer / denom)
}

/// Distance correlation between the time index and observed values.
///
/// Unlike rank-based methods (Kendall, Spearman, Hoeffding), distance
/// correlation operates on the raw metric distances between observations.
/// This preserves magnitude and acceleration information that rank
/// transforms discard — for example, a sudden large drop in the Fiedler
/// value looks the same as a small drop in rank space, but distance
/// correlation captures the difference.
///
/// dCor(X,Y) = 0 if and only if X and Y are independent (for finite
/// first moments), making it a true test of independence with no
/// blind spots for non-linear patterns.
///
/// Range `[0, 1]`. Requires at least 4 observations (3 produces
/// degenerate double-centering).
///
/// Complexity: `O(n²)`. For our history windows (≤ 64 values) this is
/// negligible.
///
/// Reference: Székely, G.J., Rizzo, M.L. & Bakirov, N.K. (2007).
/// "Measuring and testing dependence by correlation of distances."
/// *Annals of Statistics*, 35(6), 2769–2794.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn distance_correlation(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 4 {
        return None;
    }
    let n_f = n as f64;

    // Distance matrices. For time-series: x = [0, 1, ..., n-1], y = values.
    // Time distance matrix: a[i][j] = |i - j|
    // Value distance matrix: b[i][j] = |values[i] - values[j]|

    // Compute row means, column means, and grand mean for both matrices
    // in O(n²) without materializing the full matrix.

    // --- Time axis (a_ij = |i - j|) ---
    // Row mean of row i: (1/n) * sum_j |i - j|
    let mut a_row_mean = vec![0.0_f64; n];
    for (i, row_mean) in a_row_mean.iter_mut().enumerate() {
        let i_f = i as f64;
        let mut row_sum = 0.0_f64;
        for j in 0..n {
            row_sum += (i_f - j as f64).abs();
        }
        *row_mean = row_sum / n_f;
    }
    let a_grand_mean: f64 = a_row_mean.iter().sum::<f64>() / n_f;
    // For symmetric distance matrices, col_mean == row_mean.

    // --- Value axis (b_ij = |values[i] - values[j]|) ---
    let mut b_row_mean = vec![0.0_f64; n];
    for (i, row_mean) in b_row_mean.iter_mut().enumerate() {
        let value_i = values[i];
        let mut row_sum = 0.0_f64;
        for &value_j in values {
            row_sum += (value_i - value_j).abs();
        }
        *row_mean = row_sum / n_f;
    }
    let b_grand_mean: f64 = b_row_mean.iter().sum::<f64>() / n_f;

    // Double-centered elements:
    //   A_ij = a_ij - row_mean_i - col_mean_j + grand_mean
    //   B_ij = b_ij - row_mean_i - col_mean_j + grand_mean
    //
    // We need: dCov² = (1/n²) * sum_ij A_ij * B_ij
    //          dVar_x² = (1/n²) * sum_ij A_ij²
    //          dVar_y² = (1/n²) * sum_ij B_ij²
    let mut dcov_sq = 0.0_f64;
    let mut dvar_time_sq = 0.0_f64;
    let mut dvar_value_sq = 0.0_f64;

    for (i, &value_i) in values.iter().enumerate() {
        let i_f = i as f64;
        for (j, &value_j) in values.iter().enumerate() {
            let a_ij = (i_f - j as f64).abs() - a_row_mean[i] - a_row_mean[j] + a_grand_mean;
            let b_ij = (value_i - value_j).abs() - b_row_mean[i] - b_row_mean[j] + b_grand_mean;
            dcov_sq += a_ij * b_ij;
            dvar_time_sq += a_ij * a_ij;
            dvar_value_sq += b_ij * b_ij;
        }
    }

    dcov_sq /= n_f * n_f;
    dvar_time_sq /= n_f * n_f;
    dvar_value_sq /= n_f * n_f;

    if dvar_time_sq <= 0.0 || dvar_value_sq <= 0.0 {
        return Some(0.0);
    }

    // dCor = sqrt(dCov² / sqrt(dVar_x² * dVar_y²)).
    // Numerical noise can drive `dcov_sq` slightly negative for nearly
    // independent windows; clamp to 0 because dCov² is non-negative by
    // definition.
    let denom = (dvar_time_sq * dvar_value_sq).sqrt();
    if denom <= 0.0 {
        return Some(0.0);
    }
    let dcor = (dcov_sq / denom).max(0.0).sqrt();

    if dcor.is_finite() {
        Some(dcor.clamp(0.0, 1.0))
    } else {
        None
    }
}

/// Sample skewness (Fisher's definition).
///
/// Measures asymmetry of the distribution. Near bifurcation points,
/// the potential landscape becomes asymmetric — one side of the
/// potential well becomes shallower — causing the observable to become
/// skewed even before the mean shifts (Scheffer et al., 2009).
///
/// Positive skew indicates the distribution has a right tail (rare
/// high values), negative skew indicates a left tail.
#[must_use]
#[allow(clippy::cast_precision_loss)]
fn sample_skewness(values: &[f64]) -> Option<f64> {
    let n = values.len();
    if n < 3 {
        return None;
    }
    let n_f = n as f64;
    let mean = values.iter().sum::<f64>() / n_f;
    let m2: f64 = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n_f;
    let m3: f64 = values.iter().map(|v| (v - mean).powi(3)).sum::<f64>() / n_f;

    if m2 <= f64::EPSILON {
        return None;
    }

    Some(m3 / m2.powf(1.5))
}

/// Split-conformal lower prediction bound for the next value.
///
/// Uses one-step residuals `|x_t - x_{t-1}|` as conformity scores.
#[must_use]
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
fn split_conformal_lower_next(values: &[f64], alpha: f64) -> Option<f64> {
    if values.len() < 4 {
        return None;
    }
    let alpha = alpha.clamp(1e-6, 0.5);
    let mut residuals: Vec<f64> = values
        .windows(2)
        .map(|w| (w[1] - w[0]).abs())
        .filter(|r| r.is_finite())
        .collect();
    if residuals.is_empty() {
        return None;
    }
    residuals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let m = residuals.len();
    let rank = (((m as f64 + 1.0) * (1.0 - alpha)).ceil() as usize)
        .saturating_sub(1)
        .min(m - 1);
    let q = residuals[rank];
    Some(values[values.len() - 1] - q)
}

/// Anytime-valid e-process for monotone deterioration evidence.
///
/// We map per-step decreases into `[0, 1]` and apply a Hoeffding-style
/// nonnegative supermartingale factor with fixed lambda.
#[must_use]
fn deterioration_eprocess(values: &[f64], lambda: f64) -> f64 {
    if values.len() < 2 {
        return 1.0;
    }
    let lambda = lambda.clamp(1e-3, 1.0);
    let mut log_e = 0.0_f64;
    for window in values.windows(2) {
        let step_drop = (window[0] - window[1]).clamp(0.0, 1.0);
        log_e += lambda * (step_drop - 0.5) - (lambda * lambda / 8.0);
    }
    log_e.clamp(-60.0, 60.0).exp()
}

// ============================================================================
// Spectral Health Report
// ============================================================================

/// Complete spectral health report combining all analysis results.
#[derive(Debug, Clone)]
pub struct SpectralHealthReport {
    /// Health classification with evidence.
    pub classification: HealthClassification,
    /// Spectral decomposition of the dependency Laplacian.
    pub decomposition: SpectralDecomposition,
    /// Bifurcation early warning signal (if enough history is available).
    pub bifurcation: Option<BifurcationWarning>,
    /// Structural bottleneck nodes identified from the Fiedler vector.
    pub bottlenecks: Vec<BottleneckNode>,
}

impl fmt::Display for SpectralHealthReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "SpectralHealthReport:")?;
        writeln!(f, "  classification: {}", self.classification)?;
        writeln!(
            f,
            "  fiedler_value:  {:.6}",
            self.decomposition.fiedler_value
        )?;
        writeln!(
            f,
            "  spectral_gap:   {:.6}",
            self.decomposition.spectral_gap
        )?;
        writeln!(
            f,
            "  spectral_radius: {:.6}",
            self.decomposition.spectral_radius
        )?;
        writeln!(
            f,
            "  iterations:     {}",
            self.decomposition.iterations_used
        )?;
        writeln!(f, "  bottlenecks:    {}", self.bottlenecks.len())?;
        if let Some(ref bw) = self.bifurcation {
            writeln!(f, "  bifurcation:    {bw}")?;
        }
        Ok(())
    }
}

// ============================================================================
// Spectral Health Monitor
// ============================================================================

/// Spectral health monitor that maintains state across analyses for trend
/// detection.
///
/// # Usage
///
/// ```
/// use asupersync::observability::spectral_health::{
///     SpectralHealthMonitor, SpectralThresholds,
/// };
///
/// let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
///
/// // Build a dependency graph (e.g., 4 tasks in a cycle).
/// let edges = vec![(0, 1), (1, 2), (2, 3), (3, 0)];
/// let report = monitor.analyze(4, &edges);
///
/// println!("{report}");
/// assert!(report.decomposition.fiedler_value > 0.0);
/// ```
#[derive(Debug, Clone)]
pub struct SpectralHealthMonitor {
    /// Configuration thresholds.
    thresholds: SpectralThresholds,
    /// History of Fiedler values for trend analysis.
    history: SpectralHistory,
}

impl SpectralHealthMonitor {
    /// Creates a new spectral health monitor.
    #[must_use]
    pub fn new(thresholds: SpectralThresholds) -> Self {
        let history = SpectralHistory::new(thresholds.history_window);
        Self {
            thresholds,
            history,
        }
    }

    /// Returns a reference to the current thresholds.
    #[must_use]
    pub fn thresholds(&self) -> &SpectralThresholds {
        &self.thresholds
    }

    /// Performs a full spectral health analysis of the dependency graph.
    ///
    /// The graph is specified as a node count and edge list. Edges are
    /// undirected pairs `(u, v)` where `u` and `v` are node indices in
    /// `[0, node_count)`.
    pub fn analyze(&mut self, node_count: usize, edges: &[(usize, usize)]) -> SpectralHealthReport {
        let laplacian = DependencyLaplacian::new(node_count, edges);
        let decomposition = compute_spectral_decomposition(&laplacian, &self.thresholds);

        // Record for trend analysis.
        self.history.record(decomposition.fiedler_value);

        // Bifurcation analysis.
        let bifurcation = self.history.analyze(&self.thresholds);
        let approaching_disconnect = bifurcation
            .as_ref()
            .is_some_and(|bw| bw.trend == SpectralTrend::Deteriorating);

        // Health classification.
        let classification = classify_health(
            &decomposition,
            &laplacian,
            &self.thresholds,
            approaching_disconnect,
        );

        // Bottleneck analysis.
        let bottlenecks = analyze_bottlenecks(
            &decomposition,
            &laplacian,
            self.thresholds.bottleneck_threshold,
        );

        SpectralHealthReport {
            classification,
            decomposition,
            bifurcation,
            bottlenecks,
        }
    }

    /// Returns the number of historical observations recorded.
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Resets the trend history (e.g., after a topology change).
    pub fn reset_history(&mut self) {
        self.history = SpectralHistory::new(self.thresholds.history_window);
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
    fn classify_deadlocked_system() {
        let edges = vec![(0, 1), (2, 3)];
        let lap = DependencyLaplacian::new(4, &edges);
        let thresholds = SpectralThresholds::default();
        let decomp = compute_spectral_decomposition(&lap, &thresholds);
        let health = classify_health(&decomp, &lap, &thresholds, false);

        assert!(
            matches!(health, HealthClassification::Deadlocked { components: 2 }),
            "Disconnected graph should be deadlocked, got {health}"
        );
    }

    #[test]
    fn health_classification_display_all_variants() {
        let variants: Vec<HealthClassification> = vec![
            HealthClassification::Healthy { margin: 0.5 },
            HealthClassification::Degraded {
                fiedler: 0.05,
                bottleneck_nodes: vec![1, 2],
            },
            HealthClassification::Critical {
                fiedler: 0.005,
                approaching_disconnect: true,
            },
            HealthClassification::Deadlocked { components: 3 },
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
        // Nodes with |fv[i]| < 0.2: indices 1, 2, 3.
        assert_eq!(bottlenecks, vec![1, 2, 3]);
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
    fn monitor_deadlocked_disconnected() {
        let mut monitor = SpectralHealthMonitor::new(SpectralThresholds::default());
        let edges = vec![(0, 1), (2, 3)];
        let report = monitor.analyze(4, &edges);

        assert!(
            matches!(
                report.classification,
                HealthClassification::Deadlocked { components: 2 }
            ),
            "Disconnected graph should be deadlocked, got {}",
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
    fn distance_corr_captures_magnitude() {
        // Two series with same ranks but different magnitudes.
        // dCor should differentiate them because it uses raw distances.
        let small_drop: Vec<f64> = (0..8).map(|i| f64::from(i).mul_add(-0.01, 1.0)).collect();
        let big_drop: Vec<f64> = (0..8).map(|i| f64::from(i).mul_add(-0.5, 1.0)).collect();

        let dc_small = distance_correlation(&small_drop).unwrap();
        let dc_big = distance_correlation(&big_drop).unwrap();

        // Both are perfectly linear, so both should be 1.0.
        // The key value of dCor isn't distinguishing linear slopes
        // (both have dCor=1), but rather detecting non-linear patterns.
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
}
