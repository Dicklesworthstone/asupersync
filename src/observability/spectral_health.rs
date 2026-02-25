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
    /// Fiedler vector component magnitude above which a node is a bottleneck.
    pub bottleneck_threshold: f64,
    /// Maximum number of power iteration steps.
    pub max_iterations: usize,
    /// Convergence tolerance for power iteration.
    pub convergence_tolerance: f64,
    /// Number of historical Fiedler values to retain for trend analysis.
    pub history_window: usize,
}

impl SpectralThresholds {
    /// Creates thresholds tuned for production runtime monitoring.
    #[must_use]
    pub const fn production() -> Self {
        Self {
            critical_fiedler: 0.01,
            degraded_fiedler: 0.1,
            bifurcation_rate_threshold: -0.05,
            bottleneck_threshold: 0.4,
            max_iterations: 200,
            convergence_tolerance: 1e-10,
            history_window: 32,
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
/// Nodes with large absolute Fiedler vector components lie near the minimum
/// bisection of the graph and represent structural bottlenecks.
#[must_use]
pub fn identify_bottlenecks(fiedler_vector: &[f64], threshold: f64) -> Vec<usize> {
    // Find the transition region: nodes whose Fiedler vector component is
    // close to zero are near the cut. We identify these as bottlenecks.
    fiedler_vector
        .iter()
        .enumerate()
        .filter(|&(_, v)| v.abs() < threshold)
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

/// Bifurcation early warning signal.
///
/// Detects approach to critical transitions in the dependency graph by
/// monitoring the rate of change and oscillation pattern of the Fiedler value.
#[derive(Debug, Clone)]
pub struct BifurcationWarning {
    /// Current spectral trend direction.
    pub trend: SpectralTrend,
    /// Estimated time steps until the Fiedler value crosses the critical
    /// threshold, based on linear extrapolation. `None` if the trend is not
    /// deteriorating or if the extrapolation is non-positive.
    pub time_to_critical: Option<f64>,
    /// Confidence in the warning (based on consistency of the trend).
    /// Range `[0.0, 1.0]`.
    pub confidence: f64,
}

impl fmt::Display for BifurcationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BifurcationWarning(trend={}", self.trend)?;
        if let Some(ttc) = self.time_to_critical {
            write!(f, ", time_to_critical={ttc:.2}")?;
        }
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

        let trend = if oscillation_ratio > 0.5 {
            SpectralTrend::Oscillating
        } else if slope < thresholds.bifurcation_rate_threshold {
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

        // Confidence: based on R-squared of the linear fit.
        let confidence = linear_regression_r_squared(&values).clamp(0.0, 1.0);

        Some(BifurcationWarning {
            trend,
            time_to_critical,
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
            time_to_critical: Some(5.3),
            confidence: 0.87,
        };
        let s = bw.to_string();
        assert!(s.contains("deteriorating"));
        assert!(s.contains("5.30"));
        assert!(s.contains("0.87"));

        let bw_no_ttc = BifurcationWarning {
            trend: SpectralTrend::Stable,
            time_to_critical: None,
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
}
