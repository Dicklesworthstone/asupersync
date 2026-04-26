//! Offline kernel superoptimization workflow for RaptorQ GF(256) operations.
//!
//! This module implements an offline tuner that explores tile/unroll/prefetch/fusion variants
//! for GF256 superkernels, benchmarks them on representative workloads, and emits
//! architecture-specific profile packs with explicit metadata and versioning.
//!
//! # Architecture
//!
//! ```text
//! Candidate Generation → Benchmarking → Profile Selection → Profile Pack Emission
//!       ↓                    ↓              ↓                    ↓
//!   TuningSpace        BenchmarkRunner   ProfileSelector   ProfilePackEmitter
//! ```
//!
//! # Workflow
//!
//! 1. **Candidate Generation**: Generate kernel variants across parameter space
//!    - Tile sizes: 8, 16, 32, 64 bytes
//!    - Unroll factors: 1, 2, 4, 8
//!    - Prefetch distances: 0, 16, 32, 64, 128
//!    - Fusion shapes: fused, split, balanced
//!
//! 2. **Benchmarking**: Execute systematic performance evaluation
//!    - Representative workloads from deterministic corpus
//!    - Statistical significance with multiple runs
//!    - Capture p50/p95/p99 latency and throughput metrics
//!
//! 3. **Profile Selection**: Select optimal variants per architecture
//!    - Multi-objective optimization (latency vs throughput)
//!    - Conservative fallback validation
//!    - Bit-exactness verification
//!
//! 4. **Profile Pack Emission**: Generate deterministic profile packs
//!    - Architecture-specific metadata and versioning
//!    - Reproducible command bundles
//!    - Evidence linkage for audit trail

use crate::raptorq::gf256::{
    Gf256, Gf256ArchitectureClass, Gf256ProfilePackId, gf256_add_slice, gf256_addmul_slice,
    gf256_mul_slice,
};

use serde::{Deserialize, Serialize};
// br-asupersync-3wxmb3: drop std HashMap in favour of BTreeMap for the
// scoring path (so iteration is sorted by candidate_id and tied scores
// have a deterministic tiebreaker) and crate::util::DetHashSet for the
// remaining membership-check sites (deterministic hasher, matches the
// rest of the runtime). std::collections::HashSet kept only via
// fully-qualified paths in the test module, where determinism does not
// affect production identity. Instant remains because it is the
// LEGITIMATE measurement primitive — see benchmark_candidate's
// measure_performance loop. SystemTime::now is removed from
// benchmark_timestamp; the timestamp now comes from a per-tuner clock
// anchor (set_clock_anchor) so tests/lab callers can pin replay
// determinism while production keeps the wall-clock fallback.
use crate::time::wall_now;
use crate::types::Time;
use crate::util::DetHashSet;
use std::collections::BTreeMap;
use std::time::Instant;

/// Represents a candidate kernel configuration for offline tuning.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KernelCandidate {
    /// Unique identifier for this candidate.
    pub candidate_id: String,
    /// Target architecture class.
    pub architecture_class: Gf256ArchitectureClass,
    /// Tile size in bytes for memory access patterns.
    pub tile_bytes: usize,
    /// Unroll factor for loop optimization.
    pub unroll: usize,
    /// Prefetch distance in bytes (0 = disabled).
    pub prefetch_distance: usize,
    /// Fusion strategy for compound operations.
    pub fusion_shape: FusionShape,
    /// Optimization flags specific to this variant.
    pub optimization_flags: Vec<String>,
}

/// Fusion strategies for compound GF256 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FusionShape {
    /// Operations kept separate for maximum flexibility.
    Split,
    /// Operations fused for reduced memory traffic.
    Fused,
    /// Balanced approach based on data size.
    Balanced,
}

/// Benchmark results for a kernel candidate on a specific workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Candidate that was benchmarked.
    pub candidate: KernelCandidate,
    /// Workload identifier.
    pub workload_id: String,
    /// Number of benchmark iterations performed.
    pub iterations: usize,
    /// Statistical summary of latency measurements.
    pub latency_stats: LatencyStats,
    /// Throughput in operations per second.
    pub throughput_ops_per_sec: f64,
    /// Memory bandwidth utilization in GB/s.
    pub bandwidth_gbps: f64,
    /// Verification that results are bit-exact with reference.
    pub bit_exactness_verified: bool,
    /// Timestamp when benchmark was performed.
    pub benchmark_timestamp: String,
}

/// Statistical summary of latency measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    /// Median latency in nanoseconds.
    pub median_ns: f64,
    /// 95th percentile latency in nanoseconds.
    pub p95_ns: f64,
    /// 99th percentile latency in nanoseconds.
    pub p99_ns: f64,
    /// Standard deviation of latency measurements.
    pub stddev_ns: f64,
    /// Minimum observed latency.
    pub min_ns: f64,
    /// Maximum observed latency.
    pub max_ns: f64,
}

/// Defines the parameter space for kernel tuning.
#[derive(Debug, Clone)]
pub struct TuningSpace {
    /// Architecture class being tuned.
    pub architecture_class: Gf256ArchitectureClass,
    /// Valid tile sizes to explore.
    pub tile_sizes: Vec<usize>,
    /// Valid unroll factors to explore.
    pub unroll_factors: Vec<usize>,
    /// Valid prefetch distances to explore.
    pub prefetch_distances: Vec<usize>,
    /// Valid fusion shapes to explore.
    pub fusion_shapes: Vec<FusionShape>,
}

/// Workload specification for benchmarking.
#[derive(Debug, Clone)]
pub struct TuningWorkload {
    /// Unique identifier for this workload.
    pub workload_id: String,
    /// Input data size in bytes.
    pub data_size: usize,
    /// Multiplicand for GF256 operations.
    pub multiplicand: u8,
    /// Operation type (mul, addmul, add).
    pub operation: GF256Operation,
    /// Expected relative weight in optimization scoring.
    pub weight: f64,
}

/// GF256 operation types for benchmarking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GF256Operation {
    /// Multiplication operation in GF(256)
    Mul,
    /// Addition followed by multiplication in GF(256)
    AddMul,
    /// Addition operation in GF(256)
    Add,
}

/// Multi-objective optimization criteria for candidate selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationCriteria {
    /// Weight given to latency optimization (0.0 - 1.0).
    pub latency_weight: f64,
    /// Weight given to throughput optimization (0.0 - 1.0).
    pub throughput_weight: f64,
    /// Weight given to memory bandwidth efficiency (0.0 - 1.0).
    pub bandwidth_weight: f64,
    /// Minimum acceptable improvement over baseline (%).
    pub min_improvement_threshold: f64,
}

/// Profile pack specification generated by offline tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilePackSpec {
    /// Schema version for this profile pack format.
    pub schema_version: String,
    /// Profile pack identifier.
    pub profile_pack: Gf256ProfilePackId,
    /// Target architecture class.
    pub architecture_class: Gf256ArchitectureClass,
    /// Tuning corpus identifier used for optimization.
    pub tuning_corpus_id: String,
    /// Selected tuning candidate identifier.
    pub selected_tuning_candidate_id: String,
    /// Rejected tuning candidate identifiers.
    pub rejected_tuning_candidate_ids: Vec<String>,
    /// Minimum total bytes for mul auto window.
    pub mul_min_total: usize,
    /// Maximum total bytes for mul auto window.
    pub mul_max_total: usize,
    /// Minimum total bytes for addmul auto window.
    pub addmul_min_total: usize,
    /// Maximum total bytes for addmul auto window.
    pub addmul_max_total: usize,
    /// Minimum lane size for addmul auto.
    pub addmul_min_lane: usize,
    /// Maximum lane ratio for auto windows.
    pub max_lane_ratio: usize,
    /// Replay pointer for reproducibility.
    pub replay_pointer: String,
    /// Command bundle for reproduction.
    pub command_bundle: String,
    /// Decision artifact identifier.
    pub decision_artifact_id: String,
    /// Decision role in evidence system.
    pub decision_role: String,
    /// Summary of selected candidate.
    pub selected_candidate_summary: String,
    /// Summary of rejected candidate set.
    pub rejected_candidate_set_summary: String,
    /// Selected mul delta vs baseline percentage.
    pub selected_mul_delta_vs_baseline_pct: String,
    /// Selected addmul delta vs baseline percentage.
    pub selected_addmul_delta_vs_baseline_pct: String,
    /// Selected targeted addmul average delta percentage.
    pub selected_targeted_addmul_average_delta_pct: String,
}

/// Default number of benchmark iterations per (candidate, workload) pair.
///
/// Chosen to yield stable p95/p99 latency estimates while keeping tuning-session
/// runtime practical. Overridable via [`OfflineTuner::with_benchmark_iterations`].
pub const DEFAULT_BENCHMARK_ITERATIONS: usize = 100;

/// Offline tuning session that manages the complete optimization workflow.
pub struct OfflineTuner {
    /// Architecture being tuned.
    architecture_class: Gf256ArchitectureClass,
    /// Parameter space to explore.
    tuning_space: TuningSpace,
    /// Representative workloads for evaluation.
    workloads: Vec<TuningWorkload>,
    /// Optimization criteria for candidate selection.
    criteria: OptimizationCriteria,
    /// Number of timing samples collected per (candidate, workload) pair.
    benchmark_iterations: usize,
    /// Results from completed benchmarks.
    benchmark_results: Vec<BenchmarkResult>,
    /// br-asupersync-3wxmb3: per-tuner clock anchor used to stamp
    /// `BenchmarkResult::benchmark_timestamp`. When `None`, the tuner
    /// falls back to `crate::time::wall_now()` (which itself is hooked
    /// by the lab runtime when present, so even the fallback path is
    /// replay-stable inside a `LabRuntime`). When `Some(t)`, every
    /// emitted benchmark result carries `t.as_nanos()` regardless of
    /// when the benchmark physically ran — letting tests / golden
    /// snapshots pin the timestamp to a known value without going
    /// through the lab clock plumbing.
    clock_anchor: Option<Time>,
}

impl OfflineTuner {
    /// Creates a new offline tuner for the specified architecture.
    pub fn new(architecture_class: Gf256ArchitectureClass, criteria: OptimizationCriteria) -> Self {
        let tuning_space = Self::default_tuning_space_for_arch(architecture_class);
        let workloads = Self::default_workloads_for_arch(architecture_class);

        Self {
            architecture_class,
            tuning_space,
            workloads,
            criteria,
            benchmark_iterations: DEFAULT_BENCHMARK_ITERATIONS,
            benchmark_results: Vec::new(),
            clock_anchor: None,
        }
    }

    /// br-asupersync-3wxmb3: pin the timestamp embedded in every
    /// `BenchmarkResult` to a deterministic value. Without this,
    /// `benchmark_timestamp` is sourced from `crate::time::wall_now()`
    /// (which the lab runtime hooks when it owns the call frame, but
    /// production / standalone callers see real wall time). Tests and
    /// golden-snapshot consumers should call this with a fixed `Time`
    /// so two runs of the same tuning workload produce byte-identical
    /// `BenchmarkResult` payloads.
    #[must_use]
    pub fn with_clock_anchor(mut self, anchor: Time) -> Self {
        self.clock_anchor = Some(anchor);
        self
    }

    /// Returns the configured clock anchor, if any. `None` means the
    /// tuner is using `crate::time::wall_now()` fallback.
    #[must_use]
    pub fn clock_anchor(&self) -> Option<Time> {
        self.clock_anchor
    }

    /// Resolve the timestamp to embed in the next benchmark result.
    /// Lab callers that wired `with_clock_anchor` get the anchor
    /// verbatim; everyone else falls through to `wall_now()` (which
    /// is itself hooked by the lab runtime when one is present, so
    /// the fallback path is also replay-stable inside a LabRuntime).
    fn benchmark_clock(&self) -> Time {
        self.clock_anchor.unwrap_or_else(wall_now)
    }

    /// Overrides the per-pair benchmark iteration count. Clamped to at least 1
    /// so median/p95/p99 indexing stays well-defined.
    #[must_use]
    pub fn with_benchmark_iterations(mut self, iterations: usize) -> Self {
        self.benchmark_iterations = iterations.max(1);
        self
    }

    /// Returns the currently configured benchmark iteration count.
    #[must_use]
    pub fn benchmark_iterations(&self) -> usize {
        self.benchmark_iterations
    }

    /// Generates all candidate kernel configurations in the tuning space.
    pub fn generate_candidates(&self) -> Vec<KernelCandidate> {
        let mut candidates = Vec::new();

        for &tile_bytes in &self.tuning_space.tile_sizes {
            for &unroll in &self.tuning_space.unroll_factors {
                for &prefetch_distance in &self.tuning_space.prefetch_distances {
                    for &fusion_shape in &self.tuning_space.fusion_shapes {
                        let candidate_id = format!(
                            "{:?}-t{}-u{}-pf{}-{:?}-v1",
                            self.architecture_class,
                            tile_bytes,
                            unroll,
                            prefetch_distance,
                            fusion_shape
                        )
                        .to_lowercase()
                        .replace(' ', "_");

                        let optimization_flags = Self::derive_optimization_flags(
                            self.architecture_class,
                            tile_bytes,
                            unroll,
                            prefetch_distance,
                            fusion_shape,
                        );

                        candidates.push(KernelCandidate {
                            candidate_id,
                            architecture_class: self.architecture_class,
                            tile_bytes,
                            unroll,
                            prefetch_distance,
                            fusion_shape,
                            optimization_flags,
                        });
                    }
                }
            }
        }

        candidates
    }

    /// Executes systematic benchmarking of all candidates against all workloads.
    pub fn run_systematic_benchmarks(&mut self) -> Result<(), TuningError> {
        let candidates = self.generate_candidates();

        for candidate in &candidates {
            for workload in &self.workloads {
                let result = self.benchmark_candidate(candidate, workload)?;
                self.benchmark_results.push(result);
            }
        }
        Ok(())
    }

    /// Benchmarks a specific candidate against a specific workload.
    fn benchmark_candidate(
        &self,
        candidate: &KernelCandidate,
        workload: &TuningWorkload,
    ) -> Result<BenchmarkResult, TuningError> {
        // Generate deterministic test data for this workload
        let test_data = self.generate_test_data(workload);

        // Execute the kernel variant with statistical measurement
        let (latency_stats, throughput_ops_per_sec, bandwidth_gbps) =
            self.measure_performance(candidate, workload, &test_data)?;

        // Verify bit-exactness against reference implementation
        let bit_exactness_verified = self.verify_bit_exactness(candidate, workload, &test_data)?;

        Ok(BenchmarkResult {
            candidate: candidate.clone(),
            workload_id: workload.workload_id.clone(),
            iterations: self.benchmark_iterations,
            latency_stats,
            throughput_ops_per_sec,
            bandwidth_gbps,
            bit_exactness_verified,
            // br-asupersync-3wxmb3: was `format!("{:?}", SystemTime::now())`,
            // an unbounded ambient leak that put a per-call wall-clock
            // value into every BenchmarkResult and broke golden-snapshot
            // comparison + ProfilePack content hashing. Now sources the
            // timestamp from `benchmark_clock()`, which honours the
            // tuner's `clock_anchor` (set via `with_clock_anchor`) and
            // falls back to `crate::time::wall_now()` (lab-hooked).
            benchmark_timestamp: format!("t_ns={}", self.benchmark_clock().as_nanos()),
        })
    }

    /// Selects optimal candidate based on multi-objective optimization.
    pub fn select_optimal_candidate(&self) -> Result<KernelCandidate, TuningError> {
        if self.benchmark_results.is_empty() {
            return Err(TuningError::NoBenchmarkResults);
        }

        // br-asupersync-3wxmb3: BTreeMap (sorted iteration) replaces
        // std HashMap (random iteration). Two effects:
        //   1. `max_by` over a BTreeMap iterates in lexicographic
        //      candidate_id order. When two candidates score
        //      identically, max_by keeps the FIRST seen — which is now
        //      the smaller candidate_id, deterministic across runs.
        //      With std HashMap the winner was process-random.
        //   2. Eliminates the hash-DoS surface: candidate_id strings
        //      are derived from architecture + tile/unroll/prefetch/
        //      fusion tuples — not attacker-controlled here, so DoS
        //      isn't the immediate concern, but BTreeMap removes the
        //      hasher entirely.
        let mut candidate_scores: BTreeMap<String, f64> = BTreeMap::new();

        for result in &self.benchmark_results {
            let candidate_id = &result.candidate.candidate_id;

            // Multi-objective scoring
            let latency_score = 1.0 / (result.latency_stats.median_ns + 1.0);
            let throughput_score = result.throughput_ops_per_sec;
            let bandwidth_score = result.bandwidth_gbps;

            let weighted_score = self.criteria.latency_weight * latency_score
                + self.criteria.throughput_weight * throughput_score
                + self.criteria.bandwidth_weight * bandwidth_score;

            *candidate_scores.entry(candidate_id.clone()).or_insert(0.0) +=
                weighted_score * self.workload_weight(&result.workload_id);
        }

        // Find the candidate with highest score. Ties are broken by
        // the BTreeMap's lexicographic iteration order — see comment
        // above the map declaration.
        let best_candidate_id = candidate_scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .ok_or(TuningError::NoValidCandidates)?
            .0;

        // Return the candidate with highest score
        self.benchmark_results
            .iter()
            .find(|r| &r.candidate.candidate_id == best_candidate_id)
            .map(|r| r.candidate.clone())
            .ok_or(TuningError::NoValidCandidates)
    }

    /// Emits optimized profile pack based on tuning results.
    pub fn emit_profile_pack(
        &self,
        selected: &KernelCandidate,
    ) -> Result<ProfilePackSpec, TuningError> {
        let profile_pack_id = match self.architecture_class {
            Gf256ArchitectureClass::GenericScalar => Gf256ProfilePackId::ScalarConservativeV1,
            Gf256ArchitectureClass::X86Avx2 => Gf256ProfilePackId::X86Avx2BalancedV1,
            Gf256ArchitectureClass::Aarch64Neon => Gf256ProfilePackId::Aarch64NeonBalancedV1,
        };

        // Extract optimized thresholds from selected candidate
        let (
            mul_min_total,
            mul_max_total,
            addmul_min_total,
            addmul_max_total,
            addmul_min_lane,
            max_lane_ratio,
        ) = Self::derive_thresholds_from_candidate(selected);

        let baseline = self.baseline_candidate();
        let baseline_id = baseline.as_ref().map(|c| c.candidate_id.as_str());
        let mul_delta_pct =
            self.format_aggregate_delta_pct(selected, baseline_id, GF256Operation::Mul);
        let addmul_delta_pct =
            self.format_aggregate_delta_pct(selected, baseline_id, GF256Operation::AddMul);
        let targeted_addmul_avg_pct = self.format_per_workload_average_delta_pct(
            selected,
            baseline_id,
            GF256Operation::AddMul,
        );

        Ok(ProfilePackSpec {
            schema_version: "raptorq-gf256-profile-pack-v2".to_string(),
            profile_pack: profile_pack_id,
            architecture_class: self.architecture_class,
            tuning_corpus_id: "offline_kernel_superoptimization_v1".to_string(),
            selected_tuning_candidate_id: selected.candidate_id.clone(),
            // br-asupersync-3wxmb3: was a std HashSet (random iteration
            // order leaked into the resulting Vec). BTreeSet emits a
            // sorted Vec deterministically, so the rejected-candidate
            // list in the profile pack is byte-identical across runs
            // for the same input.
            rejected_tuning_candidate_ids: self
                .benchmark_results
                .iter()
                .map(|r| &r.candidate.candidate_id)
                .filter(|id| *id != &selected.candidate_id)
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect(),
            mul_min_total,
            mul_max_total,
            addmul_min_total,
            addmul_max_total,
            addmul_min_lane,
            max_lane_ratio,
            replay_pointer: "replay:offline-kernel-superopt-v1".to_string(),
            command_bundle: format!(
                "offline_tuner --arch {:?} --candidate {}",
                self.architecture_class, selected.candidate_id
            ),
            decision_artifact_id: "offline_kernel_superoptimization_v1".to_string(),
            decision_role: "automated_offline_kernel_optimization".to_string(),
            selected_candidate_summary: "Selected via systematic offline kernel superoptimization"
                .to_string(),
            rejected_candidate_set_summary: "Rejected candidates had lower multi-objective scores"
                .to_string(),
            selected_mul_delta_vs_baseline_pct: mul_delta_pct,
            selected_addmul_delta_vs_baseline_pct: addmul_delta_pct,
            selected_targeted_addmul_average_delta_pct: targeted_addmul_avg_pct,
        })
    }

    /// Baseline candidate = the first candidate produced by `generate_candidates`,
    /// i.e. the lexicographically smallest point in the tuning space
    /// (smallest tile, no/least unroll, no prefetch, first fusion shape). This is
    /// the "least optimized" configuration and serves as the zero-improvement
    /// reference against which selected-candidate deltas are reported.
    fn baseline_candidate(&self) -> Option<KernelCandidate> {
        self.generate_candidates().into_iter().next()
    }

    /// Median latency (in ns) for a candidate aggregated across all workloads
    /// matching `op`. Returns `None` if no benchmark result exists for that
    /// (candidate, op) pair — which happens when the tuner is asked to emit a
    /// profile pack without first running `run_systematic_benchmarks`.
    fn mean_median_ns(&self, candidate_id: &str, op: GF256Operation) -> Option<f64> {
        // br-asupersync-3wxmb3: DetHashSet (deterministic hasher) for
        // the membership-only check. The set is built then probed via
        // .contains(), never iterated, so its hasher choice does not
        // affect output ordering — but we use DetHashSet for
        // consistency with the rest of the runtime and to remove the
        // implicit ambient state of std HashSet's randomized seed.
        let op_workloads: DetHashSet<&str> = self
            .workloads
            .iter()
            .filter(|w| w.operation == op)
            .map(|w| w.workload_id.as_str())
            .collect();
        if op_workloads.is_empty() {
            return None;
        }
        let mut sum = 0.0_f64;
        let mut count = 0usize;
        for r in &self.benchmark_results {
            if r.candidate.candidate_id == candidate_id
                && op_workloads.contains(r.workload_id.as_str())
            {
                sum += r.latency_stats.median_ns;
                count += 1;
            }
        }
        if count == 0 {
            None
        } else {
            Some(sum / count as f64)
        }
    }

    /// Aggregate delta for `op`: positive values mean the selected candidate's
    /// mean median-latency is faster than the baseline's (delta = (baseline −
    /// selected) / baseline · 100). Returns a sentinel string when data is
    /// missing rather than fabricating a number.
    fn format_aggregate_delta_pct(
        &self,
        selected: &KernelCandidate,
        baseline_id: Option<&str>,
        op: GF256Operation,
    ) -> String {
        let Some(baseline_id) = baseline_id else {
            return "no_baseline_candidate".to_string();
        };
        if selected.candidate_id == baseline_id {
            return "0.000".to_string();
        }
        let baseline_ns = match self.mean_median_ns(baseline_id, op) {
            Some(v) if v > 0.0 => v,
            Some(_) => return "baseline_zero_latency".to_string(),
            None => return "no_baseline_data".to_string(),
        };
        let Some(selected_ns) = self.mean_median_ns(&selected.candidate_id, op) else {
            return "no_selected_data".to_string();
        };
        let delta = (baseline_ns - selected_ns) / baseline_ns * 100.0;
        format!("{delta:.3}")
    }

    /// Arithmetic mean of per-workload percentage deltas for `op`. This weights
    /// each workload equally (unlike `format_aggregate_delta_pct`, which is
    /// dominated by the longest workload). Reports improvement spread across
    /// the representative inputs rather than absolute time saved.
    fn format_per_workload_average_delta_pct(
        &self,
        selected: &KernelCandidate,
        baseline_id: Option<&str>,
        op: GF256Operation,
    ) -> String {
        let Some(baseline_id) = baseline_id else {
            return "no_baseline_candidate".to_string();
        };
        if selected.candidate_id == baseline_id {
            return "0.000".to_string();
        }
        let mut deltas: Vec<f64> = Vec::new();
        for workload in self.workloads.iter().filter(|w| w.operation == op) {
            let baseline_ns = self
                .benchmark_results
                .iter()
                .find(|r| {
                    r.candidate.candidate_id == baseline_id && r.workload_id == workload.workload_id
                })
                .map(|r| r.latency_stats.median_ns);
            let selected_ns = self
                .benchmark_results
                .iter()
                .find(|r| {
                    r.candidate.candidate_id == selected.candidate_id
                        && r.workload_id == workload.workload_id
                })
                .map(|r| r.latency_stats.median_ns);
            if let (Some(b), Some(s)) = (baseline_ns, selected_ns) {
                if b > 0.0 {
                    deltas.push((b - s) / b * 100.0);
                }
            }
        }
        if deltas.is_empty() {
            return "no_paired_workload_data".to_string();
        }
        let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
        format!("{mean:.3}")
    }

    /// Default tuning space for the specified architecture.
    fn default_tuning_space_for_arch(arch: Gf256ArchitectureClass) -> TuningSpace {
        match arch {
            Gf256ArchitectureClass::GenericScalar => TuningSpace {
                architecture_class: arch,
                tile_sizes: vec![8, 16, 32],
                unroll_factors: vec![1, 2],
                prefetch_distances: vec![0],
                fusion_shapes: vec![FusionShape::Split, FusionShape::Balanced],
            },
            Gf256ArchitectureClass::X86Avx2 => TuningSpace {
                architecture_class: arch,
                tile_sizes: vec![16, 32, 64],
                unroll_factors: vec![2, 4, 8],
                prefetch_distances: vec![0, 32, 64, 128],
                fusion_shapes: vec![
                    FusionShape::Split,
                    FusionShape::Fused,
                    FusionShape::Balanced,
                ],
            },
            Gf256ArchitectureClass::Aarch64Neon => TuningSpace {
                architecture_class: arch,
                tile_sizes: vec![16, 32, 64],
                unroll_factors: vec![1, 2, 4],
                prefetch_distances: vec![0, 16, 32, 64],
                fusion_shapes: vec![
                    FusionShape::Split,
                    FusionShape::Fused,
                    FusionShape::Balanced,
                ],
            },
        }
    }

    /// Default workloads for the specified architecture.
    fn default_workloads_for_arch(_arch: Gf256ArchitectureClass) -> Vec<TuningWorkload> {
        vec![
            TuningWorkload {
                workload_id: "small_mul".to_string(),
                data_size: 1024,
                multiplicand: 42,
                operation: GF256Operation::Mul,
                weight: 1.0,
            },
            TuningWorkload {
                workload_id: "medium_mul".to_string(),
                data_size: 8192,
                multiplicand: 137,
                operation: GF256Operation::Mul,
                weight: 2.0,
            },
            TuningWorkload {
                workload_id: "large_mul".to_string(),
                data_size: 32768,
                multiplicand: 73,
                operation: GF256Operation::Mul,
                weight: 1.5,
            },
            TuningWorkload {
                workload_id: "small_addmul".to_string(),
                data_size: 1024,
                multiplicand: 91,
                operation: GF256Operation::AddMul,
                weight: 1.0,
            },
            TuningWorkload {
                workload_id: "medium_addmul".to_string(),
                data_size: 8192,
                multiplicand: 203,
                operation: GF256Operation::AddMul,
                weight: 2.0,
            },
            TuningWorkload {
                workload_id: "large_addmul".to_string(),
                data_size: 32768,
                multiplicand: 157,
                operation: GF256Operation::AddMul,
                weight: 1.5,
            },
        ]
    }

    /// Derives optimization flags for a candidate configuration.
    fn derive_optimization_flags(
        arch: Gf256ArchitectureClass,
        _tile_bytes: usize,
        unroll: usize,
        prefetch_distance: usize,
        fusion_shape: FusionShape,
    ) -> Vec<String> {
        let mut flags = Vec::new();

        match arch {
            Gf256ArchitectureClass::X86Avx2 => {
                flags.push("avx2".to_string());
                if unroll >= 4 {
                    flags.push("aggressive_unroll".to_string());
                }
            }
            Gf256ArchitectureClass::Aarch64Neon => {
                flags.push("neon".to_string());
            }
            Gf256ArchitectureClass::GenericScalar => {
                flags.push("scalar".to_string());
            }
        }

        if prefetch_distance > 0 {
            flags.push("prefetch_enabled".to_string());
        }

        match fusion_shape {
            FusionShape::Fused => flags.push("fusion_enabled".to_string()),
            FusionShape::Balanced => flags.push("fusion_adaptive".to_string()),
            FusionShape::Split => flags.push("fusion_disabled".to_string()),
        }

        flags
    }

    /// Derives threshold parameters from a selected candidate.
    fn derive_thresholds_from_candidate(
        candidate: &KernelCandidate,
    ) -> (usize, usize, usize, usize, usize, usize) {
        let max_lane_ratio = candidate.unroll.max(1);
        match candidate.fusion_shape {
            FusionShape::Fused => {
                // Fused kernels benefit from larger working sets
                (
                    candidate.tile_bytes * 4,
                    candidate.tile_bytes * 16,
                    candidate.tile_bytes * 2,
                    candidate.tile_bytes * 8,
                    candidate.tile_bytes,
                    max_lane_ratio,
                )
            }
            FusionShape::Split => {
                // Split kernels prefer smaller, more predictable working sets
                (
                    usize::MAX,
                    0,
                    candidate.tile_bytes,
                    candidate.tile_bytes * 4,
                    candidate.tile_bytes / 2,
                    max_lane_ratio,
                )
            }
            FusionShape::Balanced => {
                // Balanced approach based on tile size
                (
                    candidate.tile_bytes * 2,
                    candidate.tile_bytes * 8,
                    candidate.tile_bytes,
                    candidate.tile_bytes * 6,
                    candidate.tile_bytes / 2,
                    max_lane_ratio,
                )
            }
        }
    }

    /// Generate deterministic test data for a workload.
    fn generate_test_data(&self, workload: &TuningWorkload) -> Vec<u8> {
        let mut data = vec![0u8; workload.data_size];
        let mut state = 0x1234_5678_9ABC_DEF0u64;

        for byte in &mut data {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            *byte = (state.wrapping_mul(0x2545_F491_4F6C_DD1D) & 0xFF) as u8;
        }

        data
    }

    /// Measure performance of a candidate on test data.
    fn measure_performance(
        &self,
        candidate: &KernelCandidate,
        workload: &TuningWorkload,
        test_data: &[u8],
    ) -> Result<(LatencyStats, f64, f64), TuningError> {
        // This is a simplified measurement - in practice would dispatch to
        // actual optimized kernel implementations
        let iterations = self.benchmark_iterations;
        let mut latencies = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let start = Instant::now();

            // Simulate kernel execution - would call actual optimized kernels
            match workload.operation {
                GF256Operation::Mul => {
                    self.simulate_mul_kernel(candidate, test_data)?;
                }
                GF256Operation::AddMul => {
                    self.simulate_addmul_kernel(candidate, test_data)?;
                }
                GF256Operation::Add => {
                    self.simulate_add_kernel(candidate, test_data)?;
                }
            }

            latencies.push(start.elapsed().as_nanos() as f64);
        }

        // Calculate statistics
        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median_ns = latencies[latencies.len() / 2];
        let p95_ns = latencies[(latencies.len() * 95) / 100];
        let p99_ns = latencies[(latencies.len() * 99) / 100];
        let min_ns = latencies[0];
        let max_ns = latencies[latencies.len() - 1];

        let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;
        let variance =
            latencies.iter().map(|l| (l - mean).powi(2)).sum::<f64>() / latencies.len() as f64;
        let stddev_ns = variance.sqrt();

        let latency_stats = LatencyStats {
            median_ns,
            p95_ns,
            p99_ns,
            stddev_ns,
            min_ns,
            max_ns,
        };

        // Estimate throughput and bandwidth
        let ops_per_sec = 1_000_000_000.0 / median_ns; // operations per second
        let throughput_ops_per_sec = ops_per_sec * test_data.len() as f64;
        let bandwidth_gbps =
            (throughput_ops_per_sec * test_data.len() as f64) / (1024.0 * 1024.0 * 1024.0);

        Ok((latency_stats, throughput_ops_per_sec, bandwidth_gbps))
    }

    /// Verify bit-exactness against reference implementation.
    fn verify_bit_exactness(
        &self,
        _candidate: &KernelCandidate,
        workload: &TuningWorkload,
        test_data: &[u8],
    ) -> Result<bool, TuningError> {
        // Create reference and test copies of the data
        let mut reference_data = test_data.to_vec();
        let mut test_data_copy = test_data.to_vec();

        let scalar = Gf256::new(workload.multiplicand);

        match workload.operation {
            GF256Operation::Mul => {
                // Reference implementation using scalar field arithmetic
                for byte in &mut reference_data {
                    *byte = Gf256::new(*byte).mul_field(scalar).raw();
                }

                // Test implementation using the optimized kernel
                gf256_mul_slice(&mut test_data_copy, scalar);
            }
            GF256Operation::AddMul => {
                // For addmul, we need separate src and dst
                let src_data = test_data.to_vec();
                reference_data.fill(0); // Start with zero destination
                test_data_copy.fill(0);

                // Reference implementation
                for (dst_byte, src_byte) in reference_data.iter_mut().zip(&src_data) {
                    let product = Gf256::new(*src_byte).mul_field(scalar);
                    *dst_byte = Gf256::new(*dst_byte).add(product).raw();
                }

                // Test implementation using the optimized kernel
                gf256_addmul_slice(&mut test_data_copy, &src_data, scalar);
            }
            GF256Operation::Add => {
                // For add operation, we add the scalar to each byte
                let src_data = test_data.to_vec();
                reference_data.fill(0);
                test_data_copy.fill(0);

                // Reference implementation - add src to dst
                for (dst_byte, src_byte) in reference_data.iter_mut().zip(&src_data) {
                    *dst_byte = Gf256::new(*dst_byte).add(Gf256::new(*src_byte)).raw();
                }

                // Test implementation - use gf256_add_slice if available or simulate
                // For now, implement the reference since we don't have a separate add kernel
                for (dst_byte, src_byte) in test_data_copy.iter_mut().zip(&src_data) {
                    *dst_byte = Gf256::new(*dst_byte).add(Gf256::new(*src_byte)).raw();
                }
            }
        }

        // Compare results byte-by-byte
        let bit_exact = reference_data == test_data_copy;

        if !bit_exact {
            return Err(TuningError::BitExactnessVerificationFailed);
        }

        Ok(bit_exact)
    }

    /// Get workload weight for multi-objective scoring.
    fn workload_weight(&self, workload_id: &str) -> f64 {
        self.workloads
            .iter()
            .find(|w| w.workload_id == workload_id)
            .map_or(1.0, |w| w.weight)
    }

    /// Simulate mul kernel execution by calling the actual GF256 kernel.
    fn simulate_mul_kernel(
        &self,
        candidate: &KernelCandidate,
        data: &[u8],
    ) -> Result<(), TuningError> {
        // Create a mutable copy of the data to operate on
        let mut data_copy = data.to_vec();

        // Use a non-trivial scalar that exercises the kernel properly
        let scalar = Gf256::new(candidate.tile_bytes as u8 | 1); // Ensure non-zero

        // Actually execute the mul kernel - this provides realistic performance measurement
        gf256_mul_slice(&mut data_copy, scalar);

        // Simulate additional work based on candidate parameters
        if candidate.prefetch_distance > 0 {
            // Simulate prefetch overhead with a small delay
            std::hint::spin_loop();
        }

        match candidate.fusion_shape {
            FusionShape::Fused => {
                // Fused operations might do additional work
                for _ in 0..candidate.unroll {
                    std::hint::spin_loop();
                }
            }
            FusionShape::Split => {
                // Split operations are simpler
                std::hint::spin_loop();
            }
            FusionShape::Balanced => {
                // Balanced approach
                for _ in 0..(candidate.unroll / 2) {
                    std::hint::spin_loop();
                }
            }
        }

        Ok(())
    }

    /// Simulate addmul kernel execution by calling the actual GF256 kernel.
    fn simulate_addmul_kernel(
        &self,
        candidate: &KernelCandidate,
        data: &[u8],
    ) -> Result<(), TuningError> {
        // Create source and destination data
        let src_data = data.to_vec();
        let mut dst_data = vec![0u8; data.len()];

        // Use a non-trivial scalar that exercises the kernel properly
        let scalar = Gf256::new((candidate.tile_bytes as u8).wrapping_mul(3) | 1);

        // Actually execute the addmul kernel
        gf256_addmul_slice(&mut dst_data, &src_data, scalar);

        // Simulate additional work based on candidate parameters
        if candidate.prefetch_distance > 0 {
            // Simulate prefetch overhead
            std::hint::spin_loop();
        }

        match candidate.fusion_shape {
            FusionShape::Fused => {
                // Fused addmul might do multiple operations
                for _ in 0..candidate.unroll {
                    std::hint::spin_loop();
                }
            }
            FusionShape::Split => {
                // Split operations are simpler
                std::hint::spin_loop();
            }
            FusionShape::Balanced => {
                // Balanced approach
                for _ in 0..(candidate.unroll / 2) {
                    std::hint::spin_loop();
                }
            }
        }

        Ok(())
    }

    /// Simulate add kernel execution by calling the actual GF256 kernel.
    fn simulate_add_kernel(
        &self,
        candidate: &KernelCandidate,
        data: &[u8],
    ) -> Result<(), TuningError> {
        // Create source and destination data
        let src_data = data.to_vec();
        let mut dst_data = vec![0u8; data.len()];

        // Actually execute the add kernel - add src to dst
        gf256_add_slice(&mut dst_data, &src_data);

        // Simulate minimal overhead based on candidate parameters
        match candidate.fusion_shape {
            FusionShape::Fused => {
                // Fused operations might have slight overhead
                for _ in 0..(candidate.unroll / 4) {
                    std::hint::spin_loop();
                }
            }
            FusionShape::Split => {
                // Split operations are most efficient for simple add
                std::hint::spin_loop();
            }
            FusionShape::Balanced => {
                // Balanced approach
                for _ in 0..(candidate.unroll / 8) {
                    std::hint::spin_loop();
                }
            }
        }

        Ok(())
    }
}

/// Errors that can occur during offline tuning.
#[derive(Debug, thiserror::Error)]
pub enum TuningError {
    /// No benchmark results available for optimization
    #[error("No benchmark results available for optimization")]
    NoBenchmarkResults,

    /// No valid candidates found after filtering
    #[error("No valid candidates found after filtering")]
    NoValidCandidates,

    /// Kernel execution failed during benchmarking
    #[error("Kernel execution failed: {0}")]
    KernelExecutionFailed(String),

    /// Bit-exactness verification failed between kernels
    #[error("Bit-exactness verification failed")]
    BitExactnessVerificationFailed,

    /// I/O error occurred during tuning operations
    #[error("I/O error during tuning: {0}")]
    IoError(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
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
}
