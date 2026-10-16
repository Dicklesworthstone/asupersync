//! DPOR-style schedule exploration engine.
//!
//! The explorer runs a test program under multiple schedules (seeds) and
//! tracks which Mazurkiewicz trace equivalence classes have been covered.
//! Two runs that differ only in the order of independent events belong to
//! the same equivalence class and need not both be explored.
//!
//! # Algorithm (Phase 0: seed-sweep)
//!
//! 1. For each seed in `[base_seed .. base_seed + max_runs)`:
//!    a. Construct a `LabRuntime` with that seed
//!    b. Run the test closure
//!    c. Record the trace and compute its Foata fingerprint
//!    d. Check invariants; log any violations
//! 2. Report: total runs, unique equivalence classes, violations found
//!
//! Future phases will add backtrack-point analysis and sleep sets for
//! targeted exploration (true DPOR), but seed-sweep already catches many
//! concurrency bugs by varying the scheduler's RNG.
//!
//! # Public API
//!
//! The explorer types are ordinary public runtime-test helpers. Construct them
//! with an [`ExplorerConfig`], run a closure under lab runtimes, then inspect
//! deterministic coverage fields such as total runs, equivalence classes,
//! novelty histograms, unexplored seeds, and DPOR race counters.
//!
//! ```
//! use asupersync::lab::{DporExplorer, ExplorerConfig, ScheduleExplorer};
//!
//! let config = ExplorerConfig::new(7, 3).worker_count(2).max_steps(1_000);
//! let baseline = ScheduleExplorer::new(config.clone());
//! assert_eq!(baseline.coverage().total_runs, 0);
//!
//! let dpor = DporExplorer::new(config);
//! let metrics = dpor.dpor_coverage();
//! assert_eq!(metrics.base.total_runs, 0);
//! assert_eq!(metrics.total_races, 0);
//! ```

use crate::lab::config::LabConfig;
use crate::lab::conformal::{CalibrationReport, ConformalCalibrator, ConformalConfig};
use crate::lab::exploration_budget::{
    ExplorationBudget, ExplorationBudgetConfig, ExplorationBudgetEstimate,
};
use crate::lab::runtime::{InvariantViolation, LabRuntime};
use crate::trace::boundary::SquareComplex;
use crate::trace::canonicalize::{TraceMonoid, trace_fingerprint};
use crate::trace::dpor::detect_races;
use crate::trace::event::TraceEvent;
use crate::trace::event_structure::TracePoset;
use crate::trace::scoring::{
    ClassId, EvidenceLedger, TopologicalScore, score_persistence, seed_fingerprint,
};
use crate::util::DetHasher;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::hash::{Hash, Hasher};
use std::io;
use std::path::Path;

const DEFAULT_SATURATION_WINDOW: usize = 10;
const DEFAULT_UNEXPLORED_LIMIT: usize = 5;
const DEFAULT_DERIVED_SEEDS: usize = 4;

/// Exploration mode: baseline seed-sweep or topology-prioritized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExplorationMode {
    /// Linear seed sweep (default).
    #[default]
    Baseline,
    /// Topology-prioritized: uses H1 persistence to score and prioritize seeds.
    TopologyPrioritized,
}

/// Configuration for the schedule explorer.
#[derive(Debug, Clone)]
pub struct ExplorerConfig {
    /// Starting seed. Runs use seeds `base_seed`, `base_seed + 1`, etc.
    pub base_seed: u64,
    /// Maximum number of exploration runs.
    pub max_runs: usize,
    /// Maximum steps per run before the runtime gives up.
    pub max_steps_per_run: u64,
    /// Number of simulated workers.
    pub worker_count: usize,
    /// Enable trace recording for canonicalization.
    pub record_traces: bool,
}

impl Default for ExplorerConfig {
    fn default() -> Self {
        Self {
            base_seed: 0,
            max_runs: 100,
            max_steps_per_run: 100_000,
            worker_count: 1,
            record_traces: true,
        }
    }
}

impl ExplorerConfig {
    /// Create a config with the given base seed and run count.
    #[must_use]
    pub fn new(base_seed: u64, max_runs: usize) -> Self {
        Self {
            base_seed,
            max_runs,
            ..Default::default()
        }
    }

    /// Set the number of simulated workers.
    #[must_use]
    pub fn worker_count(mut self, n: usize) -> Self {
        self.worker_count = n;
        self
    }

    /// Set the max steps per run.
    #[must_use]
    pub fn max_steps(mut self, n: u64) -> Self {
        self.max_steps_per_run = n;
        self
    }
}

/// Result of a single exploration run.
#[derive(Debug, Clone)]
pub struct RunResult {
    /// The seed used for this run.
    pub seed: u64,
    /// Number of steps taken.
    pub steps: u64,
    /// Foata fingerprint of the trace (equivalence class ID).
    pub fingerprint: u64,
    /// Whether this was the first run in its equivalence class.
    pub is_new_class: bool,
    /// Invariant violations detected.
    pub violations: Vec<InvariantViolation>,
    /// Schedule certificate hash (determinism witness).
    pub certificate_hash: u64,
}

/// A violation found during exploration, with reproducer info.
#[derive(Debug)]
pub struct ViolationReport {
    /// The seed that triggered the violation.
    pub seed: u64,
    /// Steps taken before the violation.
    pub steps: u64,
    /// The violations found.
    pub violations: Vec<InvariantViolation>,
    /// Fingerprint of the trace that produced the violation.
    pub fingerprint: u64,
}

/// Coverage metrics for the exploration.
#[derive(Debug, Clone, Serialize)]
pub struct CoverageMetrics {
    /// Number of distinct equivalence classes discovered.
    pub equivalence_classes: usize,
    /// Total runs performed.
    pub total_runs: usize,
    /// Number of runs that discovered a new equivalence class.
    pub new_class_discoveries: usize,
    /// Per-class run counts (fingerprint -> count).
    pub class_run_counts: BTreeMap<u64, usize>,
    /// Novelty histogram: novelty score -> run count.
    pub novelty_histogram: BTreeMap<u32, usize>,
    /// Saturation signals (deterministic summary).
    pub saturation: SaturationMetrics,
}

impl CoverageMetrics {
    /// Fraction of runs that discovered a new equivalence class.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn discovery_rate(&self) -> f64 {
        if self.total_runs == 0 {
            return 0.0;
        }
        self.new_class_discoveries as f64 / self.total_runs as f64
    }

    /// True if at least `window` runs hit existing classes (coarse saturation signal).
    #[must_use]
    pub fn is_saturated(&self, window: usize) -> bool {
        if self.total_runs < window {
            return false;
        }
        self.total_runs - self.new_class_discoveries >= window
    }

    /// Estimate the residual exploration budget from aggregate coverage counts.
    #[must_use]
    pub fn exploration_budget(&self, config: ExplorationBudgetConfig) -> ExplorationBudgetEstimate {
        ExplorationBudget::estimate_from_counts(self.total_runs, self.new_class_discoveries, config)
    }
}

/// Saturation signals for exploration coverage.
#[derive(Debug, Clone, Serialize)]
pub struct SaturationMetrics {
    /// Window size used for saturation detection.
    pub window: usize,
    /// True if coverage is saturated under the window heuristic.
    pub saturated: bool,
    /// Total runs that hit existing classes.
    pub existing_class_hits: usize,
    /// Runs since the last new class (None if no runs yet).
    pub runs_since_last_new_class: Option<usize>,
}

/// Ranked unexplored seed entry (for explainability).
#[derive(Debug, Clone)]
pub struct UnexploredSeed {
    /// Seed value.
    pub seed: u64,
    /// Optional topological score (present for topology-prioritized mode).
    pub score: Option<TopologicalScore>,
}

fn novelty_histogram_from_flags(results: &[RunResult]) -> BTreeMap<u32, usize> {
    let mut histogram = BTreeMap::new();
    for r in results {
        let novelty = u32::from(r.is_new_class);
        *histogram.entry(novelty).or_insert(0) += 1;
    }
    histogram
}

fn novelty_histogram_from_ledgers(ledgers: &[EvidenceLedger]) -> BTreeMap<u32, usize> {
    let mut histogram = BTreeMap::new();
    for ledger in ledgers {
        *histogram.entry(ledger.score.novelty).or_insert(0) += 1;
    }
    histogram
}

fn saturation_metrics(
    results: &[RunResult],
    total_runs: usize,
    new_class_discoveries: usize,
) -> SaturationMetrics {
    let existing_class_hits = total_runs.saturating_sub(new_class_discoveries);
    let runs_since_last_new_class = if results.is_empty() {
        None
    } else {
        let last_new = results.iter().rposition(|r| r.is_new_class);
        Some(last_new.map_or(results.len(), |idx| results.len() - 1 - idx))
    };
    let window = DEFAULT_SATURATION_WINDOW;
    let saturated = if total_runs < window {
        false
    } else {
        existing_class_hits >= window
    };
    SaturationMetrics {
        window,
        saturated,
        existing_class_hits,
        runs_since_last_new_class,
    }
}

/// Summary report after exploration completes.
#[derive(Debug)]
pub struct ExplorationReport {
    /// Total runs performed.
    pub total_runs: usize,
    /// Unique equivalence classes discovered.
    pub unique_classes: usize,
    /// All violations found (with reproducer seeds).
    pub violations: Vec<ViolationReport>,
    /// Coverage metrics.
    pub coverage: CoverageMetrics,
    /// Top-ranked unexplored seeds (if any remain).
    pub top_unexplored: Vec<UnexploredSeed>,
    /// Per-run results.
    pub runs: Vec<RunResult>,
}

impl ExplorationReport {
    /// True if any violations were found.
    #[must_use]
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Seeds that triggered violations (for reproduction).
    #[must_use]
    pub fn violation_seeds(&self) -> Vec<u64> {
        self.violations.iter().map(|v| v.seed).collect()
    }

    /// Verify that runs with the same fingerprint produced the same certificate.
    ///
    /// Returns pairs of (seed_a, seed_b) where the traces are in the same
    /// equivalence class but produced different certificates (divergence).
    #[must_use]
    pub fn certificate_divergences(&self) -> Vec<(u64, u64)> {
        let mut by_class: BTreeMap<u64, Vec<&RunResult>> = BTreeMap::new();
        for r in &self.runs {
            by_class.entry(r.fingerprint).or_default().push(r);
        }
        let mut divergences = Vec::new();
        for runs in by_class.values() {
            if runs.len() < 2 {
                continue;
            }
            let reference = runs[0].certificate_hash;
            for r in &runs[1..] {
                if r.certificate_hash != reference {
                    divergences.push((runs[0].seed, r.seed));
                }
            }
        }
        divergences
    }

    /// True if all runs within the same equivalence class produced identical certificates.
    #[must_use]
    pub fn certificates_consistent(&self) -> bool {
        self.certificate_divergences().is_empty()
    }

    /// Convert to a JSON-serializable summary (no heavy per-run violation payloads).
    #[must_use]
    pub fn to_json_summary(&self) -> ExplorationReportJson {
        ExplorationReportJson {
            total_runs: self.total_runs,
            unique_classes: self.unique_classes,
            violations: self
                .violations
                .iter()
                .map(ViolationReport::summary)
                .collect(),
            violation_seeds: self.violation_seeds(),
            coverage: self.coverage.clone(),
            top_unexplored: self
                .top_unexplored
                .iter()
                .map(UnexploredSeedJson::from_seed)
                .collect(),
            runs: self.runs.iter().map(RunResult::summary).collect(),
            certificate_divergences: self.certificate_divergences(),
        }
    }

    /// Serialize the summary report to JSON.
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self.to_json_summary())
    }

    /// Serialize the summary report to pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.to_json_summary())
    }

    /// Write the summary report as JSON to a file.
    ///
    /// When `pretty` is true, pretty-printed JSON is emitted.
    pub fn write_json_summary<P: AsRef<Path>>(&self, path: P, pretty: bool) -> io::Result<()> {
        let json = if pretty {
            self.to_json_pretty().map_err(json_err)?
        } else {
            self.to_json_string().map_err(json_err)?
        };
        std::fs::write(path, json)
    }
}

fn json_err(err: serde_json::Error) -> io::Error {
    io::Error::other(err)
}

/// JSON-safe summary for an exploration report.
#[derive(Debug, Serialize)]
pub struct ExplorationReportJson {
    /// Total runs performed.
    pub total_runs: usize,
    /// Unique equivalence classes discovered.
    pub unique_classes: usize,
    /// Violation summaries (stringified to keep output stable).
    pub violations: Vec<ViolationSummary>,
    /// Seeds that triggered violations.
    pub violation_seeds: Vec<u64>,
    /// Coverage metrics.
    pub coverage: CoverageMetrics,
    /// Top-ranked unexplored seeds (if any remain).
    pub top_unexplored: Vec<UnexploredSeedJson>,
    /// Per-run summaries (no heavy violation payloads).
    pub runs: Vec<RunSummary>,
    /// Certificate divergences within equivalence classes.
    pub certificate_divergences: Vec<(u64, u64)>,
}

/// JSON-safe summary for a single run.
#[derive(Debug, Serialize)]
pub struct RunSummary {
    /// Seed used for the run.
    pub seed: u64,
    /// Steps executed before completion.
    pub steps: u64,
    /// Foata fingerprint for the run's trace.
    pub fingerprint: u64,
    /// True if this run discovered a new equivalence class.
    pub is_new_class: bool,
    /// Number of invariant violations observed.
    pub violation_count: usize,
    /// Hash of the schedule certificate for determinism checks.
    pub certificate_hash: u64,
}

impl RunResult {
    fn summary(&self) -> RunSummary {
        RunSummary {
            seed: self.seed,
            steps: self.steps,
            fingerprint: self.fingerprint,
            is_new_class: self.is_new_class,
            violation_count: self.violations.len(),
            certificate_hash: self.certificate_hash,
        }
    }
}

/// JSON-safe summary for a violation report.
#[derive(Debug, Serialize)]
pub struct ViolationSummary {
    /// Seed that triggered the violation.
    pub seed: u64,
    /// Steps taken before the violation was observed.
    pub steps: u64,
    /// Foata fingerprint for the violating trace.
    pub fingerprint: u64,
    /// Stringified violation details (stable, human-readable).
    pub violations: Vec<String>,
}

impl ViolationReport {
    fn summary(&self) -> ViolationSummary {
        ViolationSummary {
            seed: self.seed,
            steps: self.steps,
            fingerprint: self.fingerprint,
            violations: self.violations.iter().map(ToString::to_string).collect(),
        }
    }
}

/// JSON-safe wrapper for optional topological scores.
#[derive(Debug, Serialize)]
pub struct TopologicalScoreJson {
    /// Novelty score (new homology classes).
    pub novelty: u32,
    /// Sum of persistence interval lengths.
    pub persistence_sum: u64,
    /// Deterministic fingerprint tie-break.
    pub fingerprint: u64,
}

impl From<TopologicalScore> for TopologicalScoreJson {
    fn from(score: TopologicalScore) -> Self {
        Self {
            novelty: score.novelty,
            persistence_sum: score.persistence_sum,
            fingerprint: score.fingerprint,
        }
    }
}

/// JSON-safe unexplored seed entry.
#[derive(Debug, Serialize)]
pub struct UnexploredSeedJson {
    /// Seed value pending exploration.
    pub seed: u64,
    /// Optional topological score (if available).
    pub score: Option<TopologicalScoreJson>,
}

impl UnexploredSeedJson {
    fn from_seed(seed: &UnexploredSeed) -> Self {
        Self {
            seed: seed.seed,
            score: seed.score.map(TopologicalScoreJson::from),
        }
    }
}

/// The schedule exploration engine.
///
/// Runs a test under multiple seeds, tracking equivalence classes and
/// detecting invariant violations.
pub struct ScheduleExplorer {
    config: ExplorerConfig,
    explored_seeds: BTreeSet<u64>,
    known_fingerprints: BTreeSet<u64>,
    class_counts: BTreeMap<u64, usize>,
    results: Vec<RunResult>,
    violations: Vec<ViolationReport>,
    new_class_count: usize,
    conformal: Option<ConformalCalibrator>,
    conformal_reports: Vec<(u64, CalibrationReport)>,
}

impl ScheduleExplorer {
    /// Create a new explorer with the given configuration.
    #[must_use]
    pub fn new(config: ExplorerConfig) -> Self {
        Self {
            config,
            explored_seeds: BTreeSet::new(),
            known_fingerprints: BTreeSet::new(),
            class_counts: BTreeMap::new(),
            results: Vec::new(),
            violations: Vec::new(),
            new_class_count: 0,
            conformal: None,
            conformal_reports: Vec::new(),
        }
    }

    /// Calibrate each run's oracle metrics with split conformal prediction.
    ///
    /// Off by default. When enabled, every explored run's oracle report
    /// (from [`LabRuntime::report`]) feeds a [`ConformalCalibrator`]. The first
    /// `min_calibration_samples` runs build the calibration set. Each later run
    /// is scored against the runs before it, and its [`CalibrationReport`] is
    /// kept with its seed in [`Self::conformal_reports`]. A run whose oracle
    /// metrics fall outside the prediction set is listed by
    /// [`Self::conformal_anomaly_seeds`] even when no invariant failed.
    ///
    /// The coverage guarantee assumes the runs are exchangeable, which holds
    /// for runs of one test that differ only in their seed.
    #[must_use]
    pub fn with_conformal_calibration(mut self, config: ConformalConfig) -> Self {
        self.conformal = Some(ConformalCalibrator::new(config));
        self
    }

    /// The calibrator fed by [`Self::with_conformal_calibration`], if enabled.
    #[must_use]
    pub fn conformal_calibrator(&self) -> Option<&ConformalCalibrator> {
        self.conformal.as_ref()
    }

    /// The seed and calibration report of every run scored after the
    /// calibration set filled, in run order. Empty unless calibration is
    /// enabled.
    #[must_use]
    pub fn conformal_reports(&self) -> &[(u64, CalibrationReport)] {
        &self.conformal_reports
    }

    /// Seeds whose oracle metrics fell outside a conformal prediction set.
    #[must_use]
    pub fn conformal_anomaly_seeds(&self) -> Vec<u64> {
        self.conformal_reports
            .iter()
            .filter(|(_, report)| report.prediction_sets.iter().any(|set| !set.conforming))
            .map(|(seed, _)| *seed)
            .collect()
    }

    /// Explore the test under multiple schedules.
    ///
    /// The `test` closure receives a freshly constructed `LabRuntime` for
    /// each run. It should set up tasks, schedule them, and call
    /// `run_until_quiescent()` (or equivalent).
    ///
    /// # Example
    ///
    /// ```
    /// use asupersync::lab::explorer::{ExplorerConfig, ScheduleExplorer};
    /// use asupersync::types::Budget;
    ///
    /// let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 50));
    /// let report = explorer.explore(|runtime| {
    ///     let region = runtime.state.create_root_region(Budget::INFINITE);
    ///     // ... set up concurrent tasks ...
    ///     runtime.run_until_quiescent();
    /// });
    ///
    /// assert!(!report.has_violations(), "Found bugs: {:?}", report.violation_seeds());
    /// println!("Explored {} classes in {} runs", report.unique_classes, report.total_runs);
    /// ```
    pub fn explore<F>(&mut self, test: F) -> ExplorationReport
    where
        F: Fn(&mut LabRuntime),
    {
        for run_idx in 0..self.config.max_runs {
            let seed = self.config.base_seed.wrapping_add(run_idx as u64);
            self.run_once(seed, &test);
        }

        self.build_report()
    }

    /// Run a single exploration with the given seed.
    fn run_once<F>(&mut self, seed: u64, test: &F)
    where
        F: Fn(&mut LabRuntime),
    {
        if !self.explored_seeds.insert(seed) {
            return;
        }

        // Build config for this run.
        let mut lab_config = LabConfig::new(seed);
        lab_config = lab_config.worker_count(self.config.worker_count);
        if let Some(max) = Some(self.config.max_steps_per_run) {
            lab_config = lab_config.max_steps(max);
        }
        if self.config.record_traces {
            lab_config = lab_config.with_default_replay_recording();
        }

        let mut runtime = LabRuntime::new(lab_config);

        // Run the test.
        test(&mut runtime);

        let steps = runtime.steps();

        // Compute trace fingerprint.
        let trace_events: Vec<TraceEvent> = runtime.trace().snapshot();
        let fingerprint = if trace_events.is_empty() {
            // Use seed as fingerprint if no trace events (recording disabled).
            seed
        } else {
            trace_fingerprint(&trace_events)
        };

        let is_new_class = self.known_fingerprints.insert(fingerprint);
        if is_new_class {
            self.new_class_count += 1;
        }
        *self.class_counts.entry(fingerprint).or_insert(0) += 1;

        // Check invariants.
        let violations = runtime.check_invariants();

        if !violations.is_empty() {
            self.violations.push(ViolationReport {
                seed,
                steps,
                violations: violations.clone(),
                fingerprint,
            });
        }

        let certificate_hash = runtime.certificate().hash();

        self.results.push(RunResult {
            seed,
            steps,
            fingerprint,
            is_new_class,
            violations,
            certificate_hash,
        });

        if let Some(calibrator) = self.conformal.as_mut() {
            // `report` does not advance the run, so this reads the state
            // the test left behind.
            let run_report = runtime.report();
            if let Some(calibration) = calibrator.predict(&run_report.oracle_report) {
                self.conformal_reports.push((seed, calibration));
            }
        }
    }

    /// Build the final report.
    fn build_report(&self) -> ExplorationReport {
        let total_runs = self.results.len();
        let novelty_histogram = novelty_histogram_from_flags(&self.results);
        let saturation = saturation_metrics(&self.results, total_runs, self.new_class_count);
        ExplorationReport {
            total_runs,
            unique_classes: self.known_fingerprints.len(),
            violations: self.violations.clone(),
            coverage: CoverageMetrics {
                equivalence_classes: self.known_fingerprints.len(),
                total_runs,
                new_class_discoveries: self.new_class_count,
                class_run_counts: self.class_counts.clone(),
                novelty_histogram,
                saturation,
            },
            top_unexplored: Vec::new(),
            runs: self.results.clone(),
        }
    }

    /// Access per-run results directly.
    #[must_use]
    pub fn results(&self) -> &[RunResult] {
        &self.results
    }

    /// Access the current coverage metrics.
    #[must_use]
    pub fn coverage(&self) -> CoverageMetrics {
        let total_runs = self.results.len();
        let novelty_histogram = novelty_histogram_from_flags(&self.results);
        let saturation = saturation_metrics(&self.results, total_runs, self.new_class_count);
        CoverageMetrics {
            equivalence_classes: self.known_fingerprints.len(),
            total_runs,
            new_class_discoveries: self.new_class_count,
            class_run_counts: self.class_counts.clone(),
            novelty_histogram,
            saturation,
        }
    }
}

/// DPOR-guided schedule exploration.
///
/// Instead of random seed-sweep, this explorer uses race detection to identify
/// backtrack points and generate targeted schedules. Each run's trace is
/// analyzed for races, and alternative schedules (derived from backtrack points)
/// are added to a work queue. The trace monoid is used for equivalence class
/// deduplication: schedules that produce equivalent traces are not re-explored.
///
/// # Algorithm
///
/// 1. Run the initial schedule (base seed)
/// 2. Detect races in the trace via `detect_races()`
/// 3. For each backtrack point, derive a new seed that permutes the schedule
/// 4. Check if the resulting trace's equivalence class is already known
/// 5. If new, explore further; if known, prune
/// 6. Repeat until work queue is empty or budget is exhausted
///
/// # Coverage Boundary
///
/// This explorer tracks Mazurkiewicz/Foata-style equivalence-class fingerprints,
/// derives targeted seeds from race backtrack points, and prunes already-seen
/// classes through a sleep set. It is DPOR-style guided coverage, not a
/// certified optimal-DPOR engine: it does not prove that every reachable class
/// is explored, nor does it claim no false negatives for deeply nested race
/// chains without additional iterative-deepening proof machinery.
pub struct DporExplorer {
    config: ExplorerConfig,
    /// Seeds pending exploration (derived from backtrack points).
    work_queue: VecDeque<u64>,
    /// Seeds already queued for exploration.
    pending_seeds: BTreeSet<u64>,
    /// Explored seeds.
    explored_seeds: BTreeSet<u64>,
    /// Known equivalence classes (fingerprint → monoid element).
    known_classes: BTreeMap<u64, TraceMonoid>,
    /// Per-class run counts.
    class_counts: BTreeMap<u64, usize>,
    /// All run results.
    results: Vec<RunResult>,
    /// Violations found.
    violations: Vec<ViolationReport>,
    /// Total races found across all runs.
    total_races: usize,
    /// Total HB-races across all runs.
    total_hb_races: usize,
    /// Backtrack points generated.
    total_backtrack_points: usize,
    /// Backtrack points pruned because their derived seed was already explored
    /// or already pending in the queue.
    pruned_backtrack_points: usize,
    /// Backtrack points pruned by sleep set.
    sleep_pruned: usize,
    /// Sleep set for deduplicating backtrack points across runs.
    sleep_set: crate::trace::dpor::SleepSet,
    /// Per-run estimated class counts (for coverage trend analysis).
    per_run_estimated_classes: Vec<usize>,
}

/// Extended coverage metrics for DPOR exploration.
#[derive(Debug, Clone, Serialize)]
pub struct DporCoverageMetrics {
    /// Base coverage metrics.
    pub base: CoverageMetrics,
    /// Total races detected across all runs (immediate, O(n³)).
    pub total_races: usize,
    /// Total HB-races detected across all runs (vector-clock based).
    pub total_hb_races: usize,
    /// Total backtrack points generated.
    pub total_backtrack_points: usize,
    /// Backtrack points pruned because their derived seed was already explored
    /// or already pending in the queue.
    pub pruned_backtrack_points: usize,
    /// Backtrack points pruned by sleep set.
    pub sleep_pruned: usize,
    /// Ratio of useful exploration (new classes / total runs).
    pub efficiency: f64,
    /// Per-run estimated class counts (trend: should plateau at saturation).
    pub estimated_class_trend: Vec<usize>,
}

impl DporExplorer {
    /// Create a new DPOR explorer with the given configuration.
    #[must_use]
    pub fn new(config: ExplorerConfig) -> Self {
        let mut work_queue = VecDeque::new();
        work_queue.push_back(config.base_seed);
        let mut pending_seeds = BTreeSet::new();
        pending_seeds.insert(config.base_seed);
        Self {
            config,
            work_queue,
            pending_seeds,
            explored_seeds: BTreeSet::new(),
            known_classes: BTreeMap::new(),
            class_counts: BTreeMap::new(),
            results: Vec::new(),
            violations: Vec::new(),
            total_races: 0,
            total_hb_races: 0,
            total_backtrack_points: 0,
            pruned_backtrack_points: 0,
            sleep_pruned: 0,
            sleep_set: crate::trace::dpor::SleepSet::new(),
            per_run_estimated_classes: Vec::new(),
        }
    }

    /// Run DPOR-guided exploration.
    ///
    /// The `test` closure receives a freshly constructed `LabRuntime` for each
    /// run. Exploration continues until the work queue is empty or `max_runs`
    /// is reached.
    pub fn explore<F>(&mut self, test: F) -> ExplorationReport
    where
        F: Fn(&mut LabRuntime),
    {
        while self.results.len() < self.config.max_runs {
            let Some(seed) = self.work_queue.pop_front() else {
                break;
            };
            self.pending_seeds.remove(&seed);
            if !self.explored_seeds.insert(seed) {
                continue;
            }

            let (trace_events, run_result) = self.run_once(seed, &test);

            // Detect races and generate backtrack points.
            if trace_events.is_empty() {
                self.per_run_estimated_classes.push(1);
            } else {
                let analysis = detect_races(&trace_events);
                self.total_races += analysis.race_count();
                self.total_backtrack_points += analysis.backtrack_points.len();

                // Also run HB-race detection for coverage metrics.
                let hb_report = crate::trace::dpor::detect_hb_races(&trace_events);
                self.total_hb_races += hb_report.race_count();

                // Record per-run estimated class count.
                let est = crate::trace::dpor::estimated_classes(&trace_events);
                self.per_run_estimated_classes.push(est);

                // For each backtrack point, derive a new seed.
                // The derivation hashes the parent seed plus the race location
                // so the same race in the same run always maps to the same
                // follow-up seed.
                for bp in &analysis.backtrack_points {
                    // Sleep set optimization: skip backtrack points we've
                    // already explored (same race structure at same position).
                    if self.sleep_set.contains(bp, &trace_events) {
                        self.sleep_pruned += 1;
                        continue;
                    }
                    self.sleep_set.insert(bp, &trace_events);

                    let mut hasher = crate::util::DetHasher::for_lab();
                    seed.hash(&mut hasher);
                    bp.divergence_index.hash(&mut hasher);
                    bp.race.earlier.hash(&mut hasher);
                    bp.race.later.hash(&mut hasher);
                    let derived_seed = hasher.finish();

                    // Check if the derived seed would likely produce a known
                    // equivalence class by checking the monoid fingerprint of
                    // the prefix up to the divergence point.
                    let prefix = &trace_events[..bp.divergence_index.min(trace_events.len())];
                    let prefix_fp = trace_fingerprint(prefix);
                    if self.known_classes.contains_key(&prefix_fp) && prefix.len() > 1 {
                        // Prefix already explored; the full trace might still
                        // be different, but we deprioritize it.
                        self.enqueue_seed_back(derived_seed);
                    } else {
                        // Unknown prefix — high priority.
                        self.enqueue_seed_front(derived_seed);
                    }
                }
            }

            self.results.push(run_result);
        }

        self.build_report()
    }

    /// Run a single schedule and return (trace_events, run_result).
    fn run_once<F>(&mut self, seed: u64, test: &F) -> (Vec<TraceEvent>, RunResult)
    where
        F: Fn(&mut LabRuntime),
    {
        let mut lab_config = LabConfig::new(seed);
        lab_config = lab_config.worker_count(self.config.worker_count);
        if let Some(max) = Some(self.config.max_steps_per_run) {
            lab_config = lab_config.max_steps(max);
        }
        if self.config.record_traces {
            lab_config = lab_config.with_default_replay_recording();
        }

        let mut runtime = LabRuntime::new(lab_config);
        test(&mut runtime);

        let steps = runtime.steps();
        let trace_events: Vec<TraceEvent> = runtime.trace().snapshot();

        let monoid = TraceMonoid::from_events(&trace_events);
        let fingerprint = monoid.class_fingerprint();

        let is_new_class = !self.known_classes.contains_key(&fingerprint);
        if is_new_class {
            self.known_classes.insert(fingerprint, monoid);
        }
        *self.class_counts.entry(fingerprint).or_insert(0) += 1;

        let violations = runtime.check_invariants();
        if !violations.is_empty() {
            self.violations.push(ViolationReport {
                seed,
                steps,
                violations: violations.clone(),
                fingerprint,
            });
        }

        let certificate_hash = runtime.certificate().hash();

        let result = RunResult {
            seed,
            steps,
            fingerprint,
            is_new_class,
            violations,
            certificate_hash,
        };

        (trace_events, result)
    }

    fn enqueue_seed_front(&mut self, seed: u64) -> bool {
        if self.explored_seeds.contains(&seed) {
            self.pruned_backtrack_points += 1;
            return false;
        }
        if self.pending_seeds.insert(seed) {
            self.work_queue.push_front(seed);
            return true;
        }
        if let Some(position) = self.work_queue.iter().position(|queued| *queued == seed) {
            if position == 0 {
                // br-asupersync-vba3uv: seed is already at the front
                // of the work queue. The previous logic fell through
                // to the trailing `pruned_backtrack_points += 1;
                // false` block, over-counting prunes for the
                // common "front-prefer of an already-front seed"
                // case. The seed IS the prioritised one — return
                // success without bumping the prune counter.
                return true;
            }
            self.work_queue.remove(position);
            self.work_queue.push_front(seed);
            return true;
        }
        self.pruned_backtrack_points += 1;
        false
    }

    fn enqueue_seed_back(&mut self, seed: u64) -> bool {
        if self.explored_seeds.contains(&seed) || !self.pending_seeds.insert(seed) {
            self.pruned_backtrack_points += 1;
            return false;
        }
        self.work_queue.push_back(seed);
        true
    }

    fn build_report(&self) -> ExplorationReport {
        let total_runs = self.results.len();
        let new_class_discoveries = self.results.iter().filter(|r| r.is_new_class).count();
        let novelty_histogram = novelty_histogram_from_flags(&self.results);
        let saturation = saturation_metrics(&self.results, total_runs, new_class_discoveries);
        let top_unexplored = self
            .work_queue
            .iter()
            .take(DEFAULT_UNEXPLORED_LIMIT)
            .map(|seed| UnexploredSeed {
                seed: *seed,
                score: None,
            })
            .collect();
        ExplorationReport {
            total_runs,
            unique_classes: self.known_classes.len(),
            violations: self.violations.clone(),
            coverage: CoverageMetrics {
                equivalence_classes: self.known_classes.len(),
                total_runs,
                new_class_discoveries,
                class_run_counts: self.class_counts.clone(),
                novelty_histogram,
                saturation,
            },
            top_unexplored,
            runs: self.results.clone(),
        }
    }

    /// Returns DPOR-specific coverage metrics.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn dpor_coverage(&self) -> DporCoverageMetrics {
        let new_class_count = self.results.iter().filter(|r| r.is_new_class).count();
        let total = self.results.len();
        let novelty_histogram = novelty_histogram_from_flags(&self.results);
        let saturation = saturation_metrics(&self.results, total, new_class_count);
        DporCoverageMetrics {
            base: CoverageMetrics {
                equivalence_classes: self.known_classes.len(),
                total_runs: total,
                new_class_discoveries: new_class_count,
                class_run_counts: self.class_counts.clone(),
                novelty_histogram,
                saturation,
            },
            total_races: self.total_races,
            total_hb_races: self.total_hb_races,
            total_backtrack_points: self.total_backtrack_points,
            pruned_backtrack_points: self.pruned_backtrack_points,
            sleep_pruned: self.sleep_pruned,
            efficiency: if total == 0 {
                0.0
            } else {
                new_class_count as f64 / total as f64
            },
            estimated_class_trend: self.per_run_estimated_classes.clone(),
        }
    }
}

/// Topology-prioritized exploration engine.
///
/// Uses H1 persistent homology to score traces and prioritize seeds that
/// exhibit novel concurrency patterns (new homology classes). Seeds are
/// drawn from a priority queue ordered by [`TopologicalScore`].
///
/// # Algorithm
///
/// 1. Start with `max_runs` seeds in the queue, all scored at zero.
/// 2. Pop the highest-scored seed, run it, compute the trace's square
///    complex and H1 persistence.
/// 3. Score the persistence pairs against previously seen classes.
/// 4. Record the result; the next seed's score reflects how novel its
///    trace was (new classes discovered, persistence interval lengths).
/// 5. Repeat until the queue is empty or budget is exhausted.
///
/// Both modes (baseline and topology-prioritized) remain deterministic
/// given the same configuration and test closure.
pub struct TopologyExplorer {
    config: ExplorerConfig,
    /// Priority queue: (score, seed). Highest score popped first.
    frontier: BinaryHeap<(TopologicalScore, u64)>,
    /// Best known score for each seed still queued in the frontier.
    pending_frontier: BTreeMap<u64, TopologicalScore>,
    /// Explored seeds.
    explored_seeds: BTreeSet<u64>,
    /// Known equivalence classes (fingerprint → run count).
    known_fingerprints: BTreeSet<u64>,
    class_counts: BTreeMap<u64, usize>,
    /// Seen persistence classes for novelty detection.
    seen_classes: BTreeSet<ClassId>,
    /// Per-run results.
    results: Vec<RunResult>,
    /// Violations found.
    violations: Vec<ViolationReport>,
    /// Per-run evidence ledgers.
    ledgers: Vec<EvidenceLedger>,
    new_class_count: usize,
}

impl TopologyExplorer {
    /// Create a new topology explorer with the given configuration.
    #[must_use]
    pub fn new(config: ExplorerConfig) -> Self {
        let mut frontier = BinaryHeap::new();
        let mut pending_frontier = BTreeMap::new();
        // Seed the frontier with initial seeds, all scored at zero.
        for i in 0..config.max_runs {
            let seed = config.base_seed.wrapping_add(i as u64);
            let score = TopologicalScore::zero(seed_fingerprint(seed));
            frontier.push((score, seed));
            pending_frontier.insert(seed, score);
        }
        Self {
            config,
            frontier,
            pending_frontier,
            explored_seeds: BTreeSet::new(),
            known_fingerprints: BTreeSet::new(),
            class_counts: BTreeMap::new(),
            seen_classes: BTreeSet::new(),
            results: Vec::new(),
            violations: Vec::new(),
            ledgers: Vec::new(),
            new_class_count: 0,
        }
    }

    /// Run topology-prioritized exploration.
    ///
    /// The `test` closure receives a freshly constructed `LabRuntime` for each run.
    pub fn explore<F>(&mut self, test: F) -> ExplorationReport
    where
        F: Fn(&mut LabRuntime),
    {
        while self.results.len() < self.config.max_runs {
            let Some((score, seed)) = self.frontier.pop() else {
                break;
            };
            let Some(pending_score) = self.pending_frontier.get(&seed).copied() else {
                continue;
            };
            if pending_score != score {
                continue;
            }
            self.pending_frontier.remove(&seed);
            if !self.explored_seeds.insert(seed) {
                continue;
            }
            self.run_once(seed, &test);
        }
        self.build_report()
    }

    fn run_once<F>(&mut self, seed: u64, test: &F)
    where
        F: Fn(&mut LabRuntime),
    {
        let mut lab_config = LabConfig::new(seed);
        lab_config = lab_config.worker_count(self.config.worker_count);
        if let Some(max) = Some(self.config.max_steps_per_run) {
            lab_config = lab_config.max_steps(max);
        }
        if self.config.record_traces {
            lab_config = lab_config.with_default_replay_recording();
        }

        let mut runtime = LabRuntime::new(lab_config);
        test(&mut runtime);

        let steps = runtime.steps();
        let trace_events: Vec<TraceEvent> = runtime.trace().snapshot();

        let fingerprint = if trace_events.is_empty() {
            seed
        } else {
            trace_fingerprint(&trace_events)
        };

        let is_new_class = self.known_fingerprints.insert(fingerprint);
        if is_new_class {
            self.new_class_count += 1;
        }
        *self.class_counts.entry(fingerprint).or_insert(0) += 1;

        // Compute topological score from the trace's square complex.
        let fp = seed_fingerprint(seed);
        let ledger = score_trace_topology(&trace_events, &mut self.seen_classes, fp);

        self.enqueue_derived_seeds(seed, &ledger);
        self.ledgers.push(ledger);

        let violations = runtime.check_invariants();
        if !violations.is_empty() {
            self.violations.push(ViolationReport {
                seed,
                steps,
                violations: violations.clone(),
                fingerprint,
            });
        }

        let certificate_hash = runtime.certificate().hash();

        self.results.push(RunResult {
            seed,
            steps,
            fingerprint,
            is_new_class,
            violations,
            certificate_hash,
        });
    }

    fn enqueue_derived_seeds(&mut self, seed: u64, ledger: &EvidenceLedger) {
        if ledger.entries.is_empty() {
            return;
        }
        if ledger.score.novelty == 0 && ledger.score.persistence_sum == 0 {
            return;
        }
        let mut pushed = 0usize;
        for (idx, entry) in ledger.entries.iter().enumerate() {
            if pushed >= DEFAULT_DERIVED_SEEDS {
                break;
            }
            let derived_seed = derive_seed(seed, entry.class, idx as u64);
            let mut score = ledger.score;
            score.fingerprint = seed_fingerprint(derived_seed);
            if self.push_frontier_seed(derived_seed, score) {
                pushed += 1;
            }
        }
    }

    fn push_frontier_seed(&mut self, seed: u64, score: TopologicalScore) -> bool {
        if self.explored_seeds.contains(&seed) {
            return false;
        }
        match self.pending_frontier.get_mut(&seed) {
            Some(existing) => {
                if *existing >= score {
                    return false;
                }
                *existing = score;
            }
            None => {
                self.pending_frontier.insert(seed, score);
            }
        }
        self.frontier.push((score, seed));
        true
    }

    fn build_report(&self) -> ExplorationReport {
        let total_runs = self.results.len();
        let novelty_histogram = novelty_histogram_from_ledgers(&self.ledgers);
        let saturation = saturation_metrics(&self.results, total_runs, self.new_class_count);
        ExplorationReport {
            total_runs,
            unique_classes: self.known_fingerprints.len(),
            violations: self.violations.clone(),
            coverage: CoverageMetrics {
                equivalence_classes: self.known_fingerprints.len(),
                total_runs,
                new_class_discoveries: self.new_class_count,
                class_run_counts: self.class_counts.clone(),
                novelty_histogram,
                saturation,
            },
            top_unexplored: self.top_unexplored(DEFAULT_UNEXPLORED_LIMIT),
            runs: self.results.clone(),
        }
    }

    /// Access per-run results.
    #[must_use]
    pub fn results(&self) -> &[RunResult] {
        &self.results
    }

    /// Access per-run evidence ledgers.
    #[must_use]
    pub fn ledgers(&self) -> &[EvidenceLedger] {
        &self.ledgers
    }

    /// Access the current coverage metrics.
    #[must_use]
    pub fn coverage(&self) -> CoverageMetrics {
        let total_runs = self.results.len();
        let novelty_histogram = novelty_histogram_from_ledgers(&self.ledgers);
        let saturation = saturation_metrics(&self.results, total_runs, self.new_class_count);
        CoverageMetrics {
            equivalence_classes: self.known_fingerprints.len(),
            total_runs,
            new_class_discoveries: self.new_class_count,
            class_run_counts: self.class_counts.clone(),
            novelty_histogram,
            saturation,
        }
    }

    fn top_unexplored(&self, limit: usize) -> Vec<UnexploredSeed> {
        let mut ranked: Vec<_> = self
            .pending_frontier
            .iter()
            .map(|(&seed, &score)| UnexploredSeed {
                seed,
                score: Some(score),
            })
            .collect();
        ranked.sort_unstable_by_key(|right| std::cmp::Reverse(right.score));
        ranked.truncate(limit);
        ranked
    }
}

pub(crate) fn score_trace_topology(
    trace_events: &[TraceEvent],
    seen_classes: &mut BTreeSet<ClassId>,
    fingerprint: u64,
) -> EvidenceLedger {
    let poset = TracePoset::from_trace(trace_events);
    let complex = SquareComplex::from_trace_poset(&poset);
    let pairs = complex.h1_persistence_pairs();
    score_persistence(&pairs, seen_classes, fingerprint)
}

fn derive_seed(seed: u64, class: ClassId, index: u64) -> u64 {
    let mut hasher = DetHasher::for_lab();
    seed.hash(&mut hasher);
    class.birth.hash(&mut hasher);
    class.death.hash(&mut hasher);
    index.hash(&mut hasher);
    hasher.finish()
}

// ViolationReport needs Clone for build_report.
impl Clone for ViolationReport {
    fn clone(&self) -> Self {
        Self {
            seed: self.seed,
            steps: self.steps,
            violations: self.violations.clone(),
            fingerprint: self.fingerprint,
        }
    }
}

#[cfg(test)]
#[path = "explorer_inline_tests.rs"]
mod tests;
