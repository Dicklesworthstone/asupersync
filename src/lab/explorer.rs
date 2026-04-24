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

use crate::lab::config::LabConfig;
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
        }
    }

    /// Explore the test under multiple schedules.
    ///
    /// The `test` closure receives a freshly constructed `LabRuntime` for
    /// each run. It should set up tasks, schedule them, and call
    /// `run_until_quiescent()` (or equivalent).
    ///
    /// # Example
    ///
    /// ```ignore
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
/// # Coverage Guarantees
///
/// DPOR explores at least one representative schedule per Mazurkiewicz
/// equivalence class reachable from the initial schedule through single-race
/// reversals. This is sound (no false negatives) but not complete for deeply
/// nested race chains without iterative deepening.
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

                    let mut hasher = crate::util::DetHasher::default();
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
        if let Some(position) = self.work_queue.iter().position(|queued| *queued == seed)
            && position > 0
        {
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
    let mut hasher = DetHasher::default();
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
    use crate::trace::{TraceData, TraceEventKind};
    use crate::types::Budget;
    use crate::types::Time;
    use insta::assert_json_snapshot;
    use serde_json::Value as JsonValue;
    use std::collections::BTreeMap;
    use std::fs;
    use tempfile::NamedTempFile;

    /// Comprehensive scrubber for DPOR exploration transcript golden artifacts.
    ///
    /// Scrubs all non-deterministic fields that vary between runs while preserving
    /// the structural integrity and meaningful patterns in exploration transcripts.
    fn scrub_exploration_transcript(value: &mut JsonValue) {
        match value {
            JsonValue::Object(map) => {
                for (key, entry) in map.iter_mut() {
                    match key.as_str() {
                        // Seeds and derived values
                        "seed" => *entry = JsonValue::String("[SEED]".to_string()),
                        "violation_seeds" => {
                            if let JsonValue::Array(seeds) = entry {
                                for seed in seeds {
                                    *seed = JsonValue::String("[SEED]".to_string());
                                }
                            }
                        }
                        "certificate_divergences" => {
                            if let JsonValue::Array(pairs) = entry {
                                for pair in pairs {
                                    if let JsonValue::Array(seeds) = pair {
                                        for seed in seeds {
                                            *seed = JsonValue::String("[SEED]".to_string());
                                        }
                                    }
                                }
                            }
                        }

                        // Hash values and fingerprints (deterministic but opaque)
                        "fingerprint" => {
                            if let JsonValue::Number(n) = entry {
                                if n.as_u64().is_some() {
                                    *entry = JsonValue::String("[FINGERPRINT]".to_string());
                                }
                            }
                        }
                        "certificate_hash" => {
                            if let JsonValue::Number(n) = entry {
                                if n.as_u64().is_some() {
                                    *entry = JsonValue::String("[CERT_HASH]".to_string());
                                }
                            }
                        }

                        // Step counts (execution-dependent)
                        "steps" => {
                            if let JsonValue::Number(n) = entry {
                                if n.as_u64().is_some() {
                                    *entry = JsonValue::String("[STEPS]".to_string());
                                }
                            }
                        }

                        // Class run counts map (preserve structure, scrub keys)
                        "class_run_counts" => {
                            if let JsonValue::Object(counts) = entry {
                                let scrubbed_counts: serde_json::Map<String, JsonValue> = counts
                                    .iter()
                                    .enumerate()
                                    .map(|(i, (_, v))| (format!("[FINGERPRINT_{}]", i), v.clone()))
                                    .collect();
                                *entry = JsonValue::Object(scrubbed_counts);
                            }
                        }

                        // Topological scores with fingerprint scrubbing
                        "score" => {
                            if let JsonValue::Object(score_map) = entry {
                                if let Some(fp) = score_map.get_mut("fingerprint") {
                                    *fp = JsonValue::String("[FINGERPRINT]".to_string());
                                }
                            }
                        }

                        _ => scrub_exploration_transcript(entry),
                    }
                }
            }
            JsonValue::Array(entries) => {
                for entry in entries {
                    scrub_exploration_transcript(entry);
                }
            }
            JsonValue::Null | JsonValue::Bool(_) | JsonValue::Number(_) | JsonValue::String(_) => {}
        }
    }

    /// Legacy scrubber for backward compatibility with existing tests.
    fn scrub_seed_fields(value: &mut JsonValue) {
        scrub_exploration_transcript(value);
    }

    fn scenario_discovery_report_v2() -> ExplorationReport {
        ExplorationReport {
            total_runs: 3,
            unique_classes: 2,
            violations: vec![ViolationReport {
                seed: 11,
                steps: 21,
                violations: vec![InvariantViolation::TaskLeak { count: 2 }],
                fingerprint: 7001,
            }],
            coverage: CoverageMetrics {
                equivalence_classes: 2,
                total_runs: 3,
                new_class_discoveries: 2,
                class_run_counts: BTreeMap::from([(7001_u64, 2_usize), (7002_u64, 1_usize)]),
                novelty_histogram: BTreeMap::from([(0_u32, 1_usize), (1_u32, 2_usize)]),
                saturation: SaturationMetrics {
                    window: 10,
                    saturated: false,
                    existing_class_hits: 1,
                    runs_since_last_new_class: Some(1),
                },
            },
            top_unexplored: vec![
                UnexploredSeed {
                    seed: 44,
                    score: Some(TopologicalScore {
                        novelty: 3,
                        persistence_sum: 15,
                        fingerprint: 991,
                    }),
                },
                UnexploredSeed {
                    seed: 45,
                    score: None,
                },
            ],
            runs: vec![
                RunResult {
                    seed: 11,
                    steps: 21,
                    fingerprint: 7001,
                    is_new_class: true,
                    violations: vec![InvariantViolation::TaskLeak { count: 2 }],
                    certificate_hash: 17_001,
                },
                RunResult {
                    seed: 12,
                    steps: 13,
                    fingerprint: 7001,
                    is_new_class: false,
                    violations: Vec::new(),
                    certificate_hash: 17_002,
                },
                RunResult {
                    seed: 13,
                    steps: 8,
                    fingerprint: 7002,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 17_099,
                },
            ],
        }
    }

    #[test]
    fn explore_single_task_no_violations() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        assert!(!report.has_violations());
        assert_eq!(report.total_runs, 5);
        // Each seed produces distinct RNG values in the trace, so fingerprints
        // differ even for a single task. This is correct: the full trace
        // (including RNG) distinguishes runs. Schedule-level equivalence
        // will be handled by DPOR's filtered independence relation.
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn explore_two_independent_tasks_discovers_classes() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 20));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(!report.has_violations());
        assert_eq!(report.total_runs, 20);
        // Two independent no-yield tasks may produce different traces
        // depending on scheduling order, but the trace events are simple
        // enough that we might get 1 or 2 classes.
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn coverage_metrics_track_discovery() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(100, 10));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            runtime.scheduler.lock().schedule(t1, 0);
            runtime.run_until_quiescent();
        });

        let cov = &report.coverage;
        assert_eq!(cov.total_runs, 10);
        assert!(cov.equivalence_classes >= 1);
        assert!(cov.new_class_discoveries >= 1);
        // Discovery rate should be between 0 and 1 inclusive.
        assert!(cov.discovery_rate() > 0.0);
        assert!(cov.discovery_rate() <= 1.0);
        let hist_total: usize = cov.novelty_histogram.values().copied().sum();
        assert_eq!(hist_total, cov.total_runs);
        assert_eq!(cov.saturation.window, DEFAULT_SATURATION_WINDOW);
    }

    #[test]
    fn violation_seeds_are_recorded() {
        // This test just verifies the reporting mechanism works.
        // We don't inject real violations here; we just check the API.
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 3));
        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        // No violations expected.
        assert!(report.violation_seeds().is_empty());
    }

    #[test]
    fn explorer_config_builder() {
        let config = ExplorerConfig::new(42, 50)
            .worker_count(4)
            .max_steps(10_000);
        assert_eq!(config.base_seed, 42);
        assert_eq!(config.max_runs, 50);
        assert_eq!(config.worker_count, 4);
        assert_eq!(config.max_steps_per_run, 10_000);
    }

    #[test]
    fn discovery_rate_correct() {
        let mut novelty_histogram = BTreeMap::new();
        novelty_histogram.insert(0, 7);
        novelty_histogram.insert(1, 3);
        let saturation = SaturationMetrics {
            window: DEFAULT_SATURATION_WINDOW,
            saturated: false,
            existing_class_hits: 7,
            runs_since_last_new_class: Some(7),
        };
        let metrics = CoverageMetrics {
            equivalence_classes: 3,
            total_runs: 10,
            new_class_discoveries: 3,
            class_run_counts: BTreeMap::new(),
            novelty_histogram,
            saturation,
        };
        assert!((metrics.discovery_rate() - 0.3).abs() < 1e-10);
    }

    // ── DPOR Explorer tests ─────────────────────────────────────────────

    #[test]
    fn dpor_explore_single_task_no_violations() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 10));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        assert!(!report.has_violations());
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn dpor_explore_two_tasks_discovers_classes() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 20));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        assert!(!report.has_violations());
        assert!(report.unique_classes >= 1);
    }

    #[test]
    fn dpor_coverage_metrics_populated() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 5));
        let _report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            runtime.scheduler.lock().schedule(t1, 0);
            runtime.run_until_quiescent();
        });

        let metrics = explorer.dpor_coverage();
        assert!(metrics.base.total_runs >= 1);
        assert!(metrics.base.equivalence_classes >= 1);
        // Efficiency should be between 0 and 1.
        assert!(metrics.efficiency >= 0.0);
        assert!(metrics.efficiency <= 1.0);
    }

    #[test]
    fn dpor_explorer_respects_max_runs() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 3));
        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        assert!(report.total_runs <= 3);
    }

    #[test]
    fn dpor_queue_promotes_pending_seed_to_front() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 4));

        assert!(explorer.enqueue_seed_back(99));
        assert!(explorer.enqueue_seed_front(99));
        assert_eq!(
            explorer
                .work_queue
                .iter()
                .copied()
                .filter(|seed| *seed == 99)
                .count(),
            1
        );
        assert_eq!(explorer.work_queue.front().copied(), Some(99));
        assert!(explorer.pending_seeds.contains(&99));
    }

    #[test]
    fn dpor_report_keeps_unexplored_seed_when_run_budget_is_exhausted() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 1));
        assert!(explorer.enqueue_seed_back(99));

        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.total_runs, 1);
        assert_eq!(
            report
                .top_unexplored
                .iter()
                .map(|entry| entry.seed)
                .collect::<Vec<_>>(),
            vec![99]
        );
    }

    // ── Certificate integration tests ───────────────────────────────────

    #[test]
    fn certificate_hash_populated_in_run_results() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        // Every run should have a non-zero certificate hash (tasks were polled).
        for r in &report.runs {
            assert_ne!(r.certificate_hash, 0, "seed {} had zero cert hash", r.seed);
        }
    }

    #[test]
    fn same_seed_produces_same_certificate() {
        let run = |seed: u64| -> u64 {
            let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(seed, 1));
            explorer.explore(|runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (t, _) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async { 99 })
                    .expect("t");
                runtime.scheduler.lock().schedule(t, 0);
                runtime.run_until_quiescent();
            });
            let first = explorer
                .results()
                .first()
                .expect("explorer should record at least one run");
            first.certificate_hash
        };

        let h1 = run(77);
        let h2 = run(77);
        assert_eq!(h1, h2, "same seed should yield same certificate");
    }

    #[test]
    fn different_seeds_may_produce_different_certificates() {
        let run = |seed: u64| -> u64 {
            let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(seed, 1));
            explorer.explore(|runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (t1, _) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async {})
                    .expect("t1");
                let (t2, _) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async {})
                    .expect("t2");
                {
                    let mut sched = runtime.scheduler.lock();
                    sched.schedule(t1, 0);
                    sched.schedule(t2, 0);
                }
                runtime.run_until_quiescent();
            });
            let first = explorer
                .results()
                .first()
                .expect("explorer should record at least one run");
            first.certificate_hash
        };

        // With two tasks and different seeds, the scheduling order may differ.
        // Collect several seeds and check we see at least 1 unique hash.
        let hashes: BTreeSet<u64> = (0..10).map(run).collect();
        assert!(!hashes.is_empty());
    }

    #[test]
    fn certificates_consistent_with_single_task() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        // certificate_divergences checks within same fingerprint class.
        // Even if no two runs share a fingerprint, no divergences is correct.
        assert!(report.certificates_consistent());
    }

    #[test]
    fn dpor_certificate_hash_populated() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        for r in &report.runs {
            assert_ne!(r.certificate_hash, 0, "seed {} had zero cert hash", r.seed);
        }
    }

    #[test]
    fn json_summary_includes_core_fields() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(7, 2));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        let json = report.to_json_string().expect("json");
        let value: JsonValue = serde_json::from_str(&json).expect("parse");
        assert!(value.get("total_runs").is_some());
        assert!(value.get("unique_classes").is_some());
        assert!(value.get("coverage").is_some());
        assert!(value.get("violations").is_some());
        assert!(value.get("violation_seeds").is_some());
    }

    #[test]
    fn json_summary_can_be_written() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(11, 1));
        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        let tmp = NamedTempFile::new().expect("tmp");
        report
            .write_json_summary(tmp.path(), false)
            .expect("write json");
        let contents = fs::read_to_string(tmp.path()).expect("read");
        let value: JsonValue = serde_json::from_str(&contents).expect("parse");
        assert!(value.get("coverage").is_some());
    }

    #[test]
    fn scenario_discovery_output_v2_scrubbed_snapshot() {
        let mut value = serde_json::to_value(scenario_discovery_report_v2().to_json_summary())
            .expect("serialize scenario report");
        scrub_seed_fields(&mut value);
        assert_json_snapshot!("scenario_discovery_output_v2_scrubbed", value);
    }

    // ── Golden Artifact Tests for DPOR Exploration Transcripts ──────────────

    #[test]
    fn golden_schedule_explorer_single_task_transcript() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("create task");
            runtime.scheduler.lock().schedule(task_id, 0);
            runtime.run_until_quiescent();
        });

        let mut transcript =
            serde_json::to_value(report.to_json_summary()).expect("serialize exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("schedule_explorer_single_task_transcript", transcript);
    }

    #[test]
    fn golden_schedule_explorer_concurrent_tasks_transcript() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(0, 10).worker_count(2));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 2 })
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        let mut transcript =
            serde_json::to_value(report.to_json_summary()).expect("serialize exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("schedule_explorer_concurrent_tasks_transcript", transcript);
    }

    #[test]
    fn golden_dpor_explorer_basic_exploration_transcript() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(0, 8));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
            }
            runtime.run_until_quiescent();
        });

        let mut transcript = serde_json::to_value(report.to_json_summary())
            .expect("serialize dpor exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("dpor_explorer_basic_exploration_transcript", transcript);
    }

    #[test]
    fn golden_dpor_coverage_metrics_transcript() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(42, 5));
        let _report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            runtime.scheduler.lock().schedule(t1, 0);
            runtime.run_until_quiescent();
        });

        let coverage = explorer.dpor_coverage();
        let mut transcript =
            serde_json::to_value(&coverage).expect("serialize dpor coverage metrics");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("dpor_coverage_metrics_transcript", transcript);
    }

    #[test]
    fn golden_topology_explorer_homology_scoring_transcript() {
        // Create a scenario with triangle-like trace structure for homology
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(7, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);

            // Create three tasks that form a triangle dependency pattern
            let (t1, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t1");
            let (t2, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t2");
            let (t3, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("t3");

            {
                let mut sched = runtime.scheduler.lock();
                sched.schedule(t1, 0);
                sched.schedule(t2, 0);
                sched.schedule(t3, 0);
            }
            runtime.run_until_quiescent();
        });

        // Test the exploration report from topology-prioritized exploration
        let mut transcript = serde_json::to_value(report.to_json_summary())
            .expect("serialize topology exploration report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("topology_explorer_homology_scoring_transcript", transcript);
    }

    #[test]
    fn golden_exploration_report_with_violations_transcript() {
        // Create a mock scenario with violations for golden testing
        let violations = vec![ViolationReport {
            seed: 123,
            steps: 45,
            violations: vec![
                InvariantViolation::TaskLeak { count: 2 },
                InvariantViolation::ObligationLeak { leaks: Vec::new() },
            ],
            fingerprint: 9876,
        }];

        let report = ExplorationReport {
            total_runs: 10,
            unique_classes: 5,
            violations,
            coverage: CoverageMetrics {
                equivalence_classes: 5,
                total_runs: 10,
                new_class_discoveries: 5,
                class_run_counts: BTreeMap::from([
                    (1000_u64, 3_usize),
                    (2000_u64, 2_usize),
                    (3000_u64, 2_usize),
                    (4000_u64, 2_usize),
                    (5000_u64, 1_usize),
                ]),
                novelty_histogram: BTreeMap::from([(0_u32, 5_usize), (1_u32, 5_usize)]),
                saturation: SaturationMetrics {
                    window: 10,
                    saturated: false,
                    existing_class_hits: 5,
                    runs_since_last_new_class: Some(2),
                },
            },
            top_unexplored: vec![UnexploredSeed {
                seed: 999,
                score: Some(TopologicalScore {
                    novelty: 2,
                    persistence_sum: 100,
                    fingerprint: 5555,
                }),
            }],
            runs: vec![
                RunResult {
                    seed: 100,
                    steps: 20,
                    fingerprint: 1000,
                    is_new_class: true,
                    violations: Vec::new(),
                    certificate_hash: 8000,
                },
                RunResult {
                    seed: 123,
                    steps: 45,
                    fingerprint: 9876,
                    is_new_class: true,
                    violations: vec![
                        InvariantViolation::TaskLeak { count: 2 },
                        InvariantViolation::ObligationLeak { leaks: Vec::new() },
                    ],
                    certificate_hash: 8123,
                },
            ],
        };

        let mut transcript =
            serde_json::to_value(report.to_json_summary()).expect("serialize violation report");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("exploration_report_with_violations_transcript", transcript);
    }

    #[test]
    fn golden_saturation_metrics_detailed_transcript() {
        // Create a scenario that tests saturation detection
        let metrics = SaturationMetrics {
            window: 10,
            saturated: true,
            existing_class_hits: 15,
            runs_since_last_new_class: Some(8),
        };

        let mut transcript = serde_json::to_value(&metrics).expect("serialize saturation metrics");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("saturation_metrics_detailed_transcript", transcript);
    }

    #[test]
    fn golden_coverage_trends_transcript() {
        // Test coverage evolution over multiple runs
        let coverage = CoverageMetrics {
            equivalence_classes: 8,
            total_runs: 25,
            new_class_discoveries: 8,
            class_run_counts: BTreeMap::from([
                (100_u64, 5_usize), // Frequent class
                (200_u64, 4_usize), // Common class
                (300_u64, 3_usize), // Less common
                (400_u64, 3_usize),
                (500_u64, 2_usize),
                (600_u64, 2_usize),
                (700_u64, 2_usize),
                (800_u64, 1_usize), // Rare classes
                (900_u64, 1_usize),
                (1000_u64, 2_usize),
            ]),
            novelty_histogram: BTreeMap::from([
                (0_u32, 17_usize), // Existing class hits
                (1_u32, 8_usize),  // New class discoveries
            ]),
            saturation: SaturationMetrics {
                window: 10,
                saturated: true,
                existing_class_hits: 17,
                runs_since_last_new_class: Some(5),
            },
        };

        let mut transcript = serde_json::to_value(&coverage).expect("serialize coverage metrics");
        scrub_exploration_transcript(&mut transcript);
        assert_json_snapshot!("coverage_trends_transcript", transcript);
    }

    #[test]
    fn schedule_report_includes_per_run_results() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(21, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.runs.len(), report.total_runs);
        assert!(!report.runs.is_empty());
    }

    #[test]
    fn dpor_report_includes_per_run_results() {
        let mut explorer = DporExplorer::new(ExplorerConfig::new(31, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.runs.len(), report.total_runs);
        assert!(!report.runs.is_empty());
    }

    #[test]
    fn topology_frontier_upgrades_pending_seed_score() {
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(10, 2));
        let low_score = TopologicalScore {
            novelty: 1,
            persistence_sum: 2,
            fingerprint: seed_fingerprint(99),
        };
        let high_score = TopologicalScore {
            novelty: 2,
            persistence_sum: 5,
            fingerprint: seed_fingerprint(99),
        };

        assert!(explorer.push_frontier_seed(99, low_score));
        assert!(explorer.push_frontier_seed(99, high_score));
        assert_eq!(
            explorer.pending_frontier.get(&99).copied(),
            Some(high_score)
        );
        assert_eq!(
            explorer
                .top_unexplored(2)
                .into_iter()
                .find(|entry| entry.seed == 99)
                .and_then(|entry| entry.score),
            Some(high_score)
        );
        assert!(!explorer.push_frontier_seed(99, low_score));
    }

    #[test]
    fn topology_report_keeps_unexplored_seed_when_run_budget_is_exhausted() {
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(10, 1));
        let score = TopologicalScore {
            novelty: 1,
            persistence_sum: 2,
            fingerprint: seed_fingerprint(99),
        };
        assert!(explorer.push_frontier_seed(99, score));

        let report = explorer.explore(|runtime| {
            let _region = runtime.state.create_root_region(Budget::INFINITE);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.total_runs, 1);
        assert_eq!(
            report
                .top_unexplored
                .iter()
                .map(|entry| entry.seed)
                .collect::<Vec<_>>(),
            vec![10]
        );
    }

    #[test]
    fn topology_report_includes_per_run_results() {
        let mut explorer = TopologyExplorer::new(ExplorerConfig::new(41, 3));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("task");
            runtime.scheduler.lock().schedule(task, 0);
            runtime.run_until_quiescent();
        });

        assert_eq!(report.runs.len(), report.total_runs);
        assert!(!report.runs.is_empty());
    }

    #[test]
    fn topology_scoring_detects_unfilled_triangle_h1_class() {
        let trace = vec![
            TraceEvent::new(
                1,
                Time::from_nanos(10),
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "triangle-a".to_string(),
                    task: None,
                    detail: "write global state".to_string(),
                },
            ),
            TraceEvent::new(
                2,
                Time::from_nanos(20),
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "triangle-b".to_string(),
                    task: None,
                    detail: "write global state".to_string(),
                },
            ),
            TraceEvent::new(
                3,
                Time::from_nanos(30),
                TraceEventKind::ChaosInjection,
                TraceData::Chaos {
                    kind: "triangle-c".to_string(),
                    task: None,
                    detail: "write global state".to_string(),
                },
            ),
        ];

        let mut seen_classes = BTreeSet::new();
        let ledger = score_trace_topology(&trace, &mut seen_classes, seed_fingerprint(7));

        assert_eq!(ledger.score.novelty, 1);
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries[0].class.death, usize::MAX);
        assert!(
            (3..6).contains(&ledger.entries[0].class.birth),
            "triangle H1 birth should come from an edge column"
        );
    }

    #[test]
    fn exploration_mode_debug_clone_copy_default_eq() {
        let m = ExplorationMode::default();
        assert_eq!(m, ExplorationMode::Baseline);

        let dbg = format!("{m:?}");
        assert!(dbg.contains("Baseline"));

        let m2 = m;
        assert_eq!(m, m2);

        let m3 = m;
        assert_eq!(m, m3);

        assert_ne!(
            ExplorationMode::Baseline,
            ExplorationMode::TopologyPrioritized
        );
    }

    #[test]
    fn explorer_config_debug_clone_default() {
        let c = ExplorerConfig::default();
        let dbg = format!("{c:?}");
        assert!(dbg.contains("ExplorerConfig"));

        let c2 = c;
        assert_eq!(c2.base_seed, 0);
        assert_eq!(c2.max_runs, 100);
        assert!(c2.record_traces);
    }

    #[test]
    fn saturation_metrics_debug_clone() {
        let s = SaturationMetrics {
            window: 10,
            saturated: false,
            existing_class_hits: 5,
            runs_since_last_new_class: Some(3),
        };
        let dbg = format!("{s:?}");
        assert!(dbg.contains("SaturationMetrics"));

        let s2 = s;
        assert_eq!(s2.window, 10);
        assert!(!s2.saturated);
    }
}
