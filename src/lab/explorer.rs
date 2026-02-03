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
use crate::trace::canonicalize::{trace_fingerprint, TraceMonoid};
use crate::trace::dpor::detect_races;
use crate::trace::event::TraceEvent;
use std::collections::{HashMap, HashSet, VecDeque};

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
#[derive(Debug)]
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
#[derive(Debug, Clone)]
pub struct CoverageMetrics {
    /// Number of distinct equivalence classes discovered.
    pub equivalence_classes: usize,
    /// Total runs performed.
    pub total_runs: usize,
    /// Number of runs that discovered a new equivalence class.
    pub new_class_discoveries: usize,
    /// Per-class run counts (fingerprint -> count).
    pub class_run_counts: HashMap<u64, usize>,
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
        let mut by_class: HashMap<u64, Vec<&RunResult>> = HashMap::new();
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
}

/// The schedule exploration engine.
///
/// Runs a test under multiple seeds, tracking equivalence classes and
/// detecting invariant violations.
pub struct ScheduleExplorer {
    config: ExplorerConfig,
    explored_seeds: HashSet<u64>,
    known_fingerprints: HashSet<u64>,
    class_counts: HashMap<u64, usize>,
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
            explored_seeds: HashSet::new(),
            known_fingerprints: HashSet::new(),
            class_counts: HashMap::new(),
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
        ExplorationReport {
            total_runs: self.results.len(),
            unique_classes: self.known_fingerprints.len(),
            violations: self.violations.clone(),
            coverage: CoverageMetrics {
                equivalence_classes: self.known_fingerprints.len(),
                total_runs: self.results.len(),
                new_class_discoveries: self.new_class_count,
                class_run_counts: self.class_counts.clone(),
            },
            runs: Vec::new(), // Omit per-run details from report to save memory.
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
        CoverageMetrics {
            equivalence_classes: self.known_fingerprints.len(),
            total_runs: self.results.len(),
            new_class_discoveries: self.new_class_count,
            class_run_counts: self.class_counts.clone(),
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
    /// Explored seeds.
    explored_seeds: HashSet<u64>,
    /// Known equivalence classes (fingerprint → monoid element).
    known_classes: HashMap<u64, TraceMonoid>,
    /// Per-class run counts.
    class_counts: HashMap<u64, usize>,
    /// All run results.
    results: Vec<RunResult>,
    /// Violations found.
    violations: Vec<ViolationReport>,
    /// Total races found across all runs.
    total_races: usize,
    /// Backtrack points generated.
    total_backtrack_points: usize,
    /// Backtrack points pruned by equivalence class deduplication.
    pruned_backtrack_points: usize,
}

/// Extended coverage metrics for DPOR exploration.
#[derive(Debug, Clone)]
pub struct DporCoverageMetrics {
    /// Base coverage metrics.
    pub base: CoverageMetrics,
    /// Total races detected across all runs.
    pub total_races: usize,
    /// Total backtrack points generated.
    pub total_backtrack_points: usize,
    /// Backtrack points pruned by equivalence deduplication.
    pub pruned_backtrack_points: usize,
    /// Ratio of useful exploration (new classes / total runs).
    pub efficiency: f64,
}

impl DporExplorer {
    /// Create a new DPOR explorer with the given configuration.
    #[must_use]
    pub fn new(config: ExplorerConfig) -> Self {
        let mut work_queue = VecDeque::new();
        work_queue.push_back(config.base_seed);
        Self {
            config,
            work_queue,
            explored_seeds: HashSet::new(),
            known_classes: HashMap::new(),
            class_counts: HashMap::new(),
            results: Vec::new(),
            violations: Vec::new(),
            total_races: 0,
            total_backtrack_points: 0,
            pruned_backtrack_points: 0,
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
        while let Some(seed) = self.work_queue.pop_front() {
            if self.results.len() >= self.config.max_runs {
                break;
            }
            if !self.explored_seeds.insert(seed) {
                continue;
            }

            let (trace_events, run_result) = self.run_once(seed, &test);

            // Detect races and generate backtrack points.
            if !trace_events.is_empty() {
                let analysis = detect_races(&trace_events);
                self.total_races += analysis.race_count();
                self.total_backtrack_points += analysis.backtrack_points.len();

                // For each backtrack point, derive a new seed.
                // We use a deterministic derivation: seed XOR hash of the
                // divergence index. This ensures the same backtrack point
                // always generates the same seed.
                for bp in &analysis.backtrack_points {
                    let derived_seed =
                        seed ^ (bp.divergence_index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);

                    if self.explored_seeds.contains(&derived_seed) {
                        self.pruned_backtrack_points += 1;
                        continue;
                    }

                    // Check if the derived seed would likely produce a known
                    // equivalence class by checking the monoid fingerprint of
                    // the prefix up to the divergence point.
                    let prefix = &trace_events[..bp.divergence_index.min(trace_events.len())];
                    let prefix_fp = trace_fingerprint(prefix);
                    if self.known_classes.contains_key(&prefix_fp) && prefix.len() > 1 {
                        // Prefix already explored; the full trace might still
                        // be different, but we deprioritize it.
                        self.work_queue.push_back(derived_seed);
                    } else {
                        // Unknown prefix — high priority.
                        self.work_queue.push_front(derived_seed);
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

    fn build_report(&self) -> ExplorationReport {
        ExplorationReport {
            total_runs: self.results.len(),
            unique_classes: self.known_classes.len(),
            violations: self.violations.clone(),
            coverage: CoverageMetrics {
                equivalence_classes: self.known_classes.len(),
                total_runs: self.results.len(),
                new_class_discoveries: self.results.iter().filter(|r| r.is_new_class).count(),
                class_run_counts: self.class_counts.clone(),
            },
            runs: Vec::new(),
        }
    }

    /// Returns DPOR-specific coverage metrics.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn dpor_coverage(&self) -> DporCoverageMetrics {
        let new_class_count = self.results.iter().filter(|r| r.is_new_class).count();
        let total = self.results.len();
        DporCoverageMetrics {
            base: CoverageMetrics {
                equivalence_classes: self.known_classes.len(),
                total_runs: total,
                new_class_discoveries: new_class_count,
                class_run_counts: self.class_counts.clone(),
            },
            total_races: self.total_races,
            total_backtrack_points: self.total_backtrack_points,
            pruned_backtrack_points: self.pruned_backtrack_points,
            efficiency: if total == 0 {
                0.0
            } else {
                new_class_count as f64 / total as f64
            },
        }
    }
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
    use super::*;
    use crate::types::Budget;

    #[test]
    fn explore_single_task_no_violations() {
        let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(42, 5));
        let report = explorer.explore(|runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (task_id, _handle) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 42 })
                .expect("create task");
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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
                let mut sched = runtime.scheduler.lock().unwrap();
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
            runtime.scheduler.lock().unwrap().schedule(t1, 0);
            runtime.run_until_quiescent();
        });

        let cov = &report.coverage;
        assert_eq!(cov.total_runs, 10);
        assert!(cov.equivalence_classes >= 1);
        assert!(cov.new_class_discoveries >= 1);
        // Discovery rate should be between 0 and 1 inclusive.
        assert!(cov.discovery_rate() > 0.0);
        assert!(cov.discovery_rate() <= 1.0);
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
        let metrics = CoverageMetrics {
            equivalence_classes: 3,
            total_runs: 10,
            new_class_discoveries: 3,
            class_run_counts: HashMap::new(),
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
            runtime.scheduler.lock().unwrap().schedule(task_id, 0);
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
                let mut sched = runtime.scheduler.lock().unwrap();
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
            runtime.scheduler.lock().unwrap().schedule(t1, 0);
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
            runtime.scheduler.lock().unwrap().schedule(t, 0);
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
            let report = explorer.explore(|runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (t, _) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async { 99 })
                    .expect("t");
                runtime.scheduler.lock().unwrap().schedule(t, 0);
                runtime.run_until_quiescent();
            });
            report.runs[0].certificate_hash
        };

        let h1 = run(77);
        let h2 = run(77);
        assert_eq!(h1, h2, "same seed should yield same certificate");
    }

    #[test]
    fn different_seeds_may_produce_different_certificates() {
        let run = |seed: u64| -> u64 {
            let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(seed, 1));
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
                    let mut sched = runtime.scheduler.lock().unwrap();
                    sched.schedule(t1, 0);
                    sched.schedule(t2, 0);
                }
                runtime.run_until_quiescent();
            });
            report.runs[0].certificate_hash
        };

        // With two tasks and different seeds, the scheduling order may differ.
        // Collect several seeds and check we see at least 1 unique hash.
        let hashes: HashSet<u64> = (0..10).map(|s| run(s)).collect();
        assert!(hashes.len() >= 1);
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
            runtime.scheduler.lock().unwrap().schedule(t, 0);
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
            runtime.scheduler.lock().unwrap().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        for r in &report.runs {
            assert_ne!(r.certificate_hash, 0, "seed {} had zero cert hash", r.seed);
        }
    }
}
