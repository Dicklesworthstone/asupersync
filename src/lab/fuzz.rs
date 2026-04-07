//! Deterministic fuzz harness for structured concurrency invariants.
//!
//! Uses seed-driven exploration to systematically fuzz scheduling decisions
//! and verify invariant oracles. When a violation is found, the seed is
//! minimized to produce a minimal reproducer.

use crate::lab::config::LabConfig;
use crate::lab::replay::normalize_for_replay;
use crate::lab::runtime::{InvariantViolation, LabRuntime};
use std::collections::BTreeMap;

/// Configuration for the deterministic fuzzer.
#[derive(Debug, Clone)]
pub struct FuzzConfig {
    /// Base seed for the fuzz campaign.
    pub base_seed: u64,
    /// Number of fuzz iterations.
    pub iterations: usize,
    /// Maximum steps per iteration before timeout.
    pub max_steps: u64,
    /// Number of simulated workers.
    pub worker_count: usize,
    /// Enable seed minimization when a violation is found.
    pub minimize: bool,
    /// Maximum minimization attempts per violation.
    pub minimize_attempts: usize,
}

impl FuzzConfig {
    /// Create a new fuzz configuration with the given seed and iteration count.
    #[must_use]
    pub fn new(base_seed: u64, iterations: usize) -> Self {
        Self {
            base_seed,
            iterations,
            max_steps: 100_000,
            worker_count: 1,
            minimize: true,
            minimize_attempts: 96,
        }
    }

    /// Set the simulated worker count.
    #[must_use]
    pub fn worker_count(mut self, count: usize) -> Self {
        self.worker_count = count;
        self
    }

    /// Set the maximum step count per iteration.
    #[must_use]
    pub fn max_steps(mut self, max: u64) -> Self {
        self.max_steps = max;
        self
    }

    /// Enable or disable seed minimization.
    #[must_use]
    pub fn minimize(mut self, enabled: bool) -> Self {
        self.minimize = enabled;
        self
    }
}

/// A fuzz finding: a seed that triggers an invariant violation.
#[derive(Debug, Clone)]
pub struct FuzzFinding {
    /// The seed that triggered the violation.
    pub seed: u64,
    /// Steps taken before the violation.
    pub steps: u64,
    /// The violations found.
    pub violations: Vec<InvariantViolation>,
    /// Certificate hash for the schedule that triggered the violation.
    pub certificate_hash: u64,
    /// Canonical normalized trace fingerprint for this failing run.
    pub trace_fingerprint: u64,
    /// Minimized seed (if minimization succeeded).
    pub minimized_seed: Option<u64>,
}

/// Results of a fuzz campaign.
#[derive(Debug)]
pub struct FuzzReport {
    /// Total iterations run.
    pub iterations: usize,
    /// Findings (seeds that triggered violations).
    pub findings: Vec<FuzzFinding>,
    /// Violation counts by category.
    pub violation_counts: BTreeMap<String, usize>,
    /// Certificate hashes seen (for determinism verification).
    pub unique_certificates: usize,
}

/// Deterministic corpus entry for a minimized failing fuzz run.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuzzRegressionCase {
    /// Seed that produced the original failure.
    pub seed: u64,
    /// Replay seed to use for regression checks (minimized when available).
    pub replay_seed: u64,
    /// Scheduler certificate hash from the failing run.
    pub certificate_hash: u64,
    /// Canonical normalized trace fingerprint for the failing run.
    pub trace_fingerprint: u64,
    /// Stable violation categories observed for this case.
    pub violation_categories: Vec<String>,
}

/// Deterministic regression corpus produced by a fuzz campaign.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FuzzRegressionCorpus {
    /// Schema version for compatibility and migration.
    pub schema_version: u32,
    /// Base seed used for this fuzz campaign.
    pub base_seed: u64,
    /// Number of iterations executed by the campaign.
    pub iterations: usize,
    /// Cases sorted in deterministic replay order.
    pub cases: Vec<FuzzRegressionCase>,
}

impl FuzzFinding {
    /// Promote this fuzz finding into a replayable dual-run scenario.
    #[must_use]
    pub fn to_promoted_scenario(
        &self,
        surface_id: &str,
        contract_version: &str,
    ) -> crate::lab::dual_run::PromotedFuzzScenario {
        crate::lab::dual_run::promote_fuzz_finding(self, surface_id, contract_version)
    }
}

impl FuzzRegressionCase {
    /// Promote this deterministic regression case into a replayable scenario.
    #[must_use]
    pub fn to_promoted_scenario(
        &self,
        surface_id: &str,
        contract_version: &str,
    ) -> crate::lab::dual_run::PromotedFuzzScenario {
        crate::lab::dual_run::promote_regression_case(self, surface_id, contract_version)
    }
}

impl FuzzRegressionCorpus {
    /// Promote this deterministic regression corpus into replayable scenarios.
    #[must_use]
    pub fn to_promoted_scenarios(
        &self,
        surface_id: &str,
        contract_version: &str,
    ) -> Vec<crate::lab::dual_run::PromotedFuzzScenario> {
        crate::lab::dual_run::promote_regression_corpus(self, surface_id, contract_version)
    }
}

impl FuzzReport {
    /// True if any violations were found.
    #[must_use]
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Seeds that triggered violations.
    #[must_use]
    pub fn finding_seeds(&self) -> Vec<u64> {
        self.findings.iter().map(|f| f.seed).collect()
    }

    /// Minimized seeds (where minimization succeeded).
    #[must_use]
    pub fn minimized_seeds(&self) -> Vec<u64> {
        self.findings
            .iter()
            .filter_map(|f| f.minimized_seed)
            .collect()
    }

    /// Build a deterministic minimized-failure replay corpus.
    ///
    /// Cases are sorted by replay seed and stable fingerprints so CI can diff
    /// corpus snapshots reproducibly.
    #[must_use]
    pub fn to_regression_corpus(&self, base_seed: u64) -> FuzzRegressionCorpus {
        let mut cases: Vec<FuzzRegressionCase> = self
            .findings
            .iter()
            .map(|finding| {
                let replay_seed = finding.minimized_seed.unwrap_or(finding.seed);
                FuzzRegressionCase {
                    seed: finding.seed,
                    replay_seed,
                    certificate_hash: finding.certificate_hash,
                    trace_fingerprint: finding.trace_fingerprint,
                    violation_categories: sorted_violation_categories(&finding.violations),
                }
            })
            .collect();

        cases.sort_by_key(|case| {
            (
                case.replay_seed,
                case.seed,
                case.trace_fingerprint,
                case.certificate_hash,
            )
        });

        FuzzRegressionCorpus {
            schema_version: 1,
            base_seed,
            iterations: self.iterations,
            cases,
        }
    }

    /// Promote every raw fuzz finding into replayable dual-run scenarios.
    #[must_use]
    pub fn to_promoted_findings(
        &self,
        surface_id: &str,
        contract_version: &str,
    ) -> Vec<crate::lab::dual_run::PromotedFuzzScenario> {
        self.findings
            .iter()
            .map(|finding| finding.to_promoted_scenario(surface_id, contract_version))
            .collect()
    }

    /// Build a deterministic regression corpus and promote it into scenarios.
    ///
    /// This is the main fuzz-to-scenario bridge used by higher-level replay
    /// and differential suites.
    #[must_use]
    pub fn to_promoted_regression_scenarios(
        &self,
        base_seed: u64,
        surface_id: &str,
        contract_version: &str,
    ) -> Vec<crate::lab::dual_run::PromotedFuzzScenario> {
        self.to_regression_corpus(base_seed)
            .to_promoted_scenarios(surface_id, contract_version)
    }
}

/// Deterministic fuzz harness.
///
/// Runs a test closure under many deterministic seeds, checking invariant
/// oracles after each run. When a violation is found, the harness optionally
/// minimizes the seed to find a simpler reproducer.
pub struct FuzzHarness {
    config: FuzzConfig,
}

impl FuzzHarness {
    /// Create a fuzz harness for the provided configuration.
    #[must_use]
    pub fn new(config: FuzzConfig) -> Self {
        Self { config }
    }

    /// Run the fuzz campaign.
    ///
    /// The `test` closure receives a `LabRuntime` and should set up tasks,
    /// schedule them, and run to quiescence.
    pub fn run<F>(&self, test: F) -> FuzzReport
    where
        F: Fn(&mut LabRuntime),
    {
        let mut findings = Vec::new();
        let mut violation_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut certificate_hashes = std::collections::BTreeSet::new();

        for i in 0..self.config.iterations {
            let seed = self.config.base_seed.wrapping_add(i as u64);
            let result = self.run_single(seed, &test);

            certificate_hashes.insert(result.certificate_hash);

            if !result.violations.is_empty() {
                for v in &result.violations {
                    let key = violation_category(v);
                    *violation_counts.entry(key).or_insert(0) += 1;
                }

                let minimized = if self.config.minimize {
                    self.minimize_seed(seed, &test)
                } else {
                    None
                };

                let (minimized_seed, certificate_hash, trace_fingerprint) = match minimized {
                    Some((min_seed, ref min_res)) => (
                        Some(min_seed),
                        min_res.certificate_hash,
                        min_res.trace_fingerprint,
                    ),
                    None => (None, result.certificate_hash, result.trace_fingerprint),
                };

                findings.push(FuzzFinding {
                    seed,
                    steps: result.steps,
                    violations: result.violations,
                    certificate_hash,
                    trace_fingerprint,
                    minimized_seed,
                });
            }
        }

        FuzzReport {
            iterations: self.config.iterations,
            findings,
            violation_counts,
            unique_certificates: certificate_hashes.len(),
        }
    }

    fn run_single<F>(&self, seed: u64, test: &F) -> SingleRunResult
    where
        F: Fn(&mut LabRuntime),
    {
        let mut lab_config = LabConfig::new(seed);
        lab_config = lab_config.worker_count(self.config.worker_count);
        lab_config = lab_config.max_steps(self.config.max_steps);

        let mut runtime = LabRuntime::new(lab_config);
        test(&mut runtime);

        let steps = runtime.steps();
        let certificate_hash = runtime.certificate().hash();
        let trace_events = runtime.trace().snapshot();
        let normalized = normalize_for_replay(&trace_events);
        let trace_fingerprint =
            crate::trace::canonicalize::trace_fingerprint(&normalized.normalized);
        let violations = runtime.check_invariants();

        SingleRunResult {
            steps,
            violations,
            certificate_hash,
            trace_fingerprint,
        }
    }

    /// Attempt to minimize a failing seed.
    ///
    /// Tries nearby seeds (bit-flips and offsets) to find the smallest
    /// seed that still reproduces the same violation-category set.
    fn minimize_seed<F>(&self, original_seed: u64, test: &F) -> Option<(u64, SingleRunResult)>
    where
        F: Fn(&mut LabRuntime),
    {
        let original_result = self.run_single(original_seed, test);
        if original_result.violations.is_empty() {
            return None;
        }
        let target_categories = sorted_violation_categories(&original_result.violations);

        let mut best_seed = original_seed;
        let mut best_result = None;

        // Try smaller seeds first (simple reduction).
        for attempt in 0..self.config.minimize_attempts {
            let candidate = match attempt {
                // Try absolute small seeds first.
                0..=15 => attempt as u64,
                // Try seeds near the original.
                16..=31 => original_seed.wrapping_sub((attempt - 15) as u64),
                // Try bit-flipped variants.
                _ => original_seed ^ (1u64 << ((attempt - 32) % 64)),
            };

            if candidate == original_seed {
                continue;
            }

            let result = self.run_single(candidate, test);
            if result.violations.is_empty() {
                continue;
            }

            let categories = sorted_violation_categories(&result.violations);
            if categories == target_categories && candidate < best_seed {
                best_seed = candidate;
                best_result = Some(result);
            }
        }

        if best_seed == original_seed {
            None
        } else {
            Some((
                best_seed,
                best_result.expect("best result should exist when updating best_seed"),
            ))
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct SingleRunResult {
    steps: u64,
    violations: Vec<InvariantViolation>,
    certificate_hash: u64,
    trace_fingerprint: u64,
}

fn violation_category(v: &InvariantViolation) -> String {
    match v {
        InvariantViolation::ObligationLeak { .. } => "obligation_leak".to_string(),
        InvariantViolation::TaskLeak { .. } => "task_leak".to_string(),
        InvariantViolation::ActorLeak { .. } => "actor_leak".to_string(),
        InvariantViolation::QuiescenceViolation => "quiescence_violation".to_string(),
        InvariantViolation::Futurelock { .. } => "futurelock".to_string(),
    }
}

fn sorted_violation_categories(violations: &[InvariantViolation]) -> Vec<String> {
    let mut categories: Vec<String> = violations.iter().map(violation_category).collect();
    categories.sort_unstable();
    categories.dedup();
    categories
}

/// Convenience function: run a quick fuzz campaign with default settings.
pub fn fuzz_quick<F>(seed: u64, iterations: usize, test: F) -> FuzzReport
where
    F: Fn(&mut LabRuntime),
{
    let harness = FuzzHarness::new(FuzzConfig::new(seed, iterations));
    harness.run(test)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Budget;

    #[test]
    fn fuzz_no_violations_with_simple_task() {
        let report = fuzz_quick(42, 10, |runtime| {
            let region = runtime.state.create_root_region(Budget::INFINITE);
            let (t, _) = runtime
                .state
                .create_task(region, Budget::INFINITE, async { 1 })
                .expect("t");
            runtime.scheduler.lock().schedule(t, 0);
            runtime.run_until_quiescent();
        });

        assert!(!report.has_findings());
        assert_eq!(report.iterations, 10);
        assert!(report.unique_certificates >= 1);
    }

    #[test]
    fn fuzz_config_builder() {
        let config = FuzzConfig::new(0, 100)
            .worker_count(4)
            .max_steps(5000)
            .minimize(false);
        assert_eq!(config.worker_count, 4);
        assert_eq!(config.max_steps, 5000);
        assert!(!config.minimize);
    }

    #[test]
    fn fuzz_two_tasks_no_violations() {
        let report = fuzz_quick(0, 20, |runtime| {
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

        assert!(!report.has_findings());
    }

    #[test]
    fn fuzz_report_seed_accessors() {
        let report = FuzzReport {
            iterations: 5,
            findings: vec![FuzzFinding {
                seed: 42,
                steps: 10,
                violations: vec![],
                certificate_hash: 123,
                trace_fingerprint: 456,
                minimized_seed: Some(3),
            }],
            violation_counts: BTreeMap::new(),
            unique_certificates: 1,
        };

        assert_eq!(report.finding_seeds(), vec![42]);
        assert_eq!(report.minimized_seeds(), vec![3]);
        assert!(report.has_findings());
    }

    #[test]
    fn fuzz_deterministic_same_seed_same_result() {
        let run = |seed: u64| -> usize {
            let report = fuzz_quick(seed, 5, |runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (t, _) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, async { 42 })
                    .expect("t");
                runtime.scheduler.lock().schedule(t, 0);
                runtime.run_until_quiescent();
            });
            report.unique_certificates
        };

        let r1 = run(77);
        let r2 = run(77);
        assert_eq!(r1, r2);
    }

    // =========================================================================
    // Wave 46 – pure data-type trait coverage
    // =========================================================================

    #[test]
    fn fuzz_config_debug_clone_defaults() {
        let cfg = FuzzConfig::new(42, 100);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("FuzzConfig"), "{dbg}");
        assert_eq!(cfg.base_seed, 42);
        assert_eq!(cfg.iterations, 100);
        assert_eq!(cfg.max_steps, 100_000);
        assert_eq!(cfg.worker_count, 1);
        assert!(cfg.minimize);
        assert_eq!(cfg.minimize_attempts, 96);
        let cloned = cfg.clone();
        assert_eq!(cloned.base_seed, cfg.base_seed);
        assert_eq!(cloned.iterations, cfg.iterations);
    }

    #[test]
    fn fuzz_finding_debug_clone() {
        let finding = FuzzFinding {
            seed: 99,
            steps: 500,
            violations: vec![],
            certificate_hash: 12345,
            trace_fingerprint: 67890,
            minimized_seed: Some(7),
        };
        let dbg = format!("{finding:?}");
        assert!(dbg.contains("FuzzFinding"), "{dbg}");
        let cloned = finding;
        assert_eq!(cloned.seed, 99);
        assert_eq!(cloned.steps, 500);
        assert_eq!(cloned.certificate_hash, 12345);
        assert_eq!(cloned.trace_fingerprint, 67890);
        assert_eq!(cloned.minimized_seed, Some(7));
    }

    #[test]
    fn fuzz_report_debug_empty() {
        let report = FuzzReport {
            iterations: 0,
            findings: vec![],
            violation_counts: BTreeMap::new(),
            unique_certificates: 0,
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("FuzzReport"), "{dbg}");
        assert!(!report.has_findings());
        assert!(report.finding_seeds().is_empty());
        assert!(report.minimized_seeds().is_empty());
    }

    #[test]
    fn regression_corpus_is_sorted_and_minimized() {
        let report = FuzzReport {
            iterations: 3,
            findings: vec![
                FuzzFinding {
                    seed: 44,
                    steps: 100,
                    violations: vec![
                        InvariantViolation::QuiescenceViolation,
                        InvariantViolation::QuiescenceViolation,
                    ],
                    certificate_hash: 0xB,
                    trace_fingerprint: 0xBB,
                    minimized_seed: Some(3),
                },
                FuzzFinding {
                    seed: 13,
                    steps: 200,
                    violations: vec![InvariantViolation::Futurelock {
                        task: crate::types::TaskId::new_for_test(1, 0),
                        region: crate::types::RegionId::new_for_test(1, 0),
                        idle_steps: 1,
                        held: Vec::new(),
                    }],
                    certificate_hash: 0xA,
                    trace_fingerprint: 0xAA,
                    minimized_seed: None,
                },
            ],
            violation_counts: BTreeMap::new(),
            unique_certificates: 2,
        };

        let corpus = report.to_regression_corpus(1234);
        assert_eq!(corpus.schema_version, 1);
        assert_eq!(corpus.base_seed, 1234);
        assert_eq!(corpus.iterations, 3);
        assert_eq!(corpus.cases.len(), 2);

        // Sorted by replay_seed then deterministic tie-breakers.
        assert_eq!(corpus.cases[0].seed, 44);
        assert_eq!(corpus.cases[0].replay_seed, 3);
        assert_eq!(
            corpus.cases[0].violation_categories,
            vec!["quiescence_violation"]
        );

        assert_eq!(corpus.cases[1].seed, 13);
        assert_eq!(corpus.cases[1].replay_seed, 13);
        assert_eq!(corpus.cases[1].violation_categories, vec!["futurelock"]);
    }

    #[test]
    fn regression_corpus_replay_seeds_preserve_violation_categories() {
        let config = FuzzConfig::new(0x6C6F_7265_6D71_6505, 4)
            .worker_count(2)
            .max_steps(256)
            .minimize(true);
        let harness = FuzzHarness::new(config.clone());

        let scenario = |runtime: &mut LabRuntime| {
            let root = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..3 {
                let (task_id, _) = runtime
                    .state
                    .create_task(root, Budget::INFINITE, async {})
                    .expect("create scheduled task");
                runtime.scheduler.lock().schedule(task_id, 0);
            }
            let _unscheduled = runtime
                .state
                .create_task(root, Budget::INFINITE, async {})
                .expect("create unscheduled task");
            runtime.run_until_quiescent();
        };

        let report = harness.run(scenario);
        assert!(report.has_findings(), "expected minimized fuzz findings");
        let corpus = report.to_regression_corpus(config.base_seed);
        assert!(
            !corpus.cases.is_empty(),
            "regression corpus must include failing replay seeds"
        );

        for case in &corpus.cases {
            let first_replay = harness.run_single(case.replay_seed, &scenario);
            assert!(
                !first_replay.violations.is_empty(),
                "replay seed {} should still violate an invariant",
                case.replay_seed
            );
            let replay_categories = sorted_violation_categories(&first_replay.violations);
            assert_eq!(
                replay_categories, case.violation_categories,
                "replay seed {} changed violation categories",
                case.replay_seed
            );

            // Deterministic replay seeds must produce stable certificates and traces.
            let second_replay = harness.run_single(case.replay_seed, &scenario);
            assert_eq!(
                first_replay.certificate_hash,
                second_replay.certificate_hash
            );
            assert_eq!(
                first_replay.trace_fingerprint,
                second_replay.trace_fingerprint
            );
        }
    }

    #[test]
    fn minimize_seed_requires_full_violation_category_match() {
        let harness = FuzzHarness::new(FuzzConfig::new(20, 1));
        let scenario = |runtime: &mut LabRuntime| {
            let seed = runtime.config().seed;
            let region = runtime.state.create_root_region(Budget::INFINITE);

            // Always leave one task unscheduled so every failing seed reports task_leak.
            let _leaked = runtime
                .state
                .create_task(region, Budget::INFINITE, async {})
                .expect("create leaked task");

            // Only seeds >= 20 also force-close the region while the leaked
            // task is still live, adding quiescence_violation to the baseline
            // task_leak category.
            if seed >= 20 {
                runtime
                    .state
                    .region(region)
                    .expect("region exists")
                    .set_state(crate::record::region::RegionState::Closed);
            }
        };

        let original = harness.run_single(20, &scenario);
        assert_eq!(
            sorted_violation_categories(&original.violations),
            vec!["quiescence_violation", "task_leak"]
        );

        let smaller = harness.run_single(19, &scenario);
        assert_eq!(
            sorted_violation_categories(&smaller.violations),
            vec!["task_leak"]
        );

        let minimized = harness.minimize_seed(20, &scenario);
        assert_eq!(
            minimized, None,
            "smaller seeds do not preserve the original full violation category set"
        );
    }

    #[test]
    fn fuzz_report_promotes_findings_into_replayable_scenarios() {
        let report = FuzzReport {
            iterations: 1,
            findings: vec![FuzzFinding {
                seed: 0xABCD,
                steps: 10,
                violations: vec![InvariantViolation::TaskLeak { count: 1 }],
                certificate_hash: 0x101,
                trace_fingerprint: 0x202,
                minimized_seed: Some(0x55),
            }],
            violation_counts: BTreeMap::from([("task_leak".to_string(), 1)]),
            unique_certificates: 1,
        };

        let promoted = report.to_promoted_findings("scheduler.surface", "v1");
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].original_seed, 0xABCD);
        assert_eq!(promoted[0].replay_seed, 0x55);
        assert_eq!(promoted[0].trace_fingerprint, 0x202);
        assert_eq!(promoted[0].violation_categories, vec!["task_leak"]);
    }

    #[test]
    fn regression_corpus_promotes_cases_with_campaign_lineage() {
        let corpus = FuzzRegressionCorpus {
            schema_version: 1,
            base_seed: 0xCAFE,
            iterations: 2,
            cases: vec![FuzzRegressionCase {
                seed: 0x10,
                replay_seed: 0x08,
                certificate_hash: 0x111,
                trace_fingerprint: 0x222,
                violation_categories: vec!["task_leak".to_string()],
            }],
        };

        let promoted = corpus.to_promoted_scenarios("scheduler.surface", "v1");
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].campaign_base_seed, Some(0xCAFE));
        assert_eq!(promoted[0].campaign_iteration, Some(0));
        assert_eq!(promoted[0].original_seed, 0x10);
        assert_eq!(promoted[0].replay_seed, 0x08);
        assert_eq!(
            promoted[0].violation_categories,
            vec!["task_leak".to_string()]
        );
    }
}
