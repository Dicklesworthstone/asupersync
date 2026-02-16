//! Deterministic fuzz harness for structured concurrency invariants.
//!
//! Uses seed-driven exploration to systematically fuzz scheduling decisions
//! and verify invariant oracles. When a violation is found, the seed is
//! minimized to produce a minimal reproducer.

use crate::lab::config::LabConfig;
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
            minimize_attempts: 64,
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

                let minimized_seed = if self.config.minimize {
                    self.minimize_seed(seed, &test)
                } else {
                    None
                };

                findings.push(FuzzFinding {
                    seed,
                    steps: result.steps,
                    violations: result.violations,
                    certificate_hash: result.certificate_hash,
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
        let violations = runtime.check_invariants();

        SingleRunResult {
            steps,
            violations,
            certificate_hash,
        }
    }

    /// Attempt to minimize a failing seed.
    ///
    /// Tries nearby seeds (bit-flips and offsets) to find the smallest
    /// seed that still reproduces the same category of violation.
    fn minimize_seed<F>(&self, original_seed: u64, test: &F) -> Option<u64>
    where
        F: Fn(&mut LabRuntime),
    {
        let original_result = self.run_single(original_seed, test);
        if original_result.violations.is_empty() {
            return None;
        }
        let target_category = violation_category(&original_result.violations[0]);

        let mut best_seed = original_seed;

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

            let cat = violation_category(&result.violations[0]);
            if cat == target_category && candidate < best_seed {
                best_seed = candidate;
            }
        }

        if best_seed == original_seed {
            None
        } else {
            Some(best_seed)
        }
    }
}

struct SingleRunResult {
    steps: u64,
    violations: Vec<InvariantViolation>,
    certificate_hash: u64,
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
            runtime.scheduler.lock().unwrap().schedule(t, 0);
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
                let mut sched = runtime.scheduler.lock().unwrap();
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
                runtime.scheduler.lock().unwrap().schedule(t, 0);
                runtime.run_until_quiescent();
            });
            report.unique_certificates
        };

        let r1 = run(77);
        let r2 = run(77);
        assert_eq!(r1, r2);
    }
}
