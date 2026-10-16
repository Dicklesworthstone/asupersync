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
    /// Deterministic entropy seed reused across iterations.
    ///
    /// This is intentionally decoupled from the per-iteration schedule seed so
    /// a fuzz campaign can vary scheduler decisions without also mutating any
    /// entropy-driven behavior inside the lab runtime.
    pub entropy_seed: u64,
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
            entropy_seed: base_seed,
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

    /// Set the deterministic entropy seed reused across iterations.
    #[must_use]
    pub fn entropy_seed(mut self, seed: u64) -> Self {
        self.entropy_seed = seed;
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
    /// Deterministic entropy seed used for the failing replay run.
    pub entropy_seed: u64,
    /// Steps taken by the replay seed that this finding describes.
    ///
    /// When minimization succeeds this corresponds to the minimized replay
    /// seed, not the original campaign seed.
    pub steps: u64,
    /// The violation details for the replay seed that this finding describes.
    ///
    /// When minimization succeeds these violations come from the minimized
    /// replay seed so they stay consistent with the stored certificate hash
    /// and trace fingerprint.
    pub violations: Vec<InvariantViolation>,
    /// Certificate hash for the replay seed's schedule.
    pub certificate_hash: u64,
    /// Canonical normalized trace fingerprint for the replay seed's failing run.
    pub trace_fingerprint: u64,
    /// Minimized seed (if minimization succeeded).
    pub minimized_seed: Option<u64>,
}

/// Results of a fuzz campaign.
#[derive(Debug)]
pub struct FuzzReport {
    /// Total iterations run.
    pub iterations: usize,
    /// Deterministic entropy seed reused across the campaign.
    pub entropy_seed: u64,
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
    /// Deterministic entropy seed required to replay this case faithfully.
    pub entropy_seed: u64,
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
    /// Deterministic entropy seed reused across this fuzz campaign.
    pub entropy_seed: u64,
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
                    entropy_seed: finding.entropy_seed,
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
            entropy_seed: self.entropy_seed,
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

                let (minimized_seed, steps, violations, certificate_hash, trace_fingerprint) =
                    match minimized {
                        Some((min_seed, ref min_res)) => (
                            Some(min_seed),
                            min_res.steps,
                            min_res.violations.clone(),
                            min_res.certificate_hash,
                            min_res.trace_fingerprint,
                        ),
                        None => (
                            None,
                            result.steps,
                            result.violations.clone(),
                            result.certificate_hash,
                            result.trace_fingerprint,
                        ),
                    };

                findings.push(FuzzFinding {
                    seed,
                    entropy_seed: self.config.entropy_seed,
                    steps,
                    violations,
                    certificate_hash,
                    trace_fingerprint,
                    minimized_seed,
                });
            }
        }

        FuzzReport {
            iterations: self.config.iterations,
            entropy_seed: self.config.entropy_seed,
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
        lab_config = lab_config.entropy_seed(self.config.entropy_seed);
        lab_config = lab_config.max_steps(self.config.max_steps);

        let mut runtime = LabRuntime::new(lab_config);

        // br-asupersync-ipejce: catch panics from the test closure
        // and convert them into a recorded TestPanic finding so the
        // campaign keeps searching. Without this, the first panic
        // (the most interesting outcome of any fuzz campaign)
        // aborts the whole search budget and attributes the crash
        // to the harness rather than the asupersync invariant
        // violation it actually represents.
        let panic_message = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            test(&mut runtime);
        }))
        .err()
        .map(|payload| {
            // Extract the canonical &str / String panic payload.
            if let Some(s) = payload.downcast_ref::<&'static str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<unknown panic payload>".to_string()
            }
        });

        let steps = runtime.steps();
        let certificate_hash = runtime.certificate().hash();
        let trace_events = runtime.trace().snapshot();
        let normalized = normalize_for_replay(&trace_events);
        let trace_fingerprint =
            crate::trace::canonicalize::trace_fingerprint(&normalized.normalized);
        let mut violations = runtime.check_invariants();
        if let Some(message) = panic_message {
            violations.push(InvariantViolation::TestPanic { message });
        }

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
        InvariantViolation::CancellationProtocol { .. } => "cancellation_protocol".to_string(),
        InvariantViolation::TestPanic { .. } => "test_panic".to_string(),
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
#[path = "fuzz_inline_tests.rs"]
mod tests;
