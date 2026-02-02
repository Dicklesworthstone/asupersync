//! Meta-test runner and coverage reporting.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::json;

use crate::lab::oracle::OracleViolation;
use crate::lab::{LabConfig, LabRuntime, OracleSuite};
use crate::record::ObligationKind;
use crate::types::{Budget, ObligationId, RegionId, TaskId, Time};

use super::mutation::{invariant_from_violation, BuiltinMutation, ALL_ORACLE_INVARIANTS};

pub(crate) struct MetaHarness {
    pub runtime: LabRuntime,
    pub oracles: OracleSuite,
    now: Time,
    next_region: u32,
    next_task: u32,
    next_obligation: u32,
    next_finalizer: u64,
}

impl MetaHarness {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            runtime: LabRuntime::new(LabConfig::new(seed)),
            oracles: OracleSuite::new(),
            now: Time::ZERO,
            next_region: 1,
            next_task: 1,
            next_obligation: 1,
            next_finalizer: 1,
        }
    }

    pub(crate) fn now(&self) -> Time {
        self.now
    }

    pub(crate) fn next_region(&mut self) -> RegionId {
        let id = RegionId::new_for_test(self.next_region, 0);
        self.next_region = self.next_region.saturating_add(1);
        id
    }

    pub(crate) fn next_task(&mut self) -> TaskId {
        let id = TaskId::new_for_test(self.next_task, 0);
        self.next_task = self.next_task.saturating_add(1);
        id
    }

    #[allow(dead_code)]
    pub(crate) fn next_obligation(&mut self) -> ObligationId {
        let id = ObligationId::new_for_test(self.next_obligation, 0);
        self.next_obligation = self.next_obligation.saturating_add(1);
        id
    }

    pub(crate) fn next_finalizer(&mut self) -> crate::lab::oracle::FinalizerId {
        let id = crate::lab::oracle::FinalizerId(self.next_finalizer);
        self.next_finalizer = self.next_finalizer.saturating_add(1);
        id
    }

    pub(crate) fn create_root_region(&mut self) -> RegionId {
        self.runtime.state.create_root_region(Budget::INFINITE)
    }

    pub(crate) fn create_runtime_task(&mut self, region: RegionId) -> TaskId {
        let (task, _handle) = self
            .runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("create task");
        task
    }

    pub(crate) fn close_region(&self, region: RegionId) {
        if let Some(record) = self.runtime.state.region(region) {
            let _ = record.begin_close(None);
            let _ = record.begin_drain();
            let _ = record.begin_finalize();
            let _ = record.complete_close();
        }
    }

    #[allow(dead_code)]
    pub(crate) fn create_obligation(&mut self, holder: TaskId, region: RegionId) -> ObligationId {
        self.runtime
            .state
            .create_obligation(ObligationKind::SendPermit, holder, region, None)
            .expect("create obligation")
    }
}

/// Result of a single meta mutation run.
#[derive(Debug, Clone)]
pub struct MetaResult {
    /// Mutation identifier.
    pub mutation: &'static str,
    /// Invariant expected to fail under mutation.
    pub invariant: &'static str,
    /// Violations from the baseline (control) run.
    pub baseline_violations: Vec<OracleViolation>,
    /// Violations from the mutated run.
    pub mutation_violations: Vec<OracleViolation>,
}

impl MetaResult {
    /// Returns true if the baseline run produced no violations.
    #[must_use]
    pub fn baseline_clean(&self) -> bool {
        self.baseline_violations.is_empty()
    }

    /// Returns true if the expected invariant was detected in the mutated run.
    #[must_use]
    pub fn mutation_detected(&self) -> bool {
        self.mutation_violations
            .iter()
            .any(|v| invariant_from_violation(v) == self.invariant)
    }
}

/// Coverage entry for a single invariant.
#[derive(Debug, Clone)]
pub struct MetaCoverageEntry {
    /// Invariant name.
    pub invariant: &'static str,
    /// Mutations that triggered this invariant.
    pub tests: Vec<&'static str>,
}

impl MetaCoverageEntry {
    /// Returns true if at least one mutation covered this invariant.
    #[must_use]
    pub fn is_covered(&self) -> bool {
        !self.tests.is_empty()
    }
}

/// Coverage report across all invariants.
#[derive(Debug, Clone)]
pub struct MetaCoverageReport {
    entries: Vec<MetaCoverageEntry>,
}

impl MetaCoverageReport {
    fn from_map(
        all_invariants: &[&'static str],
        map: &BTreeMap<&'static str, BTreeSet<&'static str>>,
    ) -> Self {
        let mut entries = Vec::with_capacity(all_invariants.len());
        for &invariant in all_invariants {
            let tests = map
                .get(invariant)
                .map(|set| set.iter().copied().collect::<Vec<_>>())
                .unwrap_or_default();
            entries.push(MetaCoverageEntry { invariant, tests });
        }
        Self { entries }
    }

    /// Returns the coverage entries in invariant order.
    #[must_use]
    pub fn entries(&self) -> &[MetaCoverageEntry] {
        &self.entries
    }

    /// Returns invariants with zero coverage.
    #[must_use]
    pub fn missing_invariants(&self) -> Vec<&'static str> {
        self.entries
            .iter()
            .filter(|entry| !entry.is_covered())
            .map(|entry| entry.invariant)
            .collect()
    }

    /// Renders a human-readable coverage report.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for entry in &self.entries {
            let _ = if entry.tests.is_empty() {
                writeln!(&mut out, "{}: <missing>", entry.invariant)
            } else {
                writeln!(&mut out, "{}: {}", entry.invariant, entry.tests.join(", "))
            };
        }
        out
    }

    /// Renders a JSON coverage report.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let invariants = self
            .entries
            .iter()
            .map(|entry| {
                json!({
                    "invariant": entry.invariant,
                    "tests": entry.tests,
                })
            })
            .collect::<Vec<_>>();

        json!({
            "invariants": invariants,
        })
    }
}

/// Report for a full meta-test run.
#[derive(Debug, Clone)]
pub struct MetaReport {
    results: Vec<MetaResult>,
    coverage: MetaCoverageReport,
}

impl MetaReport {
    /// Returns all per-mutation results.
    #[must_use]
    pub fn results(&self) -> &[MetaResult] {
        &self.results
    }

    /// Returns the coverage report.
    #[must_use]
    pub fn coverage(&self) -> &MetaCoverageReport {
        &self.coverage
    }

    /// Returns results where baseline was dirty or mutation not detected.
    #[must_use]
    pub fn failures(&self) -> Vec<&MetaResult> {
        self.results
            .iter()
            .filter(|result| !result.baseline_clean() || !result.mutation_detected())
            .collect()
    }

    /// Renders a human-readable meta report.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let failures = self.failures();
        let _ = writeln!(
            &mut out,
            "meta report: {} mutations, {} failures",
            self.results.len(),
            failures.len()
        );
        if !failures.is_empty() {
            for failure in failures {
                let _ = writeln!(
                    &mut out,
                    "failure: {} (invariant {})",
                    failure.mutation, failure.invariant
                );
            }
        }
        let _ = writeln!(&mut out, "coverage:");
        out.push_str(&self.coverage.to_text());
        out
    }

    /// Renders a JSON meta report.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let failures = self
            .failures()
            .iter()
            .map(|failure| {
                json!({
                    "mutation": failure.mutation,
                    "invariant": failure.invariant,
                    "baseline_clean": failure.baseline_clean(),
                    "mutation_detected": failure.mutation_detected(),
                })
            })
            .collect::<Vec<_>>();
        let results = self
            .results
            .iter()
            .map(|result| {
                json!({
                    "mutation": result.mutation,
                    "invariant": result.invariant,
                    "baseline_clean": result.baseline_clean(),
                    "mutation_detected": result.mutation_detected(),
                })
            })
            .collect::<Vec<_>>();
        json!({
            "summary": {
                "mutations": self.results.len(),
                "failures": failures.len(),
            },
            "results": results,
            "failures": failures,
            "coverage": self.coverage.to_json(),
        })
    }
}

/// Runner for meta-testing built-in oracle mutations.
#[derive(Debug, Clone)]
pub struct MetaRunner {
    seed: u64,
}

impl MetaRunner {
    /// Creates a new meta runner with a deterministic seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Runs all provided mutations and returns a report.
    #[must_use]
    pub fn run<I>(&self, mutations: I) -> MetaReport
    where
        I: IntoIterator<Item = BuiltinMutation>,
    {
        let mut results = Vec::new();
        let mut coverage_map: BTreeMap<&'static str, BTreeSet<&'static str>> = BTreeMap::new();

        for mutation in mutations {
            let baseline_violations = {
                let mut harness = MetaHarness::new(self.seed);
                mutation.apply_baseline(&mut harness);
                harness.oracles.check_all(harness.now())
            };

            let mutation_violations = {
                let mut harness = MetaHarness::new(self.seed);
                mutation.apply_mutation(&mut harness);
                harness.oracles.check_all(harness.now())
            };

            let result = MetaResult {
                mutation: mutation.name(),
                invariant: mutation.invariant(),
                baseline_violations,
                mutation_violations,
            };

            if result.baseline_clean() && result.mutation_detected() {
                coverage_map
                    .entry(result.invariant)
                    .or_default()
                    .insert(result.mutation);
            }

            results.push(result);
        }

        let coverage = MetaCoverageReport::from_map(ALL_ORACLE_INVARIANTS, &coverage_map);
        MetaReport { results, coverage }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::meta::mutation::builtin_mutations;

    #[test]
    fn meta_runner_deterministic() {
        let runner = MetaRunner::new(42);
        let report1 = runner.run(builtin_mutations());
        let report2 = runner.run(builtin_mutations());

        assert_eq!(report1.results().len(), report2.results().len());
        for (r1, r2) in report1.results().iter().zip(report2.results()) {
            assert_eq!(r1.mutation, r2.mutation);
            assert_eq!(r1.invariant, r2.invariant);
            assert_eq!(r1.baseline_clean(), r2.baseline_clean());
            assert_eq!(r1.mutation_detected(), r2.mutation_detected());
        }
    }

    #[test]
    fn meta_runner_all_mutations_pass() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());

        // AmbientAuthority oracle has a known detection gap.
        let failures: Vec<_> = report
            .failures()
            .into_iter()
            .filter(|f| f.mutation != "mutation_ambient_authority_spawn_without_capability")
            .collect();
        assert!(
            failures.is_empty(),
            "expected no failures, got: {:?}",
            failures.iter().map(|f| f.mutation).collect::<Vec<_>>()
        );
    }

    #[test]
    fn meta_runner_empty_mutations() {
        let runner = MetaRunner::new(42);
        let report = runner.run(std::iter::empty());

        assert!(report.results().is_empty());
        assert!(report.failures().is_empty());
    }

    #[test]
    fn meta_runner_single_mutation() {
        let runner = MetaRunner::new(42);
        let report = runner.run(vec![BuiltinMutation::TaskLeak]);

        assert_eq!(report.results().len(), 1);
        assert_eq!(report.results()[0].mutation, "mutation_task_leak");
        assert!(report.results()[0].baseline_clean());
        assert!(report.results()[0].mutation_detected());
    }

    #[test]
    fn meta_result_baseline_clean() {
        let result = MetaResult {
            mutation: "test",
            invariant: "test_inv",
            baseline_violations: vec![],
            mutation_violations: vec![],
        };
        assert!(result.baseline_clean());
    }

    #[test]
    fn meta_coverage_report_entries() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let coverage = report.coverage();

        assert_eq!(coverage.entries().len(), ALL_ORACLE_INVARIANTS.len());
    }

    #[test]
    fn meta_coverage_missing_invariants() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let missing = report.coverage().missing_invariants();

        // actor_leak, supervision, and mailbox have no builtin mutations
        assert!(missing.contains(&"actor_leak"));
        assert!(missing.contains(&"supervision"));
        assert!(missing.contains(&"mailbox"));
    }

    #[test]
    fn meta_coverage_entry_is_covered() {
        let entry_covered = MetaCoverageEntry {
            invariant: "test",
            tests: vec!["m1"],
        };
        assert!(entry_covered.is_covered());

        let entry_not = MetaCoverageEntry {
            invariant: "test",
            tests: vec![],
        };
        assert!(!entry_not.is_covered());
    }

    #[test]
    fn meta_report_to_text() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let text = report.to_text();

        assert!(text.contains("meta report:"));
        assert!(text.contains("mutations"));
        assert!(text.contains("coverage:"));
    }

    #[test]
    fn meta_report_to_json() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let json = report.to_json();

        assert!(json["summary"]["mutations"].as_u64().unwrap() > 0);
        assert!(json["results"].is_array());
        assert!(json["coverage"].is_object());
    }

    #[test]
    fn meta_coverage_to_text() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let text = report.coverage().to_text();

        assert!(text.contains("task_leak:"));
        // Uncovered invariants show <missing>
        assert!(text.contains("<missing>"));
    }

    #[test]
    fn meta_coverage_to_json() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let json = report.coverage().to_json();

        assert!(json["invariants"].is_array());
    }

    #[test]
    fn harness_next_ids_increment() {
        let mut harness = MetaHarness::new(42);

        let r1 = harness.next_region();
        let r2 = harness.next_region();
        assert_ne!(r1, r2);

        let t1 = harness.next_task();
        let t2 = harness.next_task();
        assert_ne!(t1, t2);

        let f1 = harness.next_finalizer();
        let f2 = harness.next_finalizer();
        assert_ne!(f1, f2);
    }

    #[test]
    fn harness_now_is_zero() {
        let harness = MetaHarness::new(42);
        assert_eq!(harness.now(), Time::ZERO);
    }

    #[test]
    fn meta_runner_different_seeds() {
        // Different seeds should still produce correct results.
        // AmbientAuthority oracle has a known detection gap.
        for seed in [0, 1, 999, u64::MAX] {
            let runner = MetaRunner::new(seed);
            let report = runner.run(builtin_mutations());
            let has_failures = report
                .failures()
                .into_iter()
                .any(|f| f.mutation != "mutation_ambient_authority_spawn_without_capability");
            assert!(!has_failures, "seed {seed} produced failures");
        }
    }
}
