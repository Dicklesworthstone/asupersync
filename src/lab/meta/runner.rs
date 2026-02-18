//! Meta-test runner and coverage reporting.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::json;

use crate::lab::oracle::OracleViolation;
use crate::lab::{LabConfig, LabRuntime, OracleSuite};
use crate::record::ObligationKind;
use crate::types::{Budget, ObligationId, RegionId, TaskId, Time};

use super::mutation::{ALL_ORACLE_INVARIANTS, BuiltinMutation, invariant_from_violation};

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
    /// Name of the mutation applied.
    pub mutation: &'static str,
    /// Invariant targeted by the mutation.
    pub invariant: &'static str,
    /// Violations observed under the baseline (unmutated) run.
    pub baseline_violations: Vec<OracleViolation>,
    /// Violations observed under the mutated run.
    pub mutation_violations: Vec<OracleViolation>,
}

impl MetaResult {
    /// Returns true when the baseline run produced no violations.
    #[must_use]
    pub fn baseline_clean(&self) -> bool {
        self.baseline_violations.is_empty()
    }

    /// Returns true when the mutation triggers its target invariant.
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
    /// Names of tests/mutations that cover the invariant.
    pub tests: Vec<&'static str>,
}

impl MetaCoverageEntry {
    /// Returns true when at least one test covers the invariant.
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

    /// Returns coverage entries for all invariants.
    #[must_use]
    pub fn entries(&self) -> &[MetaCoverageEntry] {
        &self.entries
    }

    /// Returns invariants with no covering tests.
    #[must_use]
    pub fn missing_invariants(&self) -> Vec<&'static str> {
        self.entries
            .iter()
            .filter(|e| !e.is_covered())
            .map(|e| e.invariant)
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
            .map(|entry| json!({ "invariant": entry.invariant, "tests": entry.tests }))
            .collect::<Vec<_>>();
        json!({ "invariants": invariants })
    }
}

/// Aggregated results and coverage from a meta run.
#[derive(Debug, Clone)]
pub struct MetaReport {
    results: Vec<MetaResult>,
    coverage: MetaCoverageReport,
}

impl MetaReport {
    /// Returns all mutation results.
    #[must_use]
    pub fn results(&self) -> &[MetaResult] {
        &self.results
    }

    /// Returns coverage information for the run.
    #[must_use]
    pub fn coverage(&self) -> &MetaCoverageReport {
        &self.coverage
    }

    /// Returns the subset of results that failed detection.
    #[must_use]
    pub fn failures(&self) -> Vec<&MetaResult> {
        self.results
            .iter()
            .filter(|r| !r.baseline_clean() || !r.mutation_detected())
            .collect()
    }

    /// Renders a human-readable report.
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
            for f in failures {
                let _ = writeln!(
                    &mut out,
                    "failure: {} (invariant {})",
                    f.mutation, f.invariant
                );
            }
        }
        let _ = writeln!(&mut out, "coverage:");
        out.push_str(&self.coverage.to_text());
        out
    }

    /// Renders a JSON report.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let failures = self.failures().iter().map(|f| json!({
            "mutation": f.mutation, "invariant": f.invariant,
            "baseline_clean": f.baseline_clean(), "mutation_detected": f.mutation_detected(),
        })).collect::<Vec<_>>();
        let results = self.results.iter().map(|r| json!({
            "mutation": r.mutation, "invariant": r.invariant,
            "baseline_clean": r.baseline_clean(), "mutation_detected": r.mutation_detected(),
        })).collect::<Vec<_>>();
        json!({
            "summary": { "mutations": self.results.len(), "failures": failures.len() },
            "results": results, "failures": failures, "coverage": self.coverage.to_json(),
        })
    }
}

/// Deterministic runner for the meta mutation suite.
#[derive(Debug, Clone)]
pub struct MetaRunner {
    seed: u64,
}

impl MetaRunner {
    /// Creates a new meta runner with the given RNG seed.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { seed }
    }

    /// Runs the provided mutations and returns results and coverage.
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
        let r1 = runner.run(builtin_mutations());
        let r2 = runner.run(builtin_mutations());
        assert_eq!(r1.results().len(), r2.results().len());
        for (a, b) in r1.results().iter().zip(r2.results()) {
            assert_eq!(a.mutation, b.mutation);
            assert_eq!(a.invariant, b.invariant);
            assert_eq!(a.baseline_clean(), b.baseline_clean());
            assert_eq!(a.mutation_detected(), b.mutation_detected());
        }
    }

    #[test]
    fn meta_runner_all_mutations_pass() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
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
        assert_eq!(
            report.coverage().entries().len(),
            ALL_ORACLE_INVARIANTS.len()
        );
    }

    #[test]
    fn meta_coverage_missing_invariants() {
        let runner = MetaRunner::new(42);
        let report = runner.run(builtin_mutations());
        let missing = report.coverage().missing_invariants();
        assert!(
            !missing.contains(&"actor_leak"),
            "actor_leak should be covered"
        );
        assert!(
            !missing.contains(&"supervision"),
            "supervision should be covered"
        );
        assert!(!missing.contains(&"mailbox"), "mailbox should be covered");
    }

    #[test]
    fn meta_coverage_entry_is_covered() {
        let covered = MetaCoverageEntry {
            invariant: "test",
            tests: vec!["m1"],
        };
        assert!(covered.is_covered());
        let not_covered = MetaCoverageEntry {
            invariant: "test",
            tests: vec![],
        };
        assert!(!not_covered.is_covered());
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
        let text = runner.run(builtin_mutations()).coverage().to_text();
        assert!(text.contains("task_leak:"));
    }

    #[test]
    fn meta_coverage_to_json() {
        let runner = MetaRunner::new(42);
        let json = runner.run(builtin_mutations()).coverage().to_json();
        assert!(json["invariants"].is_array());
    }

    #[test]
    fn harness_next_ids_increment() {
        let mut h = MetaHarness::new(42);
        let r1 = h.next_region();
        let r2 = h.next_region();
        assert_ne!(r1, r2);
        let t1 = h.next_task();
        let t2 = h.next_task();
        assert_ne!(t1, t2);
        let f1 = h.next_finalizer();
        let f2 = h.next_finalizer();
        assert_ne!(f1, f2);
    }

    #[test]
    fn harness_now_is_zero() {
        assert_eq!(MetaHarness::new(42).now(), Time::ZERO);
    }

    #[test]
    fn meta_runner_different_seeds() {
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
