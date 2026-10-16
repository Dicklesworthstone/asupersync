//! Meta-test runner and coverage reporting.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::json;

use crate::lab::oracle::OracleViolation;
use crate::lab::{LabConfig, LabRuntime, OracleSuite};
use crate::record::ObligationKind;
use crate::types::{Budget, ObligationId, RegionId, TaskId, Time};
use crate::util::ArenaIndex;

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
        let id = RegionId::from_arena(ArenaIndex::new(self.next_region, 0));
        self.next_region = self.next_region.saturating_add(1);
        id
    }

    pub(crate) fn next_task(&mut self) -> TaskId {
        let id = TaskId::from_arena(ArenaIndex::new(self.next_task, 0));
        self.next_task = self.next_task.saturating_add(1);
        id
    }

    #[allow(dead_code)]
    pub(crate) fn next_obligation(&mut self) -> ObligationId {
        let id = ObligationId::from_arena(ArenaIndex::new(self.next_obligation, 0));
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
#[path = "runner_inline_tests.rs"]
mod tests;
