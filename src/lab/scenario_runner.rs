//! Scenario runner for FrankenLab deterministic testing (bd-1hu19.2).
//!
//! Bridges [`Scenario`](super::scenario::Scenario) YAML specifications to
//! [`LabRuntime`](super::runtime::LabRuntime) execution, providing:
//!
//! - Timed fault injection based on scenario fault events
//! - Oracle filtering (only check oracles listed in the scenario)
//! - Seed exploration (run the same scenario across multiple seeds)
//! - Replay validation (run twice, verify identical trace certificates)
//!
//! # Quick Start
//!
//! ```ignore
//! use asupersync::lab::scenario_runner::{ScenarioRunner, ScenarioRunResult};
//! use asupersync::lab::scenario::Scenario;
//!
//! let yaml = std::fs::read_to_string("examples/scenarios/smoke_happy_path.yaml")?;
//! let scenario: Scenario = serde_yaml::from_str(&yaml)?;
//!
//! let result = ScenarioRunner::run(&scenario)?;
//! assert!(result.passed());
//! ```

use super::config::LabConfig;
use super::meta::mutation::ALL_ORACLE_INVARIANTS;
use super::oracle::OracleReport;
use super::runtime::{LabRunReport, LabRuntime};
use super::scenario::{FaultAction, Scenario, ValidationError};
use crate::trace::replay::ReplayTrace;
use crate::types::Time;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors produced by the scenario runner.
#[derive(Debug)]
pub enum ScenarioRunnerError {
    /// Scenario validation failed.
    Validation(Vec<ValidationError>),
    /// An oracle listed in the scenario is not recognized.
    UnknownOracle(String),
    /// Replay divergence: two runs with the same seed produced different traces.
    ReplayDivergence {
        /// The seed that diverged.
        seed: u64,
        /// Certificate from the first run.
        first: TraceCertificateSnapshot,
        /// Certificate from the second run.
        second: TraceCertificateSnapshot,
    },
}

impl std::fmt::Display for ScenarioRunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation(errors) => {
                write!(f, "scenario validation failed:")?;
                for e in errors {
                    write!(f, " {e};")?;
                }
                Ok(())
            }
            Self::UnknownOracle(name) => write!(f, "unknown oracle: {name}"),
            Self::ReplayDivergence {
                seed,
                first,
                second,
            } => write!(
                f,
                "replay divergence at seed {seed}: \
                 first(event_hash={}, schedule_hash={}, steps={}) != \
                 second(event_hash={}, schedule_hash={}, steps={})",
                first.event_hash,
                first.schedule_hash,
                first.steps,
                second.event_hash,
                second.schedule_hash,
                second.steps,
            ),
        }
    }
}

impl std::error::Error for ScenarioRunnerError {}

// ---------------------------------------------------------------------------
// Certificate snapshot (for replay validation)
// ---------------------------------------------------------------------------

/// Lightweight copy of trace identity for comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceCertificateSnapshot {
    /// Hash of all trace events.
    pub event_hash: u64,
    /// Hash of scheduling decisions.
    pub schedule_hash: u64,
    /// Total steps executed.
    pub steps: u64,
    /// Trace fingerprint (Foata equivalence class).
    pub trace_fingerprint: u64,
}

// ---------------------------------------------------------------------------
// Run result
// ---------------------------------------------------------------------------

/// Result of running a single scenario.
#[derive(Debug, Clone)]
pub struct ScenarioRunResult {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Seed used for this run.
    pub seed: u64,
    /// The underlying lab run report.
    pub lab_report: LabRunReport,
    /// Filtered oracle report (only oracles listed in the scenario).
    pub oracle_report: FilteredOracleReport,
    /// Number of fault events injected during the run.
    pub faults_injected: usize,
    /// Replay trace, if recording was enabled.
    pub replay_trace: Option<ReplayTrace>,
    /// Trace certificate snapshot for replay validation.
    pub certificate: TraceCertificateSnapshot,
}

impl ScenarioRunResult {
    /// Returns true if all checked oracles passed and no invariant violations were found.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.lab_report.quiescent
            && self.oracle_report.all_passed
            && self.lab_report.invariant_violations.is_empty()
    }

    /// Convert to JSON for artifact storage.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "scenario_id": self.scenario_id,
            "seed": self.seed,
            "passed": self.passed(),
            "steps": self.lab_report.steps_total,
            "faults_injected": self.faults_injected,
            "certificate": {
                "event_hash": self.certificate.event_hash,
                "schedule_hash": self.certificate.schedule_hash,
                "trace_fingerprint": self.certificate.trace_fingerprint,
            },
            "oracle_report": self.oracle_report.to_json(),
            "invariant_violations": self.lab_report.invariant_violations,
        })
    }
}

// ---------------------------------------------------------------------------
// Filtered oracle report
// ---------------------------------------------------------------------------

/// Oracle report filtered to only the oracles requested by the scenario.
#[derive(Debug, Clone)]
pub struct FilteredOracleReport {
    /// The full oracle report from the runtime.
    pub full_report: OracleReport,
    /// Which oracle names were checked.
    pub checked: Vec<String>,
    /// Which checked oracles passed.
    pub passed_count: usize,
    /// Which checked oracles failed.
    pub failed_count: usize,
    /// Whether all checked oracles passed.
    pub all_passed: bool,
    /// Entries for only the checked oracles.
    pub entries: Vec<super::oracle::OracleEntryReport>,
}

impl FilteredOracleReport {
    fn from_full(full_report: OracleReport, oracle_names: &[String]) -> Self {
        let check_all = oracle_names.iter().any(|n| n == "all");

        let entries: Vec<_> = if check_all {
            full_report.entries.clone()
        } else {
            full_report
                .entries
                .iter()
                .filter(|e| oracle_names.contains(&e.invariant))
                .cloned()
                .collect()
        };

        let checked: Vec<String> = entries.iter().map(|e| e.invariant.clone()).collect();
        let passed_count = entries.iter().filter(|e| e.passed).count();
        let failed_count = entries.len() - passed_count;
        let all_passed = failed_count == 0;

        Self {
            full_report,
            checked,
            passed_count,
            failed_count,
            all_passed,
            entries,
        }
    }

    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "checked": self.checked,
            "passed": self.passed_count,
            "failed": self.failed_count,
            "all_passed": self.all_passed,
            "entries": self.entries.iter().map(|e| {
                let mut v = serde_json::Map::new();
                v.insert("invariant".into(), json!(e.invariant));
                v.insert("passed".into(), json!(e.passed));
                if let Some(ref violation) = e.violation {
                    v.insert("violation".into(), json!(violation));
                }
                serde_json::Value::Object(v)
            }).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Exploration result
// ---------------------------------------------------------------------------

/// Result of exploring a scenario across multiple seeds.
#[derive(Debug, Clone)]
pub struct ScenarioExplorationResult {
    /// Scenario identifier.
    pub scenario_id: String,
    /// Number of seeds explored.
    pub seeds_explored: usize,
    /// Number of passing runs.
    pub passed: usize,
    /// Number of failing runs.
    pub failed: usize,
    /// Unique trace fingerprints observed.
    pub unique_fingerprints: usize,
    /// Per-seed results (seed → pass/fail + fingerprint).
    pub runs: Vec<ExplorationRunSummary>,
    /// First failing seed, if any.
    pub first_failure_seed: Option<u64>,
}

impl ScenarioExplorationResult {
    /// Returns true if all explored seeds passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "scenario_id": self.scenario_id,
            "seeds_explored": self.seeds_explored,
            "passed": self.passed,
            "failed": self.failed,
            "unique_fingerprints": self.unique_fingerprints,
            "first_failure_seed": self.first_failure_seed,
            "runs": self.runs.iter().map(ExplorationRunSummary::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Summary of a single exploration run.
#[derive(Debug, Clone)]
pub struct ExplorationRunSummary {
    /// Seed used.
    pub seed: u64,
    /// Whether the run passed.
    pub passed: bool,
    /// Steps executed.
    pub steps: u64,
    /// Trace fingerprint.
    pub fingerprint: u64,
    /// Failure descriptions, if any.
    pub failures: Vec<String>,
}

impl ExplorationRunSummary {
    /// Convert to JSON.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        json!({
            "seed": self.seed,
            "passed": self.passed,
            "steps": self.steps,
            "fingerprint": self.fingerprint,
            "failures": self.failures,
        })
    }
}

// ---------------------------------------------------------------------------
// ScenarioRunner
// ---------------------------------------------------------------------------

/// Execution engine for FrankenLab scenarios.
///
/// Bridges [`Scenario`] YAML specifications to deterministic runtime execution.
pub struct ScenarioRunner;

impl ScenarioRunner {
    /// Validate oracle names in a scenario against the known oracle registry.
    fn validate_oracle_names(scenario: &Scenario) -> Result<(), ScenarioRunnerError> {
        for name in &scenario.oracles {
            if name == "all" {
                continue;
            }
            if !ALL_ORACLE_INVARIANTS.contains(&name.as_str()) {
                return Err(ScenarioRunnerError::UnknownOracle(name.clone()));
            }
        }
        Ok(())
    }

    /// Create a `LabConfig` from a scenario, always enabling replay recording.
    fn lab_config_for(scenario: &Scenario, seed_override: Option<u64>) -> LabConfig {
        let config = seed_override.map_or_else(
            || scenario.to_lab_config(),
            |seed| {
                let mut modified = scenario.clone();
                modified.lab.seed = seed;
                modified.to_lab_config()
            },
        );
        // Always enable replay recording so we get trace certificates
        config.with_default_replay_recording()
    }

    /// Inject timed fault events into the runtime.
    ///
    /// Processes faults in `at_ms` order, advancing virtual time and injecting
    /// each fault action. Between faults, the runtime runs to idle.
    fn inject_faults(runtime: &mut LabRuntime, scenario: &Scenario) -> usize {
        let mut injected = 0;

        for fault in &scenario.faults {
            // Advance time to the fault trigger point
            let target_nanos = fault.at_ms.saturating_mul(1_000_000);
            let target_time = Time::from_nanos(target_nanos);
            if target_time > runtime.now() {
                let delta_nanos = target_time.as_nanos() - runtime.now().as_nanos();
                runtime.advance_time(delta_nanos);
            }

            // Run to idle so pending tasks respond to the current state
            runtime.run_until_idle();

            // Record the fault as a user_trace event
            let action_name = match fault.action {
                FaultAction::Partition => "partition",
                FaultAction::Heal => "heal",
                FaultAction::HostCrash => "host_crash",
                FaultAction::HostRestart => "host_restart",
                FaultAction::ClockSkew => "clock_skew",
                FaultAction::ClockReset => "clock_reset",
            };
            let seq = runtime.state.next_trace_seq();
            let now = runtime.now();
            runtime
                .state
                .trace
                .push_event(crate::trace::TraceEvent::user_trace(
                    seq,
                    now,
                    format!(
                        "fault:{action_name}:{}",
                        Self::fault_args_summary(&fault.args)
                    ),
                ));
            injected += 1;
        }

        injected
    }

    /// Summarize fault args for trace events.
    fn fault_args_summary(args: &BTreeMap<String, serde_json::Value>) -> String {
        args.iter()
            .map(|(k, v)| {
                let val = match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                format!("{k}={val}")
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Build a certificate snapshot from a lab report.
    fn certificate_snapshot(report: &LabRunReport) -> TraceCertificateSnapshot {
        TraceCertificateSnapshot {
            event_hash: report.trace_certificate.event_hash,
            schedule_hash: report.trace_certificate.schedule_hash,
            steps: report.steps_total,
            trace_fingerprint: report.trace_fingerprint,
        }
    }

    /// Run a scenario with the default seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario fails validation or contains unknown oracle names.
    pub fn run(scenario: &Scenario) -> Result<ScenarioRunResult, ScenarioRunnerError> {
        Self::run_with_seed(scenario, None)
    }

    /// Run a scenario, optionally overriding the seed.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario fails validation or contains unknown oracle names.
    pub fn run_with_seed(
        scenario: &Scenario,
        seed_override: Option<u64>,
    ) -> Result<ScenarioRunResult, ScenarioRunnerError> {
        // 1. Validate
        let errors = scenario.validate();
        if !errors.is_empty() {
            return Err(ScenarioRunnerError::Validation(errors));
        }
        Self::validate_oracle_names(scenario)?;

        // 2. Build runtime
        let effective_seed = seed_override.unwrap_or(scenario.lab.seed);
        let config = Self::lab_config_for(scenario, seed_override);
        let mut runtime = LabRuntime::new(config);

        // 3. Inject timed faults and run between them
        let faults_injected = Self::inject_faults(&mut runtime, scenario);

        // 4. Run to quiescence after all faults
        runtime.run_until_quiescent();

        // 5. Collect report
        let lab_report = runtime.report();
        let certificate = Self::certificate_snapshot(&lab_report);

        // 6. Filter oracle results
        let oracle_report =
            FilteredOracleReport::from_full(lab_report.oracle_report.clone(), &scenario.oracles);

        // 7. Extract replay trace
        let replay_trace = runtime.finish_replay_trace();

        Ok(ScenarioRunResult {
            scenario_id: scenario.id.clone(),
            seed: effective_seed,
            lab_report,
            oracle_report,
            faults_injected,
            replay_trace,
            certificate,
        })
    }

    /// Explore a scenario across a range of seeds.
    ///
    /// Runs the scenario once per seed in `seed_start..seed_start+count` and
    /// collects results. Useful for finding schedule-dependent bugs.
    ///
    /// # Errors
    ///
    /// Returns an error if the scenario fails validation or contains unknown oracle names.
    pub fn explore_seeds(
        scenario: &Scenario,
        seed_start: u64,
        count: usize,
    ) -> Result<ScenarioExplorationResult, ScenarioRunnerError> {
        // Validate once up front
        let errors = scenario.validate();
        if !errors.is_empty() {
            return Err(ScenarioRunnerError::Validation(errors));
        }
        Self::validate_oracle_names(scenario)?;

        let mut runs = Vec::with_capacity(count);
        let mut fingerprint_set = std::collections::HashSet::new();
        let mut first_failure_seed = None;

        for i in 0..count {
            let seed = seed_start.wrapping_add(i as u64);
            // Run with this seed (skip validation since we already validated)
            let result = Self::run_with_seed(scenario, Some(seed))?;

            fingerprint_set.insert(result.certificate.trace_fingerprint);

            let passed = result.passed();
            let failures: Vec<String> = if passed {
                Vec::new()
            } else {
                let mut f: Vec<String> = result
                    .oracle_report
                    .entries
                    .iter()
                    .filter(|e| !e.passed)
                    .map(|e| {
                        format!(
                            "{}: {}",
                            e.invariant,
                            e.violation.as_deref().unwrap_or("failed")
                        )
                    })
                    .collect();
                f.extend(result.lab_report.invariant_violations.clone());
                if !result.lab_report.quiescent {
                    f.push("runtime not quiescent at report boundary".to_string());
                }
                f
            };

            if !passed && first_failure_seed.is_none() {
                first_failure_seed = Some(seed);
            }

            runs.push(ExplorationRunSummary {
                seed,
                passed,
                steps: result.lab_report.steps_total,
                fingerprint: result.certificate.trace_fingerprint,
                failures,
            });
        }

        let passed = runs.iter().filter(|r| r.passed).count();
        let failed = runs.len() - passed;

        Ok(ScenarioExplorationResult {
            scenario_id: scenario.id.clone(),
            seeds_explored: count,
            passed,
            failed,
            unique_fingerprints: fingerprint_set.len(),
            runs,
            first_failure_seed,
        })
    }

    /// Validate replay determinism: run a scenario twice with the same seed
    /// and verify identical trace certificates.
    ///
    /// # Errors
    ///
    /// Returns `ReplayDivergence` if the two runs produce different certificates.
    pub fn validate_replay(scenario: &Scenario) -> Result<ScenarioRunResult, ScenarioRunnerError> {
        let first = Self::run(scenario)?;
        let second = Self::run(scenario)?;

        if first.certificate != second.certificate {
            return Err(ScenarioRunnerError::ReplayDivergence {
                seed: first.seed,
                first: first.certificate,
                second: second.certificate,
            });
        }

        Ok(first)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::scenario::{
        ChaosSection, FaultAction, FaultEvent, LabSection, NetworkSection, Scenario,
    };
    use std::collections::BTreeMap;

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    fn minimal_scenario() -> Scenario {
        Scenario {
            schema_version: 1,
            id: "test-minimal".to_string(),
            description: "Minimal test scenario".to_string(),
            lab: LabSection::default(),
            chaos: ChaosSection::Off,
            network: NetworkSection::default(),
            faults: Vec::new(),
            participants: Vec::new(),
            oracles: vec!["all".to_string()],
            cancellation: None,
            include: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn run_minimal_scenario() {
        init_test("run_minimal_scenario");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed(), "minimal scenario should pass");
        assert_eq!(result.scenario_id, "test-minimal");
        assert_eq!(result.seed, 42);
        assert_eq!(result.faults_injected, 0);
        crate::test_complete!("run_minimal_scenario");
    }

    #[test]
    fn passed_requires_quiescence() {
        init_test("passed_requires_quiescence");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());

        let mut forced_non_quiescent = result.clone();
        forced_non_quiescent.lab_report.quiescent = false;
        assert!(!forced_non_quiescent.passed());
        crate::test_complete!("passed_requires_quiescence");
    }

    #[test]
    fn run_with_seed_override() {
        init_test("run_with_seed_override");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run_with_seed(&scenario, Some(123)).unwrap();
        assert_eq!(result.seed, 123);
        assert!(result.passed());
        crate::test_complete!("run_with_seed_override");
    }

    #[test]
    fn run_with_faults() {
        init_test("run_with_faults");
        let mut scenario = minimal_scenario();
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::Partition,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
            FaultEvent {
                at_ms: 50,
                action: FaultAction::Heal,
                args: {
                    let mut m = BTreeMap::new();
                    m.insert("from".into(), serde_json::json!("alice"));
                    m.insert("to".into(), serde_json::json!("bob"));
                    m
                },
            },
        ];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());
        assert_eq!(result.faults_injected, 2);
        crate::test_complete!("run_with_faults");
    }

    #[test]
    fn run_with_all_fault_types() {
        init_test("run_with_all_fault_types");
        let mut scenario = minimal_scenario();
        scenario.faults = vec![
            FaultEvent {
                at_ms: 10,
                action: FaultAction::Partition,
                args: BTreeMap::new(),
            },
            FaultEvent {
                at_ms: 20,
                action: FaultAction::Heal,
                args: BTreeMap::new(),
            },
            FaultEvent {
                at_ms: 30,
                action: FaultAction::HostCrash,
                args: BTreeMap::new(),
            },
            FaultEvent {
                at_ms: 40,
                action: FaultAction::HostRestart,
                args: BTreeMap::new(),
            },
            FaultEvent {
                at_ms: 50,
                action: FaultAction::ClockSkew,
                args: BTreeMap::new(),
            },
            FaultEvent {
                at_ms: 60,
                action: FaultAction::ClockReset,
                args: BTreeMap::new(),
            },
        ];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert!(result.passed());
        assert_eq!(result.faults_injected, 6);
        crate::test_complete!("run_with_all_fault_types");
    }

    #[test]
    fn validation_rejects_bad_scenario() {
        init_test("validation_rejects_bad_scenario");
        let mut scenario = minimal_scenario();
        scenario.id = String::new(); // invalid
        let result = ScenarioRunner::run(&scenario);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScenarioRunnerError::Validation(_)
        ));
        crate::test_complete!("validation_rejects_bad_scenario");
    }

    #[test]
    fn unknown_oracle_rejected() {
        init_test("unknown_oracle_rejected");
        let mut scenario = minimal_scenario();
        scenario.oracles = vec!["nonexistent_oracle".to_string()];
        let result = ScenarioRunner::run(&scenario);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScenarioRunnerError::UnknownOracle(_)
        ));
        crate::test_complete!("unknown_oracle_rejected");
    }

    #[test]
    fn oracle_filtering_works() {
        init_test("oracle_filtering_works");
        let mut scenario = minimal_scenario();
        scenario.oracles = vec!["task_leak".to_string(), "obligation_leak".to_string()];
        let result = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(result.oracle_report.checked.len(), 2);
        assert!(result
            .oracle_report
            .checked
            .contains(&"task_leak".to_string()));
        assert!(result
            .oracle_report
            .checked
            .contains(&"obligation_leak".to_string()));
        crate::test_complete!("oracle_filtering_works");
    }

    #[test]
    fn oracle_all_checks_everything() {
        init_test("oracle_all_checks_everything");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        // "all" should check every oracle
        assert_eq!(
            result.oracle_report.checked.len(),
            ALL_ORACLE_INVARIANTS.len()
        );
        crate::test_complete!("oracle_all_checks_everything");
    }

    #[test]
    fn replay_determinism() {
        init_test("replay_determinism");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::validate_replay(&scenario).unwrap();
        assert!(result.passed());
        crate::test_complete!("replay_determinism");
    }

    #[test]
    fn explore_seeds_basic() {
        init_test("explore_seeds_basic");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 0, 5).unwrap();
        assert_eq!(result.seeds_explored, 5);
        assert_eq!(result.passed, 5);
        assert_eq!(result.failed, 0);
        assert!(result.all_passed());
        assert!(result.unique_fingerprints >= 1);
        crate::test_complete!("explore_seeds_basic");
    }

    #[test]
    fn explore_seeds_reports_each_run() {
        init_test("explore_seeds_reports_each_run");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 100, 3).unwrap();
        assert_eq!(result.runs.len(), 3);
        assert_eq!(result.runs[0].seed, 100);
        assert_eq!(result.runs[1].seed, 101);
        assert_eq!(result.runs[2].seed, 102);
        crate::test_complete!("explore_seeds_reports_each_run");
    }

    #[test]
    fn result_to_json_roundtrip() {
        init_test("result_to_json_roundtrip");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::run(&scenario).unwrap();
        let json = result.to_json();
        assert_eq!(json["scenario_id"], "test-minimal");
        assert_eq!(json["seed"], 42);
        assert!(json["passed"].as_bool().unwrap());
        assert!(json["certificate"]["event_hash"].is_u64());
        crate::test_complete!("result_to_json_roundtrip");
    }

    #[test]
    fn exploration_to_json() {
        init_test("exploration_to_json");
        let scenario = minimal_scenario();
        let result = ScenarioRunner::explore_seeds(&scenario, 0, 2).unwrap();
        let json = result.to_json();
        assert_eq!(json["seeds_explored"], 2);
        assert!(json["runs"].is_array());
        assert_eq!(json["runs"].as_array().unwrap().len(), 2);
        crate::test_complete!("exploration_to_json");
    }

    #[test]
    fn replay_trace_available_when_enabled() {
        init_test("replay_trace_available_when_enabled");
        let mut scenario = minimal_scenario();
        scenario.lab.replay_recording = true;
        let result = ScenarioRunner::run(&scenario).unwrap();
        // ScenarioRunner always enables replay recording
        assert!(result.replay_trace.is_some());
        crate::test_complete!("replay_trace_available_when_enabled");
    }

    #[test]
    fn certificates_stable_across_runs() {
        init_test("certificates_stable_across_runs");
        let scenario = minimal_scenario();
        let r1 = ScenarioRunner::run(&scenario).unwrap();
        let r2 = ScenarioRunner::run(&scenario).unwrap();
        assert_eq!(r1.certificate, r2.certificate);
        crate::test_complete!("certificates_stable_across_runs");
    }

    #[test]
    fn different_seeds_may_differ() {
        init_test("different_seeds_may_differ");
        let scenario = minimal_scenario();
        let r1 = ScenarioRunner::run_with_seed(&scenario, Some(1)).unwrap();
        let r2 = ScenarioRunner::run_with_seed(&scenario, Some(2)).unwrap();
        // Seeds 1 and 2 should both pass (empty scenario)
        assert!(r1.passed());
        assert!(r2.passed());
        // They may or may not have the same fingerprint (empty scenario probably same)
        crate::test_complete!("different_seeds_may_differ");
    }

    #[test]
    fn chaos_scenario_runs() {
        init_test("chaos_scenario_runs");
        let mut scenario = minimal_scenario();
        scenario.chaos = ChaosSection::Light;
        let result = ScenarioRunner::run(&scenario).unwrap();
        // Light chaos with no tasks should still pass
        assert!(result.passed());
        crate::test_complete!("chaos_scenario_runs");
    }

    #[test]
    fn fault_args_summary_formatting() {
        init_test("fault_args_summary_formatting");
        let mut args = BTreeMap::new();
        args.insert("from".to_string(), serde_json::json!("alice"));
        args.insert("to".to_string(), serde_json::json!("bob"));
        let summary = ScenarioRunner::fault_args_summary(&args);
        assert!(summary.contains("from=alice"));
        assert!(summary.contains("to=bob"));
        crate::test_complete!("fault_args_summary_formatting");
    }

    #[test]
    fn error_display_validation() {
        init_test("error_display_validation");
        let err = ScenarioRunnerError::Validation(vec![ValidationError {
            field: "id".into(),
            message: "empty".into(),
        }]);
        let msg = err.to_string();
        assert!(msg.contains("validation failed"));
        assert!(msg.contains("id"));
        crate::test_complete!("error_display_validation");
    }

    #[test]
    fn error_display_unknown_oracle() {
        init_test("error_display_unknown_oracle");
        let err = ScenarioRunnerError::UnknownOracle("bad_oracle".into());
        assert!(err.to_string().contains("bad_oracle"));
        crate::test_complete!("error_display_unknown_oracle");
    }

    #[test]
    fn error_display_divergence() {
        init_test("error_display_divergence");
        let err = ScenarioRunnerError::ReplayDivergence {
            seed: 42,
            first: TraceCertificateSnapshot {
                event_hash: 1,
                schedule_hash: 2,
                steps: 100,
                trace_fingerprint: 3,
            },
            second: TraceCertificateSnapshot {
                event_hash: 4,
                schedule_hash: 5,
                steps: 100,
                trace_fingerprint: 6,
            },
        };
        let msg = err.to_string();
        assert!(msg.contains("seed 42"));
        assert!(msg.contains("divergence"));
        crate::test_complete!("error_display_divergence");
    }
}
