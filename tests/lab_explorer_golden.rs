#![allow(warnings)]
#![allow(clippy::all)]

use asupersync::lab::{
    DporCoverageMetrics, DporExplorer, ExplorationReport, ExplorerConfig, ScheduleExplorer,
    TopologyExplorer,
};
use asupersync::types::Budget;
use insta::assert_json_snapshot;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
struct ScenarioGolden {
    name: &'static str,
    mode: &'static str,
    report: ScrubbedReport,
    dpor_coverage: Option<ScrubbedDporCoverage>,
}

#[derive(Debug, Serialize)]
struct ScrubbedReport {
    total_runs: usize,
    unique_classes: usize,
    violation_seeds: Vec<String>,
    coverage: ScrubbedCoverage,
    top_unexplored: Vec<ScrubbedUnexploredSeed>,
    runs: Vec<ScrubbedRun>,
    certificate_divergences: Vec<(String, String)>,
}

#[derive(Debug, Serialize)]
struct ScrubbedCoverage {
    equivalence_classes: usize,
    total_runs: usize,
    new_class_discoveries: usize,
    class_run_counts: Vec<(String, usize)>,
    novelty_histogram: BTreeMap<u32, usize>,
    saturation_window: usize,
    saturation_flag: bool,
    existing_class_hits: usize,
    runs_since_last_new_class: Option<usize>,
}

#[derive(Debug, Serialize)]
struct ScrubbedRun {
    seed: String,
    steps: u64,
    fingerprint: String,
    is_new_class: bool,
    violation_count: usize,
    certificate_hash: String,
}

#[derive(Debug, Serialize)]
struct ScrubbedUnexploredSeed {
    seed: String,
    score_novelty: Option<u32>,
    score_persistence_sum: Option<u64>,
    score_fingerprint: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScrubbedDporCoverage {
    total_races: usize,
    total_hb_races: usize,
    total_backtrack_points: usize,
    pruned_backtrack_points: usize,
    sleep_pruned: usize,
    efficiency: f64,
    estimated_class_trend: Vec<usize>,
}

#[derive(Default)]
struct ScrubContext {
    seeds: BTreeMap<u64, String>,
    fingerprints: BTreeMap<u64, String>,
    certificates: BTreeMap<u64, String>,
}

impl ScrubContext {
    fn seed_label(&mut self, seed: u64) -> String {
        if let Some(existing) = self.seeds.get(&seed) {
            return existing.clone();
        }
        let label = format!("seed-{}", self.seeds.len());
        self.seeds.insert(seed, label.clone());
        label
    }

    fn fingerprint_label(&mut self, fingerprint: u64) -> String {
        if let Some(existing) = self.fingerprints.get(&fingerprint) {
            return existing.clone();
        }
        let label = format!("fp-{}", self.fingerprints.len());
        self.fingerprints.insert(fingerprint, label.clone());
        label
    }

    fn certificate_label(&mut self, certificate_hash: u64) -> String {
        if let Some(existing) = self.certificates.get(&certificate_hash) {
            return existing.clone();
        }
        let label = format!("cert-{}", self.certificates.len());
        self.certificates.insert(certificate_hash, label.clone());
        label
    }
}

fn scrub_report(report: &ExplorationReport) -> ScrubbedReport {
    let mut scrub = ScrubContext::default();
    let class_run_counts = report
        .coverage
        .class_run_counts
        .iter()
        .map(|(&fingerprint, &count)| (scrub.fingerprint_label(fingerprint), count))
        .collect();
    let runs = report
        .runs
        .iter()
        .map(|run| ScrubbedRun {
            seed: scrub.seed_label(run.seed),
            steps: run.steps,
            fingerprint: scrub.fingerprint_label(run.fingerprint),
            is_new_class: run.is_new_class,
            violation_count: run.violations.len(),
            certificate_hash: scrub.certificate_label(run.certificate_hash),
        })
        .collect();
    let top_unexplored = report
        .top_unexplored
        .iter()
        .map(|entry| ScrubbedUnexploredSeed {
            seed: scrub.seed_label(entry.seed),
            score_novelty: entry.score.as_ref().map(|score| score.novelty),
            score_persistence_sum: entry.score.as_ref().map(|score| score.persistence_sum),
            score_fingerprint: entry
                .score
                .as_ref()
                .map(|score| scrub.fingerprint_label(score.fingerprint)),
        })
        .collect();
    let certificate_divergences = report
        .certificate_divergences()
        .into_iter()
        .map(|(left, right)| (scrub.seed_label(left), scrub.seed_label(right)))
        .collect();

    ScrubbedReport {
        total_runs: report.total_runs,
        unique_classes: report.unique_classes,
        violation_seeds: report
            .violation_seeds()
            .into_iter()
            .map(|seed| scrub.seed_label(seed))
            .collect(),
        coverage: ScrubbedCoverage {
            equivalence_classes: report.coverage.equivalence_classes,
            total_runs: report.coverage.total_runs,
            new_class_discoveries: report.coverage.new_class_discoveries,
            class_run_counts,
            novelty_histogram: report.coverage.novelty_histogram.clone(),
            saturation_window: report.coverage.saturation.window,
            saturation_flag: report.coverage.saturation.saturated,
            existing_class_hits: report.coverage.saturation.existing_class_hits,
            runs_since_last_new_class: report.coverage.saturation.runs_since_last_new_class,
        },
        top_unexplored,
        runs,
        certificate_divergences,
    }
}

fn scrub_dpor_coverage(metrics: &DporCoverageMetrics) -> ScrubbedDporCoverage {
    ScrubbedDporCoverage {
        total_races: metrics.total_races,
        total_hb_races: metrics.total_hb_races,
        total_backtrack_points: metrics.total_backtrack_points,
        pruned_backtrack_points: metrics.pruned_backtrack_points,
        sleep_pruned: metrics.sleep_pruned,
        efficiency: metrics.efficiency,
        estimated_class_trend: metrics.estimated_class_trend.clone(),
    }
}

fn run_single_task_scenario() -> ScenarioGolden {
    let mut explorer = ScheduleExplorer::new(ExplorerConfig::new(7, 3).worker_count(2));
    let report = explorer.explore(|runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async { 42usize })
            .expect("create task");
        runtime.scheduler.lock().schedule(task_id, 0);
        runtime.run_until_quiescent();
    });

    ScenarioGolden {
        name: "single_task_seed_sweep",
        mode: "schedule",
        report: scrub_report(&report),
        dpor_coverage: None,
    }
}

fn run_two_task_dpor_scenario() -> ScenarioGolden {
    let mut explorer = DporExplorer::new(ExplorerConfig::new(11, 4).worker_count(2));
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
            let mut scheduler = runtime.scheduler.lock();
            scheduler.schedule(t1, 0);
            scheduler.schedule(t2, 0);
        }
        runtime.run_until_quiescent();
    });

    ScenarioGolden {
        name: "two_task_dpor",
        mode: "dpor",
        report: scrub_report(&report),
        dpor_coverage: Some(scrub_dpor_coverage(&explorer.dpor_coverage())),
    }
}

fn run_topology_scenario() -> ScenarioGolden {
    let mut explorer = TopologyExplorer::new(ExplorerConfig::new(21, 3).worker_count(2));
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
        let (t3, _) = runtime
            .state
            .create_task(region, Budget::INFINITE, async {})
            .expect("t3");
        {
            let mut scheduler = runtime.scheduler.lock();
            scheduler.schedule(t1, 0);
            scheduler.schedule(t2, 0);
            scheduler.schedule(t3, 0);
        }
        runtime.run_until_quiescent();
    });

    ScenarioGolden {
        name: "three_task_topology_frontier",
        mode: "topology",
        report: scrub_report(&report),
        dpor_coverage: None,
    }
}

#[test]
fn scenario_discovery_output_scrubbed() {
    let golden = vec![
        run_single_task_scenario(),
        run_two_task_dpor_scenario(),
        run_topology_scenario(),
    ];

    assert_json_snapshot!("scenario_discovery_output_scrubbed", golden);
}
