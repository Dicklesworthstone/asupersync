use super::*;
use crate::lab::scenario::{ChaosSection, Participant};
use crate::types::TaskId;
use crate::util::ArenaIndex;
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

fn swarm() -> Scenario {
    let mut scenario = Scenario {
        id: "poll-cancellation-swarm".to_owned(),
        chaos: ChaosSection::Off,
        cancellation: Some(CancellationSection {
            strategy: CancellationStrategy::AllPoints,
            count: None,
            probability: None,
        }),
        participants: vec![Participant {
            name: "members".to_owned(),
            role: "swarm".to_owned(),
            properties: BTreeMap::from([("tasks".to_owned(), serde_json::json!(2))]),
        }],
        ..Scenario::default()
    };
    scenario.lab.max_steps = Some(1000);
    scenario.lab.trace_capacity = 4096;
    scenario
}

fn campaign(scenario: &Scenario) -> ScenarioCancellationReport {
    ScenarioRunner::run_cancellation_campaign(
        scenario,
        Some(17),
        ScenarioCancellationLimits::default(),
    )
    .expect("valid campaign")
}

#[test]
fn all_points_publish_real_requests_and_drain_fresh_tasks() {
    for workers in [1, 2, 3] {
        let mut scenario = swarm();
        scenario.lab.worker_count = workers;
        let report = campaign(&scenario);
        assert!(report.passed(), "workers={workers}: {}", report.to_json());
        assert_eq!(
            report.termination,
            ScenarioCancellationTermination::Completed
        );
        let schedule = report.baseline_schedule.as_ref().expect("complete capture");
        assert!(schedule.dispatches().len() >= 6);
        assert_eq!(report.trials.len(), schedule.dispatches().len());
        assert_eq!(report.remaining_trials(), 0);
        assert!(report.baseline.replay_trace.is_none());
        for (index, trial) in report.trials.iter().enumerate() {
            assert_eq!(trial.poll_index, u64::try_from(index).unwrap() + 1);
            assert_eq!(trial.target, schedule.dispatches()[index]);
            assert_eq!(trial.injection, ScenarioCancellationInjection::Requested);
            assert!(trial.target_terminal);
            assert!(trial.run.lab_report.quiescent);
            assert!(trial.run.replay_trace.is_none());
        }
        let json = report.to_json();
        assert_eq!(json["boundary"], "scheduler_poll_opportunity");
        assert_eq!(json["replay_traces_retained"], false);
        assert_eq!(json["termination"], "completed");
        assert_eq!(json["passed"], true);
    }
}

#[test]
fn all_seven_scenario_strategies_select_deterministic_boundaries() {
    let mut scenario = swarm();
    let all = campaign(&scenario);
    assert!(all.passed(), "{}", all.to_json());
    let points = all.selected_polls;
    let last = *points.last().unwrap();
    for (strategy, expected) in [
        (CancellationStrategy::Never, Vec::new()),
        (CancellationStrategy::AllPoints, points.clone()),
        (CancellationStrategy::FirstN, vec![1, 2]),
        (CancellationStrategy::LastN, vec![last - 1, last]),
        (
            CancellationStrategy::EveryNth,
            points
                .iter()
                .copied()
                .filter(|point| point % 2 == 0)
                .collect(),
        ),
    ] {
        let section = scenario.cancellation.as_mut().unwrap();
        section.strategy = strategy;
        section.count = Some(2);
        let report = campaign(&scenario);
        assert_eq!(report.selected_polls, expected);
        if expected.is_empty() {
            assert_eq!(
                report.termination,
                ScenarioCancellationTermination::NoInjectionSelected
            );
            assert!(!report.passed());
        } else {
            assert!(report.passed(), "{}", report.to_json());
        }
    }

    scenario.cancellation.as_mut().unwrap().strategy = CancellationStrategy::RandomSample;
    let sample = campaign(&scenario);
    assert_eq!(sample.selected_polls.len(), 2);
    assert!(
        sample
            .selected_polls
            .windows(2)
            .all(|pair| pair[0] < pair[1])
    );
    assert!(sample.passed(), "{}", sample.to_json());
    assert_eq!(sample.selected_polls, campaign(&scenario).selected_polls);

    scenario.cancellation.as_mut().unwrap().strategy = CancellationStrategy::Probabilistic;
    for probability in [0.0, 0.5, 1.0] {
        scenario.cancellation.as_mut().unwrap().probability = Some(probability);
        let report = campaign(&scenario);
        assert_eq!(report.selected_polls, campaign(&scenario).selected_polls);
        if probability == 0.0 {
            assert!(report.selected_polls.is_empty());
            assert!(!report.passed());
        } else if probability == 1.0 {
            assert_eq!(report.selected_polls, points);
            assert!(report.passed(), "{}", report.to_json());
        } else {
            assert!(
                report
                    .selected_polls
                    .iter()
                    .all(|point| points.contains(point))
            );
        }
    }
}

#[test]
fn empty_and_recording_only_campaigns_never_claim_success() {
    let mut scenario = swarm();
    scenario.participants.clear();
    let empty = campaign(&scenario);
    assert!(empty.baseline.passed());
    assert_eq!(
        empty.termination,
        ScenarioCancellationTermination::NoPollPoints
    );
    assert!(empty.trials.is_empty());
    assert!(!empty.passed());

    let mut scenario = swarm();
    scenario.cancellation.as_mut().unwrap().strategy = CancellationStrategy::Never;
    let never = campaign(&scenario);
    assert_eq!(
        never.termination,
        ScenarioCancellationTermination::NoInjectionSelected
    );
    assert!(never.baseline_schedule.as_ref().unwrap().dispatches().len() > 1);
    assert!(never.trials.is_empty());
    assert!(!never.passed());
}

#[test]
fn capture_run_and_step_bounds_return_nonpassing_reports() {
    let scenario = swarm();
    let run_limited = ScenarioRunner::run_cancellation_campaign(
        &scenario,
        None,
        ScenarioCancellationLimits {
            max_runs: 1,
            ..ScenarioCancellationLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        run_limited.termination,
        ScenarioCancellationTermination::RunLimit
    );
    assert_eq!(run_limited.trials.len(), 1);
    assert!(run_limited.trials[0].passed());
    assert!(run_limited.remaining_trials() > 0);
    assert!(!run_limited.passed());

    let capture_limited = ScenarioRunner::run_cancellation_campaign(
        &scenario,
        None,
        ScenarioCancellationLimits {
            max_poll_points: 1,
            ..ScenarioCancellationLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        capture_limited.termination,
        ScenarioCancellationTermination::CaptureLimit
    );
    assert!(capture_limited.baseline.passed());
    assert!(capture_limited.baseline_schedule.is_none());
    assert!(capture_limited.trials.is_empty());
    assert!(!capture_limited.passed());

    let step_limited = ScenarioRunner::run_cancellation_campaign(
        &scenario,
        None,
        ScenarioCancellationLimits {
            max_steps_per_run: 1,
            ..ScenarioCancellationLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        step_limited.termination,
        ScenarioCancellationTermination::BaselineFailed
    );
    assert_eq!(step_limited.baseline.lab_report.steps_total, 1);
    assert!(!step_limited.baseline.lab_report.quiescent);
    assert!(step_limited.trials.is_empty());
    assert!(!step_limited.passed());
}

#[test]
fn a_request_without_room_to_drain_fails_and_obeys_stop_policy() {
    let mut scenario = swarm();
    let baseline = campaign(&scenario);
    assert!(baseline.passed(), "{}", baseline.to_json());
    let last = baseline
        .baseline_schedule
        .as_ref()
        .unwrap()
        .dispatches()
        .last()
        .unwrap();
    // The baseline finishes on its final dispatch, while the campaign must
    // schedule another turn to drive the newly requested cancellation.
    assert_eq!(last.at_step(), baseline.baseline.lab_report.steps_total);
    scenario.lab.max_steps = Some(last.at_step());
    let section = scenario.cancellation.as_mut().unwrap();
    section.strategy = CancellationStrategy::LastN;
    section.count = Some(1);

    let stopped = campaign(&scenario);
    assert!(stopped.baseline.passed(), "{}", stopped.to_json());
    assert_eq!(
        stopped.termination,
        ScenarioCancellationTermination::StoppedOnFailure
    );
    assert_eq!(stopped.trials.len(), 1);
    assert_eq!(
        stopped.trials[0].injection,
        ScenarioCancellationInjection::Requested
    );
    assert!(!stopped.trials[0].target_terminal);
    assert!(!stopped.trials[0].run.lab_report.quiescent);
    assert!(!stopped.passed());

    let completed = ScenarioRunner::run_cancellation_campaign(
        &scenario,
        Some(17),
        ScenarioCancellationLimits {
            stop_on_failure: false,
            ..ScenarioCancellationLimits::default()
        },
    )
    .unwrap();
    assert_eq!(
        completed.termination,
        ScenarioCancellationTermination::Completed
    );
    assert_eq!(completed.remaining_trials(), 0);
    assert!(!completed.passed());
}

#[test]
fn admission_rejects_absent_strategy_chaos_zero_limits_and_bad_parameters() {
    let mut scenario = swarm();
    scenario.cancellation = None;
    assert!(matches!(
        ScenarioRunner::run_cancellation_campaign(
            &scenario,
            None,
            ScenarioCancellationLimits::default()
        ),
        Err(ScenarioCancellationError::MissingConfiguration)
    ));
    let mut scenario = swarm();
    scenario.chaos = ChaosSection::Light;
    assert!(matches!(
        ScenarioRunner::run_cancellation_campaign(
            &scenario,
            None,
            ScenarioCancellationLimits::default()
        ),
        Err(ScenarioCancellationError::ChaosEnabled)
    ));
    let scenario = swarm();
    for limits in [
        ScenarioCancellationLimits {
            max_runs: 0,
            ..ScenarioCancellationLimits::default()
        },
        ScenarioCancellationLimits {
            max_poll_points: 0,
            ..ScenarioCancellationLimits::default()
        },
        ScenarioCancellationLimits {
            max_steps_per_run: 0,
            ..ScenarioCancellationLimits::default()
        },
    ] {
        assert!(matches!(
            ScenarioRunner::run_cancellation_campaign(&scenario, None, limits),
            Err(ScenarioCancellationError::ZeroLimit { .. })
        ));
    }
    let mut scenario = swarm();
    let section = scenario.cancellation.as_mut().unwrap();
    section.strategy = CancellationStrategy::FirstN;
    section.count = Some(0);
    assert!(matches!(
        ScenarioRunner::run_cancellation_campaign(
            &scenario,
            None,
            ScenarioCancellationLimits::default()
        ),
        Err(ScenarioCancellationError::Scenario(
            ScenarioRunnerError::Validation { .. }
        ))
    ));
}

#[test]
fn cancellation_reaches_held_permits_and_witnesses_retired_terminal_tasks() {
    let mut scenario = swarm();
    scenario.participants = vec![
        Participant {
            name: "sender".to_owned(),
            role: "sender".to_owned(),
            properties: BTreeMap::from([("messages".to_owned(), serde_json::json!(3))]),
        },
        Participant {
            name: "receiver".to_owned(),
            role: "receiver".to_owned(),
            properties: BTreeMap::from([("capacity".to_owned(), serde_json::json!(1))]),
        },
    ];
    let plan = ScenarioRunner::workload_plan(&scenario).unwrap();
    let config = ScenarioRunner::lab_config_for(&scenario, None);
    let mut baseline_runtime = LabRuntime::new(config.clone());
    baseline_runtime
        .start_forced_schedule_recording(256)
        .unwrap();
    let (baseline, _) = ScenarioRunner::run_prepared(&scenario, None, &plan, &mut baseline_runtime);
    assert!(baseline.passed(), "{}", baseline.to_json());
    let schedule = baseline_runtime.finish_forced_schedule_recording().unwrap();
    let source: Arc<[ForcedDispatch]> = schedule.dispatches().to_vec().into();
    let mut cancelled_holding = 0;

    for (target_index, target) in source.iter().enumerate() {
        let mut runtime = LabRuntime::new(config.clone());
        runtime.set_poll_cancellation(
            PollCancellationControl::new(Arc::clone(&source), target_index).unwrap(),
        );
        let (run, tasks) = ScenarioRunner::run_prepared(&scenario, None, &plan, &mut runtime);
        assert!(run.passed(), "target={target_index}: {}", run.to_json());
        assert_eq!(
            runtime.finish_poll_cancellation(),
            Some((PollCancellationResult::Requested, true))
        );
        let (slot, generation) = target.task().unpack();
        let task_id = TaskId::from_arena(ArenaIndex::new(slot, generation));
        assert!(
            runtime.state.task(task_id).is_none(),
            "the target's terminal witness must survive task record recycling"
        );
        cancelled_holding += tasks
            .iter()
            .map(|task| task.counters.cancelled_holding.load(Ordering::Relaxed))
            .sum::<u64>();
    }
    assert!(
        cancelled_holding > 0,
        "a cancellation must reach the sender while its reserve permit is live"
    );
}

#[test]
fn prefix_divergence_disables_injection_but_allows_ordinary_drain() {
    let scenario = swarm();
    let plan = ScenarioRunner::workload_plan(&scenario).unwrap();
    let config = ScenarioRunner::lab_config_for(&scenario, None);
    let mut baseline_runtime = LabRuntime::new(config.clone());
    baseline_runtime
        .start_forced_schedule_recording(256)
        .unwrap();
    let (baseline, _) = ScenarioRunner::run_prepared(&scenario, None, &plan, &mut baseline_runtime);
    assert!(baseline.passed());
    let schedule = baseline_runtime.finish_forced_schedule_recording().unwrap();
    let mut source = schedule.dispatches().to_vec();
    let actual = source[0];
    let expected = ForcedDispatch::from_checkpoint_parts(
        actual.task(),
        actual.worker(),
        actual.lane(),
        actual.at_step() + 1,
        actual.at_nanos(),
    );
    source[0] = expected;
    let target = source.len() - 1;
    let mut runtime = LabRuntime::new(config);
    runtime.set_poll_cancellation(PollCancellationControl::new(source.into(), target).unwrap());
    let (run, _) = ScenarioRunner::run_prepared(&scenario, None, &plan, &mut runtime);
    assert!(run.passed(), "{}", run.to_json());
    assert_eq!(run.certificate, baseline.certificate);
    assert_eq!(
        runtime.finish_poll_cancellation(),
        Some((
            PollCancellationResult::PrefixDiverged {
                poll_index: 1,
                expected,
                actual,
            },
            false
        ))
    );
}

#[test]
fn ordinary_single_run_still_returns_its_replay_trace() {
    let scenario = swarm();
    let ordinary = ScenarioRunner::run_with_seed(&scenario, Some(17)).unwrap();
    assert!(ordinary.passed(), "{}", ordinary.to_json());
    assert!(ordinary.replay_trace.is_some());
    let report = campaign(&scenario);
    assert!(report.passed(), "{}", report.to_json());
    assert_eq!(report.baseline.certificate, ordinary.certificate);
    assert_eq!(report.baseline.seed_lineage, ordinary.seed_lineage);
}
