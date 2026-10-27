#![allow(clippy::pedantic, clippy::nursery, clippy::future_not_send)]

use super::*;
use crate::lab::runtime::ForcedScheduleLimits;
use crate::types::{Budget, Time};
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::task::{Poll, Waker};
use std::time::Duration;

fn limits() -> ExactScheduleLimits {
    ExactScheduleLimits::new(32, 256, 64, 256, 512)
}

fn checkpoint_limits() -> ExactScheduleCheckpointLimits {
    ExactScheduleCheckpointLimits {
        max_encoded_bytes: 1 << 20,
        max_prefixes: 256,
        max_decisions: 4096,
        max_dispatches: 8192,
        max_decoded_bytes: 1 << 20,
    }
}

fn campaign_workload(runtime: &mut LabRuntime) {
    one_poll_tasks(runtime, 3, Arc::new(Mutex::new(Vec::new())));
}

fn partial_checkpoint() -> ExactScheduleCheckpoint {
    let mut bounded = limits();
    bounded.max_runs = 1;
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), bounded);
    let key = ExactScheduleWorkloadKey([7; 32]);
    let mut checkpoint = explorer.new_checkpoint(key).unwrap();
    let batch = explorer.resume(&mut checkpoint, key, campaign_workload).unwrap();
    assert_eq!(batch.runs.len(), 1);
    assert_eq!(checkpoint.pending_prefix_count(), 3);
    checkpoint
}

fn resign_checkpoint(bytes: &mut [u8]) {
    use sha2::{Digest, Sha256};

    let end = bytes.len() - 32;
    let mut hash = Sha256::new();
    hash.update(b"asupersync.lab.exact-exploration-checkpoint.v1\0");
    hash.update(&bytes[..end]);
    let checksum: [u8; 32] = hash.finalize().into();
    bytes[end..].copy_from_slice(&checksum);
}

#[test]
fn campaign_roundtrips_between_batches_without_repeating_or_reordering_work() {
    let config = LabConfig::new(42);
    let full = ExactScheduleExplorer::new(config.clone(), limits())
        .explore(campaign_workload)
        .unwrap();
    let key = ExactScheduleWorkloadKey([7; 32]);
    let mut bounded = limits();
    bounded.max_runs = 1;
    let mut explorer = ExactScheduleExplorer::new(config.clone(), bounded);
    let mut checkpoint = explorer.new_checkpoint(key).unwrap();
    let mut executions = Vec::new();
    let mut hashes = Vec::new();
    loop {
        let bytes = checkpoint.to_canonical_bytes(checkpoint_limits()).unwrap();
        let decoded = ExactScheduleCheckpoint::try_from_canonical_bytes(
            &bytes, checkpoint_limits(),
        ).unwrap();
        assert_eq!(decoded, checkpoint);
        assert_eq!(decoded.to_canonical_bytes(checkpoint_limits()).unwrap(), bytes);
        checkpoint = decoded;
        let batch = explorer.resume(&mut checkpoint, key, campaign_workload).unwrap();
        assert!(batch.runs.len() <= bounded.max_runs);
        assert_eq!(batch.progress, checkpoint.progress());
        for run in batch.runs {
            hashes.push(run.schedule.unwrap().terminal_schedule_hash());
            executions.push(run.execution);
        }
        if checkpoint.pending_prefix_count() == 0 {
            assert_eq!(batch.termination, ExactScheduleSearchTermination::SearchExhausted);
            break;
        }
        assert_eq!(batch.termination, ExactScheduleSearchTermination::RunLimit);
        bounded.max_runs = 2;
        explorer = ExactScheduleExplorer::new(config.clone(), bounded);
    }
    assert_eq!(executions, full.runs.iter().map(|run| run.execution.clone()).collect::<Vec<_>>());
    assert_eq!(hashes, full.runs.iter().map(|run| {
        run.schedule.as_ref().unwrap().terminal_schedule_hash()
    }).collect::<Vec<_>>());
    assert_eq!(checkpoint.progress(), ExactScheduleProgress {
        runs: 6, completed: 6, incomplete: 0, failed: 0, omitted: 0,
    });
    let done = explorer.resume(&mut checkpoint, key, |_| panic!("finished campaign reran work"))
        .unwrap();
    assert!(done.runs.is_empty());
    assert_eq!(done.termination, ExactScheduleSearchTermination::SearchExhausted);
    let empty = checkpoint.to_canonical_bytes(checkpoint_limits()).unwrap();
    assert_eq!(ExactScheduleCheckpoint::try_from_canonical_bytes(&empty, checkpoint_limits()).unwrap(), checkpoint);
}

#[test]
fn campaign_stop_predicate_retains_the_stopping_runs_alternatives() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    let key = ExactScheduleWorkloadKey([7; 32]);
    let full = explorer.explore(campaign_workload).unwrap();
    let mut checkpoint = explorer.new_checkpoint(key).unwrap();
    let stopped = explorer.resume_until(&mut checkpoint, key, campaign_workload, |_| true).unwrap();
    assert_eq!(stopped.termination, ExactScheduleSearchTermination::Stopped);
    assert_eq!(stopped.runs.len(), 1);
    assert_eq!(checkpoint.pending_prefix_count(), 3);
    let rest = explorer.resume(&mut checkpoint, key, campaign_workload).unwrap();
    assert_eq!(rest.termination, ExactScheduleSearchTermination::SearchExhausted);
    let actual: Vec<_> = stopped.runs.into_iter().chain(rest.runs)
        .map(|run| run.execution).collect();
    assert_eq!(actual, full.runs.into_iter().map(|run| run.execution).collect::<Vec<_>>());
}

#[test]
fn campaign_stops_on_a_real_runtime_obligation_leak() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42).panic_on_leak(false), limits());
    let key = ExactScheduleWorkloadKey([8; 32]);
    let mut checkpoint = explorer.new_checkpoint(key).unwrap();
    let batch = explorer.resume_until_failure(&mut checkpoint, key, |runtime| {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        for index in 0..2 {
            let (task, _handle) = runtime.state.create_task(region, Budget::INFINITE, async {}).unwrap();
            if index == 0 {
                runtime.state.create_obligation(
                    crate::record::ObligationKind::SendPermit,
                    task,
                    region,
                    Some("campaign planted leak".to_owned()),
                ).unwrap();
            }
            runtime.scheduler.lock().schedule(task, 0);
        }
    }).unwrap();
    assert_eq!(batch.termination, ExactScheduleSearchTermination::Stopped);
    assert_eq!(batch.runs.len(), 1);
    assert_eq!(batch.progress.failed, 1);
    assert!(!batch.runs[0].lab.oracle_report.entry("obligation_leak").unwrap().passed);
    assert!(checkpoint.pending_prefix_count() > 0);
}

#[test]
fn campaign_rejects_incompatible_resume_before_callbacks_or_mutation() {
    let key = ExactScheduleWorkloadKey([7; 32]);
    let original = partial_checkpoint();
    let mut cases = Vec::new();
    cases.push((LabConfig::new(42), limits(), ExactScheduleWorkloadKey([9; 32]), ExactScheduleResumeError::WorkloadMismatch));
    cases.push((LabConfig::new(43), limits(), key, ExactScheduleResumeError::ExecutionMismatch));
    let mut changed = LabConfig::new(42);
    changed.entropy_seed = 99;
    cases.push((changed, limits(), key, ExactScheduleResumeError::ExecutionMismatch));
    let mut bounded = limits();
    bounded.max_pending_prefixes = 1;
    cases.push((LabConfig::new(42), bounded, key, ExactScheduleResumeError::FrontierLimit));
    bounded = limits();
    bounded.max_dispatches_per_run = 1;
    cases.push((LabConfig::new(42), bounded, key, ExactScheduleResumeError::PrefixLimit));
    bounded = limits();
    bounded.max_inventory_entries = 1;
    cases.push((LabConfig::new(42), bounded, key, ExactScheduleResumeError::InventoryLimit));
    for (config, limits, workload, expected) in cases {
        let mut checkpoint = original.clone();
        let error = ExactScheduleExplorer::new(config, limits).resume_until(
            &mut checkpoint, workload,
            |_| panic!("invalid campaign called factory"),
            |_| panic!("invalid campaign called predicate"),
        ).unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(checkpoint, original);
    }
}

#[test]
fn campaign_checks_enabled_sets_even_when_the_caller_reuses_a_workload_key() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    let mut checkpoint = partial_checkpoint();
    let polled = Arc::new(Mutex::new(Vec::new()));
    let batch = explorer.resume(&mut checkpoint, ExactScheduleWorkloadKey([7; 32]), |runtime| {
        one_poll_tasks(runtime, 2, Arc::clone(&polled));
    }).unwrap();
    assert_eq!(batch.termination, ExactScheduleSearchTermination::IncompleteRun);
    assert!(batch.runs.iter().all(|run| run.termination == ExactScheduleTermination::PrefixDiverged { decision: 0 }));
    assert!(polled.lock().is_empty());
    assert!(batch.runs.iter().all(|run| run.schedule.is_none()));
}

#[test]
fn campaign_preserves_incomplete_coverage_across_save_and_resume() {
    let key = ExactScheduleWorkloadKey([7; 32]);
    for omitted in [false, true] {
        let mut bounded = limits();
        bounded.max_runs = 1;
        if omitted { bounded.max_pending_prefixes = 1; }
        else { bounded.max_dispatches_per_run = 1; }
        let explorer = ExactScheduleExplorer::new(LabConfig::new(42), bounded);
        let mut checkpoint = explorer.new_checkpoint(key).unwrap();
        explorer.resume(&mut checkpoint, key, campaign_workload).unwrap();
        let bytes = checkpoint.to_canonical_bytes(checkpoint_limits()).unwrap();
        let mut checkpoint = ExactScheduleCheckpoint::try_from_canonical_bytes(&bytes, checkpoint_limits()).unwrap();
        let batch = ExactScheduleExplorer::new(LabConfig::new(42), limits())
            .resume(&mut checkpoint, key, campaign_workload).unwrap();
        assert_eq!(checkpoint.pending_prefix_count(), 0);
        if omitted {
            assert!(batch.progress.omitted > 0);
            assert_eq!(batch.termination, ExactScheduleSearchTermination::PrefixQueueLimit);
        } else {
            assert_eq!(batch.progress.incomplete, 1);
            assert_eq!(batch.termination, ExactScheduleSearchTermination::IncompleteRun);
        }
    }
}

#[test]
fn campaign_factory_panic_preserves_the_frontier_and_predicate_panic_commits_the_run() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    let key = ExactScheduleWorkloadKey([7; 32]);
    let mut checkpoint = explorer.new_checkpoint(key).unwrap();
    let original = checkpoint.clone();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        explorer.resume(&mut checkpoint, key, |_| panic!("factory failed"))
    })).is_err());
    assert_eq!(checkpoint, original);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        explorer.resume_until(&mut checkpoint, key, campaign_workload, |_| panic!("predicate failed"))
    })).is_err());
    assert_eq!(checkpoint.progress().runs, 1);
    assert_eq!(checkpoint.pending_prefix_count(), 3);
    let rest = explorer.resume(&mut checkpoint, key, campaign_workload).unwrap();
    assert_eq!(rest.runs.len(), 5);
    assert_eq!(rest.progress.completed, 6);
    assert_eq!(rest.termination, ExactScheduleSearchTermination::SearchExhausted);
}

#[test]
fn checkpoint_codec_enforces_each_aggregate_admission_boundary() {
    let checkpoint = partial_checkpoint();
    let bytes = checkpoint.to_canonical_bytes(checkpoint_limits()).unwrap();
    let count = |offset| usize::try_from(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())).unwrap();
    let prefixes = count(100);
    let decisions = count(108);
    let dispatches = count(116);
    let exact = ExactScheduleCheckpointLimits {
        max_encoded_bytes: bytes.len(), max_prefixes: prefixes,
        max_decisions: decisions, max_dispatches: dispatches,
        max_decoded_bytes: prefixes * std::mem::size_of::<ExactSchedulePrefix>()
            + decisions * std::mem::size_of::<ExactScheduleDecision>()
            + dispatches * std::mem::size_of::<ForcedDispatch>(),
    };
    assert_eq!(checkpoint.to_canonical_bytes(exact).unwrap(), bytes);
    assert_eq!(ExactScheduleCheckpoint::try_from_canonical_bytes(&bytes, exact).unwrap(), checkpoint);
    for (limits, error) in [
        (ExactScheduleCheckpointLimits { max_encoded_bytes: bytes.len() - 1, ..exact }, ExactScheduleCheckpointError::ByteLimit),
        (ExactScheduleCheckpointLimits { max_prefixes: prefixes - 1, ..exact }, ExactScheduleCheckpointError::PrefixLimit),
        (ExactScheduleCheckpointLimits { max_decisions: decisions - 1, ..exact }, ExactScheduleCheckpointError::DecisionLimit),
        (ExactScheduleCheckpointLimits { max_dispatches: dispatches - 1, ..exact }, ExactScheduleCheckpointError::DispatchLimit),
        (ExactScheduleCheckpointLimits { max_decoded_bytes: exact.max_decoded_bytes - 1, ..exact }, ExactScheduleCheckpointError::DecodedLimit),
    ] {
        assert_eq!(checkpoint.to_canonical_bytes(limits).unwrap_err(), error);
        assert_eq!(ExactScheduleCheckpoint::try_from_canonical_bytes(&bytes, limits).unwrap_err(), error);
    }
}

#[test]
fn checkpoint_codec_rejects_corruption_lengths_hostile_counts_and_choice_shapes() {
    let original = partial_checkpoint().to_canonical_bytes(checkpoint_limits()).unwrap();
    let decode = |bytes: &[u8]| ExactScheduleCheckpoint::try_from_canonical_bytes(bytes, checkpoint_limits());
    let mut corrupt = original.clone();
    corrupt[44] ^= 1;
    assert_eq!(decode(&corrupt).unwrap_err(), ExactScheduleCheckpointError::Checksum);
    assert_eq!(decode(&original[..original.len() - 1]).unwrap_err(), ExactScheduleCheckpointError::Length);
    let mut trailing = original.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing).unwrap_err(), ExactScheduleCheckpointError::Length);
    let mut version = original.clone();
    version[8..12].copy_from_slice(&2_u32.to_le_bytes());
    assert_eq!(decode(&version).unwrap_err(), ExactScheduleCheckpointError::Format);
    for offset in [100, 108, 116, 124, 140] {
        let mut hostile = original.clone();
        hostile[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        resign_checkpoint(&mut hostile);
        assert!(matches!(decode(&hostile), Err(
            ExactScheduleCheckpointError::Overflow | ExactScheduleCheckpointError::Length
            | ExactScheduleCheckpointError::PrefixLimit | ExactScheduleCheckpointError::DecisionLimit
            | ExactScheduleCheckpointError::DispatchLimit
        )));
    }
    for (offset, value) in [(132, 99_u64), (161, 0_u64), (68, 0_u64)] {
        let mut invalid = original.clone();
        invalid[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        resign_checkpoint(&mut invalid);
        assert_eq!(decode(&invalid).unwrap_err(), ExactScheduleCheckpointError::Shape);
    }
    for (offset, value) in [(156, 1), (160, 3)] {
        let mut invalid = original.clone();
        invalid[offset] = value;
        resign_checkpoint(&mut invalid);
        assert_eq!(decode(&invalid).unwrap_err(), ExactScheduleCheckpointError::Shape);
    }
    let mut duplicate = original.clone();
    let first_task: [u8; 8] = duplicate[148..156].try_into().unwrap();
    duplicate[177..185].copy_from_slice(&first_task);
    resign_checkpoint(&mut duplicate);
    assert_eq!(decode(&duplicate).unwrap_err(), ExactScheduleCheckpointError::Shape);
}

#[test]
fn decoded_checkpoint_identity_and_counter_headroom_are_admitted_before_execution() {
    let original = partial_checkpoint().to_canonical_bytes(checkpoint_limits()).unwrap();
    let key = ExactScheduleWorkloadKey([7; 32]);
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    for offset in [44, 52] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        resign_checkpoint(&mut bytes);
        let mut checkpoint = ExactScheduleCheckpoint::try_from_canonical_bytes(&bytes, checkpoint_limits()).unwrap();
        let before = checkpoint.clone();
        let error = explorer.resume(&mut checkpoint, key, |_| panic!("identity mismatch ran a factory"))
            .unwrap_err();
        assert_eq!(error, ExactScheduleResumeError::ExecutionMismatch);
        assert_eq!(checkpoint, before);
    }
    let mut bytes = original.clone();
    for offset in [60, 68] {
        bytes[offset..offset + 8].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
    }
    resign_checkpoint(&mut bytes);
    let mut checkpoint = ExactScheduleCheckpoint::try_from_canonical_bytes(&bytes, checkpoint_limits()).unwrap();
    let before = checkpoint.clone();
    assert_eq!(explorer.resume(&mut checkpoint, key, |_| panic!("counter overflow ran a factory")).unwrap_err(), ExactScheduleResumeError::CounterOverflow);
    assert_eq!(checkpoint, before);
    let mut bounded = limits();
    bounded.max_runs = 1;
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), bounded);
    let batch = explorer.resume(&mut checkpoint, key, campaign_workload).unwrap();
    assert_eq!(batch.progress.runs, u64::MAX);
    assert_eq!(batch.progress.completed, u64::MAX);
    let encoded = checkpoint.to_canonical_bytes(checkpoint_limits()).unwrap();
    assert_eq!(ExactScheduleCheckpoint::try_from_canonical_bytes(&encoded, checkpoint_limits()).unwrap(), checkpoint);
    assert_eq!(explorer.resume(&mut checkpoint, key, |_| panic!("exhausted counter ran a factory")).unwrap_err(), ExactScheduleResumeError::CounterOverflow);
    let mut bytes = original;
    bytes[92..100].copy_from_slice(&u64::MAX.to_le_bytes());
    resign_checkpoint(&mut bytes);
    let mut checkpoint = ExactScheduleCheckpoint::try_from_canonical_bytes(&bytes, checkpoint_limits()).unwrap();
    assert_eq!(explorer.resume(&mut checkpoint, key, |_| panic!("omission counter overflow ran a factory")).unwrap_err(), ExactScheduleResumeError::CounterOverflow);
}

fn one_poll_tasks(runtime: &mut LabRuntime, count: u8, observations: Arc<Mutex<Vec<u8>>>) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    for label in 0..count {
        let observations = Arc::clone(&observations);
        let (task, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                observations.lock().push(label);
            })
            .expect("create task");
        runtime.scheduler.lock().schedule(task, 0);
    }
}

#[test]
fn exact_explorer_executes_all_six_orders_and_replays_each_receipt() {
    let config = LabConfig::new(42);
    let explorer = ExactScheduleExplorer::new(config.clone(), limits());
    let observed = RefCell::new(Vec::new());
    let report = explorer
        .explore(|runtime| {
            let output = Arc::new(Mutex::new(Vec::new()));
            one_poll_tasks(runtime, 3, Arc::clone(&output));
            observed.borrow_mut().push(output);
        })
        .expect("supported configuration");

    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 6);
    assert!(report.pending_prefixes.is_empty());
    assert_eq!(report.omitted_prefixes, 0);
    let actual: BTreeSet<_> = observed
        .borrow()
        .iter()
        .map(|output| output.lock().clone())
        .collect();
    let expected = BTreeSet::from([
        vec![0, 1, 2],
        vec![0, 2, 1],
        vec![1, 0, 2],
        vec![1, 2, 0],
        vec![2, 0, 1],
        vec![2, 1, 0],
    ]);
    assert_eq!(actual, expected);

    for (run, original) in report.runs.iter().zip(observed.borrow().iter()) {
        assert!(run.lab.quiescent);
        let output = Arc::new(Mutex::new(Vec::new()));
        let mut runtime = LabRuntime::new_with_task_causality(config.clone());
        one_poll_tasks(&mut runtime, 3, Arc::clone(&output));
        let schedule = run.schedule.as_ref().expect("complete receipt");
        let replay = runtime
            .run_forced_schedule(schedule, ForcedScheduleLimits::new(64, 256))
            .expect("exact receipt must replay on a fresh workload");
        assert!(replay.quiescent);
        assert_eq!(replay.schedule_hash, schedule.terminal_schedule_hash());
        assert_eq!(*output.lock(), *original.lock());
    }
}

#[test]
fn exact_explorer_exposes_lost_updates_across_real_poll_boundaries() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(77), limits());
    let outcomes = RefCell::new(Vec::new());
    let report = explorer
        .explore(|runtime| {
            let counter = Arc::new(Mutex::new(0usize));
            outcomes.borrow_mut().push(Arc::clone(&counter));
            let region = runtime.state.create_root_region(Budget::INFINITE);
            for _ in 0..2 {
                let counter = Arc::clone(&counter);
                let mut read = None;
                let future = std::future::poll_fn(move |cx| {
                    if let Some(value) = read {
                        *counter.lock() = value + 1;
                        Poll::Ready(())
                    } else {
                        read = Some(*counter.lock());
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                });
                let (task, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, future)
                    .expect("create split read/write task");
                runtime.scheduler.lock().schedule(task, 0);
            }
        })
        .expect("supported configuration");

    // The six linear extensions of A-read < A-write and B-read < B-write
    // include both serial increments and the planted lost-update defect.
    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 6);
    let actual: BTreeSet<_> = outcomes.borrow().iter().map(|value| *value.lock()).collect();
    assert_eq!(actual, BTreeSet::from([1, 2]));
}

#[test]
fn exact_prefix_replays_the_same_choices_and_rejects_changed_enabled_sets() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    let report = explorer
        .explore(|runtime| one_poll_tasks(runtime, 3, Arc::new(Mutex::new(Vec::new()))))
        .unwrap();
    let original = &report.runs[1];
    let replay = explorer
        .replay(&original.execution, |runtime| {
            one_poll_tasks(runtime, 3, Arc::new(Mutex::new(Vec::new())));
        })
        .unwrap();
    assert_eq!(replay.termination, ExactScheduleTermination::Quiescent);
    assert_eq!(replay.execution, original.execution);
    assert_eq!(
        replay.schedule.unwrap().terminal_schedule_hash(),
        original.schedule.as_ref().unwrap().terminal_schedule_hash()
    );

    for change_time in [false, true] {
        let polled = Arc::new(Mutex::new(Vec::new()));
        let divergent = explorer
            .replay(&original.execution, |runtime| {
                one_poll_tasks(runtime, if change_time { 3 } else { 2 }, Arc::clone(&polled));
                if change_time {
                    runtime.advance_time(1);
                }
            })
            .unwrap();
        assert_eq!(
            divergent.termination,
            ExactScheduleTermination::PrefixDiverged { decision: 0 }
        );
        assert!(polled.lock().is_empty(), "mismatched choice was not polled");
        assert!(divergent.schedule.is_none());
        assert!(divergent.execution.decisions().is_empty());
    }

    let too_short = explorer.replay(&original.execution, |_| {}).unwrap();
    assert_eq!(
        too_short.termination,
        ExactScheduleTermination::PrefixDiverged { decision: 0 }
    );
    assert!(too_short.schedule.is_none());
}

#[test]
fn exact_explorer_reports_each_exhaustion_without_claiming_completion() {
    let setup = |runtime: &mut LabRuntime| {
        one_poll_tasks(runtime, 3, Arc::new(Mutex::new(Vec::new())));
    };
    let mut bounded = limits();
    bounded.max_runs = 1;
    let run_limited = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
        .explore(setup)
        .unwrap();
    assert_eq!(run_limited.termination, ExactScheduleSearchTermination::RunLimit);
    assert_eq!(run_limited.completed_schedules(), 1);
    assert!(!run_limited.pending_prefixes.is_empty());

    bounded = limits();
    bounded.max_pending_prefixes = 1;
    let queue_limited = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
        .explore(setup)
        .unwrap();
    assert_eq!(
        queue_limited.termination,
        ExactScheduleSearchTermination::PrefixQueueLimit
    );
    assert!(queue_limited.omitted_prefixes > 0);

    for dispatch_limit in [false, true] {
        bounded = limits();
        if dispatch_limit {
            bounded.max_dispatches_per_run = 1;
        } else {
            bounded.max_work_per_run = 1;
        }
        let report = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
            .explore(setup)
            .unwrap();
        assert_eq!(report.termination, ExactScheduleSearchTermination::IncompleteRun);
        assert_eq!(report.completed_schedules(), 0);
        let expected = if dispatch_limit {
            ExactScheduleTermination::DispatchLimit
        } else {
            ExactScheduleTermination::WorkLimit
        };
        assert!(report.runs.iter().all(|run| run.termination == expected));
        assert!(report.runs.iter().all(|run| run.schedule.is_none()));
    }
}

fn sleeping_task(runtime: &mut LabRuntime, observed: Arc<Mutex<Vec<Time>>>) {
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let (task, _handle) = runtime
        .state
        .create_task(region, Budget::INFINITE, async move {
            let cx = crate::Cx::current().expect("lab task context");
            crate::time::sleep(cx.now(), Duration::from_millis(2)).await;
            observed.lock().push(cx.now());
        })
        .expect("create sleeping task");
    runtime.scheduler.lock().schedule(task, 0);
}

#[test]
fn exact_explorer_timer_completion_has_a_strictly_replayable_receipt() {
    let config = LabConfig::new(43);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let report = ExactScheduleExplorer::new(config.clone(), limits())
        .explore(|runtime| sleeping_task(runtime, Arc::clone(&observed)))
        .unwrap();
    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 1);
    assert_eq!(*observed.lock(), vec![Time::from_millis(2)]);

    let mut replay = LabRuntime::new_with_task_causality(config);
    let replayed = Arc::new(Mutex::new(Vec::new()));
    sleeping_task(&mut replay, Arc::clone(&replayed));
    let schedule = report.runs[0].schedule.as_ref().unwrap();
    let receipt = replay
        .run_forced_schedule(schedule, ForcedScheduleLimits::new(64, 256))
        .expect("timer receipt replays");
    assert!(receipt.quiescent);
    assert_eq!(receipt.terminal_nanos, Time::from_millis(2).as_nanos());
    assert_eq!(*replayed.lock(), *observed.lock());
}

#[test]
fn parked_work_and_silent_timer_hops_are_explicitly_incomplete() {
    for silent_timer in [false, true] {
        let report = ExactScheduleExplorer::new(LabConfig::new(42), limits())
            .explore(|runtime| {
                let region = runtime.state.create_root_region(Budget::INFINITE);
                let (task, _handle) = runtime
                    .state
                    .create_task(region, Budget::INFINITE, std::future::pending::<()>())
                    .expect("create parked task");
                runtime.scheduler.lock().schedule(task, 0);
                if silent_timer {
                    let timer = runtime.state.timer_driver_handle().unwrap();
                    let _ = timer.register(Time::from_millis(1), Waker::noop().clone());
                }
            })
            .unwrap();
        assert_eq!(report.termination, ExactScheduleSearchTermination::IncompleteRun);
        assert_eq!(report.completed_schedules(), 0);
        let run = &report.runs[0];
        assert!(!run.lab.quiescent);
        assert!(run.schedule.is_none());
        if silent_timer {
            assert!(matches!(run.termination, ExactScheduleTermination::Unsupported { .. }));
        } else {
            assert_eq!(run.termination, ExactScheduleTermination::Stalled);
        }
    }
}

#[test]
fn exact_explorer_rejects_invalid_configuration_before_factory() {
    let forbidden = |_: &mut LabRuntime| panic!("invalid configuration invoked the factory");
    let multiple = ExactScheduleExplorer::new(LabConfig::new(42).worker_count(2), limits());
    assert!(matches!(
        multiple.explore(forbidden),
        Err(ExactScheduleConfigError::MultipleWorkers)
    ));
    let chaos = ExactScheduleExplorer::new(LabConfig::new(42).with_light_chaos(), limits());
    assert!(matches!(
        chaos.explore(forbidden),
        Err(ExactScheduleConfigError::ChaosEnabled)
    ));
    let mut zero = limits();
    zero.max_inventory_entries = 0;
    assert!(matches!(
        ExactScheduleExplorer::new(LabConfig::new(42), zero).explore(forbidden),
        Err(ExactScheduleConfigError::ZeroLimit)
    ));
}

#[test]
fn exact_explorer_rechecks_factory_state_and_inventory_bounds() {
    let explorer = ExactScheduleExplorer::new(LabConfig::new(42), limits());
    let started = explorer
        .explore(|runtime| {
            one_poll_tasks(runtime, 2, Arc::new(Mutex::new(Vec::new())));
            runtime.step_for_test();
        })
        .unwrap();
    assert!(matches!(
        started.runs[0].termination,
        ExactScheduleTermination::ReplayRejected(ForcedScheduleError::RuntimeAlreadyStarted { .. })
    ));
    assert!(started.runs[0].schedule.is_none());

    let paused = explorer
        .explore(|runtime| {
            one_poll_tasks(runtime, 1, Arc::new(Mutex::new(Vec::new())));
            runtime.pause_clock();
        })
        .unwrap();
    assert!(matches!(
        paused.runs[0].termination,
        ExactScheduleTermination::Unsupported { .. }
    ));
    assert!(paused.runs[0].execution.decisions().is_empty());

    let mut bounded = limits();
    bounded.max_inventory_entries = 1;
    let inventory = ExactScheduleExplorer::new(LabConfig::new(42), bounded)
        .explore(|runtime| one_poll_tasks(runtime, 2, Arc::new(Mutex::new(Vec::new()))))
        .unwrap();
    assert!(matches!(
        inventory.runs[0].termination,
        ExactScheduleTermination::Unsupported { .. }
    ));
    assert!(inventory.runs[0].execution.decisions().is_empty());
    assert_eq!(inventory.termination, ExactScheduleSearchTermination::IncompleteRun);
}

#[test]
fn exact_explorer_rejects_production_replay_installed_by_factory() {
    let config = LabConfig::new(42).with_default_replay_recording();
    let mut source = LabRuntime::new_with_task_causality(config.clone());
    one_poll_tasks(&mut source, 1, Arc::new(Mutex::new(Vec::new())));
    source.run_until_quiescent();
    let schedule = source.recorded_production_schedule().expect("source schedule");
    let polled = Arc::new(Mutex::new(Vec::new()));
    let report = ExactScheduleExplorer::new(config, limits())
        .explore(|runtime| {
            one_poll_tasks(runtime, 1, Arc::clone(&polled));
            runtime
                .replay_production_schedule_prefix(
                    &schedule,
                    crate::lab::runtime::ProductionReplayOptions::default(),
                )
                .expect("install conflicting replay before any poll");
        })
        .unwrap();
    assert_eq!(report.termination, ExactScheduleSearchTermination::IncompleteRun);
    assert!(matches!(
        report.runs[0].termination,
        ExactScheduleTermination::Unsupported { .. }
    ));
    assert!(polled.lock().is_empty());
    assert!(report.runs[0].execution.decisions().is_empty());
    assert!(report.runs[0].schedule.is_none());
}

#[test]
fn exact_explorer_pending_obligation_posts_preserve_strict_timer_receipts() {
    struct ScheduleTask {
        task: crate::types::TaskId,
        scheduler: Arc<Mutex<crate::lab::runtime::LabScheduler>>,
    }

    impl std::task::Wake for ScheduleTask {
        fn wake(self: Arc<Self>) {
            self.scheduler.lock().schedule(self.task, 0);
        }
    }

    fn setup(runtime: &mut LabRuntime, observed: Arc<Mutex<Vec<Time>>>) {
        let region = runtime.state.create_root_region(Budget::INFINITE);
        let (task, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                observed.lock().push(crate::Cx::current().unwrap().now());
            })
            .expect("create timer-scheduled task");
        let cx = runtime.state.task(task).unwrap().cx.as_ref().unwrap().clone();
        let (sender, _receiver) = crate::channel::oneshot::channel::<()>();
        drop(sender.reserve_checked(&cx).expect("checked reservation"));
        assert!(runtime.state.has_pending_obligation_posts());
        assert!(runtime.scheduler.lock().is_empty());
        let wake = Waker::from(Arc::new(ScheduleTask {
            task,
            scheduler: Arc::clone(&runtime.scheduler),
        }));
        let timer = runtime.state.timer_driver_handle().unwrap();
        let _ = timer.register(Time::from_millis(2), wake);
    }

    let config = LabConfig::new(43);
    let observed = Arc::new(Mutex::new(Vec::new()));
    let report = ExactScheduleExplorer::new(config.clone(), limits())
        .explore(|runtime| setup(runtime, Arc::clone(&observed)))
        .unwrap();
    assert_eq!(report.termination, ExactScheduleSearchTermination::SearchExhausted);
    assert_eq!(report.completed_schedules(), 1);
    let run = &report.runs[0];
    assert_eq!(run.execution.decisions().len(), 1);
    assert_eq!(run.execution.decisions()[0].selected().at_step(), 1);
    assert_eq!(*observed.lock(), vec![Time::from_millis(2)]);
    let schedule = run.schedule.as_ref().expect("complete receipt");

    let replayed = Arc::new(Mutex::new(Vec::new()));
    let mut runtime = LabRuntime::new_with_task_causality(config);
    setup(&mut runtime, Arc::clone(&replayed));
    let replay = runtime
        .run_forced_schedule(schedule, ForcedScheduleLimits::new(64, 256))
        .expect("pending posts retain the existing strict replay chronology");
    assert!(replay.quiescent);
    assert_eq!(replay.schedule_hash, schedule.terminal_schedule_hash());
    assert_eq!(*replayed.lock(), *observed.lock());
}
