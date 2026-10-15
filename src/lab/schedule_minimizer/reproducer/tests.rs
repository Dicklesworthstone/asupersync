use super::*;
use crate::lab::schedule_minimizer::{ScheduleMinimizerLimits, minimize_schedule};
use crate::lab::{LabConfig, LabRuntime};
use crate::types::Budget;
use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;

const FAILURE: FailureKey = FailureKey([7; 32]);
const WORKLOAD: WorkloadKey = WorkloadKey([11; 32]);

fn workload(seed: u64) -> (LabRuntime, (Arc<AtomicUsize>, impl Sized)) {
    let mut lab = LabRuntime::new(LabConfig::new(seed).max_steps(40));
    let root = lab.state.create_root_region(Budget::INFINITE);
    let polls = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&polls);
    let (task, handle) = lab
        .state
        .create_task(root, Budget::INFINITE, poll_fn(move |cx| {
            if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }))
        .unwrap();
    lab.scheduler.lock().schedule(task, Budget::INFINITE.priority);
    (lab, (polls, handle))
}

fn source(seed: u64) -> ForcedSchedule {
    let (mut lab, _fixture) = workload(seed);
    lab.start_forced_schedule_recording(40).unwrap();
    lab.run_until_quiescent();
    let schedule = lab.finish_forced_schedule_recording().unwrap();
    assert_eq!(schedule.dispatches().len(), 2);
    assert!(schedule.terminal_quiescent());
    schedule
}

fn limits() -> ReproducerLimits {
    ReproducerLimits {
        max_encoded_bytes: 65_536,
        max_source_dispatches: 40,
        max_retained_dispatches: 40,
        max_decoded_dispatch_bytes: 65_536,
    }
}

fn minimized(schedule: &ForcedSchedule) -> MinimizedSchedule {
    let seed = schedule.seed();
    minimize_schedule(
        schedule,
        ScheduleMinimizerLimits {
            max_source_dispatches: 40,
            max_attempts: 2,
            max_work_per_attempt: 100,
            max_total_work: 200,
            confirmations: 1,
        },
        || workload(seed),
        |_, fixture, report| {
            assert!(report.quiescent);
            (fixture.0.load(Ordering::SeqCst) == 2).then_some(FAILURE)
        },
    )
    .unwrap()
}

fn recipe() -> ScheduleReproducer {
    let schedule = source(13);
    let result = minimized(&schedule);
    ScheduleReproducer::from_minimized(schedule, &result, WORKLOAD, limits()).unwrap()
}

fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - CHECKSUM_BYTES;
    let checksum = digest(CHECKSUM_DOMAIN, &bytes[..end]);
    bytes[end..].copy_from_slice(&checksum);
}

#[test]
fn actual_minimization_round_trips_an_executable_subsequence() {
    let original = recipe();
    let bytes = original.to_canonical_bytes(limits().max_encoded_bytes).unwrap();
    let decoded = ScheduleReproducer::try_from_canonical_bytes(&bytes, limits()).unwrap();
    assert_eq!(decoded.to_canonical_bytes(bytes.len()).unwrap(), bytes);
    assert_eq!(decoded.workload(), WORKLOAD);
    assert_eq!(decoded.failure(), FAILURE);
    assert_eq!(decoded.retained_source_indices(), &[0, 1]);
    let (mut lab, fixture) = workload(decoded.source().seed());
    let candidate = decoded.candidate(100).unwrap();
    let report = lab
        .run_forced_schedule_candidate(
            &candidate,
            ForcedScheduleCandidateLimits::new(40, 40, 100),
        )
        .unwrap();
    assert!(report.lab.quiescent);
    assert_eq!(fixture.0.load(Ordering::SeqCst), 2);
}

#[test]
fn a_minimizer_result_cannot_be_rebound_to_another_source() {
    let result = minimized(&source(13));
    let error = ScheduleReproducer::from_minimized(source(14), &result, WORKLOAD, limits());
    assert!(matches!(error, Err(ReproducerError::ResultSourceMismatch)));
}

#[test]
fn every_truncation_and_trailing_bytes_are_rejected() {
    let bytes = recipe().to_canonical_bytes(65_536).unwrap();
    for len in 0..bytes.len() {
        assert!(ScheduleReproducer::try_from_canonical_bytes(&bytes[..len], limits()).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(matches!(
        ScheduleReproducer::try_from_canonical_bytes(&trailing, limits()),
        Err(ReproducerError::Length)
    ));
}

#[test]
fn every_single_byte_corruption_is_refused() {
    let bytes = recipe().to_canonical_bytes(65_536).unwrap();
    for offset in 0..bytes.len() {
        let mut corrupt = bytes.clone();
        corrupt[offset] ^= 1;
        assert!(ScheduleReproducer::try_from_canonical_bytes(&corrupt, limits()).is_err());
    }
}

#[test]
fn exact_encoded_and_combined_vector_bounds_are_enforced() {
    let recipe = recipe();
    let bytes = recipe.to_canonical_bytes(65_536).unwrap();
    let mut bounds = limits();
    bounds.max_encoded_bytes = bytes.len();
    bounds.max_source_dispatches = 2;
    bounds.max_retained_dispatches = 2;
    bounds.max_decoded_dispatch_bytes =
        2 * std::mem::size_of::<ForcedDispatch>() + 2 * std::mem::size_of::<usize>();
    assert!(ScheduleReproducer::try_from_canonical_bytes(&bytes, bounds).is_ok());
    assert!(matches!(
        recipe.to_canonical_bytes(bytes.len() - 1),
        Err(ReproducerError::ByteLimit)
    ));
    for field in 0..4 {
        let mut reduced = bounds;
        match field {
            0 => reduced.max_encoded_bytes -= 1,
            1 => reduced.max_source_dispatches -= 1,
            2 => reduced.max_retained_dispatches -= 1,
            _ => reduced.max_decoded_dispatch_bytes -= 1,
        }
        assert!(ScheduleReproducer::try_from_canonical_bytes(&bytes, reduced).is_err());
    }
}

#[test]
fn forged_lengths_cannot_overflow_or_trigger_unbounded_allocation() {
    let bytes = recipe().to_canonical_bytes(65_536).unwrap();
    for offset in [12, 20] {
        let mut forged = bytes.clone();
        forged[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        reseal(&mut forged);
        assert!(ScheduleReproducer::try_from_canonical_bytes(&forged, limits()).is_err());
    }
}

#[test]
fn valid_outer_checksum_does_not_hide_a_source_digest_mismatch() {
    let mut bytes = recipe().to_canonical_bytes(65_536).unwrap();
    bytes[92] ^= 1;
    reseal(&mut bytes);
    assert!(matches!(
        ScheduleReproducer::try_from_canonical_bytes(&bytes, limits()),
        Err(ReproducerError::SourceDigest)
    ));
}

#[test]
fn matching_outer_digest_does_not_bypass_the_nested_source_codec() {
    let mut bytes = recipe().to_canonical_bytes(65_536).unwrap();
    let source_end = HEADER_BYTES + read_count(&bytes, 12).unwrap();
    bytes[HEADER_BYTES] ^= 1;
    let source_digest = digest(SOURCE_DOMAIN, &bytes[HEADER_BYTES..source_end]);
    bytes[92..124].copy_from_slice(&source_digest);
    reseal(&mut bytes);
    assert!(matches!(
        ScheduleReproducer::try_from_canonical_bytes(&bytes, limits()),
        Err(ReproducerError::Source(_))
    ));
}

#[test]
fn nonquiescent_source_is_rejected_even_with_all_checksums_recomputed() {
    let mut bytes = recipe().to_canonical_bytes(65_536).unwrap();
    let source_end = HEADER_BYTES + read_count(&bytes, 12).unwrap();
    // The strict source format ends in terminal_quiescent, truncated, checksum.
    bytes[source_end - CHECKSUM_BYTES - 2] = 0;
    let source_checksum = digest(
        b"asupersync.lab.forced-schedule.artifact.v1\0",
        &bytes[HEADER_BYTES..source_end - CHECKSUM_BYTES],
    );
    bytes[source_end - CHECKSUM_BYTES..source_end].copy_from_slice(&source_checksum);
    let source_digest = digest(SOURCE_DOMAIN, &bytes[HEADER_BYTES..source_end]);
    bytes[92..124].copy_from_slice(&source_digest);
    reseal(&mut bytes);
    assert!(matches!(
        ScheduleReproducer::try_from_canonical_bytes(&bytes, limits()),
        Err(ReproducerError::Source(_))
    ));
}

#[test]
fn missing_reordered_and_duplicate_source_indices_are_refused() {
    let bytes = recipe().to_canonical_bytes(65_536).unwrap();
    let indices = HEADER_BYTES + read_count(&bytes, 12).unwrap();
    for pair in [[0_u64, 2], [1, 0], [0, 0]] {
        let mut forged = bytes.clone();
        forged[indices..indices + 8].copy_from_slice(&pair[0].to_le_bytes());
        forged[indices + 8..indices + 16].copy_from_slice(&pair[1].to_le_bytes());
        reseal(&mut forged);
        assert!(matches!(
            ScheduleReproducer::try_from_canonical_bytes(&forged, limits()),
            Err(ReproducerError::Index { position: 1 })
        ));
    }
}

#[test]
fn forged_workload_or_failure_is_a_new_unverified_recipe_not_authentication() {
    let mut bytes = recipe().to_canonical_bytes(65_536).unwrap();
    bytes[28..60].fill(19);
    bytes[60..92].fill(23);
    reseal(&mut bytes);
    let decoded = ScheduleReproducer::try_from_canonical_bytes(&bytes, limits()).unwrap();
    assert_eq!(decoded.workload(), WorkloadKey([19; 32]));
    assert_eq!(decoded.failure(), FailureKey([23; 32]));
    // There is deliberately no verified/pass bit in this type or its codec.
}

#[test]
fn format_version_is_not_downgraded_or_ignored() {
    let mut bytes = recipe().to_canonical_bytes(65_536).unwrap();
    bytes[8..12].copy_from_slice(&(REPRODUCER_VERSION + 1).to_le_bytes());
    reseal(&mut bytes);
    assert!(matches!(
        ScheduleReproducer::try_from_canonical_bytes(&bytes, limits()),
        Err(ReproducerError::Format)
    ));
}
