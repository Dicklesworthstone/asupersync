#![no_main]

use arbitrary::Arbitrary;
use asupersync::types::{CancelPhase, CancelReason, CancelWitness, RegionId, TaskId};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct CancelWitnessSpec {
    task_id_raw: u64,
    region_id_raw: u64,
    epoch: u64,
    phase_raw: u8,
    reason_raw: u8,
}

fn task_id_from_raw(raw: u64) -> TaskId {
    TaskId::new_for_test(raw as u32, (raw >> 32) as u32)
}

fn region_id_from_raw(raw: u64) -> RegionId {
    RegionId::new_for_test(raw as u32, (raw >> 32) as u32)
}

fuzz_target!(|spec: CancelWitnessSpec| {
    // Generate valid TaskId and RegionId from raw values
    let task_id = task_id_from_raw(spec.task_id_raw);
    let region_id = region_id_from_raw(spec.region_id_raw);

    // Generate CancelPhase from raw u8
    let phase = match spec.phase_raw % 4 {
        0 => CancelPhase::Requested,
        1 => CancelPhase::Cancelling,
        2 => CancelPhase::Finalizing,
        3 => CancelPhase::Completed,
        _ => unreachable!(), // ubs:ignore — modulo 4 ensures this is never reached
    };

    // Generate CancelReason from raw u8
    let reason = match spec.reason_raw % 6 {
        0 => CancelReason::user("fuzz user cancellation"),
        1 => CancelReason::timeout(),
        2 => CancelReason::parent_cancelled(),
        3 => CancelReason::resource_unavailable(),
        4 => CancelReason::fail_fast().with_message("fuzz fail-fast"),
        5 => CancelReason::shutdown(),
        _ => unreachable!(), // ubs:ignore — modulo 6 ensures this is never reached
    };

    // Create CancelWitness
    let witness = CancelWitness::new(task_id, region_id, spec.epoch, phase, reason.clone());

    // Test JSON serialization round-trip.
    let json = serde_json::to_string(&witness).unwrap_or_else(|err| {
        panic!("CancelWitness JSON serialization failed for {witness:?}: {err}")
    });
    let deserialized = serde_json::from_str::<CancelWitness>(&json).unwrap_or_else(|err| {
        panic!("CancelWitness JSON deserialization failed for {witness:?} from {json:?}: {err}")
    });
    assert_eq!(witness, deserialized); // ubs:ignore — fuzz test validation

    // Test byte serialization round-trip through the same JSON representation.
    let bytes = serde_json::to_vec(&witness).unwrap_or_else(|err| {
        panic!("CancelWitness JSON byte serialization failed for {witness:?}: {err}")
    });
    let deserialized = serde_json::from_slice::<CancelWitness>(&bytes).unwrap_or_else(|err| {
        panic!("CancelWitness JSON byte deserialization failed for {witness:?}: {err}")
    });
    assert_eq!(witness, deserialized); // ubs:ignore — fuzz test validation

    // Test witness validation if there are methods available
    // This covers snapshot serialization path mentioned in the bead
    let _clone = witness.clone(); // ubs:ignore — fuzz test validation
    let _debug = format!("{:?}", witness);

    // Test that all fields are accessible and consistent
    assert_eq!(witness.task_id, task_id); // ubs:ignore — fuzz test validation
    assert_eq!(witness.region_id, region_id); // ubs:ignore — fuzz test validation
    assert_eq!(witness.epoch, spec.epoch); // ubs:ignore — fuzz test validation
    assert_eq!(witness.phase, phase); // ubs:ignore — fuzz test validation
    assert_eq!(witness.reason, reason); // ubs:ignore — fuzz test validation
});
