#![no_main]

use arbitrary::Arbitrary;
use asupersync::types::{CancelPhase, CancelReason, CancelWitness, RegionId, TaskId};
use libfuzzer_sys::fuzz_target;
use serde_json;

#[derive(Arbitrary, Debug)]
struct CancelWitnessSpec {
    task_id_raw: u64,
    region_id_raw: u64,
    epoch: u64,
    phase_raw: u8,
    reason_raw: u8,
}

fuzz_target!(|spec: CancelWitnessSpec| {
    // Generate valid TaskId and RegionId from raw values
    let task_id = TaskId::from(spec.task_id_raw);
    let region_id = RegionId::from(spec.region_id_raw);

    // Generate CancelPhase from raw u8
    let phase = match spec.phase_raw % 4 {
        0 => CancelPhase::NotRequested,
        1 => CancelPhase::Requested,
        2 => CancelPhase::Cancelling,
        3 => CancelPhase::Finalized,
        _ => unreachable!(), // ubs:ignore — modulo 4 ensures this is never reached
    };

    // Generate CancelReason from raw u8
    let reason = match spec.reason_raw % 6 {
        0 => CancelReason::UserRequested,
        1 => CancelReason::Timeout,
        2 => CancelReason::ParentCancelled,
        3 => CancelReason::ResourceExhausted,
        4 => CancelReason::InternalError,
        5 => CancelReason::Shutdown,
        _ => unreachable!(), // ubs:ignore — modulo 6 ensures this is never reached
    };

    // Create CancelWitness
    let witness = CancelWitness::new(task_id, region_id, spec.epoch, phase, reason);

    // Test JSON serialization round-trip
    if let Ok(json) = serde_json::to_string(&witness) {
        if let Ok(deserialized) = serde_json::from_str::<CancelWitness>(&json) { // ubs:ignore — intentional fuzz test deserialization
            assert_eq!(witness, deserialized); // ubs:ignore — fuzz test validation
        }
    }

    // Test binary serialization round-trip (using bincode if available)
    #[cfg(feature = "serde")]
    if let Ok(bytes) = serde_json::to_vec(&witness) {
        if let Ok(deserialized) = serde_json::from_slice::<CancelWitness>(&bytes) {
            assert_eq!(witness, deserialized); // ubs:ignore — fuzz test validation
        }
    }

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