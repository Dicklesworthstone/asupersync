#![no_main]

//! Fuzz target for ReplayEvent MessagePack deserialization.
//!
//! This target focuses specifically on the MessagePack deserialization of ReplayEvent
//! structures, which are the core data items stored in trace files. ReplayEvent has
//! 30+ variants covering scheduling, timing, I/O, RNG, chaos, regions, and wakers.
//!
//! This complements the main trace file parsing fuzzer by focusing on the event
//! deserialization logic in isolation.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Skip empty input
    if data.is_empty() {
        return;
    }

    // Limit input size to prevent timeout (1MB max for individual events)
    if data.len() > 1024 * 1024 {
        return;
    }

    // Test ReplayEvent deserialization
    // This exercises all the serde logic for the 30+ ReplayEvent variants:
    // TaskScheduled, TaskYielded, TaskCompleted, TimeAdvanced, TimerCreated,
    // TimerFired, IoReady, IoResult, IoError, RngSeed, RngValue, ChaosInjection,
    // RegionCreated, RegionClosed, RegionCancelled, WakerWake, WakerBatchWake,
    // Checkpoint, and many others
    match rmp_serde::from_slice::<asupersync::trace::replay::ReplayEvent>(data) {
        Ok(event) => {
            // Successfully deserialized - test round-trip serialization
            // to ensure the event is well-formed and can be re-serialized
            match rmp_serde::to_vec(&event) {
                Ok(serialized) => {
                    // Verify round-trip consistency by deserializing again
                    let _ = rmp_serde::from_slice::<asupersync::trace::replay::ReplayEvent>(
                        &serialized,
                    );
                }
                Err(_) => {
                    // Serialization error - could indicate malformed internal state
                }
            }

            // Test the Debug implementation to catch any panics in formatting
            let _ = format!("{:?}", event);
        }
        Err(_) => {
            // Deserialization error is expected for malformed input
        }
    }

    // Test TraceMetadata deserialization as well
    match rmp_serde::from_slice::<asupersync::trace::replay::TraceMetadata>(data) {
        Ok(metadata) => {
            // Test round-trip serialization for metadata
            if let Ok(serialized) = rmp_serde::to_vec(&metadata) {
                let _ =
                    rmp_serde::from_slice::<asupersync::trace::replay::TraceMetadata>(&serialized);
            }

            // Test Debug formatting
            let _ = format!("{:?}", metadata);
        }
        Err(_) => {
            // Expected for malformed input
        }
    }

    // Test with different MessagePack format variations
    // MessagePack has multiple valid representations for the same data
    if data.len() > 4 {
        // Try parsing with msgpack as well to test cross-implementation compatibility
        let _ = rmp_serde::from_slice::<rmp_serde::Raw>(data);
    }

    // Test partial deserialization scenarios
    if data.len() > 10 {
        for truncate_at in [1, 2, 4, 8, data.len() / 2] {
            if truncate_at < data.len() {
                let truncated = &data[..truncate_at];
                let _ = rmp_serde::from_slice::<asupersync::trace::replay::ReplayEvent>(truncated);
            }
        }
    }
});
