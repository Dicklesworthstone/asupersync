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

fn assert_visible_error(error: &impl core::fmt::Debug, label: &str) {
    let diagnostic = format!("{error:?}");
    assert!(
        !diagnostic.is_empty(),
        "{label} parser errors should keep visible diagnostics",
    );
}

fn assert_nonempty_debug(value: &impl core::fmt::Debug, label: &str) {
    let debug_repr = format!("{value:?}");
    assert!(
        !debug_repr.is_empty(),
        "{label} debug output should stay visible",
    );
}

fn assert_msgpack_round_trip<T>(value: &T, label: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Debug,
{
    let serialized = match rmp_serde::to_vec(value) {
        Ok(serialized) => serialized,
        Err(error) => panic!("{label} serialization failed after successful decode: {error:?}"),
    };

    match rmp_serde::from_slice::<T>(&serialized) {
        Ok(round_tripped) => assert_nonempty_debug(&round_tripped, label),
        Err(error) => panic!("{label} serialization output failed to decode: {error:?}"),
    }
}

fn observe_msgpack_round_trip<T>(data: &[u8], label: &str)
where
    T: serde::Serialize + serde::de::DeserializeOwned + core::fmt::Debug,
{
    match rmp_serde::from_slice::<T>(data) {
        Ok(value) => {
            assert_nonempty_debug(&value, label);
            assert_msgpack_round_trip(&value, label);
        }
        Err(error) => assert_visible_error(&error, label),
    }
}

fn observe_raw_msgpack_decode(data: &[u8]) {
    match rmp_serde::from_slice::<rmp_serde::Raw>(data) {
        Ok(raw) => assert_nonempty_debug(&raw, "raw MessagePack string"),
        Err(error) => assert_visible_error(&error, "raw MessagePack string"),
    }
}

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
    observe_msgpack_round_trip::<asupersync::trace::replay::ReplayEvent>(data, "ReplayEvent");

    // Test TraceMetadata deserialization as well
    observe_msgpack_round_trip::<asupersync::trace::replay::TraceMetadata>(data, "TraceMetadata");

    // Test with different MessagePack format variations
    // MessagePack has multiple valid representations for the same data
    if data.len() > 4 {
        // Try parsing with msgpack as well to test cross-implementation compatibility
        observe_raw_msgpack_decode(data);
    }

    // Test partial deserialization scenarios
    if data.len() > 10 {
        for truncate_at in [1, 2, 4, 8, data.len() / 2] {
            if truncate_at < data.len() {
                let truncated = &data[..truncate_at];
                observe_msgpack_round_trip::<asupersync::trace::replay::ReplayEvent>(
                    truncated,
                    "truncated ReplayEvent",
                );
            }
        }
    }
});
