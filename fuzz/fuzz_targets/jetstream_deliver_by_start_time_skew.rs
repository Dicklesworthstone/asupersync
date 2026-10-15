#![no_main]

use arbitrary::Arbitrary;
use asupersync::messaging::jetstream::{
    fuzz_consumer_config_deliver_by_start_time_json, fuzz_format_deliver_by_start_time_rfc3339,
};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Arbitrary, Debug, Clone, Copy)]
struct DeliverByStartTimeInput {
    base_nanos: i64,
    skew_nanos: i64,
    mutation: SkewMutation,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum SkewMutation {
    Raw,
    ZeroBase,
    ZeroSkew,
    CrossEpochBackwards,
    CrossEpochForwards,
    LargePositiveSkew,
    LargeNegativeSkew,
}

impl DeliverByStartTimeInput {
    fn materialize(self) -> (i64, i64) {
        match self.mutation {
            SkewMutation::Raw => (self.base_nanos, self.skew_nanos),
            SkewMutation::ZeroBase => (0, self.skew_nanos),
            SkewMutation::ZeroSkew => (self.base_nanos, 0),
            SkewMutation::CrossEpochBackwards => (500_000_000, -1_500_000_000),
            SkewMutation::CrossEpochForwards => (-500_000_000, 1_500_000_000),
            SkewMutation::LargePositiveSkew => (
                self.base_nanos.saturating_abs(),
                self.skew_nanos.saturating_abs(),
            ),
            SkewMutation::LargeNegativeSkew => (
                -self.base_nanos.saturating_abs(),
                -self.skew_nanos.saturating_abs(),
            ),
        }
    }
}

fn system_time_from_signed_nanos(total_nanos: i64) -> SystemTime {
    if total_nanos >= 0 {
        UNIX_EPOCH + Duration::from_nanos(total_nanos as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(total_nanos.unsigned_abs())
    }
}

fn serialize_start_time(total_nanos: i64) -> (String, String) {
    let time = system_time_from_signed_nanos(total_nanos);
    let formatted = fuzz_format_deliver_by_start_time_rfc3339(time);
    let json = fuzz_consumer_config_deliver_by_start_time_json(time);
    (formatted, json)
}

fn assert_serialization_matches(total_nanos: i64) -> String {
    let serialized = catch_unwind(AssertUnwindSafe(|| serialize_start_time(total_nanos)));
    assert!(
        serialized.is_ok(),
        "DeliverByStartTime serialization panicked for {total_nanos}ns"
    );

    let (formatted, json) = serialized.expect("panic checked above");
    assert!(formatted.ends_with('Z'));
    assert!(formatted.contains('T'));

    let parsed: Value = serde_json::from_str(&json).expect("DeliverByStartTime JSON must parse");
    assert_eq!(
        parsed.get("deliver_policy").and_then(Value::as_str),
        Some("by_start_time")
    );
    assert_eq!(
        parsed.get("opt_start_time").and_then(Value::as_str),
        Some(formatted.as_str())
    );
    formatted
}

fuzz_target!(|input: DeliverByStartTimeInput| {
    let (base_nanos, skew_nanos) = input.materialize();
    let base_formatted = assert_serialization_matches(base_nanos);

    if let Some(skewed_nanos) = base_nanos.checked_add(skew_nanos) {
        let skewed_formatted = assert_serialization_matches(skewed_nanos);

        if skew_nanos > 0 {
            assert!(
                skewed_formatted >= base_formatted,
                "positive clock skew should not move RFC3339 start_time backwards: {base_formatted} -> {skewed_formatted}"
            );
        } else if skew_nanos < 0 {
            assert!(
                skewed_formatted <= base_formatted,
                "negative clock skew should not move RFC3339 start_time forwards: {base_formatted} -> {skewed_formatted}"
            );
        }

        if let Some(restored_nanos) = skewed_nanos.checked_sub(skew_nanos) {
            let restored_formatted = assert_serialization_matches(restored_nanos);
            assert_eq!(restored_nanos, base_nanos);
            assert_eq!(
                restored_formatted, base_formatted,
                "inverse clock skew should restore the original DeliverByStartTime encoding"
            );
        }
    }
});
