#![allow(missing_docs)]

use asupersync::atp::{
    AtpAutotuneApplicationOutcome, AtpAutotuneApplicationState, AtpAutotuneDecisionOutcome,
    AtpAutotuneLimits, AtpAutotunePolicy, AtpAutotuneReceiptStatus, AtpAutotuneSettings,
    AtpAutotuneTelemetry,
};

const MIB: u64 = 1_048_576;

fn constrained_limits() -> AtpAutotuneLimits {
    AtpAutotuneLimits {
        min_in_flight_bytes: 4 * MIB,
        max_in_flight_bytes: 128 * MIB,
        min_stream_count: 1,
        max_stream_count: 16,
        min_chunk_size_bytes: 128 * 1_024,
        max_chunk_size_bytes: 4 * 1_048_576,
        min_repair_symbols_per_second: 128,
        max_repair_symbols_per_second: 2_048,
    }
}

fn resource_constrained_window() -> AtpAutotuneTelemetry {
    let mut telemetry = AtpAutotuneTelemetry::new(
        "regression-atp-autotune-resource-constrained",
        "transfer-resource-constrained",
    )
    .with_sample_count(64);
    telemetry.rtt_micros = Some(410_000);
    telemetry.loss_permille = Some(80);
    telemetry.pto_micros = Some(650_000);
    telemetry.congestion_window_bytes = Some(32 * MIB);
    telemetry.in_flight_bytes = Some(128 * MIB);
    telemetry.send_buffer_queued_bytes = Some(32 * MIB);
    telemetry.receive_buffer_queued_bytes = Some(24 * MIB);
    telemetry.disk_read_lag_micros = Some(350_000);
    telemetry.disk_write_lag_micros = Some(420_000);
    telemetry.encode_backlog_symbols = Some(32_768);
    telemetry.decode_backlog_symbols = Some(24_576);
    telemetry.repair_roi_permille = Some(200);
    telemetry.relay_cost_micros_per_mib = Some(900_000);
    telemetry.migration_events = Some(2);
    telemetry
}

#[test]
fn resource_constrained_profile_degrades_without_escaping_safety_bounds() {
    let limits = constrained_limits();
    let current = limits.clamp(AtpAutotuneSettings::new(
        256 * MIB,
        64,
        16 * 1_048_576,
        4_096,
    ));
    let policy = AtpAutotunePolicy {
        limits,
        ..AtpAutotunePolicy::default()
    };
    let telemetry = resource_constrained_window();

    let receipt = policy.decide_with_receipt(current, &telemetry);

    receipt
        .validate_for_consumers()
        .expect("resource-constrained receipt remains consumable");
    assert_eq!(receipt.consumer_status, AtpAutotuneReceiptStatus::Degraded);
    assert_eq!(receipt.outcome, AtpAutotuneDecisionOutcome::PressureBackoff);
    assert!(receipt.decision.fail_closed);
    assert!(
        receipt
            .decision
            .bottlenecks
            .iter()
            .any(|signal| signal.observed > signal.threshold),
        "profile should carry explicit pressure evidence"
    );

    let next = receipt.decision.settings;
    assert!(next.in_flight_bytes <= current.in_flight_bytes);
    assert!(next.stream_count <= current.stream_count);
    assert!(next.chunk_size_bytes <= current.chunk_size_bytes);
    assert!(next.repair_symbols_per_second <= current.repair_symbols_per_second);
    assert!(next.in_flight_bytes >= limits.min_in_flight_bytes);
    assert!(next.stream_count >= limits.min_stream_count);
    assert!(next.chunk_size_bytes >= limits.min_chunk_size_bytes);
    assert!(next.repair_symbols_per_second >= limits.min_repair_symbols_per_second);

    let mut state = AtpAutotuneApplicationState::new(current, limits);
    let application = state.apply_decision_receipt(receipt);
    assert_eq!(
        application.outcome,
        AtpAutotuneApplicationOutcome::AppliedPressureBackoff
    );
    assert_eq!(
        application.consumer_status,
        AtpAutotuneReceiptStatus::Degraded
    );
    assert_eq!(application.applied_settings, next);
    assert_eq!(state.settings, next);
}
