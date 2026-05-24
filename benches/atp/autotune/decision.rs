#![allow(missing_docs)]

use asupersync::atp::{
    AtpAutotunePolicy, AtpAutotuneSettings, AtpAutotuneTelemetry, AtpAutotuneTelemetryReport,
};
use criterion::{BatchSize, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

const MIB: u64 = 1_048_576;

fn clean_path_report() -> AtpAutotuneTelemetryReport {
    let mut telemetry =
        AtpAutotuneTelemetry::new("bench-atp-autotune-clean", "bench-transfer-clean")
            .with_sample_count(64);
    telemetry.rtt_micros = Some(35_000);
    telemetry.loss_permille = Some(1);
    telemetry.pto_micros = Some(90_000);
    telemetry.congestion_window_bytes = Some(256 * MIB);
    telemetry.in_flight_bytes = Some(32 * MIB);
    telemetry.send_buffer_queued_bytes = Some(MIB / 2);
    telemetry.receive_buffer_queued_bytes = Some(MIB / 4);
    telemetry.disk_read_lag_micros = Some(12_000);
    telemetry.disk_write_lag_micros = Some(14_000);
    telemetry.encode_backlog_symbols = Some(128);
    telemetry.decode_backlog_symbols = Some(96);
    telemetry.repair_roi_permille = Some(850);
    telemetry.relay_cost_micros_per_mib = Some(80_000);
    telemetry.migration_events = Some(0);
    telemetry.to_report()
}

fn bench_clean_path_decision_receipt(c: &mut Criterion) {
    let policy = AtpAutotunePolicy::default();
    let current = AtpAutotuneSettings::default();
    let report = clean_path_report();

    let mut group = c.benchmark_group("atp_autotune_decision");
    group.throughput(Throughput::Elements(1));
    group.sample_size(20);

    group.bench_function("clean_path_decide_with_receipt_json", |b| {
        b.iter_batched_ref(
            || report.clone(),
            |report| {
                let telemetry = report
                    .clone()
                    .into_telemetry()
                    .expect("clean benchmark telemetry aggregates");
                let receipt = policy.decide_with_receipt(black_box(current), black_box(&telemetry));
                receipt
                    .validate_for_consumers()
                    .expect("clean benchmark receipt validates");
                let json =
                    serde_json::to_vec(&receipt).expect("clean benchmark receipt serializes");
                black_box(json.len());
            },
            BatchSize::SmallInput,
        );
    });

    group.finish();
}

criterion_group!(benches, bench_clean_path_decision_receipt);
criterion_main!(benches);
