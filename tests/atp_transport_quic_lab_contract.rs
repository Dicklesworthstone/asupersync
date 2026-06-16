//! H3 LabRuntime contract coverage for the ATP-over-QUIC transport.
//!
//! This target is intentionally separate from the active Phase-B scaffold and
//! native-link tests. It pins a narrow lab-runtime cancellation proof for the
//! public transport boundary without touching the in-flight sender/receiver
//! implementation files.

#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use asupersync::Cx;
use asupersync::lab::{LabConfig, run_async_under_lab_with_config};
use asupersync::net::atp::transport_quic::{
    QuicConfig, QuicTransportError, ReceiveReport, SendReport, receive_once, send_path,
};
use asupersync::net::quic_native::{ManagedEndpointConfig, ManagedQuicEndpoint};
use asupersync::types::{CancelKind, CancelReason};
use serde_json::Value;

fn trusted_quic_config() -> QuicConfig {
    QuicConfig::default().allow_unauthenticated_for_trusted_transport()
}

fn lab_config(seed: u64) -> LabConfig {
    let mut config = LabConfig::new(seed)
        .worker_count(2)
        .trace_capacity(4096)
        .with_cancellation_oracle(true)
        .panic_on_cancellation_violation(true);
    config.max_steps = Some(1_000);
    config
}

fn lab_contract_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn cancelled_send_path_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_reason(
            CancelReason::new(CancelKind::User)
                .with_message("H3 transport_quic lab cancellation proof"),
        );
        let addr: SocketAddr = "127.0.0.1:9".parse().expect("loopback discard addr");
        let untouched_source = PathBuf::from("h3-lab-cancel-should-not-touch-source.bin");
        let result: Result<SendReport, QuicTransportError> = send_path(
            &cancelled_cx,
            addr,
            &untouched_source,
            trusted_quic_config(),
            "h3-lab-sender",
        )
        .await;

        assert!(
            matches!(result, Err(QuicTransportError::Cancelled)),
            "cancelled lab send_path must fail closed before transfer work, got {result:?}"
        );
    });

    assert!(report.quiescent, "lab run must end quiescent: {report:?}");
    assert!(
        report.oracle_report.all_passed(),
        "lab oracles must pass: {:?}",
        report.oracle_report.to_json()
    );
    assert!(
        report.invariant_violations.is_empty(),
        "lab invariant violations: {:?}",
        report.invariant_violations
    );
    assert!(
        report.temporal_invariant_failures.is_empty(),
        "temporal invariant failures: {:?}",
        report.temporal_invariant_failures
    );
    assert!(
        report.lab_test_passed(),
        "lab test contract failed: {report:?}"
    );

    report.to_json()
}

fn empty_receive_once_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let listen: SocketAddr = "127.0.0.1:0".parse().expect("loopback bind addr");
        let mut endpoint = ManagedQuicEndpoint::bind(
            &cx,
            listen,
            ManagedEndpointConfig {
                is_server: true,
                ..ManagedEndpointConfig::default()
            },
        )
        .await
        .expect("managed endpoint binds under lab");
        let destination = PathBuf::from("h3-lab-empty-receive-destination");

        let result: Result<ReceiveReport, QuicTransportError> = receive_once(
            &cx,
            &mut endpoint,
            &destination,
            trusted_quic_config(),
            "h3-lab-receiver",
        )
        .await;

        match result {
            Err(QuicTransportError::Timeout {
                operation: "receive_once accept",
                ..
            }) => {}
            Ok(report) => panic!("empty lab receive_once must not fake success: {report:?}"),
            Err(err) => panic!("empty lab receive_once must fail as accept timeout, got {err:?}"),
        }
    });

    assert!(report.quiescent, "lab run must end quiescent: {report:?}");
    assert!(
        report.oracle_report.all_passed(),
        "lab oracles must pass: {:?}",
        report.oracle_report.to_json()
    );
    assert!(
        report.invariant_violations.is_empty(),
        "lab invariant violations: {:?}",
        report.invariant_violations
    );
    assert!(
        report.temporal_invariant_failures.is_empty(),
        "temporal invariant failures: {:?}",
        report.temporal_invariant_failures
    );
    assert!(
        report.lab_test_passed(),
        "lab test contract failed: {report:?}"
    );

    report.to_json()
}

#[test]
fn cancelled_send_path_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = cancelled_send_path_lab_report(0xb0c8_9003);
    let second = cancelled_send_path_lab_report(0xb0c8_9003);

    assert_eq!(
        first, second,
        "same-seed transport_quic lab cancellation run must replay identically"
    );
}

#[test]
fn empty_receive_once_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = empty_receive_once_lab_report(0xb0c8_9004);
    let second = empty_receive_once_lab_report(0xb0c8_9004);

    assert_eq!(
        first, second,
        "same-seed transport_quic empty receive_once lab run must replay identically"
    );
}
