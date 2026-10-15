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
use std::time::Duration;

use asupersync::Cx;
use asupersync::lab::{LabConfig, LabRunReport, run_async_under_lab_with_config};
use asupersync::net::atp::transport_quic::{
    QuicConfig, QuicTransportError, ReceiveReport, SendReport, receive_connection, receive_once,
    send_path, serve,
};
use asupersync::net::quic_native::{
    ManagedEndpointConfig, ManagedQuicEndpoint, NativeQuicConnection, NativeQuicConnectionConfig,
};
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

const CORE_H3_ORACLE_INVARIANTS: &[&str] = &[
    "task_leak",
    "obligation_leak",
    "quiescence",
    "loser_drain",
    "cancellation_protocol",
    "ambient_authority",
];

fn assert_transport_lab_report_clean(label: &str, report: &LabRunReport) {
    assert!(
        report.quiescent,
        "{label} lab run must end quiescent: {report:?}"
    );
    assert!(
        report.oracle_report.all_passed(),
        "{label} lab oracles must pass: {:?}",
        report.oracle_report.to_json()
    );
    for invariant in CORE_H3_ORACLE_INVARIANTS {
        let entry = report.oracle_report.entry(invariant).unwrap_or_else(|| {
            panic!("{label} lab report did not check core H3 oracle invariant {invariant}")
        });
        assert!(
            entry.passed,
            "{label} core H3 oracle invariant {invariant} failed: {entry:?}"
        );
    }
    assert!(
        report.invariant_violations.is_empty(),
        "{label} lab invariant violations: {:?}",
        report.invariant_violations
    );
    assert!(
        report.temporal_invariant_failures.is_empty(),
        "{label} temporal invariant failures: {:?}",
        report.temporal_invariant_failures
    );
    assert!(
        report.temporal_counterexample_prefix_len.is_none(),
        "{label} temporal counterexample prefix must be absent for clean H3 lab runs: {:?}",
        report.temporal_counterexample_prefix_len
    );
    assert!(
        report.refinement_firewall_rule_id.is_none(),
        "{label} refinement firewall rule must be absent for clean H3 lab runs: {:?}",
        report.refinement_firewall_rule_id
    );
    assert!(
        report.refinement_counterexample_prefix_len.is_none(),
        "{label} refinement counterexample prefix must be absent for clean H3 lab runs: {:?}",
        report.refinement_counterexample_prefix_len
    );
    assert!(
        !report.refinement_firewall_skipped_due_to_trace_truncation,
        "{label} refinement firewall must not be skipped by trace truncation"
    );
    assert_eq!(
        report.trace_certificate.event_count,
        u64::try_from(report.trace_len).expect("trace length fits in u64"),
        "{label} trace certificate event count must match buffered trace length",
    );
    assert!(
        report.lab_test_passed(),
        "{label} lab test contract failed: {report:?}"
    );
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

    assert_transport_lab_report_clean("cancelled send_path", &report);

    report.to_json()
}

fn invalid_send_path_config_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let addr: SocketAddr = "127.0.0.1:9".parse().expect("loopback discard addr");
        let untouched_source =
            PathBuf::from("h3-lab-invalid-send-config-should-not-touch-source.bin");
        let invalid_config = QuicConfig {
            accept_timeout: Duration::ZERO,
            ..trusted_quic_config()
        };

        let result: Result<SendReport, QuicTransportError> = send_path(
            &cx,
            addr,
            &untouched_source,
            invalid_config,
            "h3-lab-invalid-config-sender",
        )
        .await;

        match result {
            Err(QuicTransportError::Config(message)) => {
                assert!(
                    message.contains("accept_timeout"),
                    "invalid accept timeout should be named in the Config error, got {message:?}"
                );
            }
            Ok(report) => panic!("invalid lab send_path config must not fake success: {report:?}"),
            Err(err) => panic!("invalid lab send_path config must fail as Config, got {err:?}"),
        }
    });

    assert_transport_lab_report_clean("invalid send_path config", &report);

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

    assert_transport_lab_report_clean("empty receive_once", &report);

    report.to_json()
}

fn invalid_receive_once_config_lab_report(seed: u64) -> Value {
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
        let destination = PathBuf::from("h3-lab-invalid-receive-config-destination");
        let invalid_config = QuicConfig {
            accept_timeout: Duration::ZERO,
            ..trusted_quic_config()
        };

        let result: Result<ReceiveReport, QuicTransportError> = receive_once(
            &cx,
            &mut endpoint,
            &destination,
            invalid_config,
            "h3-lab-invalid-config-receiver",
        )
        .await;

        match result {
            Err(QuicTransportError::Config(message)) => {
                assert!(
                    message.contains("accept_timeout"),
                    "invalid accept timeout should be named in the Config error, got {message:?}"
                );
            }
            Ok(report) => {
                panic!("invalid lab receive_once config must not fake success: {report:?}")
            }
            Err(err) => panic!("invalid lab receive_once config must fail as Config, got {err:?}"),
        }
    });

    assert_transport_lab_report_clean("invalid receive_once config", &report);

    report.to_json()
}

fn cancelled_receive_once_lab_report(seed: u64) -> Value {
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
        let destination = PathBuf::from("h3-lab-cancelled-receive-destination");

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_reason(
            CancelReason::new(CancelKind::User)
                .with_message("H3 transport_quic receive lab cancellation proof"),
        );

        let result: Result<ReceiveReport, QuicTransportError> = receive_once(
            &cancelled_cx,
            &mut endpoint,
            &destination,
            trusted_quic_config(),
            "h3-lab-cancelled-receiver",
        )
        .await;

        assert!(
            matches!(result, Err(QuicTransportError::Cancelled)),
            "cancelled lab receive_once must fail closed before accept work, got {result:?}"
        );
    });

    assert_transport_lab_report_clean("cancelled receive_once", &report);

    report.to_json()
}

fn cancelled_receive_connection_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_reason(
            CancelReason::new(CancelKind::User)
                .with_message("H3 transport_quic receive_connection lab cancellation proof"),
        );
        let connection = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer addr");
        let destination = PathBuf::from("h3-lab-cancelled-receive-connection-destination");

        let result: Result<ReceiveReport, QuicTransportError> = receive_connection(
            &cancelled_cx,
            connection,
            peer,
            &destination,
            trusted_quic_config(),
            "h3-lab-cancelled-receive-connection",
        )
        .await;

        assert!(
            matches!(result, Err(QuicTransportError::Cancelled)),
            "cancelled lab receive_connection must fail closed before native receive body, got {result:?}"
        );
    });

    assert_transport_lab_report_clean("cancelled receive_connection", &report);

    report.to_json()
}

fn invalid_receive_connection_config_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let connection = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
        let peer: SocketAddr = "127.0.0.1:9".parse().expect("loopback peer addr");
        let destination = PathBuf::from("h3-lab-invalid-receive-connection-config-destination");
        let invalid_config = QuicConfig {
            accept_timeout: Duration::ZERO,
            ..trusted_quic_config()
        };

        let result: Result<ReceiveReport, QuicTransportError> = receive_connection(
            &cx,
            connection,
            peer,
            &destination,
            invalid_config,
            "h3-lab-invalid-config-receive-connection",
        )
        .await;

        match result {
            Err(QuicTransportError::Config(message)) => {
                assert!(
                    message.contains("accept_timeout"),
                    "invalid accept timeout should be named in the Config error, got {message:?}"
                );
            }
            Ok(report) => {
                panic!("invalid lab receive_connection config must not fake success: {report:?}")
            }
            Err(err) => {
                panic!("invalid lab receive_connection config must fail as Config, got {err:?}")
            }
        }
    });

    assert_transport_lab_report_clean("invalid receive_connection config", &report);

    report.to_json()
}

fn cancelled_serve_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let listen: SocketAddr = "127.0.0.1:0".parse().expect("loopback bind addr");
        let endpoint = ManagedQuicEndpoint::bind(
            &cx,
            listen,
            ManagedEndpointConfig {
                is_server: true,
                ..ManagedEndpointConfig::default()
            },
        )
        .await
        .expect("managed endpoint binds under lab");
        let destination = PathBuf::from("h3-lab-cancelled-serve-destination");

        let cancelled_cx = Cx::for_testing();
        cancelled_cx.set_cancel_reason(
            CancelReason::new(CancelKind::User)
                .with_message("H3 transport_quic serve lab cancellation proof"),
        );

        let callback_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_flag = std::sync::Arc::clone(&callback_called);
        let result = serve(
            &cancelled_cx,
            endpoint,
            destination,
            trusted_quic_config(),
            "h3-lab-cancelled-serve".to_string(),
            move |_result| {
                callback_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            },
        )
        .await;

        assert!(
            matches!(result, Err(QuicTransportError::Cancelled)),
            "cancelled lab serve must fail closed before draining work, got {result:?}"
        );
        assert!(
            !callback_called.load(std::sync::atomic::Ordering::Relaxed),
            "cancelled lab serve must not invoke the receive result callback"
        );
    });

    assert_transport_lab_report_clean("cancelled serve", &report);

    report.to_json()
}

fn invalid_serve_config_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let listen: SocketAddr = "127.0.0.1:0".parse().expect("loopback bind addr");
        let endpoint = ManagedQuicEndpoint::bind(
            &cx,
            listen,
            ManagedEndpointConfig {
                is_server: true,
                ..ManagedEndpointConfig::default()
            },
        )
        .await
        .expect("managed endpoint binds under lab");
        let destination = PathBuf::from("h3-lab-invalid-serve-config-destination");
        let invalid_config = QuicConfig {
            accept_timeout: Duration::ZERO,
            ..trusted_quic_config()
        };

        let callback_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_flag = std::sync::Arc::clone(&callback_called);
        let result = serve(
            &cx,
            endpoint,
            destination,
            invalid_config,
            "h3-lab-invalid-config-serve".to_string(),
            move |_result| {
                callback_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            },
        )
        .await;

        match result {
            Err(QuicTransportError::Config(message)) => {
                assert!(
                    message.contains("accept_timeout"),
                    "invalid accept timeout should be named in the Config error, got {message:?}"
                );
            }
            Ok(()) => panic!("invalid lab serve config must not fake success"),
            Err(err) => panic!("invalid lab serve config must fail as Config, got {err:?}"),
        }
        assert!(
            !callback_called.load(std::sync::atomic::Ordering::Relaxed),
            "invalid lab serve config must not invoke the receive result callback"
        );
    });

    assert_transport_lab_report_clean("invalid serve config", &report);

    report.to_json()
}

fn empty_serve_lab_report(seed: u64) -> Value {
    let (_output, report) = run_async_under_lab_with_config(lab_config(seed), |cx| async move {
        cx.checkpoint()
            .expect("lab root context must remain uncancelled");

        let listen: SocketAddr = "127.0.0.1:0".parse().expect("loopback bind addr");
        let endpoint = ManagedQuicEndpoint::bind(
            &cx,
            listen,
            ManagedEndpointConfig {
                is_server: true,
                ..ManagedEndpointConfig::default()
            },
        )
        .await
        .expect("managed endpoint binds under lab");
        let destination = PathBuf::from("h3-lab-empty-serve-destination");

        let callback_called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let callback_flag = std::sync::Arc::clone(&callback_called);
        let result = serve(
            &cx,
            endpoint,
            destination,
            trusted_quic_config(),
            "h3-lab-empty-serve".to_string(),
            move |_result| {
                callback_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            },
        )
        .await;

        assert!(
            result.is_ok(),
            "empty lab serve must drain the empty endpoint without error, got {result:?}"
        );
        assert!(
            !callback_called.load(std::sync::atomic::Ordering::Relaxed),
            "empty lab serve must not invoke the receive result callback"
        );
    });

    assert_transport_lab_report_clean("empty serve", &report);

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
fn invalid_send_path_config_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = invalid_send_path_config_lab_report(0xb0c8_900b);
    let second = invalid_send_path_config_lab_report(0xb0c8_900b);

    assert_eq!(
        first, second,
        "same-seed transport_quic invalid send_path config lab run must replay identically"
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

#[test]
fn invalid_receive_once_config_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = invalid_receive_once_config_lab_report(0xb0c8_9007);
    let second = invalid_receive_once_config_lab_report(0xb0c8_9007);

    assert_eq!(
        first, second,
        "same-seed transport_quic invalid receive_once config lab run must replay identically"
    );
}

#[test]
fn cancelled_receive_once_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = cancelled_receive_once_lab_report(0xb0c8_9005);
    let second = cancelled_receive_once_lab_report(0xb0c8_9005);

    assert_eq!(
        first, second,
        "same-seed transport_quic cancelled receive_once lab run must replay identically"
    );
}

#[test]
fn cancelled_receive_connection_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = cancelled_receive_connection_lab_report(0xb0c8_9009);
    let second = cancelled_receive_connection_lab_report(0xb0c8_9009);

    assert_eq!(
        first, second,
        "same-seed transport_quic cancelled receive_connection lab run must replay identically"
    );
}

#[test]
fn invalid_receive_connection_config_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = invalid_receive_connection_config_lab_report(0xb0c8_900a);
    let second = invalid_receive_connection_config_lab_report(0xb0c8_900a);

    assert_eq!(
        first, second,
        "same-seed transport_quic invalid receive_connection config lab run must replay identically"
    );
}

#[test]
fn cancelled_serve_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = cancelled_serve_lab_report(0xb0c8_9006);
    let second = cancelled_serve_lab_report(0xb0c8_9006);

    assert_eq!(
        first, second,
        "same-seed transport_quic cancelled serve lab run must replay identically"
    );
}

#[test]
fn invalid_serve_config_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = invalid_serve_config_lab_report(0xb0c8_900c);
    let second = invalid_serve_config_lab_report(0xb0c8_900c);

    assert_eq!(
        first, second,
        "same-seed transport_quic invalid serve config lab run must replay identically"
    );
}

#[test]
fn empty_serve_is_quiescent_oracle_clean_and_replay_stable() {
    let _guard = lab_contract_lock()
        .lock()
        .expect("lab contract tests serialize cleanly");
    let first = empty_serve_lab_report(0xb0c8_9008);
    let second = empty_serve_lab_report(0xb0c8_9008);

    assert_eq!(
        first, second,
        "same-seed transport_quic empty serve lab run must replay identically"
    );
}
