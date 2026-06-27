//! `transport_quic` Phase B scaffold contract (b0k8qo.2.1 / arq-quic-epic).
//!
//! Pins B1's acceptance from OUTSIDE the crate (robust to internal `cfg(test)`
//! churn): the ATP-over-QUIC transport exposes a public API that mirrors
//! `transport_tcp`'s shapes EXACTLY, reuses the manifest/report/receipt wire
//! types, validates its `QuicConfig`, and makes unwired transfer entry points
//! FAIL CLOSED with typed errors, never fake success. B2 has since wired
//! `send_path` source preflight before the native connect boundary, and B3 has
//! wired `receive_connection`; this contract pins those boundaries instead of
//! the old all-`NotImplemented` scaffold.
//!
//! These tests drive the real public functions (no mocks). The async entry
//! points are exercised with a runtime-free `block_on`, and `Cx::for_testing`
//! requires `--features test-internals`.

#![allow(missing_docs)]

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::net::atp::transport_quic::{
    self, ManifestEntry, QuicAdaptiveArm, QuicAdaptiveBlockPlan, QuicAdaptiveController,
    QuicAdaptivePolicy, QuicConfig, QuicPathEstimate, QuicPathSignalSample, QuicSprayPacingLimiter,
    QuicTransportError, ReceiveReceipt, ReceiveReport, SendReport, TransferManifest,
    apply_quic_adaptive_block_plan, quic_spray_pacing_decision_from_config, receive_connection,
    receive_once, send_path,
};
use asupersync::net::quic_core::ConnectionId;
use asupersync::net::quic_native::{
    ManagedEndpointConfig, ManagedQuicEndpoint, NativeQuicConnection, NativeQuicConnectionConfig,
};
use asupersync::observability::{DiagnosticContext, LogCollector, LogLevel};
use asupersync::security::SecurityContext;
use asupersync::types::Budget;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    futures_lite::future::block_on(fut)
}

fn trusted_quic_config() -> QuicConfig {
    QuicConfig::default().allow_unauthenticated_for_trusted_transport()
}

fn bind_managed_server_endpoint(cx: &Cx) -> ManagedQuicEndpoint {
    block_on(ManagedQuicEndpoint::bind(
        cx,
        "127.0.0.1:0".parse().unwrap(),
        ManagedEndpointConfig {
            is_server: true,
            ..ManagedEndpointConfig::default()
        },
    ))
    .expect("managed endpoint should bind")
}

fn quic_path_estimate(loss: f64, bw_median_bps: f64) -> QuicPathEstimate {
    QuicPathEstimate {
        rtt_s: 0.075,
        loss_p_hat: loss,
        loss_p_bar: loss,
        bw_median_bps,
        bw_trough_bps: bw_median_bps * 0.7,
        enc_symbols_per_s: 2_000_000.0,
        dec_symbols_per_s: 1_500_000.0,
        coding_ref_k: 1024,
        coding_gamma: 1.5,
        samples: 8,
    }
}

fn quic_pacing_signal(rtt_s: f64, cwnd_bytes: u64, loss_rate: f64) -> QuicPathSignalSample {
    QuicPathSignalSample {
        smoothed_rtt_s: rtt_s,
        congestion_window_bytes: cwnd_bytes,
        loss_rate,
    }
}

// ─── Public API surface mirrors transport_tcp ────────────────────────────────

/// All four transfer entry points are public items at the mirrored paths.
/// (`send_path` / `receive_connection` signatures are pinned exactly by the
/// calling tests below; `receive_once` / `serve` are referenced here since they
/// take a `ManagedQuicEndpoint` that is heavier to construct in a unit test.)
#[test]
fn public_api_entry_points_exist() {
    let _ = transport_quic::send_path;
    let _ = transport_quic::receive_once;
    let _ = transport_quic::receive_connection;
    let _ = transport_quic::serve::<fn(Result<ReceiveReport, QuicTransportError>)>;
}

/// The manifest/report/receipt types are REUSED from `transport_tcp` (same
/// types, re-exported), not re-declared — so QUIC and TCP commit to one schema.
#[test]
fn manifest_and_receipt_types_are_reused_from_transport_tcp() {
    // Type identity: a transport_tcp value is assignable to a transport_quic
    // binding of the re-exported name. If these were distinct types this would
    // not compile.
    let tcp_manifest = asupersync::net::atp::transport_tcp::TransferManifest {
        transfer_id: "t".to_string(),
        root_name: "r".to_string(),
        is_directory: false,
        total_bytes: 0,
        merkle_root_hex: "00".repeat(32),
        metadata_root_hex: None,
        delta_manifest: None,
        entries: vec![],
    };
    let quic_manifest: TransferManifest = tcp_manifest;
    assert_eq!(quic_manifest.entries.len(), 0);

    let tcp_receipt = asupersync::net::atp::transport_tcp::ReceiveReceipt {
        committed: false,
        bytes_received: 0,
        files: 0,
        sha_ok: false,
        merkle_ok: false,
        symbols_accepted: 0,
        feedback_rounds: 0,
        decode_count: 0,
        decode_micros: 0,
        reason: Some("x".to_string()),
        committed_paths: vec![],
    };
    let _quic_receipt: ReceiveReceipt = tcp_receipt;
}

// ─── QuicConfig validation ───────────────────────────────────────────────────

#[test]
fn default_config_requires_symbol_auth_or_trusted_mode() {
    let default = QuicConfig::default();
    assert_eq!(
        default.max_block_size,
        usize::from(default.symbol_size) * 512
    );
    assert!(matches!(
        default.validate(),
        Err(QuicTransportError::Config(message)) if message.contains("symbol_auth_context")
    ));
    assert!(trusted_quic_config().validate().is_ok());
}

#[test]
fn config_validation_rejects_nonsense_knobs() {
    let bad = [
        QuicConfig {
            chunk_size: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            symbol_size: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            max_block_size: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            symbol_size: 4000,
            max_datagram_size: 1200,
            ..trusted_quic_config()
        },
        QuicConfig {
            // raw symbol fits the datagram, but symbol + envelope header does not
            symbol_size: 1199,
            max_datagram_size: 1200,
            ..trusted_quic_config()
        },
        QuicConfig {
            repair_overhead: 0.0,
            ..trusted_quic_config()
        },
        QuicConfig {
            max_transfer_bytes: 0,
            ..trusted_quic_config()
        },
        QuicConfig {
            idle_timeout: Duration::ZERO,
            ..trusted_quic_config()
        },
        QuicConfig {
            handshake_timeout: Duration::ZERO,
            ..trusted_quic_config()
        },
        QuicConfig {
            accept_timeout: Duration::ZERO,
            ..trusted_quic_config()
        },
        QuicConfig {
            max_feedback_rounds: 0,
            ..trusted_quic_config()
        },
    ];
    for cfg in bad {
        assert!(
            matches!(cfg.validate(), Err(QuicTransportError::Config(_))),
            "config {cfg:?} should fail validation"
        );
    }
}

#[test]
fn adaptive_controller_replays_same_quic_arm_trajectory() {
    fn run() -> Vec<(u32, u64, usize)> {
        let mut controller = QuicAdaptiveController::new(QuicAdaptivePolicy::default(), 0xA7A7);
        controller.update_estimate(quic_path_estimate(0.02, 12_000_000.0));
        let mut trajectory = Vec::new();

        for _ in 0..24 {
            let plan = controller
                .next_block_plan(transport_quic::DEFAULT_SYMBOL_SIZE)
                .expect("enough evidence activates the controller");
            let arm = QuicAdaptiveArm::from_block_plan(plan).expect("valid controller arm");
            trajectory.push((arm.k, arm.repair_overhead.to_bits(), arm.datagram_fanout));
            controller.observe(
                u64::from(plan.k),
                u64::from(plan.k),
                0.01,
                u64::from(plan.k) * u64::from(transport_quic::DEFAULT_SYMBOL_SIZE),
            );
        }

        trajectory
    }

    assert_eq!(run(), run(), "same seed and rewards must replay exactly");
}

#[test]
fn adaptive_model_profile_matches_online_single_arm_selection() {
    let mut policy = QuicAdaptivePolicy::default();
    policy.arm_grid_k = vec![512];
    policy.arm_grid_fanout = vec![3];

    let mut controller = QuicAdaptiveController::new(policy, 0xC4C4);
    controller.update_estimate(quic_path_estimate(0.04, 9_000_000.0));

    let profile = controller.model_plan(transport_quic::DEFAULT_SYMBOL_SIZE);
    let selected = controller
        .next_block_plan(transport_quic::DEFAULT_SYMBOL_SIZE)
        .expect("single-arm evidence activates online controller");
    assert_eq!(
        selected, profile,
        "single-arm offline/model profile must match online selection"
    );
    assert_eq!(selected.k, 512);
    assert_eq!(selected.fanout, 3);

    let profile_config =
        apply_quic_adaptive_block_plan(trusted_quic_config(), profile).expect("profile applies");
    let selected_config =
        apply_quic_adaptive_block_plan(trusted_quic_config(), selected).expect("selection applies");
    assert_eq!(selected_config.symbol_size, profile_config.symbol_size);
    assert_eq!(
        selected_config.max_block_size,
        profile_config.max_block_size
    );
    assert_eq!(
        selected_config.repair_overhead,
        profile_config.repair_overhead
    );
    assert_eq!(
        selected_config.datagram_fanout,
        profile_config.datagram_fanout
    );

    let snapshot = controller.diagnostic_snapshot();
    assert_eq!(snapshot.epoch, 1);
    assert_eq!(snapshot.selected_plan, Some(profile));
}

#[test]
fn adaptive_arm_rejects_invalid_controller_output() {
    assert!(matches!(
        QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
            k: 0,
            overhead: 0.1,
            fanout: 1,
        }),
        Err(QuicTransportError::Config(message)) if message.contains('k')
    ));
    assert!(matches!(
        QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
            k: 128,
            overhead: f64::NAN,
            fanout: 1,
        }),
        Err(QuicTransportError::Config(message)) if message.contains("overhead")
    ));
    assert!(matches!(
        QuicAdaptiveArm::from_block_plan(QuicAdaptiveBlockPlan {
            k: 128,
            overhead: 0.1,
            fanout: 0,
        }),
        Err(QuicTransportError::Config(message)) if message.contains("fanout")
    ));
}

#[test]
fn adaptive_arm_is_visible_on_public_send_path_trace() {
    let config = apply_quic_adaptive_block_plan(
        QuicConfig {
            symbol_size: 128,
            ..trusted_quic_config()
        },
        QuicAdaptiveBlockPlan {
            k: 2,
            overhead: 0.25,
            fanout: 3,
        },
    )
    .expect("adaptive block plan applies to QUIC config");

    assert_eq!(config.max_block_size, 256);
    assert_eq!(config.repair_overhead, 1.25);
    assert_eq!(config.datagram_fanout, 3);

    let cx = Cx::for_testing();
    let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("adaptive-before-connect.bin");
    let result: Result<SendReport, QuicTransportError> =
        block_on(send_path(&cx, addr, &missing, config, "adaptive-sender"));
    assert!(
        matches!(result, Err(QuicTransportError::Source(_))),
        "missing source should fail after the adaptive config is traced, got {result:?}"
    );

    let entries = collector.peek();
    let start = entries
        .iter()
        .find(|entry| entry.message() == "atp_quic.transport.start")
        .expect("transport start trace entry");
    assert_eq!(start.get_field("operation"), Some("send_path"));
    assert_eq!(start.get_field("peer_id"), Some("adaptive-sender"));
    assert_eq!(start.get_field("symbol_size"), Some("128"));
    assert_eq!(start.get_field("max_block_size"), Some("256"));
    assert_eq!(start.get_field("repair_overhead"), Some("1.2500"));
    assert_eq!(start.get_field("datagram_fanout"), Some("3"));
}

#[test]
fn spray_pacing_policy_is_public_and_uses_cwnd_as_telemetry() {
    let config = QuicConfig {
        symbol_size: 1024,
        max_spray_symbols_per_flush: 32,
        ..trusted_quic_config()
    };

    let low_cwnd =
        quic_spray_pacing_decision_from_config(&config, quic_pacing_signal(0.040, 12_000, 0.0));
    let high_cwnd =
        quic_spray_pacing_decision_from_config(&config, quic_pacing_signal(0.040, 768 * 1024, 0.0));
    assert_eq!(high_cwnd.max_burst_symbols, low_cwnd.max_burst_symbols);
    assert_eq!(high_cwnd.pacing_rate_bps, low_cwnd.pacing_rate_bps);
    assert!(high_cwnd.cwnd_symbols > low_cwnd.cwnd_symbols);
    assert!(high_cwnd.max_burst_symbols <= config.max_spray_symbols_per_flush);

    let lossy = quic_spray_pacing_decision_from_config(
        &config,
        quic_pacing_signal(0.040, 768 * 1024, 0.35),
    );
    assert_eq!(lossy.limiter, QuicSprayPacingLimiter::LossBackoff);
    assert!(lossy.congestion_loss_rate > 0.0);
    assert!(lossy.pacing_rate_bps < high_cwnd.pacing_rate_bps);

    let bwlimited = quic_spray_pacing_decision_from_config(
        &QuicConfig {
            bwlimit_bps: Some(256 * 1024),
            ..config
        },
        quic_pacing_signal(0.040, 768 * 1024, 0.0),
    );
    assert_eq!(bwlimited.limiter, QuicSprayPacingLimiter::BandwidthLimit);
    assert!(bwlimited.pacing_rate_bps <= 256 * 1024);
}

fn adaptive_epoch_trace_fields_under_lab(seed: u64) -> Vec<(String, String)> {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(128));
    let root = runtime.state.create_root_region(Budget::INFINITE);
    let collector = LogCollector::new(16).with_min_level(LogLevel::Trace);
    let collector_for_task = collector.clone();

    let (task_id, _handle) = runtime
        .state
        .create_task(root, Budget::INFINITE, async move {
            let cx = Cx::current().expect("lab task installs Cx");
            cx.set_diagnostic_context(DiagnosticContext::new());
            cx.set_log_collector(collector_for_task);

            let mut controller = QuicAdaptiveController::new(QuicAdaptivePolicy::default(), 0xC1A0);
            controller.update_estimate(quic_path_estimate(0.02, 12_000_000.0));
            let plan = controller
                .next_block_plan(transport_quic::DEFAULT_SYMBOL_SIZE)
                .expect("controller activates inside lab runtime");
            let arm = QuicAdaptiveArm::from_block_plan(plan).expect("valid QUIC adaptive arm");
            assert_eq!(arm.k, plan.k);
            assert_eq!(arm.datagram_fanout, plan.fanout);

            controller.observe(
                u64::from(plan.k),
                u64::from(plan.k),
                0.01,
                u64::from(plan.k) * u64::from(transport_quic::DEFAULT_SYMBOL_SIZE),
            );
            let snapshot = controller.diagnostic_snapshot();
            assert_eq!(snapshot.epoch, 1);
            assert_eq!(snapshot.selected_plan, Some(plan));
            assert_eq!(snapshot.weights.len(), 24);

            controller.trace_last_decision(&cx, "atp_quic.adaptive.epoch", "quic");
        })
        .expect("lab adaptive trace task should spawn");
    runtime
        .scheduler
        .lock()
        .schedule(task_id, Budget::INFINITE.priority);
    runtime.run_until_quiescent();

    let violations = runtime.oracles.check_all(runtime.now());
    assert!(
        violations.is_empty(),
        "adaptive epoch trace should leave lab invariants clean: {violations:?}"
    );

    let entries = collector.peek();
    let entry = entries
        .iter()
        .find(|entry| entry.message() == "atp_quic.adaptive.epoch")
        .expect("adaptive epoch trace entry");
    [
        "transport",
        "epoch",
        "selected_arm_index",
        "k",
        "repair_overhead",
        "fanout",
        "weight_count",
        "weights",
        "loss_scale",
    ]
    .into_iter()
    .map(|field| {
        (
            field.to_string(),
            entry.get_field(field).expect("trace field").to_string(),
        )
    })
    .collect()
}

#[test]
fn adaptive_epoch_trace_replays_under_lab_runtime() {
    let first = adaptive_epoch_trace_fields_under_lab(0xA5A5);
    let second = adaptive_epoch_trace_fields_under_lab(0xA5A5);
    assert_eq!(first, second, "same lab seed must replay trace fields");

    let field = |name: &str| -> &str {
        first
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
            .expect("field present")
    };
    assert_eq!(field("transport"), "quic");
    assert_eq!(field("epoch"), "1");
    assert_ne!(field("selected_arm_index"), "none");
    assert_ne!(field("k"), "none");
    assert_ne!(field("repair_overhead"), "none");
    assert_ne!(field("fanout"), "none");
    assert_eq!(field("weight_count"), "24");
    assert!(field("weights").contains(','));
    assert_ne!(
        field("weights"),
        "1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000,1.000000",
        "post-observe weights should be trace-visible, not just the initial uniform grid"
    );
}

// ─── Error taxonomy / Display ────────────────────────────────────────────────

#[test]
fn not_implemented_display_is_actionable() {
    let e = QuicTransportError::NotImplemented {
        operation: "send_path",
        wired_by: "asupersync-arq-quic-epic-b0k8qo.2.2 (B2: QUIC sender coroutine)",
    };
    let s = e.to_string();
    assert!(s.contains("send_path"));
    assert!(s.contains("b0k8qo.2.2"));
    assert!(s.contains("failing closed"));
}

#[test]
fn timeout_and_too_large_display_carry_context() {
    let t = QuicTransportError::Timeout {
        operation: "receive frame",
        timeout: Duration::from_secs(30),
    };
    assert!(t.to_string().contains("receive frame"));
    assert!(t.to_string().contains("30s"));

    let big = QuicTransportError::TooLarge {
        size: 5_000,
        max: 1_000,
    };
    assert!(big.to_string().contains("5000"));
    assert!(big.to_string().contains("1000"));
}

// ─── JSON round-trips on the reused wire types ───────────────────────────────

#[test]
fn manifest_json_roundtrips() {
    let manifest = TransferManifest {
        transfer_id: "abc123".to_string(),
        root_name: "tree".to_string(),
        is_directory: true,
        total_bytes: 1234,
        merkle_root_hex: "ab".repeat(32),
        metadata_root_hex: None,
        delta_manifest: None,
        entries: vec![
            ManifestEntry {
                index: 0,
                rel_path: "dir/a.txt".to_string(),
                size: 1000,
                sha256_hex: "11".repeat(32),
                metadata: None,
            },
            ManifestEntry {
                index: 1,
                rel_path: "dir/b.bin".to_string(),
                size: 234,
                sha256_hex: "22".repeat(32),
                metadata: None,
            },
        ],
    };
    let json = serde_json::to_vec(&manifest).unwrap();
    let back: TransferManifest = serde_json::from_slice(&json).unwrap();
    assert_eq!(manifest, back);
}

#[test]
fn receipt_json_roundtrips_committed_and_rejected() {
    let committed = ReceiveReceipt {
        committed: true,
        bytes_received: 1234,
        files: 2,
        sha_ok: true,
        merkle_ok: true,
        symbols_accepted: 8,
        feedback_rounds: 1,
        decode_count: 2,
        decode_micros: 17,
        reason: None,
        committed_paths: vec!["/dest/dir/a.txt".to_string(), "/dest/dir/b.bin".to_string()],
    };
    let rejected = ReceiveReceipt {
        committed: false,
        bytes_received: 1234,
        files: 2,
        sha_ok: false,
        merkle_ok: true,
        symbols_accepted: 3,
        feedback_rounds: 2,
        decode_count: 1,
        decode_micros: 11,
        reason: Some("per-entry SHA-256 mismatch".to_string()),
        committed_paths: vec![],
    };
    for r in [committed, rejected] {
        let json = serde_json::to_vec(&r).unwrap();
        let back: ReceiveReceipt = serde_json::from_slice(&json).unwrap();
        assert_eq!(r, back);
    }
}

// ─── Fail-closed: unwired boundaries return typed errors, never fake success ──

#[test]
fn send_path_rejects_missing_source_before_native_connect() {
    let cx = Cx::for_testing();
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("definitely-missing-payload.bin");
    let result: Result<SendReport, QuicTransportError> = block_on(send_path(
        &cx,
        addr,
        &missing,
        trusted_quic_config(),
        "sender",
    ));
    assert!(
        matches!(result, Err(QuicTransportError::Source(_))),
        "missing source should fail before native connect, got {result:?}"
    );
}

#[test]
fn send_path_start_trace_carries_stable_structured_fields() {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("trace-before-native-connect.bin");
    let result: Result<SendReport, QuicTransportError> = block_on(send_path(
        &cx,
        addr,
        &missing,
        trusted_quic_config(),
        "sender",
    ));
    assert!(
        matches!(result, Err(QuicTransportError::Source(_))),
        "missing source should still fail before native connect, got {result:?}"
    );

    let entries = collector.peek();
    let start = entries
        .iter()
        .find(|entry| entry.message() == "atp_quic.transport.start")
        .expect("transport start trace entry");
    assert_eq!(start.level(), LogLevel::Trace);
    assert_eq!(start.get_field("operation"), Some("send_path"));
    assert_eq!(start.get_field("protocol"), Some("3"));
    assert_eq!(start.get_field("peer_id"), Some("sender"));

    for required in [
        "chunk_size",
        "symbol_size",
        "max_block_size",
        "max_datagram_size",
        "repair_overhead",
        "max_transfer_bytes",
        "idle_timeout",
        "handshake_timeout",
        "accept_timeout",
        "max_active_connections",
        "max_feedback_rounds",
        "datagram_fanout",
    ] {
        assert!(
            start
                .get_field(required)
                .is_some_and(|value| !value.is_empty()),
            "transport start trace must include non-empty {required}"
        );
    }
}

#[test]
fn send_path_extended_config_trace_carries_overflow_safe_fields() {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let config = QuicConfig {
        bwlimit_bps: Some(256 * 1024),
        max_spray_symbols_per_flush: 17,
        responsiveness_pressure: 0.125,
        allow_special_files: true,
        preserve_hardlinks: true,
        ..trusted_quic_config()
    };
    let expected_metadata_policy = format!("{:?}", config.metadata_policy);
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("trace-extended-config.bin");

    let result: Result<SendReport, QuicTransportError> =
        block_on(send_path(&cx, addr, &missing, config, "sender"));
    assert!(
        matches!(result, Err(QuicTransportError::Source(_))),
        "missing source should still fail after extended config trace, got {result:?}"
    );

    let entries = collector.peek();
    let start = entries
        .iter()
        .find(|entry| entry.message() == "atp_quic.transport.start")
        .expect("transport start trace entry");
    assert_eq!(start.get_field("operation"), Some("send_path"));
    assert_eq!(start.get_field("datagram_fanout"), Some("1"));
    assert_eq!(
        start.get_field("bwlimit_bps"),
        None,
        "extended config fields live on atp_quic.transport.config to stay under LogEntry's field cap"
    );

    let config = entries
        .iter()
        .find(|entry| entry.message() == "atp_quic.transport.config")
        .expect("transport extended config trace entry");
    assert_eq!(config.level(), LogLevel::Trace);
    assert_eq!(config.get_field("operation"), Some("send_path"));
    assert_eq!(config.get_field("peer_id"), Some("sender"));
    assert_eq!(config.get_field("bwlimit_bps"), Some("262144"));
    assert_eq!(config.get_field("max_spray_symbols_per_flush"), Some("17"));
    assert_eq!(
        config.get_field("responsiveness_pressure"),
        Some("0.125000")
    );
    assert_eq!(
        config.get_field("metadata_policy"),
        Some(expected_metadata_policy.as_str())
    );
    assert_eq!(config.get_field("allow_special_files"), Some("true"));
    assert_eq!(config.get_field("preserve_hardlinks"), Some("true"));
}

fn assert_transport_start_trace(collector: &LogCollector, operation: &str, peer_id: &str) {
    let entries = collector.peek();
    let start = entries
        .iter()
        .find(|entry| entry.message() == "atp_quic.transport.start")
        .expect("transport start trace entry");
    assert_eq!(start.level(), LogLevel::Trace);
    assert_eq!(start.get_field("operation"), Some(operation));
    assert_eq!(start.get_field("protocol"), Some("3"));
    assert_eq!(start.get_field("peer_id"), Some(peer_id));

    for required in [
        "chunk_size",
        "symbol_size",
        "max_block_size",
        "max_datagram_size",
        "repair_overhead",
        "max_transfer_bytes",
        "idle_timeout",
        "handshake_timeout",
        "accept_timeout",
        "max_active_connections",
        "max_feedback_rounds",
        "datagram_fanout",
    ] {
        assert!(
            start
                .get_field(required)
                .is_some_and(|value| !value.is_empty()),
            "transport start trace must include non-empty {required}"
        );
    }
}

fn assert_accepted_trace(
    collector: &LogCollector,
    message: &str,
    connection_id: ConnectionId,
    peer: SocketAddr,
    peer_id: &str,
) {
    let entries = collector.peek();
    let accepted = entries
        .iter()
        .find(|entry| entry.message() == message)
        .expect("accepted connection trace entry");
    let expected_connection_id = format!("{connection_id:?}");
    let expected_peer = peer.to_string();
    assert_eq!(accepted.level(), LogLevel::Trace);
    assert_eq!(
        accepted.get_field("connection_id"),
        Some(expected_connection_id.as_str())
    );
    assert_eq!(accepted.get_field("peer"), Some(expected_peer.as_str()));
    assert_eq!(accepted.get_field("peer_id"), Some(peer_id));
}

#[test]
fn authenticated_start_trace_omits_key_material() {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], 9));
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("trace-authenticated-missing.bin");
    let config = QuicConfig::default().with_symbol_auth(SecurityContext::for_testing(0xA7_51));

    let result: Result<SendReport, QuicTransportError> =
        block_on(send_path(&cx, addr, &missing, config, "sender"));
    assert!(
        matches!(result, Err(QuicTransportError::Source(_))),
        "authenticated missing source should fail after start trace, got {result:?}"
    );

    let entries = collector.peek();
    let start = entries
        .iter()
        .find(|entry| entry.message() == "atp_quic.transport.start")
        .expect("transport start trace entry");
    assert_transport_start_trace(&collector, "send_path", "sender");

    for forbidden_field in [
        "symbol_auth_context",
        "auth_key",
        "authkey",
        "private_key",
        "key_material",
        "secret",
    ] {
        assert_eq!(
            start.get_field(forbidden_field),
            None,
            "transport start trace must not expose sensitive field {forbidden_field}"
        );
    }

    for (key, value) in start.fields() {
        let rendered = format!("{key}={value}").to_ascii_lowercase();
        for forbidden_fragment in [
            "symbol_auth_context",
            "authkey",
            "private_key",
            "key_material",
            "secret",
        ] {
            assert!(
                !rendered.contains(forbidden_fragment),
                "transport start trace leaked sensitive fragment {forbidden_fragment}: {rendered}"
            );
        }
    }
}

#[test]
fn send_path_observes_cancel_before_source_preflight() {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let temp = tempfile::tempdir().expect("temp dir");
    let missing = temp.path().join("cancel-before-source-check.bin");
    let result: Result<SendReport, QuicTransportError> = block_on(send_path(
        &cx,
        addr,
        &missing,
        trusted_quic_config(),
        "sender",
    ));
    assert!(
        matches!(result, Err(QuicTransportError::Cancelled)),
        "cancelled send_path must fail closed before source preflight, got {result:?}"
    );
}

#[test]
fn send_path_valid_source_fails_closed_without_client_tls() {
    // A valid source preflights fine, but `send_path` now opens a *real* native
    // QUIC connection, which requires client TLS trust (server name + roots).
    // `trusted_quic_config()` configures the symbol-auth posture but no client
    // TLS, so the transfer fails closed with a typed Config error before any
    // network I/O — never a fabricated success. (On a build without the `tls`
    // feature the same call fails closed with Config for lack of a handshake.)
    let cx = Cx::for_testing();
    let temp = tempfile::tempdir().expect("temp dir");
    let source = temp.path().join("payload.bin");
    std::fs::write(&source, b"payload").expect("write source");
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let result: Result<SendReport, QuicTransportError> = block_on(send_path(
        &cx,
        addr,
        &source,
        trusted_quic_config(),
        "sender",
    ));
    assert!(
        matches!(result, Err(QuicTransportError::Config(_))),
        "valid-source send_path must fail closed (Config) without client TLS, got {result:?}"
    );
}

#[test]
fn send_path_rejects_invalid_config_before_touching_network() {
    let cx = Cx::for_testing();
    let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let cfg = QuicConfig {
        accept_timeout: Duration::ZERO,
        ..trusted_quic_config()
    };
    let result = block_on(send_path(&cx, addr, Path::new("/x"), cfg, "sender"));
    assert!(matches!(result, Err(QuicTransportError::Config(_))));
}

#[test]
fn receive_connection_rejects_missing_control_stream_without_fake_success() {
    let cx = Cx::for_testing();
    let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_connection(
        &cx,
        conn,
        peer,
        Path::new("/tmp"),
        trusted_quic_config(),
        "receiver",
    ));
    match result {
        Ok(report) => panic!("missing control stream must not fake success: {report:?}"),
        Err(QuicTransportError::NotImplemented {
            operation: "receive_connection",
            ..
        }) => panic!("receive_connection should stay wired past the B1 scaffold"),
        Err(_) => {}
    }
}

#[test]
fn receive_connection_observes_cancel_before_native_receive_body() -> TestResult {
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    let peer = SocketAddr::from(([127, 0, 0, 1], 9));
    let temp = tempfile::tempdir()?;

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_connection(
        &cx,
        conn,
        peer,
        temp.path(),
        trusted_quic_config(),
        "receiver",
    ));

    assert!(
        matches!(result, Err(QuicTransportError::Cancelled)),
        "cancelled receive_connection must fail closed before native receive body, got {result:?}"
    );

    Ok(())
}

#[test]
fn receive_connection_rejects_invalid_config_before_native_receive_body() -> TestResult {
    let cx = Cx::for_testing();
    let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    let peer = SocketAddr::from(([127, 0, 0, 1], 9));
    let temp = tempfile::tempdir()?;
    let cfg = QuicConfig {
        accept_timeout: Duration::ZERO,
        ..trusted_quic_config()
    };

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_connection(
        &cx,
        conn,
        peer,
        temp.path(),
        cfg,
        "receiver",
    ));

    assert!(
        matches!(result, Err(QuicTransportError::Config(_))),
        "invalid receive_connection config must fail before native receive body, got {result:?}"
    );

    Ok(())
}

#[test]
fn receive_connection_start_trace_carries_stable_structured_fields() -> TestResult {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let conn = NativeQuicConnection::new(NativeQuicConnectionConfig::default());
    let peer = SocketAddr::from(([127, 0, 0, 1], 9));
    let temp = tempfile::tempdir()?;

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_connection(
        &cx,
        conn,
        peer,
        temp.path(),
        trusted_quic_config(),
        "receiver",
    ));

    match result {
        Ok(report) => panic!("missing control stream must not fake success: {report:?}"),
        Err(QuicTransportError::NotImplemented {
            operation: "receive_connection",
            ..
        }) => panic!("receive_connection should stay wired past the B1 scaffold"),
        Err(_) => {}
    }

    assert_transport_start_trace(&collector, "receive_connection", "receiver");

    Ok(())
}

#[test]
fn receive_once_rejects_empty_endpoint_without_fake_success() {
    let cx = Cx::for_testing();
    let mut endpoint = block_on(ManagedQuicEndpoint::bind(
        &cx,
        "127.0.0.1:0".parse().unwrap(),
        ManagedEndpointConfig {
            is_server: true,
            ..ManagedEndpointConfig::default()
        },
    ))
    .expect("managed endpoint should bind");

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_once(
        &cx,
        &mut endpoint,
        Path::new("/tmp"),
        trusted_quic_config(),
        "receiver",
    ));
    match result {
        Ok(report) => panic!("empty endpoint must not fake success: {report:?}"),
        Err(QuicTransportError::Timeout {
            operation: "receive_once accept",
            ..
        }) => {}
        Err(QuicTransportError::NotImplemented {
            operation: "receive_once",
            ..
        }) => panic!("receive_once should stay wired past the B1 scaffold"),
        Err(err) => panic!("empty endpoint should fail closed as accept timeout, got {err:?}"),
    }
}

#[test]
fn receive_once_observes_cancel_before_endpoint_accept() {
    let setup_cx = Cx::for_testing();
    let mut endpoint = bind_managed_server_endpoint(&setup_cx);
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let temp = tempfile::tempdir().expect("temp dir");

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_once(
        &cx,
        &mut endpoint,
        temp.path(),
        trusted_quic_config(),
        "receiver",
    ));

    assert!(
        matches!(result, Err(QuicTransportError::Cancelled)),
        "cancelled receive_once must fail closed before endpoint accept, got {result:?}"
    );
}

#[test]
fn receive_once_rejects_invalid_config_before_endpoint_accept() {
    let cx = Cx::for_testing();
    let mut endpoint = bind_managed_server_endpoint(&cx);
    let temp = tempfile::tempdir().expect("temp dir");
    let cfg = QuicConfig {
        accept_timeout: Duration::ZERO,
        ..trusted_quic_config()
    };

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_once(
        &cx,
        &mut endpoint,
        temp.path(),
        cfg,
        "receiver",
    ));

    assert!(
        matches!(result, Err(QuicTransportError::Config(_))),
        "invalid receive_once config must fail before endpoint accept, got {result:?}"
    );
}

#[test]
fn receive_once_start_trace_carries_stable_structured_fields() {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let mut endpoint = block_on(ManagedQuicEndpoint::bind(
        &cx,
        "127.0.0.1:0".parse().unwrap(),
        ManagedEndpointConfig {
            is_server: true,
            ..ManagedEndpointConfig::default()
        },
    ))
    .expect("managed endpoint should bind");
    let temp = tempfile::tempdir().expect("temp dir");
    let mut config = trusted_quic_config();
    config.accept_timeout = Duration::from_millis(10);

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_once(
        &cx,
        &mut endpoint,
        temp.path(),
        config,
        "receiver",
    ));
    assert!(
        matches!(
            result,
            Err(QuicTransportError::Timeout {
                operation: "receive_once accept",
                ..
            })
        ),
        "empty receive_once should fail closed as accept timeout, got {result:?}"
    );
    assert_transport_start_trace(&collector, "receive_once", "receiver");
}

#[test]
fn receive_once_accepted_trace_carries_stable_structured_fields() -> TestResult {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(16).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let mut endpoint = bind_managed_server_endpoint(&cx);
    let connection_id = ConnectionId::new(b"h1recv1").expect("valid connection id");
    let peer = SocketAddr::from(([127, 0, 0, 1], 57_771));
    block_on(endpoint.create_connection_for_testing(&cx, connection_id, peer))?;
    let temp = tempfile::tempdir()?;

    let result: Result<ReceiveReport, QuicTransportError> = block_on(receive_once(
        &cx,
        &mut endpoint,
        temp.path(),
        trusted_quic_config(),
        "receiver",
    ));

    match result {
        Ok(report) => panic!("unseeded accepted connection must not fake success: {report:?}"),
        Err(QuicTransportError::Timeout {
            operation: "receive_once accept",
            ..
        }) => panic!("routed accepted connection must not take the empty-endpoint timeout path"),
        Err(QuicTransportError::NotImplemented {
            operation: "receive_once",
            ..
        }) => panic!("receive_once should stay wired past the B1 scaffold"),
        Err(_) => {}
    }

    assert_accepted_trace(
        &collector,
        "atp_quic.receive_once.accepted",
        connection_id,
        peer,
        "receiver",
    );

    Ok(())
}

#[test]
fn serve_empty_endpoint_drains_without_fake_result() {
    let cx = Cx::for_testing();
    let endpoint = block_on(ManagedQuicEndpoint::bind(
        &cx,
        "127.0.0.1:0".parse().unwrap(),
        ManagedEndpointConfig {
            is_server: true,
            ..ManagedEndpointConfig::default()
        },
    ))
    .expect("managed endpoint should bind");
    let temp = tempfile::tempdir().expect("temp dir");
    let mut callbacks = 0usize;
    let mut config = trusted_quic_config();
    config.accept_timeout = Duration::from_millis(10);

    let result = block_on(transport_quic::serve(
        &cx,
        endpoint,
        temp.path().to_path_buf(),
        config,
        "receiver".to_string(),
        |result| {
            callbacks += 1;
            panic!("empty endpoint must not report a transfer result: {result:?}");
        },
    ));

    assert!(
        result.is_ok(),
        "empty endpoint serve should drain: {result:?}"
    );
    assert_eq!(callbacks, 0);
}

#[test]
fn serve_observes_cancel_before_endpoint_drain() {
    let setup_cx = Cx::for_testing();
    let endpoint = bind_managed_server_endpoint(&setup_cx);
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let temp = tempfile::tempdir().expect("temp dir");
    let mut callbacks = 0usize;

    let result = block_on(transport_quic::serve(
        &cx,
        endpoint,
        temp.path().to_path_buf(),
        trusted_quic_config(),
        "receiver".to_string(),
        |result| {
            callbacks += 1;
            panic!("cancelled serve must not report a transfer result: {result:?}");
        },
    ));

    assert!(
        matches!(result, Err(QuicTransportError::Cancelled)),
        "cancelled serve must fail closed before endpoint drain, got {result:?}"
    );
    assert_eq!(callbacks, 0);
}

#[test]
fn serve_rejects_invalid_config_before_endpoint_drain() {
    let cx = Cx::for_testing();
    let endpoint = bind_managed_server_endpoint(&cx);
    let temp = tempfile::tempdir().expect("temp dir");
    let mut callbacks = 0usize;
    let cfg = QuicConfig {
        accept_timeout: Duration::ZERO,
        ..trusted_quic_config()
    };

    let result = block_on(transport_quic::serve(
        &cx,
        endpoint,
        temp.path().to_path_buf(),
        cfg,
        "receiver".to_string(),
        |result| {
            callbacks += 1;
            panic!("invalid-config serve must not report a transfer result: {result:?}");
        },
    ));

    assert!(
        matches!(result, Err(QuicTransportError::Config(_))),
        "invalid serve config must fail before endpoint drain, got {result:?}"
    );
    assert_eq!(callbacks, 0);
}

#[test]
fn serve_start_trace_carries_stable_structured_fields() {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(8).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let endpoint = block_on(ManagedQuicEndpoint::bind(
        &cx,
        "127.0.0.1:0".parse().unwrap(),
        ManagedEndpointConfig {
            is_server: true,
            ..ManagedEndpointConfig::default()
        },
    ))
    .expect("managed endpoint should bind");
    let temp = tempfile::tempdir().expect("temp dir");
    let mut callbacks = 0usize;
    let mut config = trusted_quic_config();
    config.accept_timeout = Duration::from_millis(10);

    let result = block_on(transport_quic::serve(
        &cx,
        endpoint,
        temp.path().to_path_buf(),
        config,
        "receiver".to_string(),
        |result| {
            callbacks += 1;
            panic!("empty endpoint must not report a transfer result: {result:?}");
        },
    ));

    assert!(
        result.is_ok(),
        "empty endpoint serve should drain: {result:?}"
    );
    assert_eq!(callbacks, 0);
    assert_transport_start_trace(&collector, "serve", "receiver");
}

#[test]
fn serve_accepted_trace_carries_stable_structured_fields() -> TestResult {
    let cx = Cx::for_testing();
    let collector = LogCollector::new(16).with_min_level(LogLevel::Trace);
    cx.set_diagnostic_context(DiagnosticContext::new());
    cx.set_log_collector(collector.clone());

    let mut endpoint = bind_managed_server_endpoint(&cx);
    let connection_id = ConnectionId::new(b"h1serve").expect("valid connection id");
    let peer = SocketAddr::from(([127, 0, 0, 1], 57_772));
    block_on(endpoint.create_connection_for_testing(&cx, connection_id, peer))?;
    let temp = tempfile::tempdir()?;
    let mut callbacks = 0usize;

    let result = block_on(transport_quic::serve(
        &cx,
        endpoint,
        temp.path().to_path_buf(),
        trusted_quic_config(),
        "receiver".to_string(),
        |result| {
            callbacks += 1;
            match result {
                Ok(report) => {
                    panic!("unseeded accepted connection must not fake success: {report:?}")
                }
                Err(QuicTransportError::NotImplemented {
                    operation: "receive_connection",
                    ..
                }) => panic!("serve should keep the accepted connection body wired"),
                Err(_) => {}
            }
        },
    ));

    assert!(
        result.is_ok(),
        "serve should drain routed connection: {result:?}"
    );
    assert_eq!(callbacks, 1);
    assert_accepted_trace(
        &collector,
        "atp_quic.serve.accepted",
        connection_id,
        peer,
        "receiver",
    );

    Ok(())
}
