//! G3.3 (asupersync-atp-dataplane-redesign-317hxr.14.3): observability invariants
//! for the ATP-RQ data plane.
//!
//! Two type-level / structural guarantees that gate the "SEE it work" contract:
//!
//!   * **CLI metrics presence** — the `SendReport` / `ReceiveReport` types that
//!     `atp send` / `atp recv` serialize into their JSON report carry the declared
//!     G3 aggregate metrics (symbols sent/accepted, feedback rounds, bytes, files).
//!     Pinning the fields here means a rename/removal fails this test AND breaks
//!     the CLI's `rq_send_json`/`rq_recv_json` in lockstep, so the user never
//!     silently loses the convergence/saturation signal.
//!   * **No-manifest-leak** — the committed `TransferManifest` (the persisted
//!     content descriptor sent in the `ObjectManifest` frame) must NOT carry any
//!     runtime metric/trace field. Metrics belong in the report/receipt, never in
//!     the manifest; leaking them would bloat the wire manifest and entangle
//!     persisted content identity with transient runtime state.
//!
//! The third G3.3 leg — trace-emission completeness (each component emits its
//! declared `cx.trace` fields on a real transfer) — requires the lab runtime with
//! a trace sink and lives in the e2e/lab suite; these structural checks are the
//! runtime-free, code-first portion.

use asupersync::net::atp::transport_rq::{
    ManifestEntry, ReceiveReceipt, ReceiveReport, SendReport, TransferManifest,
};

/// Runtime metric/trace field names that belong in the report/receipt (the CLI
/// JSON) and must NEVER appear in the committed manifest.
const RUNTIME_METRIC_KEYS: &[&str] = &[
    "symbols_sent",
    "symbols_accepted",
    "feedback_rounds",
    "bytes_sent",
    "bytes_received",
    "decode_time",
    "decode_ms",
    "peak_rss",
    "avg_rss",
    "ring_occupancy",
    "fan_out",
    "fanout",
    "drop_count",
    "park_count",
    "throughput",
    "cpu_pct",
    "wall_s",
    "wall_ms",
];

#[test]
fn send_report_carries_declared_g3_metrics() {
    let receipt = ReceiveReceipt {
        committed: true,
        bytes_received: 1024,
        files: 1,
        sha_ok: true,
        merkle_ok: true,
        symbols_accepted: 80,
        feedback_rounds: 2,
        reason: None,
        committed_paths: Vec::new(),
    };
    let report = SendReport {
        transfer_id: "abc123".to_string(),
        bytes_sent: 1024,
        files: 1,
        symbols_sent: 96,
        feedback_rounds: 2,
        merkle_root_hex: "00".repeat(32),
        receipt,
        udp_send_acceleration: Default::default(),
        peer: "127.0.0.1:8472".parse().unwrap(),
    };

    // These are exactly what the CLI's rq_send_json/tcp_send_json serialize.
    assert_eq!(report.symbols_sent, 96);
    assert_eq!(report.feedback_rounds, 2);
    assert_eq!(report.bytes_sent, 1024);
    assert_eq!(report.files, 1);
    // Receiver-side metrics ride along in the receipt the sender reports.
    assert_eq!(report.receipt.symbols_accepted, 80);
    assert_eq!(report.receipt.feedback_rounds, 2);
    assert!(report.receipt.sha_ok && report.receipt.merkle_ok);
}

#[test]
fn receive_report_carries_declared_g3_metrics() {
    let report = ReceiveReport {
        transfer_id: "abc123".to_string(),
        bytes_received: 2048,
        files: 3,
        committed: true,
        symbols_accepted: 200,
        feedback_rounds: 1,
        committed_paths: Vec::new(),
        peer: "127.0.0.1:8472".parse().unwrap(),
    };

    assert_eq!(report.symbols_accepted, 200);
    assert_eq!(report.feedback_rounds, 1);
    assert_eq!(report.bytes_received, 2048);
    assert_eq!(report.files, 3);
    assert!(report.committed);
}

#[test]
fn committed_manifest_does_not_leak_runtime_metrics() {
    let manifest = TransferManifest {
        transfer_id: "deadbeef".to_string(),
        root_name: "tree".to_string(),
        is_directory: true,
        total_bytes: 1024,
        merkle_root_hex: "00".repeat(32),
        entries: vec![ManifestEntry {
            index: 0,
            rel_path: "a/b.bin".to_string(),
            size: 1024,
            sha256_hex: "ab".repeat(32),
            members: Vec::new(),
            fragment: None,
        }],
    };

    let json = serde_json::to_string(&manifest).expect("serialize transfer manifest");
    for key in RUNTIME_METRIC_KEYS {
        assert!(
            !json.contains(key),
            "committed manifest leaks runtime metric field {key:?}; manifest JSON = {json}"
        );
    }

    // Positive control: the manifest DOES carry its content-descriptor fields, so
    // the negative assertions above are meaningful (not vacuous on an empty blob).
    assert!(json.contains("transfer_id"));
    assert!(json.contains("merkle_root_hex"));
    assert!(json.contains("total_bytes"));
    assert!(json.contains("sha256_hex"));
}
