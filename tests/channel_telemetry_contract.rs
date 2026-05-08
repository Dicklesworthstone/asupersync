#![allow(missing_docs)]

use asupersync::channel::{mpsc, oneshot};
use asupersync::cx::Cx;
use asupersync::types::{Budget, CancelKind};
use asupersync::util::ArenaIndex;
use asupersync::{RegionId, TaskId};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::Path;
use std::task::{Context, Poll, Waker};

const CONTRACT_PATH: &str = "artifacts/channel_telemetry_contract_v1.json";

fn telemetry_test_cx() -> Cx {
    Cx::new(
        RegionId::from_arena(ArenaIndex::new(0, 0)),
        TaskId::from_arena(ArenaIndex::new(0, 0)),
        Budget::INFINITE,
    )
}

fn repo_path(relative: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn contract() -> Value {
    let raw = std::fs::read_to_string(repo_path(CONTRACT_PATH))
        .unwrap_or_else(|error| panic!("read {CONTRACT_PATH}: {error}"));
    serde_json::from_str(&raw).unwrap_or_else(|error| panic!("parse {CONTRACT_PATH}: {error}"))
}

fn array<'a>(value: &'a Value, key: &str) -> &'a Vec<Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{key} must be an array"))
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{key} must be a string"));
    assert!(!text.trim().is_empty(), "{key} must be nonempty");
    text
}

fn string_set(value: &Value, key: &str) -> BTreeSet<String> {
    array(value, key)
        .iter()
        .map(|item| {
            item.as_str()
                .unwrap_or_else(|| panic!("{key} entries must be strings"))
                .to_string()
        })
        .collect()
}

fn rows_by_kind(contract: &Value) -> BTreeMap<String, &Value> {
    array(contract, "channel_rows")
        .iter()
        .map(|row| (string(row, "channel_kind").to_string(), row))
        .collect()
}

fn pressure_fields(row: &Value) -> Vec<String> {
    let fields = string_set(row, "metric_fields");
    [
        "queued_messages",
        "reserved_uncommitted_obligations",
        "send_waiter_count",
        "recv_waiter_count",
        "receiver_health",
        "lagged_receiver_count",
        "cancellation_count",
    ]
    .iter()
    .filter(|field| fields.contains(**field))
    .map(|field| (*field).to_string())
    .collect()
}

fn markdown_projection(contract: &Value) -> String {
    let mut lines = vec![
        "| channel_kind | status | required_pressure_fields |".to_string(),
        "| --- | --- | --- |".to_string(),
    ];
    for (kind, row) in rows_by_kind(contract) {
        lines.push(format!(
            "| {kind} | {} | {} |",
            string(row, "report_status"),
            pressure_fields(row).join(", ")
        ));
    }
    lines.join("\n") + "\n"
}

#[test]
fn contract_declares_channel_telemetry_policy_and_sources() {
    let contract = contract();
    assert_eq!(
        contract["contract_version"].as_str(),
        Some("channel-telemetry-contract-v1")
    );
    assert_eq!(contract["bead_id"].as_str(), Some("asupersync-97wkp1"));

    let source = contract
        .get("source_of_truth")
        .expect("source_of_truth object");
    for key in [
        "contract",
        "contract_test",
        "channel_module",
        "flow_control_monitor",
    ] {
        let path = string(source, key);
        assert!(
            repo_path(path).exists(),
            "source_of_truth.{key} must point to a live repo file: {path}"
        );
    }

    let policy = contract
        .get("telemetry_policy")
        .expect("telemetry_policy object");
    assert_eq!(policy["default_mode"].as_str(), Some("disabled"));
    assert_eq!(policy["enabled_mode"].as_str(), Some("opt_in"));
    assert_eq!(policy["lab_runtime_deterministic"].as_bool(), Some(true));
    assert_eq!(policy["no_ambient_globals"].as_bool(), Some(true));
    assert_eq!(
        policy["reserved_uncommitted_obligations_must_be_separate_from_queued_data"].as_bool(),
        Some(true)
    );
}

#[test]
fn contract_covers_all_required_channel_kinds_with_live_source_paths() {
    let contract = contract();
    let required = string_set(&contract, "required_channel_kinds");
    let rows = rows_by_kind(&contract);
    let actual = rows.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(actual, required);

    for (kind, row) in rows {
        let path = string(row, "implementation_path");
        assert!(
            repo_path(path).exists(),
            "{kind} implementation path must exist: {path}"
        );
        assert!(
            !array(row, "core_invariants").is_empty(),
            "{kind} must name core invariants"
        );
    }
}

#[test]
fn metric_fields_keep_reservation_pressure_separate_from_backlog() {
    let contract = contract();
    let required_fields = string_set(&contract, "required_metric_fields");
    for required in [
        "channel_id",
        "channel_kind",
        "queued_messages",
        "reserved_uncommitted_obligations",
        "receiver_health",
        "cancellation_count",
        "closed",
    ] {
        assert!(
            required_fields.contains(required),
            "required_metric_fields must include {required}"
        );
    }

    for (kind, row) in rows_by_kind(&contract) {
        let fields = string_set(row, "metric_fields");
        let raw_fields = array(row, "metric_fields");
        for required in [
            "channel_id",
            "channel_kind",
            "queued_messages",
            "reserved_uncommitted_obligations",
            "receiver_health",
            "cancellation_count",
            "closed",
        ] {
            assert!(fields.contains(required), "{kind} must include {required}");
        }
        assert!(
            fields.contains("queued_messages"),
            "{kind} must expose queued data separately"
        );
        assert!(
            fields.contains("reserved_uncommitted_obligations"),
            "{kind} must expose uncommitted reserves separately"
        );
        let queued_entries = raw_fields
            .iter()
            .filter(|field| field.as_str() == Some("queued_messages"))
            .count();
        let reserve_entries = raw_fields
            .iter()
            .filter(|field| field.as_str() == Some("reserved_uncommitted_obligations"))
            .count();
        assert_eq!(
            queued_entries, 1,
            "{kind} must list queued data exactly once"
        );
        assert_eq!(
            reserve_entries, 1,
            "{kind} must list uncommitted reserves exactly once"
        );
    }
}

#[test]
fn unwired_channel_rows_fail_closed_until_live_metrics_exist() {
    let contract = contract();
    let allowed_statuses = string_set(&contract, "allowed_report_statuses");
    assert!(allowed_statuses.contains("XFAIL"));
    assert!(!allowed_statuses.contains("PASS"));

    for (kind, row) in rows_by_kind(&contract) {
        let status = string(row, "report_status");
        assert!(
            allowed_statuses.contains(status),
            "{kind} status must be recognized"
        );
        if row["live_telemetry_wired"].as_bool() == Some(false) {
            assert_eq!(status, "XFAIL", "{kind} must fail closed while unwired");
            assert!(
                string(row, "status_reason").contains("not wired yet"),
                "{kind} must explain why it is XFAIL"
            );
        }
    }
}

#[test]
fn live_mpsc_snapshot_reports_backlog_waiters_and_cancelled_pressure() {
    let contract = contract();
    let rows = rows_by_kind(&contract);
    let mpsc_row = rows.get("mpsc").expect("mpsc row exists");
    assert_eq!(mpsc_row["live_telemetry_wired"].as_bool(), Some(true));
    assert_eq!(mpsc_row["report_status"].as_str(), Some("LIVE"));

    let cx = telemetry_test_cx();
    let (tx, mut rx) = mpsc::channel::<u8>(2);
    let initial = tx.telemetry_snapshot(197);
    assert_eq!(initial.channel_id, 197);
    assert_eq!(initial.channel_kind, "mpsc");
    assert_eq!(initial.capacity, 2);
    assert_eq!(initial.queued_messages, 0);
    assert_eq!(initial.reserved_uncommitted_obligations, 0);
    assert_eq!(initial.send_waiter_count, 0);
    assert_eq!(initial.recv_waiter_count, 0);
    assert_eq!(initial.receiver_health, "open");
    assert_eq!(initial.lagged_receiver_count, None);
    assert_eq!(initial.cancellation_count, 0);
    assert!(!initial.closed);

    let permit = tx.try_reserve().expect("try_reserve succeeds");
    let reserved = permit.telemetry_snapshot(197);
    assert_eq!(reserved.queued_messages, 0);
    assert_eq!(reserved.reserved_uncommitted_obligations, 1);
    assert_eq!(reserved.receiver_health, "open");
    assert!(!reserved.closed);

    permit.abort();
    let aborted = rx.telemetry_snapshot(197);
    assert_eq!(aborted.queued_messages, 0);
    assert_eq!(aborted.reserved_uncommitted_obligations, 0);
    assert_eq!(aborted.cancellation_count, 1);
    assert_eq!(aborted.receiver_health, "open");

    tx.try_send(11).expect("try_send succeeds");
    let ready = rx.telemetry_snapshot(197);
    assert_eq!(ready.queued_messages, 1);
    assert_eq!(ready.reserved_uncommitted_obligations, 0);
    assert_eq!(ready.receiver_health, "value_ready");
    assert!(!ready.closed);

    assert_eq!(rx.try_recv().expect("value ready"), 11);
    let drained = tx.telemetry_snapshot(197);
    assert_eq!(drained.queued_messages, 0);
    assert_eq!(drained.cancellation_count, 1);

    let (tx, mut rx) = mpsc::channel::<u8>(1);
    tx.try_send(7).expect("fill channel");
    let mut reserve = Box::pin(tx.reserve(&cx));
    let waker = Waker::noop().clone();
    let mut task_cx = Context::from_waker(&waker);
    assert!(matches!(reserve.as_mut().poll(&mut task_cx), Poll::Pending));
    let waiting = tx.telemetry_snapshot(198);
    assert_eq!(waiting.queued_messages, 1);
    assert_eq!(waiting.reserved_uncommitted_obligations, 0);
    assert_eq!(waiting.send_waiter_count, 1);
    drop(reserve);
    assert_eq!(tx.telemetry_snapshot(198).send_waiter_count, 0);

    let mut recv = Box::pin(rx.recv(&cx));
    assert!(matches!(
        recv.as_mut().poll(&mut task_cx),
        Poll::Ready(Ok(7))
    ));
    drop(recv);

    let cancelled_cx = telemetry_test_cx();
    cancelled_cx.cancel_with(CancelKind::User, Some("channel telemetry contract"));
    let (tx, mut rx) = mpsc::channel::<u8>(1);
    let mut reserve = Box::pin(tx.reserve(&cancelled_cx));
    assert!(matches!(
        reserve.as_mut().poll(&mut task_cx),
        Poll::Ready(Err(mpsc::SendError::Cancelled(())))
    ));
    drop(reserve);
    let after_cancelled_reserve = tx.telemetry_snapshot(199);
    assert_eq!(after_cancelled_reserve.cancellation_count, 1);
    assert_eq!(after_cancelled_reserve.reserved_uncommitted_obligations, 0);
    assert!(!after_cancelled_reserve.closed);

    let mut recv = Box::pin(rx.recv(&cancelled_cx));
    assert!(matches!(
        recv.as_mut().poll(&mut task_cx),
        Poll::Ready(Err(mpsc::RecvError::Cancelled))
    ));
    drop(recv);
    let after_cancelled_recv = rx.telemetry_snapshot(199);
    assert_eq!(after_cancelled_recv.cancellation_count, 2);
    assert!(!after_cancelled_recv.closed);
    drop(tx);
    let after_sender_drop = rx.telemetry_snapshot(199);
    assert!(after_sender_drop.closed);
    assert_eq!(after_sender_drop.receiver_health, "sender_closed");

    let (tx, rx) = mpsc::channel::<u8>(1);
    drop(rx);
    let after_receiver_drop = tx.telemetry_snapshot(200);
    assert!(after_receiver_drop.closed);
    assert_eq!(after_receiver_drop.receiver_health, "receiver_dropped");
}

#[test]
fn live_oneshot_snapshot_reports_reserved_queued_and_cancelled_pressure() {
    let contract = contract();
    let rows = rows_by_kind(&contract);
    let oneshot_row = rows.get("oneshot").expect("oneshot row exists");
    assert_eq!(oneshot_row["live_telemetry_wired"].as_bool(), Some(true));
    assert_eq!(oneshot_row["report_status"].as_str(), Some("LIVE"));

    let cx = telemetry_test_cx();
    let (tx, rx) = oneshot::channel::<u8>();
    let initial = tx.telemetry_snapshot(97);
    assert_eq!(initial.channel_id, 97);
    assert_eq!(initial.channel_kind, "oneshot");
    assert_eq!(initial.capacity, 1);
    assert_eq!(initial.queued_messages, 0);
    assert_eq!(initial.reserved_uncommitted_obligations, 0);
    assert_eq!(initial.recv_waiter_count, 0);
    assert_eq!(initial.receiver_health, "open");
    assert_eq!(initial.lagged_receiver_count, None);
    assert_eq!(initial.cancellation_count, 0);
    assert!(!initial.closed);

    let permit = tx.reserve(&cx).expect("reserve succeeds");
    let reserved = permit.telemetry_snapshot(97);
    assert_eq!(reserved.queued_messages, 0);
    assert_eq!(reserved.reserved_uncommitted_obligations, 1);
    assert_eq!(reserved.receiver_health, "open");
    assert!(!reserved.closed);

    let receiver_view = rx.telemetry_snapshot(97);
    assert_eq!(receiver_view.reserved_uncommitted_obligations, 1);
    assert_eq!(receiver_view.queued_messages, 0);
    assert_eq!(receiver_view.cancellation_count, 0);

    permit.abort();
    let aborted = rx.telemetry_snapshot(97);
    assert_eq!(aborted.queued_messages, 0);
    assert_eq!(aborted.reserved_uncommitted_obligations, 0);
    assert_eq!(aborted.receiver_health, "sender_closed");
    assert_eq!(aborted.cancellation_count, 1);
    assert!(aborted.closed);
    assert_eq!(aborted.closed_reason, Some("abort"));

    let (tx, mut rx) = oneshot::channel::<u8>();
    tx.send(&cx, 11).expect("send succeeds");
    let ready = rx.telemetry_snapshot(98);
    assert_eq!(ready.queued_messages, 1);
    assert_eq!(ready.reserved_uncommitted_obligations, 0);
    assert_eq!(ready.receiver_health, "value_ready");
    assert!(!ready.closed);

    assert_eq!(rx.try_recv().expect("value ready"), 11);
    let committed = rx.telemetry_snapshot(98);
    assert_eq!(committed.queued_messages, 0);
    assert!(committed.closed);
    assert_eq!(committed.closed_reason, Some("committed"));

    let cancelled_cx = telemetry_test_cx();
    cancelled_cx.cancel_with(CancelKind::User, Some("channel telemetry contract"));
    let (tx, mut rx) = oneshot::channel::<u8>();
    let waker = Waker::noop().clone();
    let mut task_cx = Context::from_waker(&waker);
    let mut recv = Box::pin(rx.recv(&cancelled_cx));
    assert!(matches!(
        recv.as_mut().poll(&mut task_cx),
        Poll::Ready(Err(oneshot::RecvError::Cancelled))
    ));
    drop(recv);

    let after_cancelled_recv = rx.telemetry_snapshot(99);
    assert_eq!(after_cancelled_recv.cancellation_count, 1);
    assert!(!after_cancelled_recv.closed);
    drop(tx);
    let after_sender_drop = rx.telemetry_snapshot(99);
    assert!(after_sender_drop.closed);
    assert_eq!(after_sender_drop.closed_reason, Some("sender_drop"));
}

#[test]
fn receiver_health_and_lag_are_explicit_for_multireceiver_channels() {
    let contract = contract();
    let rows = rows_by_kind(&contract);
    for kind in ["broadcast", "watch", "session"] {
        let row = rows.get(kind).expect("row for multireceiver channel");
        let fields = string_set(row, "metric_fields");
        assert!(
            fields.contains("receiver_health"),
            "{kind} must expose receiver_health"
        );
        assert!(
            fields.contains("lagged_receiver_count"),
            "{kind} must expose lagged_receiver_count"
        );
    }
}

#[test]
fn golden_markdown_projection_is_stable_and_redacted() {
    let contract = contract();
    let expected = string(&contract, "golden_markdown");
    let actual = markdown_projection(&contract);
    assert_eq!(actual, expected);

    for forbidden in [
        "/home/ubuntu/",
        "body_md",
        "ack_required",
        "Authorization: Bearer ",
    ] {
        assert!(
            !actual.contains(forbidden),
            "markdown projection must not expose raw coordination marker {forbidden}"
        );
    }
}

#[test]
fn proof_commands_are_rch_routed_and_target_this_contract() {
    let contract = contract();
    let commands = string_set(&contract, "proof_commands");
    assert!(
        commands
            .iter()
            .any(|command| command.contains("--test channel_telemetry_contract")),
        "contract must name its own proof command"
    );
    for command in commands {
        assert!(
            command.starts_with("rch exec -- "),
            "proof command must be rch-routed: {command}"
        );
    }
}
