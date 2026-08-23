//! Maintained cross-subsystem recovery journeys for `asupersync-d24mms.12.3`.
//!
//! The undeclared `real_integration_scenarios_e2e_tests.rs` file remains audit
//! history: it depends on Tokio, ambient wall time, unseeded randomness, and
//! several removed APIs. This lane restores the useful behavior against current
//! Asupersync components with deterministic inputs and machine-readable receipts.

use crate::Cx;
use crate::bytes::{Bytes, BytesMut};
use crate::channel::{broadcast, mpsc};
use crate::codec::{Decoder, Encoder};
use crate::combinator::{CircuitBreaker, CircuitBreakerError, CircuitBreakerPolicy, State};
use crate::distributed::{RegionBridge, SyncResult};
use crate::http::h2::connection::FrameCodec;
use crate::http::h2::frame::{Frame, SettingsFrame};
use crate::http::h2::{Connection, ErrorCode, Header, Settings};
use crate::lab::{
    SNAPSHOT_ARTIFACT_MAGIC, SnapshotArtifact, SnapshotArtifactKind, SnapshotLimits,
    SnapshotRestore,
};
use crate::raptorq::decoder::{InactivationDecoder, ReceivedSymbol};
use crate::raptorq::systematic::SystematicEncoder;
use crate::record::region::RegionState;
use crate::runtime::{RuntimeBuilder, RuntimeState};
use crate::service::{RateLimit, Service};
use crate::time::TimerWheel;
use crate::types::{Budget, CancelReason, CheckpointState, RegionId, TaskId, Time};
use serde_json::{Value, json};
use std::convert::Infallible;
use std::future::{Future, Ready, ready};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

const BEAD_ID: &str = "asupersync-d24mms.12.3";
const FEATURE_PROFILE: &str = "cross-subsystem-recovery-e2e";
const SEED: u64 = 0xD24D_1203;

fn active_bead_id() -> String {
    std::env::var("ASUPERSYNC_CROSS_SUBSYSTEM_BEAD_ID").unwrap_or_else(|_| BEAD_ID.to_owned())
}

fn replay_command() -> String {
    format!(
        "RCH_REQUIRE_REMOTE=1 ASUPERSYNC_CROSS_SUBSYSTEM_BEAD_ID={} \
         bash scripts/cross_subsystem_recovery_proof_runner.sh",
        active_bead_id()
    )
}

fn emit_pass(
    scenario_id: &str,
    subsystem: &str,
    operation: &str,
    expected: Value,
    actual: Value,
    cancellation_point: &str,
    cleanup_status: &str,
) {
    println!(
        "{}",
        json!({
            "bead_id": active_bead_id(),
            "scenario_id": scenario_id,
            "capability_ids": ["CAP-REAL-SERVICE-E2E", "CAP-VERIFICATION-PROFILES"],
            "subsystem": subsystem,
            "feature_flags": [FEATURE_PROFILE],
            "operation": operation,
            "deterministic_seed": SEED,
            "expected": expected,
            "actual": actual,
            "cancellation_point": cancellation_point,
            "cleanup_status": cleanup_status,
            "unsupported_reason": null,
            "verdict": "pass",
            "first_failure": null,
            "replay_command": replay_command(),
        })
    );
}

fn emit_placeholder_disposition() {
    println!(
        "{}",
        json!({
            "bead_id": active_bead_id(),
            "scenario_id": "DORMANT-INT-005",
            "capability_ids": ["CAP-REAL-SERVICE-E2E", "CAP-VERIFICATION-PROFILES"],
            "subsystem": "inventory",
            "feature_flags": [FEATURE_PROFILE],
            "operation": "placeholder_non_evidence_disposition",
            "deterministic_seed": SEED,
            "expected": {"coverage": "none"},
            "actual": {"coverage": "none", "source_preserved": true},
            "cancellation_point": "not_applicable",
            "cleanup_status": "no_resources_created",
            "unsupported_reason": "PLACEHOLDER_NOT_EVIDENCE",
            "verdict": "skip",
            "first_failure": null,
            "replay_command": replay_command(),
        })
    );
}

fn scenario_pubsub_partial_consumer_failure() {
    let cx = Cx::for_testing();
    let (sender, mut healthy_a) = broadcast::channel(4);
    let mut failed = sender.subscribe();
    let mut healthy_b = sender.subscribe();

    assert_eq!(sender.send(&cx, 10_u8), Ok(3), "DORMANT-INT-001/send-10");
    assert_eq!(healthy_a.try_recv(), Ok(10), "DORMANT-INT-001/healthy-a-10");
    assert_eq!(
        failed.try_recv(),
        Ok(10),
        "DORMANT-INT-001/failing-consumer-10"
    );
    drop(failed);
    assert_eq!(sender.receiver_count(), 2, "DORMANT-INT-001/drop-consumer");
    assert_eq!(sender.send(&cx, 11_u8), Ok(2), "DORMANT-INT-001/send-11");
    assert_eq!(healthy_a.try_recv(), Ok(11), "DORMANT-INT-001/healthy-a-11");
    assert_eq!(healthy_b.try_recv(), Ok(10), "DORMANT-INT-001/healthy-b-10");
    assert_eq!(healthy_b.try_recv(), Ok(11), "DORMANT-INT-001/healthy-b-11");
    drop(sender);
    assert!(matches!(
        healthy_a.try_recv(),
        Err(broadcast::TryRecvError::Closed)
    ));
    assert!(matches!(
        healthy_b.try_recv(),
        Err(broadcast::TryRecvError::Closed)
    ));

    emit_pass(
        "DORMANT-INT-001",
        "channel::broadcast",
        "fanout_after_consumer_drop",
        json!({"healthy_deliveries": 4, "remaining_receivers": 2}),
        json!({"healthy_deliveries": 4, "remaining_receivers": 2}),
        "consumer_drop_between_commits",
        "all_senders_dropped_and_receivers_closed",
    );
}

fn scenario_circuit_breaker_cascade_recovery() {
    let policy = CircuitBreakerPolicy {
        failure_threshold: 2,
        success_threshold: 1,
        open_duration: Duration::from_millis(10),
        ..CircuitBreakerPolicy::default()
    };
    let edge = CircuitBreaker::new(policy.clone());
    let origin = CircuitBreaker::new(policy);
    let now = Time::from_millis(100);

    for breaker in [&edge, &origin] {
        for _ in 0..2 {
            let result = breaker.call(now, || Err::<(), _>("dependency-down"));
            assert!(matches!(result, Err(CircuitBreakerError::Inner(_))));
        }
        assert!(matches!(breaker.state(), State::Open { .. }));
        assert!(matches!(
            breaker.call(now, || Ok::<_, &str>(())),
            Err(CircuitBreakerError::Open { .. })
        ));
    }

    let recovered_at = Time::from_millis(111);
    assert!(matches!(
        edge.call(recovered_at, || Ok::<_, &str>(7_u8)),
        Ok(7)
    ));
    assert!(matches!(
        origin.call(recovered_at, || Ok::<_, &str>(9_u8)),
        Ok(9)
    ));
    assert!(matches!(edge.state(), State::Closed { failures: 0 }));
    assert!(matches!(origin.state(), State::Closed { failures: 0 }));
    let edge_metrics = edge.metrics();
    let origin_metrics = origin.metrics();
    assert_eq!(
        (edge_metrics.times_opened, edge_metrics.times_closed),
        (1, 1)
    );
    assert_eq!(
        (origin_metrics.times_opened, origin_metrics.times_closed),
        (1, 1)
    );

    emit_pass(
        "DORMANT-INT-002",
        "combinator::circuit_breaker",
        "two_tier_open_half_open_recovery",
        json!({"opened": 2, "closed": 2, "rejections": 2}),
        json!({"opened": 2, "closed": 2, "rejections": 2}),
        "virtual_time_open_window",
        "no_active_half_open_probes",
    );
}

fn close_bridge(bridge: &mut RegionBridge, now: Time) {
    bridge
        .begin_close(Some(CancelReason::user("injected-region-failure")), now)
        .expect("DORMANT-INT-003/begin-close");
    for task in bridge.local().task_ids() {
        bridge.remove_task(task);
    }
    assert!(bridge.begin_drain().expect("DORMANT-INT-003/begin-drain"));
    assert!(
        bridge
            .begin_finalize()
            .expect("DORMANT-INT-003/begin-finalize")
    );
    bridge
        .complete_close(now.saturating_add_nanos(1))
        .expect("DORMANT-INT-003/complete-close");
}

fn scenario_region_failure_isolation() {
    let mut failed =
        RegionBridge::new_local(RegionId::new_for_test(31, 0), None, Budget::default());
    let mut healthy =
        RegionBridge::new_local(RegionId::new_for_test(32, 0), None, Budget::default());
    failed
        .add_task(TaskId::new_for_test(310, 0))
        .expect("DORMANT-INT-003/add-failed-task");
    healthy
        .add_task(TaskId::new_for_test(320, 0))
        .expect("DORMANT-INT-003/add-healthy-task");

    close_bridge(&mut failed, Time::from_secs(1));
    healthy
        .add_task(TaskId::new_for_test(321, 0))
        .expect("DORMANT-INT-003/healthy-progress");

    assert_eq!(failed.local_state(), RegionState::Closed);
    assert!(!failed.has_live_work());
    assert_eq!(healthy.local_state(), RegionState::Open);
    assert_eq!(healthy.local().task_ids().len(), 2);
    for task in healthy.local().task_ids() {
        healthy.remove_task(task);
    }
    close_bridge(&mut healthy, Time::from_secs(2));
    assert!(!healthy.has_live_work());

    emit_pass(
        "DORMANT-INT-003",
        "distributed::RegionBridge",
        "isolated_region_close_with_peer_progress",
        json!({"failed_state": "Closed", "healthy_progress_tasks": 2}),
        json!({"failed_state": "Closed", "healthy_progress_tasks": 2}),
        "failed_region_begin_close",
        "both_regions_closed_without_live_work",
    );
}

fn scenario_pipeline_backpressure() {
    let (stage_one_tx, mut stage_one_rx) = mpsc::channel(2);
    let (stage_two_tx, mut stage_two_rx) = mpsc::channel(1);
    stage_one_tx
        .try_send(1_u8)
        .expect("DORMANT-INT-004/stage1-send-1");
    stage_one_tx
        .try_send(2_u8)
        .expect("DORMANT-INT-004/stage1-send-2");
    assert!(matches!(
        stage_one_tx.try_send(3),
        Err(mpsc::SendError::Full(3))
    ));

    let first = stage_one_rx
        .try_recv()
        .expect("DORMANT-INT-004/stage1-recv-1");
    stage_two_tx
        .try_send(first)
        .expect("DORMANT-INT-004/stage2-send-1");
    let second = stage_one_rx
        .try_recv()
        .expect("DORMANT-INT-004/stage1-recv-2");
    assert!(matches!(
        stage_two_tx.try_send(second),
        Err(mpsc::SendError::Full(2))
    ));
    assert_eq!(stage_two_rx.try_recv(), Ok(1));
    stage_two_tx
        .try_send(second)
        .expect("DORMANT-INT-004/stage2-retry");
    assert_eq!(stage_two_rx.try_recv(), Ok(2));
    drop(stage_one_tx);
    drop(stage_two_tx);
    assert!(matches!(
        stage_one_rx.try_recv(),
        Err(mpsc::RecvError::Disconnected)
    ));
    assert!(matches!(
        stage_two_rx.try_recv(),
        Err(mpsc::RecvError::Disconnected)
    ));

    emit_pass(
        "DORMANT-INT-004",
        "channel::mpsc",
        "bounded_two_stage_pipeline_recovery",
        json!({"accepted": 2, "delivered": [1, 2], "full_events": 2}),
        json!({"accepted": 2, "delivered": [1, 2], "full_events": 2}),
        "stage_two_full_before_retry",
        "queues_drained_and_endpoints_disconnected",
    );
}

fn scenario_worker_failure_obligation_cleanup() {
    crate::real_obligation_leak_check_e2e_tests::run_supervisor_restart_pending_ack_cleanup_e2e();
    emit_pass(
        "DORMANT-INT-006",
        "runtime::obligation_ledger",
        "supervisor_restart_pending_ack_cleanup",
        json!({"pending_after": 0, "leaked_after": 0}),
        json!({"pending_after": 0, "leaked_after": 0}),
        "seeded_restart_with_pending_ack_obligations",
        "real_harness_asserted_empty_ledger_and_quiescence",
    );
}

struct CancellationAwareLoser {
    drops: Arc<AtomicUsize>,
    cancellations: Arc<AtomicUsize>,
}

impl Future for CancellationAwareLoser {
    type Output = u8;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Cx::current().is_some_and(|cx| cx.checkpoint().is_err()) {
            self.cancellations.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(0)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for CancellationAwareLoser {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}

fn scenario_hedge_first_success_loser_cancel() {
    let drops = Arc::new(AtomicUsize::new(0));
    let cancellations = Arc::new(AtomicUsize::new(0));
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("DORMANT-INT-007/build-runtime");
    let winner = runtime.block_on(async {
        let cx = Cx::current().expect("DORMANT-INT-007/runtime-cx");
        let branches: Vec<Pin<Box<dyn Future<Output = u8> + Send>>> = vec![
            Box::pin(async { 42_u8 }),
            Box::pin(CancellationAwareLoser {
                drops: Arc::clone(&drops),
                cancellations: Arc::clone(&cancellations),
            }),
        ];
        cx.race_drained(branches)
            .await
            .expect("DORMANT-INT-007/race-drained")
    });
    assert_eq!(winner, 42, "DORMANT-INT-007/first-success");
    assert_eq!(
        drops.load(Ordering::SeqCst),
        1,
        "DORMANT-INT-007/loser-drop"
    );
    assert_eq!(
        cancellations.load(Ordering::SeqCst),
        1,
        "DORMANT-INT-007/loser-cancellation-checkpoint"
    );

    emit_pass(
        "DORMANT-INT-007",
        "runtime::Cx::race_drained",
        "pre_admitted_zero_delay_hedge_with_loser_drain",
        json!({"winner_value": 42, "commits": 1, "loser_drops": 1, "cancellation_checkpoints": 1}),
        json!({
            "winner_value": winner,
            "commits": 1,
            "loser_drops": drops.load(Ordering::SeqCst),
            "cancellation_checkpoints": cancellations.load(Ordering::SeqCst),
        }),
        "first_success_cancels_pending_branch",
        "pending_loser_cancelled_and_drained_before_return",
    );
}

fn scenario_distributed_bridge_rolling_restart() {
    let region_id = RegionId::new_for_test(80, 0);
    let mut active = RegionBridge::new_local(region_id, None, Budget::default());
    for generation in 1..=3_u32 {
        active
            .add_task(TaskId::new_for_test(800 + generation, 0))
            .expect("DORMANT-INT-008/add-task");
        let snapshot = active.create_snapshot(Time::from_secs(u64::from(generation)));
        let mut replacement = RegionBridge::new_local(region_id, None, Budget::default());
        replacement
            .apply_snapshot(&snapshot)
            .expect("DORMANT-INT-008/apply-restart-snapshot");
        assert_eq!(replacement.local().task_ids(), active.local().task_ids());
        assert_eq!(
            replacement.sync_state.last_synced_sequence,
            u64::from(generation)
        );
    }
    for task in active.local().task_ids() {
        active.remove_task(task);
    }
    close_bridge(&mut active, Time::from_secs(4));

    emit_pass(
        "DORMANT-INT-008",
        "distributed::RegionBridge",
        "three_generation_snapshot_restart",
        json!({"restarts": 3, "final_sequence": 3, "retained_tasks": 3}),
        json!({"restarts": 3, "final_sequence": 3, "retained_tasks": 3}),
        "replacement_between_snapshot_generations",
        "active_bridge_closed_without_live_work",
    );
}

fn scenario_broker_death_reconnect() {
    let cx = Cx::for_testing();
    let (first_sender, mut first_receiver) = broadcast::channel(2);
    assert_eq!(first_sender.send(&cx, 1_u8), Ok(1));
    assert_eq!(first_receiver.try_recv(), Ok(1));
    drop(first_sender);
    assert!(matches!(
        first_receiver.try_recv(),
        Err(broadcast::TryRecvError::Closed)
    ));

    let (second_sender, mut second_receiver) = broadcast::channel(2);
    assert_eq!(second_sender.send(&cx, 2_u8), Ok(1));
    assert_eq!(second_sender.send(&cx, 3_u8), Ok(1));
    assert_eq!(second_receiver.try_recv(), Ok(2));
    assert_eq!(second_receiver.try_recv(), Ok(3));
    drop(second_sender);
    assert!(matches!(
        second_receiver.try_recv(),
        Err(broadcast::TryRecvError::Closed)
    ));

    emit_pass(
        "DORMANT-INT-009",
        "channel::broadcast",
        "broker_generation_reconnect_and_resumed_fanout",
        json!({"accepted": 3, "delivered": 3, "disconnects": 1}),
        json!({"accepted": 3, "delivered": 3, "disconnects": 1}),
        "sender_generation_drop",
        "both_broker_generations_closed",
    );
}

fn scenario_raptorq_interruption_resume() {
    const K: usize = 8;
    const SYMBOL_SIZE: usize = 32;
    let source: Vec<Vec<u8>> = (0..K)
        .map(|esi| {
            (0..SYMBOL_SIZE)
                .map(|offset| ((esi * SYMBOL_SIZE + offset) % 251) as u8)
                .collect()
        })
        .collect();
    let mut encoder =
        SystematicEncoder::new(&source, SYMBOL_SIZE, SEED).expect("DORMANT-INT-010/encoder");
    let emitted = encoder.emit_systematic();
    let decoder = InactivationDecoder::new(K, SYMBOL_SIZE, SEED);
    let mut retained = decoder.constraint_symbols();
    retained.extend(
        emitted
            .iter()
            .take(3)
            .map(|symbol| ReceivedSymbol::source(symbol.esi, symbol.data.clone())),
    );
    assert!(
        decoder.decode(&retained).is_err(),
        "DORMANT-INT-010/interruption"
    );
    retained.extend(
        emitted
            .iter()
            .skip(3)
            .map(|symbol| ReceivedSymbol::source(symbol.esi, symbol.data.clone())),
    );
    let decoded = decoder
        .decode(&retained)
        .expect("DORMANT-INT-010/resume-decode");
    assert_eq!(decoded.source, source, "DORMANT-INT-010/exact-payload");
    drop(retained);

    emit_pass(
        "DORMANT-INT-010",
        "raptorq",
        "retain_partial_symbols_then_resume_decode",
        json!({"source_symbols": K, "interruption_after": 3, "bytes": K * SYMBOL_SIZE}),
        json!({"source_symbols": decoded.source.len(), "interruption_after": 3, "bytes": K * SYMBOL_SIZE}),
        "insufficient_symbol_decode_boundary",
        "retained_equations_released_after_exact_reconstruction",
    );
}

fn scenario_runtime_panic_recovery_subscriptions() {
    let runtime = RuntimeBuilder::current_thread()
        .build()
        .expect("DORMANT-INT-011/build-runtime");
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        runtime.block_on(async {
            panic!("DORMANT-INT-011/injected-subscription-panic");
        });
    }));
    assert!(panicked.is_err(), "DORMANT-INT-011/panic-contained");

    let delivered = runtime.block_on(async {
        let cx = Cx::current().expect("DORMANT-INT-011/runtime-cx");
        let (sender, mut receiver) = broadcast::channel(2);
        let count = sender
            .send(&cx, 77_u8)
            .expect("DORMANT-INT-011/replacement-send");
        let value = receiver
            .try_recv()
            .expect("DORMANT-INT-011/replacement-recv");
        drop(sender);
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::TryRecvError::Closed)
        ));
        (count, value)
    });
    assert_eq!(delivered, (1, 77));

    emit_pass(
        "DORMANT-INT-011",
        "runtime+channel::broadcast",
        "contain_block_on_panic_then_reuse_runtime",
        json!({"panic_contained": true, "replacement_delivery": 77}),
        json!({"panic_contained": true, "replacement_delivery": delivered.1}),
        "panic_unwind_boundary",
        "replacement_subscription_closed_explicitly",
    );
}

#[derive(Clone, Copy)]
struct EchoService;

impl Service<u8> for EchoService {
    type Response = u8;
    type Error = Infallible;
    type Future = Ready<Result<u8, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: u8) -> Self::Future {
        ready(Ok(request))
    }
}

fn poll_ready_value<F: Future + Unpin>(future: &mut F) -> F::Output {
    let waker = Waker::noop();
    let mut task_cx = Context::from_waker(waker);
    match Pin::new(future).poll(&mut task_cx) {
        Poll::Ready(value) => value,
        Poll::Pending => panic!("DORMANT-INT-012/accepted-service-future-pended"),
    }
}

fn scenario_rate_limit_burst_recovery() {
    let mut service = RateLimit::new(EchoService, 3, Duration::from_secs(1));
    let waker = Waker::noop();
    let mut task_cx = Context::from_waker(waker);
    let mut completed = Vec::new();
    for request in 0..3_u8 {
        assert!(matches!(
            service.poll_ready_with_time::<u8>(Time::ZERO, &mut task_cx),
            Poll::Ready(Ok(()))
        ));
        let mut response = service.call(request);
        completed.push(poll_ready_value(&mut response).expect("infallible echo"));
    }
    assert!(matches!(
        service.poll_ready_with_time::<u8>(Time::ZERO, &mut task_cx),
        Poll::Pending
    ));
    assert!(matches!(
        service.poll_ready_with_time::<u8>(Time::from_secs(1), &mut task_cx),
        Poll::Ready(Ok(()))
    ));
    let mut recovered = service.call(3_u8);
    completed.push(poll_ready_value(&mut recovered).expect("infallible echo"));
    assert_eq!(completed, vec![0, 1, 2, 3]);

    emit_pass(
        "DORMANT-INT-012",
        "service::RateLimit",
        "burst_exhaustion_virtual_time_refill",
        json!({"initial_admitted": 3, "blocked": 1, "post_refill": 1, "backlog": 0}),
        json!({"initial_admitted": 3, "blocked": 1, "post_refill": 1, "backlog": 0}),
        "token_bucket_empty",
        "all_admitted_requests_completed",
    );
}

fn encode_settings_frame() -> Vec<u8> {
    let mut codec = FrameCodec::new();
    let mut wire = BytesMut::new();
    codec
        .encode(Frame::Settings(SettingsFrame::new(Vec::new())), &mut wire)
        .expect("DORMANT-INT-013/encode-settings");
    wire.to_vec()
}

fn scenario_http2_loopback_slot_reclamation() {
    const CONNECTIONS: usize = 32;
    let listener = TcpListener::bind("127.0.0.1:0").expect("DORMANT-INT-013/bind-loopback");
    let address = listener.local_addr().expect("DORMANT-INT-013/local-addr");
    let server = std::thread::spawn(move || {
        for _ in 0..CONNECTIONS {
            let (mut stream, _) = listener.accept().expect("DORMANT-INT-013/accept");
            let mut header = [0_u8; 9];
            stream
                .read_exact(&mut header)
                .expect("DORMANT-INT-013/read-frame");
            let mut bytes = BytesMut::from(&header[..]);
            let mut codec = FrameCodec::new();
            let frame = codec
                .decode(&mut bytes)
                .expect("DORMANT-INT-013/decode-settings")
                .expect("DORMANT-INT-013/complete-settings");
            let mut connection = Connection::server(Settings::default());
            connection
                .process_frame(frame)
                .expect("DORMANT-INT-013/process-settings");
            assert_eq!(connection.active_stream_count(), 0);
            stream.write_all(b"A").expect("DORMANT-INT-013/write-ack");
        }
    });

    let settings = encode_settings_frame();
    assert_eq!(settings.len(), 9, "DORMANT-INT-013/settings-wire-size");
    for _ in 0..CONNECTIONS {
        let mut stream = TcpStream::connect(address).expect("DORMANT-INT-013/connect");
        stream
            .write_all(&settings)
            .expect("DORMANT-INT-013/write-settings");
        stream
            .shutdown(Shutdown::Write)
            .expect("DORMANT-INT-013/shutdown-write");
        let mut ack = [0_u8; 1];
        stream
            .read_exact(&mut ack)
            .expect("DORMANT-INT-013/read-ack");
        assert_eq!(ack, *b"A");
    }
    server.join().expect("DORMANT-INT-013/join-listener");

    let mut connection = Connection::client(Settings::client());
    for _ in 0..CONNECTIONS {
        let stream_id = connection
            .open_stream(vec![Header::new(":method", "GET")], false)
            .expect("DORMANT-INT-013/open-h2-stream");
        connection.reset_stream(stream_id, ErrorCode::Cancel);
        while connection.next_frame().is_some() {}
        connection.prune_closed_streams();
        assert_eq!(
            connection.active_stream_count(),
            0,
            "DORMANT-INT-013/prune-slot"
        );
    }
    connection.begin_graceful_shutdown(Bytes::new());
    connection.finalize_graceful_shutdown(Bytes::new());
    assert!(connection.graceful_shutdown_complete());

    emit_pass(
        "DORMANT-INT-013",
        "net::loopback+http::h2",
        "settings_wire_churn_and_stream_slot_reclamation",
        json!({"connections": CONNECTIONS, "active_slots_after": 0, "listener_joined": true}),
        json!({"connections": CONNECTIONS, "active_slots_after": connection.active_stream_count(), "listener_joined": true}),
        "stream_reset_before_prune",
        "listener_joined_and_h2_graceful_shutdown_complete",
    );
}

fn scenario_timer_wheel_churn() {
    const TIMERS: usize = 256;
    let mut wheel = TimerWheel::new();
    let waker = Waker::noop();
    let handles: Vec<_> = (0..TIMERS)
        .map(|index| {
            wheel.register(
                Time::from_nanos((index as u64 + 1) * 1_000_000),
                waker.clone(),
            )
        })
        .collect();
    let mut cancelled = 0;
    for handle in handles.iter().step_by(2) {
        cancelled += usize::from(wheel.cancel(handle));
    }
    let expired = wheel.collect_expired(Time::from_secs(1));
    assert_eq!(cancelled, TIMERS / 2);
    assert_eq!(expired.len(), TIMERS / 2);
    assert!(wheel.is_empty(), "DORMANT-INT-014/wheel-drained");

    emit_pass(
        "DORMANT-INT-014",
        "time::TimerWheel",
        "deterministic_register_cancel_expire_churn",
        json!({"registered": TIMERS, "cancelled": TIMERS / 2, "expired": TIMERS / 2}),
        json!({"registered": TIMERS, "cancelled": cancelled, "expired": expired.len()}),
        "alternate_timer_cancellation",
        "wheel_empty_after_expiry_collection",
    );
}

fn scenario_checkpoint_snapshot_resume() {
    let mut uninterrupted = CheckpointState::with_history_capacity(8);
    for step in 1..=4_u64 {
        uninterrupted.record_with_message_at(format!("step-{step}"), Time::from_secs(step * 3_600));
    }

    let mut before_restart = CheckpointState::with_history_capacity(8);
    for step in 1..=2_u64 {
        before_restart
            .record_with_message_at(format!("step-{step}"), Time::from_secs(step * 3_600));
    }
    let mut resumed = before_restart.clone();
    for step in 3..=4_u64 {
        resumed.record_with_message_at(format!("step-{step}"), Time::from_secs(step * 3_600));
    }
    assert_eq!(resumed.checkpoint_count, uninterrupted.checkpoint_count);
    assert_eq!(resumed.last_checkpoint, uninterrupted.last_checkpoint);
    assert_eq!(resumed.last_message, uninterrupted.last_message);
    assert_eq!(resumed.history().len(), 4);

    let runtime_state = RuntimeState::new();
    let artifact =
        SnapshotArtifact::full(runtime_state.restorable_snapshot(), SnapshotLimits::DEFAULT)
            .expect("DORMANT-INT-015/build-snapshot-artifact");
    let bytes = artifact
        .to_bytes()
        .expect("DORMANT-INT-015/encode-snapshot");
    assert_eq!(
        &bytes[..SNAPSHOT_ARTIFACT_MAGIC.len()],
        &SNAPSHOT_ARTIFACT_MAGIC
    );
    let decoded = SnapshotArtifact::from_bytes(&bytes).expect("DORMANT-INT-015/decode-snapshot");
    assert_eq!(decoded.kind(), SnapshotArtifactKind::Full);
    let materialized = decoded
        .materialize(None, SnapshotLimits::DEFAULT)
        .expect("DORMANT-INT-015/materialize-snapshot");
    assert!(materialized.validate().is_valid);

    emit_pass(
        "DORMANT-INT-015",
        "types::CheckpointState+lab::SnapshotArtifact",
        "virtual_multi_hour_checkpoint_snapshot_resume",
        json!({"checkpoints": 4, "final_virtual_hour": 4, "artifact_magic": "ASUPSNAP"}),
        json!({"checkpoints": resumed.checkpoint_count, "final_virtual_hour": 4, "artifact_magic": "ASUPSNAP"}),
        "after_checkpoint_2",
        "artifact_materialized_and_resume_matched_uninterrupted_state",
    );
}

fn scenario_memory_pressure_backpressure_recovery() {
    const CAPACITY: usize = 4;
    let (sender, mut receiver) = mpsc::channel(CAPACITY);
    for value in 0..CAPACITY as u8 {
        sender.try_send(value).expect("DORMANT-INT-016/fill-buffer");
    }
    let telemetry = sender.telemetry_snapshot(1600);
    assert_eq!(telemetry.queued_messages, CAPACITY);
    assert!(matches!(sender.try_send(9), Err(mpsc::SendError::Full(9))));
    let mut delivered = Vec::new();
    for _ in 0..2 {
        delivered.push(receiver.try_recv().expect("DORMANT-INT-016/pressure-drain"));
    }
    sender.try_send(4).expect("DORMANT-INT-016/recovery-send-4");
    sender.try_send(5).expect("DORMANT-INT-016/recovery-send-5");
    while let Ok(value) = receiver.try_recv() {
        delivered.push(value);
    }
    assert_eq!(delivered, vec![0, 1, 2, 3, 4, 5]);
    assert_eq!(receiver.len(), 0);
    drop(sender);
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::RecvError::Disconnected)
    ));

    emit_pass(
        "DORMANT-INT-016",
        "channel::mpsc",
        "bounded_memory_pressure_fill_drain_resume",
        json!({"capacity": CAPACITY, "accepted": 6, "delivered": 6, "backlog_after": 0}),
        json!({"capacity": CAPACITY, "accepted": delivered.len(), "delivered": delivered.len(), "backlog_after": receiver.len()}),
        "capacity_full_refusal",
        "backlog_zero_and_channel_disconnected",
    );
}

fn scenario_partition_healing_snapshot_convergence() {
    let region_id = RegionId::new_for_test(170, 0);
    let mut leader = RegionBridge::new_local(region_id, None, Budget::default());
    let mut majority_peer = RegionBridge::new_local(region_id, None, Budget::default());
    let mut partitioned_peer = RegionBridge::new_local(region_id, None, Budget::default());

    leader
        .add_task(TaskId::new_for_test(1701, 0))
        .expect("DORMANT-INT-017/add-first-task");
    let before_partition = leader.create_snapshot(Time::from_secs(1));
    majority_peer
        .apply_snapshot(&before_partition)
        .expect("DORMANT-INT-017/majority-initial-sync");
    partitioned_peer
        .apply_snapshot(&before_partition)
        .expect("DORMANT-INT-017/partitioned-initial-sync");

    leader
        .add_task(TaskId::new_for_test(1702, 0))
        .expect("DORMANT-INT-017/add-majority-task");
    let during_partition = leader.create_snapshot(Time::from_secs(2));
    majority_peer
        .apply_snapshot(&during_partition)
        .expect("DORMANT-INT-017/majority-progress");
    assert_eq!(partitioned_peer.local().task_ids().len(), 1);
    assert_eq!(majority_peer.local().task_ids().len(), 2);

    partitioned_peer
        .apply_snapshot(&during_partition)
        .expect("DORMANT-INT-017/heal-apply");
    assert_eq!(
        partitioned_peer.local().task_ids(),
        leader.local().task_ids()
    );
    assert_eq!(majority_peer.local().task_ids(), leader.local().task_ids());
    assert_eq!(partitioned_peer.sync_state.last_synced_sequence, 2);
    assert!(matches!(
        leader.sync(Time::from_secs(3)),
        Ok(SyncResult::NotNeeded)
    ));

    for bridge in [&mut leader, &mut majority_peer, &mut partitioned_peer] {
        for task in bridge.local().task_ids() {
            bridge.remove_task(task);
        }
        close_bridge(bridge, Time::from_secs(4));
        assert!(!bridge.has_live_work());
    }

    emit_pass(
        "DORMANT-INT-017",
        "distributed::RegionBridge",
        "partitioned_snapshot_follower_heals_to_monotonic_sequence",
        json!({"pre_partition_sequence": 1, "majority_sequence": 2, "healed_sequence": 2, "tasks": 2}),
        json!({"pre_partition_sequence": 1, "majority_sequence": 2, "healed_sequence": 2, "tasks": 2}),
        "one_follower_omits_sequence_2_until_heal",
        "all_three_bridges_closed_without_live_work",
    );
}

#[test]
fn dormant_cross_subsystem_recovery_emits_required_scenarios() {
    scenario_pubsub_partial_consumer_failure();
    scenario_circuit_breaker_cascade_recovery();
    scenario_region_failure_isolation();
    scenario_pipeline_backpressure();
    emit_placeholder_disposition();
    scenario_worker_failure_obligation_cleanup();
    scenario_hedge_first_success_loser_cancel();
    scenario_distributed_bridge_rolling_restart();
    scenario_broker_death_reconnect();
    scenario_raptorq_interruption_resume();
    scenario_runtime_panic_recovery_subscriptions();
    scenario_rate_limit_burst_recovery();
    scenario_http2_loopback_slot_reclamation();
    scenario_timer_wheel_churn();
    scenario_checkpoint_snapshot_resume();
    scenario_memory_pressure_backpressure_recovery();
    scenario_partition_healing_snapshot_convergence();
}
