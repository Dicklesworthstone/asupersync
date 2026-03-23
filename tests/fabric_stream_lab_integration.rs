//! LabRuntime integration coverage for FABRIC stream and consumer surfaces.
#![cfg(feature = "messaging-fabric")]

use asupersync::cx::Cx;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::messaging::capability::FabricCapability as RuntimeFabricCapability;
use asupersync::messaging::consumer::{
    AckResolution, ConsumerDemandClass, ConsumerDispatchMode, CursorLeaseHolder, FabricConsumer,
    FabricConsumerConfig, FabricConsumerError, PullDispatchOutcome, PullRequest,
    RecoverableCapsule, SequenceWindow,
};
use asupersync::messaging::fabric::{
    CellEpoch, CellTemperature, DataCapsule, NodeRole, PlacementPolicy, RepairPolicy,
    StewardCandidate, StorageClass, SubjectCell, SubjectPattern,
};
use asupersync::messaging::{CapturePolicy, DeliveryClass, Fabric, FabricStreamConfig};
use asupersync::remote::NodeId;
use asupersync::runtime::yield_now;
use asupersync::types::{Budget, RegionId, TaskId};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamConsumerLogEntry {
    seq: u64,
    lane: &'static str,
    action: &'static str,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StreamHandleSummary {
    endpoint: String,
    subjects: Vec<String>,
    delivery_class: DeliveryClass,
    capture_policy: CapturePolicy,
    request_timeout: Option<Duration>,
    reply_subject: String,
    reply_payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PushAckSummary {
    window: (u64, u64),
    pending_after_dispatch: u64,
    pending_after_ack: u64,
    ack_floor_after_ack: u64,
    total_acquired: u64,
    total_committed: u64,
    committed_against: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PullFlowSummary {
    first_window: (u64, u64),
    tail_window: (u64, u64),
    pending_after_first_dispatch: u64,
    pending_after_tail_dispatch: u64,
    ack_floor_after_first_ack: u64,
    total_committed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PullNoDataSummary {
    demand_class: ConsumerDemandClass,
    available_tail: u64,
    waiting_after_error: usize,
}

fn test_fabric_cx(slot: u32) -> Cx {
    Cx::new(
        RegionId::new_for_test(slot, 0),
        TaskId::new_for_test(slot, 0),
        Budget::INFINITE,
    )
}

fn grant_fabric_capability(cx: &Cx, capability: RuntimeFabricCapability) {
    cx.grant_fabric_capability(capability)
        .expect("fabric capability grant");
}

fn grant_publish(cx: &Cx, subject: &str) {
    grant_fabric_capability(
        cx,
        RuntimeFabricCapability::Publish {
            subject: SubjectPattern::parse(subject).expect("publish subject"),
        },
    );
}

fn grant_subscribe(cx: &Cx, subject: &str) {
    grant_fabric_capability(
        cx,
        RuntimeFabricCapability::Subscribe {
            subject: SubjectPattern::parse(subject).expect("subscribe subject"),
        },
    );
}

fn grant_create_stream(cx: &Cx, subject: &str) {
    grant_fabric_capability(
        cx,
        RuntimeFabricCapability::CreateStream {
            subject: SubjectPattern::parse(subject).expect("stream subject"),
        },
    );
}

fn push_log(
    log: &Arc<Mutex<Vec<StreamConsumerLogEntry>>>,
    seq: &Arc<AtomicU64>,
    lane: &'static str,
    action: &'static str,
    detail: impl Into<String>,
) {
    log.lock().expect("log lock").push(StreamConsumerLogEntry {
        seq: seq.fetch_add(1, Ordering::SeqCst),
        lane,
        action,
        detail: detail.into(),
    });
}

fn candidate(name: &str, domain: &str) -> StewardCandidate {
    StewardCandidate::new(NodeId::new(name), domain)
        .with_role(NodeRole::Steward)
        .with_role(NodeRole::RepairWitness)
        .with_storage_class(StorageClass::Durable)
}

fn test_cell() -> SubjectCell {
    SubjectCell::new(
        &SubjectPattern::parse("orders.created").expect("pattern"),
        CellEpoch::new(7, 11),
        &[
            candidate("node-a", "rack-a"),
            candidate("node-b", "rack-b"),
            candidate("node-c", "rack-c"),
        ],
        &PlacementPolicy {
            cold_stewards: 3,
            warm_stewards: 3,
            hot_stewards: 3,
            ..PlacementPolicy::default()
        },
        RepairPolicy::default(),
        DataCapsule {
            temperature: CellTemperature::Warm,
            retained_message_blocks: 4,
        },
    )
    .expect("cell")
}

fn run_stream_handle_scenario(
    seed: u64,
) -> (StreamHandleSummary, Vec<StreamConsumerLogEntry>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<StreamHandleSummary>));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = test_fabric_cx(820);
                grant_publish(&cx, "service.lookup");
                grant_subscribe(&cx, "service.lookup");
                grant_create_stream(&cx, "orders.>");
                yield_now().await;

                let fabric = Fabric::connect(&cx, "lab://fabric-stream")
                    .await
                    .expect("connect");
                push_log(
                    &log,
                    &seq,
                    "stream",
                    "connect",
                    fabric.endpoint().to_string(),
                );

                let handle = fabric
                    .stream(
                        &cx,
                        FabricStreamConfig {
                            subjects: vec![
                                SubjectPattern::parse("orders.created").expect("created"),
                                SubjectPattern::parse("orders.snapshot").expect("snapshot"),
                            ],
                            delivery_class: DeliveryClass::DurableOrdered,
                            capture_policy: CapturePolicy::ExplicitOptIn,
                            request_timeout: Some(Duration::from_secs(5)),
                        },
                    )
                    .await
                    .expect("stream");
                push_log(
                    &log,
                    &seq,
                    "stream",
                    "declare",
                    format!("subjects={}", handle.config().subjects.len()),
                );

                yield_now().await;
                let reply = fabric
                    .request(&cx, "service.lookup", b"lookup".to_vec())
                    .await
                    .expect("request");
                push_log(
                    &log,
                    &seq,
                    "stream",
                    "request",
                    format!("reply_subject={}", reply.subject.as_str()),
                );

                *summary.lock().expect("summary lock") = Some(StreamHandleSummary {
                    endpoint: handle.endpoint().to_string(),
                    subjects: handle
                        .config()
                        .subjects
                        .iter()
                        .map(SubjectPattern::canonical_key)
                        .collect(),
                    delivery_class: handle.config().delivery_class,
                    capture_policy: handle.config().capture_policy,
                    request_timeout: handle.config().request_timeout,
                    reply_subject: reply.subject.as_str().to_string(),
                    reply_payload_len: reply.payload.len(),
                });
            })
            .expect("create stream task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    assert!(runtime.is_quiescent(), "stream scenario should quiesce");
    assert!(
        violations.is_empty(),
        "stream scenario should not violate lab invariants: {violations:?}"
    );

    let summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("stream summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    (summary, log_entries, runtime.steps())
}

fn run_push_ack_scenario(seed: u64) -> (PushAckSummary, Vec<StreamConsumerLogEntry>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<PushAckSummary>));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let owner = asupersync::messaging::consumer::FabricConsumerOwner {
                    holder: TaskId::new_for_test(41, 0),
                    region: RegionId::new_for_test(7, 0),
                };
                let mut consumer =
                    FabricConsumer::new_owned(&test_cell(), FabricConsumerConfig::default(), owner)
                        .expect("consumer");
                let window = SequenceWindow::new(5, 6).expect("window");
                let capsule =
                    RecoverableCapsule::default().with_window(NodeId::new("node-a"), window);

                yield_now().await;
                let delivery = consumer
                    .dispatch_push(window, &capsule, None)
                    .expect("dispatch");
                let pending_after_dispatch = consumer.state().pending_count;
                let total_acquired = consumer.obligation_stats().total_acquired;
                push_log(
                    &log,
                    &seq,
                    "push",
                    "dispatch",
                    format!("pending={pending_after_dispatch}"),
                );

                yield_now().await;
                let against = match consumer
                    .acknowledge_delivery(&delivery.attempt)
                    .expect("ack")
                {
                    AckResolution::Committed { against, .. } => against,
                    AckResolution::StaleNoOp { .. } => panic!("push ack should commit"),
                };
                let stats = consumer.obligation_stats();
                let committed_against = match against {
                    CursorLeaseHolder::Steward(node) => node.as_str().to_string(),
                    CursorLeaseHolder::Relay(node) => node.as_str().to_string(),
                };
                push_log(
                    &log,
                    &seq,
                    "push",
                    "ack",
                    format!("ack_floor={}", consumer.state().ack_floor),
                );

                *summary.lock().expect("summary lock") = Some(PushAckSummary {
                    window: (window.start(), window.end()),
                    pending_after_dispatch,
                    pending_after_ack: consumer.state().pending_count,
                    ack_floor_after_ack: consumer.state().ack_floor,
                    total_acquired,
                    total_committed: stats.total_committed,
                    committed_against,
                });
            })
            .expect("create push task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    assert!(runtime.is_quiescent(), "push scenario should quiesce");
    assert!(
        violations.is_empty(),
        "push scenario should not violate lab invariants: {violations:?}"
    );

    let summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("push summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    (summary, log_entries, runtime.steps())
}

fn run_pull_flow_scenario(seed: u64) -> (PullFlowSummary, Vec<StreamConsumerLogEntry>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<PullFlowSummary>));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let mut consumer =
                    FabricConsumer::new(&test_cell(), FabricConsumerConfig::default())
                        .expect("consumer");
                let capsule = RecoverableCapsule::default().with_window(
                    NodeId::new("node-a"),
                    SequenceWindow::new(1, 12).expect("capsule window"),
                );

                consumer.switch_mode(ConsumerDispatchMode::Pull);
                consumer
                    .queue_pull_request(
                        PullRequest::new(3, ConsumerDemandClass::CatchUp).expect("catchup"),
                    )
                    .expect("queue catchup");
                push_log(&log, &seq, "pull", "queue", "catchup");

                yield_now().await;
                let first = match consumer
                    .dispatch_next_pull(12, &capsule, None)
                    .expect("dispatch catchup")
                {
                    PullDispatchOutcome::Scheduled(delivery) => *delivery,
                    PullDispatchOutcome::Waiting(_) => panic!("catchup request should schedule"),
                };
                let pending_after_first_dispatch = consumer.state().pending_count;
                push_log(
                    &log,
                    &seq,
                    "pull",
                    "dispatch_first",
                    format!("window={}..={}", first.window.start(), first.window.end()),
                );

                yield_now().await;
                let ack = consumer
                    .acknowledge_delivery(&first.attempt)
                    .expect("ack first");
                assert!(
                    matches!(ack, AckResolution::Committed { .. }),
                    "first pull delivery should commit"
                );
                let ack_floor_after_first_ack = consumer.state().ack_floor;
                push_log(
                    &log,
                    &seq,
                    "pull",
                    "ack_first",
                    format!("ack_floor={ack_floor_after_first_ack}"),
                );

                consumer
                    .queue_pull_request(
                        PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"),
                    )
                    .expect("queue tail");
                yield_now().await;
                let tail = match consumer
                    .dispatch_next_pull(12, &capsule, None)
                    .expect("dispatch tail")
                {
                    PullDispatchOutcome::Scheduled(delivery) => *delivery,
                    PullDispatchOutcome::Waiting(_) => panic!("tail request should schedule"),
                };
                let pending_after_tail_dispatch = consumer.state().pending_count;
                push_log(
                    &log,
                    &seq,
                    "pull",
                    "dispatch_tail",
                    format!("window={}..={}", tail.window.start(), tail.window.end()),
                );

                yield_now().await;
                let ack = consumer
                    .acknowledge_delivery(&tail.attempt)
                    .expect("ack tail");
                assert!(
                    matches!(ack, AckResolution::Committed { .. }),
                    "tail pull delivery should commit"
                );

                *summary.lock().expect("summary lock") = Some(PullFlowSummary {
                    first_window: (first.window.start(), first.window.end()),
                    tail_window: (tail.window.start(), tail.window.end()),
                    pending_after_first_dispatch,
                    pending_after_tail_dispatch,
                    ack_floor_after_first_ack,
                    total_committed: consumer.obligation_stats().total_committed,
                });
            })
            .expect("create pull task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    assert!(runtime.is_quiescent(), "pull scenario should quiesce");
    assert!(
        violations.is_empty(),
        "pull scenario should not violate lab invariants: {violations:?}"
    );

    let summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("pull summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    (summary, log_entries, runtime.steps())
}

fn run_pull_no_data_scenario(seed: u64) -> (PullNoDataSummary, Vec<StreamConsumerLogEntry>, u64) {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<PullNoDataSummary>));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let mut consumer =
                    FabricConsumer::new(&test_cell(), FabricConsumerConfig::default())
                        .expect("consumer");
                let capsule = RecoverableCapsule::default().with_window(
                    NodeId::new("node-a"),
                    SequenceWindow::new(1, 4).expect("capsule window"),
                );
                consumer.switch_mode(ConsumerDispatchMode::Pull);
                consumer
                    .queue_pull_request(
                        PullRequest::new(1, ConsumerDemandClass::Tail)
                            .expect("pull")
                            .with_no_wait(),
                    )
                    .expect("queue pull");
                push_log(&log, &seq, "pull_no_data", "queue", "tail_no_wait");

                yield_now().await;
                let (demand_class, available_tail) = match consumer
                    .dispatch_next_pull(0, &capsule, None)
                    .expect_err("no-wait pull with no data must fail closed")
                {
                    FabricConsumerError::NoDataAvailable {
                        demand_class,
                        available_tail,
                    } => (demand_class, available_tail),
                    other => panic!("expected no data error, got {other:?}"),
                };
                push_log(
                    &log,
                    &seq,
                    "pull_no_data",
                    "error",
                    format!("demand={demand_class:?} available_tail={available_tail}"),
                );

                *summary.lock().expect("summary lock") = Some(PullNoDataSummary {
                    demand_class,
                    available_tail,
                    waiting_after_error: consumer.waiting_pull_request_count(),
                });
            })
            .expect("create pull-no-data task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    runtime.run_until_quiescent();
    let violations = runtime.check_invariants();
    assert!(
        runtime.is_quiescent(),
        "pull-no-data scenario should quiesce"
    );
    assert!(
        violations.is_empty(),
        "pull-no-data scenario should not violate lab invariants: {violations:?}"
    );

    let summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("pull-no-data summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    (summary, log_entries, runtime.steps())
}

#[test]
fn fabric_stream_handle_is_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_stream_handle_scenario(0x5172_0001);
    let (second_summary, second_log, second_steps) = run_stream_handle_scenario(0x5172_0001);

    assert_eq!(first_summary, second_summary);
    assert_eq!(first_log, second_log);
    assert_eq!(first_steps, second_steps);
}

#[test]
fn fabric_stream_handle_preserves_capture_policy_timeout_and_request_surface() {
    let (summary, log, _) = run_stream_handle_scenario(0x5172_0002);

    assert_eq!(summary.endpoint, "lab://fabric-stream");
    assert_eq!(
        summary.subjects,
        vec!["orders.created".to_string(), "orders.snapshot".to_string()]
    );
    assert_eq!(summary.delivery_class, DeliveryClass::DurableOrdered);
    assert_eq!(summary.capture_policy, CapturePolicy::ExplicitOptIn);
    assert_eq!(summary.request_timeout, Some(Duration::from_secs(5)));
    assert_eq!(summary.reply_subject, "service.lookup");
    assert_eq!(summary.reply_payload_len, 6);
    assert_eq!(log.len(), 3);
}

#[test]
fn fabric_consumer_push_ack_flow_is_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_push_ack_scenario(0x5172_0010);
    let (second_summary, second_log, second_steps) = run_push_ack_scenario(0x5172_0010);

    assert_eq!(first_summary, second_summary);
    assert_eq!(first_log, second_log);
    assert_eq!(first_steps, second_steps);
}

#[test]
fn fabric_consumer_push_ack_flow_drains_pending_obligations() {
    let (summary, log, _) = run_push_ack_scenario(0x5172_0011);

    assert_eq!(summary.window, (5, 6));
    assert_eq!(summary.pending_after_dispatch, 2);
    assert_eq!(summary.pending_after_ack, 0);
    assert_eq!(summary.ack_floor_after_ack, 6);
    assert_eq!(summary.total_acquired, 1);
    assert_eq!(summary.total_committed, 1);
    assert_eq!(summary.committed_against, "node-a");
    assert_eq!(log.len(), 2);
}

#[test]
fn fabric_consumer_pull_flow_is_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_pull_flow_scenario(0x5172_0020);
    let (second_summary, second_log, second_steps) = run_pull_flow_scenario(0x5172_0020);

    assert_eq!(first_summary, second_summary);
    assert_eq!(first_log, second_log);
    assert_eq!(first_steps, second_steps);
}

#[test]
fn fabric_consumer_pull_flow_advances_ack_floor_and_tail_window() {
    let (summary, log, _) = run_pull_flow_scenario(0x5172_0021);

    assert_eq!(summary.first_window, (1, 3));
    assert_eq!(summary.tail_window, (11, 12));
    assert_eq!(summary.pending_after_first_dispatch, 3);
    assert_eq!(summary.pending_after_tail_dispatch, 2);
    assert_eq!(summary.ack_floor_after_first_ack, 3);
    assert_eq!(summary.total_committed, 2);
    assert_eq!(log.len(), 4);
}

#[test]
fn fabric_consumer_pull_no_data_path_is_deterministic_across_seeded_lab_runs() {
    let (first_summary, first_log, first_steps) = run_pull_no_data_scenario(0x5172_0030);
    let (second_summary, second_log, second_steps) = run_pull_no_data_scenario(0x5172_0030);

    assert_eq!(first_summary, second_summary);
    assert_eq!(first_log, second_log);
    assert_eq!(first_steps, second_steps);
}

#[test]
fn fabric_consumer_pull_no_wait_fails_closed_when_no_data_is_available() {
    let (summary, log, _) = run_pull_no_data_scenario(0x5172_0031);

    assert_eq!(summary.demand_class, ConsumerDemandClass::Tail);
    assert_eq!(summary.available_tail, 0);
    assert_eq!(summary.waiting_after_error, 0);
    assert_eq!(log.len(), 2);
}
