#![allow(clippy::all)]
//! Aggregated FABRIC E2E coverage with structured per-scenario summaries.
#![cfg(feature = "messaging-fabric")]

mod common;

use common::{init_test_logging, test_context_with_seed};

use asupersync::cx::Cx;
use asupersync::distributed::RegionBridge;
use asupersync::lab::{LabConfig, LabRuntime};
use asupersync::messaging::capability::FabricCapability as RuntimeFabricCapability;
use asupersync::messaging::consumer::{
    AckResolution, ConsumerDemandClass, ConsumerDispatchMode, FabricConsumer, FabricConsumerConfig,
    FabricConsumerOwner, PullDispatchOutcome, PullRequest, RecoverableCapsule, SequenceWindow,
};
use asupersync::messaging::control::{ControlBudget, SystemSubjectFamily};
use asupersync::messaging::fabric::{
    CellEpoch, CellTemperature, ControlCapsuleError, DataCapsule, NodeRole, ObservedCellLoad,
    PlacementPolicy, RebalanceBudget, RebalanceCutEvidence, RebalanceObligationSummary,
    RepairPolicy, RepairSymbolBinding, StewardCandidate, StorageClass, SubjectCell, SubjectPattern,
};
use asupersync::messaging::federation::{
    FederationBridge, FederationRole, GatewayConfig, ReplicationCatchUpAction, ReplicationConfig,
};
use asupersync::messaging::ir::ReplySpaceRule;
use asupersync::messaging::service::{
    CompensationSemantics, EvidenceLevel, MobilityConstraint, OverloadPolicy, RequestCertificate,
    ServiceAdmission, ValidatedServiceRequest,
};
use asupersync::messaging::stream::{
    CapturePolicy as StreamCapturePolicy, InMemoryStorageBackend, Stream, StreamConfig,
};
use asupersync::messaging::{
    AckKind, CapturePolicy, DeliveryClass, Fabric, FabricCapability as MorphismCapability,
    FabricStreamConfig, Morphism, ShardedSublist, Subject,
};
use asupersync::obligation::ledger::ObligationLedger;
use asupersync::remote::NodeId;
use asupersync::runtime::yield_now;
use asupersync::test_logging::{TestHarness, TestReportAggregator, TestSummary};
use asupersync::types::{Budget, RegionId, TaskId, Time};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FabricLogEntry {
    seq: u64,
    lane: &'static str,
    action: &'static str,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PacketPlaneOutcome {
    wildcard_subjects: Vec<String>,
    exact_subjects: Vec<String>,
    cancelled_next_is_none: bool,
    reply_subject: String,
    reply_payload_len: usize,
    log: Vec<FabricLogEntry>,
    steps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum ValidationStatus {
    Valid,
    Invalid,
}

impl ValidationStatus {
    const fn is_valid(self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum PresenceStatus {
    Present,
    Missing,
}

impl PresenceStatus {
    const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum LedgerStatus {
    Clean,
    Leaked,
}

impl LedgerStatus {
    const fn is_clean(self) -> bool {
        matches!(self, Self::Clean)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CertifiedRequestChecks {
    request_certificate: ValidationStatus,
    reply_certificate: ValidationStatus,
    service_obligation: PresenceStatus,
    delivery_receipt: PresenceStatus,
    ledger: LedgerStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CertifiedRequestOutcome {
    reply_subject: String,
    reply_payload_len: usize,
    reply_ack_kind: AckKind,
    reply_delivery_class: DeliveryClass,
    published_delivery_class: DeliveryClass,
    checks: CertifiedRequestChecks,
    log: Vec<FabricLogEntry>,
    steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct StreamHandleOutcome {
    endpoint_matches_prefix: bool,
    subjects: Vec<String>,
    delivery_class: DeliveryClass,
    capture_policy: String,
    request_timeout_millis: Option<u64>,
    reply_subject: String,
    reply_payload_len: usize,
    log: Vec<FabricLogEntry>,
    steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ConsumerFlowOutcome {
    push_window: (u64, u64),
    pending_after_push_dispatch: u64,
    pending_after_push_ack: u64,
    ack_floor_after_push_ack: u64,
    catch_up_window: (u64, u64),
    tail_window: (u64, u64),
    pending_after_tail_dispatch: u64,
    no_data_waiting_after_error: usize,
    total_acquired: u64,
    total_committed: u64,
    log: Vec<FabricLogEntry>,
    steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct MirrorSourceDrainOutcome {
    catch_up_action: ReplicationCatchUpAction,
    snapshot_sequence: u64,
    target_task_count: usize,
    close_blocked_before_drain: bool,
    closed_after_drain: bool,
    mirror_remaining: usize,
    source_remaining: usize,
    log: Vec<FabricLogEntry>,
    steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ControlPlaneAdvisoryOutcome {
    propagated_interest_count: usize,
    forwarded_advisory_count: usize,
    timed_out: bool,
    no_ghost_interest: bool,
    log: Vec<FabricLogEntry>,
    steps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct BrokerlessRebalanceOutcome {
    next_temperature: String,
    next_stewards: Vec<String>,
    drained_stewards: Vec<String>,
    control_append_sequence: u64,
    resulting_generation: u64,
    joint_fence_generation: u64,
    repair_holder_count: usize,
    shared_control_shard_id: Option<String>,
    shared_control_shard_slot: Option<usize>,
    old_sequencer_fenced: bool,
    log: Vec<FabricLogEntry>,
    steps: u64,
}

static ENDPOINT_NONCE: AtomicU64 = AtomicU64::new(0);

fn test_fabric_cx(slot: u32) -> Cx {
    Cx::new(
        RegionId::new_for_test(slot, 0),
        TaskId::new_for_test(slot, 0),
        Budget::INFINITE,
    )
}

fn push_log(
    log: &Arc<Mutex<Vec<FabricLogEntry>>>,
    seq: &Arc<AtomicU64>,
    lane: &'static str,
    action: &'static str,
    detail: impl Into<String>,
) {
    log.lock().expect("log lock").push(FabricLogEntry {
        seq: seq.fetch_add(1, Ordering::SeqCst),
        lane,
        action,
        detail: detail.into(),
    });
}

fn unique_endpoint(prefix: &str, seed: u64) -> String {
    let nonce = ENDPOINT_NONCE.fetch_add(1, Ordering::SeqCst);
    format!("lab://{prefix}-{seed:016x}-{nonce:08x}")
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

fn candidate(name: &str, domain: &str) -> StewardCandidate {
    StewardCandidate::new(NodeId::new(name), domain)
        .with_role(NodeRole::Steward)
        .with_role(NodeRole::RepairWitness)
        .with_storage_class(StorageClass::Durable)
}

fn rebalance_candidate(
    name: &str,
    domain: &str,
    storage_class: StorageClass,
    latency_millis: u32,
) -> StewardCandidate {
    StewardCandidate::new(NodeId::new(name), domain)
        .with_role(NodeRole::Steward)
        .with_role(NodeRole::RepairWitness)
        .with_storage_class(storage_class)
        .with_latency_millis(latency_millis)
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

fn brokerless_rebalance_policy() -> PlacementPolicy {
    PlacementPolicy {
        cold_stewards: 1,
        warm_stewards: 3,
        hot_stewards: 4,
        candidate_pool_size: 6,
        rebalance_budget: RebalanceBudget {
            max_steward_changes: 3,
        },
        ..PlacementPolicy::default()
    }
}

fn brokerless_rebalance_candidates() -> Vec<StewardCandidate> {
    vec![
        rebalance_candidate("node-a", "rack-a", StorageClass::Durable, 5),
        rebalance_candidate("node-b", "rack-b", StorageClass::Durable, 6),
        rebalance_candidate("node-c", "rack-c", StorageClass::Standard, 7),
        rebalance_candidate("node-d", "rack-d", StorageClass::Standard, 8),
        rebalance_candidate("node-e", "rack-e", StorageClass::Standard, 9),
        rebalance_candidate("node-f", "rack-f", StorageClass::Standard, 10),
    ]
}

fn brokerless_repair_bindings(
    cell: &SubjectCell,
    next_stewards: &[NodeId],
    next_temperature: CellTemperature,
    candidates: &[StewardCandidate],
    retention_generation: u64,
) -> Vec<RepairSymbolBinding> {
    let witness_target = match next_temperature {
        CellTemperature::Cold | CellTemperature::Warm => cell.repair_policy.cold_witnesses,
        CellTemperature::Hot => cell.repair_policy.hot_witnesses,
    };
    let required_holders = next_stewards
        .len()
        .saturating_add(witness_target)
        .max(cell.repair_policy.recoverability_target as usize);

    let mut holders = next_stewards.to_vec();
    for candidate in candidates {
        if holders.len() >= required_holders {
            break;
        }
        if holders.iter().any(|node| node == &candidate.node_id) || !candidate.can_repair() {
            continue;
        }
        holders.push(candidate.node_id.clone());
    }

    holders
        .into_iter()
        .map(|node_id| RepairSymbolBinding::new(node_id, cell.epoch, retention_generation))
        .collect()
}

fn service_admission(
    request_id: &str,
    subject: &str,
    delivery_class: DeliveryClass,
    timeout: Option<Duration>,
    issued_at: Time,
) -> ServiceAdmission {
    let validated = ValidatedServiceRequest {
        delivery_class,
        timeout,
        priority_hint: None,
        guaranteed_durability: delivery_class,
        evidence_level: EvidenceLevel::Standard,
        mobility_constraint: MobilityConstraint::Unrestricted,
        compensation_policy: CompensationSemantics::None,
        overload_policy: OverloadPolicy::RejectNew,
    };
    let certificate = RequestCertificate::from_validated(
        request_id.to_owned(),
        "caller-a".to_owned(),
        subject.to_owned(),
        &validated,
        ReplySpaceRule::CallerInbox,
        "OrderService".to_owned(),
        0xC0DE,
        issued_at,
    );

    ServiceAdmission {
        validated,
        certificate,
    }
}

fn assert_runtime_clean(runtime: &mut LabRuntime, label: &str) {
    runtime.run_until_quiescent();
    let pending_obligations = runtime.state.pending_obligation_count();
    let violations = runtime.check_invariants();
    assert!(runtime.is_quiescent(), "{label} should quiesce");
    assert_eq!(
        pending_obligations, 0,
        "{label} should not leave runtime obligations pending"
    );
    assert!(
        violations.is_empty(),
        "{label} should not violate lab invariants: {violations:?}"
    );
}

#[allow(clippy::too_many_lines)]
fn run_packet_plane(seed: u64) -> PacketPlaneOutcome {
    #[derive(Debug, Clone, Default)]
    struct PacketPlaneState {
        wildcard_subjects: Vec<String>,
        exact_subjects: Vec<String>,
        cancelled_next_is_none: bool,
        reply_subject: Option<String>,
        reply_payload_len: Option<usize>,
    }

    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let state = Arc::new(Mutex::new(PacketPlaneState::default()));
    let endpoint = unique_endpoint("fabric-e2e-packet", seed);

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let state = Arc::clone(&state);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = test_fabric_cx(900);
                let cancelled = test_fabric_cx(901);
                grant_publish(&cx, "orders.>");
                grant_subscribe(&cx, "orders.>");
                grant_subscribe(&cx, "orders.created");
                grant_publish(&cx, "service.lookup");
                grant_subscribe(&cx, "service.lookup");

                yield_now().await;
                let fabric = Fabric::connect(&cx, &endpoint).await.expect("connect");
                let _ = fabric.endpoint();
                push_log(&log, &seq, "packet", "connect", "connected");

                let mut wildcard = fabric.subscribe(&cx, "orders.>").await.expect("wildcard");
                let mut exact = fabric
                    .subscribe(&cx, "orders.created")
                    .await
                    .expect("exact");
                push_log(
                    &log,
                    &seq,
                    "packet",
                    "subscribe",
                    "orders.> + orders.created",
                );

                yield_now().await;
                let _created = fabric
                    .publish(&cx, "orders.created", b"created".to_vec())
                    .await
                    .expect("publish created");
                push_log(&log, &seq, "packet", "publish", "orders.created");

                yield_now().await;
                let _updated = fabric
                    .publish(&cx, "orders.updated", b"updated".to_vec())
                    .await
                    .expect("publish updated");
                push_log(&log, &seq, "packet", "publish", "orders.updated");

                let wildcard_created = wildcard.next(&cx).await.expect("wildcard created");
                let exact_created = exact.next(&cx).await.expect("exact created");
                let wildcard_updated = wildcard.next(&cx).await.expect("wildcard updated");

                cancelled.set_cancel_requested(true);
                let cancelled_next_is_none = wildcard.next(&cancelled).await.is_none();
                push_log(
                    &log,
                    &seq,
                    "packet",
                    "cancelled_next",
                    format!("none={cancelled_next_is_none}"),
                );

                let reply = fabric
                    .request(&cx, "service.lookup", b"lookup".to_vec())
                    .await
                    .expect("request");
                push_log(
                    &log,
                    &seq,
                    "packet",
                    "request",
                    format!("reply_subject={}", reply.subject.as_str()),
                );

                let mut guard = state.lock().expect("state lock");
                guard.wildcard_subjects = vec![
                    wildcard_created.subject.as_str().to_string(),
                    wildcard_updated.subject.as_str().to_string(),
                ];
                guard.exact_subjects = vec![exact_created.subject.as_str().to_string()];
                guard.cancelled_next_is_none = cancelled_next_is_none;
                guard.reply_subject = Some(reply.subject.as_str().to_string());
                guard.reply_payload_len = Some(reply.payload.len());
            })
            .expect("create packet-plane task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    assert_runtime_clean(&mut runtime, "packet plane e2e");

    let state = state.lock().expect("state lock").clone();
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);

    PacketPlaneOutcome {
        wildcard_subjects: state.wildcard_subjects,
        exact_subjects: state.exact_subjects,
        cancelled_next_is_none: state.cancelled_next_is_none,
        reply_subject: state.reply_subject.expect("reply subject"),
        reply_payload_len: state.reply_payload_len.expect("reply payload len"),
        log: log_entries,
        steps: runtime.steps(),
    }
}

#[allow(clippy::too_many_lines)]
fn run_certified_request(seed: u64) -> CertifiedRequestOutcome {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<CertifiedRequestOutcome>));
    let endpoint = unique_endpoint("fabric-e2e-certified", seed);

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = test_fabric_cx(920);
                grant_publish(&cx, "service.lookup");
                grant_subscribe(&cx, "service.>");

                yield_now().await;
                let fabric = Fabric::connect(&cx, &endpoint).await.expect("connect");
                let mut subscription = fabric.subscribe(&cx, "service.>").await.expect("subscribe");
                let _ = fabric.endpoint();
                push_log(&log, &seq, "certified", "connect", "connected");

                let mut ledger = ObligationLedger::new();
                let admission = service_admission(
                    "req-certified",
                    "service.lookup",
                    DeliveryClass::ObligationBacked,
                    Some(Duration::from_secs(5)),
                    cx.now(),
                );

                yield_now().await;
                let certified = fabric
                    .request_certified(
                        &cx,
                        &mut ledger,
                        &admission,
                        "callee-a",
                        b"lookup".to_vec(),
                        AckKind::Received,
                        true,
                    )
                    .await
                    .expect("certified request");
                let published = subscription.next(&cx).await.expect("published request");
                push_log(
                    &log,
                    &seq,
                    "certified",
                    "request",
                    format!("reply_subject={}", certified.reply.subject.as_str()),
                );

                *summary.lock().expect("summary lock") = Some(CertifiedRequestOutcome {
                    reply_subject: certified.reply.subject.as_str().to_string(),
                    reply_payload_len: certified.reply.payload.len(),
                    reply_ack_kind: certified.reply.ack_kind,
                    reply_delivery_class: certified.reply.delivery_class,
                    published_delivery_class: published.delivery_class,
                    checks: CertifiedRequestChecks {
                        request_certificate: if certified.request_certificate.validate().is_ok() {
                            ValidationStatus::Valid
                        } else {
                            ValidationStatus::Invalid
                        },
                        reply_certificate: if certified.reply_certificate.validate().is_ok() {
                            ValidationStatus::Valid
                        } else {
                            ValidationStatus::Invalid
                        },
                        service_obligation: if certified
                            .reply_certificate
                            .service_obligation_id
                            .is_some()
                        {
                            PresenceStatus::Present
                        } else {
                            PresenceStatus::Missing
                        },
                        delivery_receipt: if certified.delivery_receipt.is_some() {
                            PresenceStatus::Present
                        } else {
                            PresenceStatus::Missing
                        },
                        ledger: if ledger.pending_count() == 0 && ledger.check_leaks().is_clean() {
                            LedgerStatus::Clean
                        } else {
                            LedgerStatus::Leaked
                        },
                    },
                    log: Vec::new(),
                    steps: 0,
                });
            })
            .expect("create certified task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    assert_runtime_clean(&mut runtime, "certified request e2e");

    let mut summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("certified summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    summary.log = log_entries;
    summary.steps = runtime.steps();
    summary
}

fn run_stream_handle(seed: u64) -> StreamHandleOutcome {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<StreamHandleOutcome>));
    let endpoint = unique_endpoint("fabric-e2e-stream", seed);

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let cx = test_fabric_cx(940);
                grant_publish(&cx, "service.lookup");
                grant_subscribe(&cx, "service.lookup");
                grant_create_stream(&cx, "orders.>");

                yield_now().await;
                let fabric = Fabric::connect(&cx, &endpoint).await.expect("connect");
                push_log(&log, &seq, "stream", "connect", "connected");

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

                *summary.lock().expect("summary lock") = Some(StreamHandleOutcome {
                    endpoint_matches_prefix: handle
                        .endpoint()
                        .starts_with("lab://fabric-e2e-stream-"),
                    subjects: handle
                        .config()
                        .subjects
                        .iter()
                        .map(SubjectPattern::canonical_key)
                        .collect(),
                    delivery_class: handle.config().delivery_class,
                    capture_policy: format!("{:?}", handle.config().capture_policy),
                    request_timeout_millis: handle.config().request_timeout.map(|duration| {
                        u64::try_from(duration.as_millis()).expect("timeout fits in u64")
                    }),
                    reply_subject: reply.subject.as_str().to_string(),
                    reply_payload_len: reply.payload.len(),
                    log: Vec::new(),
                    steps: 0,
                });
            })
            .expect("create stream task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    assert_runtime_clean(&mut runtime, "stream handle e2e");

    let mut summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("stream summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    summary.log = log_entries;
    summary.steps = runtime.steps();
    summary
}

#[allow(clippy::too_many_lines)]
fn run_consumer_flow(seed: u64) -> ConsumerFlowOutcome {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<ConsumerFlowOutcome>));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let owner = FabricConsumerOwner {
                    holder: TaskId::new_for_test(41, 0),
                    region: RegionId::new_for_test(7, 0),
                };
                let mut consumer =
                    FabricConsumer::new_owned(&test_cell(), FabricConsumerConfig::default(), owner)
                        .expect("consumer");
                let push_window = SequenceWindow::new(5, 6).expect("push window");
                let push_capsule =
                    RecoverableCapsule::default().with_window(NodeId::new("node-a"), push_window);
                let full_capsule = RecoverableCapsule::default().with_window(
                    NodeId::new("node-a"),
                    SequenceWindow::new(1, 12).expect("capsule window"),
                );

                yield_now().await;
                let push_delivery = consumer
                    .dispatch_push(push_window, &push_capsule, None)
                    .expect("dispatch push");
                let pending_after_push_dispatch = consumer.state().pending_count;
                let total_acquired = consumer.obligation_stats().total_acquired;
                push_log(
                    &log,
                    &seq,
                    "consumer",
                    "dispatch_push",
                    format!(
                        "window={}..={}",
                        push_delivery.window.start(),
                        push_delivery.window.end()
                    ),
                );

                yield_now().await;
                let push_ack = consumer
                    .acknowledge_delivery(&push_delivery.attempt)
                    .expect("ack push");
                assert!(
                    matches!(push_ack, AckResolution::Committed { .. }),
                    "push delivery should commit"
                );
                let pending_after_push_ack = consumer.state().pending_count;
                let ack_floor_after_push_ack = consumer.state().ack_floor;
                push_log(
                    &log,
                    &seq,
                    "consumer",
                    "ack_push",
                    format!("ack_floor={ack_floor_after_push_ack}"),
                );

                consumer.switch_mode(ConsumerDispatchMode::Pull);
                consumer
                    .queue_pull_request(
                        PullRequest::new(3, ConsumerDemandClass::CatchUp).expect("catchup"),
                    )
                    .expect("queue catchup");
                push_log(&log, &seq, "consumer", "queue_pull", "catchup");

                yield_now().await;
                let catch_up_delivery = match consumer
                    .dispatch_next_pull(12, &full_capsule, None)
                    .expect("dispatch catchup")
                {
                    PullDispatchOutcome::Scheduled(delivery) => *delivery,
                    PullDispatchOutcome::Waiting(_) => {
                        panic!("catchup request should schedule")
                    }
                };
                let catch_up_window = (
                    catch_up_delivery.window.start(),
                    catch_up_delivery.window.end(),
                );
                push_log(
                    &log,
                    &seq,
                    "consumer",
                    "dispatch_catchup",
                    format!(
                        "window={}..={}",
                        catch_up_delivery.window.start(),
                        catch_up_delivery.window.end()
                    ),
                );
                let catch_up_ack = consumer
                    .acknowledge_delivery(&catch_up_delivery.attempt)
                    .expect("ack catchup");
                assert!(
                    matches!(catch_up_ack, AckResolution::Committed { .. }),
                    "catchup delivery should commit"
                );

                consumer
                    .queue_pull_request(
                        PullRequest::new(2, ConsumerDemandClass::Tail).expect("tail"),
                    )
                    .expect("queue tail");
                yield_now().await;
                let tail_delivery = match consumer
                    .dispatch_next_pull(12, &full_capsule, None)
                    .expect("dispatch tail")
                {
                    PullDispatchOutcome::Scheduled(delivery) => *delivery,
                    PullDispatchOutcome::Waiting(_) => panic!("tail request should schedule"),
                };
                let tail_window = (tail_delivery.window.start(), tail_delivery.window.end());
                let pending_after_tail_dispatch = consumer.state().pending_count;
                push_log(
                    &log,
                    &seq,
                    "consumer",
                    "dispatch_tail",
                    format!(
                        "window={}..={}",
                        tail_delivery.window.start(),
                        tail_delivery.window.end()
                    ),
                );
                let tail_ack = consumer
                    .acknowledge_delivery(&tail_delivery.attempt)
                    .expect("ack tail");
                assert!(
                    matches!(tail_ack, AckResolution::Committed { .. }),
                    "tail delivery should commit"
                );

                consumer
                    .queue_pull_request(
                        PullRequest::new(1, ConsumerDemandClass::Tail)
                            .expect("tail no data")
                            .with_no_wait(),
                    )
                    .expect("queue no data");
                let no_data_waiting_after_error = match consumer
                    .dispatch_next_pull(0, &full_capsule, None)
                    .expect_err("tail no-data request should fail")
                {
                    asupersync::messaging::consumer::FabricConsumerError::NoDataAvailable {
                        ..
                    } => consumer.waiting_pull_request_count(),
                    other => panic!("unexpected no-data error: {other:?}"),
                };
                push_log(&log, &seq, "consumer", "tail_no_data", "observed");

                *summary.lock().expect("summary lock") = Some(ConsumerFlowOutcome {
                    push_window: (push_window.start(), push_window.end()),
                    pending_after_push_dispatch,
                    pending_after_push_ack,
                    ack_floor_after_push_ack,
                    catch_up_window,
                    tail_window,
                    pending_after_tail_dispatch,
                    no_data_waiting_after_error,
                    total_acquired,
                    total_committed: consumer.obligation_stats().total_committed,
                    log: Vec::new(),
                    steps: 0,
                });
            })
            .expect("create consumer task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    assert_runtime_clean(&mut runtime, "consumer flow e2e");

    let mut summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("consumer summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    summary.log = log_entries;
    summary.steps = runtime.steps();
    summary
}

#[allow(clippy::too_many_lines)]
fn run_mirror_source_drain(seed: u64) -> MirrorSourceDrainOutcome {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<MirrorSourceDrainOutcome>));
    let stream = Arc::new(Mutex::new(
        Stream::new(
            "orders-mirror",
            RegionId::new_for_test(60, 0),
            Time::ZERO,
            StreamConfig {
                subject_filter: SubjectPattern::new("orders.>"),
                capture_policy: StreamCapturePolicy::IncludeReplySubjects,
                delivery_class: DeliveryClass::DurableOrdered,
                ..StreamConfig::default()
            },
            InMemoryStorageBackend::default(),
        )
        .expect("stream"),
    ));

    {
        let mut stream = stream.lock().expect("stream lock");
        stream
            .append(
                asupersync::messaging::Subject::new("orders.created"),
                b"snapshot".to_vec(),
                Time::ZERO,
            )
            .expect("append record");
        stream
            .add_mirror_region(RegionId::new_for_test(61, 0))
            .expect("mirror region");
        stream
            .add_source_region(RegionId::new_for_test(62, 0))
            .expect("source region");
    }

    let ready = Arc::new(AtomicBool::new(false));
    let removed = Arc::new(AtomicUsize::new(0));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let ready = Arc::clone(&ready);
        let removed = Arc::clone(&removed);
        let stream = Arc::clone(&stream);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let mut federation = FederationBridge::new(
                    FederationRole::ReplicationLink(ReplicationConfig::default()),
                    vec![Morphism::default()],
                    Vec::new(),
                    [MorphismCapability::RewriteNamespace],
                )
                .expect("replication bridge");
                push_log(&log, &seq, "mirror", "bridge", "replication-link-ready");

                let mut source =
                    RegionBridge::new_local(RegionId::new_for_test(70, 0), None, Budget::new());
                source
                    .add_task(TaskId::new_for_test(71, 0))
                    .expect("source task");
                let transfer = federation
                    .export_replication_transfer(&mut source, Time::from_secs(1))
                    .expect("export transfer");
                push_log(
                    &log,
                    &seq,
                    "mirror",
                    "export_transfer",
                    format!("sequence={}", transfer.sequence),
                );

                let catch_up = federation
                    .plan_replication_catch_up(transfer.sequence, 0)
                    .expect("plan catch up");
                push_log(
                    &log,
                    &seq,
                    "mirror",
                    "plan_catch_up",
                    format!("action={:?}", catch_up.action),
                );

                let mut target =
                    RegionBridge::new_local(RegionId::new_for_test(70, 0), None, Budget::new());
                let snapshot = federation
                    .apply_replication_transfer(&mut target, &transfer)
                    .expect("apply transfer");
                push_log(
                    &log,
                    &seq,
                    "mirror",
                    "apply_transfer",
                    format!("target_tasks={}", target.local().task_ids().len()),
                );

                let close_blocked_before_drain = {
                    let mut stream = stream.lock().expect("stream lock");
                    stream.close().is_err()
                };
                push_log(
                    &log,
                    &seq,
                    "mirror",
                    "close_before_drain",
                    format!("blocked={close_blocked_before_drain}"),
                );
                ready.store(true, Ordering::SeqCst);

                for _ in 0..16 {
                    if removed.load(Ordering::SeqCst) == 2 {
                        break;
                    }
                    yield_now().await;
                }
                assert_eq!(
                    removed.load(Ordering::SeqCst),
                    2,
                    "mirror and source should drain"
                );

                let (closed_after_drain, snapshot_state) = {
                    let mut stream = stream.lock().expect("stream lock");
                    let closed_after_drain = stream.close().is_ok();
                    let snapshot_state = stream.snapshot().expect("snapshot");
                    drop(stream);
                    (closed_after_drain, snapshot_state)
                };
                push_log(
                    &log,
                    &seq,
                    "mirror",
                    "close_after_drain",
                    format!(
                        "closed={closed_after_drain} mirror_remaining={} source_remaining={}",
                        snapshot_state.mirror_regions.len(),
                        snapshot_state.source_regions.len()
                    ),
                );

                *summary.lock().expect("summary lock") = Some(MirrorSourceDrainOutcome {
                    catch_up_action: catch_up.action,
                    snapshot_sequence: snapshot.sequence,
                    target_task_count: target.local().task_ids().len(),
                    close_blocked_before_drain,
                    closed_after_drain,
                    mirror_remaining: snapshot_state.mirror_regions.len(),
                    source_remaining: snapshot_state.source_regions.len(),
                    log: Vec::new(),
                    steps: 0,
                });
            })
            .expect("create mirror/source controller");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let ready = Arc::clone(&ready);
        let removed = Arc::clone(&removed);
        let stream = Arc::clone(&stream);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                if stream
                    .lock()
                    .expect("stream lock")
                    .remove_mirror_region(RegionId::new_for_test(61, 0))
                {
                    removed.fetch_add(1, Ordering::SeqCst);
                    push_log(&log, &seq, "mirror", "remove_mirror", "removed");
                }
            })
            .expect("create mirror drain task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let ready = Arc::clone(&ready);
        let removed = Arc::clone(&removed);
        let stream = Arc::clone(&stream);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                yield_now().await;
                if stream
                    .lock()
                    .expect("stream lock")
                    .remove_source_region(RegionId::new_for_test(62, 0))
                {
                    removed.fetch_add(1, Ordering::SeqCst);
                    push_log(&log, &seq, "mirror", "remove_source", "removed");
                }
            })
            .expect("create source drain task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    assert_runtime_clean(&mut runtime, "mirror/source drain e2e");

    let mut summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("mirror/source summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    summary.log = log_entries;
    summary.steps = runtime.steps();
    summary
}

#[allow(clippy::too_many_lines)]
fn run_control_plane_advisory_flow(seed: u64) -> ControlPlaneAdvisoryOutcome {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<ControlPlaneAdvisoryOutcome>));
    let bridge = Arc::new(Mutex::new(
        FederationBridge::new(
            FederationRole::GatewayFabric(GatewayConfig::default()),
            vec![Morphism::default()],
            Vec::new(),
            [MorphismCapability::RewriteNamespace],
        )
        .expect("gateway bridge"),
    ));
    let ready = Arc::new(AtomicBool::new(false));
    let interests_done = Arc::new(AtomicUsize::new(0));
    let advisories_done = Arc::new(AtomicUsize::new(0));

    {
        let bridge = Arc::clone(&bridge);
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let ready = Arc::clone(&ready);
        let interests_done = Arc::clone(&interests_done);
        let advisories_done = Arc::clone(&advisories_done);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let index = ShardedSublist::with_prefix_depth(8, 1);
                let guard = index.subscribe(&SubjectPattern::new("advisory.>"), None);
                assert_eq!(index.lookup(&Subject::new("advisory.control.tick")).total(), 1);

                bridge
                    .lock()
                    .expect("bridge lock")
                    .activate()
                    .expect("activate");
                push_log(&log, &seq, "advisory", "activate", "gateway-ready");
                ready.store(true, Ordering::SeqCst);

                for _ in 0..20 {
                    if interests_done.load(Ordering::SeqCst) == 3
                        && advisories_done.load(Ordering::SeqCst) == 4
                    {
                        break;
                    }
                    yield_now().await;
                }
                assert_eq!(
                    interests_done.load(Ordering::SeqCst),
                    3,
                    "all interests should plan"
                );
                assert_eq!(
                    advisories_done.load(Ordering::SeqCst),
                    4,
                    "all advisories should forward"
                );

                drop(guard);
                let no_ghost_interest =
                    index.lookup(&Subject::new("advisory.control.tick")).total() == 0;
                push_log(
                    &log,
                    &seq,
                    "advisory",
                    "ghost_interest_cleared",
                    format!("cleared={no_ghost_interest}"),
                );

                let timed_out = bridge
                    .lock()
                    .expect("bridge lock")
                    .reconcile_gateway_convergence(Duration::from_secs(20))
                    .expect("convergence")
                    .timed_out;
                push_log(
                    &log,
                    &seq,
                    "advisory",
                    "convergence",
                    format!("timed_out={timed_out}"),
                );

                let (propagated_interest_count, forwarded_advisory_count) = {
                    let runtime = bridge.lock().expect("bridge lock").runtime();
                    match runtime {
                        asupersync::messaging::federation::FederationBridgeRuntime::Gateway(
                            runtime,
                        ) => (
                            runtime.propagated_interests.len(),
                            runtime.forwarded_advisories.len(),
                        ),
                        other => panic!("expected gateway runtime, got {other:?}"),
                    }
                };
                push_log(
                    &log,
                    &seq,
                    "advisory",
                    "runtime_counts",
                    format!(
                        "interests={propagated_interest_count} advisories={forwarded_advisory_count}"
                    ),
                );

                *summary.lock().expect("summary lock") = Some(ControlPlaneAdvisoryOutcome {
                    propagated_interest_count,
                    forwarded_advisory_count,
                    timed_out,
                    no_ghost_interest,
                    log: Vec::new(),
                    steps: 0,
                });
            })
            .expect("create advisory controller");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for pattern in ["tenant.route.>", "tenant.replay.>", "tenant.audit.>"] {
        let bridge = Arc::clone(&bridge);
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let ready = Arc::clone(&ready);
        let interests_done = Arc::clone(&interests_done);
        let pattern = pattern.to_string();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                bridge
                    .lock()
                    .expect("bridge lock")
                    .plan_gateway_interest(
                        SystemSubjectFamily::Route,
                        SubjectPattern::new(&pattern),
                        2,
                        ControlBudget::default(),
                    )
                    .expect("plan interest");
                interests_done.fetch_add(1, Ordering::SeqCst);
                push_log(&log, &seq, "advisory", "plan_interest", pattern);
            })
            .expect("create interest task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    for pattern in [
        "tenant.advisory.alpha",
        "tenant.advisory.beta",
        "tenant.advisory.gamma",
        "tenant.advisory.delta",
    ] {
        let bridge = Arc::clone(&bridge);
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let ready = Arc::clone(&ready);
        let advisories_done = Arc::clone(&advisories_done);
        let pattern = pattern.to_string();
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                while !ready.load(Ordering::SeqCst) {
                    yield_now().await;
                }
                bridge
                    .lock()
                    .expect("bridge lock")
                    .forward_gateway_advisory(
                        SystemSubjectFamily::Replay,
                        SubjectPattern::new(&pattern),
                        ControlBudget::break_glass(),
                    )
                    .expect("forward advisory");
                advisories_done.fetch_add(1, Ordering::SeqCst);
                push_log(&log, &seq, "advisory", "forward_advisory", pattern);
            })
            .expect("create advisory task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    assert_runtime_clean(&mut runtime, "control-plane advisory e2e");

    let mut summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("control-plane advisory summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    summary.log = log_entries;
    summary.steps = runtime.steps();
    summary
}

#[allow(clippy::too_many_lines)]
fn run_brokerless_rebalance(seed: u64) -> BrokerlessRebalanceOutcome {
    let mut runtime = LabRuntime::new(LabConfig::new(seed).max_steps(5_000));
    let region = runtime.state.create_root_region(Budget::INFINITE);
    let log = Arc::new(Mutex::new(Vec::new()));
    let seq = Arc::new(AtomicU64::new(0));
    let summary = Arc::new(Mutex::new(None::<BrokerlessRebalanceOutcome>));

    {
        let log = Arc::clone(&log);
        let seq = Arc::clone(&seq);
        let summary = Arc::clone(&summary);
        let (task_id, _handle) = runtime
            .state
            .create_task(region, Budget::INFINITE, async move {
                let policy = brokerless_rebalance_policy();
                let candidates = brokerless_rebalance_candidates();
                let repair_policy = RepairPolicy {
                    recoverability_target: 3,
                    cold_witnesses: 1,
                    hot_witnesses: 2,
                };
                let cell = SubjectCell::new(
                    &SubjectPattern::parse("orders.created").expect("pattern"),
                    CellEpoch::new(11, 2),
                    &candidates,
                    &policy,
                    repair_policy,
                    DataCapsule::default(),
                )
                .expect("subject cell");
                let observed_load = ObservedCellLoad::new(256);

                yield_now().await;
                let plan = policy
                    .plan_rebalance(
                        &cell.subject_partition,
                        &candidates,
                        &cell.steward_set,
                        cell.data_capsule.temperature,
                        observed_load,
                    )
                    .expect("rebalance plan");
                push_log(
                    &log,
                    &seq,
                    "rebalance",
                    "plan",
                    format!(
                        "temperature={:?} stewards={}",
                        plan.next_temperature,
                        plan.next_stewards.len()
                    ),
                );

                let next_sequencer = plan
                    .added_stewards
                    .first()
                    .cloned()
                    .unwrap_or_else(|| plan.next_stewards[0].clone());
                let retention_generation = 7;
                let repair_symbols = brokerless_repair_bindings(
                    &cell,
                    &plan.next_stewards,
                    plan.next_temperature,
                    &candidates,
                    retention_generation,
                );
                let cut_evidence = RebalanceCutEvidence {
                    next_sequencer: next_sequencer.clone(),
                    retention_generation,
                    obligation_summary: RebalanceObligationSummary {
                        publish_obligations_below_cut: 0,
                        active_consumer_leases: 2,
                        transferred_consumer_leases: 2,
                        ambiguous_consumer_lease_owners: 0,
                        active_reply_rights: 1,
                        reissued_reply_rights: 1,
                        dangling_reply_rights: 0,
                    },
                    repair_symbols,
                };
                push_log(
                    &log,
                    &seq,
                    "rebalance",
                    "cut_evidence",
                    format!("repair_holders={}", cut_evidence.repair_symbols.len()),
                );

                yield_now().await;
                let original_lease = cell
                    .control_capsule
                    .active_sequencer_lease()
                    .expect("active sequencer lease");
                let mut certified = cell
                    .certify_self_rebalance(&policy, &candidates, observed_load, cut_evidence)
                    .expect("certified rebalance");
                push_log(
                    &log,
                    &seq,
                    "rebalance",
                    "certify",
                    format!(
                        "epoch={}:{} fence={}",
                        certified.resulting_cell.epoch.membership_epoch,
                        certified.resulting_cell.epoch.generation,
                        certified.joint_config.fence_generation
                    ),
                );

                let old_sequencer_fenced = matches!(
                    certified
                        .resulting_cell
                        .control_capsule
                        .authoritative_append(&original_lease),
                    Err(ControlCapsuleError::StaleSequencerLease {
                        current_holder,
                        current_fence_generation,
                        ..
                    }) if current_holder == next_sequencer
                        && current_fence_generation == certified.resulting_cell.epoch.generation
                );
                push_log(
                    &log,
                    &seq,
                    "rebalance",
                    "fence_old_sequencer",
                    format!("fenced={old_sequencer_fenced}"),
                );

                let shared_control_shard_id = certified
                    .resulting_cell
                    .control_capsule
                    .shared_control_shard
                    .as_ref()
                    .map(|shard| shard.shard_id.clone());
                let shared_control_shard_slot = certified
                    .resulting_cell
                    .control_capsule
                    .shared_control_shard
                    .as_ref()
                    .map(|shard| shard.slot_index);

                *summary.lock().expect("summary lock") = Some(BrokerlessRebalanceOutcome {
                    next_temperature: format!("{:?}", certified.plan.next_temperature),
                    next_stewards: certified
                        .plan
                        .next_stewards
                        .iter()
                        .map(|node| node.as_str().to_owned())
                        .collect(),
                    drained_stewards: certified
                        .drained_stewards
                        .iter()
                        .map(|node| node.as_str().to_owned())
                        .collect(),
                    control_append_sequence: certified.control_append.identity.sequence,
                    resulting_generation: certified.resulting_cell.epoch.generation,
                    joint_fence_generation: certified.joint_config.fence_generation,
                    repair_holder_count: certified.cut_evidence.repair_symbols.len(),
                    shared_control_shard_id,
                    shared_control_shard_slot,
                    old_sequencer_fenced,
                    log: Vec::new(),
                    steps: 0,
                });
            })
            .expect("create brokerless rebalance task");
        runtime.scheduler.lock().schedule(task_id, 0);
    }

    assert_runtime_clean(&mut runtime, "brokerless rebalance e2e");

    let mut summary = summary
        .lock()
        .expect("summary lock")
        .clone()
        .expect("brokerless rebalance summary");
    let mut log_entries = log.lock().expect("log lock").clone();
    log_entries.sort_unstable_by_key(|entry| entry.seq);
    summary.log = log_entries;
    summary.steps = runtime.steps();
    summary
}

fn log_scenario_summary<T: Serialize>(scenario: &str, summary: &T) {
    tracing::info!(
        scenario = scenario,
        summary = %serde_json::to_string(summary).expect("serialize scenario summary"),
        "fabric e2e scenario summary"
    );
}

fn packet_plane_subtest(seed: u64) -> TestSummary {
    let mut harness = TestHarness::with_context(
        "fabric_e2e_packet_plane",
        test_context_with_seed("fabric-e2e-packet-plane", seed),
    );
    harness.enter_phase("run");
    let summary = run_packet_plane(seed);
    log_scenario_summary("packet_plane", &summary);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_eq(
        "wildcard subjects",
        &vec!["orders.created".to_string(), "orders.updated".to_string()],
        &summary.wildcard_subjects,
    );
    harness.assert_eq(
        "exact subjects",
        &vec!["orders.created".to_string()],
        &summary.exact_subjects,
    );
    harness.assert_true(
        "cancelled next returns none",
        summary.cancelled_next_is_none,
    );
    harness.assert_eq(
        "reply subject",
        &"service.lookup".to_string(),
        &summary.reply_subject,
    );
    harness.assert_eq("reply payload len", &6usize, &summary.reply_payload_len);
    harness.assert_true("timeline captured", summary.log.len() >= 5);
    harness.collect_artifact(
        "packet_plane_summary.json",
        &serde_json::to_string_pretty(&summary).expect("serialize packet summary"),
    );
    harness.exit_phase();

    harness.finish()
}

fn certified_request_subtest(seed: u64) -> TestSummary {
    let mut harness = TestHarness::with_context(
        "fabric_e2e_certified_request",
        test_context_with_seed("fabric-e2e-certified-request", seed),
    );
    harness.enter_phase("run");
    let summary = run_certified_request(seed);
    log_scenario_summary("certified_request", &summary);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_eq(
        "reply subject",
        &"service.lookup".to_string(),
        &summary.reply_subject,
    );
    harness.assert_eq("reply payload len", &6usize, &summary.reply_payload_len);
    harness.assert_eq(
        "reply ack kind",
        &AckKind::Received,
        &summary.reply_ack_kind,
    );
    harness.assert_eq(
        "reply delivery class",
        &DeliveryClass::ObligationBacked,
        &summary.reply_delivery_class,
    );
    harness.assert_eq(
        "published delivery class",
        &DeliveryClass::ObligationBacked,
        &summary.published_delivery_class,
    );
    harness.assert_true(
        "request certificate validates",
        summary.checks.request_certificate.is_valid(),
    );
    harness.assert_true(
        "reply certificate validates",
        summary.checks.reply_certificate.is_valid(),
    );
    harness.assert_true(
        "service obligation id captured",
        summary.checks.service_obligation.is_present(),
    );
    harness.assert_true(
        "delivery receipt present",
        summary.checks.delivery_receipt.is_present(),
    );
    harness.assert_true("ledger resolves cleanly", summary.checks.ledger.is_clean());
    harness.collect_artifact(
        "certified_request_summary.json",
        &serde_json::to_string_pretty(&summary).expect("serialize certified summary"),
    );
    harness.exit_phase();

    harness.finish()
}

fn stream_handle_subtest(seed: u64) -> TestSummary {
    let mut harness = TestHarness::with_context(
        "fabric_e2e_stream_handle",
        test_context_with_seed("fabric-e2e-stream-handle", seed),
    );
    harness.enter_phase("run");
    let summary = run_stream_handle(seed);
    log_scenario_summary("stream_handle", &summary);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_true(
        "endpoint matches expected prefix",
        summary.endpoint_matches_prefix,
    );
    harness.assert_eq(
        "subjects",
        &vec!["orders.created".to_string(), "orders.snapshot".to_string()],
        &summary.subjects,
    );
    harness.assert_eq(
        "delivery class",
        &DeliveryClass::DurableOrdered,
        &summary.delivery_class,
    );
    harness.assert_eq(
        "capture policy",
        &"ExplicitOptIn".to_string(),
        &summary.capture_policy,
    );
    harness.assert_eq(
        "request timeout millis",
        &Some(5_000_u64),
        &summary.request_timeout_millis,
    );
    harness.assert_eq(
        "reply subject",
        &"service.lookup".to_string(),
        &summary.reply_subject,
    );
    harness.assert_eq("reply payload len", &6usize, &summary.reply_payload_len);
    harness.collect_artifact(
        "stream_handle_summary.json",
        &serde_json::to_string_pretty(&summary).expect("serialize stream summary"),
    );
    harness.exit_phase();

    harness.finish()
}

fn consumer_flow_subtest(seed: u64) -> TestSummary {
    let mut harness = TestHarness::with_context(
        "fabric_e2e_consumer_flow",
        test_context_with_seed("fabric-e2e-consumer-flow", seed),
    );
    harness.enter_phase("run");
    let summary = run_consumer_flow(seed);
    log_scenario_summary("consumer_flow", &summary);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_eq("push window", &(5_u64, 6_u64), &summary.push_window);
    harness.assert_eq(
        "pending after push dispatch",
        &2_u64,
        &summary.pending_after_push_dispatch,
    );
    harness.assert_eq(
        "pending after push ack",
        &0_u64,
        &summary.pending_after_push_ack,
    );
    harness.assert_eq(
        "ack floor after push ack",
        &6_u64,
        &summary.ack_floor_after_push_ack,
    );
    harness.assert_eq("catch up window", &(7_u64, 9_u64), &summary.catch_up_window);
    harness.assert_eq("tail window", &(11_u64, 12_u64), &summary.tail_window);
    harness.assert_eq(
        "pending after tail dispatch",
        &2_u64,
        &summary.pending_after_tail_dispatch,
    );
    harness.assert_eq(
        "no data leaves queue empty",
        &0_usize,
        &summary.no_data_waiting_after_error,
    );
    harness.assert_eq("total acquired", &1_u64, &summary.total_acquired);
    harness.assert_eq("total committed", &3_u64, &summary.total_committed);
    harness.collect_artifact(
        "consumer_flow_summary.json",
        &serde_json::to_string_pretty(&summary).expect("serialize consumer summary"),
    );
    harness.exit_phase();

    harness.finish()
}

fn mirror_source_drain_subtest(seed: u64) -> TestSummary {
    let mut harness = TestHarness::with_context(
        "fabric_e2e_mirror_source_drain",
        test_context_with_seed("fabric-e2e-mirror-source-drain", seed),
    );
    harness.enter_phase("run");
    let summary = run_mirror_source_drain(seed);
    log_scenario_summary("mirror_source_drain", &summary);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_eq(
        "catch up action",
        &ReplicationCatchUpAction::SnapshotThenDelta,
        &summary.catch_up_action,
    );
    harness.assert_eq("snapshot sequence", &1_u64, &summary.snapshot_sequence);
    harness.assert_eq("target task count", &1_usize, &summary.target_task_count);
    harness.assert_true(
        "close blocked before drain",
        summary.close_blocked_before_drain,
    );
    harness.assert_true("closed after drain", summary.closed_after_drain);
    harness.assert_eq("mirror remaining", &0_usize, &summary.mirror_remaining);
    harness.assert_eq("source remaining", &0_usize, &summary.source_remaining);
    harness.assert_true("timeline captured", summary.log.len() >= 6);
    harness.collect_artifact(
        "mirror_source_drain_summary.json",
        &serde_json::to_string_pretty(&summary).expect("serialize mirror/source summary"),
    );
    harness.exit_phase();

    harness.finish()
}

fn control_plane_advisory_flow_subtest(seed: u64) -> TestSummary {
    let mut harness = TestHarness::with_context(
        "fabric_e2e_control_plane_advisory_flow",
        test_context_with_seed("fabric-e2e-control-plane-advisory-flow", seed),
    );
    harness.enter_phase("run");
    let summary = run_control_plane_advisory_flow(seed);
    log_scenario_summary("control_plane_advisory_flow", &summary);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_eq(
        "propagated interest count",
        &3_usize,
        &summary.propagated_interest_count,
    );
    harness.assert_eq(
        "forwarded advisory count",
        &4_usize,
        &summary.forwarded_advisory_count,
    );
    harness.assert_true("convergence timed out", summary.timed_out);
    harness.assert_true("ghost interest cleared", summary.no_ghost_interest);
    harness.assert_true("timeline captured", summary.log.len() >= 11);
    harness.collect_artifact(
        "control_plane_advisory_flow_summary.json",
        &serde_json::to_string_pretty(&summary).expect("serialize advisory summary"),
    );
    harness.exit_phase();

    harness.finish()
}

fn brokerless_rebalance_subtest(seed: u64) -> TestSummary {
    let mut harness = TestHarness::with_context(
        "fabric_e2e_brokerless_rebalance",
        test_context_with_seed("fabric-e2e-brokerless-rebalance", seed),
    );
    harness.enter_phase("run");
    let summary = run_brokerless_rebalance(seed);
    log_scenario_summary("brokerless_rebalance", &summary);
    harness.exit_phase();

    harness.enter_phase("verify");
    harness.assert_eq(
        "next temperature",
        &"Warm".to_string(),
        &summary.next_temperature,
    );
    harness.assert_eq("next steward count", &3_usize, &summary.next_stewards.len());
    harness.assert_eq(
        "control append sequence",
        &1_u64,
        &summary.control_append_sequence,
    );
    harness.assert_eq(
        "resulting generation",
        &3_u64,
        &summary.resulting_generation,
    );
    harness.assert_eq(
        "joint fence generation",
        &summary.resulting_generation,
        &summary.joint_fence_generation,
    );
    harness.assert_eq(
        "repair holder count",
        &4_usize,
        &summary.repair_holder_count,
    );
    harness.assert_true(
        "shared control shard assigned",
        summary.shared_control_shard_id.is_some(),
    );
    harness.assert_true(
        "shared control shard slot captured",
        summary.shared_control_shard_slot.is_some(),
    );
    harness.assert_true(
        "old sequencer lease is fenced",
        summary.old_sequencer_fenced,
    );
    harness.assert_true("timeline captured", summary.log.len() >= 4);
    harness.collect_artifact(
        "brokerless_rebalance_summary.json",
        &serde_json::to_string_pretty(&summary).expect("serialize brokerless rebalance summary"),
    );
    harness.exit_phase();

    harness.finish()
}

#[test]
fn fabric_e2e_aggregated_report_covers_public_surface_scenarios() {
    init_test_logging();

    let mut aggregator = TestReportAggregator::new();
    aggregator.add(packet_plane_subtest(0xFABC_0001));
    aggregator.add(certified_request_subtest(0xFABC_0002));
    aggregator.add(stream_handle_subtest(0xFABC_0003));
    aggregator.add(consumer_flow_subtest(0xFABC_0004));
    aggregator.add(mirror_source_drain_subtest(0xFABC_0005));
    aggregator.add(control_plane_advisory_flow_subtest(0xFABC_0006));
    aggregator.add(brokerless_rebalance_subtest(0xFABC_0007));

    let report = aggregator.report();
    assert_eq!(report.total_tests, 7);
    assert_eq!(report.passed_tests, 7);
    assert_eq!(report.failed_tests, 0);
    assert_eq!(report.coverage_matrix.len(), 7);
    assert!(report.total_assertions >= 39);
    assert!(
        report
            .coverage_matrix
            .iter()
            .all(|row| !row.phases_exercised.is_empty())
    );

    tracing::info!(
        json = %aggregator.report_json(),
        "fabric e2e aggregated coverage report"
    );
}

#[test]
fn fabric_e2e_fixed_seed_scenarios_are_deterministic() {
    init_test_logging();

    let first_packet = run_packet_plane(0xFADE_1001);
    let second_packet = run_packet_plane(0xFADE_1001);
    assert_eq!(first_packet, second_packet);

    let first_certified = run_certified_request(0xFADE_1002);
    let second_certified = run_certified_request(0xFADE_1002);
    assert_eq!(first_certified, second_certified);

    let first_stream = run_stream_handle(0xFADE_1003);
    let second_stream = run_stream_handle(0xFADE_1003);
    assert_eq!(first_stream, second_stream);

    let first_consumer = run_consumer_flow(0xFADE_1004);
    let second_consumer = run_consumer_flow(0xFADE_1004);
    assert_eq!(first_consumer, second_consumer);

    let first_mirror_source = run_mirror_source_drain(0xFADE_1005);
    let second_mirror_source = run_mirror_source_drain(0xFADE_1005);
    assert_eq!(first_mirror_source, second_mirror_source);

    let first_advisory = run_control_plane_advisory_flow(0xFADE_1006);
    let second_advisory = run_control_plane_advisory_flow(0xFADE_1006);
    assert_eq!(first_advisory, second_advisory);

    let first_rebalance = run_brokerless_rebalance(0xFADE_1007);
    let second_rebalance = run_brokerless_rebalance(0xFADE_1007);
    assert_eq!(first_rebalance, second_rebalance);
}
