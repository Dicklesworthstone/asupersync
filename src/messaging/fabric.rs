//! Foundational brokerless subject-fabric types and placement rules.
//!
//! The goal of this module is deliberately narrow: define the smallest
//! trustworthy `SubjectCell` model plus the canonical subject-partition,
//! bounded control-capsule artifacts, and deterministic placement rules that
//! later brokerless beads can build on. It does not attempt to implement the
//! full distributed data plane, federation, or consumer semantics yet.

use super::capability::FabricCapability;
use super::class::{AckKind, DeliveryClass};
use super::control::MembershipRecord;
use super::explain::{DataPlaneDecisionKind, ExplainDecisionSpec, ExplainPlan};
use super::ir::{CostVector, RetentionPolicy, SubjectFamily};
use super::policy::SemanticServiceClass;
use super::service::{ReplyCertificate, RequestCertificate, ServiceAdmission, ServiceObligation};
pub use super::subject::{Subject, SubjectPattern, SubjectPatternError, SubjectToken};
use super::subject::{Sublist, SubscriptionGuard, SubscriptionId};
use crate::config::EncodingConfig as RaptorQEncodingConfig;
use crate::cx::Cx;
#[cfg(test)]
use crate::decoding::{
    DecodingConfig as RaptorQDecodingConfig, DecodingPipeline as RaptorQDecodingPipeline,
    RejectReason,
};
use crate::distributed::HashRing;
use crate::encoding::EncodingPipeline as RaptorQEncodingPipeline;
use crate::error::{Error as AsupersyncError, ErrorKind};
use crate::obligation::ledger::{ObligationLedger, ObligationToken};
use crate::record::{ObligationAbortReason, ObligationKind};
use crate::remote::NodeId;
#[cfg(test)]
use crate::security::AuthenticatedSymbol;
use crate::security::{AuthKey, AuthenticationTag};
use crate::types::resource::{PoolConfig, SymbolPool};
use crate::types::{
    DEFAULT_SYMBOL_SIZE, ObjectId, ObjectParams, ObligationId, Symbol, SymbolId, Time,
};
use crate::util::DetHasher;
use franken_decision::{
    DecisionAuditEntry, DecisionContract, EvalContext, FallbackPolicy, LossMatrix, Posterior,
    evaluate,
};
use franken_kernel::{DecisionId, TraceId};
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;
use thiserror::Error;

fn fabric_input_error(message: impl Into<String>) -> AsupersyncError {
    AsupersyncError::new(ErrorKind::User).with_message(message)
}

#[allow(clippy::result_large_err)]
fn validate_publish_delivery_class(
    delivery_class: DeliveryClass,
    has_durability_ledger: bool,
) -> Result<(), AsupersyncError> {
    match (has_durability_ledger, delivery_class) {
        (false, DeliveryClass::EphemeralInteractive) | (true, DeliveryClass::DurableOrdered) => {
            Ok(())
        }
        (false, DeliveryClass::DurableOrdered) => Err(fabric_input_error(
            "durable-ordered publish requires reserve_publish_durable so the durability obligation is tracked",
        )),
        (true, DeliveryClass::EphemeralInteractive) => Err(fabric_input_error(
            "ephemeral-interactive publish should use reserve_publish; reserve_publish_durable would borrow a ledger without allocating an obligation",
        )),
        (
            _,
            DeliveryClass::ObligationBacked
            | DeliveryClass::MobilitySafe
            | DeliveryClass::ForensicReplayable,
        ) => Err(fabric_input_error(format!(
            "packet-plane publish does not yet support delivery class `{delivery_class}`; use the higher-layer service or control surfaces for stronger acknowledgement boundaries"
        ))),
    }
}

#[allow(clippy::result_large_err)]
fn parse_subject(raw: impl AsRef<str>) -> Result<Subject, AsupersyncError> {
    Subject::parse(raw.as_ref()).map_err(|error| fabric_input_error(error.to_string()))
}

#[allow(clippy::result_large_err)]
fn parse_subject_pattern(raw: impl AsRef<str>) -> Result<SubjectPattern, AsupersyncError> {
    SubjectPattern::parse(raw.as_ref()).map_err(|error| fabric_input_error(error.to_string()))
}

fn render_fabric_capability(capability: &FabricCapability) -> String {
    match capability {
        FabricCapability::Publish { subject } => format!("publish:{}", subject.canonical_key()),
        FabricCapability::Subscribe { subject } => {
            format!("subscribe:{}", subject.canonical_key())
        }
        FabricCapability::CreateStream { subject } => {
            format!("create_stream:{}", subject.canonical_key())
        }
        FabricCapability::ConsumeStream { stream } => format!("consume_stream:{stream}"),
        FabricCapability::TransformSpace { subject } => {
            format!("transform_space:{}", subject.canonical_key())
        }
        FabricCapability::AdminControl => "admin_control".to_owned(),
    }
}

fn fabric_capability_denied_error(
    subject: SubjectPattern,
    delivery_class: DeliveryClass,
    requested_capability: String,
    decision_id: DecisionId,
) -> AsupersyncError {
    let message = format!(
        "fabric capability `{requested_capability}` is required for `{}` at delivery class `{delivery_class}`",
        subject.canonical_key()
    );
    AsupersyncError::new(ErrorKind::AdmissionDenied)
        .with_message(message)
        .with_source(FabricError::CapabilityDenied {
            subject,
            delivery_class,
            requested_capability,
            decision_id,
        })
}

fn shared_fabric_state(endpoint: &str) -> Arc<Mutex<FabricState>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<String, Weak<Mutex<FabricState>>>>> = OnceLock::new();

    let registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut registry = registry.lock();
    registry.retain(|_, state| state.upgrade().is_some());

    if let Some(existing) = registry.get(endpoint).and_then(Weak::upgrade) {
        return existing;
    }

    let state = Arc::new(Mutex::new(FabricState::new(endpoint)));
    registry.insert(endpoint.to_owned(), Arc::downgrade(&state));
    state
}

/// Minimal public Browser/Native FABRIC handle.
///
/// This surface intentionally models the NATS-small API promised by the FABRIC
/// plan without pretending the full distributed data plane is implemented yet.
/// The current behavior is an in-process semantic seam that:
///
/// - validates subjects and subject patterns,
/// - preserves explicit `&Cx` propagation on every async entry point, and
/// - keeps Layer 0 publish/subscribe on the default
///   [`DeliveryClass::EphemeralInteractive`] path.
#[derive(Debug, Clone)]
pub struct Fabric {
    endpoint: String,
    state: Arc<Mutex<FabricState>>,
}

#[derive(Debug)]
struct FabricState {
    cells: BTreeMap<String, FabricCellRuntime>,
    cell_routes: BTreeMap<SubscriptionId, String>,
    subscribers: BTreeMap<u64, FabricSubscriberState>,
    decision_records: Vec<FabricDecisionRecord>,
    routing: Arc<Sublist>,
    next_sequence: u64,
    next_subscriber_id: u64,
    cell_buffer_capacity: usize,
    placement_policy: PlacementPolicy,
    repair_policy: RepairPolicy,
    default_data_capsule: DataCapsule,
    default_epoch: CellEpoch,
    local_candidates: Vec<StewardCandidate>,
}

#[derive(Debug, Clone)]
struct FabricSubscriberState {
    pattern: SubjectPattern,
    next_sequence: u64,
}

#[derive(Debug, Clone)]
struct FabricBufferedMessage {
    sequence: u64,
    message: FabricMessage,
}

#[derive(Debug, Clone)]
struct PreparedFabricPublish {
    routed_cells: Vec<String>,
    message: FabricMessage,
    capacity: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FabricCellBufferState {
    Empty,
    Buffered,
    Backpressured,
}

impl FabricCellBufferState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Buffered => "buffered",
            Self::Backpressured => "backpressured",
        }
    }

    const fn from_buffer_len(buffer_len: usize, capacity: usize) -> Self {
        if buffer_len == 0 {
            Self::Empty
        } else if buffer_len >= capacity {
            Self::Backpressured
        } else {
            Self::Buffered
        }
    }
}

#[derive(Debug)]
struct FabricCellRuntime {
    cell: SubjectCell,
    durable_capsule: RecoverableDataCapsule,
    _route_guard: SubscriptionGuard,
    buffer: VecDeque<FabricBufferedMessage>,
    state: FabricCellBufferState,
}

impl FabricCellRuntime {
    fn new(cell: SubjectCell, route_guard: SubscriptionGuard) -> Self {
        Self {
            durable_capsule: RecoverableDataCapsule::new(&cell),
            cell,
            _route_guard: route_guard,
            buffer: VecDeque::new(),
            state: FabricCellBufferState::Empty,
        }
    }
}

impl FabricState {
    const DEFAULT_CELL_BUFFER_CAPACITY: usize = 64;

    fn new(endpoint: &str) -> Self {
        Self {
            cells: BTreeMap::new(),
            cell_routes: BTreeMap::new(),
            subscribers: BTreeMap::new(),
            decision_records: Vec::new(),
            routing: Arc::new(Sublist::new()),
            next_sequence: 0,
            next_subscriber_id: 1,
            cell_buffer_capacity: Self::DEFAULT_CELL_BUFFER_CAPACITY,
            placement_policy: PlacementPolicy::default(),
            repair_policy: RepairPolicy::default(),
            default_data_capsule: DataCapsule::default(),
            default_epoch: CellEpoch::new(0, 1),
            local_candidates: vec![
                StewardCandidate::new(
                    NodeId::new(format!(
                        "fabric-local-{:016x}",
                        stable_hash(("fabric-endpoint", endpoint))
                    )),
                    "local",
                )
                .with_role(NodeRole::Steward)
                .with_role(NodeRole::RepairWitness),
            ],
        }
    }

    fn effective_cell_buffer_capacity(&self) -> usize {
        self.cell_buffer_capacity.max(1)
    }

    fn push_decision(&mut self, cx: &Cx, record: FabricDecisionRecord) {
        trace_fabric_decision_recorded(cx, &record);
        self.decision_records.push(record);
    }

    #[allow(clippy::result_large_err)]
    fn capability_cell_id_for_subject(
        &self,
        subject: &SubjectPattern,
    ) -> Result<CellId, AsupersyncError> {
        let canonical_partition = self
            .placement_policy
            .normalization
            .normalize(subject)
            .map_err(|error| fabric_input_error(error.to_string()))?;
        Ok(CellId::for_partition(
            self.default_epoch,
            &canonical_partition,
        ))
    }

    #[allow(clippy::result_large_err)]
    fn enforce_capability(
        &mut self,
        cx: &Cx,
        subject: &SubjectPattern,
        delivery_class: DeliveryClass,
        requested: &FabricCapability,
    ) -> Result<(), AsupersyncError> {
        let requested_capability = render_fabric_capability(requested);
        let granted_capability_count = cx.fabric_capabilities().len();
        let allowed = cx.check_fabric_capability(requested);
        let cell_id = self.capability_cell_id_for_subject(subject)?;
        let record = FabricCapabilityDecision::new(
            cell_id,
            subject.canonical_key(),
            delivery_class,
            requested_capability.clone(),
            granted_capability_count,
            allowed,
        )
        .evaluate();
        let decision_id = record.decision_id();
        let cell_id_str = cell_id.to_string();
        let subject_str = subject.canonical_key();
        let delivery_class_str = delivery_class.to_string();
        let granted_capability_count_str = granted_capability_count.to_string();
        let allowed_str = if allowed { "true" } else { "false" };
        let decision_id_str = decision_id.to_string();
        cx.trace_with_fields(
            "fabric.capability_check",
            &[
                ("event", "fabric.capability_check"),
                ("cell_id", cell_id_str.as_str()),
                ("subject", subject_str.as_str()),
                ("delivery_class", delivery_class_str.as_str()),
                ("requested_capability", requested_capability.as_str()),
                (
                    "granted_capability_count",
                    granted_capability_count_str.as_str(),
                ),
                ("allowed", allowed_str),
                ("decision_id", decision_id_str.as_str()),
            ],
        );
        self.push_decision(cx, record);

        if allowed {
            Ok(())
        } else {
            Err(fabric_capability_denied_error(
                subject.clone(),
                delivery_class,
                requested_capability,
                decision_id,
            ))
        }
    }

    fn primary_cell_id_for_routed_keys(&self, routed_cells: &[String]) -> Option<CellId> {
        routed_cells
            .first()
            .and_then(|cell_key| self.cells.get(cell_key).map(|cell| cell.cell.cell_id))
    }

    fn register_subscription(&mut self, pattern: SubjectPattern, next_sequence: u64) -> u64 {
        let id = self.next_subscriber_id;
        self.next_subscriber_id += 1;
        self.subscribers.insert(
            id,
            FabricSubscriberState {
                pattern,
                next_sequence,
            },
        );
        id
    }

    fn remove_subscription(&mut self, id: u64) {
        self.subscribers.remove(&id);
    }

    #[allow(clippy::result_large_err)]
    fn ensure_cell_for_subject(
        &mut self,
        cx: &Cx,
        subject: &Subject,
    ) -> Result<String, AsupersyncError> {
        let literal_partition = parse_subject_pattern(subject.as_str())?;
        let canonical_partition = self
            .placement_policy
            .normalization
            .normalize(&literal_partition)
            .map_err(|error| fabric_input_error(error.to_string()))?;
        let cell_key = canonical_partition.canonical_key();

        if self.cells.contains_key(&cell_key) {
            return Ok(cell_key);
        }

        let cell = SubjectCell::new(
            &literal_partition,
            self.default_epoch,
            &self.local_candidates,
            &self.placement_policy,
            self.repair_policy.clone(),
            self.default_data_capsule.clone(),
        )
        .map_err(|error| fabric_input_error(error.to_string()))?;
        let route_guard = self.routing.subscribe(&cell.subject_partition, None);
        let route_id = route_guard.id();
        let cell_id = cell.cell_id;

        self.cell_routes.insert(route_id, cell_key.clone());
        self.cells
            .insert(cell_key.clone(), FabricCellRuntime::new(cell, route_guard));
        trace_fabric_cell_state_transition(
            cx,
            cell_id,
            None,
            FabricCellBufferState::Empty,
            "cell created",
        );

        Ok(cell_key)
    }

    #[allow(clippy::result_large_err)]
    fn route_keys_for_subject(
        &mut self,
        cx: &Cx,
        subject: &Subject,
        delivery_class: DeliveryClass,
    ) -> Result<Vec<String>, AsupersyncError> {
        let expected_cell = self.ensure_cell_for_subject(cx, subject)?;
        let matches = self.routing.lookup(subject);
        let mut routed = Vec::with_capacity(matches.subscribers.len());

        for route_id in matches.subscribers {
            if let Some(cell_key) = self.cell_routes.get(&route_id) {
                routed.push(cell_key.clone());
            }
        }

        if routed.is_empty() {
            routed.push(expected_cell.clone());
        }

        routed.sort();
        routed.dedup();

        if let Some(cell_id) = self.cells.get(&expected_cell).map(|cell| cell.cell.cell_id) {
            let decision = FabricRoutingDecision::new(
                cell_id,
                subject.as_str(),
                delivery_class,
                routed.clone(),
            )
            .evaluate();
            self.push_decision(cx, decision);
        }
        Ok(routed)
    }

    #[allow(clippy::result_large_err)]
    fn publish_message(
        &mut self,
        cx: &Cx,
        subject: &Subject,
        payload: Vec<u8>,
        delivery_class: DeliveryClass,
    ) -> Result<(), AsupersyncError> {
        let prepared = self.prepare_publish_message(cx, subject, payload, delivery_class)?;
        self.apply_prepared_publish(cx, prepared);
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn prepare_publish_message(
        &mut self,
        cx: &Cx,
        subject: &Subject,
        payload: Vec<u8>,
        delivery_class: DeliveryClass,
    ) -> Result<PreparedFabricPublish, AsupersyncError> {
        self.prune_cells(cx);

        let routed_cells = self.route_keys_for_subject(cx, subject, delivery_class)?;
        let capacity = self.effective_cell_buffer_capacity();
        let message = FabricMessage {
            subject: subject.clone(),
            payload,
            delivery_class,
        };

        for cell_key in &routed_cells {
            let full_cell = {
                let Some(cell) = self.cells.get_mut(cell_key) else {
                    return Err(AsupersyncError::new(ErrorKind::RoutingFailed)
                        .with_message(format!("missing fabric cell runtime for {cell_key}")));
                };

                if cell.buffer.len() < capacity {
                    None
                } else {
                    let cell_id = cell.cell.cell_id;
                    let queued_messages = cell.buffer.len();
                    let from_state = cell.state;
                    if from_state != FabricCellBufferState::Backpressured {
                        cell.state = FabricCellBufferState::Backpressured;
                        trace_fabric_cell_state_transition(
                            cx,
                            cell_id,
                            Some(from_state),
                            FabricCellBufferState::Backpressured,
                            "buffer capacity exhausted",
                        );
                    }
                    let error = AsupersyncError::new(ErrorKind::ChannelFull).with_message(
                        format!(
                            "fabric cell {cell_id} is backpressured at capacity {capacity} for subject {}",
                            subject.as_str()
                        ),
                    );
                    let decision = FabricRetryDecision::new(
                        cell_id,
                        subject.as_str(),
                        delivery_class,
                        queued_messages,
                        capacity,
                    )
                    .evaluate();
                    Some((decision, error))
                }
            };

            if let Some((decision, error)) = full_cell {
                self.push_decision(cx, decision);
                return Err(error);
            }
        }

        Ok(PreparedFabricPublish {
            routed_cells,
            message,
            capacity,
        })
    }

    fn apply_prepared_publish(&mut self, cx: &Cx, prepared: PreparedFabricPublish) {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        let local_candidates = self.local_candidates.clone();

        for cell_key in prepared.routed_cells {
            let mut transition = None;

            {
                let cell = self
                    .cells
                    .get_mut(&cell_key)
                    .expect("prepared routed cell must exist for publish");
                cell.buffer.push_back(FabricBufferedMessage {
                    sequence,
                    message: prepared.message.clone(),
                });
                if prepared.message.delivery_class == DeliveryClass::DurableOrdered {
                    if let Err(error) = cell.durable_capsule.record_publish(
                        &cell.cell,
                        &local_candidates,
                        sequence,
                        &prepared.message,
                    ) {
                        trace_data_capsule_publish_error(cx, cell.cell.cell_id, sequence, &error);
                    }
                }

                let next_state =
                    FabricCellBufferState::from_buffer_len(cell.buffer.len(), prepared.capacity);
                if cell.state != next_state {
                    transition = Some((cell.cell.cell_id, cell.state, next_state));
                    cell.state = next_state;
                }
            }

            if let Some((cell_id, from_state, to_state)) = transition {
                trace_fabric_cell_state_transition(
                    cx,
                    cell_id,
                    Some(from_state),
                    to_state,
                    "publish accepted",
                );
            }
        }
    }

    fn next_matching_message(&mut self, cx: &Cx, subscription_id: u64) -> Option<FabricMessage> {
        let subscriber = self.subscribers.get(&subscription_id)?.clone();

        let next = self
            .cells
            .values()
            .flat_map(|cell| cell.buffer.iter())
            .filter(|entry| {
                entry.sequence >= subscriber.next_sequence
                    && subscriber.pattern.matches(&entry.message.subject)
            })
            .min_by_key(|entry| entry.sequence)
            .cloned();

        let next = next?;
        let subscriber_state = self.subscribers.get_mut(&subscription_id)?;
        subscriber_state.next_sequence = next.sequence + 1;
        self.prune_cells(cx);
        Some(next.message)
    }

    fn prune_cells(&mut self, cx: &Cx) {
        let subscribers = &self.subscribers;
        let capacity = self.effective_cell_buffer_capacity();

        for cell in self.cells.values_mut() {
            while let Some(front) = cell.buffer.front() {
                let retained = subscribers.values().any(|subscriber| {
                    subscriber.next_sequence <= front.sequence
                        && subscriber.pattern.matches(&front.message.subject)
                });
                if retained {
                    break;
                }
                cell.buffer.pop_front();
            }

            let next_state = FabricCellBufferState::from_buffer_len(cell.buffer.len(), capacity);
            if cell.state != next_state {
                let from_state = cell.state;
                cell.state = next_state;
                trace_fabric_cell_state_transition(
                    cx,
                    cell.cell.cell_id,
                    Some(from_state),
                    next_state,
                    "buffer retention pruned",
                );
            }
        }
    }
}

fn trace_fabric_cell_state_transition(
    cx: &Cx,
    cell_id: CellId,
    from_state: Option<FabricCellBufferState>,
    to_state: FabricCellBufferState,
    reason: &str,
) {
    let cell_id = cell_id.to_string();
    let from_state = from_state.map_or("absent", |state| state.as_str());
    let to_state = to_state.as_str();
    cx.trace_with_fields(
        "fabric.cell_state_transition",
        &[
            ("event", "fabric.cell_state_transition"),
            ("cell_id", cell_id.as_str()),
            ("from_state", from_state),
            ("to_state", to_state),
            ("reason", reason),
        ],
    );
}

fn trace_publish_reserve(
    cx: &Cx,
    subject: &Subject,
    delivery_class: DeliveryClass,
    obligation_id: Option<ObligationId>,
) {
    let subject_str = subject.as_str();
    let class_str = delivery_class.to_string();
    let obligation_str = obligation_id.map_or_else(String::new, |id| format!("{id}"));
    cx.trace_with_fields(
        "fabric.publish_reserve",
        &[
            ("event", "publish_reserve"),
            ("subject", subject_str),
            ("delivery_class", class_str.as_str()),
            ("obligation_id", obligation_str.as_str()),
        ],
    );
}

fn trace_publish_commit(
    cx: &Cx,
    subject: &Subject,
    delivery_class: DeliveryClass,
    obligation_id: Option<ObligationId>,
    payload_len: usize,
) {
    let subject_str = subject.as_str();
    let class_str = delivery_class.to_string();
    let obligation_str = obligation_id.map_or_else(String::new, |id| format!("{id}"));
    let len_str = payload_len.to_string();
    cx.trace_with_fields(
        "fabric.publish_commit",
        &[
            ("event", "publish_commit"),
            ("subject", subject_str),
            ("delivery_class", class_str.as_str()),
            ("obligation_id", obligation_str.as_str()),
            ("payload_len", len_str.as_str()),
        ],
    );
}

fn trace_publish_abort(
    cx: &Cx,
    subject: &Subject,
    delivery_class: DeliveryClass,
    obligation_id: Option<ObligationId>,
    reason: &str,
) {
    let subject_str = subject.as_str();
    let class_str = delivery_class.to_string();
    let obligation_str = obligation_id.map_or_else(String::new, |id| format!("{id}"));
    cx.trace_with_fields(
        "fabric.publish_abort",
        &[
            ("event", "publish_abort"),
            ("subject", subject_str),
            ("delivery_class", class_str.as_str()),
            ("obligation_id", obligation_str.as_str()),
            ("reason", reason),
        ],
    );
}

fn trace_data_capsule_publish_error(
    cx: &Cx,
    cell_id: CellId,
    sequence: u64,
    error: &DataCapsuleError,
) {
    let cell_id = cell_id.to_string();
    let sequence = sequence.to_string();
    let reason = error.to_string();
    cx.trace_with_fields(
        "fabric.data_capsule_publish_error",
        &[
            ("event", "fabric_data_capsule_publish_error"),
            ("cell_id", cell_id.as_str()),
            ("sequence", sequence.as_str()),
            ("reason", reason.as_str()),
        ],
    );
}

/// Emit a structured trace when a fabric operation is cancelled at its
/// checkpoint.  This gives operators visibility into cancel pressure on
/// the packet plane without extra error-handling boilerplate.
#[allow(clippy::result_large_err)]
fn fabric_checkpoint(cx: &Cx, operation: &str) -> Result<(), AsupersyncError> {
    match cx.checkpoint() {
        Ok(()) => Ok(()),
        Err(err) => {
            cx.trace_with_fields(
                "fabric.cancelled",
                &[("event", "fabric_cancelled"), ("operation", operation)],
            );
            Err(err)
        }
    }
}

/// Operator-visible FABRIC decision classes backed by Franken decision
/// contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FabricDecisionKind {
    /// Route a subject across one or more canonical cells.
    Routing,
    /// Decide whether a bounded publish should retry, back off, or fail closed.
    Retry,
    /// Accept or reject a capability-bearing operation.
    Capability,
    /// Select the effective delivery class once semantic floors apply.
    DeliveryClassEscalation,
}

impl FabricDecisionKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Routing => "routing",
            Self::Retry => "retry",
            Self::Capability => "capability",
            Self::DeliveryClassEscalation => "delivery_class_escalation",
        }
    }

    const fn explain_kind(self) -> DataPlaneDecisionKind {
        match self {
            Self::Routing => DataPlaneDecisionKind::SecuritySensitiveRouting,
            Self::Retry => DataPlaneDecisionKind::DistributedFailover,
            Self::Capability => DataPlaneDecisionKind::MultiTenantGovernance,
            Self::DeliveryClassEscalation => DataPlaneDecisionKind::AdaptiveDeliveryPolicy,
        }
    }

    fn retention(self) -> RetentionPolicy {
        match self {
            Self::Routing | Self::Retry => RetentionPolicy::RetainFor {
                duration: Duration::from_mins(5),
            },
            Self::Capability | Self::DeliveryClassEscalation => RetentionPolicy::RetainFor {
                duration: Duration::from_mins(15),
            },
        }
    }
}

/// Materialized FABRIC decision record ready for explain-plan rendering.
#[derive(Debug, Clone)]
pub struct FabricDecisionRecord {
    /// High-level FABRIC decision class.
    pub kind: FabricDecisionKind,
    /// Canonical subject cell anchoring the decision.
    pub cell_id: CellId,
    /// Subject or subject-pattern scope for the decision.
    pub subject: String,
    /// Effective delivery class when the decision was made.
    pub delivery_class: DeliveryClass,
    /// Deterministic annotations for operator tooling.
    pub annotations: BTreeMap<String, String>,
    /// Franken decision-contract audit payload.
    pub audit: DecisionAuditEntry,
}

impl FabricDecisionRecord {
    /// Stable identifier for the underlying decision audit record.
    #[must_use]
    pub fn decision_id(&self) -> DecisionId {
        self.audit.decision_id
    }

    /// Number of evidence slots carried by the posterior snapshot.
    #[must_use]
    pub fn evidence_count(&self) -> usize {
        self.audit.posterior_snapshot.len()
    }

    /// Decision-contract name for filtering and operator search.
    #[must_use]
    pub fn contract_name(&self) -> &str {
        &self.audit.contract_name
    }

    fn explain_summary(&self) -> String {
        match self.kind {
            FabricDecisionKind::Routing => format!(
                "route `{}` using fabric action `{}`",
                self.subject, self.audit.action_chosen
            ),
            FabricDecisionKind::Retry => format!(
                "retry posture `{}` for `{}`",
                self.audit.action_chosen, self.subject
            ),
            FabricDecisionKind::Capability => format!(
                "capability decision `{}` for `{}`",
                self.audit.action_chosen, self.subject
            ),
            FabricDecisionKind::DeliveryClassEscalation => format!(
                "selected delivery class `{}` for `{}`",
                self.audit.action_chosen, self.subject
            ),
        }
    }

    fn explain_spec(&self) -> ExplainDecisionSpec {
        let mut spec = ExplainDecisionSpec::new(
            self.kind.explain_kind(),
            self.subject.clone(),
            fabric_subject_family(&self.subject),
            self.delivery_class,
            self.explain_summary(),
            self.kind.retention(),
        )
        .with_estimated_cost(CostVector::baseline_for_delivery_class(self.delivery_class))
        .with_annotation("cell_id", self.cell_id.to_string())
        .with_annotation("contract", self.contract_name())
        .with_annotation("evidence_count", self.evidence_count().to_string())
        .with_annotation("fabric_decision_kind", self.kind.as_str());

        for (key, value) in &self.annotations {
            spec = spec.with_annotation(key.clone(), value.clone());
        }

        spec
    }

    /// Attach this FABRIC decision record to an explain plan.
    pub fn record_into_plan(&self, plan: &mut ExplainPlan) {
        plan.record_audit_entry(self.explain_spec(), self.audit.clone());
    }
}

#[derive(Debug, Clone)]
struct StaticActionDecisionContract {
    name: &'static str,
    states: Vec<String>,
    actions: Vec<String>,
    losses: LossMatrix,
    chosen_action: usize,
    fallback: FallbackPolicy,
}

impl DecisionContract for StaticActionDecisionContract {
    fn name(&self) -> &str {
        self.name
    }

    fn state_space(&self) -> &[String] {
        &self.states
    }

    fn action_set(&self) -> &[String] {
        &self.actions
    }

    fn loss_matrix(&self) -> &LossMatrix {
        &self.losses
    }

    fn update_posterior(&self, posterior: &mut Posterior, observation: usize) {
        let mut likelihoods = vec![0.1; self.states.len()];
        if let Some(slot) = likelihoods.get_mut(observation) {
            *slot = 0.9;
        }
        posterior.bayesian_update(&likelihoods);
    }

    fn choose_action(&self, _posterior: &Posterior) -> usize {
        self.chosen_action
    }

    fn fallback_action(&self) -> usize {
        self.chosen_action
    }

    fn fallback_policy(&self) -> &FallbackPolicy {
        &self.fallback
    }
}

fn normalize_decision_posterior<const N: usize>(mut weights: [f64; N]) -> Posterior {
    for weight in &mut weights {
        if *weight <= 0.0 {
            *weight = 0.01;
        }
    }
    let total = weights.iter().sum::<f64>().max(f64::EPSILON);
    Posterior::new(
        weights
            .into_iter()
            .map(|weight| weight / total)
            .collect::<Vec<_>>(),
    )
    .expect("fabric decision posterior should normalize")
}

fn fabric_decision_context<T: Hash>(
    contract_name: &'static str,
    cell_id: CellId,
    subject: &str,
    seed: &T,
    calibration_score: f64,
    e_process: f64,
    ci_width: f64,
) -> EvalContext {
    let ts_unix_ms = 1_700_000_000_000_u64.saturating_add(stable_hash((
        "fabric-decision-ts",
        contract_name,
        cell_id.raw(),
        subject,
        seed,
    )));
    let fingerprint = u128::from(stable_hash((
        "fabric-decision",
        contract_name,
        cell_id.raw(),
        subject,
        seed,
    )));

    EvalContext {
        calibration_score,
        e_process,
        ci_width,
        decision_id: DecisionId::from_parts(ts_unix_ms, fingerprint),
        trace_id: TraceId::from_parts(ts_unix_ms, fingerprint ^ 0xFABA_1C00_5EED_u128),
        ts_unix_ms,
    }
}

fn fabric_subject_family(subject: &str) -> SubjectFamily {
    if subject.starts_with("_INBOX.") {
        SubjectFamily::Reply
    } else if subject.starts_with("service.") || subject.starts_with("svc.") {
        SubjectFamily::Command
    } else if subject.starts_with("control.") || subject.starts_with("$SYS.") {
        SubjectFamily::Control
    } else {
        SubjectFamily::Event
    }
}

fn usize_to_f64(value: usize) -> f64 {
    f64::from(u32::try_from(value).unwrap_or(u32::MAX))
}

const fn delivery_class_index(class: DeliveryClass) -> usize {
    match class {
        DeliveryClass::EphemeralInteractive => 0,
        DeliveryClass::DurableOrdered => 1,
        DeliveryClass::ObligationBacked => 2,
        DeliveryClass::MobilitySafe => 3,
        DeliveryClass::ForensicReplayable => 4,
    }
}

const fn delivery_class_rank(class: DeliveryClass) -> u8 {
    match class {
        DeliveryClass::EphemeralInteractive => 0,
        DeliveryClass::DurableOrdered => 1,
        DeliveryClass::ObligationBacked => 2,
        DeliveryClass::MobilitySafe => 3,
        DeliveryClass::ForensicReplayable => 4,
    }
}

fn evaluate_fabric_decision(
    kind: FabricDecisionKind,
    cell_id: CellId,
    subject: &str,
    delivery_class: DeliveryClass,
    annotations: BTreeMap<String, String>,
    contract: &StaticActionDecisionContract,
    posterior: Posterior,
    ctx: EvalContext,
) -> FabricDecisionRecord {
    let outcome = evaluate(contract, &posterior, &ctx);
    FabricDecisionRecord {
        kind,
        cell_id,
        subject: subject.to_owned(),
        delivery_class,
        annotations,
        audit: outcome.audit_entry,
    }
}

fn trace_fabric_decision_recorded(cx: &Cx, record: &FabricDecisionRecord) {
    let cell_id = record.cell_id.to_string();
    let evidence_count = record.evidence_count().to_string();
    cx.trace_with_fields(
        "fabric.decision_recorded",
        &[
            ("event", "fabric.decision_recorded"),
            ("contract", record.contract_name()),
            ("cell_id", cell_id.as_str()),
            ("evidence_count", evidence_count.as_str()),
            ("action", record.audit.action_chosen.as_str()),
        ],
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FabricRoutingDecisionSnapshot {
    routed_cell_count: usize,
    delivery_class: DeliveryClass,
}

impl FabricRoutingDecisionSnapshot {
    fn posterior(self) -> Posterior {
        let weights = if self.routed_cell_count > 1 {
            [0.08, 0.84, 0.08]
        } else if self.delivery_class >= DeliveryClass::MobilitySafe {
            [0.18, 0.12, 0.70]
        } else {
            [0.84, 0.08, 0.08]
        };
        normalize_decision_posterior(weights)
    }

    fn calibration_score(self) -> f64 {
        if self.routed_cell_count > 1 {
            0.9
        } else {
            0.96
        }
    }

    fn e_process(self) -> f64 {
        1.0 + usize_to_f64(self.routed_cell_count) / 2.0
    }

    fn ci_width(self) -> f64 {
        0.08 + usize_to_f64(self.routed_cell_count) / 20.0
    }
}

/// Decision contract for routing one subject through canonical FABRIC cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricRoutingDecision {
    /// Canonical cell owning the subject being routed.
    pub cell_id: CellId,
    /// Subject being routed.
    pub subject: String,
    /// Delivery class in force at the routing boundary.
    pub delivery_class: DeliveryClass,
    /// Canonical cell keys selected by the runtime.
    pub routed_cell_keys: Vec<String>,
}

impl FabricRoutingDecision {
    /// Construct a routing decision from the resolved route set.
    #[must_use]
    pub fn new(
        cell_id: CellId,
        subject: impl Into<String>,
        delivery_class: DeliveryClass,
        routed_cell_keys: Vec<String>,
    ) -> Self {
        Self {
            cell_id,
            subject: subject.into(),
            delivery_class,
            routed_cell_keys,
        }
    }

    /// Evaluate the routing contract into a materialized audit record.
    #[must_use]
    pub fn evaluate(&self) -> FabricDecisionRecord {
        let snapshot = FabricRoutingDecisionSnapshot {
            routed_cell_count: self.routed_cell_keys.len().max(1),
            delivery_class: self.delivery_class,
        };
        let contract = StaticActionDecisionContract {
            name: "fabric_routing_decision",
            states: vec![
                "single_cell_route".into(),
                "fanout_route".into(),
                "high_assurance_route".into(),
            ],
            actions: vec!["single_cell".into(), "fanout_cells".into()],
            losses: LossMatrix::new(
                vec![
                    "single_cell_route".into(),
                    "fanout_route".into(),
                    "high_assurance_route".into(),
                ],
                vec!["single_cell".into(), "fanout_cells".into()],
                vec![
                    1.0, 6.0, // single
                    8.0, 1.0, // fanout
                    2.0, 4.0, // high assurance
                ],
            )
            .expect("fabric routing losses should be valid"),
            chosen_action: usize::from(self.routed_cell_keys.len() > 1),
            fallback: FallbackPolicy::default(),
        };
        let ctx = fabric_decision_context(
            contract.name,
            self.cell_id,
            &self.subject,
            &snapshot,
            snapshot.calibration_score(),
            snapshot.e_process(),
            snapshot.ci_width(),
        );
        evaluate_fabric_decision(
            FabricDecisionKind::Routing,
            self.cell_id,
            &self.subject,
            self.delivery_class,
            BTreeMap::from([
                (
                    "routed_cell_count".to_owned(),
                    self.routed_cell_keys.len().to_string(),
                ),
                (
                    "routed_cell_keys".to_owned(),
                    self.routed_cell_keys.join(","),
                ),
            ]),
            &contract,
            snapshot.posterior(),
            ctx,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FabricRetryDecisionSnapshot {
    queued_messages: usize,
    capacity: usize,
    delivery_class: DeliveryClass,
}

impl FabricRetryDecisionSnapshot {
    fn posterior(self) -> Posterior {
        if self.queued_messages >= self.capacity {
            normalize_decision_posterior([0.05, 0.10, 0.85])
        } else if self.queued_messages.saturating_add(1) >= self.capacity {
            normalize_decision_posterior([0.12, 0.72, 0.16])
        } else if self.delivery_class >= DeliveryClass::MobilitySafe {
            normalize_decision_posterior([0.68, 0.22, 0.10])
        } else {
            normalize_decision_posterior([0.84, 0.10, 0.06])
        }
    }

    fn calibration_score(self) -> f64 {
        if self.queued_messages >= self.capacity {
            0.93
        } else {
            0.88
        }
    }

    fn e_process(self) -> f64 {
        1.0 + usize_to_f64(self.queued_messages) / usize_to_f64(self.capacity.max(1))
    }

    fn ci_width(self) -> f64 {
        0.09 + usize_to_f64(self.queued_messages) / (usize_to_f64(self.capacity.max(1)) * 2.0)
    }
}

/// Decision contract describing bounded publish retry posture for one cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricRetryDecision {
    /// Canonical cell under pressure.
    pub cell_id: CellId,
    /// Subject being published.
    pub subject: String,
    /// Delivery class in force for the publish.
    pub delivery_class: DeliveryClass,
    /// Messages currently buffered in the target cell.
    pub queued_messages: usize,
    /// Effective cell capacity.
    pub capacity: usize,
}

impl FabricRetryDecision {
    /// Construct a retry decision from the current cell-buffer snapshot.
    #[must_use]
    pub fn new(
        cell_id: CellId,
        subject: impl Into<String>,
        delivery_class: DeliveryClass,
        queued_messages: usize,
        capacity: usize,
    ) -> Self {
        Self {
            cell_id,
            subject: subject.into(),
            delivery_class,
            queued_messages,
            capacity: capacity.max(1),
        }
    }

    /// Evaluate the retry contract into a materialized audit record.
    #[must_use]
    pub fn evaluate(&self) -> FabricDecisionRecord {
        let snapshot = FabricRetryDecisionSnapshot {
            queued_messages: self.queued_messages,
            capacity: self.capacity,
            delivery_class: self.delivery_class,
        };
        let chosen_action = if self.queued_messages >= self.capacity {
            2
        } else {
            0
        };
        let contract = StaticActionDecisionContract {
            name: "fabric_retry_decision",
            states: vec![
                "transient_headroom".into(),
                "pressure_building".into(),
                "buffer_exhausted".into(),
            ],
            actions: vec!["retry_now".into(), "backoff".into(), "fail_closed".into()],
            losses: LossMatrix::new(
                vec![
                    "transient_headroom".into(),
                    "pressure_building".into(),
                    "buffer_exhausted".into(),
                ],
                vec!["retry_now".into(), "backoff".into(), "fail_closed".into()],
                vec![
                    1.0, 4.0, 12.0, // transient
                    5.0, 1.0, 3.0, // pressure
                    10.0, 4.0, 1.0, // exhausted
                ],
            )
            .expect("fabric retry losses should be valid"),
            chosen_action,
            fallback: FallbackPolicy::default(),
        };
        let ctx = fabric_decision_context(
            contract.name,
            self.cell_id,
            &self.subject,
            &snapshot,
            snapshot.calibration_score(),
            snapshot.e_process(),
            snapshot.ci_width(),
        );
        evaluate_fabric_decision(
            FabricDecisionKind::Retry,
            self.cell_id,
            &self.subject,
            self.delivery_class,
            BTreeMap::from([
                (
                    "queued_messages".to_owned(),
                    self.queued_messages.to_string(),
                ),
                ("capacity".to_owned(), self.capacity.to_string()),
            ]),
            &contract,
            snapshot.posterior(),
            ctx,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FabricCapabilityDecisionSnapshot {
    allowed: bool,
    granted_capability_count: usize,
    admin_requested: bool,
}

impl FabricCapabilityDecisionSnapshot {
    fn posterior(self) -> Posterior {
        if self.allowed {
            normalize_decision_posterior([0.82, 0.08, 0.05, 0.05])
        } else if self.admin_requested {
            normalize_decision_posterior([0.05, 0.10, 0.75, 0.10])
        } else if self.granted_capability_count == 0 {
            normalize_decision_posterior([0.05, 0.25, 0.10, 0.60])
        } else {
            normalize_decision_posterior([0.05, 0.68, 0.12, 0.15])
        }
    }

    fn calibration_score(self) -> f64 {
        if self.allowed { 0.95 } else { 0.9 }
    }

    fn e_process(self) -> f64 {
        1.0 + usize_to_f64(self.granted_capability_count) / 4.0
    }

    fn ci_width(self) -> f64 {
        if self.allowed { 0.08 } else { 0.15 }
    }
}

/// Decision contract for capability-scoped FABRIC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricCapabilityDecision {
    /// Canonical cell associated with the capability-bearing operation.
    pub cell_id: CellId,
    /// Subject or subject-pattern scope being checked.
    pub subject: String,
    /// Delivery class promised for the operation.
    pub delivery_class: DeliveryClass,
    /// Requested capability rendered in deterministic operator form.
    pub requested_capability: String,
    /// Number of grants that were available at decision time.
    pub granted_capability_count: usize,
    /// Whether the operation was allowed.
    pub allowed: bool,
}

impl FabricCapabilityDecision {
    /// Construct a capability decision.
    #[must_use]
    pub fn new(
        cell_id: CellId,
        subject: impl Into<String>,
        delivery_class: DeliveryClass,
        requested_capability: impl Into<String>,
        granted_capability_count: usize,
        allowed: bool,
    ) -> Self {
        Self {
            cell_id,
            subject: subject.into(),
            delivery_class,
            requested_capability: requested_capability.into(),
            granted_capability_count,
            allowed,
        }
    }

    /// Evaluate the capability contract into a materialized audit record.
    #[must_use]
    pub fn evaluate(&self) -> FabricDecisionRecord {
        let snapshot = FabricCapabilityDecisionSnapshot {
            allowed: self.allowed,
            granted_capability_count: self.granted_capability_count,
            admin_requested: self.requested_capability == "admin_control",
        };
        let contract = StaticActionDecisionContract {
            name: "fabric_capability_decision",
            states: vec![
                "scope_covered".into(),
                "scope_mismatch".into(),
                "admin_mismatch".into(),
                "escalation_detected".into(),
            ],
            actions: vec!["allow".into(), "reject".into()],
            losses: LossMatrix::new(
                vec![
                    "scope_covered".into(),
                    "scope_mismatch".into(),
                    "admin_mismatch".into(),
                    "escalation_detected".into(),
                ],
                vec!["allow".into(), "reject".into()],
                vec![
                    1.0, 8.0, // covered
                    9.0, 1.0, // mismatch
                    12.0, 1.0, // admin mismatch
                    14.0, 1.0, // escalation
                ],
            )
            .expect("fabric capability losses should be valid"),
            chosen_action: usize::from(!self.allowed),
            fallback: FallbackPolicy::default(),
        };
        let ctx = fabric_decision_context(
            contract.name,
            self.cell_id,
            &self.subject,
            &snapshot,
            snapshot.calibration_score(),
            snapshot.e_process(),
            snapshot.ci_width(),
        );
        evaluate_fabric_decision(
            FabricDecisionKind::Capability,
            self.cell_id,
            &self.subject,
            self.delivery_class,
            BTreeMap::from([
                (
                    "requested_capability".to_owned(),
                    self.requested_capability.clone(),
                ),
                (
                    "granted_capability_count".to_owned(),
                    self.granted_capability_count.to_string(),
                ),
            ]),
            &contract,
            snapshot.posterior(),
            ctx,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FabricDeliveryClassEscalationSnapshot {
    requested: DeliveryClass,
    selected: DeliveryClass,
}

impl FabricDeliveryClassEscalationSnapshot {
    fn posterior(self) -> Posterior {
        if self.selected == self.requested {
            normalize_decision_posterior([0.84, 0.10, 0.06])
        } else if self.selected == DeliveryClass::ForensicReplayable {
            normalize_decision_posterior([0.05, 0.20, 0.75])
        } else {
            normalize_decision_posterior([0.10, 0.80, 0.10])
        }
    }

    fn calibration_score(self) -> f64 {
        if self.selected == self.requested {
            0.95
        } else {
            0.9
        }
    }

    fn e_process(self) -> f64 {
        1.0 + f64::from(delivery_class_rank(self.selected)) / 2.0
    }

    fn ci_width(self) -> f64 {
        if self.selected == self.requested {
            0.08
        } else {
            0.12
        }
    }
}

/// Decision contract for selecting the effective delivery class after applying
/// semantic floors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricDeliveryClassEscalation {
    /// Canonical cell associated with the escalation surface.
    pub cell_id: CellId,
    /// Subject being evaluated.
    pub subject: String,
    /// Delivery class originally requested by the caller.
    pub requested_delivery_class: DeliveryClass,
    /// Minimum delivery class required by the semantic surface.
    pub minimum_delivery_class: DeliveryClass,
    /// Effective delivery class selected after applying the floor.
    pub selected_delivery_class: DeliveryClass,
}

impl FabricDeliveryClassEscalation {
    /// Construct a delivery-class selection from a requested class and floor.
    #[must_use]
    pub fn new(
        cell_id: CellId,
        subject: impl Into<String>,
        requested_delivery_class: DeliveryClass,
        minimum_delivery_class: DeliveryClass,
    ) -> Self {
        let selected_delivery_class = requested_delivery_class.max(minimum_delivery_class);
        Self {
            cell_id,
            subject: subject.into(),
            requested_delivery_class,
            minimum_delivery_class,
            selected_delivery_class,
        }
    }

    /// Evaluate the delivery-class selection into a materialized audit record.
    #[must_use]
    pub fn evaluate(&self) -> FabricDecisionRecord {
        let snapshot = FabricDeliveryClassEscalationSnapshot {
            requested: self.requested_delivery_class,
            selected: self.selected_delivery_class,
        };
        let actions = DeliveryClass::ALL
            .into_iter()
            .map(|class| class.to_string())
            .collect::<Vec<_>>();
        let contract = StaticActionDecisionContract {
            name: "fabric_delivery_class_escalation",
            states: vec![
                "no_escalation".into(),
                "floor_escalation".into(),
                "forensic_escalation".into(),
            ],
            actions: actions.clone(),
            losses: LossMatrix::new(
                vec![
                    "no_escalation".into(),
                    "floor_escalation".into(),
                    "forensic_escalation".into(),
                ],
                actions,
                vec![
                    1.0, 2.0, 4.0, 8.0, 14.0, // no escalation
                    8.0, 4.0, 1.0, 2.0, 5.0, // floor escalation
                    16.0, 12.0, 8.0, 4.0, 1.0, // forensic escalation
                ],
            )
            .expect("fabric delivery-class losses should be valid"),
            chosen_action: delivery_class_index(self.selected_delivery_class),
            fallback: FallbackPolicy::default(),
        };
        let ctx = fabric_decision_context(
            contract.name,
            self.cell_id,
            &self.subject,
            &snapshot,
            snapshot.calibration_score(),
            snapshot.e_process(),
            snapshot.ci_width(),
        );
        evaluate_fabric_decision(
            FabricDecisionKind::DeliveryClassEscalation,
            self.cell_id,
            &self.subject,
            self.selected_delivery_class,
            BTreeMap::from([
                (
                    "requested_delivery_class".to_owned(),
                    self.requested_delivery_class.to_string(),
                ),
                (
                    "minimum_delivery_class".to_owned(),
                    self.minimum_delivery_class.to_string(),
                ),
                (
                    "selected_delivery_class".to_owned(),
                    self.selected_delivery_class.to_string(),
                ),
            ]),
            &contract,
            snapshot.posterior(),
            ctx,
        )
    }
}

/// Published or received packet-plane message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricMessage {
    /// Concrete subject of the message.
    pub subject: Subject,
    /// Message payload bytes.
    pub payload: Vec<u8>,
    /// Semantic class applied to the message.
    pub delivery_class: DeliveryClass,
}

/// Packet-plane publish acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReceipt {
    /// Subject accepted by the packet plane.
    pub subject: Subject,
    /// Number of payload bytes accepted.
    pub payload_len: usize,
    /// Acknowledgement boundary reached by the operation.
    pub ack_kind: AckKind,
    /// Delivery class used for the publish.
    pub delivery_class: DeliveryClass,
}

/// Two-phase publish permit.
///
/// Represents a reserved slot in the fabric packet plane.  The holder
/// **must** call [`PublishPermit::send`] to commit the publish or
/// [`PublishPermit::abort`] to release the slot.  Dropping without
/// calling either method aborts cleanly (no data committed, no
/// obligation leaked).
///
/// For [`DeliveryClass::EphemeralInteractive`] the permit is lightweight
/// (no obligation token).  For durable or obligation-backed classes an
/// [`ObligationId`] is allocated during [`Fabric::reserve_publish_durable`]
/// and committed or aborted together with the payload.
#[derive(Debug)]
struct PublishPermitObligation<'ledger> {
    ledger: &'ledger mut ObligationLedger,
    token: ObligationToken,
    reserved_at: Time,
}

/// Two-phase publish reservation for the packet plane.
#[must_use = "a PublishPermit must be sent or explicitly aborted"]
pub struct PublishPermit<'ledger> {
    /// Fabric shared state handle.
    state: Arc<Mutex<FabricState>>,
    /// Pre-validated subject.
    subject: Subject,
    /// Delivery class selected for the publish.
    delivery_class: DeliveryClass,
    /// Pre-computed routing and capacity snapshot from `prepare_publish_message`.
    prepared: Option<PreparedFabricPublish>,
    /// Obligation token for durable delivery classes (None for ephemeral).
    obligation_id: Option<ObligationId>,
    /// Live ledger token for durable delivery classes.
    obligation: Option<PublishPermitObligation<'ledger>>,
    /// Whether `send` or `abort` has been called.  Guards against
    /// double-consume and ensures `Drop` only fires the abort path once.
    consumed: bool,
}

impl fmt::Debug for PublishPermit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishPermit")
            .field("subject", &self.subject)
            .field("delivery_class", &self.delivery_class)
            .field("obligation_id", &self.obligation_id)
            .field("has_obligation", &self.obligation.is_some())
            .field("consumed", &self.consumed)
            .finish()
    }
}

impl PublishPermit<'_> {
    fn commit_obligation(&mut self, now: Time) {
        if let Some(obligation) = self.obligation.take() {
            let _ = obligation.ledger.commit(obligation.token, now);
        }
    }

    fn abort_obligation(&mut self, now: Time, reason: ObligationAbortReason) {
        if let Some(obligation) = self.obligation.take() {
            let _ = obligation.ledger.abort(obligation.token, now, reason);
        }
    }

    fn drop_abort_time(&self) -> Time {
        self.obligation
            .as_ref()
            .map_or(Time::ZERO, |obligation| obligation.reserved_at)
    }

    /// Commit the publish by supplying the payload.
    ///
    /// The payload is enqueued to all routed cells, the obligation (if any)
    /// is committed, and a [`PublishReceipt`] is returned.  This method
    /// consumes the permit; calling it a second time is a compile error.
    ///
    /// The returned acknowledgement certifies the minimum honest boundary
    /// for the selected delivery class on this narrow packet-plane seam.
    pub fn send(mut self, cx: &Cx, payload: impl Into<Vec<u8>>) -> PublishReceipt {
        let payload = payload.into();
        let payload_len = payload.len();
        let delivery_class = self.delivery_class;
        let subject = self.subject.clone();
        let obligation_id = self.obligation_id;

        // Rebuild the prepared publish with the actual payload.
        if let Some(mut prepared) = self.prepared.take() {
            prepared.message.payload = payload;
            self.state.lock().apply_prepared_publish(cx, prepared);
        }

        self.commit_obligation(cx.now());
        trace_publish_commit(cx, &subject, delivery_class, obligation_id, payload_len);
        self.consumed = true;

        PublishReceipt {
            subject,
            payload_len,
            ack_kind: delivery_class.minimum_ack(),
            delivery_class,
        }
    }

    /// Explicitly abort the publish, releasing the reserved slot and any
    /// associated obligation without committing data.
    ///
    /// For durable delivery classes, this also aborts the backing
    /// obligation token.
    pub fn abort(mut self, cx: &Cx) {
        self.abort_obligation(cx.now(), ObligationAbortReason::Explicit);
        trace_publish_abort(
            cx,
            &self.subject,
            self.delivery_class,
            self.obligation_id,
            "explicit",
        );
        self.prepared = None;
        self.consumed = true;
    }

    /// Returns the subject that was reserved.
    #[must_use]
    pub fn subject(&self) -> &Subject {
        &self.subject
    }

    /// Returns the delivery class for this permit.
    #[must_use]
    pub fn delivery_class(&self) -> DeliveryClass {
        self.delivery_class
    }

    /// Returns the obligation ID allocated for durable delivery classes,
    /// or `None` for ephemeral publishes.
    #[must_use]
    pub fn obligation_id(&self) -> Option<ObligationId> {
        self.obligation_id
    }
}

impl Drop for PublishPermit<'_> {
    fn drop(&mut self) {
        if !self.consumed {
            // Silent abort — the slot is released and the obligation (if any)
            // is aborted deterministically instead of leaking into drain.
            self.abort_obligation(self.drop_abort_time(), ObligationAbortReason::Explicit);
            self.prepared = None;
        }
    }
}

/// Request/reply response envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricReply {
    /// Reply subject echoed by the current semantic seam.
    pub subject: Subject,
    /// Reply payload bytes.
    pub payload: Vec<u8>,
    /// Acknowledgement boundary observed for the request.
    pub ack_kind: AckKind,
    /// Delivery class used for the request.
    pub delivery_class: DeliveryClass,
}

/// Follow-on delivery receipt produced when a certified reply crosses a
/// tracked delivery or receipt boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricReplyDelivery {
    /// Follow-on reply-delivery obligation id.
    pub obligation_id: ObligationId,
    /// Boundary satisfied by the immediate loopback seam.
    pub delivery_boundary: AckKind,
    /// Whether the caller explicitly required a receipt boundary.
    pub receipt_required: bool,
}

/// Obligation-backed request/reply result with explicit certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricCertifiedReply {
    /// The public reply envelope observed by the caller.
    pub reply: FabricReply,
    /// Admission certificate carried into the request.
    pub request_certificate: RequestCertificate,
    /// Reply certificate proving the callee resolved the service obligation.
    pub reply_certificate: ReplyCertificate,
    /// Delivery receipt when the reply crossed a tracked boundary.
    pub delivery_receipt: Option<FabricReplyDelivery>,
}

/// Capture policy for stream declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CapturePolicy {
    /// Stream capture is disabled.
    #[default]
    Disabled,
    /// Capture only when the caller explicitly opts into the stream.
    ExplicitOptIn,
}

/// Public stream configuration for `Fabric::stream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricStreamConfig {
    /// Subjects captured by the stream declaration.
    pub subjects: Vec<SubjectPattern>,
    /// Requested delivery class for the stream surface.
    pub delivery_class: DeliveryClass,
    /// Capture behavior for matching packet-plane traffic.
    pub capture_policy: CapturePolicy,
    /// Optional request timeout carried into stream operations.
    pub request_timeout: Option<Duration>,
}

impl Default for FabricStreamConfig {
    fn default() -> Self {
        Self {
            subjects: Vec::new(),
            delivery_class: DeliveryClass::EphemeralInteractive,
            capture_policy: CapturePolicy::ExplicitOptIn,
            request_timeout: None,
        }
    }
}

impl FabricStreamConfig {
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), AsupersyncError> {
        if self.subjects.is_empty() {
            return Err(AsupersyncError::new(ErrorKind::ConfigError)
                .with_message("stream config must declare at least one subject pattern"));
        }

        SubjectPattern::validate_non_overlapping(&self.subjects)
            .map_err(|error| fabric_input_error(error.to_string()))?;
        Ok(())
    }
}

/// Ergonomic alias matching the planned user-facing `stream(...)` example.
pub type StreamConfig = FabricStreamConfig;

/// Handle returned by `Fabric::stream`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricStreamHandle {
    endpoint: String,
    config: FabricStreamConfig,
}

impl FabricStreamHandle {
    /// Return the configured stream declaration.
    #[must_use]
    pub fn config(&self) -> &FabricStreamConfig {
        &self.config
    }

    /// Return the endpoint that created the stream declaration.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

/// Subscription handle returned by `Fabric::subscribe`.
#[derive(Debug, Clone)]
pub struct FabricSubscription {
    inner: Arc<FabricSubscriptionInner>,
}

#[derive(Debug)]
struct FabricSubscriptionInner {
    id: u64,
    pattern: SubjectPattern,
    state: Arc<Mutex<FabricState>>,
}

impl Drop for FabricSubscriptionInner {
    fn drop(&mut self) {
        self.state.lock().remove_subscription(self.id);
    }
}

impl FabricSubscription {
    /// Return the subscribed pattern.
    #[must_use]
    pub fn pattern(&self) -> &SubjectPattern {
        &self.inner.pattern
    }

    /// Return the next matching message, if one is currently available.
    ///
    /// Cancellation propagates by returning `None` once the supplied `Cx`
    /// observes a cancellation request.
    #[allow(clippy::unused_async)]
    pub async fn next(&mut self, cx: &Cx) -> Option<FabricMessage> {
        if fabric_checkpoint(cx, "subscription_next").is_err() {
            return None;
        }

        self.inner
            .state
            .lock()
            .next_matching_message(cx, self.inner.id)
    }
}

impl Fabric {
    /// Connect to a known fabric endpoint.
    #[allow(clippy::unused_async)]
    pub async fn connect(cx: &Cx, endpoint: impl AsRef<str>) -> Result<Self, AsupersyncError> {
        fabric_checkpoint(cx, "connect")?;

        let endpoint = endpoint.as_ref().trim();
        if endpoint.is_empty() {
            return Err(AsupersyncError::new(ErrorKind::ConfigError)
                .with_message("fabric endpoint must not be empty"));
        }

        Ok(Self {
            endpoint: endpoint.to_owned(),
            state: shared_fabric_state(endpoint),
        })
    }

    /// Return the endpoint used for the current handle.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Reserve a publish slot on the fabric packet plane.
    ///
    /// Returns a [`PublishPermit`] that the caller **must** either
    /// [`send`](PublishPermit::send) (committing payload to routed cells)
    /// or [`abort`](PublishPermit::abort).  Dropping the permit without
    /// calling either method aborts cleanly.
    ///
    /// For [`DeliveryClass::EphemeralInteractive`] the permit is
    /// lightweight.  For durable classes, pass an [`ObligationLedger`] to
    /// [`reserve_publish_durable`] instead, which allocates an obligation
    /// token that participates in region drain.
    #[allow(clippy::unused_async)]
    pub async fn reserve_publish(
        &self,
        cx: &Cx,
        subject: impl AsRef<str>,
        delivery_class: DeliveryClass,
    ) -> Result<PublishPermit<'static>, AsupersyncError> {
        fabric_checkpoint(cx, "reserve_publish")?;
        validate_publish_delivery_class(delivery_class, false)?;

        let subject = parse_subject(subject)?;
        let requested_capability = FabricCapability::Publish {
            subject: parse_subject_pattern(subject.as_str())?,
        };
        // Prepare with an empty payload — the real payload is supplied at
        // send time.  The prepare phase validates routing and capacity.
        let prepared = {
            let mut state = self.state.lock();
            state.enforce_capability(
                cx,
                match &requested_capability {
                    FabricCapability::Publish { subject } => subject,
                    _ => unreachable!("publish path constructs publish capability"),
                },
                delivery_class,
                &requested_capability,
            )?;
            state.prepare_publish_message(cx, &subject, Vec::new(), delivery_class)?
        };

        trace_publish_reserve(cx, &subject, delivery_class, None);

        Ok(PublishPermit {
            state: Arc::clone(&self.state),
            subject,
            delivery_class,
            prepared: Some(prepared),
            obligation_id: None,
            obligation: None,
            consumed: false,
        })
    }

    /// Reserve a publish slot with obligation tracking for durable delivery.
    ///
    /// Like [`reserve_publish`](Self::reserve_publish) but allocates an
    /// [`ObligationId`] in the provided ledger.  The obligation is
    /// committed when [`PublishPermit::send`] is called and aborted on
    /// drop or explicit [`PublishPermit::abort`]. Today this surface only
    /// supports [`DeliveryClass::DurableOrdered`]; ephemeral publishes
    /// should use [`reserve_publish`](Self::reserve_publish), and stronger
    /// classes belong to the higher-layer service/control flows that can
    /// honestly certify them.
    #[allow(clippy::unused_async)]
    pub async fn reserve_publish_durable<'ledger>(
        &self,
        cx: &Cx,
        ledger: &'ledger mut ObligationLedger,
        subject: impl AsRef<str>,
        delivery_class: DeliveryClass,
    ) -> Result<PublishPermit<'ledger>, AsupersyncError> {
        fabric_checkpoint(cx, "reserve_publish_durable")?;
        validate_publish_delivery_class(delivery_class, true)?;

        let subject = parse_subject(subject)?;
        let requested_capability = FabricCapability::Publish {
            subject: parse_subject_pattern(subject.as_str())?,
        };
        let prepared = {
            let mut state = self.state.lock();
            state.enforce_capability(
                cx,
                match &requested_capability {
                    FabricCapability::Publish { subject } => subject,
                    _ => unreachable!("durable publish path constructs publish capability"),
                },
                delivery_class,
                &requested_capability,
            )?;
            state.prepare_publish_message(cx, &subject, Vec::new(), delivery_class)?
        };

        let obligation = if delivery_class > DeliveryClass::EphemeralInteractive {
            let reserved_at = cx.now();
            let token = ledger.acquire(
                ObligationKind::SendPermit,
                cx.task_id(),
                cx.region_id(),
                reserved_at,
            );
            Some(PublishPermitObligation {
                ledger,
                token,
                reserved_at,
            })
        } else {
            None
        };
        let obligation_id = obligation.as_ref().map(|obligation| obligation.token.id());

        trace_publish_reserve(cx, &subject, delivery_class, obligation_id);

        Ok(PublishPermit {
            state: Arc::clone(&self.state),
            subject,
            delivery_class,
            prepared: Some(prepared),
            obligation_id,
            obligation,
            consumed: false,
        })
    }

    /// Publish a packet-plane message with the default delivery class.
    ///
    /// Convenience wrapper around [`reserve_publish`](Self::reserve_publish)
    /// followed by [`PublishPermit::send`].
    #[allow(clippy::unused_async)]
    pub async fn publish(
        &self,
        cx: &Cx,
        subject: impl AsRef<str>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<PublishReceipt, AsupersyncError> {
        let permit = self
            .reserve_publish(cx, subject, DeliveryClass::EphemeralInteractive)
            .await?;
        Ok(permit.send(cx, payload))
    }

    /// Subscribe to a packet-plane subject pattern.
    #[allow(clippy::unused_async)]
    pub async fn subscribe(
        &self,
        cx: &Cx,
        subject_pattern: impl AsRef<str>,
    ) -> Result<FabricSubscription, AsupersyncError> {
        fabric_checkpoint(cx, "subscribe")?;
        let pattern = parse_subject_pattern(subject_pattern)?;
        let state = Arc::clone(&self.state);
        let id = {
            let mut state = state.lock();
            let requested_capability = FabricCapability::Subscribe {
                subject: pattern.clone(),
            };
            state.enforce_capability(
                cx,
                &pattern,
                DeliveryClass::EphemeralInteractive,
                &requested_capability,
            )?;
            let next_sequence = state.next_sequence;
            state.register_subscription(pattern.clone(), next_sequence)
        };

        Ok(FabricSubscription {
            inner: Arc::new(FabricSubscriptionInner { id, pattern, state }),
        })
    }

    /// Issue a bounded request/reply interaction.
    ///
    /// The current API-design seam performs an immediate loopback reply so the
    /// public surface is testable before the full authority/data plane lands.
    pub async fn request(
        &self,
        cx: &Cx,
        subject: impl AsRef<str>,
        payload: impl Into<Vec<u8>>,
    ) -> Result<FabricReply, AsupersyncError> {
        fabric_checkpoint(cx, "request")?;
        let subject = parse_subject(subject)?;
        let requested_capability = FabricCapability::Subscribe {
            subject: parse_subject_pattern(subject.as_str())?,
        };
        self.state.lock().enforce_capability(
            cx,
            match &requested_capability {
                FabricCapability::Subscribe { subject } => subject,
                _ => unreachable!("request path constructs subscribe capability"),
            },
            DeliveryClass::EphemeralInteractive,
            &requested_capability,
        )?;
        let payload = payload.into();
        let receipt = self.publish(cx, subject.as_str(), payload.clone()).await?;

        Ok(FabricReply {
            subject: receipt.subject,
            payload,
            ack_kind: receipt.ack_kind,
            delivery_class: receipt.delivery_class,
        })
    }

    /// Execute an obligation-backed request/reply using a prior service
    /// admission certificate.
    ///
    /// This keeps the default [`Fabric::request`] path NATS-cheap while making
    /// stronger request/reply contracts an explicit opt-in. The caller must
    /// provide a [`ServiceAdmission`] produced by the FABRIC service boundary;
    /// this method then allocates and resolves the corresponding service
    /// obligation, emits a reply certificate, and commits any required
    /// reply-delivery obligation before returning.
    #[allow(clippy::unused_async)]
    #[allow(clippy::too_many_arguments)]
    pub async fn request_certified(
        &self,
        cx: &Cx,
        ledger: &mut ObligationLedger,
        admission: &ServiceAdmission,
        callee: impl Into<String>,
        payload: impl Into<Vec<u8>>,
        delivery_boundary: AckKind,
        receipt_required: bool,
    ) -> Result<FabricCertifiedReply, AsupersyncError> {
        fabric_checkpoint(cx, "request_certified")?;
        admission
            .certificate
            .validate()
            .map_err(|error| fabric_input_error(error.to_string()))?;

        let delivery_class = admission.validated.delivery_class;
        if delivery_class < DeliveryClass::ObligationBacked {
            return Err(fabric_input_error(format!(
                "certified fabric request requires obligation-backed or stronger delivery class, got {delivery_class}"
            )));
        }
        if admission.certificate.delivery_class != delivery_class {
            return Err(fabric_input_error(format!(
                "service admission delivery class {delivery_class} does not match certificate {}",
                admission.certificate.delivery_class
            )));
        }
        if admission.certificate.timeout != admission.validated.timeout {
            return Err(fabric_input_error(
                "service admission timeout does not match certificate timeout",
            ));
        }

        let callee = callee.into();
        let subject = parse_subject(&admission.certificate.subject)?;
        let publish_capability = FabricCapability::Publish {
            subject: parse_subject_pattern(subject.as_str())?,
        };
        let subscribe_capability = FabricCapability::Subscribe {
            subject: match &publish_capability {
                FabricCapability::Publish { subject } => subject.clone(),
                _ => unreachable!("certified request constructs publish capability"),
            },
        };
        let payload = payload.into();
        let now = cx.now();
        let service_latency =
            Duration::from_nanos(now.duration_since(admission.certificate.issued_at));
        let mut state = self.state.lock();
        state.enforce_capability(
            cx,
            match &publish_capability {
                FabricCapability::Publish { subject } => subject,
                _ => unreachable!("certified request constructs publish capability"),
            },
            delivery_class,
            &publish_capability,
        )?;
        state.enforce_capability(
            cx,
            match &subscribe_capability {
                FabricCapability::Subscribe { subject } => subject,
                _ => unreachable!("certified request constructs subscribe capability"),
            },
            delivery_class,
            &subscribe_capability,
        )?;
        let prepared_publish =
            state.prepare_publish_message(cx, &subject, payload.clone(), delivery_class)?;
        if let Some(cell_id) = state.primary_cell_id_for_routed_keys(&prepared_publish.routed_cells)
        {
            let decision = FabricDeliveryClassEscalation::new(
                cell_id,
                subject.as_str(),
                delivery_class,
                DeliveryClass::ObligationBacked,
            )
            .evaluate();
            state.push_decision(cx, decision);
        }
        let mut obligation = ServiceObligation::allocate(
            ledger,
            admission.certificate.request_id.clone(),
            admission.certificate.caller.clone(),
            callee.clone(),
            admission.certificate.subject.clone(),
            delivery_class,
            cx.task_id(),
            cx.region_id(),
            now,
            admission.validated.timeout,
        )
        .map_err(|error| fabric_input_error(error.to_string()))?;

        let commit = obligation
            .commit_with_reply(
                ledger,
                now,
                payload.clone(),
                delivery_boundary,
                receipt_required,
            )
            .map_err(|error| fabric_input_error(error.to_string()))?;
        let reply_certificate =
            ReplyCertificate::from_commit(&commit, callee, now, service_latency);
        debug_assert!(reply_certificate.validate().is_ok());

        let delivery_receipt = commit.reply_obligation.map(|reply_obligation| {
            let receipt = reply_obligation.commit_delivery(ledger, now);
            FabricReplyDelivery {
                obligation_id: receipt.obligation_id,
                delivery_boundary: receipt.delivery_boundary,
                receipt_required: receipt.receipt_required,
            }
        });

        state.apply_prepared_publish(cx, prepared_publish);
        drop(state);

        Ok(FabricCertifiedReply {
            reply: FabricReply {
                subject,
                payload,
                ack_kind: delivery_boundary,
                delivery_class,
            },
            request_certificate: admission.certificate.clone(),
            reply_certificate,
            delivery_receipt,
        })
    }

    /// Opt into a stream declaration with explicit configuration.
    #[allow(clippy::unused_async)]
    pub async fn stream(
        &self,
        cx: &Cx,
        config: FabricStreamConfig,
    ) -> Result<FabricStreamHandle, AsupersyncError> {
        fabric_checkpoint(cx, "stream")?;
        config.validate()?;
        {
            let mut state = self.state.lock();
            for subject in &config.subjects {
                let requested_capability = FabricCapability::CreateStream {
                    subject: subject.clone(),
                };
                state.enforce_capability(
                    cx,
                    subject,
                    config.delivery_class,
                    &requested_capability,
                )?;
            }
        }

        Ok(FabricStreamHandle {
            endpoint: self.endpoint.clone(),
            config,
        })
    }

    /// Return a snapshot of the recorded FABRIC decision audits for this
    /// endpoint.
    #[must_use]
    pub fn decision_records(&self) -> Vec<FabricDecisionRecord> {
        self.state.lock().decision_records.clone()
    }

    /// Render the recorded FABRIC decision audits into an explain-plan payload.
    #[must_use]
    pub fn render_explain_plan(&self) -> ExplainPlan {
        let records = self.decision_records();
        let mut plan = ExplainPlan {
            summary: format!(
                "Rendered {} FABRIC decision record(s) for endpoint `{}`",
                records.len(),
                self.endpoint
            ),
            aggregate_cost: CostVector::default(),
            breakdown: Vec::new(),
            important_decisions: Vec::new(),
        };

        for record in &records {
            record.record_into_plan(&mut plan);
        }

        plan
    }
}

/// Compact identifier for a subject cell.
///
/// `CellId` is deterministic for a given canonical subject partition and
/// membership epoch so replay and placement evidence stay stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellId(u128);

impl CellId {
    /// Derive a stable cell id for the given subject partition and epoch.
    #[must_use]
    pub fn for_partition(epoch: CellEpoch, subject_partition: &SubjectPattern) -> Self {
        let canonical = subject_partition.canonical_key();
        let lower = stable_hash((
            "subject-cell",
            epoch.membership_epoch,
            epoch.generation,
            &canonical,
        ));
        let upper = stable_hash((
            "subject-cell:v2",
            epoch.membership_epoch,
            epoch.generation,
            &canonical,
        ));
        Self((u128::from(upper) << 64) | u128::from(lower))
    }

    /// Return the raw 128-bit identifier.
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }
}

impl fmt::Display for CellId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cell-{:032x}", self.0)
    }
}

/// Membership epoch and local generation for a subject cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellEpoch {
    /// Cluster or roster epoch used for placement.
    pub membership_epoch: u64,
    /// Per-cell generation inside the membership epoch.
    pub generation: u64,
}

impl CellEpoch {
    /// Create a new cell epoch descriptor.
    #[must_use]
    pub const fn new(membership_epoch: u64, generation: u64) -> Self {
        Self {
            membership_epoch,
            generation,
        }
    }

    /// Advance the per-cell generation while keeping the membership epoch.
    #[must_use]
    pub const fn next_generation(self) -> Self {
        Self {
            membership_epoch: self.membership_epoch,
            generation: self.generation + 1,
        }
    }
}

impl SubjectPattern {
    /// Aggregate ephemeral reply subjects before placement.
    ///
    /// This intentionally collapses reply-space suffix churn so fabric cells do
    /// not explode on per-request inbox identifiers.
    #[must_use]
    pub fn aggregate_reply_space(&self, policy: ReplySpaceCompactionPolicy) -> Self {
        if !policy.enabled
            || !self.is_reply_subject()
            || self.segments().len() <= policy.preserve_segments
        {
            return self.clone();
        }

        let keep = policy.preserve_segments.max(1).min(self.segments().len());
        let mut segments = self.segments()[..keep].to_vec();
        if !matches!(segments.last(), Some(SubjectToken::Tail)) {
            segments.push(SubjectToken::Tail);
        }
        Self::from_tokens(segments).expect("reply-space compaction must produce a valid pattern")
    }

    /// Validate that the provided set of patterns is pairwise non-overlapping.
    #[allow(clippy::result_large_err)]
    pub fn validate_non_overlapping(patterns: &[Self]) -> Result<(), FabricError> {
        for (index, left) in patterns.iter().enumerate() {
            for right in patterns.iter().skip(index + 1) {
                if left.overlaps(right) {
                    return Err(FabricError::OverlappingSubjectPartitions {
                        left: left.clone(),
                        right: right.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn is_reply_subject(&self) -> bool {
        matches!(
            self.segments().first(),
            Some(SubjectToken::Literal(prefix))
                if prefix == "_INBOX" || prefix == "_RPLY" || prefix == "reply"
        )
    }

    fn literal_segments(&self) -> Result<Vec<String>, SubjectPatternError> {
        self.segments()
            .iter()
            .map(|segment| match segment {
                SubjectToken::Literal(value) => Ok(value.clone()),
                SubjectToken::One | SubjectToken::Tail => Err(
                    SubjectPatternError::LiteralOnlyPatternRequired(self.canonical_key()),
                ),
            })
            .collect()
    }
}

/// Reply-space compaction settings applied before placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplySpaceCompactionPolicy {
    /// Whether reply-space aggregation is enabled.
    pub enabled: bool,
    /// Number of leading segments to keep before collapsing the suffix.
    pub preserve_segments: usize,
}

impl Default for ReplySpaceCompactionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            preserve_segments: 3,
        }
    }
}

/// Deterministic literal-prefix rewrite applied before placement.
///
/// This models the "import/export morphism" stage from the fabric plan without
/// allowing wildcard-bearing rewrites that would re-introduce ambiguity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectPrefixMorphism {
    from: Vec<String>,
    to: Vec<String>,
}

impl SubjectPrefixMorphism {
    /// Create a new literal-prefix rewrite.
    pub fn new(from: &str, to: &str) -> Result<Self, SubjectPatternError> {
        let from = SubjectPattern::parse(from)?;
        let to = SubjectPattern::parse(to)?;

        Ok(Self {
            from: from.literal_segments()?,
            to: to.literal_segments()?,
        })
    }

    fn apply(&self, pattern: &SubjectPattern) -> Option<SubjectPattern> {
        if pattern.segments().len() < self.from.len() {
            return None;
        }

        let mut remainder = Vec::new();
        for (index, segment) in pattern.segments().iter().enumerate() {
            let Some(expected) = self.from.get(index) else {
                remainder.push(segment.clone());
                continue;
            };

            match segment {
                SubjectToken::Literal(value) if value == expected => {}
                _ => return None,
            }
        }

        let mut rewritten = self
            .to
            .iter()
            .cloned()
            .map(SubjectToken::Literal)
            .collect::<Vec<_>>();
        rewritten.extend(remainder);
        Some(
            SubjectPattern::from_tokens(rewritten)
                .expect("rewritten literal-prefix morphism must stay syntactically valid"),
        )
    }
}

/// Canonicalization pipeline that runs before subject-cell placement.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NormalizationPolicy {
    /// Ordered literal-prefix rewrites that canonicalize alias subject spaces.
    pub morphisms: Vec<SubjectPrefixMorphism>,
    /// Reply-space aggregation policy applied after morphisms.
    pub reply_space_policy: ReplySpaceCompactionPolicy,
}

impl NormalizationPolicy {
    /// Produce the authoritative canonical subject partition used for placement.
    #[allow(clippy::result_large_err)]
    pub fn normalize(&self, pattern: &SubjectPattern) -> Result<SubjectPattern, FabricError> {
        let mut canonical = pattern.clone();
        let mut seen = BTreeSet::from([canonical.canonical_key()]);
        let mut index = 0;

        while index < self.morphisms.len() {
            let Some(candidate) = self.morphisms[index].apply(&canonical) else {
                index += 1;
                continue;
            };

            for other in self.morphisms.iter().skip(index + 1) {
                let Some(other_candidate) = other.apply(&canonical) else {
                    continue;
                };
                if candidate != other_candidate {
                    return Err(FabricError::ConflictingSubjectMorphisms {
                        subject: pattern.clone(),
                        left: candidate,
                        right: other_candidate,
                    });
                }
            }

            if candidate == canonical {
                index += 1;
                continue;
            }

            if !seen.insert(candidate.canonical_key()) {
                return Err(FabricError::CyclicSubjectMorphisms {
                    subject: pattern.clone(),
                    cycle_point: candidate,
                });
            }

            canonical = candidate;
            index = 0;
        }

        Ok(canonical.aggregate_reply_space(self.reply_space_policy))
    }

    /// Produce a deterministic, deduplicated, non-overlapping canonical
    /// partition set for placement.
    #[allow(clippy::result_large_err)]
    pub fn canonicalize_partitions(
        &self,
        patterns: &[SubjectPattern],
    ) -> Result<Vec<SubjectPattern>, FabricError> {
        let mut canonical_by_key = BTreeMap::new();

        for pattern in patterns {
            let canonical = self.normalize(pattern)?;
            canonical_by_key
                .entry(canonical.canonical_key())
                .or_insert(canonical);
        }

        let canonical_partitions = canonical_by_key.into_values().collect::<Vec<_>>();
        SubjectPattern::validate_non_overlapping(&canonical_partitions)?;
        Ok(canonical_partitions)
    }
}

/// Coarse cell traffic temperature used to scale stewardship.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellTemperature {
    /// Minimal steward footprint for cold partitions.
    Cold,
    /// Intermediate steward footprint.
    Warm,
    /// Wider steward set for hot partitions.
    Hot,
}

/// Observed load signal used to steer temperature transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedCellLoad {
    /// Approximate publish arrival rate for the cell.
    pub publishes_per_second: u64,
}

impl ObservedCellLoad {
    /// Create a simple load sample from a publish rate estimate.
    #[must_use]
    pub const fn new(publishes_per_second: u64) -> Self {
        Self {
            publishes_per_second,
        }
    }
}

const fn cell_temperature_rank(temperature: CellTemperature) -> u8 {
    match temperature {
        CellTemperature::Cold => 0,
        CellTemperature::Warm => 1,
        CellTemperature::Hot => 2,
    }
}

/// Hysteresis thresholds that damp steward-set temperature changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThermalHysteresis {
    /// Promote cold cells to warm once this rate is reached.
    pub cold_to_warm_publishes_per_second: u64,
    /// Demote warm cells back to cold only once load falls below this rate.
    pub warm_to_cold_publishes_per_second: u64,
    /// Promote warm cells to hot once this rate is reached.
    pub warm_to_hot_publishes_per_second: u64,
    /// Demote hot cells back to warm only once load falls below this rate.
    pub hot_to_warm_publishes_per_second: u64,
}

impl Default for ThermalHysteresis {
    fn default() -> Self {
        Self {
            cold_to_warm_publishes_per_second: 128,
            warm_to_cold_publishes_per_second: 48,
            warm_to_hot_publishes_per_second: 1_024,
            hot_to_warm_publishes_per_second: 512,
        }
    }
}

/// Explicit budget limiting how aggressively a steward set may change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RebalanceBudget {
    /// Maximum node additions/removals allowed in a single rebalance step.
    pub max_steward_changes: usize,
}

impl Default for RebalanceBudget {
    fn default() -> Self {
        Self {
            max_steward_changes: 2,
        }
    }
}

/// Deterministic strategy used to pack low-rate cells onto shared control
/// shards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedShardPackingStrategy {
    /// Use a stable hash of the canonical partition to derive shard id and slot.
    StableHashBucket,
}

/// Explicit limits for when a cell may share control-plane storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CardinalityPolicy {
    /// Maximum number of logical cells packed onto one shared control shard.
    pub max_cells_per_shared_shard: usize,
    /// Minimum publish rate that upgrades a cell to a dedicated control shard.
    pub dedicated_shard_min_publishes_per_second: u64,
    /// Deterministic packing strategy applied to shared-shard assignment.
    pub packing_strategy: SharedShardPackingStrategy,
}

impl Default for CardinalityPolicy {
    fn default() -> Self {
        Self {
            max_cells_per_shared_shard: 8,
            dedicated_shard_min_publishes_per_second: 1_024,
            packing_strategy: SharedShardPackingStrategy::StableHashBucket,
        }
    }
}

impl CardinalityPolicy {
    #[allow(clippy::result_large_err)]
    fn validate(self) -> Result<(), FabricError> {
        if self.max_cells_per_shared_shard == 0 {
            return Err(FabricError::InvalidSharedShardCardinalityLimit);
        }
        Ok(())
    }

    #[must_use]
    fn wants_dedicated_shard(
        self,
        temperature: CellTemperature,
        observed_load: ObservedCellLoad,
    ) -> bool {
        matches!(temperature, CellTemperature::Hot)
            || observed_load.publishes_per_second >= self.dedicated_shard_min_publishes_per_second
    }

    #[allow(clippy::result_large_err)]
    fn assign_shared_shard(
        self,
        canonical_partition: &SubjectPattern,
    ) -> Result<SharedControlShard, FabricError> {
        self.validate()?;

        match self.packing_strategy {
            SharedShardPackingStrategy::StableHashBucket => {
                let limit = u64::try_from(self.max_cells_per_shared_shard)
                    .expect("shared shard cardinality limit must fit into u64");
                let fingerprint =
                    stable_hash(("shared-control-shard", canonical_partition.canonical_key()));
                let shard_bucket = fingerprint / limit;
                let slot_index = usize::try_from(fingerprint % limit)
                    .expect("slot index derived from cardinality limit must fit usize");
                Ok(SharedControlShard {
                    shard_id: format!("shared-control-shard-{shard_bucket:016x}"),
                    slot_index,
                    cardinality_limit: self.max_cells_per_shared_shard,
                })
            }
        }
    }
}

/// Incremental steward-set transition plan under hysteresis and budget limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalancePlan {
    /// Temperature recommended after applying hysteresis to the observed load.
    pub next_temperature: CellTemperature,
    /// Steward set after applying the rebalance budget to the desired target.
    pub next_stewards: Vec<NodeId>,
    /// Newly added stewards in this incremental rebalance step.
    pub added_stewards: Vec<NodeId>,
    /// Stewards removed in this incremental rebalance step.
    pub removed_stewards: Vec<NodeId>,
}

/// Repair-material binding captured for one steward or repair witness while a
/// rebalance cut is being certified.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepairSymbolBinding {
    /// Repair-capable node that collected the material.
    pub node_id: NodeId,
    /// Cell epoch the material belongs to.
    pub cell_epoch: CellEpoch,
    /// Retention generation the symbols were derived from.
    pub retention_generation: u64,
}

impl RepairSymbolBinding {
    /// Construct a repair-symbol binding for one repair-capable node.
    #[must_use]
    pub const fn new(node_id: NodeId, cell_epoch: CellEpoch, retention_generation: u64) -> Self {
        Self {
            node_id,
            cell_epoch,
            retention_generation,
        }
    }
}

/// Explicit transfer summary that proves a rebalance cut does not strand live
/// publish, consumer, or reply obligations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalanceObligationSummary {
    /// Number of unresolved publish obligations below the cut frontier.
    pub publish_obligations_below_cut: usize,
    /// Number of active consumer leases that must move or be reissued.
    pub active_consumer_leases: usize,
    /// Number of consumer leases explicitly transferred or reissued.
    pub transferred_consumer_leases: usize,
    /// Number of consumers still reporting ambiguous lease ownership.
    pub ambiguous_consumer_lease_owners: usize,
    /// Number of active reply rights at the cut frontier.
    pub active_reply_rights: usize,
    /// Number of reply rights explicitly reissued onto the next epoch.
    pub reissued_reply_rights: usize,
    /// Number of dangling reply rights that would become ownerless.
    pub dangling_reply_rights: usize,
}

/// Semantic-cut evidence attached to a steward-set rebalance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebalanceCutEvidence {
    /// Steward that will hold append and cursor authority after the cut.
    pub next_sequencer: NodeId,
    /// Retention generation against which repair material was captured.
    pub retention_generation: u64,
    /// Explicit obligation-transfer proof attached to the cut.
    pub obligation_summary: RebalanceObligationSummary,
    /// Repair symbol bindings collected by next stewards and witnesses.
    pub repair_symbols: Vec<RepairSymbolBinding>,
}

/// Certified outcome of a steward-set self-rebalance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertifiedRebalance {
    /// Authoritative append proving the cut was decided under the prior epoch.
    pub control_append: AppendCertificate,
    /// In-band joint configuration entry fencing the old steward lease.
    pub joint_config: JointConfigEntry,
    /// Incremental rebalance plan that was certified.
    pub plan: RebalancePlan,
    /// Canonical semantic-cut evidence attached to the certification.
    pub cut_evidence: RebalanceCutEvidence,
    /// Removed stewards whose old authority must now drain.
    pub drained_stewards: Vec<NodeId>,
    /// Resulting subject cell after the certified cut and epoch advance.
    pub resulting_cell: SubjectCell,
}

/// Storage class used during steward negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StorageClass {
    /// Ephemeral memory-only participation.
    Ephemeral,
    /// General durable node.
    Standard,
    /// Durable or archival-capable node.
    Durable,
}

/// Health tier used during steward negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StewardHealth {
    /// Fully eligible and healthy.
    Healthy,
    /// Eligible but less preferred.
    Degraded,
    /// Draining; still visible but last resort.
    Draining,
    /// Not eligible for stewardship.
    Unavailable,
}

/// Logical role a node may play inside the subject fabric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeRole {
    /// Publisher or request originator for a subject flow.
    Origin,
    /// Passive subscriber consuming pushed messages.
    Subscriber,
    /// Stateful consumer with explicit cursor or delivery ownership.
    Consumer,
    /// Node eligible to steward the control and data capsules of a cell.
    Steward,
    /// Node eligible to store repair symbols outside the active steward quorum.
    RepairWitness,
    /// Node allowed to relay traffic across topology boundaries.
    Bridge,
}

/// Candidate node used during steward placement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StewardCandidate {
    /// Stable identity of the candidate node.
    pub node_id: NodeId,
    /// Logical roles currently available on the node.
    pub roles: BTreeSet<NodeRole>,
    /// Current health state used during placement scoring.
    pub health: StewardHealth,
    /// Durability tier offered by the node.
    pub storage_class: StorageClass,
    /// Failure-domain label used to diversify steward placement.
    pub failure_domain: String,
    /// Measured or budgeted one-way latency envelope in milliseconds.
    pub latency_millis: u32,
}

impl StewardCandidate {
    /// Create a new candidate with conservative defaults.
    #[must_use]
    pub fn new(node_id: NodeId, failure_domain: impl Into<String>) -> Self {
        Self {
            node_id,
            roles: BTreeSet::new(),
            health: StewardHealth::Healthy,
            storage_class: StorageClass::Standard,
            failure_domain: failure_domain.into(),
            latency_millis: 10,
        }
    }

    /// Mark the candidate with an additional role.
    #[must_use]
    pub fn with_role(mut self, role: NodeRole) -> Self {
        self.roles.insert(role);
        self
    }

    /// Override the candidate health.
    #[must_use]
    pub fn with_health(mut self, health: StewardHealth) -> Self {
        self.health = health;
        self
    }

    /// Override the storage class.
    #[must_use]
    pub fn with_storage_class(mut self, storage_class: StorageClass) -> Self {
        self.storage_class = storage_class;
        self
    }

    /// Override the measured latency envelope.
    #[must_use]
    pub fn with_latency_millis(mut self, latency_millis: u32) -> Self {
        self.latency_millis = latency_millis;
        self
    }

    /// Return true when the node is currently eligible to act as a steward.
    #[must_use]
    pub fn is_steward_eligible(&self) -> bool {
        self.roles.contains(&NodeRole::Steward) && self.health != StewardHealth::Unavailable
    }

    /// Return true when the node can also act as a repair witness.
    #[must_use]
    pub fn can_repair(&self) -> bool {
        self.roles.contains(&NodeRole::RepairWitness) || self.is_steward_eligible()
    }
}

/// Foundational placement policy for a `SubjectCell`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementPolicy {
    /// Virtual node count used by the deterministic hash ring.
    pub vnodes_per_node: usize,
    /// Number of candidate nodes to consider before final negotiation.
    pub candidate_pool_size: usize,
    /// Target steward count for cold cells.
    pub cold_stewards: usize,
    /// Target steward count for warm cells.
    pub warm_stewards: usize,
    /// Target steward count for hot cells.
    pub hot_stewards: usize,
    /// Soft latency cap for preferred candidates.
    pub max_latency_millis: u32,
    /// Load thresholds used to damp temperature transitions.
    pub thermal_hysteresis: ThermalHysteresis,
    /// Budget limiting how many steward moves one rebalance may perform.
    pub rebalance_budget: RebalanceBudget,
    /// Canonicalization rules applied before consistent hashing.
    pub normalization: NormalizationPolicy,
    /// Control-shard packing policy for low-rate cells.
    pub cardinality_policy: CardinalityPolicy,
}

impl Default for PlacementPolicy {
    fn default() -> Self {
        Self {
            vnodes_per_node: 64,
            candidate_pool_size: 6,
            cold_stewards: 1,
            warm_stewards: 3,
            hot_stewards: 5,
            max_latency_millis: 150,
            thermal_hysteresis: ThermalHysteresis::default(),
            rebalance_budget: RebalanceBudget::default(),
            normalization: NormalizationPolicy::default(),
            cardinality_policy: CardinalityPolicy::default(),
        }
    }
}

impl PlacementPolicy {
    /// Recommend the next cell temperature from the current load sample.
    #[must_use]
    pub fn recommend_temperature(
        &self,
        current: CellTemperature,
        observed_load: ObservedCellLoad,
    ) -> CellTemperature {
        let rate = observed_load.publishes_per_second;

        match current {
            CellTemperature::Cold => {
                if rate >= self.thermal_hysteresis.warm_to_hot_publishes_per_second {
                    CellTemperature::Hot
                } else if rate >= self.thermal_hysteresis.cold_to_warm_publishes_per_second {
                    CellTemperature::Warm
                } else {
                    CellTemperature::Cold
                }
            }
            CellTemperature::Warm => {
                if rate >= self.thermal_hysteresis.warm_to_hot_publishes_per_second {
                    CellTemperature::Hot
                } else if rate <= self.thermal_hysteresis.warm_to_cold_publishes_per_second {
                    CellTemperature::Cold
                } else {
                    CellTemperature::Warm
                }
            }
            CellTemperature::Hot => {
                if rate <= self.thermal_hysteresis.hot_to_warm_publishes_per_second {
                    CellTemperature::Warm
                } else {
                    CellTemperature::Hot
                }
            }
        }
    }

    fn target_steward_count(&self, temperature: CellTemperature) -> usize {
        match temperature {
            CellTemperature::Cold => self.cold_stewards,
            CellTemperature::Warm => self.warm_stewards,
            CellTemperature::Hot => self.hot_stewards,
        }
    }

    /// Plan an incremental steward-set transition subject to the rebalance budget.
    #[allow(clippy::result_large_err)]
    pub fn plan_rebalance(
        &self,
        subject_partition: &SubjectPattern,
        candidates: &[StewardCandidate],
        current_stewards: &[NodeId],
        current_temperature: CellTemperature,
        observed_load: ObservedCellLoad,
    ) -> Result<RebalancePlan, FabricError> {
        let next_temperature = self.recommend_temperature(current_temperature, observed_load);
        let canonical_partition = self.normalization.normalize(subject_partition)?;
        let desired_stewards =
            self.select_stewards(&canonical_partition, candidates, next_temperature)?;
        let next_stewards = self.advance_toward_desired(
            current_stewards,
            &desired_stewards,
            self.target_steward_count(next_temperature),
        );

        let added_stewards = next_stewards
            .iter()
            .filter(|node| !contains_node(current_stewards, node))
            .cloned()
            .collect();
        let removed_stewards = current_stewards
            .iter()
            .filter(|node| !contains_node(&next_stewards, node))
            .cloned()
            .collect();

        Ok(RebalancePlan {
            next_temperature,
            next_stewards,
            added_stewards,
            removed_stewards,
        })
    }

    #[allow(clippy::result_large_err)]
    fn candidate_pool<'a>(
        &self,
        subject_partition: &SubjectPattern,
        candidates: &'a [StewardCandidate],
        temperature: CellTemperature,
    ) -> Result<Vec<&'a StewardCandidate>, FabricError> {
        let eligible: Vec<&StewardCandidate> = candidates
            .iter()
            .filter(|candidate| candidate.is_steward_eligible())
            .collect();
        if eligible.is_empty() {
            return Err(FabricError::NoStewardCandidates {
                partition: subject_partition.clone(),
            });
        }

        let required = self
            .candidate_pool_size
            .max(self.target_steward_count(temperature))
            .min(eligible.len());

        let mut ring = HashRing::new(self.vnodes_per_node.max(1));
        let mut by_node = BTreeMap::new();
        for candidate in &eligible {
            let key = candidate.node_id.as_str().to_string();
            ring.add_node(key.clone());
            by_node.insert(key, *candidate);
        }

        let subject_key = subject_partition.canonical_key();
        let mut pool = Vec::new();
        let mut seen = BTreeSet::new();
        for salt in 0_u64.. {
            if pool.len() >= required || seen.len() >= eligible.len() {
                break;
            }
            let lookup = (&subject_key, salt);
            let Some(node_id) = ring.node_for_key(&lookup) else {
                break;
            };
            if !seen.insert(node_id.to_string()) {
                continue;
            }
            if let Some(candidate) = by_node.get(node_id) {
                pool.push(*candidate);
            }
        }

        Ok(pool)
    }

    #[allow(clippy::result_large_err)]
    fn select_stewards(
        &self,
        subject_partition: &SubjectPattern,
        candidates: &[StewardCandidate],
        temperature: CellTemperature,
    ) -> Result<Vec<NodeId>, FabricError> {
        let pool = self.candidate_pool(subject_partition, candidates, temperature)?;
        let target = self.target_steward_count(temperature).min(pool.len());
        if target == 0 {
            return Err(FabricError::NoStewardCandidates {
                partition: subject_partition.clone(),
            });
        }

        let mut preferred: Vec<&StewardCandidate> = pool
            .iter()
            .copied()
            .filter(|candidate| candidate.latency_millis <= self.max_latency_millis)
            .collect();
        let mut fallback: Vec<&StewardCandidate> = pool
            .iter()
            .copied()
            .filter(|candidate| candidate.latency_millis > self.max_latency_millis)
            .collect();

        preferred.sort_by(|left, right| compare_candidates(left, right, temperature));
        fallback.sort_by(|left, right| compare_candidates(left, right, temperature));
        preferred.extend(fallback);

        let mut selected = Vec::with_capacity(target);
        let mut selected_ids = BTreeSet::new();
        let mut used_domains = BTreeSet::new();

        for candidate in &preferred {
            if selected.len() >= target {
                break;
            }
            if !used_domains.insert(candidate.failure_domain.clone()) {
                continue;
            }
            selected_ids.insert(candidate.node_id.as_str().to_string());
            selected.push(candidate.node_id.clone());
        }

        for candidate in preferred {
            if selected.len() >= target {
                break;
            }
            if !selected_ids.insert(candidate.node_id.as_str().to_string()) {
                continue;
            }
            selected.push(candidate.node_id.clone());
        }

        Ok(selected)
    }

    fn advance_toward_desired(
        &self,
        current_stewards: &[NodeId],
        desired_stewards: &[NodeId],
        target_len: usize,
    ) -> Vec<NodeId> {
        let desired_ids = desired_stewards
            .iter()
            .map(NodeId::as_str)
            .collect::<BTreeSet<_>>();
        let mut remaining_budget = self.rebalance_budget.max_steward_changes;
        let mut next = current_stewards.to_vec();

        while next.len() > target_len && remaining_budget > 0 {
            let remove_index = next
                .iter()
                .rposition(|node| !desired_ids.contains(node.as_str()))
                .unwrap_or_else(|| next.len().saturating_sub(1));
            next.remove(remove_index);
            remaining_budget = remaining_budget.saturating_sub(1);
        }

        for desired in desired_stewards {
            if contains_node(&next, desired) {
                continue;
            }

            if next.len() < target_len {
                if remaining_budget == 0 {
                    break;
                }
                next.push(desired.clone());
                remaining_budget = remaining_budget.saturating_sub(1);
                continue;
            }

            let Some(remove_index) = next
                .iter()
                .rposition(|node| !desired_ids.contains(node.as_str()))
            else {
                continue;
            };
            if remaining_budget < 2 {
                break;
            }
            next.remove(remove_index);
            remaining_budget = remaining_budget.saturating_sub(1);
            next.push(desired.clone());
            remaining_budget = remaining_budget.saturating_sub(1);
        }

        next
    }

    #[allow(clippy::result_large_err)]
    fn control_shard_assignment_for_canonical(
        &self,
        canonical_partition: &SubjectPattern,
        temperature: CellTemperature,
        observed_load: ObservedCellLoad,
    ) -> Result<Option<SharedControlShard>, FabricError> {
        self.cardinality_policy.validate()?;
        if self
            .cardinality_policy
            .wants_dedicated_shard(temperature, observed_load)
        {
            return Ok(None);
        }
        self.cardinality_policy
            .assign_shared_shard(canonical_partition)
            .map(Some)
    }
}

/// Control-plane epoch fenced into brokerless control artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlEpoch {
    /// Placement epoch used for the current subject cell.
    pub cell_epoch: CellEpoch,
    /// Monotonic control-plane revision inside the cell epoch.
    pub policy_revision: u64,
}

impl ControlEpoch {
    /// Construct the current control epoch for a subject cell.
    #[must_use]
    pub const fn new(cell_epoch: CellEpoch, policy_revision: u64) -> Self {
        Self {
            cell_epoch,
            policy_revision,
        }
    }

    #[must_use]
    const fn bump_policy(self) -> Self {
        Self {
            cell_epoch: self.cell_epoch,
            policy_revision: self.policy_revision + 1,
        }
    }
}

/// Lease proving that one steward currently owns authoritative append rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencerLease {
    /// Steward currently allowed to append control-log decisions.
    pub holder: NodeId,
    /// Control epoch for which the lease is valid.
    pub control_epoch: ControlEpoch,
    /// Fence generation invalidating older authority artifacts.
    pub fence_generation: u64,
}

/// Unique identity of one authoritative append in the control log.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlAppendIdentity {
    /// Subject cell that owns the append.
    pub cell_id: CellId,
    /// Cell epoch the append belongs to.
    pub epoch: CellEpoch,
    /// Monotonic sequence number inside the epoch.
    pub sequence: u64,
}

/// Commit proof emitted for one authoritative control-log append.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendCertificate {
    /// Unique identity of the committed append.
    pub identity: ControlAppendIdentity,
    /// Steward that held append authority for the decision.
    pub sequencer: NodeId,
    /// Control epoch for the append.
    pub control_epoch: ControlEpoch,
    /// Fence generation under which the append was committed.
    pub fence_generation: u64,
}

/// Joint-consensus reconfiguration entry kept in-band with the control log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JointConfigEntry {
    /// Control epoch after the reconfiguration decision.
    pub control_epoch: ControlEpoch,
    /// Prior steward set that still overlaps the new decision set.
    pub old_stewards: Vec<NodeId>,
    /// New steward set activated by the decision.
    pub new_stewards: Vec<NodeId>,
    /// Sequencer installed for the next decision window.
    pub next_sequencer: NodeId,
    /// Fence generation that invalidates older authority artifacts.
    pub fence_generation: u64,
}

/// Fence artifact proving that a prior sequencer lease is stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceToken {
    /// Control epoch for the fencing decision.
    pub control_epoch: ControlEpoch,
    /// Sequencer that just lost authority.
    pub previous_holder: NodeId,
    /// Sequencer that now owns authority.
    pub next_holder: NodeId,
    /// Fence generation that invalidates the previous lease.
    pub fence_generation: u64,
}

/// Fenced lease for consumer-control authority within a subject cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorAuthorityLease {
    /// Holder currently allowed to issue cursor-control decisions.
    pub holder: NodeId,
    /// Control epoch for which the lease is valid.
    pub control_epoch: ControlEpoch,
    /// Fence generation invalidating older cursor-authority leases.
    pub fence_generation: u64,
}

/// Shared control shard assignment for cold or low-rate cells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedControlShard {
    /// Shared shard identity carrying the packed control stream.
    pub shard_id: String,
    /// Slot occupied by this cell within the shard.
    pub slot_index: usize,
    /// Maximum number of cells admitted to the shard.
    pub cardinality_limit: usize,
}

/// Deterministic outcome when a replica or late delivery response presents an
/// append certificate to the control capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicatedAppendOutcome {
    /// The append was newly committed.
    Committed(AppendCertificate),
    /// The append was already committed with the same identity and certificate.
    IdempotentNoop(AppendCertificate),
    /// The append belongs to a fenced control generation and must be rejected.
    StaleReject {
        /// Identity of the rejected append.
        identity: ControlAppendIdentity,
        /// Fence generation carried by the rejected append.
        attempted_fence_generation: u64,
        /// Current fence generation of the capsule.
        current_fence_generation: u64,
    },
}

/// Validation failure while mutating the bounded control capsule.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ControlCapsuleError {
    /// Authoritative appends require an active sequencer lease.
    #[error("control capsule has no active sequencer lease")]
    NoActiveSequencer,
    /// Cursor-control decisions require an active cursor-authority lease.
    #[error("control capsule has no active cursor-authority lease")]
    NoCursorAuthority,
    /// The requested steward is not part of the active steward pool.
    #[error("node `{node}` is not part of the active steward pool")]
    UnknownSteward {
        /// Node that failed membership validation.
        node: NodeId,
    },
    /// A stale sequencer lease attempted to emit a control-log append.
    #[error(
        "sequencer lease for `{holder}` at fence generation {fence_generation} is stale (current holder `{current_holder}`, current fence generation {current_fence_generation})"
    )]
    StaleSequencerLease {
        /// Holder that attempted the stale append.
        holder: NodeId,
        /// Fence generation carried by the stale lease.
        fence_generation: u64,
        /// Holder of the current live lease.
        current_holder: NodeId,
        /// Capsule fence generation after the latest authoritative change.
        current_fence_generation: u64,
    },
    /// A stale cursor-authority lease attempted a control decision.
    #[error(
        "cursor authority lease for `{holder}` at fence generation {fence_generation} is stale (current holder `{current_holder}`, current fence generation {current_fence_generation})"
    )]
    StaleCursorAuthorityLease {
        /// Holder that attempted the stale decision.
        holder: NodeId,
        /// Fence generation carried by the stale cursor lease.
        fence_generation: u64,
        /// Holder of the current live cursor-authority lease.
        current_holder: NodeId,
        /// Capsule fence generation after the latest authoritative change.
        current_fence_generation: u64,
    },
    /// Two different append certificates tried to claim the same append
    /// identity.
    #[error("append identity `{identity:?}` is already committed with different contents")]
    ConflictingAppendIdentity {
        /// Identity that collided with an existing committed append.
        identity: ControlAppendIdentity,
    },
    /// Replicated append certificates must belong to the current cell.
    #[error(
        "append identity `{identity:?}` belongs to cell `{actual}`, but this capsule owns `{expected}`"
    )]
    WrongCell {
        /// Identity that failed validation.
        identity: ControlAppendIdentity,
        /// Cell owned by this capsule.
        expected: CellId,
        /// Cell carried by the replicated certificate.
        actual: CellId,
    },
    /// Replicated append certificates must belong to the current cell epoch.
    #[error(
        "append identity `{identity:?}` belongs to epoch `{actual:?}`, but this capsule is on `{expected:?}`"
    )]
    WrongEpoch {
        /// Identity that failed validation.
        identity: ControlAppendIdentity,
        /// Cell epoch owned by this capsule.
        expected: CellEpoch,
        /// Cell epoch carried by the replicated certificate.
        actual: CellEpoch,
    },
    /// Joint consensus requires an overlap set between old and new stewards.
    #[error("joint configuration must retain at least one steward across the transition")]
    JointConfigRequiresOverlap,
    /// Joint consensus steward sets must contain distinct members.
    #[error("joint configuration contains duplicate steward `{node}`")]
    DuplicateSteward {
        /// Duplicate steward discovered in the proposed steward set.
        node: NodeId,
    },
    /// Shared control shards must admit at least one slot.
    #[error("shared control shard cardinality limit must be at least 1")]
    InvalidSharedShardLimit,
    /// Slot indexes outside the shard cardinality bound are invalid.
    #[error(
        "shared control shard `{shard_id}` slot {slot_index} exceeds cardinality limit {cardinality_limit}"
    )]
    SharedShardOverCapacity {
        /// Shared shard identity.
        shard_id: String,
        /// Slot requested for the cell.
        slot_index: usize,
        /// Cardinality bound of the shard.
        cardinality_limit: usize,
    },
}

/// Bounded control-plane state owned by a subject cell.
///
/// This is intentionally narrower than a full brokerless control plane: it
/// captures enough explicit artifacts to model fenced sequencing, joint
/// reconfiguration, cursor-authority transfer, and deterministic stale
/// rejection without pretending the entire distributed protocol already exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlCapsuleV1 {
    cell_id: CellId,
    cell_epoch: CellEpoch,
    /// Full steward pool negotiated for the current control epoch.
    pub steward_pool: Vec<NodeId>,
    /// Steward currently holding the append lease, if any.
    pub active_sequencer: Option<NodeId>,
    /// Fence generation invalidating older authority artifacts.
    pub sequencer_lease_generation: u64,
    /// Monotonic revision of the policy snapshot stored in the capsule.
    pub policy_revision: u64,
    /// Holder currently allowed to issue cursor-control decisions.
    pub cursor_authority: Option<CursorAuthorityLease>,
    /// Optional shared control shard assignment for low-rate cells.
    pub shared_control_shard: Option<SharedControlShard>,
    /// History of in-band joint-consensus configuration transitions.
    pub joint_config_history: Vec<JointConfigEntry>,
    committed_appends: BTreeMap<ControlAppendIdentity, AppendCertificate>,
    next_sequence: u64,
}

impl ControlCapsuleV1 {
    fn new(cell_id: CellId, steward_pool: Vec<NodeId>, epoch: CellEpoch) -> Self {
        let policy_revision = 1;
        let active_sequencer = steward_pool.first().cloned();
        let cursor_authority = steward_pool
            .first()
            .cloned()
            .map(|holder| CursorAuthorityLease {
                holder,
                control_epoch: ControlEpoch::new(epoch, policy_revision),
                fence_generation: epoch.generation,
            });

        Self {
            cell_id,
            cell_epoch: epoch,
            steward_pool,
            active_sequencer,
            sequencer_lease_generation: epoch.generation,
            policy_revision,
            cursor_authority,
            shared_control_shard: None,
            joint_config_history: Vec::new(),
            committed_appends: BTreeMap::new(),
            next_sequence: 1,
        }
    }

    /// Return the current sequencer holder, if one exists.
    #[must_use]
    pub fn active_sequencer_holder(&self) -> Option<&NodeId> {
        self.active_sequencer.as_ref()
    }

    /// Return the current bounded control epoch for the cell.
    #[must_use]
    pub const fn control_epoch(&self) -> ControlEpoch {
        ControlEpoch::new(self.cell_epoch, self.policy_revision)
    }

    /// Return the current sequencer lease, if one exists.
    #[must_use]
    pub fn active_sequencer_lease(&self) -> Option<SequencerLease> {
        self.active_sequencer.clone().map(|holder| SequencerLease {
            holder,
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        })
    }

    /// Return the current cursor-authority lease, if one exists.
    #[must_use]
    pub fn cursor_authority_lease(&self) -> Option<&CursorAuthorityLease> {
        self.cursor_authority.as_ref()
    }

    fn advance_control_fence(&mut self) {
        self.sequencer_lease_generation += 1;
        let control_epoch = self.control_epoch();
        if let Some(lease) = &mut self.cursor_authority {
            lease.fence_generation = self.sequencer_lease_generation;
            lease.control_epoch = control_epoch;
        }
    }

    fn install_sequencer(&mut self, holder: NodeId) -> SequencerLease {
        let lease = SequencerLease {
            holder: holder.clone(),
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.active_sequencer = Some(holder);
        lease
    }

    fn install_cursor_authority(&mut self, holder: NodeId) -> CursorAuthorityLease {
        let lease = CursorAuthorityLease {
            holder,
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.cursor_authority = Some(lease.clone());
        lease
    }

    fn rebind_epoch(&mut self, cell_id: CellId, epoch: CellEpoch) {
        self.cell_id = cell_id;
        self.cell_epoch = epoch;
        self.policy_revision = 1;
        self.sequencer_lease_generation = self.sequencer_lease_generation.max(epoch.generation);
        let control_epoch = self.control_epoch();
        if let Some(cursor_authority) = &mut self.cursor_authority {
            cursor_authority.control_epoch = control_epoch;
            cursor_authority.fence_generation = self.sequencer_lease_generation;
        }
        self.committed_appends.clear();
        self.next_sequence = 1;
    }

    fn validate_sequencer_lease(
        &self,
        lease: &SequencerLease,
    ) -> Result<SequencerLease, ControlCapsuleError> {
        let Some(active) = self.active_sequencer_lease() else {
            return Err(ControlCapsuleError::NoActiveSequencer);
        };
        if lease != &active {
            return Err(ControlCapsuleError::StaleSequencerLease {
                holder: lease.holder.clone(),
                fence_generation: lease.fence_generation,
                current_holder: active.holder.clone(),
                current_fence_generation: active.fence_generation,
            });
        }
        Ok(active)
    }

    /// Emit and commit one authoritative append under the active sequencer
    /// lease. The committed certificate is retained so duplicate late delivery
    /// collapses to an idempotent no-op rather than duplicating authority.
    pub fn authoritative_append(
        &mut self,
        lease: &SequencerLease,
    ) -> Result<AppendCertificate, ControlCapsuleError> {
        let active = self.validate_sequencer_lease(lease)?;
        let identity = ControlAppendIdentity {
            cell_id: self.cell_id,
            epoch: self.cell_epoch,
            sequence: self.next_sequence,
        };
        self.next_sequence += 1;

        let certificate = AppendCertificate {
            identity: identity.clone(),
            sequencer: active.holder,
            control_epoch: self.control_epoch(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.committed_appends.insert(identity, certificate.clone());
        Ok(certificate)
    }

    /// Accept a replicated or late append certificate from elsewhere in the
    /// control plane and reduce it to a deterministic committed/no-op/stale
    /// outcome.
    pub fn accept_replicated_append(
        &mut self,
        certificate: AppendCertificate,
    ) -> Result<ReplicatedAppendOutcome, ControlCapsuleError> {
        if certificate.identity.cell_id != self.cell_id {
            return Err(ControlCapsuleError::WrongCell {
                identity: certificate.identity.clone(),
                expected: self.cell_id,
                actual: certificate.identity.cell_id,
            });
        }
        if certificate.identity.epoch != self.cell_epoch {
            return Err(ControlCapsuleError::WrongEpoch {
                identity: certificate.identity.clone(),
                expected: self.cell_epoch,
                actual: certificate.identity.epoch,
            });
        }
        if certificate.fence_generation != self.sequencer_lease_generation {
            return Ok(ReplicatedAppendOutcome::StaleReject {
                identity: certificate.identity,
                attempted_fence_generation: certificate.fence_generation,
                current_fence_generation: self.sequencer_lease_generation,
            });
        }

        if let Some(existing) = self.committed_appends.get(&certificate.identity) {
            if existing == &certificate {
                return Ok(ReplicatedAppendOutcome::IdempotentNoop(existing.clone()));
            }
            return Err(ControlCapsuleError::ConflictingAppendIdentity {
                identity: certificate.identity,
            });
        }

        self.next_sequence = self
            .next_sequence
            .max(certificate.identity.sequence.saturating_add(1));
        self.committed_appends
            .insert(certificate.identity.clone(), certificate.clone());
        Ok(ReplicatedAppendOutcome::Committed(certificate))
    }

    /// Fence the active sequencer and install a new steward lease.
    pub fn fence_sequencer(
        &mut self,
        next_holder: NodeId,
    ) -> Result<FenceToken, ControlCapsuleError> {
        if !contains_node(&self.steward_pool, &next_holder) {
            return Err(ControlCapsuleError::UnknownSteward { node: next_holder });
        }

        let Some(previous_holder) = self.active_sequencer_holder().cloned() else {
            return Err(ControlCapsuleError::NoActiveSequencer);
        };

        self.advance_control_fence();
        let token = FenceToken {
            control_epoch: self.control_epoch(),
            previous_holder,
            next_holder: next_holder.clone(),
            fence_generation: self.sequencer_lease_generation,
        };
        self.install_sequencer(next_holder);
        Ok(token)
    }

    /// Install an in-band joint-consensus transition with overlap between the
    /// old and new stewardship sets and a freshly fenced sequencer lease.
    pub fn reconfigure(
        &mut self,
        new_stewards: Vec<NodeId>,
        next_sequencer: NodeId,
    ) -> Result<JointConfigEntry, ControlCapsuleError> {
        if let Some(node) = duplicate_node(&new_stewards) {
            return Err(ControlCapsuleError::DuplicateSteward { node });
        }
        if !new_stewards
            .iter()
            .any(|candidate| contains_node(&self.steward_pool, candidate))
        {
            return Err(ControlCapsuleError::JointConfigRequiresOverlap);
        }
        if !contains_node(&new_stewards, &next_sequencer) {
            return Err(ControlCapsuleError::UnknownSteward {
                node: next_sequencer,
            });
        }

        let old_stewards = self.steward_pool.clone();
        self.steward_pool.clone_from(&new_stewards);
        self.policy_revision += 1;
        self.advance_control_fence();
        self.install_sequencer(next_sequencer.clone());
        self.install_cursor_authority(next_sequencer.clone());

        let joint = JointConfigEntry {
            control_epoch: self.control_epoch(),
            old_stewards,
            new_stewards,
            next_sequencer,
            fence_generation: self.sequencer_lease_generation,
        };
        self.joint_config_history.push(joint.clone());
        Ok(joint)
    }

    /// Fence and transfer cursor-control authority to a new holder.
    pub fn transfer_cursor_authority(
        &mut self,
        next_holder: NodeId,
    ) -> Result<CursorAuthorityLease, ControlCapsuleError> {
        if !contains_node(&self.steward_pool, &next_holder) {
            return Err(ControlCapsuleError::UnknownSteward { node: next_holder });
        }
        self.advance_control_fence();
        Ok(self.install_cursor_authority(next_holder))
    }

    /// Validate that a caller still holds the current fenced cursor-authority
    /// lease.
    pub fn validate_cursor_authority(
        &self,
        lease: &CursorAuthorityLease,
    ) -> Result<(), ControlCapsuleError> {
        let Some(active) = self.cursor_authority.as_ref() else {
            return Err(ControlCapsuleError::NoCursorAuthority);
        };
        if lease != active {
            return Err(ControlCapsuleError::StaleCursorAuthorityLease {
                holder: lease.holder.clone(),
                fence_generation: lease.fence_generation,
                current_holder: active.holder.clone(),
                current_fence_generation: self.sequencer_lease_generation,
            });
        }
        Ok(())
    }

    /// Pack the cell onto a shared control shard under an explicit cardinality
    /// limit.
    pub fn attach_shared_control_shard(
        &mut self,
        shard_id: impl Into<String>,
        slot_index: usize,
        cardinality_limit: usize,
    ) -> Result<SharedControlShard, ControlCapsuleError> {
        let shard_id = shard_id.into();
        if cardinality_limit == 0 {
            return Err(ControlCapsuleError::InvalidSharedShardLimit);
        }
        if slot_index >= cardinality_limit {
            return Err(ControlCapsuleError::SharedShardOverCapacity {
                shard_id,
                slot_index,
                cardinality_limit,
            });
        }

        let shard = SharedControlShard {
            shard_id,
            slot_index,
            cardinality_limit,
        };
        self.shared_control_shard = Some(shard.clone());
        Ok(shard)
    }
}

/// Minimal data-plane configuration owned by a subject cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataCapsule {
    /// Current traffic temperature of the cell.
    pub temperature: CellTemperature,
    /// Number of recent message blocks retained inline by the cell.
    pub retained_message_blocks: usize,
}

impl Default for DataCapsule {
    fn default() -> Self {
        Self {
            temperature: CellTemperature::Cold,
            retained_message_blocks: 1,
        }
    }
}

impl DataCapsule {
    fn wants_inline_payload(payload_len: usize) -> bool {
        payload_len <= DEFAULT_SYMBOL_SIZE
    }

    fn repair_symbols_per_block(&self, holder_count: usize, steward_count: usize) -> usize {
        let holder_bonus = holder_count.saturating_sub(steward_count).max(1);
        let temperature_bonus = match self.temperature {
            CellTemperature::Cold => 0,
            CellTemperature::Warm => 1,
            CellTemperature::Hot => 2,
        };
        holder_bonus + temperature_bonus
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SegmentWindow {
    start_sequence: u64,
    end_sequence: u64,
}

impl SegmentWindow {
    const fn single(sequence: u64) -> Self {
        Self {
            start_sequence: sequence,
            end_sequence: sequence,
        }
    }

    const fn contains(self, sequence: u64) -> bool {
        self.start_sequence <= sequence && sequence <= self.end_sequence
    }
}

impl fmt::Display for SegmentWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", self.start_sequence, self.end_sequence)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StoredCapsuleSymbol {
    holder: NodeId,
    symbol: Symbol,
    authentication_tag: AuthenticationTag,
    wrapped_for_external_holder: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DurableSegmentEncoding {
    Inline {
        payload: Vec<u8>,
    },
    Coded {
        params: ObjectParams,
        source_symbols: usize,
        repair_symbols: usize,
        symbols: Vec<StoredCapsuleSymbol>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableSegment {
    window: SegmentWindow,
    payload_digest: u64,
    auth_key: AuthKey,
    holders: Vec<NodeId>,
    sealed: bool,
    durability_target_met: bool,
    encoding: DurableSegmentEncoding,
}

impl DurableSegment {
    fn build(
        cell: &SubjectCell,
        candidates: &[StewardCandidate],
        sequence: u64,
        message: &FabricMessage,
    ) -> Result<Self, DataCapsuleError> {
        let window = SegmentWindow::single(sequence);
        let payload_digest = stable_hash((
            "fabric-data-capsule-payload",
            cell.cell_id.raw(),
            cell.epoch,
            window,
            &message.payload,
        ));
        let auth_key =
            derive_data_capsule_auth_key(cell.cell_id, cell.epoch, window, payload_digest);
        let (holders, required_holders) =
            select_data_capsule_holders(cell, candidates, &cell.repair_policy);
        let durability_target_met = holders.len() >= required_holders;

        if DataCapsule::wants_inline_payload(message.payload.len()) {
            return Ok(Self {
                window,
                payload_digest,
                auth_key,
                holders: cell.steward_set.clone(),
                sealed: true,
                durability_target_met,
                encoding: DurableSegmentEncoding::Inline {
                    payload: message.payload.clone(),
                },
            });
        }

        let encoding_config = data_capsule_encoding_config(message.payload.len());
        let object_id = data_capsule_object_id(cell.cell_id, cell.epoch, window, payload_digest);
        let source_symbols = message
            .payload
            .len()
            .div_ceil(usize::from(encoding_config.symbol_size));
        let source_symbols_u16 =
            u16::try_from(source_symbols).map_err(|_| DataCapsuleError::TooManySourceSymbols {
                count: source_symbols,
            })?;
        let repair_symbols_per_block = cell
            .data_capsule
            .repair_symbols_per_block(holders.len(), cell.steward_set.len());
        let params = ObjectParams::new(
            object_id,
            u64::try_from(message.payload.len()).map_err(|_| {
                DataCapsuleError::PayloadTooLarge {
                    bytes: message.payload.len(),
                }
            })?,
            encoding_config.symbol_size,
            1,
            source_symbols_u16,
        );

        let mut encoder = RaptorQEncodingPipeline::new(
            encoding_config.clone(),
            SymbolPool::new(PoolConfig {
                symbol_size: encoding_config.symbol_size,
                ..PoolConfig::default()
            }),
        );
        let encoded_symbols = encoder
            .encode_with_repair(object_id, &message.payload, repair_symbols_per_block)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| DataCapsuleError::Encoding(error.to_string()))?;
        let source_symbol_count = encoded_symbols
            .iter()
            .filter(|symbol| symbol.kind().is_source())
            .count();
        let repair_symbol_count = encoded_symbols.len().saturating_sub(source_symbol_count);
        let stored_symbols = encoded_symbols
            .into_iter()
            .enumerate()
            .map(|(index, symbol)| {
                let holder = holders[index % holders.len()].clone();
                let symbol = symbol.into_symbol();
                let authentication_tag = AuthenticationTag::compute(&auth_key, &symbol);
                StoredCapsuleSymbol {
                    wrapped_for_external_holder: !contains_node(&cell.steward_set, &holder),
                    holder,
                    symbol,
                    authentication_tag,
                }
            })
            .collect();

        Ok(Self {
            window,
            payload_digest,
            auth_key,
            holders,
            sealed: true,
            durability_target_met,
            encoding: DurableSegmentEncoding::Coded {
                params,
                source_symbols: source_symbol_count,
                repair_symbols: repair_symbol_count,
                symbols: stored_symbols,
            },
        })
    }

    #[cfg(test)]
    fn repair_symbol_count(&self) -> usize {
        match &self.encoding {
            DurableSegmentEncoding::Inline { .. } => 0,
            DurableSegmentEncoding::Coded { repair_symbols, .. } => *repair_symbols,
        }
    }

    #[cfg(test)]
    fn source_symbol_count(&self) -> usize {
        match &self.encoding {
            DurableSegmentEncoding::Inline { payload } => {
                if payload.is_empty() {
                    0
                } else {
                    1
                }
            }
            DurableSegmentEncoding::Coded { source_symbols, .. } => *source_symbols,
        }
    }

    #[cfg(test)]
    fn reconstruct_payload(
        &self,
        available_holders: &BTreeSet<NodeId>,
    ) -> Result<Vec<u8>, DataCapsuleError> {
        debug_assert!(
            self.sealed,
            "only sealed durable segments may be reconstructed"
        );
        debug_assert_ne!(self.payload_digest, 0);
        let _durability_target_met = self.durability_target_met;
        match &self.encoding {
            DurableSegmentEncoding::Inline { payload } => {
                if self
                    .holders
                    .iter()
                    .any(|holder| available_holders.contains(holder))
                {
                    Ok(payload.clone())
                } else {
                    Err(DataCapsuleError::NoAvailableHolders {
                        window: self.window,
                    })
                }
            }
            DurableSegmentEncoding::Coded {
                params, symbols, ..
            } => {
                let mut decoder = RaptorQDecodingPipeline::new(RaptorQDecodingConfig {
                    symbol_size: params.symbol_size,
                    max_block_size: usize::from(params.symbols_per_block)
                        * usize::from(params.symbol_size),
                    repair_overhead: 1.0,
                    min_overhead: 0,
                    max_buffered_symbols: 0,
                    block_timeout: Duration::from_secs(30),
                    verify_auth: false,
                });
                decoder
                    .set_object_params(*params)
                    .map_err(|error| DataCapsuleError::Decoding(error.to_string()))?;

                let mut fed_any = false;
                for stored in symbols {
                    if !available_holders.contains(&stored.holder) {
                        continue;
                    }
                    let _wrapped_for_external_holder = stored.wrapped_for_external_holder;
                    if !stored
                        .authentication_tag
                        .verify(&self.auth_key, &stored.symbol)
                    {
                        return Err(DataCapsuleError::AuthenticationFailed {
                            holder: stored.holder.clone(),
                            symbol_id: stored.symbol.id(),
                        });
                    }
                    fed_any = true;
                    match decoder
                        .feed(AuthenticatedSymbol::new_verified(
                            stored.symbol.clone(),
                            stored.authentication_tag,
                        ))
                        .map_err(|error| DataCapsuleError::Decoding(error.to_string()))?
                    {
                        crate::decoding::SymbolAcceptResult::Rejected(
                            RejectReason::BlockAlreadyDecoded,
                        )
                        | crate::decoding::SymbolAcceptResult::Duplicate
                        | crate::decoding::SymbolAcceptResult::Accepted { .. }
                        | crate::decoding::SymbolAcceptResult::DecodingStarted { .. }
                        | crate::decoding::SymbolAcceptResult::BlockComplete { .. } => {}
                        crate::decoding::SymbolAcceptResult::Rejected(reason) => {
                            return Err(DataCapsuleError::DecodingRejected {
                                reason: format!("{reason:?}"),
                            });
                        }
                    }
                }

                if !fed_any {
                    return Err(DataCapsuleError::NoAvailableHolders {
                        window: self.window,
                    });
                }

                decoder
                    .into_data()
                    .map_err(|error| DataCapsuleError::Decoding(error.to_string()))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoverableDataCapsule {
    cell_id: CellId,
    repair_policy: RepairPolicy,
    segments: VecDeque<DurableSegment>,
    symbol_spread: BTreeMap<NodeId, Vec<SegmentWindow>>,
}

impl RecoverableDataCapsule {
    fn new(cell: &SubjectCell) -> Self {
        Self {
            cell_id: cell.cell_id,
            repair_policy: cell.repair_policy.clone(),
            segments: VecDeque::new(),
            symbol_spread: BTreeMap::new(),
        }
    }

    #[cfg(test)]
    fn latest_segment(&self) -> Option<&DurableSegment> {
        self.segments.back()
    }

    fn record_publish(
        &mut self,
        cell: &SubjectCell,
        candidates: &[StewardCandidate],
        sequence: u64,
        message: &FabricMessage,
    ) -> Result<(), DataCapsuleError> {
        debug_assert_eq!(self.cell_id, cell.cell_id);
        if message.delivery_class != DeliveryClass::DurableOrdered {
            return Ok(());
        }

        let segment = DurableSegment::build(cell, candidates, sequence, message)?;
        self.segments.push_back(segment);
        let keep = cell.data_capsule.retained_message_blocks.max(1);
        while self.segments.len() > keep {
            self.segments.pop_front();
        }
        self.repair_policy = cell.repair_policy.clone();
        self.rebuild_symbol_spread();
        Ok(())
    }

    #[cfg(test)]
    fn reconstruct_payload(
        &self,
        sequence: u64,
        available_holders: &BTreeSet<NodeId>,
    ) -> Result<Vec<u8>, DataCapsuleError> {
        let segment = self
            .segments
            .iter()
            .find(|segment| segment.window.contains(sequence))
            .ok_or(DataCapsuleError::MissingSegment { sequence })?;
        segment.reconstruct_payload(available_holders)
    }

    fn rebuild_symbol_spread(&mut self) {
        self.symbol_spread.clear();
        for segment in &self.segments {
            for holder in &segment.holders {
                self.symbol_spread
                    .entry(holder.clone())
                    .or_default()
                    .push(segment.window);
            }
        }
        for windows in self.symbol_spread.values_mut() {
            windows.sort();
            windows.dedup();
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
enum DataCapsuleError {
    #[error("payload of {bytes} bytes exceeds the bounded data-capsule envelope")]
    PayloadTooLarge { bytes: usize },
    #[error("durable segment requires {required} holders but only {available} were available")]
    InsufficientRepairHolders { required: usize, available: usize },
    #[error("payload requires unsupported source-symbol count {count}")]
    TooManySourceSymbols { count: usize },
    #[error("raptorq encoding failed: {0}")]
    Encoding(String),
    #[error("raptorq decoding failed: {0}")]
    Decoding(String),
    #[error("decoder rejected a retained symbol: {reason}")]
    DecodingRejected { reason: String },
    #[error("no retained holder can serve segment window {window}")]
    NoAvailableHolders { window: SegmentWindow },
    #[error("no durable segment retained sequence {sequence}")]
    MissingSegment { sequence: u64 },
    #[error("symbol authentication failed for holder `{holder}` symbol `{symbol_id}`")]
    AuthenticationFailed { holder: NodeId, symbol_id: SymbolId },
}

fn data_capsule_object_id(
    cell_id: CellId,
    epoch: CellEpoch,
    window: SegmentWindow,
    payload_digest: u64,
) -> ObjectId {
    ObjectId::new(
        stable_hash((
            "fabric-data-capsule-object-high",
            cell_id.raw(),
            epoch,
            window,
            payload_digest,
        )),
        stable_hash((
            "fabric-data-capsule-object-low",
            cell_id.raw(),
            epoch,
            window,
            payload_digest,
        )),
    )
}

fn derive_data_capsule_auth_key(
    cell_id: CellId,
    epoch: CellEpoch,
    window: SegmentWindow,
    payload_digest: u64,
) -> AuthKey {
    AuthKey::from_seed(stable_hash((
        "fabric-data-capsule-auth",
        cell_id.raw(),
        epoch,
        window,
        payload_digest,
    )))
}

fn select_data_capsule_holders(
    cell: &SubjectCell,
    candidates: &[StewardCandidate],
    repair_policy: &RepairPolicy,
) -> (Vec<NodeId>, usize) {
    let required_holders =
        repair_policy.minimum_repair_holders(cell.data_capsule.temperature, cell.steward_set.len());
    let mut holders = cell.steward_set.clone();

    for candidate in candidates {
        if holders.len() >= required_holders {
            break;
        }
        if contains_node(&holders, &candidate.node_id) || !candidate.can_repair() {
            continue;
        }
        holders.push(candidate.node_id.clone());
    }

    (holders, required_holders)
}

fn data_capsule_encoding_config(payload_len: usize) -> RaptorQEncodingConfig {
    RaptorQEncodingConfig {
        repair_overhead: 1.0,
        max_block_size: payload_len.max(DEFAULT_SYMBOL_SIZE),
        symbol_size: DEFAULT_SYMBOL_SIZE as u16,
        encoding_parallelism: 1,
        decoding_parallelism: 1,
    }
}

/// Repair and recoverability policy for a cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPolicy {
    /// Minimum recoverability class the cell should preserve during churn.
    pub recoverability_target: u8,
    /// Number of repair witnesses to keep for cold cells.
    pub cold_witnesses: usize,
    /// Number of repair witnesses to keep for hot cells.
    pub hot_witnesses: usize,
}

impl Default for RepairPolicy {
    fn default() -> Self {
        Self {
            recoverability_target: 2,
            cold_witnesses: 1,
            hot_witnesses: 3,
        }
    }
}

impl RepairPolicy {
    fn witness_target(&self, temperature: CellTemperature) -> usize {
        match temperature {
            CellTemperature::Cold | CellTemperature::Warm => self.cold_witnesses,
            CellTemperature::Hot => self.hot_witnesses,
        }
    }

    fn minimum_repair_holders(&self, temperature: CellTemperature, steward_count: usize) -> usize {
        steward_count
            .saturating_add(self.witness_target(temperature))
            .max(self.recoverability_target as usize)
    }
}

/// Declared reordering contract for one protocol kernel inside a subject cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReorderingLaw {
    /// Preserve submission order across all conversation families in the cell.
    PreserveSubmissionOrder,
    /// Independent conversation families may be reordered across lanes.
    IndependentFamiliesMayReorder,
}

/// Declared issuance contract for one protocol kernel inside a subject cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParallelIssueLaw {
    /// All work in the cell must serialize through one execution lane.
    SerializeWithinCell,
    /// Independent conversation families may issue on separate lanes.
    IndependentFamiliesMayIssueInParallel,
}

/// Protocol-level concurrency contract carried by a FABRIC subject family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolKernel {
    /// Stable protocol or service family name.
    pub name: String,
    /// Delivery tier attached to the protocol family.
    pub delivery_class: DeliveryClass,
    /// Semantic interference classes that must serialize together.
    pub interference_classes: BTreeSet<String>,
    /// Obligation surfaces touched by the protocol family.
    pub obligation_footprint: BTreeSet<String>,
    /// Whether the kernel permits independent families to reorder.
    pub reordering_law: ReorderingLaw,
    /// Whether the kernel permits independent families to issue in parallel.
    pub parallel_issue_law: ParallelIssueLaw,
}

impl ProtocolKernel {
    /// Construct a protocol kernel with fail-closed serialization defaults.
    #[must_use]
    pub fn new(name: impl Into<String>, delivery_class: DeliveryClass) -> Self {
        Self {
            name: name.into(),
            delivery_class,
            interference_classes: BTreeSet::new(),
            obligation_footprint: BTreeSet::new(),
            reordering_law: ReorderingLaw::PreserveSubmissionOrder,
            parallel_issue_law: ParallelIssueLaw::SerializeWithinCell,
        }
    }

    /// Declare an interference class that must not execute concurrently.
    #[must_use]
    pub fn with_interference_class(mut self, interference_class: impl Into<String>) -> Self {
        self.interference_classes.insert(interference_class.into());
        self
    }

    /// Declare an obligation footprint touched by the kernel.
    #[must_use]
    pub fn with_obligation_footprint(mut self, footprint: impl Into<String>) -> Self {
        self.obligation_footprint.insert(footprint.into());
        self
    }

    /// Allow independent conversation families to reorder across lanes.
    #[must_use]
    pub fn allow_reordering(mut self) -> Self {
        self.reordering_law = ReorderingLaw::IndependentFamiliesMayReorder;
        self
    }

    /// Allow independent conversation families to issue on separate lanes.
    #[must_use]
    pub fn allow_parallel_issue(mut self) -> Self {
        self.parallel_issue_law = ParallelIssueLaw::IndependentFamiliesMayIssueInParallel;
        self
    }

    /// Return true when the kernel explicitly permits semantic lane splitting.
    #[must_use]
    pub fn permits_semantic_lane_split(&self) -> bool {
        self.reordering_law == ReorderingLaw::IndependentFamiliesMayReorder
            && self.parallel_issue_law == ParallelIssueLaw::IndependentFamiliesMayIssueInParallel
    }
}

/// One protocol-carrying conversation family routed within a subject cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticConversationFamily {
    /// Stable family identifier for diagnostics and deterministic ordering.
    pub family_id: String,
    /// Protocol-bearing subject routed through the cell.
    pub protocol_subject: SubjectPattern,
    /// Declared kernel semantics for the conversation family.
    pub kernel: ProtocolKernel,
    /// Shared-state surface touched by the family.
    pub shared_state_footprint: BTreeSet<String>,
    /// Relative work estimate used for deterministic lane ordering.
    pub estimated_work_units: usize,
}

impl SemanticConversationFamily {
    /// Construct a conversation family with one unit of projected work.
    #[must_use]
    pub fn new(
        family_id: impl Into<String>,
        protocol_subject: SubjectPattern,
        kernel: ProtocolKernel,
    ) -> Self {
        Self {
            family_id: family_id.into(),
            protocol_subject,
            kernel,
            shared_state_footprint: BTreeSet::new(),
            estimated_work_units: 1,
        }
    }

    /// Declare one shared-state surface touched by the family.
    #[must_use]
    pub fn with_shared_state_footprint(mut self, footprint: impl Into<String>) -> Self {
        self.shared_state_footprint.insert(footprint.into());
        self
    }

    /// Override the relative projected work units for deterministic planning.
    #[must_use]
    pub fn with_estimated_work_units(mut self, estimated_work_units: usize) -> Self {
        self.estimated_work_units = estimated_work_units.max(1);
        self
    }

    /// Return true when two families must serialize on the same execution lane.
    #[must_use]
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.family_id == other.family_id
            || !self.kernel.permits_semantic_lane_split()
            || !other.kernel.permits_semantic_lane_split()
            || footprints_overlap(
                &self.kernel.interference_classes,
                &other.kernel.interference_classes,
            )
            || footprints_overlap(
                &self.kernel.obligation_footprint,
                &other.kernel.obligation_footprint,
            )
            || footprints_overlap(&self.shared_state_footprint, &other.shared_state_footprint)
    }

    #[must_use]
    fn scheduling_pressure(&self) -> usize {
        self.estimated_work_units
            + self.kernel.interference_classes.len()
            + self.kernel.obligation_footprint.len()
            + self.shared_state_footprint.len()
    }
}

/// Deterministic execution lane inside one `SubjectCell`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticExecutionLane {
    /// Stable lane identity rooted in the canonical subject cell.
    pub lane_id: String,
    /// Conversation families serialized on this lane.
    pub families: Vec<SemanticConversationFamily>,
    /// Aggregate interference classes covered by the lane.
    pub interference_classes: BTreeSet<String>,
    /// Aggregate obligation footprint covered by the lane.
    pub obligation_footprint: BTreeSet<String>,
    /// Aggregate shared-state footprint covered by the lane.
    pub shared_state_footprint: BTreeSet<String>,
    /// Total projected work units serialized through the lane.
    pub projected_work_units: usize,
}

impl SemanticExecutionLane {
    #[must_use]
    fn new(
        cell_id: CellId,
        lane_index: usize,
        mut families: Vec<SemanticConversationFamily>,
    ) -> Self {
        families.sort_by(compare_semantic_families);

        let mut interference_classes = BTreeSet::new();
        let mut obligation_footprint = BTreeSet::new();
        let mut shared_state_footprint = BTreeSet::new();
        let projected_work_units = families
            .iter()
            .map(|family| family.estimated_work_units)
            .sum();

        for family in &families {
            interference_classes.extend(family.kernel.interference_classes.iter().cloned());
            obligation_footprint.extend(family.kernel.obligation_footprint.iter().cloned());
            shared_state_footprint.extend(family.shared_state_footprint.iter().cloned());
        }

        Self {
            lane_id: format!("{cell_id}:semantic-lane-{lane_index}"),
            families,
            interference_classes,
            obligation_footprint,
            shared_state_footprint,
            projected_work_units,
        }
    }
}

/// Semantic lane plan layered above canonical `SubjectCell` ownership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticLanePlan {
    /// Canonical subject cell owning the plan.
    pub cell_id: CellId,
    /// Deterministic execution lanes for the cell.
    pub lanes: Vec<SemanticExecutionLane>,
}

impl SemanticLanePlan {
    /// Projected work if every family serialized through one lane.
    #[must_use]
    pub fn serial_work_units(&self) -> usize {
        self.lanes
            .iter()
            .map(|lane| lane.projected_work_units)
            .sum()
    }

    /// Projected work on the critical lane after semantic partitioning.
    #[must_use]
    pub fn projected_parallel_rounds(&self) -> usize {
        self.lanes
            .iter()
            .map(|lane| lane.projected_work_units)
            .max()
            .unwrap_or(0)
    }
}

/// Smallest sovereign unit of the brokerless subject fabric.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectCell {
    /// Deterministic identifier for this canonical subject partition and epoch.
    pub cell_id: CellId,
    /// Canonical non-overlapping subject slice owned by this cell.
    pub subject_partition: SubjectPattern,
    /// Active steward set selected for the current temperature and epoch.
    pub steward_set: Vec<NodeId>,
    /// Current bounded control-plane capsule for the cell.
    pub control_capsule: ControlCapsuleV1,
    /// Current data-plane capsule placeholder for the cell.
    pub data_capsule: DataCapsule,
    /// Repair and recoverability policy attached to the cell.
    pub repair_policy: RepairPolicy,
    /// Membership epoch and generation fenced into the cell identity.
    pub epoch: CellEpoch,
}

impl SubjectCell {
    /// Create a new subject cell with deterministic placement.
    #[allow(clippy::result_large_err)]
    pub fn new(
        subject_partition: &SubjectPattern,
        epoch: CellEpoch,
        candidates: &[StewardCandidate],
        placement_policy: &PlacementPolicy,
        repair_policy: RepairPolicy,
        data_capsule: DataCapsule,
    ) -> Result<Self, FabricError> {
        let canonical_partition = placement_policy
            .normalization
            .normalize(subject_partition)?;
        let steward_set = placement_policy.select_stewards(
            &canonical_partition,
            candidates,
            data_capsule.temperature,
        )?;
        let cell_id = CellId::for_partition(epoch, &canonical_partition);
        let shared_control_shard = placement_policy.control_shard_assignment_for_canonical(
            &canonical_partition,
            data_capsule.temperature,
            ObservedCellLoad::new(0),
        )?;
        let mut control_capsule = ControlCapsuleV1::new(cell_id, steward_set.clone(), epoch);
        control_capsule.shared_control_shard = shared_control_shard;

        Ok(Self {
            cell_id,
            subject_partition: canonical_partition,
            steward_set,
            control_capsule,
            data_capsule,
            repair_policy,
            epoch,
        })
    }

    /// Partition protocol families into deterministic execution lanes above the
    /// canonical subject-cell ownership boundary.
    #[must_use]
    pub fn plan_semantic_execution_lanes(
        &self,
        families: &[SemanticConversationFamily],
    ) -> SemanticLanePlan {
        if families.is_empty() {
            return SemanticLanePlan {
                cell_id: self.cell_id,
                lanes: Vec::new(),
            };
        }

        let mut ordered = families.to_vec();
        ordered.sort_by(compare_semantic_families);

        let mut visited = vec![false; ordered.len()];
        let mut lane_families = Vec::new();

        for start in 0..ordered.len() {
            if visited[start] {
                continue;
            }

            visited[start] = true;
            let mut stack = vec![start];
            let mut component = Vec::new();

            while let Some(index) = stack.pop() {
                component.push(ordered[index].clone());
                for candidate in 0..ordered.len() {
                    if visited[candidate] || index == candidate {
                        continue;
                    }
                    if ordered[index].conflicts_with(&ordered[candidate]) {
                        visited[candidate] = true;
                        stack.push(candidate);
                    }
                }
            }

            component.sort_by(compare_semantic_families);
            lane_families.push(component);
        }

        lane_families.sort_by(|left, right| {
            right
                .iter()
                .map(|family| family.estimated_work_units)
                .sum::<usize>()
                .cmp(
                    &left
                        .iter()
                        .map(|family| family.estimated_work_units)
                        .sum::<usize>(),
                )
                .then_with(|| {
                    let left_name = left.first().map_or("", |family| family.family_id.as_str());
                    let right_name = right.first().map_or("", |family| family.family_id.as_str());
                    left_name.cmp(right_name)
                })
        });

        let lanes = lane_families
            .into_iter()
            .enumerate()
            .map(|(lane_index, component)| {
                SemanticExecutionLane::new(self.cell_id, lane_index, component)
            })
            .collect();

        SemanticLanePlan {
            cell_id: self.cell_id,
            lanes,
        }
    }

    /// Certify an explicit steward-set self-rebalance under the current epoch,
    /// then advance the cell generation once the cut is fenced.
    #[allow(clippy::result_large_err)]
    pub fn certify_self_rebalance(
        &self,
        placement_policy: &PlacementPolicy,
        candidates: &[StewardCandidate],
        observed_load: ObservedCellLoad,
        cut_evidence: RebalanceCutEvidence,
    ) -> Result<CertifiedRebalance, RebalanceError> {
        let plan = placement_policy.plan_rebalance(
            &self.subject_partition,
            candidates,
            &self.steward_set,
            self.data_capsule.temperature,
            observed_load,
        )?;
        if plan.next_temperature == self.data_capsule.temperature
            && plan.next_stewards == self.steward_set
        {
            return Err(RebalanceError::NoRebalanceNeeded {
                cell_id: self.cell_id,
            });
        }
        if !contains_node(&plan.next_stewards, &cut_evidence.next_sequencer) {
            return Err(RebalanceError::NextSequencerNotInPlan {
                node: cut_evidence.next_sequencer,
            });
        }

        cut_evidence.obligation_summary.validate()?;
        let canonical_repair_symbols = validate_repair_bindings(
            &cut_evidence,
            candidates,
            &plan,
            self.epoch,
            &self.repair_policy,
        )?;

        let mut next_control = self.control_capsule.clone();
        let active_lease = next_control
            .active_sequencer_lease()
            .ok_or(ControlCapsuleError::NoActiveSequencer)?;
        let control_append = next_control.authoritative_append(&active_lease)?;
        let joint_config = next_control.reconfigure(
            plan.next_stewards.clone(),
            cut_evidence.next_sequencer.clone(),
        )?;

        let next_epoch = self.epoch.next_generation();
        let next_cell_id = CellId::for_partition(next_epoch, &self.subject_partition);
        next_control.rebind_epoch(next_cell_id, next_epoch);
        next_control.shared_control_shard = placement_policy
            .control_shard_assignment_for_canonical(
                &self.subject_partition,
                plan.next_temperature,
                observed_load,
            )?;

        let resulting_cell = Self {
            cell_id: next_cell_id,
            subject_partition: self.subject_partition.clone(),
            steward_set: plan.next_stewards.clone(),
            control_capsule: next_control,
            data_capsule: DataCapsule {
                temperature: plan.next_temperature,
                retained_message_blocks: self.data_capsule.retained_message_blocks,
            },
            repair_policy: self.repair_policy.clone(),
            epoch: next_epoch,
        };

        Ok(CertifiedRebalance {
            control_append,
            joint_config,
            plan: plan.clone(),
            cut_evidence: RebalanceCutEvidence {
                next_sequencer: cut_evidence.next_sequencer,
                retention_generation: cut_evidence.retention_generation,
                obligation_summary: cut_evidence.obligation_summary,
                repair_symbols: canonical_repair_symbols,
            },
            drained_stewards: plan.removed_stewards,
            resulting_cell,
        })
    }

    /// Start a bounded speculative publish attempt for a low-conflict cell.
    #[allow(clippy::result_large_err)]
    pub fn begin_speculative_publish(
        &self,
        policy: &SpeculativeExecutionPolicy,
        conflict_histogram: &CellConflictHistogram,
        request: &SpeculativePublishRequest,
    ) -> Result<SpeculativePublishAttempt, SpeculativeExecutionError> {
        conflict_histogram.validate()?;
        policy.validate(self, request, conflict_histogram)?;

        Ok(SpeculativePublishAttempt::new(
            self.cell_id,
            request,
            conflict_histogram.conflict_rate_basis_points(),
        ))
    }
}

/// Rolling conflict histogram used to decide whether speculation is still safe
/// for a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CellConflictHistogram {
    /// Completed speculative attempts in the current rolling window.
    pub completed_attempts: u64,
    /// Attempts in that window that rolled back due to a conflict.
    pub conflicted_attempts: u64,
}

impl CellConflictHistogram {
    /// Construct a histogram snapshot.
    #[must_use]
    pub const fn new(completed_attempts: u64, conflicted_attempts: u64) -> Self {
        Self {
            completed_attempts,
            conflicted_attempts,
        }
    }

    #[allow(clippy::result_large_err)]
    fn validate(self) -> Result<(), SpeculativeExecutionError> {
        if self.conflicted_attempts > self.completed_attempts {
            return Err(SpeculativeExecutionError::InvalidConflictHistogram {
                completed_attempts: self.completed_attempts,
                conflicted_attempts: self.conflicted_attempts,
            });
        }
        Ok(())
    }

    /// Return the current conflict rate in basis points.
    #[must_use]
    pub fn conflict_rate_basis_points(self) -> u16 {
        if self.completed_attempts == 0 {
            return 0;
        }

        let rate =
            (u128::from(self.conflicted_attempts) * 10_000) / u128::from(self.completed_attempts);
        u16::try_from(rate).unwrap_or(u16::MAX)
    }

    fn record_confirmation(&mut self) {
        self.completed_attempts = self.completed_attempts.saturating_add(1);
    }

    fn record_conflict(&mut self) {
        self.completed_attempts = self.completed_attempts.saturating_add(1);
        self.conflicted_attempts = self.conflicted_attempts.saturating_add(1);
    }
}

/// Explicit operator kill switches for speculative execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeculativeKillSwitches {
    /// Master enable flag for the whole feature.
    pub globally_enabled: bool,
    /// Cells that must never admit speculative work.
    pub disabled_cells: BTreeSet<CellId>,
    /// Service classes that must stay on the non-speculative path.
    pub disabled_service_classes: BTreeSet<SemanticServiceClass>,
}

impl Default for SpeculativeKillSwitches {
    fn default() -> Self {
        Self {
            globally_enabled: true,
            disabled_cells: BTreeSet::new(),
            disabled_service_classes: BTreeSet::new(),
        }
    }
}

impl SpeculativeKillSwitches {
    #[allow(clippy::result_large_err)]
    fn ensure_enabled(
        &self,
        cell_id: CellId,
        service_class: SemanticServiceClass,
    ) -> Result<(), SpeculativeExecutionError> {
        if !self.globally_enabled {
            return Err(SpeculativeExecutionError::GlobalKillSwitch);
        }
        if self.disabled_cells.contains(&cell_id) {
            return Err(SpeculativeExecutionError::CellKillSwitch { cell_id });
        }
        if self.disabled_service_classes.contains(&service_class) {
            return Err(SpeculativeExecutionError::ServiceClassKillSwitch { service_class });
        }
        Ok(())
    }
}

/// Admission policy for speculative subject-cell execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeculativeExecutionPolicy {
    /// Service classes that may use the speculative fast path.
    pub allowed_service_classes: BTreeSet<SemanticServiceClass>,
    /// Maximum admissible conflict rate before speculation is disabled.
    pub max_conflict_rate_basis_points: u16,
    /// Hottest cell temperature still allowed to speculate.
    pub max_admissible_temperature: CellTemperature,
    /// Explicit operator kill switches.
    pub kill_switches: SpeculativeKillSwitches,
}

impl Default for SpeculativeExecutionPolicy {
    fn default() -> Self {
        Self {
            allowed_service_classes: BTreeSet::from([
                SemanticServiceClass::ReplyCritical,
                SemanticServiceClass::DurablePipeline,
            ]),
            max_conflict_rate_basis_points: 500,
            max_admissible_temperature: CellTemperature::Warm,
            kill_switches: SpeculativeKillSwitches::default(),
        }
    }
}

impl SpeculativeExecutionPolicy {
    /// Disable speculation for one specific cell.
    #[must_use]
    pub fn with_disabled_cell(mut self, cell_id: CellId) -> Self {
        self.kill_switches.disabled_cells.insert(cell_id);
        self
    }

    /// Override the maximum admissible conflict rate.
    #[must_use]
    pub fn with_max_conflict_rate_basis_points(
        mut self,
        max_conflict_rate_basis_points: u16,
    ) -> Self {
        self.max_conflict_rate_basis_points = max_conflict_rate_basis_points.min(10_000);
        self
    }

    #[allow(clippy::result_large_err)]
    fn validate(
        &self,
        cell: &SubjectCell,
        request: &SpeculativePublishRequest,
        conflict_histogram: &CellConflictHistogram,
    ) -> Result<(), SpeculativeExecutionError> {
        request.validate()?;
        self.kill_switches
            .ensure_enabled(cell.cell_id, request.service_class)?;

        if !self
            .allowed_service_classes
            .contains(&request.service_class)
        {
            return Err(SpeculativeExecutionError::ServiceClassNotAdmitted {
                service_class: request.service_class,
            });
        }
        if request.delivery_class < DeliveryClass::ObligationBacked {
            return Err(SpeculativeExecutionError::DeliveryClassNotSupported {
                delivery_class: request.delivery_class,
            });
        }
        if cell_temperature_rank(cell.data_capsule.temperature)
            > cell_temperature_rank(self.max_admissible_temperature)
        {
            return Err(SpeculativeExecutionError::CellTooHot {
                cell_id: cell.cell_id,
                temperature: cell.data_capsule.temperature,
                max_temperature: self.max_admissible_temperature,
            });
        }

        let observed_basis_points = conflict_histogram.conflict_rate_basis_points();
        if observed_basis_points > self.max_conflict_rate_basis_points {
            return Err(SpeculativeExecutionError::ConflictRateTooHigh {
                cell_id: cell.cell_id,
                observed_basis_points,
                threshold_basis_points: self.max_conflict_rate_basis_points,
            });
        }

        Ok(())
    }
}

/// Request to begin a speculative publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeculativePublishRequest {
    /// Stable publish identifier used for replay and diagnostics.
    pub publish_id: String,
    /// Service class requesting the fast path.
    pub service_class: SemanticServiceClass,
    /// Delivery class promised at the boundary.
    pub delivery_class: DeliveryClass,
    /// Stable idempotency key for the publish.
    pub idempotency_key: String,
    /// Deterministic digest or digest surrogate for the payload.
    pub payload_digest: String,
}

impl SpeculativePublishRequest {
    /// Construct a request with the canonical obligation-backed default.
    #[must_use]
    pub fn new(
        publish_id: impl Into<String>,
        service_class: SemanticServiceClass,
        idempotency_key: impl Into<String>,
        payload_digest: impl Into<String>,
    ) -> Self {
        Self {
            publish_id: publish_id.into(),
            service_class,
            delivery_class: DeliveryClass::ObligationBacked,
            idempotency_key: idempotency_key.into(),
            payload_digest: payload_digest.into(),
        }
    }

    /// Override the delivery class.
    #[must_use]
    pub fn with_delivery_class(mut self, delivery_class: DeliveryClass) -> Self {
        self.delivery_class = delivery_class;
        self
    }

    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), SpeculativeExecutionError> {
        if self.publish_id.trim().is_empty() {
            return Err(SpeculativeExecutionError::EmptyPublishId);
        }
        if self.idempotency_key.trim().is_empty() {
            return Err(SpeculativeExecutionError::EmptyIdempotencyKey);
        }
        if self.payload_digest.trim().is_empty() {
            return Err(SpeculativeExecutionError::EmptyPayloadDigest);
        }
        Ok(())
    }
}

/// Tentative obligation opened for a speculative publish attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TentativePublishObligation {
    /// Stable obligation id derived from the request and cell.
    pub obligation_id: String,
    /// Cell that owns the speculative attempt.
    pub cell_id: CellId,
    /// Publish identifier carried into replay artifacts.
    pub publish_id: String,
    /// Idempotency key reserved by the tentative attempt.
    pub idempotency_key: String,
}

/// Committed obligation produced after the control capsule confirms a tentative
/// publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedPublishObligation {
    /// Stable obligation id carried forward from the tentative stage.
    pub obligation_id: String,
    /// Cell that owns the committed publish.
    pub cell_id: CellId,
    /// Control-capsule sequence that confirmed the publish.
    pub control_sequence: u64,
}

/// Replay-friendly state marker for a speculative attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpeculativeReplayDecision {
    /// The publish is still tentative.
    Tentative,
    /// The control capsule confirmed the publish.
    Confirmed,
    /// The control capsule detected a conflicting append and the attempt rolled back.
    AbortedConflict,
}

/// Stable artifact that lets tests and replay oracles verify speculative
/// decisions from first principles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeculativeReplayArtifact {
    /// Stable replay key for the tentative publish.
    pub replay_key: String,
    /// Stable oracle key used to compare repeated runs.
    pub oracle_key: String,
    /// Cell that owns the speculative attempt.
    pub cell_id: CellId,
    /// Service class that requested speculation.
    pub service_class: SemanticServiceClass,
    /// Delivery class promised by the caller.
    pub delivery_class: DeliveryClass,
    /// Tentative obligation tracked by the attempt.
    pub tentative_obligation_id: String,
    /// Decision reached so far.
    pub decision: SpeculativeReplayDecision,
    /// Conflict rate snapshot used at admission time.
    pub conflict_rate_basis_points: u16,
    /// Confirming control-capsule sequence, if any.
    pub control_sequence: Option<u64>,
    /// Stable conflict identifier, if the attempt rolled back.
    pub conflict_key: Option<String>,
    verification_fingerprint: u64,
}

impl SpeculativeReplayArtifact {
    fn tentative(
        cell_id: CellId,
        request: &SpeculativePublishRequest,
        tentative_obligation_id: &str,
        conflict_rate_basis_points: u16,
    ) -> Self {
        let base_hash = stable_hash((
            "speculative-publish",
            cell_id.raw(),
            request.publish_id.as_str(),
            request.idempotency_key.as_str(),
            request.payload_digest.as_str(),
            request.service_class,
            request.delivery_class,
        ));
        let replay_key = format!("speculative-replay-{base_hash:016x}");
        let oracle_key = format!(
            "speculative-oracle-{:016x}",
            stable_hash(("speculative-oracle", base_hash))
        );
        let mut artifact = Self {
            replay_key,
            oracle_key,
            cell_id,
            service_class: request.service_class,
            delivery_class: request.delivery_class,
            tentative_obligation_id: tentative_obligation_id.to_owned(),
            decision: SpeculativeReplayDecision::Tentative,
            conflict_rate_basis_points,
            control_sequence: None,
            conflict_key: None,
            verification_fingerprint: 0,
        };
        artifact.verification_fingerprint = artifact.compute_fingerprint();
        artifact
    }

    fn resolved(
        &self,
        decision: SpeculativeReplayDecision,
        control_sequence: Option<u64>,
        conflict_key: Option<String>,
    ) -> Self {
        let mut artifact = Self {
            replay_key: self.replay_key.clone(),
            oracle_key: self.oracle_key.clone(),
            cell_id: self.cell_id,
            service_class: self.service_class,
            delivery_class: self.delivery_class,
            tentative_obligation_id: self.tentative_obligation_id.clone(),
            decision,
            conflict_rate_basis_points: self.conflict_rate_basis_points,
            control_sequence,
            conflict_key,
            verification_fingerprint: 0,
        };
        artifact.verification_fingerprint = artifact.compute_fingerprint();
        artifact
    }

    /// Return true when the artifact's verification fingerprint still matches
    /// its observable fields.
    #[must_use]
    pub fn verifies(&self) -> bool {
        self.verification_fingerprint == self.compute_fingerprint()
    }

    fn compute_fingerprint(&self) -> u64 {
        stable_hash((
            "speculative-replay-artifact",
            self.replay_key.as_str(),
            self.oracle_key.as_str(),
            self.cell_id.raw(),
            self.service_class,
            self.delivery_class,
            self.tentative_obligation_id.as_str(),
            self.decision,
            self.conflict_rate_basis_points,
            self.control_sequence,
            self.conflict_key.as_deref(),
        ))
    }
}

/// Admitted speculative publish that is still hidden from consumers until the
/// control capsule confirms it.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "speculative publish attempts must be resolved via confirm() or abort_due_to_conflict()"]
pub struct SpeculativePublishAttempt {
    /// Cell that owns the speculative attempt.
    pub cell_id: CellId,
    /// Service class admitted onto the fast path.
    pub service_class: SemanticServiceClass,
    /// Delivery class promised by the caller.
    pub delivery_class: DeliveryClass,
    /// Distinct tentative obligation backing the fast path.
    pub tentative_obligation: TentativePublishObligation,
    /// Replay-friendly artifact for the attempt.
    pub replay_artifact: SpeculativeReplayArtifact,
    consumer_visible: bool,
    resolved: bool,
}

impl SpeculativePublishAttempt {
    fn new(
        cell_id: CellId,
        request: &SpeculativePublishRequest,
        conflict_rate_basis_points: u16,
    ) -> Self {
        let obligation_hash = stable_hash((
            "tentative-publish-obligation",
            cell_id.raw(),
            request.publish_id.as_str(),
            request.idempotency_key.as_str(),
            request.payload_digest.as_str(),
        ));
        let obligation_id = format!("tentative-obligation-{obligation_hash:016x}");
        let tentative_obligation = TentativePublishObligation {
            obligation_id: obligation_id.clone(),
            cell_id,
            publish_id: request.publish_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
        };
        let replay_artifact = SpeculativeReplayArtifact::tentative(
            cell_id,
            request,
            &obligation_id,
            conflict_rate_basis_points,
        );

        Self {
            cell_id,
            service_class: request.service_class,
            delivery_class: request.delivery_class,
            tentative_obligation,
            replay_artifact,
            consumer_visible: false,
            resolved: false,
        }
    }

    /// Tentative results stay hidden from consumers until confirmation.
    #[must_use]
    pub const fn consumer_visible(&self) -> bool {
        self.consumer_visible
    }

    /// Confirm the speculative fast path and convert its tentative obligation
    /// into a committed control-capsule fact.
    pub fn confirm(
        mut self,
        conflict_histogram: &mut CellConflictHistogram,
        control_sequence: u64,
    ) -> ConfirmedSpeculativePublish {
        conflict_histogram.record_confirmation();
        self.resolved = true;

        ConfirmedSpeculativePublish {
            committed_obligation: CommittedPublishObligation {
                obligation_id: self.tentative_obligation.obligation_id.clone(),
                cell_id: self.cell_id,
                control_sequence,
            },
            replay_artifact: self.replay_artifact.resolved(
                SpeculativeReplayDecision::Confirmed,
                Some(control_sequence),
                None,
            ),
            consumer_visible: true,
        }
    }

    /// Abort the speculative fast path after the control capsule discovers a
    /// conflicting append and surface the corrected non-speculative outcome.
    pub fn abort_due_to_conflict(
        mut self,
        conflict_histogram: &mut CellConflictHistogram,
        conflict_key: impl Into<String>,
        corrected_outcome: impl Into<String>,
    ) -> AbortedSpeculativePublish {
        conflict_histogram.record_conflict();
        self.resolved = true;

        let conflict_key = conflict_key.into();
        AbortedSpeculativePublish {
            tentative_obligation: self.tentative_obligation.clone(),
            replay_artifact: self.replay_artifact.resolved(
                SpeculativeReplayDecision::AbortedConflict,
                None,
                Some(conflict_key.clone()),
            ),
            corrected_outcome: corrected_outcome.into(),
            consumer_visible: false,
            conflict_key,
        }
    }
}

impl Drop for SpeculativePublishAttempt {
    fn drop(&mut self) {
        debug_assert!(
            self.resolved || std::thread::panicking(),
            "SpeculativePublishAttempt dropped without confirm() or abort_due_to_conflict()"
        );
    }
}

/// Successful resolution of a speculative publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedSpeculativePublish {
    /// Committed obligation emitted after the control capsule confirms the
    /// tentative path.
    pub committed_obligation: CommittedPublishObligation,
    /// Replay artifact covering the confirmed outcome.
    pub replay_artifact: SpeculativeReplayArtifact,
    consumer_visible: bool,
}

impl ConfirmedSpeculativePublish {
    /// Confirmed speculative publishes become visible to consumers.
    #[must_use]
    pub const fn consumer_visible(&self) -> bool {
        self.consumer_visible
    }
}

/// Rolled-back speculative publish after a conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortedSpeculativePublish {
    /// Tentative obligation that was aborted deterministically.
    pub tentative_obligation: TentativePublishObligation,
    /// Replay artifact covering the aborted outcome.
    pub replay_artifact: SpeculativeReplayArtifact,
    /// Corrected non-speculative outcome surfaced after the rollback.
    pub corrected_outcome: String,
    /// Stable conflict identifier used by replay and diagnostics.
    pub conflict_key: String,
    consumer_visible: bool,
}

impl AbortedSpeculativePublish {
    /// Aborted speculative publishes stay hidden from consumers.
    #[must_use]
    pub const fn consumer_visible(&self) -> bool {
        self.consumer_visible
    }
}

/// Deterministic admission and state-machine errors for speculative subject-cell
/// execution.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SpeculativeExecutionError {
    /// Histogram snapshots must never report more conflicts than completed attempts.
    #[error(
        "speculative conflict histogram has {conflicted_attempts} conflicts but only {completed_attempts} completed attempts"
    )]
    InvalidConflictHistogram {
        /// Completed attempts in the rolling window.
        completed_attempts: u64,
        /// Conflicted attempts in the rolling window.
        conflicted_attempts: u64,
    },
    /// Publish ids must be stable and non-empty.
    #[error("speculative publish id must not be empty")]
    EmptyPublishId,
    /// Idempotency keys must be stable and non-empty.
    #[error("speculative idempotency key must not be empty")]
    EmptyIdempotencyKey,
    /// Payload digests are mandatory for replay and rollback auditing.
    #[error("speculative payload digest must not be empty")]
    EmptyPayloadDigest,
    /// Speculation is not valid below the obligation-backed tier.
    #[error(
        "speculative execution requires obligation-backed or stronger delivery classes, got {delivery_class}"
    )]
    DeliveryClassNotSupported {
        /// Delivery class rejected for speculation.
        delivery_class: DeliveryClass,
    },
    /// Operators may disable the entire speculative path.
    #[error("speculative execution is globally disabled")]
    GlobalKillSwitch,
    /// Operators may disable speculation for one cell.
    #[error("speculative execution is disabled for cell `{cell_id}`")]
    CellKillSwitch {
        /// Cell held off the speculative path.
        cell_id: CellId,
    },
    /// Operators may disable speculation for one service class.
    #[error("speculative execution is disabled for service class `{service_class:?}`")]
    ServiceClassKillSwitch {
        /// Service class held off the speculative path.
        service_class: SemanticServiceClass,
    },
    /// Only explicit service classes may use the feature.
    #[error("service class `{service_class:?}` is not admitted for speculative execution")]
    ServiceClassNotAdmitted {
        /// Service class rejected by the policy.
        service_class: SemanticServiceClass,
    },
    /// Hotter cells must stay on the authoritative path.
    #[error(
        "cell `{cell_id}` has temperature {temperature:?}, above speculative limit {max_temperature:?}"
    )]
    CellTooHot {
        /// Cell rejected for speculation.
        cell_id: CellId,
        /// Observed current temperature.
        temperature: CellTemperature,
        /// Hottest temperature still admitted by policy.
        max_temperature: CellTemperature,
    },
    /// Conflict history exceeded the configured safe envelope.
    #[error(
        "cell `{cell_id}` conflict rate {observed_basis_points}bp exceeds speculative threshold {threshold_basis_points}bp"
    )]
    ConflictRateTooHigh {
        /// Cell rejected for speculation.
        cell_id: CellId,
        /// Observed rolling conflict rate.
        observed_basis_points: u16,
        /// Maximum rate allowed by policy.
        threshold_basis_points: u16,
    },
}

/// Deterministic failures while certifying a self-rebalance.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RebalanceError {
    /// The sampled load stayed inside the current hysteresis band.
    #[error("rebalance for `{cell_id}` produced no epoch-changing steward transition")]
    NoRebalanceNeeded {
        /// Cell that remained within its current rebalance envelope.
        cell_id: CellId,
    },
    /// The chosen next sequencer is not present in the certified target set.
    #[error("next sequencer `{node}` is not part of the certified steward set")]
    NextSequencerNotInPlan {
        /// Node proposed as the next sequencer.
        node: NodeId,
    },
    /// There are still unresolved publish obligations below the semantic cut.
    #[error("rebalance cut still has {unresolved} publish obligations below the cut frontier")]
    PublishFrontierNotDrained {
        /// Count of unresolved publish obligations.
        unresolved: usize,
    },
    /// Consumer lease ownership was not unique at the cut frontier.
    #[error("rebalance cut still has {ambiguous} ambiguous consumer lease owners")]
    AmbiguousConsumerLeaseOwners {
        /// Count of ambiguous lease owners.
        ambiguous: usize,
    },
    /// Consumer lease transfers or reissues did not cover all live leases.
    #[error("rebalance cut transferred {transferred} consumer leases but requires {active_leases}")]
    ConsumerLeaseTransferIncomplete {
        /// Number of active consumer leases at the cut.
        active_leases: usize,
        /// Number of consumer leases explicitly transferred or reissued.
        transferred: usize,
    },
    /// Reply rights were left dangling at the cut frontier.
    #[error("rebalance cut leaves {dangling} dangling reply rights")]
    DanglingReplyRights {
        /// Count of dangling reply rights.
        dangling: usize,
    },
    /// Reply-right reissue proof did not cover all live reply rights.
    #[error("rebalance cut reissued {reissued} reply rights but requires {active_rights}")]
    ReplyRightsNotReissued {
        /// Number of active reply rights at the cut.
        active_rights: usize,
        /// Number of reply rights reissued onto the next epoch.
        reissued: usize,
    },
    /// Rebalance evidence carried multiple repair bindings for the same node.
    #[error("rebalance evidence contains duplicate repair bindings for `{node}`")]
    DuplicateRepairBinding {
        /// Node with conflicting duplicate bindings.
        node: NodeId,
    },
    /// Repair material was bound to the wrong epoch.
    #[error("repair symbol binding for `{node}` uses epoch {actual:?}, expected {expected:?}")]
    RepairBindingWrongEpoch {
        /// Repair-capable holder attached to the binding.
        node: NodeId,
        /// Cell epoch that should have been used.
        expected: CellEpoch,
        /// Epoch carried by the binding.
        actual: CellEpoch,
    },
    /// Repair material was bound to the wrong retention generation.
    #[error(
        "repair symbol binding for `{node}` uses retention generation {actual}, expected {expected}"
    )]
    RepairBindingWrongRetentionGeneration {
        /// Repair-capable holder attached to the binding.
        node: NodeId,
        /// Retention generation that should have been used.
        expected: u64,
        /// Retention generation carried by the binding.
        actual: u64,
    },
    /// Only repair-capable nodes may be credited with repair material.
    #[error("repair symbol holder `{node}` is not eligible to store repair material")]
    IneligibleRepairHolder {
        /// Holder that is not repair-capable in the supplied candidate set.
        node: NodeId,
    },
    /// Every next steward must prove it collected the current repair material.
    #[error("next steward `{node}` is missing a repair-symbol binding for the rebalance cut")]
    MissingStewardRepairBinding {
        /// Steward missing a binding.
        node: NodeId,
    },
    /// The certified cut did not gather enough repair-capable holders.
    #[error("rebalance collected {actual} repair-capable holders but requires at least {required}")]
    InsufficientRepairSymbolHolders {
        /// Required number of repair-capable holders.
        required: usize,
        /// Number of unique holders actually proven.
        actual: usize,
    },
    /// Placement planning failed.
    #[error(transparent)]
    Placement(#[from] FabricError),
    /// Control-capsule fencing or reconfiguration failed.
    #[error(transparent)]
    Control(#[from] ControlCapsuleError),
}

/// Errors produced by foundational fabric modeling and placement.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FabricError {
    /// Two canonical subject partitions still overlap after normalization.
    #[error("subject partitions `{left}` and `{right}` overlap")]
    OverlappingSubjectPartitions {
        /// Left partition in the conflicting pair.
        left: SubjectPattern,
        /// Right partition in the conflicting pair.
        right: SubjectPattern,
    },
    /// No steward-eligible nodes were available for the requested partition.
    #[error("no steward-eligible candidates available for partition `{partition}`")]
    NoStewardCandidates {
        /// Canonical partition that could not be placed.
        partition: SubjectPattern,
    },
    /// Shared control-shard packing requires a positive cardinality bound.
    #[error("shared control shard cardinality limit must be at least 1")]
    InvalidSharedShardCardinalityLimit,
    /// Multiple distinct morphisms claimed the same subject and disagreed on the result.
    #[error("subject `{subject}` matched multiple canonical morphisms (`{left}` and `{right}`)")]
    ConflictingSubjectMorphisms {
        /// Original subject presented to the normalization pipeline.
        subject: SubjectPattern,
        /// First canonical candidate produced by a matching morphism.
        left: SubjectPattern,
        /// Conflicting canonical candidate produced by another morphism.
        right: SubjectPattern,
    },
    /// Prefix morphisms cycled instead of converging on one canonical partition.
    #[error("subject `{subject}` entered a morphism cycle at `{cycle_point}`")]
    CyclicSubjectMorphisms {
        /// Original subject presented to the normalization pipeline.
        subject: SubjectPattern,
        /// Canonical subject that repeated while chasing morphisms.
        cycle_point: SubjectPattern,
    },
    /// Runtime FABRIC authority did not cover the requested subject space.
    #[error(
        "fabric capability `{requested_capability}` denied for `{subject}` at delivery class `{delivery_class}` (decision `{decision_id}`)"
    )]
    CapabilityDenied {
        /// Subject or subject pattern that was denied.
        subject: SubjectPattern,
        /// Delivery class in force at the denied surface.
        delivery_class: DeliveryClass,
        /// Deterministic operator rendering of the missing capability.
        requested_capability: String,
        /// Decision-contract identifier recorded for the denial.
        decision_id: DecisionId,
    },
}

/// Bootstrap mode used to start a typed discovery session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryBootstrap {
    /// Discover peers without any preconfigured seed list.
    SelfDiscover,
    /// Start from a deterministic seed list.
    SeedList(Vec<NodeId>),
}

impl DiscoveryBootstrap {
    #[allow(clippy::result_large_err)]
    fn replay_key(&self) -> Result<String, DiscoveryError> {
        match self {
            Self::SelfDiscover => Ok("self-discover".to_owned()),
            Self::SeedList(seeds) => {
                if seeds.is_empty() {
                    return Err(DiscoveryError::EmptySeedList);
                }
                if let Some(node) = duplicate_node(seeds) {
                    return Err(DiscoveryError::DuplicateSeed { node });
                }
                Ok(format!(
                    "seed-list:{}",
                    seeds
                        .iter()
                        .map(NodeId::as_str)
                        .collect::<Vec<_>>()
                        .join(",")
                ))
            }
        }
    }
}

/// Signed admission artifact required before a peer is trusted in discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryAdmissionCredential {
    /// Node identity covered by the admission decision.
    pub subject: NodeId,
    /// Authority that issued the admission decision.
    pub issuer: NodeId,
    /// Membership epoch in which the credential was minted.
    pub membership_epoch: u64,
    /// Exact capability envelopes admitted for the subject.
    pub admitted_capabilities: Vec<FabricCapability>,
    /// Opaque signature or proof material.
    pub signature: String,
}

impl DiscoveryAdmissionCredential {
    fn authorizes(&self, capability: &FabricCapability) -> bool {
        self.admitted_capabilities
            .iter()
            .any(|granted| fabric_capability_covers(granted, capability))
    }
}

/// Resource budget advertised during discovery negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiscoveryResourceBudget {
    /// Approximate free storage budget in bytes.
    pub storage_bytes_available: u64,
    /// Approximate outbound budget in kibibytes per second.
    pub uplink_kib_per_sec: u32,
    /// Number of repair-capable slots the peer can currently offer.
    pub repair_slots: u16,
}

/// One interest sample exchanged during discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryInterestSummaryEntry {
    /// Subject space being summarized.
    pub subject: SubjectPattern,
    /// Approximate converged subscriber count.
    pub subscribers: u64,
}

/// Capability-scoped or blinded interest disclosure emitted by discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryInterestAdvertisement {
    /// Raw subject visibility was authorized for the viewer.
    Scoped {
        /// Subject space carried verbatim.
        subject: SubjectPattern,
        /// Approximate converged subscriber count.
        subscribers: u64,
    },
    /// Raw subject visibility was denied, so only a stable blinded key is sent.
    Blinded {
        /// Session-scoped blinded fingerprint for replay and diagnostics.
        subject_fingerprint: u64,
        /// Approximate converged subscriber count.
        subscribers: u64,
    },
}

/// Steward-lease evidence advertised during discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryStewardLeaseView {
    /// Subject cell covered by the steward lease.
    pub cell_id: CellId,
    /// Lease the peer claims is still current.
    pub lease: SequencerLease,
}

/// Recent control-epoch evidence advertised during discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryControlEpochView {
    /// Subject cell covered by the control epoch.
    pub cell_id: CellId,
    /// Most recent observed control epoch for the cell.
    pub control_epoch: ControlEpoch,
}

/// Non-authoritative health and placement hints exchanged during discovery.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DiscoveryAdvisoryHints {
    /// Replica-health snapshot. This is advisory only.
    pub membership: Option<MembershipRecord>,
    /// Cells the peer suggests for placement or routing. Advisory only.
    pub suggested_cells: Vec<CellId>,
}

/// Typed discovery handshake payload exchanged before session establishment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryHello {
    /// Identity of the advertising peer.
    pub node_id: NodeId,
    /// Bootstrap mode used to reach the peer.
    pub bootstrap: DiscoveryBootstrap,
    /// Capability set the peer claims to currently hold.
    pub capability_set: Vec<FabricCapability>,
    /// Signed membership and admission credential for the peer.
    pub credential: DiscoveryAdmissionCredential,
    /// Policy versions the peer can negotiate.
    pub supported_policy_versions: BTreeSet<u64>,
    /// Resource budget the peer advertises for cooperative routing or repair.
    pub resource_budget: DiscoveryResourceBudget,
    /// Capability-scoped interest samples.
    pub interest_summary: Vec<DiscoveryInterestSummaryEntry>,
    /// Steward-lease claims carried in the handshake.
    pub stewardship_leases: Vec<DiscoveryStewardLeaseView>,
    /// Recent control epochs used to distinguish authority from stale gossip.
    pub recent_control_epochs: Vec<DiscoveryControlEpochView>,
    /// Health and placement hints that remain advisory even after admission.
    pub advisory_hints: DiscoveryAdvisoryHints,
}

impl DiscoveryHello {
    #[allow(clippy::result_large_err)]
    fn validate(&self, policy: &DiscoveryNegotiationPolicy) -> Result<(), DiscoveryError> {
        let _ = self.bootstrap.replay_key()?;

        if self.credential.subject != self.node_id {
            return Err(DiscoveryError::CredentialSubjectMismatch {
                expected: self.node_id.clone(),
                actual: self.credential.subject.clone(),
            });
        }
        if self.credential.signature.trim().is_empty() {
            return Err(DiscoveryError::MissingCredentialSignature {
                node: self.node_id.clone(),
            });
        }
        if !policy.trusted_issuers.contains(&self.credential.issuer) {
            return Err(DiscoveryError::UntrustedCredentialIssuer {
                issuer: self.credential.issuer.clone(),
            });
        }
        if !self
            .supported_policy_versions
            .iter()
            .any(|version| policy.supported_policy_versions.contains(version))
        {
            return Err(DiscoveryError::NoCompatiblePolicyVersion {
                node: self.node_id.clone(),
            });
        }
        for capability in &self.capability_set {
            if !self.credential.authorizes(capability) {
                return Err(DiscoveryError::CapabilityEscalation {
                    node: self.node_id.clone(),
                    capability: capability.clone(),
                });
            }
        }
        self.validate_interest_summary_scope()?;
        self.validate_authority_membership_epochs()?;
        self.validate_authoritative_stewardship_consistency()?;

        Ok(())
    }

    /// Return the interest summary as visible to a viewer with `capabilities`.
    #[must_use]
    pub fn interest_advertisements_for(
        &self,
        capabilities: &[FabricCapability],
        session_id: DiscoverySessionId,
    ) -> Vec<DiscoveryInterestAdvertisement> {
        self.interest_summary
            .iter()
            .map(|entry| {
                if capabilities_allow_interest_visibility(capabilities, &entry.subject) {
                    DiscoveryInterestAdvertisement::Scoped {
                        subject: entry.subject.clone(),
                        subscribers: entry.subscribers,
                    }
                } else {
                    DiscoveryInterestAdvertisement::Blinded {
                        subject_fingerprint: stable_hash((
                            "fabric::discovery::interest",
                            session_id.raw(),
                            entry.subject.canonical_key(),
                        )),
                        subscribers: entry.subscribers,
                    }
                }
            })
            .collect()
    }

    /// Return only stewardship leases backed by the current advertised control epoch.
    #[must_use]
    fn authoritative_stewardship(&self) -> Vec<DiscoveryStewardLeaseView> {
        let mut latest_by_cell = BTreeMap::new();
        for observed in &self.recent_control_epochs {
            latest_by_cell
                .entry(observed.cell_id)
                .and_modify(|current: &mut ControlEpoch| {
                    *current = (*current).max(observed.control_epoch);
                })
                .or_insert(observed.control_epoch);
        }

        let mut authoritative_by_cell = BTreeMap::new();
        self.stewardship_leases.iter().for_each(|lease| {
            if latest_by_cell
                .get(&lease.cell_id)
                .is_some_and(|current| *current == lease.lease.control_epoch)
            {
                authoritative_by_cell
                    .entry(lease.cell_id)
                    .or_insert_with(|| lease.clone());
            }
        });
        authoritative_by_cell.into_values().collect()
    }

    #[allow(clippy::result_large_err)]
    fn validate_interest_summary_scope(&self) -> Result<(), DiscoveryError> {
        for entry in &self.interest_summary {
            if !capabilities_cover_interest_subject(&self.capability_set, &entry.subject) {
                return Err(DiscoveryError::InterestSummaryOutsideCapabilitySet {
                    node: self.node_id.clone(),
                    subject: entry.subject.clone(),
                });
            }
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn validate_authority_membership_epochs(&self) -> Result<(), DiscoveryError> {
        let expected_membership_epoch = self.credential.membership_epoch;
        for observed in &self.recent_control_epochs {
            let actual_membership_epoch = observed.control_epoch.cell_epoch.membership_epoch;
            if actual_membership_epoch != expected_membership_epoch {
                return Err(DiscoveryError::ControlEpochMembershipMismatch {
                    node: self.node_id.clone(),
                    cell_id: observed.cell_id,
                    expected_membership_epoch,
                    actual_membership_epoch,
                });
            }
        }
        for lease in &self.stewardship_leases {
            let actual_membership_epoch = lease.lease.control_epoch.cell_epoch.membership_epoch;
            if actual_membership_epoch != expected_membership_epoch {
                return Err(DiscoveryError::StewardLeaseMembershipMismatch {
                    node: self.node_id.clone(),
                    cell_id: lease.cell_id,
                    expected_membership_epoch,
                    actual_membership_epoch,
                });
            }
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn validate_authoritative_stewardship_consistency(&self) -> Result<(), DiscoveryError> {
        let mut latest_by_cell = BTreeMap::new();
        for observed in &self.recent_control_epochs {
            latest_by_cell
                .entry(observed.cell_id)
                .and_modify(|current: &mut ControlEpoch| {
                    *current = (*current).max(observed.control_epoch);
                })
                .or_insert(observed.control_epoch);
        }

        let mut authoritative_by_cell = BTreeMap::<CellId, &SequencerLease>::new();
        for lease in &self.stewardship_leases {
            if latest_by_cell
                .get(&lease.cell_id)
                .is_some_and(|current| *current == lease.lease.control_epoch)
            {
                match authoritative_by_cell.entry(lease.cell_id) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(&lease.lease);
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if entry.get() != &&lease.lease =>
                    {
                        return Err(DiscoveryError::ConflictingAuthoritativeStewardLease {
                            node: self.node_id.clone(),
                            cell_id: lease.cell_id,
                        });
                    }
                    std::collections::btree_map::Entry::Occupied(_) => {}
                }
            }
        }
        Ok(())
    }
}

/// Local policy used while establishing a typed discovery session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryNegotiationPolicy {
    /// Admission issuers trusted to sign peer credentials.
    pub trusted_issuers: BTreeSet<NodeId>,
    /// Policy versions the local node can negotiate.
    pub supported_policy_versions: BTreeSet<u64>,
    /// Capabilities that determine how much of the peer's namespace is visible.
    pub viewer_capabilities: Vec<FabricCapability>,
    /// Lease TTL to bind into the resulting discovery obligation.
    pub lease_ttl_millis: u64,
}

/// Stable replay identifier for one typed discovery session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiscoverySessionId(u128);

impl DiscoverySessionId {
    #[allow(clippy::result_large_err)]
    fn for_handshake(
        local_node: &NodeId,
        hello: &DiscoveryHello,
        policy_version: u64,
    ) -> Result<Self, DiscoveryError> {
        let bootstrap_key = hello.bootstrap.replay_key()?;
        let lower = stable_hash((
            "fabric::discovery",
            local_node.as_str(),
            hello.node_id.as_str(),
            bootstrap_key.as_str(),
            policy_version,
            hello.credential.issuer.as_str(),
            hello.credential.membership_epoch,
            hello.credential.signature.as_str(),
        ));
        let upper = stable_hash((
            "fabric::discovery:v2",
            local_node.as_str(),
            hello.node_id.as_str(),
            bootstrap_key.as_str(),
            policy_version,
            hello.credential.issuer.as_str(),
            hello.credential.membership_epoch,
            hello.credential.signature.as_str(),
        ));
        Ok(Self((u128::from(upper) << 64) | u128::from(lower)))
    }

    /// Return the raw 128-bit identifier.
    #[must_use]
    pub const fn raw(self) -> u128 {
        self.0
    }
}

/// Explicit lease obligation attached to a discovery session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryLeaseObligation {
    /// Stable identifier of the session that owns the obligation.
    pub session_id: DiscoverySessionId,
    /// Local node that must renew or release the lease.
    pub local_node: NodeId,
    /// Remote peer whose discovery state is being leased.
    pub peer_node: NodeId,
    /// Policy version agreed for the session.
    pub policy_version: u64,
    /// Time-to-live of the discovery lease.
    pub ttl_millis: u64,
}

/// Lifecycle stage of a typed discovery session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySessionState {
    /// The handshake completed and the lease obligation is active.
    Established,
}

/// Replayable typed transition in the discovery state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySessionTransition {
    /// Bootstrap mode validated.
    BootstrapValidated {
        /// Bootstrap mode that reached the peer.
        bootstrap: DiscoveryBootstrap,
    },
    /// Signed peer identity and capability exchange accepted.
    PeerAuthenticated {
        /// Remote peer that was authenticated.
        peer: NodeId,
        /// Negotiated policy version.
        policy_version: u64,
    },
    /// Interest disclosures filtered according to namespace visibility.
    InterestSummaryScoped {
        /// Count of raw subject disclosures.
        visible: usize,
        /// Count of blinded subject disclosures.
        blinded: usize,
    },
    /// Steward authority accepted only where the current control epoch matched.
    AuthorityValidated {
        /// Count of authoritative current-epoch steward leases.
        authoritative_leases: usize,
        /// Count of recent control epochs carried in the handshake.
        recent_epochs: usize,
    },
    /// Session lease bound explicitly into the transcript.
    LeaseBound {
        /// Lease obligation activated for the session.
        obligation: DiscoveryLeaseObligation,
    },
    /// Session is fully established.
    Established {
        /// Remote peer bound to the session.
        peer: NodeId,
    },
}

impl DiscoverySessionTransition {
    /// Stable transition kind for replay and tests.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::BootstrapValidated { .. } => "bootstrap_validated",
            Self::PeerAuthenticated { .. } => "peer_authenticated",
            Self::InterestSummaryScoped { .. } => "interest_summary_scoped",
            Self::AuthorityValidated { .. } => "authority_validated",
            Self::LeaseBound { .. } => "lease_bound",
            Self::Established { .. } => "established",
        }
    }
}

/// Typed discovery session established after validating admission and capability scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverySession {
    /// Stable replay identifier for the session.
    pub session_id: DiscoverySessionId,
    /// Local node that established the session.
    pub local_node: NodeId,
    /// Remote peer bound into the session.
    pub peer_node: NodeId,
    /// Bootstrap path that reached the peer.
    pub bootstrap: DiscoveryBootstrap,
    /// Negotiated policy version.
    pub policy_version: u64,
    /// Peer capability set accepted by signed admission.
    pub peer_capabilities: Vec<FabricCapability>,
    /// Peer resource budget snapshot.
    pub peer_resource_budget: DiscoveryResourceBudget,
    /// Interest disclosures visible to the local viewer.
    pub peer_interest_advertisements: Vec<DiscoveryInterestAdvertisement>,
    /// Steward-lease claims that remained authoritative after epoch validation.
    pub authoritative_stewardship: Vec<DiscoveryStewardLeaseView>,
    /// Current control epochs advertised by the peer.
    pub recent_control_epochs: Vec<DiscoveryControlEpochView>,
    /// Non-authoritative hints retained separately from authority artifacts.
    pub advisory_hints: DiscoveryAdvisoryHints,
    /// Explicit obligation that keeps the session alive.
    pub lease_obligation: DiscoveryLeaseObligation,
    /// Current session state.
    pub state: DiscoverySessionState,
    transitions: Vec<DiscoverySessionTransition>,
}

impl DiscoverySession {
    /// Establish a typed discovery session from one validated peer hello.
    #[allow(clippy::result_large_err)]
    pub fn establish(
        local_node: NodeId,
        hello: &DiscoveryHello,
        policy: &DiscoveryNegotiationPolicy,
    ) -> Result<Self, DiscoveryError> {
        hello.validate(policy)?;

        let policy_version = hello
            .supported_policy_versions
            .intersection(&policy.supported_policy_versions)
            .copied()
            .max()
            .ok_or_else(|| DiscoveryError::NoCompatiblePolicyVersion {
                node: hello.node_id.clone(),
            })?;

        let session_id = DiscoverySessionId::for_handshake(&local_node, hello, policy_version)?;
        let peer_interest_advertisements =
            hello.interest_advertisements_for(&policy.viewer_capabilities, session_id);
        let authoritative_stewardship = hello.authoritative_stewardship();
        let visible = peer_interest_advertisements
            .iter()
            .filter(|entry| matches!(entry, DiscoveryInterestAdvertisement::Scoped { .. }))
            .count();
        let blinded = peer_interest_advertisements.len().saturating_sub(visible);
        let lease_obligation = DiscoveryLeaseObligation {
            session_id,
            local_node: local_node.clone(),
            peer_node: hello.node_id.clone(),
            policy_version,
            ttl_millis: policy.lease_ttl_millis.max(1),
        };
        let transitions = vec![
            DiscoverySessionTransition::BootstrapValidated {
                bootstrap: hello.bootstrap.clone(),
            },
            DiscoverySessionTransition::PeerAuthenticated {
                peer: hello.node_id.clone(),
                policy_version,
            },
            DiscoverySessionTransition::InterestSummaryScoped { visible, blinded },
            DiscoverySessionTransition::AuthorityValidated {
                authoritative_leases: authoritative_stewardship.len(),
                recent_epochs: hello.recent_control_epochs.len(),
            },
            DiscoverySessionTransition::LeaseBound {
                obligation: lease_obligation.clone(),
            },
            DiscoverySessionTransition::Established {
                peer: hello.node_id.clone(),
            },
        ];

        Ok(Self {
            session_id,
            local_node,
            peer_node: hello.node_id.clone(),
            bootstrap: hello.bootstrap.clone(),
            policy_version,
            peer_capabilities: hello.capability_set.clone(),
            peer_resource_budget: hello.resource_budget.clone(),
            peer_interest_advertisements,
            authoritative_stewardship,
            recent_control_epochs: hello.recent_control_epochs.clone(),
            advisory_hints: hello.advisory_hints.clone(),
            lease_obligation,
            state: DiscoverySessionState::Established,
            transitions,
        })
    }

    /// Replayable transition transcript for the session.
    #[must_use]
    pub fn transitions(&self) -> &[DiscoverySessionTransition] {
        &self.transitions
    }
}

/// Failures produced while validating a typed discovery handshake.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DiscoveryError {
    /// Seed-list bootstrap must carry at least one node.
    #[error("discovery seed-list bootstrap requires at least one seed node")]
    EmptySeedList,
    /// Seed-list bootstrap may not repeat nodes.
    #[error("discovery seed-list bootstrap contains duplicate node `{node}`")]
    DuplicateSeed {
        /// Repeated seed node.
        node: NodeId,
    },
    /// Credential subject and peer hello identity must match exactly.
    #[error(
        "discovery credential subject `{actual}` does not match peer hello identity `{expected}`"
    )]
    CredentialSubjectMismatch {
        /// Peer identity from the hello.
        expected: NodeId,
        /// Credential subject bound into the signature.
        actual: NodeId,
    },
    /// Discovery credentials must carry some signature or proof material.
    #[error("discovery credential for `{node}` is missing signature material")]
    MissingCredentialSignature {
        /// Peer whose credential lacked proof material.
        node: NodeId,
    },
    /// Credential issuer was not trusted by local discovery policy.
    #[error("discovery credential issuer `{issuer}` is not trusted")]
    UntrustedCredentialIssuer {
        /// Issuer that failed trust validation.
        issuer: NodeId,
    },
    /// Discovery requires at least one shared policy version.
    #[error("peer `{node}` does not share a supported discovery policy version")]
    NoCompatiblePolicyVersion {
        /// Peer that failed policy negotiation.
        node: NodeId,
    },
    /// Peer capability exchange exceeded the signed admission envelope.
    #[error("peer `{node}` advertised capability `{capability}` beyond signed admission")]
    CapabilityEscalation {
        /// Peer that attempted the capability escalation.
        node: NodeId,
        /// Capability not covered by signed admission.
        capability: FabricCapability,
    },
    /// Interest summaries must stay inside the peer's claimed capability scope.
    #[error(
        "peer `{node}` advertised interest summary for `{subject}` outside its claimed capability scope"
    )]
    InterestSummaryOutsideCapabilitySet {
        /// Peer that advertised an out-of-scope interest subject.
        node: NodeId,
        /// Interest subject not covered by the peer capability set.
        subject: SubjectPattern,
    },
    /// Advertised control epochs must align with the signed admission epoch.
    #[error(
        "peer `{node}` advertised control epoch for cell `{cell_id}` in membership epoch {actual_membership_epoch}, but signed admission is in epoch {expected_membership_epoch}"
    )]
    ControlEpochMembershipMismatch {
        /// Peer carrying the mismatched control epoch.
        node: NodeId,
        /// Cell whose epoch evidence was inconsistent.
        cell_id: CellId,
        /// Membership epoch bound into the signed admission.
        expected_membership_epoch: u64,
        /// Membership epoch carried by the advertised control epoch.
        actual_membership_epoch: u64,
    },
    /// Advertised steward leases must align with the signed admission epoch.
    #[error(
        "peer `{node}` advertised steward lease for cell `{cell_id}` in membership epoch {actual_membership_epoch}, but signed admission is in epoch {expected_membership_epoch}"
    )]
    StewardLeaseMembershipMismatch {
        /// Peer carrying the mismatched steward lease.
        node: NodeId,
        /// Cell whose steward lease was inconsistent.
        cell_id: CellId,
        /// Membership epoch bound into the signed admission.
        expected_membership_epoch: u64,
        /// Membership epoch carried by the advertised steward lease.
        actual_membership_epoch: u64,
    },
    /// A cell may not advertise two different current authoritative leases.
    #[error(
        "peer `{node}` advertised conflicting authoritative steward leases for cell `{cell_id}`"
    )]
    ConflictingAuthoritativeStewardLease {
        /// Peer that carried contradictory authority evidence.
        node: NodeId,
        /// Cell whose authority evidence conflicted.
        cell_id: CellId,
    },
}

fn capabilities_allow_interest_visibility(
    capabilities: &[FabricCapability],
    subject: &SubjectPattern,
) -> bool {
    capabilities_cover_interest_subject(capabilities, subject)
}

fn capabilities_cover_interest_subject(
    capabilities: &[FabricCapability],
    subject: &SubjectPattern,
) -> bool {
    capabilities
        .iter()
        .any(|capability| interest_capability_covers_subject(capability, subject))
}

fn interest_capability_covers_subject(
    capability: &FabricCapability,
    subject: &SubjectPattern,
) -> bool {
    match capability {
        FabricCapability::Subscribe { subject: granted }
        | FabricCapability::CreateStream { subject: granted }
        | FabricCapability::TransformSpace { subject: granted } => {
            discovery_pattern_covers_pattern(granted, subject)
        }
        FabricCapability::AdminControl => true,
        FabricCapability::Publish { .. } | FabricCapability::ConsumeStream { .. } => false,
    }
}

fn fabric_capability_covers(granted: &FabricCapability, requested: &FabricCapability) -> bool {
    match (granted, requested) {
        (
            FabricCapability::Publish { subject: granted },
            FabricCapability::Publish { subject: requested },
        )
        | (
            FabricCapability::Subscribe { subject: granted },
            FabricCapability::Subscribe { subject: requested },
        )
        | (
            FabricCapability::CreateStream { subject: granted },
            FabricCapability::CreateStream { subject: requested },
        )
        | (
            FabricCapability::TransformSpace { subject: granted },
            FabricCapability::TransformSpace { subject: requested },
        ) => discovery_pattern_covers_pattern(granted, requested),
        (
            FabricCapability::ConsumeStream { stream: granted },
            FabricCapability::ConsumeStream { stream: requested },
        ) => granted == requested,
        (FabricCapability::AdminControl, FabricCapability::AdminControl) => true,
        _ => false,
    }
}

fn discovery_pattern_covers_pattern(granted: &SubjectPattern, requested: &SubjectPattern) -> bool {
    discovery_pattern_covers_segments(granted.segments(), requested.segments())
}

fn discovery_pattern_covers_segments(granted: &[SubjectToken], requested: &[SubjectToken]) -> bool {
    match (granted.split_first(), requested.split_first()) {
        (Some((SubjectToken::Tail, _)), _) | (None, None) => true,
        (None, Some(_))
        | (Some(_), None)
        | (
            Some((SubjectToken::Literal(_), _)),
            Some((SubjectToken::One | SubjectToken::Tail, _)),
        )
        | (Some((SubjectToken::One, _)), Some((SubjectToken::Tail, _))) => false,
        (
            Some((SubjectToken::Literal(granted_head), granted_rest)),
            Some((SubjectToken::Literal(requested_head), requested_rest)),
        ) => {
            granted_head == requested_head
                && discovery_pattern_covers_segments(granted_rest, requested_rest)
        }
        (
            Some((SubjectToken::One, granted_rest)),
            Some((SubjectToken::Literal(_) | SubjectToken::One, requested_rest)),
        ) => discovery_pattern_covers_segments(granted_rest, requested_rest),
    }
}

impl RebalanceObligationSummary {
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), RebalanceError> {
        if self.publish_obligations_below_cut != 0 {
            return Err(RebalanceError::PublishFrontierNotDrained {
                unresolved: self.publish_obligations_below_cut,
            });
        }
        if self.ambiguous_consumer_lease_owners != 0 {
            return Err(RebalanceError::AmbiguousConsumerLeaseOwners {
                ambiguous: self.ambiguous_consumer_lease_owners,
            });
        }
        if self.transferred_consumer_leases < self.active_consumer_leases {
            return Err(RebalanceError::ConsumerLeaseTransferIncomplete {
                active_leases: self.active_consumer_leases,
                transferred: self.transferred_consumer_leases,
            });
        }
        if self.dangling_reply_rights != 0 {
            return Err(RebalanceError::DanglingReplyRights {
                dangling: self.dangling_reply_rights,
            });
        }
        if self.reissued_reply_rights < self.active_reply_rights {
            return Err(RebalanceError::ReplyRightsNotReissued {
                active_rights: self.active_reply_rights,
                reissued: self.reissued_reply_rights,
            });
        }
        Ok(())
    }
}

fn stable_hash<T: Hash>(value: T) -> u64 {
    let mut hasher = DetHasher::default();
    value.hash(&mut hasher);
    hasher.finish()
}

fn footprints_overlap(left: &BTreeSet<String>, right: &BTreeSet<String>) -> bool {
    left.iter().any(|entry| right.contains(entry))
}

fn compare_semantic_families(
    left: &SemanticConversationFamily,
    right: &SemanticConversationFamily,
) -> std::cmp::Ordering {
    right
        .scheduling_pressure()
        .cmp(&left.scheduling_pressure())
        .then_with(|| right.estimated_work_units.cmp(&left.estimated_work_units))
        .then_with(|| left.family_id.cmp(&right.family_id))
        .then_with(|| {
            left.protocol_subject
                .as_str()
                .cmp(right.protocol_subject.as_str())
        })
}

fn compare_candidates(
    left: &StewardCandidate,
    right: &StewardCandidate,
    temperature: CellTemperature,
) -> std::cmp::Ordering {
    candidate_score(right, temperature)
        .cmp(&candidate_score(left, temperature))
        .then_with(|| left.latency_millis.cmp(&right.latency_millis))
        .then_with(|| left.failure_domain.cmp(&right.failure_domain))
        .then_with(|| left.node_id.as_str().cmp(right.node_id.as_str()))
}

fn candidate_score(candidate: &StewardCandidate, temperature: CellTemperature) -> u64 {
    let health_score = match candidate.health {
        StewardHealth::Healthy => 400_u64,
        StewardHealth::Degraded => 250,
        StewardHealth::Draining => 100,
        StewardHealth::Unavailable => 0,
    };
    let storage_score = match candidate.storage_class {
        StorageClass::Ephemeral => 40_u64,
        StorageClass::Standard => 80,
        StorageClass::Durable => 120,
    };
    // Only an explicit RepairWitness role differentiates extra repair capacity
    // beyond ordinary stewardship during hot-cell placement.
    let hot_repair_bonus = if matches!(temperature, CellTemperature::Hot)
        && candidate.roles.contains(&NodeRole::RepairWitness)
    {
        40_u64
    } else {
        0
    };
    let latency_credit = 1_000_u64.saturating_sub(u64::from(candidate.latency_millis));

    health_score + storage_score + hot_repair_bonus + latency_credit
}

fn contains_node(nodes: &[NodeId], candidate: &NodeId) -> bool {
    nodes.iter().any(|node| node == candidate)
}

fn duplicate_node(nodes: &[NodeId]) -> Option<NodeId> {
    let mut seen = BTreeSet::new();
    for node in nodes {
        if !seen.insert(node.clone()) {
            return Some(node.clone());
        }
    }
    None
}

#[allow(clippy::result_large_err)]
fn validate_repair_bindings(
    cut_evidence: &RebalanceCutEvidence,
    candidates: &[StewardCandidate],
    plan: &RebalancePlan,
    current_epoch: CellEpoch,
    repair_policy: &RepairPolicy,
) -> Result<Vec<RepairSymbolBinding>, RebalanceError> {
    let mut by_node = BTreeMap::new();
    for binding in &cut_evidence.repair_symbols {
        if binding.cell_epoch != current_epoch {
            return Err(RebalanceError::RepairBindingWrongEpoch {
                node: binding.node_id.clone(),
                expected: current_epoch,
                actual: binding.cell_epoch,
            });
        }
        if binding.retention_generation != cut_evidence.retention_generation {
            return Err(RebalanceError::RepairBindingWrongRetentionGeneration {
                node: binding.node_id.clone(),
                expected: cut_evidence.retention_generation,
                actual: binding.retention_generation,
            });
        }
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.node_id == binding.node_id);
        let retained_steward = contains_node(&plan.next_stewards, &binding.node_id);
        if !candidate.is_some_and(StewardCandidate::can_repair) && !retained_steward {
            return Err(RebalanceError::IneligibleRepairHolder {
                node: binding.node_id.clone(),
            });
        }
        if by_node
            .insert(binding.node_id.clone(), binding.clone())
            .is_some()
        {
            return Err(RebalanceError::DuplicateRepairBinding {
                node: binding.node_id.clone(),
            });
        }
    }

    for steward in &plan.next_stewards {
        if !by_node.contains_key(steward) {
            return Err(RebalanceError::MissingStewardRepairBinding {
                node: steward.clone(),
            });
        }
    }

    let required_holders =
        repair_policy.minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
    let actual_holders = by_node.len();
    if actual_holders < required_holders {
        return Err(RebalanceError::InsufficientRepairSymbolHolders {
            required: required_holders,
            actual: actual_holders,
        });
    }

    Ok(by_node.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::super::ir::ReplySpaceRule;
    use super::super::service::{
        CompensationSemantics, EvidenceLevel, MobilityConstraint, OverloadPolicy, ServiceAdmission,
        ValidatedServiceRequest,
    };
    use super::*;
    use crate::runtime::RuntimeBuilder;
    use crate::test_utils::run_test_with_cx;
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::time::Duration;

    fn candidate(
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

    fn service_admission(
        request_id: &str,
        subject: &str,
        delivery_class: DeliveryClass,
        timeout: Option<Duration>,
        issued_at: crate::types::Time,
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

    fn grant_capability(cx: &Cx, capability: FabricCapability) {
        cx.grant_fabric_capability(capability)
            .expect("fabric capability grant");
    }

    fn grant_publish(cx: &Cx, subject: &str) {
        grant_capability(
            cx,
            FabricCapability::Publish {
                subject: SubjectPattern::parse(subject).expect("publish subject"),
            },
        );
    }

    fn grant_subscribe(cx: &Cx, subject: &str) {
        grant_capability(
            cx,
            FabricCapability::Subscribe {
                subject: SubjectPattern::parse(subject).expect("subscribe subject"),
            },
        );
    }

    fn grant_create_stream(cx: &Cx, subject: &str) {
        grant_capability(
            cx,
            FabricCapability::CreateStream {
                subject: SubjectPattern::parse(subject).expect("stream subject"),
            },
        );
    }

    fn canonical_cell_key(subject: &str) -> String {
        PlacementPolicy::default()
            .normalization
            .normalize(&SubjectPattern::parse(subject).expect("subject pattern"))
            .expect("canonical subject partition")
            .canonical_key()
    }

    #[test]
    fn stream_config_defaults_to_ephemeral_interactive() {
        let config = FabricStreamConfig::default();
        assert_eq!(config.delivery_class, DeliveryClass::EphemeralInteractive);
        assert_eq!(config.capture_policy, CapturePolicy::ExplicitOptIn);
        assert!(config.subjects.is_empty());
    }

    #[test]
    fn stream_config_rejects_empty_subject_lists() {
        let err = FabricStreamConfig::default()
            .validate()
            .expect_err("empty stream declarations must fail closed");
        assert_eq!(err.kind(), ErrorKind::ConfigError);
    }

    #[test]
    fn stream_config_rejects_overlapping_subjects() {
        let config = FabricStreamConfig {
            subjects: vec![
                SubjectPattern::parse("orders.>").expect("orders wildcard"),
                SubjectPattern::parse("orders.created").expect("orders literal"),
            ],
            ..FabricStreamConfig::default()
        };

        let err = config
            .validate()
            .expect_err("overlapping capture declarations must be rejected");
        assert_eq!(err.kind(), ErrorKind::User);
    }

    #[test]
    fn connect_rejects_blank_endpoints() {
        run_test_with_cx(|cx| async move {
            let err = Fabric::connect(&cx, "   ")
                .await
                .expect_err("blank endpoint must fail");
            assert_eq!(err.kind(), ErrorKind::ConfigError);
        });
    }

    #[test]
    fn publish_and_subscribe_round_trip_with_ephemeral_defaults() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/publish")
                .await
                .expect("connect");
            let mut subscription = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            let receipt = fabric
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");
            let message = subscription.next(&cx).await.expect("message");

            assert_eq!(receipt.ack_kind, AckKind::Accepted);
            assert_eq!(receipt.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(message.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());
        });
    }

    #[test]
    fn request_uses_same_surface_and_returns_reply() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            grant_subscribe(&cx, "service.lookup");
            let fabric = Fabric::connect(&cx, "node1:4222/request")
                .await
                .expect("connect");
            let reply = fabric
                .request(&cx, "service.lookup", b"lookup".to_vec())
                .await
                .expect("request");

            assert_eq!(reply.ack_kind, AckKind::Accepted);
            assert_eq!(reply.delivery_class, DeliveryClass::EphemeralInteractive);
            assert_eq!(reply.subject.as_str(), "service.lookup");
            assert_eq!(reply.payload, b"lookup".to_vec());
        });
    }

    #[test]
    fn certified_request_emits_certificates_and_resolves_obligations() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            grant_subscribe(&cx, "service.>");
            let fabric = Fabric::connect(&cx, "node1:4222/certified")
                .await
                .expect("connect");
            let mut subscription = fabric.subscribe(&cx, "service.>").await.expect("subscribe");
            let mut ledger = ObligationLedger::new();
            let admission = service_admission(
                "req-certified",
                "service.lookup",
                DeliveryClass::ObligationBacked,
                Some(Duration::from_secs(5)),
                cx.now(),
            );

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
            let published = subscription.next(&cx).await.expect("published message");

            assert_eq!(published.delivery_class, DeliveryClass::ObligationBacked);
            assert_eq!(certified.reply.ack_kind, AckKind::Received);
            assert_eq!(
                certified.reply.delivery_class,
                DeliveryClass::ObligationBacked
            );
            assert_eq!(certified.reply.subject.as_str(), "service.lookup");
            assert_eq!(certified.reply.payload, b"lookup".to_vec());
            assert!(certified.request_certificate.validate().is_ok());
            assert!(certified.reply_certificate.validate().is_ok());
            assert_eq!(
                certified.reply_certificate.delivery_class,
                DeliveryClass::ObligationBacked
            );
            assert!(certified.reply_certificate.service_obligation_id.is_some());
            assert_eq!(
                certified.reply_certificate.service_latency,
                Duration::from_nanos(
                    certified
                        .reply_certificate
                        .issued_at
                        .duration_since(admission.certificate.issued_at)
                )
            );
            assert_eq!(
                certified
                    .delivery_receipt
                    .as_ref()
                    .map(|receipt| receipt.delivery_boundary),
                Some(AckKind::Received)
            );
            assert_eq!(ledger.pending_count(), 0);
            assert!(ledger.check_leaks().is_clean());
        });
    }

    #[test]
    fn certified_request_rejects_non_obligation_delivery_classes() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/certified-reject")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();
            let admission = service_admission(
                "req-ephemeral",
                "service.lookup",
                DeliveryClass::EphemeralInteractive,
                None,
                cx.now(),
            );

            let err = fabric
                .request_certified(
                    &cx,
                    &mut ledger,
                    &admission,
                    "callee-a",
                    b"lookup".to_vec(),
                    AckKind::Accepted,
                    false,
                )
                .await
                .expect_err("ephemeral class must use plain request");

            assert_eq!(err.kind(), ErrorKind::User);
            assert!(
                err.to_string().contains("obligation-backed or stronger"),
                "unexpected error: {err}"
            );
            assert!(ledger.is_empty());
        });
    }

    #[test]
    fn stream_accepts_explicit_subjects_and_preserves_endpoint() {
        run_test_with_cx(|cx| async move {
            grant_create_stream(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/stream")
                .await
                .expect("connect");
            let handle = fabric
                .stream(
                    &cx,
                    FabricStreamConfig {
                        subjects: vec![SubjectPattern::parse("orders.>").expect("pattern")],
                        delivery_class: DeliveryClass::DurableOrdered,
                        capture_policy: CapturePolicy::ExplicitOptIn,
                        request_timeout: Some(Duration::from_secs(5)),
                    },
                )
                .await
                .expect("stream");

            assert_eq!(handle.endpoint(), "node1:4222/stream");
            assert_eq!(
                handle.config().delivery_class,
                DeliveryClass::DurableOrdered
            );
            assert_eq!(handle.config().subjects.len(), 1);
        });
    }

    #[test]
    fn stream_requires_create_stream_capability() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/stream-denied")
                .await
                .expect("connect");

            let err = fabric
                .stream(
                    &cx,
                    FabricStreamConfig {
                        subjects: vec![SubjectPattern::parse("orders.>").expect("pattern")],
                        delivery_class: DeliveryClass::DurableOrdered,
                        capture_policy: CapturePolicy::ExplicitOptIn,
                        request_timeout: Some(Duration::from_secs(5)),
                    },
                )
                .await
                .expect_err("stream declaration without create-stream capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn stream_requires_capability_for_each_declared_subject() {
        run_test_with_cx(|cx| async move {
            grant_create_stream(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/stream-partial")
                .await
                .expect("connect");

            let err = fabric
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
                .expect_err("partially authorized stream declarations must fail closed");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 2);
            assert_eq!(decisions[0].audit.action_chosen, "allow");
            assert_eq!(decisions[1].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn same_endpoint_connections_share_published_messages() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let publisher = Fabric::connect(&cx, "node1:4222/shared")
                .await
                .expect("connect");
            let subscriber = Fabric::connect(&cx, "node1:4222/shared")
                .await
                .expect("connect");
            let mut subscription = subscriber
                .subscribe(&cx, "orders.>")
                .await
                .expect("subscribe");

            publisher
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");
            let message = subscription.next(&cx).await.expect("message");

            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());
        });
    }

    #[test]
    fn different_endpoints_do_not_share_messages() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let left = Fabric::connect(&cx, "node1:4222/left")
                .await
                .expect("connect");
            let right = Fabric::connect(&cx, "node1:4222/right")
                .await
                .expect("connect");
            let mut subscription = right.subscribe(&cx, "orders.>").await.expect("subscribe");

            left.publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");

            assert_eq!(subscription.next(&cx).await, None);
        });
    }

    #[test]
    fn late_subscriber_does_not_replay_prior_messages_on_shared_endpoint() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let publisher = Fabric::connect(&cx, "node1:4222/live-only")
                .await
                .expect("connect");
            let late_subscriber = Fabric::connect(&cx, "node1:4222/live-only")
                .await
                .expect("connect");

            publisher
                .publish(&cx, "orders.created", b"before-subscribe".to_vec())
                .await
                .expect("publish");

            let mut subscription = late_subscriber
                .subscribe(&cx, "orders.>")
                .await
                .expect("subscribe");

            assert_eq!(
                subscription.next(&cx).await,
                None,
                "late subscribers should not replay pre-subscription packet-plane history"
            );

            publisher
                .publish(&cx, "orders.created", b"after-subscribe".to_vec())
                .await
                .expect("publish");

            let message = subscription.next(&cx).await.expect("live message");
            assert_eq!(message.payload, b"after-subscribe".to_vec());
        });
    }

    #[test]
    fn publish_creates_subject_cells_and_prunes_after_delivery() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/cell-create")
                .await
                .expect("connect");
            let mut subscription = fabric
                .subscribe(&cx, "orders.created")
                .await
                .expect("subscribe");

            fabric
                .publish(&cx, "orders.created", b"payload".to_vec())
                .await
                .expect("publish");

            {
                let state = fabric.state.lock();
                let cell_key = canonical_cell_key("orders.created");
                let cell = state.cells.get(&cell_key).expect("cell runtime");
                assert_eq!(state.cells.len(), 1);
                assert_eq!(state.cell_routes.len(), 1);
                assert_eq!(cell.cell.subject_partition.canonical_key(), cell_key);
                assert_eq!(cell.buffer.len(), 1);
                assert_eq!(cell.state, FabricCellBufferState::Buffered);
            }

            let message = subscription.next(&cx).await.expect("message");
            assert_eq!(message.subject.as_str(), "orders.created");
            assert_eq!(message.payload, b"payload".to_vec());

            let state = fabric.state.lock();
            let cell = state
                .cells
                .get(&canonical_cell_key("orders.created"))
                .expect("cell runtime");
            assert!(cell.buffer.is_empty(), "consumed messages should be pruned");
            assert_eq!(cell.state, FabricCellBufferState::Empty);
        });
    }

    #[test]
    fn wildcard_subscription_reads_messages_across_multiple_cells_in_publish_order() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.>");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/fanout")
                .await
                .expect("connect");
            let mut subscription = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            fabric
                .publish(&cx, "orders.created", b"created".to_vec())
                .await
                .expect("first publish");
            fabric
                .publish(&cx, "orders.updated", b"updated".to_vec())
                .await
                .expect("second publish");

            let first = subscription.next(&cx).await.expect("first message");
            let second = subscription.next(&cx).await.expect("second message");

            assert_eq!(first.subject.as_str(), "orders.created");
            assert_eq!(first.payload, b"created".to_vec());
            assert_eq!(second.subject.as_str(), "orders.updated");
            assert_eq!(second.payload, b"updated".to_vec());
            assert_eq!(subscription.next(&cx).await, None);

            let state = fabric.state.lock();
            assert_eq!(state.cells.len(), 2);
            assert!(
                state
                    .cells
                    .contains_key(&canonical_cell_key("orders.created"))
            );
            assert!(
                state
                    .cells
                    .contains_key(&canonical_cell_key("orders.updated"))
            );
        });
    }

    #[test]
    fn publish_backpressures_full_cells_until_subscribers_drain_them() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/backpressure")
                .await
                .expect("connect");
            fabric.state.lock().cell_buffer_capacity = 1;
            let mut subscription = fabric
                .subscribe(&cx, "orders.created")
                .await
                .expect("subscribe");

            fabric
                .publish(&cx, "orders.created", b"first".to_vec())
                .await
                .expect("first publish");

            let err = fabric
                .publish(&cx, "orders.created", b"second".to_vec())
                .await
                .expect_err("full cell should reject a second publish");
            assert_eq!(err.kind(), ErrorKind::ChannelFull);

            let cell_key = canonical_cell_key("orders.created");
            {
                let state = fabric.state.lock();
                let cell = state.cells.get(&cell_key).expect("cell runtime");
                assert_eq!(cell.state, FabricCellBufferState::Backpressured);
                assert_eq!(cell.buffer.len(), 1);
            }

            let drained = subscription.next(&cx).await.expect("drained message");
            assert_eq!(drained.payload, b"first".to_vec());

            fabric
                .publish(&cx, "orders.created", b"third".to_vec())
                .await
                .expect("drain should restore capacity");

            let delivered = subscription.next(&cx).await.expect("delivered message");
            assert_eq!(delivered.payload, b"third".to_vec());
        });
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]

        #[test]
        fn full_wildcard_subscription_preserves_publish_order_and_reuses_canonical_cells(
            subject_indexes in proptest::collection::vec(0usize..4, 1..8)
        ) {
            let endpoint = format!(
                "node1:4222/property-{:016x}",
                stable_hash(("fabric-property-order", &subject_indexes))
            );
            let runtime = RuntimeBuilder::current_thread()
                .build()
                .expect("failed to build runtime");
            let cx = Cx::for_testing();
            grant_publish(&cx, ">");
            grant_subscribe(&cx, ">");

            runtime.block_on(async move {
                let fabric = Fabric::connect(&cx, endpoint).await.expect("connect");
                let mut subscription = fabric.subscribe(&cx, ">").await.expect("subscribe");
                let subjects = [
                    "orders.created",
                    "orders.updated",
                    "_INBOX.orders.region.req-1",
                    "_INBOX.orders.region.req-2",
                ];

                for (ordinal, index) in subject_indexes.iter().copied().enumerate() {
                    fabric
                        .publish(&cx, subjects[index], vec![ordinal as u8])
                        .await
                        .expect("publish");
                }

                for (ordinal, index) in subject_indexes.iter().copied().enumerate() {
                    let message = subscription.next(&cx).await.expect("message");
                    assert_eq!(message.subject.as_str(), subjects[index]);
                    assert_eq!(message.payload, vec![ordinal as u8]);
                }
                assert_eq!(subscription.next(&cx).await, None);

                let expected_cells = subject_indexes
                    .iter()
                    .map(|index| canonical_cell_key(subjects[*index]))
                    .collect::<BTreeSet<_>>();
                let state = fabric.state.lock();
                let actual_cells = state.cells.keys().cloned().collect::<BTreeSet<_>>();
                assert_eq!(actual_cells, expected_cells);
            });
        }
    }

    #[test]
    fn parse_subject_pattern_trims_outer_whitespace() {
        let pattern = SubjectPattern::parse("  orders.created.>  ").expect("pattern");
        assert_eq!(pattern.canonical_key(), "orders.created.>");
    }

    #[test]
    fn parse_subject_pattern_rejects_non_terminal_tail_wildcard() {
        let err = SubjectPattern::parse("orders.>.created").expect_err("should reject");
        assert_eq!(err, SubjectPatternError::TailWildcardMustBeTerminal);
    }

    #[test]
    fn reply_space_aggregation_compacts_ephemeral_suffixes() {
        let pattern =
            SubjectPattern::parse("_INBOX.orders.region.instance.12345").expect("pattern");
        let compacted = pattern.aggregate_reply_space(ReplySpaceCompactionPolicy {
            enabled: true,
            preserve_segments: 3,
        });
        assert_eq!(compacted.canonical_key(), "_INBOX.orders.region.>");
    }

    #[test]
    fn overlap_detection_handles_literals_and_wildcards() {
        let left = SubjectPattern::parse("orders.*").expect("left");
        let right = SubjectPattern::parse("orders.created").expect("right");
        let third = SubjectPattern::parse("metrics.>").expect("third");
        let fourth = SubjectPattern::parse("orders.created").expect("fourth");

        assert!(left.overlaps(&right));
        assert!(!left.overlaps(&third));
        assert!(third.overlaps(&SubjectPattern::parse("metrics.region.1").expect("tail")));
        assert!(right.overlaps(&fourth));
    }

    #[test]
    fn tail_wildcard_requires_a_non_empty_suffix() {
        let wildcard = SubjectPattern::parse("orders.>").expect("wildcard");
        let bare_prefix = SubjectPattern::parse("orders").expect("bare prefix");

        assert!(!wildcard.overlaps(&bare_prefix));
        assert!(wildcard.overlaps(&SubjectPattern::parse("orders.created").expect("expanded")));
    }

    #[test]
    fn normalization_policy_applies_prefix_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "orders.created");
    }

    #[test]
    fn normalization_policy_chains_prefix_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                SubjectPrefixMorphism::new("orders", "canonical.orders").expect("morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "canonical.orders.created");
    }

    #[test]
    fn normalization_policy_rejects_morphism_cycles() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                SubjectPrefixMorphism::new("orders", "svc.orders").expect("morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let err = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect_err("should reject cycle");

        assert!(matches!(err, FabricError::CyclicSubjectMorphisms { .. }));
    }

    #[test]
    fn normalization_policy_rejects_conflicting_morphisms() {
        let policy = NormalizationPolicy {
            morphisms: vec![
                SubjectPrefixMorphism::new("svc.orders", "orders").expect("left morphism"),
                SubjectPrefixMorphism::new("svc.orders", "legacy.orders").expect("right morphism"),
            ],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };

        let err = policy
            .normalize(&SubjectPattern::parse("svc.orders.created").expect("pattern"))
            .expect_err("conflicting rewrites must fail closed");

        assert!(matches!(
            err,
            FabricError::ConflictingSubjectMorphisms { .. }
        ));
    }

    #[test]
    fn normalization_policy_can_compact_reply_space_after_morphism() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc", "_INBOX").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };

        let canonical = policy
            .normalize(&SubjectPattern::parse("svc.orders.region.instance.123").expect("pattern"))
            .expect("normalized");

        assert_eq!(canonical.canonical_key(), "_INBOX.orders.region.>");
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_deduplicates_aliases() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };
        let partitions = vec![
            SubjectPattern::parse("orders.created").expect("canonical"),
            SubjectPattern::parse("svc.orders.created").expect("alias"),
            SubjectPattern::parse("orders.created").expect("duplicate"),
        ];

        let canonical = policy
            .canonicalize_partitions(&partitions)
            .expect("canonical partitions");

        assert_eq!(canonical.len(), 1);
        assert_eq!(canonical[0].canonical_key(), "orders.created");
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_preserves_nested_wildcards() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc", "canonical").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };
        let partitions = vec![
            SubjectPattern::parse("svc.region.*.>").expect("nested wildcard"),
            SubjectPattern::parse("svc.metrics.*").expect("disjoint wildcard"),
        ];

        let canonical = policy
            .canonicalize_partitions(&partitions)
            .expect("canonical partitions");
        let keys = canonical
            .into_iter()
            .map(|pattern| pattern.canonical_key())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            vec![
                "canonical.metrics.*".to_string(),
                "canonical.region.*.>".to_string(),
            ]
        );
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_rejects_overlap_after_normalization() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy::default(),
        };
        let partitions = vec![
            SubjectPattern::parse("svc.orders.created").expect("alias"),
            SubjectPattern::parse("orders.*").expect("wildcard"),
        ];

        let err = policy
            .canonicalize_partitions(&partitions)
            .expect_err("overlap after normalization must fail closed");

        assert!(matches!(
            err,
            FabricError::OverlappingSubjectPartitions { .. }
        ));
    }

    #[test]
    fn normalization_policy_canonicalize_partitions_is_order_stable() {
        let policy = NormalizationPolicy {
            morphisms: vec![SubjectPrefixMorphism::new("svc", "canonical").expect("morphism")],
            reply_space_policy: ReplySpaceCompactionPolicy {
                enabled: true,
                preserve_segments: 3,
            },
        };
        let partitions = vec![
            SubjectPattern::parse("svc.region.two.*").expect("two"),
            SubjectPattern::parse("_INBOX.orders.region.instance.9").expect("reply"),
            SubjectPattern::parse("svc.region.one.>").expect("one"),
        ];

        let canonical = policy
            .canonicalize_partitions(&partitions)
            .expect("canonical partitions");
        let keys = canonical
            .into_iter()
            .map(|pattern| pattern.canonical_key())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            vec![
                "_INBOX.orders.region.>".to_string(),
                "canonical.region.one.>".to_string(),
                "canonical.region.two.*".to_string(),
            ]
        );
    }

    #[test]
    fn non_overlapping_validation_rejects_conflicts() {
        let patterns = vec![
            SubjectPattern::parse("orders.created").expect("orders.created"),
            SubjectPattern::parse("orders.*").expect("orders.*"),
        ];
        let err = SubjectPattern::validate_non_overlapping(&patterns).expect_err("should overlap");
        assert!(matches!(
            err,
            FabricError::OverlappingSubjectPartitions { .. }
        ));
    }

    #[test]
    fn cell_id_is_stable_for_same_partition_and_epoch() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let epoch = CellEpoch::new(7, 3);
        let first = CellId::for_partition(epoch, &partition);
        let second = CellId::for_partition(epoch, &partition);

        assert_eq!(first, second);
        assert_ne!(
            first,
            CellId::for_partition(CellEpoch::new(8, 3), &partition)
        );
    }

    #[test]
    fn alias_subjects_collapse_to_the_same_subject_cell() {
        let policy = PlacementPolicy {
            normalization: NormalizationPolicy {
                morphisms: vec![
                    SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                ],
                ..NormalizationPolicy::default()
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 9),
        ];
        let epoch = CellEpoch::new(17, 4);

        let canonical = SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("canonical"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("canonical cell");
        let aliased = SubjectCell::new(
            &SubjectPattern::parse("svc.orders.created").expect("aliased"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("aliased cell");

        assert_eq!(canonical.subject_partition, aliased.subject_partition);
        assert_eq!(canonical.cell_id, aliased.cell_id);
        assert_eq!(canonical.steward_set, aliased.steward_set);
    }

    #[test]
    fn thermal_hysteresis_damps_temperature_flips() {
        let policy = PlacementPolicy::default();

        assert_eq!(
            policy.recommend_temperature(CellTemperature::Warm, ObservedCellLoad::new(64)),
            CellTemperature::Warm
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Warm, ObservedCellLoad::new(32)),
            CellTemperature::Cold
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Hot, ObservedCellLoad::new(768)),
            CellTemperature::Hot
        );
        assert_eq!(
            policy.recommend_temperature(CellTemperature::Hot, ObservedCellLoad::new(256)),
            CellTemperature::Warm
        );
    }

    #[test]
    fn rebalance_budget_limits_steward_churn() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 5,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 1,
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];
        let current_stewards = vec![NodeId::new("node-a")];

        let plan = policy
            .plan_rebalance(
                &partition,
                &candidates,
                &current_stewards,
                CellTemperature::Cold,
                ObservedCellLoad::new(2_048),
            )
            .expect("rebalance");

        assert_eq!(plan.next_temperature, CellTemperature::Hot);
        assert_eq!(plan.added_stewards.len(), 1);
        assert!(plan.removed_stewards.is_empty());
        assert_eq!(plan.next_stewards.len(), 2);
        assert!(
            plan.next_stewards
                .iter()
                .any(|node| node.as_str() == "node-a")
        );
    }

    #[test]
    fn rebalance_planning_uses_normalized_subject_partition() {
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 1,
            hot_stewards: 1,
            candidate_pool_size: 4,
            normalization: NormalizationPolicy {
                morphisms: vec![
                    SubjectPrefixMorphism::new("svc.orders", "orders").expect("morphism"),
                ],
                ..NormalizationPolicy::default()
            },
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
            candidate("node-d", "rack-d", StorageClass::Standard, 8),
            candidate("node-e", "rack-e", StorageClass::Standard, 9),
        ];
        let alias_subjects = [
            "svc.orders.created",
            "svc.orders.updated",
            "svc.orders.cancelled",
            "svc.orders.fulfilled",
            "svc.orders.archived",
            "svc.orders.audit",
            "svc.orders.retry",
            "svc.orders.snapshot",
        ];

        let (aliased, current_stewards) = alias_subjects
            .iter()
            .find_map(|raw| {
                let aliased = SubjectPattern::parse(raw).expect("pattern");
                let canonical = policy.normalization.normalize(&aliased).expect("canonical");
                let raw_stewards = policy
                    .select_stewards(&aliased, &candidates, CellTemperature::Warm)
                    .expect("raw placement");
                let canonical_stewards = policy
                    .select_stewards(&canonical, &candidates, CellTemperature::Warm)
                    .expect("canonical placement");

                (raw_stewards != canonical_stewards).then_some((aliased, canonical_stewards))
            })
            .expect("expected at least one alias subject to hash differently before normalization");

        let plan = policy
            .plan_rebalance(
                &aliased,
                &candidates,
                &current_stewards,
                CellTemperature::Warm,
                ObservedCellLoad::new(256),
            )
            .expect("rebalance");

        assert_eq!(plan.next_stewards, current_stewards);
        assert!(plan.added_stewards.is_empty());
        assert!(plan.removed_stewards.is_empty());
    }

    #[test]
    fn placement_is_deterministic_and_filters_ineligible_nodes() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 2,
            candidate_pool_size: 4,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 8),
            candidate("node-b", "rack-b", StorageClass::Standard, 12),
            StewardCandidate::new(NodeId::new("observer"), "rack-c")
                .with_role(NodeRole::Subscriber)
                .with_health(StewardHealth::Healthy),
        ];

        let first = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("placement");
        let second = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("placement");

        assert_eq!(first, second);
        assert!(first.iter().all(|node| node.as_str() != "observer"));
    }

    #[test]
    fn hot_cells_widen_steward_set() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 5,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];

        let cold = policy
            .select_stewards(&partition, &candidates, CellTemperature::Cold)
            .expect("cold");
        let hot = policy
            .select_stewards(&partition, &candidates, CellTemperature::Hot)
            .expect("hot");

        assert_eq!(cold.len(), 1);
        assert_eq!(hot.len(), 3);
    }

    #[test]
    fn placement_prefers_failure_domain_diversity() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 2,
            candidate_pool_size: 4,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-a", StorageClass::Durable, 5),
            candidate("node-c", "rack-b", StorageClass::Standard, 6),
            candidate("node-d", "rack-c", StorageClass::Standard, 7),
        ];

        let selected = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("selected");
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().any(|node| node.as_str() == "node-a"));
        assert!(
            selected
                .iter()
                .any(|node| node.as_str() == "node-c" || node.as_str() == "node-d")
        );
    }

    #[test]
    fn placement_falls_back_to_high_latency_candidates_to_fill_steward_set() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 3,
            warm_stewards: 3,
            hot_stewards: 3,
            candidate_pool_size: 3,
            max_latency_millis: 20,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 7),
            candidate("node-c", "rack-c", StorageClass::Standard, 250),
        ];

        let selected = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("selected");

        assert_eq!(selected.len(), 3);
        assert!(selected.iter().any(|node| node.as_str() == "node-c"));
    }

    #[test]
    fn hot_placement_prefers_explicit_repair_witness_capacity() {
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 1,
            hot_stewards: 1,
            candidate_pool_size: 2,
            max_latency_millis: 20,
            ..PlacementPolicy::default()
        };
        let candidates = vec![
            StewardCandidate::new(NodeId::new("node-a"), "rack-a")
                .with_role(NodeRole::Steward)
                .with_storage_class(StorageClass::Standard)
                .with_latency_millis(5),
            StewardCandidate::new(NodeId::new("node-b"), "rack-b")
                .with_role(NodeRole::Steward)
                .with_role(NodeRole::RepairWitness)
                .with_storage_class(StorageClass::Standard)
                .with_latency_millis(5),
        ];

        let warm = policy
            .select_stewards(&partition, &candidates, CellTemperature::Warm)
            .expect("warm");
        let hot = policy
            .select_stewards(&partition, &candidates, CellTemperature::Hot)
            .expect("hot");

        assert_eq!(warm, vec![NodeId::new("node-a")]);
        assert_eq!(hot, vec![NodeId::new("node-b")]);
    }

    #[test]
    fn subject_cell_construction_builds_capsules_and_compacts_reply_space() {
        let subject_partition =
            SubjectPattern::parse("_INBOX.orders.region.instance.123").expect("pattern");
        let policy = PlacementPolicy {
            cold_stewards: 2,
            warm_stewards: 2,
            hot_stewards: 3,
            candidate_pool_size: 4,
            normalization: NormalizationPolicy {
                morphisms: Vec::new(),
                reply_space_policy: ReplySpaceCompactionPolicy {
                    enabled: true,
                    preserve_segments: 3,
                },
            },
            ..PlacementPolicy::default()
        };
        let data_capsule = DataCapsule {
            temperature: CellTemperature::Warm,
            retained_message_blocks: 4,
        };
        let candidates = vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Standard, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
        ];

        let cell = SubjectCell::new(
            &subject_partition,
            CellEpoch::new(11, 2),
            &candidates,
            &policy,
            RepairPolicy::default(),
            data_capsule,
        )
        .expect("cell");

        assert_eq!(
            cell.subject_partition.canonical_key(),
            "_INBOX.orders.region.>"
        );
        assert_eq!(
            cell.control_capsule.active_sequencer_holder(),
            cell.steward_set.first()
        );
        assert_eq!(cell.steward_set.len(), 2);
    }

    fn control_capsule() -> ControlCapsuleV1 {
        let epoch = CellEpoch::new(23, 4);
        let partition = SubjectPattern::parse("orders.created").expect("pattern");
        let cell_id = CellId::for_partition(epoch, &partition);
        ControlCapsuleV1::new(
            cell_id,
            vec![NodeId::new("node-a"), NodeId::new("node-b")],
            epoch,
        )
    }

    fn rebalance_policy() -> PlacementPolicy {
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

    fn rebalance_candidates() -> Vec<StewardCandidate> {
        vec![
            candidate("node-a", "rack-a", StorageClass::Durable, 5),
            candidate("node-b", "rack-b", StorageClass::Durable, 6),
            candidate("node-c", "rack-c", StorageClass::Standard, 7),
            candidate("node-d", "rack-d", StorageClass::Standard, 8),
            candidate("node-e", "rack-e", StorageClass::Standard, 9),
            candidate("node-f", "rack-f", StorageClass::Standard, 10),
        ]
    }

    fn cold_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule::default(),
        )
        .expect("cold cell")
    }

    fn warm_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule {
                temperature: CellTemperature::Warm,
                retained_message_blocks: 4,
            },
        )
        .expect("warm cell")
    }

    fn hot_subject_cell(candidates: &[StewardCandidate], policy: &PlacementPolicy) -> SubjectCell {
        SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            candidates,
            policy,
            RepairPolicy {
                recoverability_target: 3,
                cold_witnesses: 1,
                hot_witnesses: 2,
            },
            DataCapsule {
                temperature: CellTemperature::Hot,
                retained_message_blocks: 6,
            },
        )
        .expect("hot cell")
    }

    fn repair_bindings_for(
        cell: &SubjectCell,
        plan: &RebalancePlan,
        candidates: &[StewardCandidate],
        retention_generation: u64,
        required_holders: usize,
    ) -> Vec<RepairSymbolBinding> {
        let mut holders = plan.next_stewards.clone();
        for candidate in candidates {
            if holders.len() >= required_holders {
                break;
            }
            if contains_node(&holders, &candidate.node_id) || !candidate.can_repair() {
                continue;
            }
            holders.push(candidate.node_id.clone());
        }
        holders
            .into_iter()
            .map(|node_id| RepairSymbolBinding::new(node_id, cell.epoch, retention_generation))
            .collect()
    }

    fn successful_rebalance_evidence(
        cell: &SubjectCell,
        plan: &RebalancePlan,
        candidates: &[StewardCandidate],
        retention_generation: u64,
    ) -> RebalanceCutEvidence {
        let required_holders = cell
            .repair_policy
            .minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
        RebalanceCutEvidence {
            next_sequencer: plan
                .added_stewards
                .first()
                .cloned()
                .unwrap_or_else(|| plan.next_stewards[0].clone()),
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
            repair_symbols: repair_bindings_for(
                cell,
                plan,
                candidates,
                retention_generation,
                required_holders,
            ),
        }
    }

    fn split_capable_kernel(
        name: &str,
        interference_class: &str,
        obligation_footprint: &str,
    ) -> ProtocolKernel {
        ProtocolKernel::new(name, DeliveryClass::ObligationBacked)
            .with_interference_class(interference_class)
            .with_obligation_footprint(obligation_footprint)
            .allow_reordering()
            .allow_parallel_issue()
    }

    fn semantic_family(
        family_id: &str,
        kernel: ProtocolKernel,
        shared_state_footprint: &str,
        estimated_work_units: usize,
    ) -> SemanticConversationFamily {
        SemanticConversationFamily::new(
            family_id,
            SubjectPattern::parse("orders.created").expect("family subject"),
            kernel,
        )
        .with_shared_state_footprint(shared_state_footprint)
        .with_estimated_work_units(estimated_work_units)
    }

    fn subscribe_capability(subject: &str) -> FabricCapability {
        FabricCapability::Subscribe {
            subject: SubjectPattern::parse(subject).expect("capability subject"),
        }
    }

    fn discovery_policy(viewer_capabilities: Vec<FabricCapability>) -> DiscoveryNegotiationPolicy {
        DiscoveryNegotiationPolicy {
            trusted_issuers: BTreeSet::from([NodeId::new("admission-authority")]),
            supported_policy_versions: BTreeSet::from([1, 3]),
            viewer_capabilities,
            lease_ttl_millis: 30_000,
        }
    }

    fn discovery_interest(subject: &str, subscribers: u64) -> DiscoveryInterestSummaryEntry {
        DiscoveryInterestSummaryEntry {
            subject: SubjectPattern::parse(subject).expect("interest subject"),
            subscribers,
        }
    }

    fn discovery_credential(
        node: &str,
        admitted_capabilities: Vec<FabricCapability>,
    ) -> DiscoveryAdmissionCredential {
        DiscoveryAdmissionCredential {
            subject: NodeId::new(node),
            issuer: NodeId::new("admission-authority"),
            membership_epoch: 11,
            admitted_capabilities,
            signature: format!("sig:{node}:v1"),
        }
    }

    fn discovery_hello(
        node: &str,
        bootstrap: DiscoveryBootstrap,
        capability_set: Vec<FabricCapability>,
        credential_capabilities: Vec<FabricCapability>,
        interest_summary: Vec<DiscoveryInterestSummaryEntry>,
        stewardship_leases: Vec<DiscoveryStewardLeaseView>,
        recent_control_epochs: Vec<DiscoveryControlEpochView>,
    ) -> DiscoveryHello {
        let suggested_cells = recent_control_epochs
            .iter()
            .map(|view| view.cell_id)
            .collect();
        DiscoveryHello {
            node_id: NodeId::new(node),
            bootstrap,
            capability_set,
            credential: discovery_credential(node, credential_capabilities),
            supported_policy_versions: BTreeSet::from([2, 3]),
            resource_budget: DiscoveryResourceBudget {
                storage_bytes_available: 64 * 1024 * 1024,
                uplink_kib_per_sec: 4_096,
                repair_slots: 3,
            },
            interest_summary,
            stewardship_leases,
            recent_control_epochs,
            advisory_hints: DiscoveryAdvisoryHints {
                membership: Some(MembershipRecord::new(
                    4,
                    crate::messaging::control::MembershipState::Healthy,
                    1_234,
                    180,
                )),
                suggested_cells,
            },
        }
    }

    fn discovery_blinded_fingerprint(session_id: DiscoverySessionId, subject: &str) -> u64 {
        stable_hash((
            "fabric::discovery::interest",
            session_id.raw(),
            SubjectPattern::parse(subject)
                .expect("blinded subject")
                .canonical_key(),
        ))
    }

    #[test]
    fn discovery_session_establishes_handshake_with_explicit_lease_obligation() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-a",
            DiscoveryBootstrap::SeedList(vec![NodeId::new("seed-a"), NodeId::new("seed-b")]),
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 9)],
            vec![DiscoveryStewardLeaseView {
                cell_id: cell.cell_id,
                lease: cell
                    .control_capsule
                    .active_sequencer_lease()
                    .expect("active lease"),
            }],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: cell.control_capsule.control_epoch(),
            }],
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect("session");

        assert_eq!(session.state, DiscoverySessionState::Established);
        assert_eq!(session.policy_version, 3);
        assert_eq!(session.authoritative_stewardship.len(), 1);
        assert_eq!(session.lease_obligation.peer_node, NodeId::new("peer-a"));
        assert_eq!(session.lease_obligation.ttl_millis, 30_000);
        assert_eq!(
            session
                .transitions()
                .iter()
                .map(DiscoverySessionTransition::kind)
                .collect::<Vec<_>>(),
            vec![
                "bootstrap_validated",
                "peer_authenticated",
                "interest_summary_scoped",
                "authority_validated",
                "lease_bound",
                "established",
            ]
        );
    }

    #[test]
    fn discovery_session_rejects_capability_escalation_outside_signed_admission() {
        let granted = subscribe_capability("tenant.alpha.orders.>");
        let escalated = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-b",
            DiscoveryBootstrap::SelfDiscover,
            vec![escalated.clone()],
            vec![granted],
            vec![discovery_interest("tenant.alpha.orders.>", 3)],
            Vec::new(),
            Vec::new(),
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("capability escalation must fail");

        assert_eq!(
            err,
            DiscoveryError::CapabilityEscalation {
                node: NodeId::new("peer-b"),
                capability: escalated,
            }
        );
    }

    #[test]
    fn discovery_interest_summary_blinds_namespaces_outside_viewer_capability() {
        let hello = discovery_hello(
            "peer-c",
            DiscoveryBootstrap::SelfDiscover,
            vec![
                subscribe_capability("tenant.alpha.>"),
                subscribe_capability("tenant.beta.>"),
            ],
            vec![
                subscribe_capability("tenant.alpha.>"),
                subscribe_capability("tenant.beta.>"),
            ],
            vec![
                discovery_interest("tenant.alpha.orders.>", 7),
                discovery_interest("tenant.beta.orders.>", 11),
            ],
            Vec::new(),
            Vec::new(),
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect("session");

        assert_eq!(
            session.peer_interest_advertisements[0],
            DiscoveryInterestAdvertisement::Scoped {
                subject: SubjectPattern::parse("tenant.alpha.orders.>").expect("alpha"),
                subscribers: 7,
            }
        );
        assert_eq!(
            session.peer_interest_advertisements[1],
            DiscoveryInterestAdvertisement::Blinded {
                subject_fingerprint: discovery_blinded_fingerprint(
                    session.session_id,
                    "tenant.beta.orders.>",
                ),
                subscribers: 11,
            }
        );
    }

    #[test]
    fn discovery_rejects_interest_summary_outside_peer_capability_scope() {
        let capability = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-c2",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability],
            vec![discovery_interest("tenant.beta.orders.>", 11)],
            Vec::new(),
            Vec::new(),
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("interest summary outside peer capability scope must fail");

        assert_eq!(
            err,
            DiscoveryError::InterestSummaryOutsideCapabilitySet {
                node: NodeId::new("peer-c2"),
                subject: SubjectPattern::parse("tenant.beta.orders.>").expect("beta"),
            }
        );
    }

    #[test]
    fn discovery_namespace_visibility_is_narrower_than_membership() {
        let hello = discovery_hello(
            "peer-d",
            DiscoveryBootstrap::SelfDiscover,
            vec![subscribe_capability("tenant.alpha.>")],
            vec![subscribe_capability("tenant.alpha.>")],
            vec![discovery_interest("tenant.alpha.orders.>", 5)],
            Vec::new(),
            Vec::new(),
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(Vec::new()),
        )
        .expect("session");

        assert!(session.advisory_hints.membership.is_some());
        assert_eq!(
            session.peer_interest_advertisements,
            vec![DiscoveryInterestAdvertisement::Blinded {
                subject_fingerprint: discovery_blinded_fingerprint(
                    session.session_id,
                    "tenant.alpha.orders.>",
                ),
                subscribers: 5,
            }]
        );
    }

    #[test]
    fn discovery_session_blinding_is_not_linkable_across_distinct_credentials() {
        let hello_v1 = discovery_hello(
            "peer-d1",
            DiscoveryBootstrap::SelfDiscover,
            vec![subscribe_capability("tenant.alpha.>")],
            vec![subscribe_capability("tenant.alpha.>")],
            vec![discovery_interest("tenant.alpha.orders.>", 5)],
            Vec::new(),
            Vec::new(),
        );
        let mut hello_v2 = hello_v1.clone();
        hello_v2.credential.signature = "sig:peer-d1:v2".to_owned();

        let policy = discovery_policy(Vec::new());
        let session_v1 = DiscoverySession::establish(NodeId::new("local-a"), &hello_v1, &policy)
            .expect("session v1");
        let session_v2 = DiscoverySession::establish(NodeId::new("local-a"), &hello_v2, &policy)
            .expect("session v2");

        assert_ne!(session_v1.session_id, session_v2.session_id);
        assert_ne!(
            session_v1.peer_interest_advertisements,
            session_v2.peer_interest_advertisements
        );
    }

    #[test]
    fn discovery_sybil_resistance_rejects_untrusted_issuer() {
        let capability = subscribe_capability("tenant.alpha.>");
        let mut hello = discovery_hello(
            "peer-e",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability],
            vec![discovery_interest("tenant.alpha.orders.>", 2)],
            Vec::new(),
            Vec::new(),
        );
        hello.credential.issuer = NodeId::new("rogue-issuer");

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![subscribe_capability("tenant.alpha.>")]),
        )
        .expect_err("untrusted issuer must fail");

        assert_eq!(
            err,
            DiscoveryError::UntrustedCredentialIssuer {
                issuer: NodeId::new("rogue-issuer"),
            }
        );
    }

    #[test]
    fn discovery_stale_steward_leases_do_not_become_authoritative() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let stale_lease = cell
            .control_capsule
            .active_sequencer_lease()
            .expect("active lease");
        let hello = discovery_hello(
            "peer-f",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 4)],
            vec![DiscoveryStewardLeaseView {
                cell_id: cell.cell_id,
                lease: stale_lease,
            }],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: ControlEpoch::new(
                    cell.epoch,
                    cell.control_capsule.policy_revision + 1,
                ),
            }],
        );

        let session = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect("session");

        assert!(
            session.authoritative_stewardship.is_empty(),
            "stale lease should remain advisory until backed by the current control epoch"
        );
    }

    #[test]
    fn discovery_rejects_authority_evidence_from_wrong_membership_epoch() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let mut hello = discovery_hello(
            "peer-h",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 4)],
            vec![DiscoveryStewardLeaseView {
                cell_id: cell.cell_id,
                lease: cell
                    .control_capsule
                    .active_sequencer_lease()
                    .expect("active lease"),
            }],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: cell.control_capsule.control_epoch(),
            }],
        );
        hello.recent_control_epochs[0].control_epoch = ControlEpoch::new(
            CellEpoch::new(12, cell.epoch.generation),
            cell.control_capsule.policy_revision,
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect_err("authority evidence from the wrong membership epoch must fail");

        assert_eq!(
            err,
            DiscoveryError::ControlEpochMembershipMismatch {
                node: NodeId::new("peer-h"),
                cell_id: cell.cell_id,
                expected_membership_epoch: 11,
                actual_membership_epoch: 12,
            }
        );
    }

    #[test]
    fn discovery_rejects_conflicting_current_authoritative_leases() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let capability = subscribe_capability("tenant.alpha.>");
        let current_control_epoch = cell.control_capsule.control_epoch();
        let mut conflicting_lease = cell
            .control_capsule
            .active_sequencer_lease()
            .expect("active lease");
        conflicting_lease.holder = NodeId::new("node-z");
        let hello = discovery_hello(
            "peer-i",
            DiscoveryBootstrap::SelfDiscover,
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 4)],
            vec![
                DiscoveryStewardLeaseView {
                    cell_id: cell.cell_id,
                    lease: cell
                        .control_capsule
                        .active_sequencer_lease()
                        .expect("active lease"),
                },
                DiscoveryStewardLeaseView {
                    cell_id: cell.cell_id,
                    lease: conflicting_lease,
                },
            ],
            vec![DiscoveryControlEpochView {
                cell_id: cell.cell_id,
                control_epoch: current_control_epoch,
            }],
        );

        let err = DiscoverySession::establish(
            NodeId::new("local-a"),
            &hello,
            &discovery_policy(vec![capability]),
        )
        .expect_err("conflicting current leases must fail");

        assert_eq!(
            err,
            DiscoveryError::ConflictingAuthoritativeStewardLease {
                node: NodeId::new("peer-i"),
                cell_id: cell.cell_id,
            }
        );
    }

    #[test]
    fn discovery_session_transcript_is_replayable_for_identical_inputs() {
        let capability = subscribe_capability("tenant.alpha.>");
        let hello = discovery_hello(
            "peer-g",
            DiscoveryBootstrap::SeedList(vec![NodeId::new("seed-a")]),
            vec![capability.clone()],
            vec![capability.clone()],
            vec![discovery_interest("tenant.alpha.orders.>", 6)],
            Vec::new(),
            Vec::new(),
        );
        let policy = discovery_policy(vec![capability]);

        let first = DiscoverySession::establish(NodeId::new("local-a"), &hello, &policy)
            .expect("first session");
        let second = DiscoverySession::establish(NodeId::new("local-a"), &hello, &policy)
            .expect("second session");

        assert_eq!(first.session_id, second.session_id);
        assert_eq!(first.transitions(), second.transitions());
        assert_eq!(
            first.peer_interest_advertisements,
            second.peer_interest_advertisements
        );
    }

    #[test]
    fn control_capsule_v1_fences_stale_sequencer_leases() {
        let mut capsule = control_capsule();
        let original = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let fence = capsule
            .fence_sequencer(NodeId::new("node-b"))
            .expect("fence should succeed");

        assert_eq!(fence.previous_holder, NodeId::new("node-a"));
        assert_eq!(fence.next_holder, NodeId::new("node-b"));

        let err = capsule
            .authoritative_append(&original)
            .expect_err("old sequencer lease must be fenced");
        assert!(matches!(
            err,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == NodeId::new("node-b")
                && current_fence_generation == fence.fence_generation
        ));

        let current = capsule
            .active_sequencer_lease()
            .expect("refreshed sequencer lease");
        let certificate = capsule
            .authoritative_append(&current)
            .expect("fresh lease should append");
        assert_eq!(certificate.identity.sequence, 1);
        assert_eq!(certificate.sequencer, NodeId::new("node-b"));
    }

    #[test]
    fn control_capsule_v1_authoritative_appends_are_monotonic_within_epoch() {
        let mut capsule = control_capsule();
        let lease = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let first = capsule
            .authoritative_append(&lease)
            .expect("first append should commit");
        let second = capsule
            .authoritative_append(&lease)
            .expect("second append should commit");

        assert_eq!(first.identity.cell_id, second.identity.cell_id);
        assert_eq!(first.identity.epoch, second.identity.epoch);
        assert_eq!(first.identity.sequence, 1);
        assert_eq!(second.identity.sequence, 2);
        assert!(first.identity < second.identity);
    }

    #[test]
    fn control_capsule_v1_reconfiguration_uses_joint_overlap_and_single_live_sequencer() {
        let mut capsule = control_capsule();
        let original = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let err = capsule
            .reconfigure(
                vec![NodeId::new("node-c"), NodeId::new("node-d")],
                NodeId::new("node-c"),
            )
            .expect_err("overlap-free reconfiguration must fail");
        assert_eq!(err, ControlCapsuleError::JointConfigRequiresOverlap);

        let joint = capsule
            .reconfigure(
                vec![NodeId::new("node-a"), NodeId::new("node-c")],
                NodeId::new("node-c"),
            )
            .expect("joint reconfiguration should succeed");

        assert_eq!(
            joint.old_stewards,
            vec![NodeId::new("node-a"), NodeId::new("node-b")]
        );
        assert_eq!(
            joint.new_stewards,
            vec![NodeId::new("node-a"), NodeId::new("node-c")]
        );
        assert_eq!(joint.next_sequencer, NodeId::new("node-c"));
        assert_eq!(capsule.policy_revision, 2);
        assert_eq!(
            capsule.active_sequencer_holder().map(NodeId::as_str),
            Some("node-c")
        );
        assert_eq!(capsule.joint_config_history, vec![joint.clone()]);

        let stale = capsule
            .authoritative_append(&original)
            .expect_err("old sequencer must not decide after fencing");
        assert!(matches!(
            stale,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                ..
            } if current_holder == NodeId::new("node-c")
        ));

        let current = capsule
            .active_sequencer_lease()
            .expect("new sequencer lease");
        let certificate = capsule
            .authoritative_append(&current)
            .expect("new sequencer should be able to append");
        assert_eq!(certificate.sequencer, NodeId::new("node-c"));
        assert_eq!(certificate.control_epoch, joint.control_epoch);
    }

    #[test]
    fn control_capsule_v1_reconfiguration_rejects_duplicate_stewards_without_mutation() {
        let mut capsule = control_capsule();

        let err = capsule
            .reconfigure(
                vec![NodeId::new("node-a"), NodeId::new("node-a")],
                NodeId::new("node-a"),
            )
            .expect_err("duplicate steward sets must fail closed");
        assert_eq!(
            err,
            ControlCapsuleError::DuplicateSteward {
                node: NodeId::new("node-a")
            }
        );
        assert_eq!(
            capsule.steward_pool,
            vec![NodeId::new("node-a"), NodeId::new("node-b")]
        );
        assert_eq!(capsule.policy_revision, 1);
        assert_eq!(
            capsule.active_sequencer_holder().map(NodeId::as_str),
            Some("node-a")
        );
    }

    #[test]
    fn control_capsule_v1_replicated_append_is_idempotent_or_stale() {
        let mut capsule = control_capsule();
        let lease = capsule
            .active_sequencer_lease()
            .expect("initial sequencer lease");

        let first = capsule
            .authoritative_append(&lease)
            .expect("first append should commit");
        let second = capsule
            .authoritative_append(&lease)
            .expect("second append should commit");
        assert_ne!(first.identity, second.identity);

        let outcome = capsule
            .accept_replicated_append(first.clone())
            .expect("duplicate delivery should collapse");
        assert_eq!(
            outcome,
            ReplicatedAppendOutcome::IdempotentNoop(first.clone())
        );

        capsule
            .fence_sequencer(NodeId::new("node-b"))
            .expect("fence should succeed");
        let stale = capsule
            .accept_replicated_append(second.clone())
            .expect("late delivery must reduce deterministically");
        assert_eq!(
            stale,
            ReplicatedAppendOutcome::StaleReject {
                identity: second.identity.clone(),
                attempted_fence_generation: second.fence_generation,
                current_fence_generation: capsule.sequencer_lease_generation,
            }
        );
    }

    #[test]
    fn control_capsule_v1_cursor_authority_transfer_fences_old_holder() {
        let mut capsule = control_capsule();
        let original = capsule
            .cursor_authority_lease()
            .cloned()
            .expect("initial cursor-authority lease");

        let transferred = capsule
            .transfer_cursor_authority(NodeId::new("node-b"))
            .expect("steward transfer should succeed");

        capsule
            .validate_cursor_authority(&transferred)
            .expect("fresh cursor-authority lease should validate");
        let err = capsule
            .validate_cursor_authority(&original)
            .expect_err("old cursor-authority lease must be fenced");
        assert!(matches!(
            err,
            ControlCapsuleError::StaleCursorAuthorityLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == NodeId::new("node-b")
                && current_fence_generation == capsule.sequencer_lease_generation
        ));
    }

    #[test]
    fn control_capsule_v1_cursor_authority_transfer_rejects_foreign_holder_without_mutation() {
        let mut capsule = control_capsule();
        let original = capsule
            .cursor_authority_lease()
            .cloned()
            .expect("initial cursor-authority lease");
        let original_generation = capsule.sequencer_lease_generation;

        let err = capsule
            .transfer_cursor_authority(NodeId::new("consumer-a"))
            .expect_err("foreign holders must be rejected");
        assert_eq!(
            err,
            ControlCapsuleError::UnknownSteward {
                node: NodeId::new("consumer-a")
            }
        );
        assert_eq!(capsule.cursor_authority_lease(), Some(&original));
        assert_eq!(capsule.sequencer_lease_generation, original_generation);
    }

    #[test]
    fn subject_cell_certified_rebalance_advances_epoch_and_fences_old_sequencer() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let original = cell
            .control_capsule
            .active_sequencer_lease()
            .expect("original sequencer lease");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 7);
        let next_sequencer = evidence.next_sequencer.clone();

        let mut certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");

        assert_eq!(certified.plan, plan);
        assert_eq!(certified.control_append.identity.cell_id, cell.cell_id);
        assert_eq!(certified.control_append.identity.epoch, cell.epoch);
        assert_eq!(
            certified.resulting_cell.epoch,
            CellEpoch::new(cell.epoch.membership_epoch, cell.epoch.generation + 1)
        );
        assert_eq!(certified.resulting_cell.steward_set, plan.next_stewards);
        assert_eq!(
            certified.resulting_cell.data_capsule.temperature,
            CellTemperature::Warm
        );
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .active_sequencer_holder(),
            Some(&next_sequencer)
        );
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .cursor_authority_lease()
                .map(|lease| &lease.holder),
            Some(&next_sequencer)
        );

        let stale = certified
            .resulting_cell
            .control_capsule
            .authoritative_append(&original)
            .expect_err("pre-cut sequencer lease must be fenced");
        assert!(matches!(
            stale,
            ControlCapsuleError::StaleSequencerLease {
                current_holder,
                current_fence_generation,
                ..
            } if current_holder == next_sequencer
                && current_fence_generation == certified.resulting_cell.epoch.generation
        ));
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_consumer_lease_transfer() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 9);
        evidence.obligation_summary.transferred_consumer_leases = 1;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("consumer lease transfer gaps must fail closed");
        assert_eq!(
            err,
            RebalanceError::ConsumerLeaseTransferIncomplete {
                active_leases: 2,
                transferred: 1,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_reply_right_reissue() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 10);
        evidence.obligation_summary.active_reply_rights = 2;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("reply rights must be reissued onto the next epoch");
        assert_eq!(
            err,
            RebalanceError::ReplyRightsNotReissued {
                active_rights: 2,
                reissued: 1,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_honors_hysteresis_band() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let err = cell
            .certify_self_rebalance(
                &policy,
                &candidates,
                ObservedCellLoad::new(512),
                RebalanceCutEvidence {
                    next_sequencer: cell.steward_set[0].clone(),
                    retention_generation: 4,
                    obligation_summary: RebalanceObligationSummary {
                        publish_obligations_below_cut: 0,
                        active_consumer_leases: 0,
                        transferred_consumer_leases: 0,
                        ambiguous_consumer_lease_owners: 0,
                        active_reply_rights: 0,
                        reissued_reply_rights: 0,
                        dangling_reply_rights: 0,
                    },
                    repair_symbols: Vec::new(),
                },
            )
            .expect_err("in-band load should not force an epoch change");
        assert_eq!(
            err,
            RebalanceError::NoRebalanceNeeded {
                cell_id: cell.cell_id,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_hot_repair_spread() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 11);
        evidence.repair_symbols =
            repair_bindings_for(&cell, &plan, &candidates, 11, plan.next_stewards.len());

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("hot rebalance must prove wider repair spread");
        assert_eq!(
            err,
            RebalanceError::InsufficientRepairSymbolHolders {
                required: 6,
                actual: 4,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_wrong_symbol_epoch_binding() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 12);
        evidence.repair_symbols[0].cell_epoch = cell.epoch.next_generation();

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("repair symbols must be bound to the certified source epoch");
        assert_eq!(
            err,
            RebalanceError::RepairBindingWrongEpoch {
                node: plan.next_stewards[0].clone(),
                expected: cell.epoch,
                actual: cell.epoch.next_generation(),
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_wrong_symbol_retention_generation() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 13);
        evidence.repair_symbols[0].retention_generation = 99;

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("repair symbols must be bound to the certified retention generation");
        assert_eq!(
            err,
            RebalanceError::RepairBindingWrongRetentionGeneration {
                node: plan.next_stewards[0].clone(),
                expected: 13,
                actual: 99,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_ineligible_repair_holder() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 14);
        evidence.repair_symbols[0].node_id = NodeId::new("observer-z");

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("non-steward non-repair candidates must not certify the cut");
        assert_eq!(
            err,
            RebalanceError::IneligibleRepairHolder {
                node: NodeId::new("observer-z"),
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_rejects_duplicate_repair_bindings() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 15);
        evidence
            .repair_symbols
            .push(evidence.repair_symbols[0].clone());

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("duplicate repair bindings must fail closed");
        assert_eq!(
            err,
            RebalanceError::DuplicateRepairBinding {
                node: plan.next_stewards[0].clone(),
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_requires_binding_for_each_next_steward() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(256);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let missing_steward = plan.next_stewards[0].clone();
        let mut evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 16);
        evidence
            .repair_symbols
            .retain(|binding| binding.node_id != missing_steward);

        let err = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect_err("every next steward must carry a repair binding");
        assert_eq!(
            err,
            RebalanceError::MissingStewardRepairBinding {
                node: missing_steward,
            }
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_allows_retained_steward_binding_after_candidate_drop() {
        let policy = PlacementPolicy {
            cold_stewards: 1,
            warm_stewards: 3,
            hot_stewards: 3,
            candidate_pool_size: 3,
            rebalance_budget: RebalanceBudget {
                max_steward_changes: 1,
            },
            ..PlacementPolicy::default()
        };
        let all_candidates = rebalance_candidates();
        let cell = cold_subject_cell(&all_candidates, &policy);
        let current_steward = cell.steward_set[0].clone();
        let reduced_candidates: Vec<_> = all_candidates
            .into_iter()
            .filter(|candidate| candidate.node_id != current_steward)
            .collect();
        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &reduced_candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        assert!(
            contains_node(&plan.next_stewards, &current_steward),
            "budgeted rebalance should retain the current steward for one step"
        );

        let required_holders = cell
            .repair_policy
            .minimum_repair_holders(plan.next_temperature, plan.next_stewards.len());
        let repair_symbols =
            repair_bindings_for(&cell, &plan, &reduced_candidates, 13, required_holders);
        assert!(
            repair_symbols
                .iter()
                .any(|binding| binding.node_id == current_steward),
            "retained steward should remain eligible as a repair holder"
        );

        let evidence = RebalanceCutEvidence {
            next_sequencer: plan
                .added_stewards
                .first()
                .cloned()
                .expect("one added steward"),
            retention_generation: 13,
            obligation_summary: RebalanceObligationSummary {
                publish_obligations_below_cut: 0,
                active_consumer_leases: 0,
                transferred_consumer_leases: 0,
                ambiguous_consumer_lease_owners: 0,
                active_reply_rights: 0,
                reissued_reply_rights: 0,
                dangling_reply_rights: 0,
            },
            repair_symbols,
        };

        let certified = cell
            .certify_self_rebalance(&policy, &reduced_candidates, observed_load, evidence)
            .expect("retained stewards remain lawful repair holders during budgeted churn");
        assert!(contains_node(
            &certified.resulting_cell.steward_set,
            &current_steward
        ));
    }

    #[test]
    fn subject_cell_certified_rebalance_preserves_monotonic_fence_generation_across_epochs() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let mut cell = warm_subject_cell(&candidates, &policy);
        let second_steward = cell.steward_set[1].clone();
        let original_steward = cell.steward_set[0].clone();

        cell.control_capsule
            .fence_sequencer(second_steward)
            .expect("first fence");
        cell.control_capsule
            .fence_sequencer(original_steward)
            .expect("second fence");
        let pre_cut_generation = cell.control_capsule.sequencer_lease_generation;
        assert!(
            pre_cut_generation > cell.epoch.generation,
            "test setup must lift fence generation above the cell epoch generation"
        );

        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 14);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation,
            pre_cut_generation + 1
        );
        assert!(
            certified
                .resulting_cell
                .control_capsule
                .sequencer_lease_generation
                > certified.resulting_cell.epoch.generation
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_tracks_drained_stewards_from_removed_set() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        let observed_load = ObservedCellLoad::new(32);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        assert!(
            !plan.removed_stewards.is_empty(),
            "cooling rebalance should drain at least one prior steward"
        );
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 17);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("certified rebalance");

        assert_eq!(certified.drained_stewards, plan.removed_stewards);
        for removed in &certified.drained_stewards {
            assert!(
                !contains_node(&certified.resulting_cell.steward_set, removed),
                "drained steward must no longer appear in the resulting stewardship set"
            );
        }
    }

    #[test]
    fn control_capsule_v1_shared_control_shard_respects_cardinality_limits() {
        let mut capsule = control_capsule();

        let shard = capsule
            .attach_shared_control_shard("control-shard-a", 1, 3)
            .expect("slot inside cardinality bound should succeed");
        assert_eq!(capsule.shared_control_shard, Some(shard.clone()));

        let err = capsule
            .attach_shared_control_shard("control-shard-a", 3, 3)
            .expect_err("out-of-range slot must fail");
        assert_eq!(
            err,
            ControlCapsuleError::SharedShardOverCapacity {
                shard_id: "control-shard-a".to_owned(),
                slot_index: 3,
                cardinality_limit: 3,
            }
        );
    }

    #[test]
    fn subject_cell_new_packs_low_rate_cells_onto_shared_control_shards() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);

        let shard = cell
            .control_capsule
            .shared_control_shard
            .as_ref()
            .expect("cold cells should pack onto a shared control shard");
        assert_eq!(
            shard.cardinality_limit,
            policy.cardinality_policy.max_cells_per_shared_shard
        );
        assert!(
            shard.slot_index < shard.cardinality_limit,
            "slot assignment must stay inside the shard cardinality limit"
        );
    }

    #[test]
    fn subject_cell_new_rejects_zero_shared_shard_cardinality_limit() {
        let candidates = rebalance_candidates();
        let policy = PlacementPolicy {
            cardinality_policy: CardinalityPolicy {
                max_cells_per_shared_shard: 0,
                ..CardinalityPolicy::default()
            },
            ..rebalance_policy()
        };

        let err = SubjectCell::new(
            &SubjectPattern::parse("orders.created").expect("pattern"),
            CellEpoch::new(11, 2),
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect_err("zero-cardinality shared shard policy must fail closed");
        assert_eq!(err, FabricError::InvalidSharedShardCardinalityLimit);
    }

    #[test]
    fn subject_cell_certified_rebalance_promotes_hot_cells_to_dedicated_control_shards() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        assert!(
            cell.control_capsule.shared_control_shard.is_some(),
            "warm cells should start on a shared control shard"
        );

        let observed_load = ObservedCellLoad::new(2_048);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 15);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("hot rebalance");
        assert_eq!(certified.plan.next_temperature, CellTemperature::Hot);
        assert_eq!(
            certified
                .resulting_cell
                .control_capsule
                .shared_control_shard,
            None,
            "hot cells should be promoted to dedicated control shards"
        );
    }

    #[test]
    fn subject_cell_certified_rebalance_demotes_cooled_cells_back_to_shared_shards() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        assert_eq!(
            cell.control_capsule.shared_control_shard, None,
            "hot cells should start on dedicated control shards"
        );

        let observed_load = ObservedCellLoad::new(32);
        let plan = policy
            .plan_rebalance(
                &cell.subject_partition,
                &candidates,
                &cell.steward_set,
                cell.data_capsule.temperature,
                observed_load,
            )
            .expect("rebalance plan");
        let evidence = successful_rebalance_evidence(&cell, &plan, &candidates, 16);

        let certified = cell
            .certify_self_rebalance(&policy, &candidates, observed_load, evidence)
            .expect("cooled rebalance");
        assert_eq!(certified.plan.next_temperature, CellTemperature::Warm);
        assert!(
            certified
                .resulting_cell
                .control_capsule
                .shared_control_shard
                .is_some(),
            "cooled cells should demote back onto shared control shards"
        );
    }

    #[test]
    fn reply_space_compaction_packs_ephemeral_reply_subjects_onto_same_shared_shard() {
        let candidates = rebalance_candidates();
        let policy = PlacementPolicy {
            normalization: NormalizationPolicy {
                reply_space_policy: ReplySpaceCompactionPolicy {
                    enabled: true,
                    preserve_segments: 2,
                },
                ..NormalizationPolicy::default()
            },
            ..rebalance_policy()
        };
        let epoch = CellEpoch::new(17, 1);

        let first = SubjectCell::new(
            &SubjectPattern::parse("_INBOX.clientA.req-1").expect("reply subject"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("first compacted reply cell");
        let second = SubjectCell::new(
            &SubjectPattern::parse("_INBOX.clientA.req-2").expect("reply subject"),
            epoch,
            &candidates,
            &policy,
            RepairPolicy::default(),
            DataCapsule::default(),
        )
        .expect("second compacted reply cell");

        assert_eq!(
            first.subject_partition, second.subject_partition,
            "reply-space compaction should collapse ephemeral reply subjects onto one canonical partition"
        );
        assert_eq!(
            first.control_capsule.shared_control_shard, second.control_capsule.shared_control_shard,
            "compacted reply subjects should share the same control shard assignment"
        );
    }

    #[test]
    fn subject_cell_speculative_publish_confirms_without_exposing_tentative_state() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let histogram = CellConflictHistogram::default();

        let attempt = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-confirm",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-confirm",
                    "digest-orders-confirm",
                ),
            )
            .expect("low-conflict cell should admit speculative publish");

        assert!(
            !attempt.consumer_visible(),
            "tentative results must stay hidden until confirmation"
        );
        assert!(attempt.replay_artifact.verifies());

        let mut histogram = histogram;
        let confirmed = attempt.confirm(&mut histogram, 41);
        assert_eq!(histogram, CellConflictHistogram::new(1, 0));
        assert_eq!(confirmed.committed_obligation.control_sequence, 41);
        assert!(confirmed.consumer_visible());
        assert_eq!(
            confirmed.replay_artifact.decision,
            SpeculativeReplayDecision::Confirmed
        );
        assert!(confirmed.replay_artifact.verifies());
    }

    #[test]
    fn subject_cell_speculative_publish_aborts_conflict_and_tracks_histogram() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let mut histogram = CellConflictHistogram::default();

        let attempt = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-conflict",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-conflict",
                    "digest-orders-conflict",
                ),
            )
            .expect("low-conflict cell should admit speculative publish");

        let aborted = attempt.abort_due_to_conflict(
            &mut histogram,
            "cursor-conflict-7",
            "fallback-authoritative-path",
        );
        assert_eq!(histogram, CellConflictHistogram::new(1, 1));
        assert!(
            !aborted.consumer_visible(),
            "conflicted tentative results must stay hidden from consumers"
        );
        assert_eq!(aborted.corrected_outcome, "fallback-authoritative-path");
        assert_eq!(aborted.conflict_key, "cursor-conflict-7");
        assert_eq!(
            aborted.replay_artifact.decision,
            SpeculativeReplayDecision::AbortedConflict
        );
        assert!(aborted.replay_artifact.verifies());
    }

    #[test]
    fn subject_cell_speculative_publish_honors_explicit_kill_switch() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy =
            SpeculativeExecutionPolicy::default().with_disabled_cell(cell.cell_id);
        let histogram = CellConflictHistogram::default();

        let err = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-kill-switch",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-kill-switch",
                    "digest-orders-kill-switch",
                ),
            )
            .expect_err("disabled cells must reject speculation");
        assert_eq!(
            err,
            SpeculativeExecutionError::CellKillSwitch {
                cell_id: cell.cell_id
            }
        );
    }

    #[test]
    fn subject_cell_speculative_publish_rejects_high_conflict_histogram() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy =
            SpeculativeExecutionPolicy::default().with_max_conflict_rate_basis_points(500);
        let histogram = CellConflictHistogram::new(20, 2);

        let err = cell
            .begin_speculative_publish(
                &speculative_policy,
                &histogram,
                &SpeculativePublishRequest::new(
                    "orders-high-conflict",
                    SemanticServiceClass::ReplyCritical,
                    "idem-orders-high-conflict",
                    "digest-orders-high-conflict",
                ),
            )
            .expect_err("conflict-heavy cells must stay off the speculative path");
        assert_eq!(
            err,
            SpeculativeExecutionError::ConflictRateTooHigh {
                cell_id: cell.cell_id,
                observed_basis_points: 1_000,
                threshold_basis_points: 500,
            }
        );
    }

    #[test]
    fn subject_cell_speculative_publish_artifacts_are_replayable_for_identical_inputs() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let histogram = CellConflictHistogram::new(4, 0);
        let request = SpeculativePublishRequest::new(
            "orders-replay",
            SemanticServiceClass::ReplyCritical,
            "idem-orders-replay",
            "digest-orders-replay",
        )
        .with_delivery_class(DeliveryClass::MobilitySafe);

        let first = cell
            .begin_speculative_publish(&speculative_policy, &histogram, &request)
            .expect("first replayable attempt");
        let second = cell
            .begin_speculative_publish(&speculative_policy, &histogram, &request)
            .expect("second replayable attempt");

        assert_eq!(
            first.tentative_obligation.obligation_id,
            second.tentative_obligation.obligation_id
        );
        assert_eq!(
            first.replay_artifact.replay_key,
            second.replay_artifact.replay_key
        );
        assert_eq!(
            first.replay_artifact.oracle_key,
            second.replay_artifact.oracle_key
        );
        assert!(first.replay_artifact.verifies());
        assert!(second.replay_artifact.verifies());

        let mut histogram = histogram;
        let _ = first.confirm(&mut histogram, 7);
        let _ = second.abort_due_to_conflict(
            &mut histogram,
            "cursor-replay-cleanup",
            "fallback-replay-cleanup",
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    fn subject_cell_speculative_publish_drop_without_resolution_panics_in_debug() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);
        let speculative_policy = SpeculativeExecutionPolicy::default();
        let histogram = CellConflictHistogram::default();

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let attempt = cell
                .begin_speculative_publish(
                    &speculative_policy,
                    &histogram,
                    &SpeculativePublishRequest::new(
                        "orders-drop",
                        SemanticServiceClass::ReplyCritical,
                        "idem-orders-drop",
                        "digest-orders-drop",
                    ),
                )
                .expect("low-conflict cell should admit speculative publish");
            drop(attempt);
        }));

        assert!(
            panic.is_err(),
            "unresolved speculative attempts should trip the debug drop contract"
        );
    }

    #[test]
    fn semantic_conversation_family_requires_explicit_parallel_contracts_to_split() {
        let ledger_issue = semantic_family(
            "ledger-issue",
            split_capable_kernel("ledger-issue", "ledger-issue", "publish-ledger"),
            "order:123",
            3,
        );
        let billing_notify = semantic_family(
            "billing-notify",
            split_capable_kernel("billing-notify", "billing-notify", "notify-billing"),
            "billing:invoice-123",
            1,
        );
        assert!(
            !ledger_issue.conflicts_with(&billing_notify),
            "disjoint footprints with explicit split permissions should commute"
        );

        let serial_kernel = semantic_family(
            "serial-repair",
            ProtocolKernel::new("serial-repair", DeliveryClass::DurableOrdered)
                .with_interference_class("serial-repair")
                .with_obligation_footprint("repair-ledger"),
            "repair:cell-7",
            2,
        );
        assert!(
            ledger_issue.conflicts_with(&serial_kernel),
            "families without explicit reorder/parallel contracts must fail closed"
        );

        let overlapping_state = semantic_family(
            "ledger-confirm",
            split_capable_kernel("ledger-confirm", "ledger-confirm", "confirm-ledger"),
            "order:123",
            2,
        );
        assert!(
            ledger_issue.conflicts_with(&overlapping_state),
            "shared-state overlap must keep families on the same lane"
        );
    }

    #[test]
    fn subject_cell_semantic_lane_plan_decomposes_hot_namespace_by_shared_state_footprint() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);

        let families = vec![
            semantic_family(
                "orders-123-authorize",
                split_capable_kernel("payments-authorize", "payments-authorize", "obligation:123"),
                "order:123",
                4,
            ),
            semantic_family(
                "orders-987-authorize",
                split_capable_kernel(
                    "payments-authorize",
                    "payments-authorize-987",
                    "obligation:987",
                ),
                "order:987",
                1,
            ),
            semantic_family(
                "orders-123-settle",
                split_capable_kernel("payments-settle", "payments-settle", "obligation:123"),
                "order:123",
                2,
            ),
        ];

        let plan = cell.plan_semantic_execution_lanes(&families);
        assert_eq!(plan.lanes.len(), 2);

        let lane_families: Vec<Vec<&str>> = plan
            .lanes
            .iter()
            .map(|lane| {
                lane.families
                    .iter()
                    .map(|family| family.family_id.as_str())
                    .collect()
            })
            .collect();
        assert_eq!(
            lane_families,
            vec![
                vec!["orders-123-authorize", "orders-123-settle"],
                vec!["orders-987-authorize"],
            ]
        );
    }

    #[test]
    fn subject_cell_semantic_lane_plan_projects_parallel_round_reduction() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = cold_subject_cell(&candidates, &policy);

        let families = vec![
            semantic_family(
                "inventory-rebuild",
                split_capable_kernel("inventory-rebuild", "inventory", "inventory-scan"),
                "inventory:west",
                5,
            ),
            semantic_family(
                "billing-snapshot",
                split_capable_kernel("billing-snapshot", "billing", "billing-scan"),
                "billing:east",
                4,
            ),
            semantic_family(
                "analytics-flush",
                split_capable_kernel("analytics-flush", "analytics", "analytics-flush"),
                "analytics:global",
                3,
            ),
        ];

        let first = cell.plan_semantic_execution_lanes(&families);
        let second = cell.plan_semantic_execution_lanes(&families);

        assert_eq!(first, second, "lane planning must be deterministic");
        assert_eq!(first.lanes.len(), 3);
        assert_eq!(first.serial_work_units(), 12);
        assert_eq!(first.projected_parallel_rounds(), 5);
        assert!(
            first.serial_work_units() > first.projected_parallel_rounds(),
            "independent families should reduce projected serialized rounds"
        );
    }

    #[test]
    fn recoverable_data_capsule_uses_inline_fast_path_for_tiny_payloads() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = warm_subject_cell(&candidates, &policy);
        let mut capsule = RecoverableDataCapsule::new(&cell);
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload: b"tiny".to_vec(),
            delivery_class: DeliveryClass::DurableOrdered,
        };

        capsule
            .record_publish(&cell, &candidates, 7, &message)
            .expect("record inline segment");

        let segment = capsule.latest_segment().expect("latest segment");
        assert!(matches!(
            segment.encoding,
            DurableSegmentEncoding::Inline { .. }
        ));
        assert_eq!(segment.source_symbol_count(), 1);
        assert_eq!(segment.repair_symbol_count(), 0);
        assert_eq!(segment.holders, cell.steward_set);

        let available = cell.steward_set.iter().cloned().collect::<BTreeSet<_>>();
        let recovered = capsule
            .reconstruct_payload(7, &available)
            .expect("inline payload should be readable from a steward");
        assert_eq!(recovered, message.payload);
    }

    #[test]
    fn recoverable_data_capsule_reconstructs_coded_payload_from_partial_holders() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        let mut capsule = RecoverableDataCapsule::new(&cell);
        let payload = vec![0x5a; DEFAULT_SYMBOL_SIZE * 3];
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload: payload.clone(),
            delivery_class: DeliveryClass::DurableOrdered,
        };

        capsule
            .record_publish(&cell, &candidates, 11, &message)
            .expect("record coded segment");

        let segment = capsule.latest_segment().expect("latest segment");
        assert!(matches!(
            segment.encoding,
            DurableSegmentEncoding::Coded { .. }
        ));
        assert!(
            segment.repair_symbol_count() >= 3,
            "hot cells should allocate extra repair symbols"
        );
        let available = segment
            .holders
            .iter()
            .take(segment.holders.len().saturating_sub(1))
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(
            !available.is_empty(),
            "test requires at least one retained holder"
        );

        let recovered = capsule
            .reconstruct_payload(11, &available)
            .expect("partial quorum should reconstruct the coded segment");
        assert_eq!(recovered, payload);
    }

    #[test]
    fn recoverable_data_capsule_detects_symbol_tampering() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cell = hot_subject_cell(&candidates, &policy);
        let payload = vec![0x33; DEFAULT_SYMBOL_SIZE * 2];
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload,
            delivery_class: DeliveryClass::DurableOrdered,
        };

        let mut segment =
            DurableSegment::build(&cell, &candidates, 19, &message).expect("coded segment");
        let available = segment.holders.iter().cloned().collect::<BTreeSet<_>>();
        match &mut segment.encoding {
            DurableSegmentEncoding::Inline { .. } => panic!("expected coded segment"),
            DurableSegmentEncoding::Coded { symbols, .. } => {
                let first = symbols.first_mut().expect("stored symbol");
                first.symbol.data_mut()[0] ^= 0x01;
            }
        }

        let err = segment
            .reconstruct_payload(&available)
            .expect_err("tampered symbol must fail authentication");
        assert!(matches!(err, DataCapsuleError::AuthenticationFailed { .. }));
    }

    #[test]
    fn recoverable_data_capsule_hot_cells_plan_more_repair_than_cold_cells() {
        let policy = rebalance_policy();
        let candidates = rebalance_candidates();
        let cold = cold_subject_cell(&candidates, &policy);
        let hot = hot_subject_cell(&candidates, &policy);
        let payload = vec![0xab; DEFAULT_SYMBOL_SIZE * 2];
        let message = FabricMessage {
            subject: Subject::parse("orders.created").expect("subject"),
            payload,
            delivery_class: DeliveryClass::DurableOrdered,
        };

        let cold_segment =
            DurableSegment::build(&cold, &candidates, 29, &message).expect("cold segment");
        let hot_segment =
            DurableSegment::build(&hot, &candidates, 29, &message).expect("hot segment");

        assert!(
            hot_segment.repair_symbol_count() > cold_segment.repair_symbol_count(),
            "hot cells should deepen repair spread"
        );
        assert!(
            hot_segment.holders.len() >= cold_segment.holders.len(),
            "hot cells should not reduce holder coverage"
        );
    }

    #[test]
    fn reserve_publish_durable_records_recoverable_capsule_state() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable-capsule")
                .await
                .expect("connect");

            {
                let mut state = fabric.state.lock();
                state.default_data_capsule = DataCapsule {
                    temperature: CellTemperature::Hot,
                    retained_message_blocks: 3,
                };
                state.repair_policy = RepairPolicy {
                    recoverability_target: 3,
                    cold_witnesses: 1,
                    hot_witnesses: 2,
                };
                state.placement_policy.cold_stewards = 2;
                state.placement_policy.warm_stewards = 2;
                state.placement_policy.hot_stewards = 2;
                state.placement_policy.candidate_pool_size = 4;
                state.local_candidates = vec![
                    candidate("node-a", "rack-a", StorageClass::Durable, 5),
                    candidate("node-b", "rack-b", StorageClass::Durable, 6),
                    candidate("node-c", "rack-c", StorageClass::Standard, 7),
                    candidate("node-d", "rack-d", StorageClass::Standard, 8),
                ];
            }

            let mut ledger = ObligationLedger::new();
            let permit = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::DurableOrdered,
                )
                .await
                .expect("durable permit");
            let payload = vec![0x44; DEFAULT_SYMBOL_SIZE * 3];
            permit.send(&cx, payload.clone());

            let state = fabric.state.lock();
            let cell = state
                .cells
                .get(&canonical_cell_key("orders.created"))
                .expect("cell runtime");
            let segment = cell
                .durable_capsule
                .latest_segment()
                .expect("durable segment recorded");
            assert!(matches!(
                segment.encoding,
                DurableSegmentEncoding::Coded { .. }
            ));
            assert!(
                cell.durable_capsule.symbol_spread.len() >= 3,
                "coded durable publish should spread symbols across stewards and witnesses"
            );

            let available = segment
                .holders
                .iter()
                .take(segment.holders.len().saturating_sub(1))
                .cloned()
                .collect::<BTreeSet<_>>();
            let recovered = cell
                .durable_capsule
                .reconstruct_payload(segment.window.start_sequence, &available)
                .expect("runtime durable capsule should reconstruct from partial holders");
            assert_eq!(recovered, payload);
        });
    }

    // ── Two-phase publish tests ───────────────────────────────────

    #[test]
    fn reserve_publish_then_send_delivers_message() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-send")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            let permit = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect("reserve");

            assert_eq!(permit.subject().as_str(), "orders.created");
            assert_eq!(permit.delivery_class(), DeliveryClass::EphemeralInteractive);
            assert!(permit.obligation_id().is_none());

            let receipt = permit.send(&cx, b"hello".to_vec());
            assert_eq!(receipt.payload_len, 5);
            assert_eq!(receipt.ack_kind, AckKind::Accepted);
            assert_eq!(receipt.delivery_class, DeliveryClass::EphemeralInteractive);

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(msg.subject.as_str(), "orders.created");
            assert_eq!(msg.payload, b"hello".to_vec());
        });
    }

    #[test]
    fn reserve_publish_then_abort_delivers_nothing() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.>");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-abort")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            let permit = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect("reserve");
            permit.abort(&cx);

            // Publish a second message to verify the first was not delivered.
            let _ = fabric
                .publish(&cx, "orders.other", b"after-abort".to_vec())
                .await
                .expect("publish after abort");

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(
                msg.subject.as_str(),
                "orders.other",
                "aborted permit must not deliver its message"
            );
        });
    }

    #[test]
    fn reserve_publish_drop_delivers_nothing() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.>");
            grant_subscribe(&cx, "orders.>");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-drop")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "orders.>").await.expect("subscribe");

            {
                let _permit = fabric
                    .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                    .await
                    .expect("reserve");
                // permit dropped without send or abort
            }

            let _ = fabric
                .publish(&cx, "orders.other", b"after-drop".to_vec())
                .await
                .expect("publish after drop");

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(
                msg.subject.as_str(),
                "orders.other",
                "dropped permit must not deliver its message"
            );
        });
    }

    #[test]
    fn reserve_publish_durable_allocates_obligation() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let permit = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::DurableOrdered,
                )
                .await
                .expect("reserve durable");

            let obligation_id = permit
                .obligation_id()
                .expect("durable publish must allocate obligation");
            assert_eq!(permit.delivery_class(), DeliveryClass::DurableOrdered);

            let receipt = permit.send(&cx, b"durable-payload".to_vec());
            assert_eq!(receipt.ack_kind, AckKind::Recoverable);
            assert_eq!(receipt.delivery_class, DeliveryClass::DurableOrdered);
            assert_eq!(ledger.pending_count(), 0);
            assert_eq!(ledger.stats().total_committed, 1);
            assert_eq!(
                ledger
                    .get(obligation_id)
                    .expect("committed obligation must remain recorded")
                    .state,
                crate::record::ObligationState::Committed
            );
        });
    }

    #[test]
    fn reserve_publish_durable_abort_resolves_obligation() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable-abort")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let permit = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::DurableOrdered,
                )
                .await
                .expect("reserve durable");
            let obligation_id = permit
                .obligation_id()
                .expect("durable publish must allocate obligation");

            permit.abort(&cx);

            assert_eq!(ledger.pending_count(), 0);
            assert_eq!(ledger.stats().total_aborted, 1);
            assert_eq!(
                ledger
                    .get(obligation_id)
                    .expect("aborted obligation must remain recorded")
                    .state,
                crate::record::ObligationState::Aborted
            );
        });
    }

    #[test]
    fn reserve_publish_durable_drop_resolves_obligation() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-durable-drop")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();
            let obligation_id;

            {
                let permit = fabric
                    .reserve_publish_durable(
                        &cx,
                        &mut ledger,
                        "orders.created",
                        DeliveryClass::DurableOrdered,
                    )
                    .await
                    .expect("reserve durable");
                obligation_id = permit
                    .obligation_id()
                    .expect("durable publish must allocate obligation");
            }

            assert_eq!(ledger.pending_count(), 0);
            assert_eq!(ledger.stats().total_aborted, 1);
            assert_eq!(
                ledger
                    .get(obligation_id)
                    .expect("dropped obligation must remain recorded")
                    .state,
                crate::record::ObligationState::Aborted
            );
        });
    }

    #[test]
    fn reserve_publish_rejects_durable_ordered_without_ledger() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-plain-durable")
                .await
                .expect("connect");

            let err = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::DurableOrdered)
                .await
                .expect_err("durable ordered publish without ledger must fail");

            assert!(
                err.to_string().contains("reserve_publish_durable"),
                "expected ledger guidance in error, got {err}"
            );
        });
    }

    #[test]
    fn reserve_publish_durable_rejects_ephemeral_interactive() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-ephemeral-durable")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let err = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::EphemeralInteractive,
                )
                .await
                .expect_err("ephemeral publish should stay on reserve_publish");

            assert!(
                err.to_string().contains("reserve_publish"),
                "expected plain-publish guidance, got {err}"
            );
            assert_eq!(ledger.pending_count(), 0);
        });
    }

    #[test]
    fn reserve_publish_durable_rejects_higher_layer_delivery_classes() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/two-phase-unsupported-class")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();

            let err = fabric
                .reserve_publish_durable(
                    &cx,
                    &mut ledger,
                    "orders.created",
                    DeliveryClass::ObligationBacked,
                )
                .await
                .expect_err("packet-plane publish must reject higher-layer delivery classes");

            assert!(
                err.to_string()
                    .contains("does not yet support delivery class"),
                "expected unsupported-class guidance, got {err}"
            );
            assert_eq!(ledger.pending_count(), 0);
        });
    }

    #[test]
    fn reserve_publish_requires_matching_publish_capability() {
        run_test_with_cx(|cx| async move {
            let fabric = Fabric::connect(&cx, "node1:4222/deny-reserve")
                .await
                .expect("connect");

            let err = fabric
                .reserve_publish(&cx, "orders.created", DeliveryClass::EphemeralInteractive)
                .await
                .expect_err("reserve without publish capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn subscribe_requires_matching_subscribe_capability() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "orders.created");
            let fabric = Fabric::connect(&cx, "node1:4222/deny-subscribe")
                .await
                .expect("connect");

            let err = fabric
                .subscribe(&cx, "orders.>")
                .await
                .expect_err("subscribe without subscribe capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn request_requires_subscribe_capability_even_with_publish_granted() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            let fabric = Fabric::connect(&cx, "node1:4222/deny-request")
                .await
                .expect("connect");

            let err = fabric
                .request(&cx, "service.lookup", b"lookup".to_vec())
                .await
                .expect_err("request without subscribe capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 1);
            assert_eq!(decisions[0].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn certified_request_requires_publish_and_subscribe_capabilities() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "service.lookup");
            let fabric = Fabric::connect(&cx, "node1:4222/deny-certified")
                .await
                .expect("connect");
            let mut ledger = ObligationLedger::new();
            let admission = service_admission(
                "req-certified-denied",
                "service.lookup",
                DeliveryClass::ObligationBacked,
                Some(Duration::from_secs(5)),
                cx.now(),
            );

            let err = fabric
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
                .expect_err("certified request without subscribe capability must fail");

            assert_eq!(err.kind(), ErrorKind::AdmissionDenied);
            let decisions = fabric
                .decision_records()
                .into_iter()
                .filter(|record| record.contract_name() == "fabric_capability_decision")
                .collect::<Vec<_>>();
            assert_eq!(decisions.len(), 2);
            assert_eq!(decisions[0].audit.action_chosen, "allow");
            assert_eq!(decisions[1].audit.action_chosen, "reject");
        });
    }

    #[test]
    fn publish_convenience_wrapper_works() {
        run_test_with_cx(|cx| async move {
            grant_publish(&cx, "events.fired");
            grant_subscribe(&cx, "events.>");
            let fabric = Fabric::connect(&cx, "node1:4222/publish-wrapper")
                .await
                .expect("connect");
            let mut sub = fabric.subscribe(&cx, "events.>").await.expect("subscribe");

            let receipt = fabric
                .publish(&cx, "events.fired", b"wrapper".to_vec())
                .await
                .expect("publish via wrapper");

            assert_eq!(receipt.ack_kind, AckKind::Accepted);
            assert_eq!(receipt.delivery_class, DeliveryClass::EphemeralInteractive);

            let msg = sub.next(&cx).await.expect("message");
            assert_eq!(msg.subject.as_str(), "events.fired");
            assert_eq!(msg.payload, b"wrapper".to_vec());
        });
    }
}
