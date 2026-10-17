//! Federation-role definitions for FABRIC interconnects.

use super::control::{ControlBudget, SystemSubjectFamily};
use super::morphism::{
    FabricCapability, Morphism, MorphismClass, MorphismEvaluationError, MorphismValidationError,
};
use super::subject::{
    NamespaceComponent, NamespaceKernel, NamespaceKernelError, Subject, SubjectPattern,
    SubjectPatternError,
};
use crate::distributed::{RegionBridge, RegionSnapshot, SnapshotError};
use crate::remote::NodeId;
use crate::security::AuthKey;
use crate::supervision::{RestartConfig, SupervisionStrategy};
use crate::types::Time;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::mem;
use std::time::Duration;
use thiserror::Error;

/// Constraints applied to export/import morphisms on leaf fabrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct MorphismConstraints {
    /// Morphism classes allowed to cross the leaf boundary.
    pub allowed_classes: BTreeSet<MorphismClass>,
    /// Largest multiplicative namespace expansion allowed on the leaf boundary.
    pub max_expansion_factor: u16,
    /// Largest fanout allowed on the leaf boundary.
    pub max_fanout: u16,
}

impl Default for MorphismConstraints {
    fn default() -> Self {
        Self {
            allowed_classes: [MorphismClass::DerivedView, MorphismClass::Egress]
                .into_iter()
                .collect(),
            max_expansion_factor: 4,
            max_fanout: 8,
        }
    }
}

impl MorphismConstraints {
    fn validate(&self) -> Result<(), FederationError> {
        if self.allowed_classes.is_empty() {
            return Err(FederationError::EmptyAllowedMorphismClasses);
        }
        if self.max_expansion_factor == 0 {
            return Err(FederationError::ZeroMaxExpansionFactor);
        }
        if self.max_fanout == 0 {
            return Err(FederationError::ZeroMaxFanout);
        }
        Ok(())
    }

    fn admits(&self, morphism: &Morphism) -> Result<(), FederationError> {
        if !self.allowed_classes.contains(&morphism.class) {
            return Err(FederationError::LeafMorphismClassNotAllowed {
                class: morphism.class,
            });
        }
        if morphism.quota_policy.max_expansion_factor > self.max_expansion_factor {
            return Err(FederationError::LeafExpansionFactorExceeded {
                actual: morphism.quota_policy.max_expansion_factor,
                max: self.max_expansion_factor,
            });
        }
        if morphism.quota_policy.max_fanout > self.max_fanout {
            return Err(FederationError::LeafFanoutExceeded {
                actual: morphism.quota_policy.max_fanout,
                max: self.max_fanout,
            });
        }
        Ok(())
    }
}

/// Configuration for a constrained leaf fabric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct LeafConfig {
    /// Maximum reconnect backoff tolerated for intermittent links.
    pub max_reconnect_backoff: Duration,
    /// Maximum buffered entries retained while disconnected.
    pub offline_buffer_limit: u64,
    /// Morphism restrictions for import/export traffic.
    pub morphism_constraints: MorphismConstraints,
}

impl Default for LeafConfig {
    fn default() -> Self {
        Self {
            max_reconnect_backoff: Duration::from_secs(30),
            offline_buffer_limit: 1_024,
            morphism_constraints: MorphismConstraints::default(),
        }
    }
}

impl LeafConfig {
    fn validate(&self) -> Result<(), FederationError> {
        if self.max_reconnect_backoff.is_zero() {
            return Err(FederationError::ZeroDuration {
                field: "role.leaf_fabric.max_reconnect_backoff".to_owned(),
            });
        }
        if self.offline_buffer_limit == 0 {
            return Err(FederationError::ZeroOfflineBufferLimit);
        }
        self.morphism_constraints.validate()
    }
}

/// How a gateway advertises and propagates downstream interest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum InterestPropagationPolicy {
    /// Propagate only explicit subscriptions.
    ExplicitSubscriptions,
    /// Advertise bounded subject prefixes.
    PrefixAnnouncements,
    /// Propagate interest only when demand appears downstream.
    #[default]
    DemandDriven,
}

/// Configuration for a gateway fabric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Strategy used to propagate downstream interest.
    pub interest_propagation_policy: InterestPropagationPolicy,
    /// Maximum fanout amplification the gateway may introduce.
    pub amplification_limit: u16,
    /// Time budget for converging interest and replay state.
    pub convergence_timeout: Duration,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            interest_propagation_policy: InterestPropagationPolicy::default(),
            amplification_limit: 16,
            convergence_timeout: Duration::from_secs(15),
        }
    }
}

impl GatewayConfig {
    fn validate(&self) -> Result<(), FederationError> {
        if self.amplification_limit == 0 {
            return Err(FederationError::ZeroAmplificationLimit);
        }
        if self.convergence_timeout.is_zero() {
            return Err(FederationError::ZeroDuration {
                field: "role.gateway_fabric.convergence_timeout".to_owned(),
            });
        }
        Ok(())
    }
}

/// Ordering promise carried by a replication link.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OrderingGuarantee {
    /// Preserve ordering within each subject independently.
    #[default]
    PerSubject,
    /// Preserve ordering across a full replicated stream snapshot and catch-up.
    SnapshotConsistent,
    /// Preserve only checkpoint-to-checkpoint ordering.
    CheckpointBounded,
}

/// How replication catches a lagging peer back up.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CatchUpPolicy {
    /// Require a fresh snapshot before replaying deltas.
    SnapshotRequired,
    /// Prefer a snapshot, but allow delta-only recovery when safe.
    #[default]
    SnapshotThenDelta,
    /// Rely on retained logs only.
    LogOnly,
}

/// Configuration for a replication-oriented link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Ordering guarantee exposed by the replication boundary.
    pub ordering_guarantee: OrderingGuarantee,
    /// Interval between durable snapshots.
    pub snapshot_interval: Duration,
    /// Policy for bringing a lagging replica back into convergence.
    pub catch_up_policy: CatchUpPolicy,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            ordering_guarantee: OrderingGuarantee::default(),
            snapshot_interval: Duration::from_secs(60),
            catch_up_policy: CatchUpPolicy::default(),
        }
    }
}

impl ReplicationConfig {
    fn validate(&self) -> Result<(), FederationError> {
        if self.snapshot_interval.is_zero() {
            return Err(FederationError::ZeroDuration {
                field: "role.replication_link.snapshot_interval".to_owned(),
            });
        }
        Ok(())
    }
}

/// Trace-retention policy for replay-oriented links.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceRetention {
    /// Keep only the latest bounded number of artifacts.
    LatestArtifacts {
        /// Maximum retained replay artifacts.
        max_artifacts: u32,
    },
    /// Retain artifacts for a bounded duration window.
    DurationWindow {
        /// Retention window.
        retention: Duration,
    },
    /// Retain artifacts until the remote side acknowledges receipt.
    UntilAcknowledged,
}

impl Default for TraceRetention {
    fn default() -> Self {
        Self::LatestArtifacts { max_artifacts: 128 }
    }
}

impl TraceRetention {
    fn validate(&self) -> Result<(), FederationError> {
        match self {
            Self::LatestArtifacts { max_artifacts } if *max_artifacts == 0 => {
                Err(FederationError::ZeroTraceArtifactLimit)
            }
            Self::DurationWindow { retention } if retention.is_zero() => {
                Err(FederationError::ZeroDuration {
                    field: "role.edge_replay_link.trace_retention.retention".to_owned(),
                })
            }
            Self::LatestArtifacts { .. }
            | Self::DurationWindow { .. }
            | Self::UntilAcknowledged => Ok(()),
        }
    }
}

/// How replay evidence is shipped across the bridge.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceShippingPolicy {
    /// Ship evidence only when a disconnected peer reconnects.
    #[default]
    OnReconnect,
    /// Ship evidence in periodic bounded batches.
    PeriodicBatch,
    /// Continuously mirror evidence as it is produced.
    ContinuousMirror,
}

/// Configuration for a replay- and evidence-oriented link.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeReplayConfig {
    /// Trace-retention policy for replay artifacts.
    pub trace_retention: TraceRetention,
    /// Shipping strategy for evidence and trace material.
    pub evidence_shipping_policy: EvidenceShippingPolicy,
    /// Maximum replay depth retained across a disconnected period.
    pub reconnection_replay_depth: u32,
}

impl Default for EdgeReplayConfig {
    fn default() -> Self {
        Self {
            trace_retention: TraceRetention::default(),
            evidence_shipping_policy: EvidenceShippingPolicy::default(),
            reconnection_replay_depth: 256,
        }
    }
}

impl EdgeReplayConfig {
    fn validate(&self) -> Result<(), FederationError> {
        self.trace_retention.validate()?;
        if self.reconnection_replay_depth == 0 {
            return Err(FederationError::ZeroReplayDepth);
        }
        Ok(())
    }
}

/// Top-level federation roles reserved by the FABRIC design.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "config", rename_all = "snake_case")]
pub enum FederationRole {
    /// Constrained export/import boundary optimized for leaves and intermittently connected peers.
    LeafFabric(LeafConfig),
    /// Interest-propagating gateway boundary between fabrics.
    GatewayFabric(GatewayConfig),
    /// Replication-oriented bridge with stronger ordering and catch-up semantics.
    ReplicationLink(ReplicationConfig),
    /// Replay- and evidence-oriented bridge for delayed forensic recovery.
    EdgeReplayLink(EdgeReplayConfig),
}

impl FederationRole {
    /// Return the stable role name for diagnostics and logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::LeafFabric(_) => "leaf_fabric",
            Self::GatewayFabric(_) => "gateway_fabric",
            Self::ReplicationLink(_) => "replication_link",
            Self::EdgeReplayLink(_) => "edge_replay_link",
        }
    }

    /// Validate the role-specific configuration.
    pub fn validate(&self) -> Result<(), FederationError> {
        match self {
            Self::LeafFabric(config) => config.validate(),
            Self::GatewayFabric(config) => config.validate(),
            Self::ReplicationLink(config) => config.validate(),
            Self::EdgeReplayLink(config) => config.validate(),
        }
    }
}

/// Lifecycle state for a federation bridge.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FederationBridgeState {
    /// The bridge is configured but not yet carrying traffic.
    #[default]
    Provisioning,
    /// The bridge is actively exchanging traffic.
    Active,
    /// The bridge is degraded but still present.
    Degraded,
    /// The bridge has been closed.
    Closed,
}

/// Direction of travel across a federation boundary.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FederationDirection {
    /// Traffic is leaving the local fabric for the remote side.
    #[default]
    LocalToRemote,
    /// Traffic is entering the local fabric from the remote side.
    RemoteToLocal,
}

/// Route record retained while a leaf bridge is disconnected or degraded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BufferedLeafRoute {
    /// Direction that the route was attempting to travel.
    pub direction: FederationDirection,
    /// Subject pattern being routed across the leaf boundary.
    pub subject: SubjectPattern,
    /// Effective fanout requested by the route.
    pub fanout: u16,
}

/// Outcome of attempting to route traffic through a leaf bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LeafRouteDisposition {
    /// The route was forwarded immediately because the bridge was active.
    Forwarded {
        /// Route record that was forwarded.
        route: BufferedLeafRoute,
    },
    /// The route was buffered for later replay.
    Buffered {
        /// Route record retained for later replay.
        route: BufferedLeafRoute,
        /// Current number of buffered entries after insertion.
        buffered_entries: usize,
        /// Number of oldest entries dropped to stay within the configured bound.
        dropped_entries: u64,
    },
}

/// Result of draining a disconnected leaf bridge's offline buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeafBufferDrain {
    /// Buffered routes ready to forward after reconnection.
    pub routes: Vec<BufferedLeafRoute>,
    /// Number of older buffered entries that were dropped while disconnected.
    pub dropped_entries: u64,
}

/// Interest propagation plan emitted by a gateway bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayInterestPlan {
    /// Control-plane family carrying the propagated interest.
    pub family: SystemSubjectFamily,
    /// Subject pattern being advertised across the gateway.
    pub pattern: SubjectPattern,
    /// Requested amplification for this propagation step.
    pub requested_amplification: u16,
    /// Amplification admitted after applying the configured and budget limits.
    pub admitted_amplification: u16,
    /// Reserved control-plane budget used for the propagation decision.
    pub budget: ControlBudget,
    /// Policy selected for this gateway role.
    pub policy: InterestPropagationPolicy,
}

/// Canonical gateway interest key retained in runtime state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GatewayInterestRecord {
    /// Control-plane family carrying the propagated interest.
    pub family: SystemSubjectFamily,
    /// Subject pattern being advertised across the gateway.
    pub pattern: SubjectPattern,
}

/// Advisory record forwarded across a gateway bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayAdvisoryRecord {
    /// Advisory family being forwarded.
    pub family: SystemSubjectFamily,
    /// Subject pattern attached to the advisory.
    pub pattern: SubjectPattern,
    /// Reserved control-plane budget for the forwarding action.
    pub budget: ControlBudget,
}

/// Result of a bounded gateway convergence attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayConvergenceRecord {
    /// Wall-clock budget spent converging interests and advisories.
    pub elapsed: Duration,
    /// Whether the convergence attempt exceeded the configured timeout.
    pub timed_out: bool,
    /// Number of propagated interests considered during convergence.
    pub propagated_interest_count: usize,
    /// Number of advisories included in the bounded convergence pass.
    pub forwarded_advisory_count: usize,
}

/// Snapshot-bearing transfer exported by a replication bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationTransfer {
    /// Snapshot sequence exported from the distributed bridge.
    pub sequence: u64,
    /// Ordering guarantee promised by the replication role.
    pub ordering_guarantee: OrderingGuarantee,
    /// Lowercase SHA-256 content hash of the exported snapshot.
    pub snapshot_hash: String,
    /// Deterministic binary snapshot payload.
    pub snapshot_bytes: Vec<u8>,
}

/// Action required to bring a lagging replication peer back into convergence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationCatchUpAction {
    /// Local and remote sequences already agree.
    #[default]
    AlreadyConverged,
    /// Ship a fresh snapshot before any delta replay.
    Snapshot,
    /// Ship a fresh snapshot and then resume log replay.
    SnapshotThenDelta,
    /// Rely on retained deltas only.
    DeltaOnly,
}

/// Plan describing how a lagging replication peer should catch up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationCatchUpPlan {
    /// Configured catch-up policy that produced this plan.
    pub policy: CatchUpPolicy,
    /// Selected recovery action for the current lag.
    pub action: ReplicationCatchUpAction,
    /// Local sequence observed at plan time.
    pub local_sequence: u64,
    /// Remote sequence observed at plan time.
    pub remote_sequence: u64,
    /// Monotonic lag between local and remote.
    pub lag: u64,
}

/// Replay artifact retained for delayed forensic shipping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayArtifactRecord {
    /// Stable artifact identifier used for acknowledgement and deduplication.
    pub artifact_id: String,
    /// Control-plane family that produced the artifact.
    pub family: SystemSubjectFamily,
    /// Logical capture timestamp relative to the local bridge lifecycle.
    pub captured_at: Duration,
    /// Monotonic sequence attached to the artifact.
    pub sequence: u64,
    /// Size of the retained artifact payload in bytes.
    pub bytes: usize,
}

/// Shipping plan emitted by an edge replay bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayShippingPlan {
    /// Shipping policy that selected the current batch.
    pub policy: EvidenceShippingPolicy,
    /// Retained artifacts to ship in this batch.
    pub artifacts: Vec<ReplayArtifactRecord>,
}

/// Inspectable role-specific runtime state for a federation bridge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationBridgeRuntime {
    /// Offline buffering state for a leaf bridge.
    Leaf(LeafBridgeRuntime),
    /// Interest propagation and advisory state for a gateway bridge.
    Gateway(GatewayBridgeRuntime),
    /// Replication snapshot state for a replication bridge.
    Replication(ReplicationBridgeRuntime),
    /// Retained forensic artifact state for an edge replay bridge.
    EdgeReplay(EdgeReplayBridgeRuntime),
}

impl FederationBridgeRuntime {
    fn for_role(role: &FederationRole) -> Self {
        match role {
            FederationRole::LeafFabric(_) => Self::Leaf(LeafBridgeRuntime::default()),
            FederationRole::GatewayFabric(_) => Self::Gateway(GatewayBridgeRuntime::default()),
            FederationRole::ReplicationLink(_) => {
                Self::Replication(ReplicationBridgeRuntime::default())
            }
            FederationRole::EdgeReplayLink(_) => {
                Self::EdgeReplay(EdgeReplayBridgeRuntime::default())
            }
        }
    }
}

/// Runtime state for a leaf federation bridge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeafBridgeRuntime {
    /// Buffered routes retained while the remote leaf is unavailable.
    pub buffered_routes: VecDeque<BufferedLeafRoute>,
    /// Number of oldest routes dropped to stay within the configured limit.
    pub dropped_routes: u64,
}

/// Runtime state for a gateway federation bridge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GatewayBridgeRuntime {
    /// Canonical interest keys currently propagated to remote fabrics.
    pub propagated_interests: BTreeSet<GatewayInterestRecord>,
    /// Advisory records forwarded by the gateway bridge.
    pub forwarded_advisories: Vec<GatewayAdvisoryRecord>,
    /// Most recent bounded convergence attempt.
    pub last_convergence: Option<GatewayConvergenceRecord>,
}

/// Runtime state for a replication federation bridge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplicationBridgeRuntime {
    /// Most recent sequence exported into a replication transfer.
    pub last_exported_sequence: Option<u64>,
    /// Most recent sequence applied from a replication transfer.
    pub last_applied_sequence: Option<u64>,
    /// Most recent catch-up plan issued by the bridge.
    pub last_catch_up: Option<ReplicationCatchUpPlan>,
}

/// Runtime state for an edge replay federation bridge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EdgeReplayBridgeRuntime {
    /// Replay artifacts retained for delayed shipping.
    pub retained_artifacts: Vec<ReplayArtifactRecord>,
    /// Number of non-empty shipping batches emitted so far.
    pub shipped_batches: u64,
}

/// A configured federation bridge between the local fabric and a remote boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationBridge {
    /// Role and role-specific configuration for the bridge.
    pub role: FederationRole,
    /// Morphisms applied while leaving the local fabric.
    pub local_morphisms: Vec<Morphism>,
    /// Morphisms applied while importing traffic from the remote fabric.
    pub remote_morphisms: Vec<Morphism>,
    /// Capabilities available to the bridge when executing its morphisms.
    pub capability_scope: BTreeSet<FabricCapability>,
    /// Current lifecycle state for the bridge.
    pub state: FederationBridgeState,
    /// Ephemeral role-specific runtime state kept out of serialized configs.
    #[serde(skip, default)]
    runtime: Option<FederationBridgeRuntime>,
}

impl PartialEq for FederationBridge {
    fn eq(&self, other: &Self) -> bool {
        self.role == other.role
            && self.local_morphisms == other.local_morphisms
            && self.remote_morphisms == other.remote_morphisms
            && self.capability_scope == other.capability_scope
            && self.state == other.state
    }
}

impl FederationBridge {
    /// Construct and validate a federation bridge definition.
    pub fn new<I>(
        role: FederationRole,
        local_morphisms: Vec<Morphism>,
        remote_morphisms: Vec<Morphism>,
        capability_scope: I,
    ) -> Result<Self, FederationError>
    where
        I: IntoIterator<Item = FabricCapability>,
    {
        role.validate()?;

        let capability_scope = capability_scope.into_iter().collect::<BTreeSet<_>>();
        let runtime = FederationBridgeRuntime::for_role(&role);
        if capability_scope.is_empty() {
            return Err(FederationError::EmptyCapabilityScope);
        }
        if local_morphisms.is_empty() && remote_morphisms.is_empty() {
            return Err(FederationError::EmptyMorphismSet);
        }

        for morphism in local_morphisms.iter().chain(remote_morphisms.iter()) {
            morphism.validate()?;
            ensure_capability_scope(&capability_scope, morphism)?;
        }

        match &role {
            FederationRole::LeafFabric(config) => {
                for morphism in local_morphisms.iter().chain(remote_morphisms.iter()) {
                    config.morphism_constraints.admits(morphism)?;
                }
            }
            FederationRole::GatewayFabric(config) => {
                for morphism in local_morphisms.iter().chain(remote_morphisms.iter()) {
                    if morphism.quota_policy.max_fanout > config.amplification_limit {
                        return Err(FederationError::GatewayAmplificationExceeded {
                            actual: morphism.quota_policy.max_fanout,
                            max: config.amplification_limit,
                        });
                    }
                }
            }
            FederationRole::ReplicationLink(_) => {}
            FederationRole::EdgeReplayLink(_) => {
                if !capability_scope.contains(&FabricCapability::ObserveEvidence) {
                    return Err(FederationError::EdgeReplayRequiresObserveEvidence);
                }
            }
        }

        Ok(Self {
            role,
            local_morphisms,
            remote_morphisms,
            capability_scope,
            state: FederationBridgeState::Provisioning,
            runtime: Some(runtime),
        })
    }

    /// Transition the bridge into active service.
    pub fn activate(&mut self) -> Result<(), FederationError> {
        if self.state == FederationBridgeState::Closed {
            return Err(FederationError::CannotActivateClosedBridge);
        }
        self.state = FederationBridgeState::Active;
        Ok(())
    }

    /// Mark the bridge degraded while retaining its configuration.
    pub fn mark_degraded(&mut self) -> Result<(), FederationError> {
        if self.state == FederationBridgeState::Closed {
            return Err(FederationError::CannotDegradeClosedBridge);
        }
        self.state = FederationBridgeState::Degraded;
        Ok(())
    }

    /// Close the bridge and prevent further activation.
    pub fn close(&mut self) {
        self.state = FederationBridgeState::Closed;
    }

    /// Returns a snapshot of the role-specific bridge runtime state.
    #[must_use]
    pub fn runtime(&self) -> FederationBridgeRuntime {
        self.runtime
            .clone()
            .unwrap_or_else(|| FederationBridgeRuntime::for_role(&self.role))
    }

    /// Route traffic across a leaf bridge, buffering when the link is not active.
    pub fn queue_leaf_route(
        &mut self,
        direction: FederationDirection,
        subject: SubjectPattern,
        fanout: u16,
    ) -> Result<LeafRouteDisposition, FederationError> {
        let config = self.leaf_config("queue_leaf_route")?.clone();
        self.ensure_not_closed("queue_leaf_route")?;

        if fanout > config.morphism_constraints.max_fanout {
            return Err(FederationError::LeafFanoutExceeded {
                actual: fanout,
                max: config.morphism_constraints.max_fanout,
            });
        }

        let route = BufferedLeafRoute {
            direction,
            subject,
            fanout,
        };

        if self.state == FederationBridgeState::Active {
            return Ok(LeafRouteDisposition::Forwarded { route });
        }

        let buffer_limit = usize::try_from(config.offline_buffer_limit).unwrap_or(usize::MAX);
        let runtime = self.leaf_runtime_mut("queue_leaf_route")?;
        if runtime.buffered_routes.len() == buffer_limit {
            runtime.buffered_routes.pop_front();
            runtime.dropped_routes = runtime.dropped_routes.saturating_add(1);
        }
        runtime.buffered_routes.push_back(route.clone());

        Ok(LeafRouteDisposition::Buffered {
            route,
            buffered_entries: runtime.buffered_routes.len(),
            dropped_entries: runtime.dropped_routes,
        })
    }

    /// Drain buffered leaf traffic after the bridge has re-entered active service.
    pub fn drain_leaf_buffer(&mut self) -> Result<LeafBufferDrain, FederationError> {
        self.leaf_config("drain_leaf_buffer")?;
        self.ensure_active_state("drain_leaf_buffer")?;

        let runtime = self.leaf_runtime_mut("drain_leaf_buffer")?;
        let routes = mem::take(&mut runtime.buffered_routes)
            .into_iter()
            .collect();
        let dropped_entries = mem::take(&mut runtime.dropped_routes);

        Ok(LeafBufferDrain {
            routes,
            dropped_entries,
        })
    }

    /// Plan an interest propagation step for a gateway bridge with explicit admission control.
    pub fn plan_gateway_interest(
        &mut self,
        family: SystemSubjectFamily,
        pattern: SubjectPattern,
        requested_amplification: u16,
        budget: ControlBudget,
    ) -> Result<GatewayInterestPlan, FederationError> {
        let config = self.gateway_config("plan_gateway_interest")?.clone();
        self.ensure_operational_state("plan_gateway_interest")?;

        let budget_limit = u16::try_from(budget.poll_quota).unwrap_or(u16::MAX);
        let effective_limit = config.amplification_limit.min(budget_limit);
        if requested_amplification > effective_limit {
            return Err(FederationError::GatewayAmplificationExceeded {
                actual: requested_amplification,
                max: effective_limit,
            });
        }

        let plan = GatewayInterestPlan {
            family,
            pattern: pattern.clone(),
            requested_amplification,
            admitted_amplification: requested_amplification,
            budget,
            policy: config.interest_propagation_policy,
        };

        self.gateway_runtime_mut("plan_gateway_interest")?
            .propagated_interests
            .insert(GatewayInterestRecord { family, pattern });

        Ok(plan)
    }

    /// Forward a bounded control-plane advisory across a gateway bridge.
    pub fn forward_gateway_advisory(
        &mut self,
        family: SystemSubjectFamily,
        pattern: SubjectPattern,
        budget: ControlBudget,
    ) -> Result<GatewayAdvisoryRecord, FederationError> {
        self.gateway_config("forward_gateway_advisory")?;
        self.ensure_operational_state("forward_gateway_advisory")?;

        let record = GatewayAdvisoryRecord {
            family,
            pattern,
            budget,
        };

        self.gateway_runtime_mut("forward_gateway_advisory")?
            .forwarded_advisories
            .push(record.clone());

        Ok(record)
    }

    /// Record the outcome of a bounded gateway convergence attempt.
    pub fn reconcile_gateway_convergence(
        &mut self,
        elapsed: Duration,
    ) -> Result<GatewayConvergenceRecord, FederationError> {
        let config = self
            .gateway_config("reconcile_gateway_convergence")?
            .clone();
        self.ensure_operational_state("reconcile_gateway_convergence")?;

        let timed_out = elapsed > config.convergence_timeout;
        if timed_out {
            self.mark_degraded()?;
        }

        let runtime = self.gateway_runtime_mut("reconcile_gateway_convergence")?;
        let record = GatewayConvergenceRecord {
            elapsed,
            timed_out,
            propagated_interest_count: runtime.propagated_interests.len(),
            forwarded_advisory_count: runtime.forwarded_advisories.len(),
        };
        runtime.last_convergence = Some(record.clone());

        Ok(record)
    }

    /// Export a deterministic replication transfer from the local distributed bridge.
    pub fn export_replication_transfer(
        &mut self,
        bridge: &mut RegionBridge,
        now: Time,
        snapshot_auth_key: &AuthKey,
    ) -> Result<ReplicationTransfer, FederationError> {
        let config = self
            .replication_config("export_replication_transfer")?
            .clone();
        self.ensure_not_closed("export_replication_transfer")?;

        let snapshot = bridge.create_authenticated_snapshot(now, snapshot_auth_key);
        let transfer = ReplicationTransfer {
            sequence: snapshot.sequence,
            ordering_guarantee: config.ordering_guarantee,
            snapshot_hash: snapshot.content_hash().to_hex(),
            snapshot_bytes: snapshot.to_bytes(),
        };

        self.replication_runtime_mut("export_replication_transfer")?
            .last_exported_sequence = Some(transfer.sequence);

        Ok(transfer)
    }

    /// Plan how a lagging replication peer should catch up to the current sequence.
    pub fn plan_replication_catch_up(
        &mut self,
        local_sequence: u64,
        remote_sequence: u64,
    ) -> Result<ReplicationCatchUpPlan, FederationError> {
        let config = self
            .replication_config("plan_replication_catch_up")?
            .clone();
        self.ensure_not_closed("plan_replication_catch_up")?;

        if remote_sequence > local_sequence {
            return Err(FederationError::ReplicationCatchUpRemoteAhead {
                local_sequence,
                remote_sequence,
            });
        }

        let lag = local_sequence.saturating_sub(remote_sequence);
        let action = if lag == 0 {
            ReplicationCatchUpAction::AlreadyConverged
        } else {
            match config.catch_up_policy {
                CatchUpPolicy::SnapshotRequired => ReplicationCatchUpAction::Snapshot,
                CatchUpPolicy::SnapshotThenDelta => {
                    if remote_sequence == 0 || lag > 1 {
                        ReplicationCatchUpAction::SnapshotThenDelta
                    } else {
                        ReplicationCatchUpAction::DeltaOnly
                    }
                }
                CatchUpPolicy::LogOnly => ReplicationCatchUpAction::DeltaOnly,
            }
        };

        let plan = ReplicationCatchUpPlan {
            policy: config.catch_up_policy,
            action,
            local_sequence,
            remote_sequence,
            lag,
        };

        self.replication_runtime_mut("plan_replication_catch_up")?
            .last_catch_up = Some(plan.clone());

        Ok(plan)
    }

    /// Apply a replication transfer to an existing distributed bridge.
    pub fn apply_replication_transfer(
        &mut self,
        bridge: &mut RegionBridge,
        transfer: &ReplicationTransfer,
        snapshot_auth_key: &AuthKey,
    ) -> Result<RegionSnapshot, FederationError> {
        self.replication_config("apply_replication_transfer")?;
        self.ensure_not_closed("apply_replication_transfer")?;

        let snapshot =
            RegionSnapshot::from_bytes_with_key(&transfer.snapshot_bytes, snapshot_auth_key)?;
        if snapshot.sequence != transfer.sequence {
            return Err(FederationError::ReplicationTransferSequenceMismatch {
                expected: transfer.sequence,
                actual: snapshot.sequence,
            });
        }
        let actual_hash = snapshot.content_hash();
        let actual_hash_hex = actual_hash.to_hex();
        if actual_hash_hex != transfer.snapshot_hash {
            return Err(FederationError::ReplicationTransferHashMismatch {
                expected: transfer.snapshot_hash.clone(),
                actual: actual_hash_hex,
            });
        }
        bridge.apply_snapshot(&snapshot).map_err(|error| {
            FederationError::DistributedBridgeOperationFailed {
                operation: "apply_snapshot".to_owned(),
                message: error.to_string(),
            }
        })?;

        self.replication_runtime_mut("apply_replication_transfer")?
            .last_applied_sequence = Some(snapshot.sequence);

        Ok(snapshot)
    }

    /// Retain a replay artifact for later forensic shipping.
    pub fn retain_replay_artifact(
        &mut self,
        artifact: ReplayArtifactRecord,
    ) -> Result<(), FederationError> {
        let config = self.edge_replay_config("retain_replay_artifact")?.clone();
        self.ensure_not_closed("retain_replay_artifact")?;

        let runtime = self.edge_replay_runtime_mut("retain_replay_artifact")?;
        runtime.retained_artifacts.push(artifact);
        trim_replay_artifacts(runtime, &config);

        Ok(())
    }

    /// Acknowledge receipt of an edge replay artifact when using ack-based retention.
    pub fn acknowledge_replay_artifact(
        &mut self,
        artifact_id: &str,
    ) -> Result<bool, FederationError> {
        let config = self
            .edge_replay_config("acknowledge_replay_artifact")?
            .clone();
        self.ensure_not_closed("acknowledge_replay_artifact")?;

        if !matches!(config.trace_retention, TraceRetention::UntilAcknowledged) {
            return Ok(false);
        }

        let runtime = self.edge_replay_runtime_mut("acknowledge_replay_artifact")?;
        let before = runtime.retained_artifacts.len();
        runtime
            .retained_artifacts
            .retain(|artifact| artifact.artifact_id != artifact_id);

        Ok(runtime.retained_artifacts.len() != before)
    }

    /// Plan a replay/evidence shipping batch for the current bridge state.
    pub fn plan_replay_shipping(&mut self) -> Result<ReplayShippingPlan, FederationError> {
        let config = self.edge_replay_config("plan_replay_shipping")?.clone();
        self.ensure_not_closed("plan_replay_shipping")?;

        let state = self.state;
        let runtime = self.edge_replay_runtime_mut("plan_replay_shipping")?;
        let artifacts = match config.evidence_shipping_policy {
            EvidenceShippingPolicy::OnReconnect => {
                if state == FederationBridgeState::Active {
                    runtime.retained_artifacts.clone()
                } else {
                    Vec::new()
                }
            }
            EvidenceShippingPolicy::PeriodicBatch => {
                let batch_size = usize::min(runtime.retained_artifacts.len(), 32);
                runtime.retained_artifacts
                    [runtime.retained_artifacts.len().saturating_sub(batch_size)..]
                    .to_vec()
            }
            EvidenceShippingPolicy::ContinuousMirror => runtime
                .retained_artifacts
                .last()
                .cloned()
                .into_iter()
                .collect(),
        };

        if !artifacts.is_empty() {
            runtime.shipped_batches = runtime.shipped_batches.saturating_add(1);
        }

        Ok(ReplayShippingPlan {
            policy: config.evidence_shipping_policy,
            artifacts,
        })
    }

    fn ensure_not_closed(&self, operation: &'static str) -> Result<(), FederationError> {
        if self.state == FederationBridgeState::Closed {
            return Err(FederationError::BridgeNotOperational {
                operation,
                state: self.state,
            });
        }
        Ok(())
    }

    fn ensure_operational_state(&self, operation: &'static str) -> Result<(), FederationError> {
        match self.state {
            FederationBridgeState::Active | FederationBridgeState::Degraded => Ok(()),
            state => Err(FederationError::BridgeNotOperational { operation, state }),
        }
    }

    fn ensure_active_state(&self, operation: &'static str) -> Result<(), FederationError> {
        if self.state != FederationBridgeState::Active {
            return Err(FederationError::BridgeNotOperational {
                operation,
                state: self.state,
            });
        }
        Ok(())
    }

    fn runtime_mut(&mut self) -> &mut FederationBridgeRuntime {
        if self.runtime.is_none() {
            self.runtime = Some(FederationBridgeRuntime::for_role(&self.role));
        }
        self.runtime
            .as_mut()
            .expect("runtime must exist after lazy initialization")
    }

    fn leaf_config(&self, operation: &'static str) -> Result<&LeafConfig, FederationError> {
        match &self.role {
            FederationRole::LeafFabric(config) => Ok(config),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "leaf_fabric",
                actual: self.role.name(),
            }),
        }
    }

    fn gateway_config(&self, operation: &'static str) -> Result<&GatewayConfig, FederationError> {
        match &self.role {
            FederationRole::GatewayFabric(config) => Ok(config),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "gateway_fabric",
                actual: self.role.name(),
            }),
        }
    }

    fn replication_config(
        &self,
        operation: &'static str,
    ) -> Result<&ReplicationConfig, FederationError> {
        match &self.role {
            FederationRole::ReplicationLink(config) => Ok(config),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "replication_link",
                actual: self.role.name(),
            }),
        }
    }

    fn edge_replay_config(
        &self,
        operation: &'static str,
    ) -> Result<&EdgeReplayConfig, FederationError> {
        match &self.role {
            FederationRole::EdgeReplayLink(config) => Ok(config),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "edge_replay_link",
                actual: self.role.name(),
            }),
        }
    }

    fn leaf_runtime_mut(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut LeafBridgeRuntime, FederationError> {
        let actual = self.role.name();
        match self.runtime_mut() {
            FederationBridgeRuntime::Leaf(runtime) => Ok(runtime),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "leaf_fabric",
                actual,
            }),
        }
    }

    fn gateway_runtime_mut(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut GatewayBridgeRuntime, FederationError> {
        let actual = self.role.name();
        match self.runtime_mut() {
            FederationBridgeRuntime::Gateway(runtime) => Ok(runtime),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "gateway_fabric",
                actual,
            }),
        }
    }

    fn replication_runtime_mut(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut ReplicationBridgeRuntime, FederationError> {
        let actual = self.role.name();
        match self.runtime_mut() {
            FederationBridgeRuntime::Replication(runtime) => Ok(runtime),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "replication_link",
                actual,
            }),
        }
    }

    fn edge_replay_runtime_mut(
        &mut self,
        operation: &'static str,
    ) -> Result<&mut EdgeReplayBridgeRuntime, FederationError> {
        let actual = self.role.name();
        match self.runtime_mut() {
            FederationBridgeRuntime::EdgeReplay(runtime) => Ok(runtime),
            _ => Err(FederationError::RoleOperationMismatch {
                operation,
                expected: "edge_replay_link",
                actual,
            }),
        }
    }
}

fn trim_replay_artifacts(runtime: &mut EdgeReplayBridgeRuntime, config: &EdgeReplayConfig) {
    match &config.trace_retention {
        TraceRetention::LatestArtifacts { max_artifacts } => {
            let keep = usize::try_from(*max_artifacts).unwrap_or(usize::MAX);
            if runtime.retained_artifacts.len() > keep {
                let drop_count = runtime.retained_artifacts.len() - keep;
                runtime.retained_artifacts.drain(..drop_count);
            }
        }
        TraceRetention::DurationWindow { retention } => {
            if let Some(latest) = runtime
                .retained_artifacts
                .last()
                .map(|artifact| artifact.captured_at)
            {
                runtime
                    .retained_artifacts
                    .retain(|artifact| latest.saturating_sub(artifact.captured_at) <= *retention);
            }
        }
        TraceRetention::UntilAcknowledged => {}
    }

    let depth_limit = usize::try_from(config.reconnection_replay_depth).unwrap_or(usize::MAX);
    if runtime.retained_artifacts.len() > depth_limit {
        let drop_count = runtime.retained_artifacts.len() - depth_limit;
        runtime.retained_artifacts.drain(..drop_count);
    }
}

fn ensure_capability_scope(
    capability_scope: &BTreeSet<FabricCapability>,
    morphism: &Morphism,
) -> Result<(), FederationError> {
    for capability in &morphism.capability_requirements {
        if !capability_scope.contains(capability) {
            return Err(FederationError::CapabilityScopeMissing {
                capability: *capability,
            });
        }
    }
    Ok(())
}

/// Deterministic restart envelope for distributed supervision planning.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DistributedRestartEnvelope {
    /// Stop the distributed worker when it fails.
    #[default]
    Stop,
    /// Restart the worker with an explicit bounded restart budget.
    Restart {
        /// Maximum number of restarts permitted in the rolling window.
        max_restarts: u32,
        /// Rolling time window used for restart accounting.
        window: Duration,
        /// Budget cost charged per restart attempt.
        restart_cost: u64,
        /// Minimum remaining time budget required to attempt a restart.
        min_remaining_for_restart: Option<Duration>,
        /// Minimum remaining poll budget required to attempt a restart.
        min_polls_for_restart: u32,
    },
    /// Escalate the failure to the next distributed supervision boundary.
    Escalate,
}

impl DistributedRestartEnvelope {
    /// Construct a bounded restart envelope.
    #[must_use]
    pub fn restart(max_restarts: u32, window: Duration) -> Self {
        Self::Restart {
            max_restarts,
            window,
            restart_cost: 0,
            min_remaining_for_restart: None,
            min_polls_for_restart: 0,
        }
    }

    /// Add per-restart cost accounting.
    #[must_use]
    pub fn with_restart_cost(self, restart_cost: u64) -> Self {
        match self {
            Self::Restart {
                max_restarts,
                window,
                min_remaining_for_restart,
                min_polls_for_restart,
                ..
            } => Self::Restart {
                max_restarts,
                window,
                restart_cost,
                min_remaining_for_restart,
                min_polls_for_restart,
            },
            other => other,
        }
    }

    /// Require a minimum remaining time budget before restarting.
    #[must_use]
    pub fn with_min_remaining(self, min_remaining_for_restart: Duration) -> Self {
        match self {
            Self::Restart {
                max_restarts,
                window,
                restart_cost,
                min_polls_for_restart,
                ..
            } => Self::Restart {
                max_restarts,
                window,
                restart_cost,
                min_remaining_for_restart: Some(min_remaining_for_restart),
                min_polls_for_restart,
            },
            other => other,
        }
    }

    /// Require a minimum remaining poll budget before restarting.
    #[must_use]
    pub fn with_min_polls(self, min_polls_for_restart: u32) -> Self {
        match self {
            Self::Restart {
                max_restarts,
                window,
                restart_cost,
                min_remaining_for_restart,
                ..
            } => Self::Restart {
                max_restarts,
                window,
                restart_cost,
                min_remaining_for_restart,
                min_polls_for_restart,
            },
            other => other,
        }
    }

    fn lease_ttl(&self) -> Duration {
        match self {
            Self::Restart { window, .. } if !window.is_zero() => *window,
            Self::Stop | Self::Escalate | Self::Restart { .. } => Duration::from_secs(30),
        }
    }

    fn to_supervision_strategy(&self) -> Result<SupervisionStrategy, FederationError> {
        match self {
            Self::Stop => Ok(SupervisionStrategy::Stop),
            Self::Escalate => Ok(SupervisionStrategy::Escalate),
            Self::Restart {
                max_restarts,
                window,
                restart_cost,
                min_remaining_for_restart,
                min_polls_for_restart,
            } => {
                if *max_restarts == 0 {
                    return Err(FederationError::ZeroRestartBudget);
                }
                if window.is_zero() {
                    return Err(FederationError::ZeroDuration {
                        field: "distributed_supervision.restart.window".to_owned(),
                    });
                }
                if min_remaining_for_restart.is_some_and(|duration| duration.is_zero()) {
                    return Err(FederationError::ZeroDuration {
                        field: "distributed_supervision.restart.min_remaining_for_restart"
                            .to_owned(),
                    });
                }

                let mut config = RestartConfig::new(*max_restarts, *window)
                    .with_restart_cost(*restart_cost)
                    .with_min_polls(*min_polls_for_restart);
                if let Some(min_remaining) = min_remaining_for_restart {
                    config = config.with_min_remaining(*min_remaining);
                }
                Ok(SupervisionStrategy::Restart(config))
            }
        }
    }
}

/// Declarative node specification for distributed supervision planning.
#[derive(Debug, Clone, PartialEq)]
pub struct DistributedSupervisionNodeSpec {
    /// Stable node identifier used across mailbox, monitor, and handoff plans.
    pub node_id: NodeId,
    /// Canonical tenant/service namespace for this node's mailbox and telemetry.
    pub namespace: NamespaceKernel,
    /// Mailbox component within the namespace.
    pub mailbox_component: NamespaceComponent,
    /// Failure domain identifier used for failover validation.
    pub failure_domain: NamespaceComponent,
    /// Logical mailbox capacity used by remote routing plans.
    pub mailbox_capacity: usize,
    /// Restart envelope compiled into a concrete supervision strategy.
    pub restart_envelope: DistributedRestartEnvelope,
    /// Export morphisms applied when routing this node's mailbox outward.
    pub export_morphisms: Vec<Morphism>,
    /// Import morphisms applied when routing traffic into this node's mailbox.
    pub import_morphisms: Vec<Morphism>,
    /// Remote nodes this node monitors.
    pub monitor_targets: Vec<NodeId>,
    /// Remote nodes this node links bidirectionally.
    pub link_targets: Vec<NodeId>,
    /// Eligible failover targets for this node.
    pub failover_targets: Vec<NodeId>,
}

impl DistributedSupervisionNodeSpec {
    /// Build a validated distributed-supervision node specification.
    pub fn new(
        node_id: impl Into<String>,
        tenant: impl AsRef<str>,
        service: impl AsRef<str>,
        failure_domain: impl AsRef<str>,
        mailbox_capacity: usize,
        restart_envelope: DistributedRestartEnvelope,
    ) -> Result<Self, FederationError> {
        if mailbox_capacity == 0 {
            return Err(FederationError::ZeroMailboxCapacity);
        }

        let node_id = NodeId::new(node_id.into());
        let mailbox_component = NamespaceComponent::parse(node_id.as_str())?;
        let failure_domain = NamespaceComponent::parse(failure_domain)?;

        Ok(Self {
            node_id,
            namespace: NamespaceKernel::new(tenant, service)?,
            mailbox_component,
            failure_domain,
            mailbox_capacity,
            restart_envelope,
            export_morphisms: Vec::new(),
            import_morphisms: Vec::new(),
            monitor_targets: Vec::new(),
            link_targets: Vec::new(),
            failover_targets: Vec::new(),
        })
    }

    /// Install export morphisms for the node's mailbox route.
    #[must_use]
    pub fn with_export_morphisms(mut self, export_morphisms: Vec<Morphism>) -> Self {
        self.export_morphisms = export_morphisms;
        self
    }

    /// Install import morphisms for the node's mailbox route.
    #[must_use]
    pub fn with_import_morphisms(mut self, import_morphisms: Vec<Morphism>) -> Self {
        self.import_morphisms = import_morphisms;
        self
    }

    /// Declare nodes this node monitors.
    #[must_use]
    pub fn with_monitor_targets<I, S>(mut self, monitor_targets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.monitor_targets = monitor_targets
            .into_iter()
            .map(|target| NodeId::new(target.into()))
            .collect();
        self
    }

    /// Declare bidirectional link relationships.
    #[must_use]
    pub fn with_link_targets<I, S>(mut self, link_targets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.link_targets = link_targets
            .into_iter()
            .map(|target| NodeId::new(target.into()))
            .collect();
        self
    }

    /// Declare eligible failover targets.
    #[must_use]
    pub fn with_failover_targets<I, S>(mut self, failover_targets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.failover_targets = failover_targets
            .into_iter()
            .map(|target| NodeId::new(target.into()))
            .collect();
        self
    }

    fn mailbox_subject(&self) -> Result<Subject, FederationError> {
        Ok(self
            .namespace
            .mailbox_subject(self.mailbox_component.as_str())?)
    }

    fn registry_subject(&self) -> SubjectPattern {
        SubjectPattern::from(&self.namespace.service_discovery_subject())
    }

    fn observability_subject(&self) -> Result<SubjectPattern, FederationError> {
        Ok(SubjectPattern::from(
            &self.namespace.observability_subject(format!(
                "supervision-{}",
                self.mailbox_component.as_str()
            ))?,
        ))
    }
}

/// Compiled supervision state for one distributed node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledDistributedSupervisionNode {
    /// Stable node identifier.
    pub node_id: NodeId,
    /// Failure domain attached to this node.
    pub failure_domain: String,
    /// Mailbox capacity compiled into the remote routing surface.
    pub mailbox_capacity: usize,
    /// Canonical mailbox subject before morphism application.
    pub mailbox_subject: SubjectPattern,
    /// Mailbox subject after export morphisms are applied.
    pub exported_mailbox_subject: SubjectPattern,
    /// Mailbox subject after import morphisms are applied.
    pub imported_mailbox_subject: SubjectPattern,
    /// Concrete supervision strategy derived from the restart envelope.
    pub supervision_strategy: SupervisionStrategy,
}

/// Compiled mailbox-routing plan for one distributed node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedMailboxRoute {
    /// Node owning the mailbox.
    pub node_id: NodeId,
    /// Canonical mailbox subject.
    pub mailbox_subject: SubjectPattern,
    /// Exported mailbox subject after namespace rewriting.
    pub exported_mailbox_subject: SubjectPattern,
    /// Imported mailbox subject after namespace rewriting.
    pub imported_mailbox_subject: SubjectPattern,
    /// Morphism classes participating in export routing.
    pub export_classes: Vec<MorphismClass>,
    /// Morphism classes participating in import routing.
    pub import_classes: Vec<MorphismClass>,
}

/// Compiled monitor relationship between two distributed nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedMonitorPlan {
    /// Monitoring node.
    pub watcher: NodeId,
    /// Monitored node.
    pub monitored: NodeId,
    /// Subject carrying deterministic down notifications.
    pub notification_subject: SubjectPattern,
    /// Mailbox subject for the monitored node.
    pub monitored_mailbox_subject: SubjectPattern,
}

/// Compiled bidirectional link contract between two distributed nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedLinkPlan {
    /// First endpoint in canonical lexical order.
    pub left_node: NodeId,
    /// Second endpoint in canonical lexical order.
    pub right_node: NodeId,
    /// Control-plane subject carrying link lifecycle signals.
    pub control_subject: SubjectPattern,
    /// System family reserved for the link lifecycle.
    pub family: SystemSubjectFamily,
}

/// Registry-lease management plan for one distributed node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedRegistryLeasePlan {
    /// Node covered by the lease.
    pub node_id: NodeId,
    /// Failure domain owning the lease.
    pub failure_domain: String,
    /// Service-discovery subject guarded by the lease.
    pub registry_subject: SubjectPattern,
    /// System subject used to renew or revoke the lease.
    pub lease_subject: SubjectPattern,
    /// Deterministic lease TTL.
    pub lease_ttl: Duration,
}

/// Compiled drain and handoff contract for cross-domain failover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedFailoverHandoffContract {
    /// Failing source node.
    pub source_node: NodeId,
    /// Replacement target node.
    pub target_node: NodeId,
    /// Source node failure domain.
    pub source_failure_domain: String,
    /// Target node failure domain.
    pub target_failure_domain: String,
    /// Subject used to initiate a quiescent handoff.
    pub handoff_subject: SubjectPattern,
    /// Subject used to drain in-flight work during failover.
    pub drain_subject: SubjectPattern,
    /// Lease surface the target must claim before cutover.
    pub registry_lease_subject: SubjectPattern,
    /// Replay/evidence surface for this failover contract.
    pub evidence_subject: SubjectPattern,
    /// Strategy that governs the target after cutover.
    pub target_strategy: SupervisionStrategy,
}

/// Evidence-routing hooks emitted for one distributed node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedEvidenceHook {
    /// Node producing evidence.
    pub node_id: NodeId,
    /// Namespace-local observability subject for the node.
    pub observability_subject: SubjectPattern,
    /// Replay/control-plane subject for durable evidence shipping.
    pub replay_subject: SubjectPattern,
    /// Control-plane family used for replay shipping.
    pub family: SystemSubjectFamily,
}

/// Deterministic distributed-supervision compilation output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistributedSupervisionPlan {
    /// Compiled node-local supervision state.
    pub nodes: Vec<CompiledDistributedSupervisionNode>,
    /// Mailbox-routing plans for every node.
    pub mailbox_routes: Vec<DistributedMailboxRoute>,
    /// Remote monitor relationships.
    pub monitor_plans: Vec<DistributedMonitorPlan>,
    /// Remote link relationships.
    pub link_plans: Vec<DistributedLinkPlan>,
    /// Registry-lease plans for mailbox discovery and failover.
    pub registry_leases: Vec<DistributedRegistryLeasePlan>,
    /// Cross-domain failover contracts.
    pub failover_handoffs: Vec<DistributedFailoverHandoffContract>,
    /// Evidence hooks for replay and observability.
    pub evidence_hooks: Vec<DistributedEvidenceHook>,
}

#[derive(Debug)]
struct DistributedNodeCompilationPass {
    nodes: Vec<CompiledDistributedSupervisionNode>,
    mailbox_routes: Vec<DistributedMailboxRoute>,
    registry_leases: Vec<DistributedRegistryLeasePlan>,
    evidence_hooks: Vec<DistributedEvidenceHook>,
}

#[derive(Debug)]
struct DistributedNodeArtifacts {
    compiled_node: CompiledDistributedSupervisionNode,
    mailbox_route: DistributedMailboxRoute,
    registry_lease: DistributedRegistryLeasePlan,
    evidence_hook: DistributedEvidenceHook,
}

#[derive(Debug)]
struct DistributedRelationCompilationPass {
    monitor_plans: Vec<DistributedMonitorPlan>,
    link_plans: Vec<DistributedLinkPlan>,
    failover_handoffs: Vec<DistributedFailoverHandoffContract>,
}

/// Deterministic compiler for distributed supervision plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DistributedSupervisionCompiler;

impl DistributedSupervisionCompiler {
    /// Compile a distributed supervision graph into mailbox, monitor, link,
    /// lease, failover, and evidence plans.
    pub fn compile(
        nodes: &[DistributedSupervisionNodeSpec],
    ) -> Result<DistributedSupervisionPlan, FederationError> {
        let by_id = build_distributed_supervision_index(nodes)?;
        let node_pass = compile_distributed_nodes(&by_id)?;
        let relation_pass = compile_distributed_relations(&by_id)?;

        Ok(DistributedSupervisionPlan {
            nodes: node_pass.nodes,
            mailbox_routes: node_pass.mailbox_routes,
            monitor_plans: relation_pass.monitor_plans,
            link_plans: relation_pass.link_plans,
            registry_leases: node_pass.registry_leases,
            failover_handoffs: relation_pass.failover_handoffs,
            evidence_hooks: node_pass.evidence_hooks,
        })
    }
}

fn build_distributed_supervision_index(
    nodes: &[DistributedSupervisionNodeSpec],
) -> Result<BTreeMap<String, &DistributedSupervisionNodeSpec>, FederationError> {
    if nodes.is_empty() {
        return Err(FederationError::EmptyDistributedSupervisionGraph);
    }

    let mut by_id = BTreeMap::new();
    for node in nodes {
        if by_id
            .insert(node.node_id.as_str().to_owned(), node)
            .is_some()
        {
            return Err(FederationError::DuplicateDistributedSupervisionNode {
                node_id: node.node_id.as_str().to_owned(),
            });
        }
        if node.mailbox_capacity == 0 {
            return Err(FederationError::ZeroMailboxCapacity);
        }
        for morphism in node
            .export_morphisms
            .iter()
            .chain(node.import_morphisms.iter())
        {
            morphism.validate()?;
        }
    }

    Ok(by_id)
}

fn compile_distributed_nodes(
    by_id: &BTreeMap<String, &DistributedSupervisionNodeSpec>,
) -> Result<DistributedNodeCompilationPass, FederationError> {
    let mut pass = DistributedNodeCompilationPass {
        nodes: Vec::new(),
        mailbox_routes: Vec::new(),
        registry_leases: Vec::new(),
        evidence_hooks: Vec::new(),
    };

    for node in by_id.values().copied() {
        let artifacts = compile_distributed_node_artifacts(node)?;
        pass.nodes.push(artifacts.compiled_node);
        pass.mailbox_routes.push(artifacts.mailbox_route);
        pass.registry_leases.push(artifacts.registry_lease);
        pass.evidence_hooks.push(artifacts.evidence_hook);
    }

    Ok(pass)
}

fn compile_distributed_node_artifacts(
    node: &DistributedSupervisionNodeSpec,
) -> Result<DistributedNodeArtifacts, FederationError> {
    let mailbox_subject = node.mailbox_subject()?;
    let mailbox_pattern = SubjectPattern::from(&mailbox_subject);
    let exported_mailbox_subject =
        apply_morphisms_to_subject(&mailbox_subject, &node.export_morphisms)?;
    let imported_mailbox_subject =
        apply_morphisms_to_subject(&mailbox_subject, &node.import_morphisms)?;
    let supervision_strategy = node.restart_envelope.to_supervision_strategy()?;
    let lease_subject = system_subject_pattern(
        SystemSubjectFamily::Route,
        &["registry-lease", node.mailbox_component.as_str()],
    )?;
    let replay_subject = system_subject_pattern(
        SystemSubjectFamily::Replay,
        &["supervision", node.mailbox_component.as_str()],
    )?;

    Ok(DistributedNodeArtifacts {
        compiled_node: CompiledDistributedSupervisionNode {
            node_id: node.node_id.clone(),
            failure_domain: node.failure_domain.as_str().to_owned(),
            mailbox_capacity: node.mailbox_capacity,
            mailbox_subject: mailbox_pattern.clone(),
            exported_mailbox_subject: exported_mailbox_subject.clone(),
            imported_mailbox_subject: imported_mailbox_subject.clone(),
            supervision_strategy,
        },
        mailbox_route: DistributedMailboxRoute {
            node_id: node.node_id.clone(),
            mailbox_subject: mailbox_pattern,
            exported_mailbox_subject,
            imported_mailbox_subject,
            export_classes: node.export_morphisms.iter().map(|m| m.class).collect(),
            import_classes: node.import_morphisms.iter().map(|m| m.class).collect(),
        },
        registry_lease: DistributedRegistryLeasePlan {
            node_id: node.node_id.clone(),
            failure_domain: node.failure_domain.as_str().to_owned(),
            registry_subject: node.registry_subject(),
            lease_subject,
            lease_ttl: node.restart_envelope.lease_ttl(),
        },
        evidence_hook: DistributedEvidenceHook {
            node_id: node.node_id.clone(),
            observability_subject: node.observability_subject()?,
            replay_subject,
            family: SystemSubjectFamily::Replay,
        },
    })
}

fn compile_distributed_relations(
    by_id: &BTreeMap<String, &DistributedSupervisionNodeSpec>,
) -> Result<DistributedRelationCompilationPass, FederationError> {
    let mut pass = DistributedRelationCompilationPass {
        monitor_plans: Vec::new(),
        link_plans: Vec::new(),
        failover_handoffs: Vec::new(),
    };
    let mut link_pairs = BTreeSet::new();

    for node in by_id.values().copied() {
        extend_monitor_plans(&mut pass.monitor_plans, by_id, node)?;
        extend_link_plans(&mut pass.link_plans, &mut link_pairs, by_id, node)?;
        extend_failover_handoffs(&mut pass.failover_handoffs, by_id, node)?;
    }

    Ok(pass)
}

fn extend_monitor_plans(
    monitor_plans: &mut Vec<DistributedMonitorPlan>,
    by_id: &BTreeMap<String, &DistributedSupervisionNodeSpec>,
    node: &DistributedSupervisionNodeSpec,
) -> Result<(), FederationError> {
    for target_id in dedup_node_targets(&node.monitor_targets) {
        let target = resolve_distributed_target(by_id, node, &target_id, "monitor")?;
        monitor_plans.push(DistributedMonitorPlan {
            watcher: node.node_id.clone(),
            monitored: target.node_id.clone(),
            notification_subject: system_subject_pattern(
                SystemSubjectFamily::Drain,
                &[
                    "monitor",
                    node.mailbox_component.as_str(),
                    target.mailbox_component.as_str(),
                ],
            )?,
            monitored_mailbox_subject: SubjectPattern::from(&target.mailbox_subject()?),
        });
    }

    Ok(())
}

fn extend_link_plans(
    link_plans: &mut Vec<DistributedLinkPlan>,
    link_pairs: &mut BTreeSet<(String, String)>,
    by_id: &BTreeMap<String, &DistributedSupervisionNodeSpec>,
    node: &DistributedSupervisionNodeSpec,
) -> Result<(), FederationError> {
    for target_id in dedup_node_targets(&node.link_targets) {
        let target = resolve_distributed_target(by_id, node, &target_id, "link")?;
        let (left, right) = canonical_node_pair(&node.node_id, &target.node_id);
        if link_pairs.insert((left.as_str().to_owned(), right.as_str().to_owned())) {
            link_plans.push(DistributedLinkPlan {
                left_node: left.clone(),
                right_node: right.clone(),
                control_subject: system_subject_pattern(
                    SystemSubjectFamily::Drain,
                    &["link", node_component(&left)?, node_component(&right)?],
                )?,
                family: SystemSubjectFamily::Drain,
            });
        }
    }

    Ok(())
}

fn extend_failover_handoffs(
    failover_handoffs: &mut Vec<DistributedFailoverHandoffContract>,
    by_id: &BTreeMap<String, &DistributedSupervisionNodeSpec>,
    node: &DistributedSupervisionNodeSpec,
) -> Result<(), FederationError> {
    for target_id in dedup_node_targets(&node.failover_targets) {
        let target = resolve_distributed_target(by_id, node, &target_id, "failover_target")?;
        if node.failure_domain == target.failure_domain {
            return Err(FederationError::FailoverTargetSameFailureDomain {
                node_id: node.node_id.as_str().to_owned(),
                target: target.node_id.as_str().to_owned(),
                failure_domain: node.failure_domain.as_str().to_owned(),
            });
        }

        failover_handoffs.push(DistributedFailoverHandoffContract {
            source_node: node.node_id.clone(),
            target_node: target.node_id.clone(),
            source_failure_domain: node.failure_domain.as_str().to_owned(),
            target_failure_domain: target.failure_domain.as_str().to_owned(),
            handoff_subject: system_subject_pattern(
                SystemSubjectFamily::Drain,
                &[
                    "handoff",
                    node.mailbox_component.as_str(),
                    target.mailbox_component.as_str(),
                ],
            )?,
            drain_subject: system_subject_pattern(
                SystemSubjectFamily::Drain,
                &[
                    "failover",
                    node.mailbox_component.as_str(),
                    target.mailbox_component.as_str(),
                ],
            )?,
            registry_lease_subject: system_subject_pattern(
                SystemSubjectFamily::Route,
                &["registry-lease", target.mailbox_component.as_str()],
            )?,
            evidence_subject: system_subject_pattern(
                SystemSubjectFamily::Replay,
                &[
                    "failover",
                    node.mailbox_component.as_str(),
                    target.mailbox_component.as_str(),
                ],
            )?,
            target_strategy: target.restart_envelope.to_supervision_strategy()?,
        });
    }

    Ok(())
}

fn apply_morphisms_to_subject(
    subject: &Subject,
    morphisms: &[Morphism],
) -> Result<SubjectPattern, FederationError> {
    let mut tokens = subject.tokens().to_vec();
    for morphism in morphisms {
        morphism.validate()?;
        tokens = morphism.transform.apply_tokens(&tokens)?;
    }
    Ok(SubjectPattern::from(&Subject::parse(&tokens.join("."))?))
}

fn dedup_node_targets(targets: &[NodeId]) -> Vec<NodeId> {
    targets
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn resolve_distributed_target<'a>(
    by_id: &BTreeMap<String, &'a DistributedSupervisionNodeSpec>,
    source: &DistributedSupervisionNodeSpec,
    target: &NodeId,
    relation: &'static str,
) -> Result<&'a DistributedSupervisionNodeSpec, FederationError> {
    if source.node_id == *target {
        return Err(FederationError::SelfReferentialDistributedRelation {
            node_id: source.node_id.as_str().to_owned(),
            relation,
        });
    }

    by_id.get(target.as_str()).copied().ok_or_else(|| {
        FederationError::UnknownDistributedSupervisionTarget {
            node_id: source.node_id.as_str().to_owned(),
            target: target.as_str().to_owned(),
            relation,
        }
    })
}

fn canonical_node_pair(left: &NodeId, right: &NodeId) -> (NodeId, NodeId) {
    if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    }
}

fn node_component(node: &NodeId) -> Result<&str, FederationError> {
    NamespaceComponent::parse(node.as_str())?;
    Ok(node.as_str())
}

fn system_subject_pattern(
    family: SystemSubjectFamily,
    suffix: &[&str],
) -> Result<SubjectPattern, FederationError> {
    let mut raw = family.prefix();
    for component in suffix {
        NamespaceComponent::parse(component)?;
        raw.push('.');
        raw.push_str(component);
    }
    Ok(SubjectPattern::parse(&raw)?)
}

/// Validation failures for federation-role configuration and bridge wiring.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FederationError {
    /// Duration-valued configuration fields must be positive.
    #[error("duration at `{field}` must be greater than zero")]
    ZeroDuration {
        /// Field that contained a zero duration.
        field: String,
    },
    /// Leaf fabrics must retain at least one offline buffer slot.
    #[error("leaf offline buffer limit must be greater than zero")]
    ZeroOfflineBufferLimit,
    /// Leaf morphism constraints must allow at least one class.
    #[error("leaf morphism constraints must allow at least one morphism class")]
    EmptyAllowedMorphismClasses,
    /// Leaf morphism expansion caps must be positive.
    #[error("leaf morphism max expansion factor must be greater than zero")]
    ZeroMaxExpansionFactor,
    /// Leaf morphism fanout caps must be positive.
    #[error("leaf morphism max fanout must be greater than zero")]
    ZeroMaxFanout,
    /// Gateway fanout bounds must be positive.
    #[error("gateway amplification limit must be greater than zero")]
    ZeroAmplificationLimit,
    /// Replay links must retain at least one artifact when using count-based retention.
    #[error("trace-retention artifact limit must be greater than zero")]
    ZeroTraceArtifactLimit,
    /// Replay links must keep at least one reconnection step.
    #[error("reconnection replay depth must be greater than zero")]
    ZeroReplayDepth,
    /// Federation bridges must expose at least one capability.
    #[error("federation bridge capability scope must not be empty")]
    EmptyCapabilityScope,
    /// Federation bridges must install at least one morphism on one side.
    #[error("federation bridge must declare at least one local or remote morphism")]
    EmptyMorphismSet,
    /// Capability scope must cover every installed morphism.
    #[error("bridge capability scope is missing required capability `{capability:?}`")]
    CapabilityScopeMissing {
        /// Missing capability.
        capability: FabricCapability,
    },
    /// Leaf fabrics reject morphism classes outside the configured envelope.
    #[error("leaf morphism constraints do not admit class `{class:?}`")]
    LeafMorphismClassNotAllowed {
        /// Disallowed morphism class.
        class: MorphismClass,
    },
    /// Leaf fabrics bound namespace expansion.
    #[error("leaf morphism expansion factor {actual} exceeds configured max {max}")]
    LeafExpansionFactorExceeded {
        /// Expansion factor requested by the morphism.
        actual: u16,
        /// Configured maximum expansion factor.
        max: u16,
    },
    /// Leaf fabrics bound fanout.
    #[error("leaf morphism fanout {actual} exceeds configured max {max}")]
    LeafFanoutExceeded {
        /// Fanout requested by the morphism.
        actual: u16,
        /// Configured maximum fanout.
        max: u16,
    },
    /// Gateway fabrics reject morphisms that exceed the configured amplification bound.
    #[error("gateway morphism fanout {actual} exceeds amplification limit {max}")]
    GatewayAmplificationExceeded {
        /// Fanout requested by the morphism.
        actual: u16,
        /// Gateway amplification limit.
        max: u16,
    },
    /// A bridge operation was attempted against the wrong federation role.
    #[error("operation `{operation}` requires role `{expected}`, but bridge role is `{actual}`")]
    RoleOperationMismatch {
        /// Operation being attempted.
        operation: &'static str,
        /// Role required by the operation.
        expected: &'static str,
        /// Actual configured role for the bridge.
        actual: &'static str,
    },
    /// Some bridge operations require an active or degraded bridge rather than provisioning/closed.
    #[error("operation `{operation}` is not available while bridge state is `{state:?}`")]
    BridgeNotOperational {
        /// Operation being attempted.
        operation: &'static str,
        /// Current bridge state.
        state: FederationBridgeState,
    },
    /// Replay bridges require evidence-observation capability.
    #[error("edge replay links require observe-evidence capability in scope")]
    EdgeReplayRequiresObserveEvidence,
    /// Distributed supervision nodes must reserve a positive mailbox capacity.
    #[error("distributed supervision mailbox capacity must be greater than zero")]
    ZeroMailboxCapacity,
    /// Distributed restart envelopes must budget at least one restart.
    #[error("distributed supervision restart envelope must allow at least one restart")]
    ZeroRestartBudget,
    /// Distributed supervision compilation requires at least one node.
    #[error("distributed supervision graph must contain at least one node")]
    EmptyDistributedSupervisionGraph,
    /// Node identifiers must be unique in one distributed supervision graph.
    #[error("duplicate distributed supervision node `{node_id}`")]
    DuplicateDistributedSupervisionNode {
        /// Duplicate node identifier.
        node_id: String,
    },
    /// Relations must refer to an existing target node.
    #[error(
        "distributed supervision node `{node_id}` references unknown {relation} target `{target}`"
    )]
    UnknownDistributedSupervisionTarget {
        /// Source node identifier.
        node_id: String,
        /// Missing target identifier.
        target: String,
        /// Relation carrying the missing target.
        relation: &'static str,
    },
    /// Monitor/link/failover relations must not point back to self.
    #[error("distributed supervision node `{node_id}` must not declare a self-{relation}")]
    SelfReferentialDistributedRelation {
        /// Source node identifier.
        node_id: String,
        /// Relation carrying the self-reference.
        relation: &'static str,
    },
    /// Failover requires a genuinely different failure domain.
    #[error(
        "distributed supervision failover from `{node_id}` to `{target}` must cross failure domains (current domain `{failure_domain}`)"
    )]
    FailoverTargetSameFailureDomain {
        /// Source node identifier.
        node_id: String,
        /// Failover target identifier.
        target: String,
        /// Shared failure domain that made the failover invalid.
        failure_domain: String,
    },
    /// Closed bridges cannot be reactivated.
    #[error("cannot activate a closed federation bridge")]
    CannotActivateClosedBridge,
    /// Closed bridges cannot re-enter degraded service.
    #[error("cannot degrade a closed federation bridge")]
    CannotDegradeClosedBridge,
    /// Replication transfer payloads must decode into valid region snapshots.
    #[error(transparent)]
    SnapshotDecode(#[from] SnapshotError),
    /// Distributed bridge integration failed while applying a recovered snapshot.
    #[error("distributed bridge operation `{operation}` failed: {message}")]
    DistributedBridgeOperationFailed {
        /// Underlying distributed bridge operation.
        operation: String,
        /// Stringified error from the distributed bridge surface.
        message: String,
    },
    /// Replication transfer metadata must match the decoded snapshot payload.
    #[error("replication transfer sequence mismatch: expected {expected}, got {actual}")]
    ReplicationTransferSequenceMismatch {
        /// Sequence number advertised by the transfer envelope.
        expected: u64,
        /// Sequence number decoded from the snapshot payload.
        actual: u64,
    },
    /// Replication transfer content hash must match the decoded snapshot payload.
    #[error("replication transfer hash mismatch: expected {expected}, got {actual}")]
    ReplicationTransferHashMismatch {
        /// Hash advertised by the transfer envelope.
        expected: String,
        /// Hash recomputed from the decoded snapshot payload.
        actual: String,
    },
    /// Catch-up planning fails closed if the remote peer reports a newer sequence.
    #[error(
        "replication catch-up cannot treat remote peer as converged when remote sequence {remote_sequence} exceeds local sequence {local_sequence}"
    )]
    ReplicationCatchUpRemoteAhead {
        /// Local sequence available to export.
        local_sequence: u64,
        /// Remote sequence reported by the peer.
        remote_sequence: u64,
    },
    /// Underlying morphism validation failed.
    #[error(transparent)]
    MorphismValidation(#[from] MorphismValidationError),
    /// Deterministic morphism evaluation failed while compiling a plan.
    #[error(transparent)]
    MorphismEvaluation(#[from] MorphismEvaluationError),
    /// Subject or mailbox construction failed.
    #[error(transparent)]
    SubjectPattern(#[from] SubjectPatternError),
    /// Namespace kernel construction failed.
    #[error(transparent)]
    NamespaceKernel(#[from] NamespaceKernelError),
}

#[cfg(test)]
#[path = "federation_inline_tests.rs"]
mod tests;
