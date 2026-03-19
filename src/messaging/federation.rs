//! Federation-role definitions for FABRIC interconnects.

use super::morphism::{FabricCapability, Morphism, MorphismClass, MorphismValidationError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;
use thiserror::Error;

/// Constraints applied to export/import morphisms on leaf fabrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
            snapshot_interval: Duration::from_mins(1),
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

/// A configured federation bridge between the local fabric and a remote boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Replay bridges require evidence-observation capability.
    #[error("edge replay links require observe-evidence capability in scope")]
    EdgeReplayRequiresObserveEvidence,
    /// Closed bridges cannot be reactivated.
    #[error("cannot activate a closed federation bridge")]
    CannotActivateClosedBridge,
    /// Closed bridges cannot re-enter degraded service.
    #[error("cannot degrade a closed federation bridge")]
    CannotDegradeClosedBridge,
    /// Underlying morphism validation failed.
    #[error(transparent)]
    MorphismValidation(#[from] MorphismValidationError),
}

#[cfg(test)]
mod tests {
    use super::super::morphism::{ResponsePolicy, ReversibilityRequirement, SharingPolicy};
    use super::*;

    fn derived_view_morphism() -> Morphism {
        Morphism::default()
    }

    fn authoritative_morphism() -> Morphism {
        Morphism {
            class: MorphismClass::Authoritative,
            reversibility: ReversibilityRequirement::Bijective,
            capability_requirements: vec![FabricCapability::CarryAuthority],
            response_policy: ResponsePolicy::ReplyAuthoritative,
            ..Morphism::default()
        }
    }

    #[test]
    fn leaf_bridge_accepts_constrained_morphisms() {
        let bridge = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("leaf bridge should accept bounded derived-view morphisms");

        assert_eq!(bridge.role.name(), "leaf_fabric");
        assert_eq!(bridge.state, FederationBridgeState::Provisioning);
    }

    #[test]
    fn leaf_bridge_rejects_disallowed_authoritative_morphism() {
        let err = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![authoritative_morphism()],
            Vec::new(),
            [FabricCapability::CarryAuthority],
        )
        .expect_err("leaf bridge should reject authoritative morphisms");

        assert_eq!(
            err,
            FederationError::LeafMorphismClassNotAllowed {
                class: MorphismClass::Authoritative,
            }
        );
    }

    #[test]
    fn gateway_config_rejects_zero_convergence_timeout() {
        let role = FederationRole::GatewayFabric(GatewayConfig {
            convergence_timeout: Duration::ZERO,
            ..GatewayConfig::default()
        });

        let err = role
            .validate()
            .expect_err("zero convergence timeout must be rejected");

        assert_eq!(
            err,
            FederationError::ZeroDuration {
                field: "role.gateway_fabric.convergence_timeout".to_owned(),
            }
        );
    }

    #[test]
    fn gateway_bridge_rejects_morphism_fanout_above_limit() {
        let mut morphism = derived_view_morphism();
        morphism.quota_policy.max_fanout = 9;
        let role = FederationRole::GatewayFabric(GatewayConfig {
            amplification_limit: 4,
            ..GatewayConfig::default()
        });

        let err = FederationBridge::new(
            role,
            vec![morphism],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect_err("gateway should reject excessive fanout");

        assert_eq!(
            err,
            FederationError::GatewayAmplificationExceeded { actual: 9, max: 4 }
        );
    }

    #[test]
    fn edge_replay_bridge_requires_observe_evidence_capability() {
        let err = FederationBridge::new(
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect_err("edge replay should require evidence capability");

        assert_eq!(err, FederationError::EdgeReplayRequiresObserveEvidence);
    }

    #[test]
    fn bridge_lifecycle_moves_through_active_degraded_and_closed_states() {
        let mut bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("replication bridge should be valid");

        bridge.activate().expect("bridge should activate");
        assert_eq!(bridge.state, FederationBridgeState::Active);

        bridge
            .mark_degraded()
            .expect("bridge should enter degraded state");
        assert_eq!(bridge.state, FederationBridgeState::Degraded);

        bridge.activate().expect("bridge should reactivate");
        assert_eq!(bridge.state, FederationBridgeState::Active);

        bridge.close();
        assert_eq!(bridge.state, FederationBridgeState::Closed);
        assert_eq!(
            bridge
                .activate()
                .expect_err("closed bridge must not reactivate"),
            FederationError::CannotActivateClosedBridge
        );
    }

    // ========================================================================
    // Comprehensive federation tests (bead 8w83i.11.3)
    // ========================================================================

    // -- MorphismConstraints validation --------------------------------------

    #[test]
    fn morphism_constraints_default_allows_derived_view_and_egress() {
        let mc = MorphismConstraints::default();
        assert!(mc.allowed_classes.contains(&MorphismClass::DerivedView));
        assert!(mc.allowed_classes.contains(&MorphismClass::Egress));
        assert_eq!(mc.allowed_classes.len(), 2);
        assert!(mc.validate().is_ok());
    }

    #[test]
    fn morphism_constraints_rejects_empty_allowed_classes() {
        let mc = MorphismConstraints {
            allowed_classes: BTreeSet::new(),
            ..MorphismConstraints::default()
        };
        assert_eq!(
            mc.validate().unwrap_err(),
            FederationError::EmptyAllowedMorphismClasses
        );
    }

    #[test]
    fn morphism_constraints_rejects_zero_expansion_factor() {
        let mc = MorphismConstraints {
            max_expansion_factor: 0,
            ..MorphismConstraints::default()
        };
        assert_eq!(
            mc.validate().unwrap_err(),
            FederationError::ZeroMaxExpansionFactor
        );
    }

    #[test]
    fn morphism_constraints_rejects_zero_fanout() {
        let mc = MorphismConstraints {
            max_fanout: 0,
            ..MorphismConstraints::default()
        };
        assert_eq!(mc.validate().unwrap_err(), FederationError::ZeroMaxFanout);
    }

    #[test]
    fn morphism_constraints_admits_within_bounds() {
        let mc = MorphismConstraints::default();
        let m = derived_view_morphism();
        assert!(mc.admits(&m).is_ok());
    }

    #[test]
    fn morphism_constraints_rejects_expansion_factor_exceeded() {
        let mc = MorphismConstraints {
            max_expansion_factor: 2,
            ..MorphismConstraints::default()
        };
        let mut m = derived_view_morphism();
        m.quota_policy.max_expansion_factor = 5;
        match mc.admits(&m) {
            Err(FederationError::LeafExpansionFactorExceeded { actual, max }) => {
                assert_eq!(actual, 5);
                assert_eq!(max, 2);
            }
            other => panic!("expected LeafExpansionFactorExceeded, got {other:?}"),
        }
    }

    #[test]
    fn morphism_constraints_rejects_fanout_exceeded() {
        let mc = MorphismConstraints {
            max_fanout: 3,
            ..MorphismConstraints::default()
        };
        let mut m = derived_view_morphism();
        m.quota_policy.max_fanout = 10;
        match mc.admits(&m) {
            Err(FederationError::LeafFanoutExceeded { actual, max }) => {
                assert_eq!(actual, 10);
                assert_eq!(max, 3);
            }
            other => panic!("expected LeafFanoutExceeded, got {other:?}"),
        }
    }

    // -- LeafConfig validation -----------------------------------------------

    #[test]
    fn leaf_config_default_validates() {
        let config = LeafConfig::default();
        assert!(config.validate().is_ok());
        assert!(config.max_reconnect_backoff > Duration::ZERO);
        assert!(config.offline_buffer_limit > 0);
    }

    #[test]
    fn leaf_config_rejects_zero_reconnect_backoff() {
        let config = LeafConfig {
            max_reconnect_backoff: Duration::ZERO,
            ..LeafConfig::default()
        };
        match config.validate() {
            Err(FederationError::ZeroDuration { field }) => {
                assert!(field.contains("max_reconnect_backoff"));
            }
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    #[test]
    fn leaf_config_rejects_zero_offline_buffer() {
        let config = LeafConfig {
            offline_buffer_limit: 0,
            ..LeafConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            FederationError::ZeroOfflineBufferLimit
        );
    }

    // -- GatewayConfig validation --------------------------------------------

    #[test]
    fn gateway_config_default_validates() {
        let config = GatewayConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.interest_propagation_policy,
            InterestPropagationPolicy::DemandDriven
        );
    }

    #[test]
    fn gateway_config_rejects_zero_amplification_limit() {
        let config = GatewayConfig {
            amplification_limit: 0,
            ..GatewayConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            FederationError::ZeroAmplificationLimit
        );
    }

    // -- ReplicationConfig validation ----------------------------------------

    #[test]
    fn replication_config_default_validates() {
        let config = ReplicationConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.ordering_guarantee, OrderingGuarantee::PerSubject);
        assert_eq!(config.catch_up_policy, CatchUpPolicy::SnapshotThenDelta);
    }

    #[test]
    fn replication_config_rejects_zero_snapshot_interval() {
        let config = ReplicationConfig {
            snapshot_interval: Duration::ZERO,
            ..ReplicationConfig::default()
        };
        match config.validate() {
            Err(FederationError::ZeroDuration { field }) => {
                assert!(field.contains("snapshot_interval"));
            }
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    // -- TraceRetention validation -------------------------------------------

    #[test]
    fn trace_retention_default_validates() {
        let retention = TraceRetention::default();
        assert!(retention.validate().is_ok());
        assert!(matches!(
            retention,
            TraceRetention::LatestArtifacts { max_artifacts: 128 }
        ));
    }

    #[test]
    fn trace_retention_rejects_zero_artifacts() {
        let retention = TraceRetention::LatestArtifacts { max_artifacts: 0 };
        assert_eq!(
            retention.validate().unwrap_err(),
            FederationError::ZeroTraceArtifactLimit
        );
    }

    #[test]
    fn trace_retention_rejects_zero_duration_window() {
        let retention = TraceRetention::DurationWindow {
            retention: Duration::ZERO,
        };
        match retention.validate() {
            Err(FederationError::ZeroDuration { .. }) => {}
            other => panic!("expected ZeroDuration, got {other:?}"),
        }
    }

    #[test]
    fn trace_retention_until_acknowledged_validates() {
        let retention = TraceRetention::UntilAcknowledged;
        assert!(retention.validate().is_ok());
    }

    // -- EdgeReplayConfig validation -----------------------------------------

    #[test]
    fn edge_replay_config_default_validates() {
        let config = EdgeReplayConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(
            config.evidence_shipping_policy,
            EvidenceShippingPolicy::OnReconnect
        );
        assert!(config.reconnection_replay_depth > 0);
    }

    #[test]
    fn edge_replay_config_rejects_zero_replay_depth() {
        let config = EdgeReplayConfig {
            reconnection_replay_depth: 0,
            ..EdgeReplayConfig::default()
        };
        assert_eq!(
            config.validate().unwrap_err(),
            FederationError::ZeroReplayDepth
        );
    }

    // -- FederationRole name and validation -----------------------------------

    #[test]
    fn all_role_names_are_distinct() {
        let roles = [
            FederationRole::LeafFabric(LeafConfig::default()),
            FederationRole::GatewayFabric(GatewayConfig::default()),
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
        ];
        let mut names: Vec<&str> = roles.iter().map(|r| r.name()).collect();
        let orig = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), orig, "role names must be unique");
    }

    #[test]
    fn all_default_role_configs_validate() {
        let roles = [
            FederationRole::LeafFabric(LeafConfig::default()),
            FederationRole::GatewayFabric(GatewayConfig::default()),
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
        ];
        for role in &roles {
            assert!(
                role.validate().is_ok(),
                "role {} default config should validate",
                role.name()
            );
        }
    }

    // -- FederationBridge construction ----------------------------------------

    #[test]
    fn bridge_rejects_empty_capability_scope() {
        let err = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            Vec::<FabricCapability>::new(),
        )
        .unwrap_err();
        assert_eq!(err, FederationError::EmptyCapabilityScope);
    }

    #[test]
    fn bridge_rejects_empty_morphism_set() {
        let err = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            Vec::new(),
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap_err();
        assert_eq!(err, FederationError::EmptyMorphismSet);
    }

    #[test]
    fn bridge_rejects_missing_capability_for_morphism() {
        let err = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![authoritative_morphism()],
            Vec::new(),
            // Missing CarryAuthority
            [FabricCapability::RewriteNamespace],
        )
        .unwrap_err();
        assert_eq!(
            err,
            FederationError::CapabilityScopeMissing {
                capability: FabricCapability::CarryAuthority,
            }
        );
    }

    #[test]
    fn bridge_accepts_morphisms_on_remote_side_only() {
        let bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            Vec::new(),
            vec![derived_view_morphism()],
            [FabricCapability::RewriteNamespace],
        )
        .expect("remote-only morphisms should be accepted");
        assert!(bridge.local_morphisms.is_empty());
        assert_eq!(bridge.remote_morphisms.len(), 1);
    }

    #[test]
    fn bridge_accepts_morphisms_on_both_sides() {
        let bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            vec![derived_view_morphism()],
            [FabricCapability::RewriteNamespace],
        )
        .expect("morphisms on both sides should be accepted");
        assert_eq!(bridge.local_morphisms.len(), 1);
        assert_eq!(bridge.remote_morphisms.len(), 1);
    }

    #[test]
    fn edge_replay_bridge_succeeds_with_observe_evidence() {
        let bridge = FederationBridge::new(
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [
                FabricCapability::RewriteNamespace,
                FabricCapability::ObserveEvidence,
            ],
        )
        .expect("edge replay with ObserveEvidence should succeed");
        assert_eq!(bridge.role.name(), "edge_replay_link");
    }

    // -- Bridge lifecycle edge cases -----------------------------------------

    #[test]
    fn bridge_starts_in_provisioning() {
        let bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        assert_eq!(bridge.state, FederationBridgeState::Provisioning);
    }

    #[test]
    fn closed_bridge_cannot_be_degraded() {
        let mut bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.close();
        assert_eq!(
            bridge.mark_degraded().unwrap_err(),
            FederationError::CannotDegradeClosedBridge
        );
    }

    #[test]
    fn degraded_bridge_can_be_reactivated() {
        let mut bridge = FederationBridge::new(
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            vec![derived_view_morphism()],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .unwrap();
        bridge.mark_degraded().unwrap();
        bridge
            .activate()
            .expect("degraded bridge should reactivate");
        assert_eq!(bridge.state, FederationBridgeState::Active);
    }

    // -- Serialization round-trips -------------------------------------------

    #[test]
    fn leaf_config_json_round_trip() {
        let config = LeafConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: LeafConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn gateway_config_json_round_trip() {
        let config = GatewayConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: GatewayConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn replication_config_json_round_trip() {
        let config = ReplicationConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: ReplicationConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn edge_replay_config_json_round_trip() {
        let config = EdgeReplayConfig::default();
        let json = serde_json::to_string(&config).expect("serialize");
        let roundtrip: EdgeReplayConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(config, roundtrip);
    }

    #[test]
    fn federation_role_tagged_json_round_trip() {
        for role in [
            FederationRole::LeafFabric(LeafConfig::default()),
            FederationRole::GatewayFabric(GatewayConfig::default()),
            FederationRole::ReplicationLink(ReplicationConfig::default()),
            FederationRole::EdgeReplayLink(EdgeReplayConfig::default()),
        ] {
            let json = serde_json::to_string(&role).expect("serialize");
            let roundtrip: FederationRole = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(role, roundtrip);
        }
    }

    #[test]
    fn bridge_state_json_round_trip() {
        for state in [
            FederationBridgeState::Provisioning,
            FederationBridgeState::Active,
            FederationBridgeState::Degraded,
            FederationBridgeState::Closed,
        ] {
            let json = serde_json::to_string(&state).expect("serialize");
            let roundtrip: FederationBridgeState =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(state, roundtrip);
        }
    }

    #[test]
    fn interest_propagation_all_variants_json_round_trip() {
        for policy in [
            InterestPropagationPolicy::ExplicitSubscriptions,
            InterestPropagationPolicy::PrefixAnnouncements,
            InterestPropagationPolicy::DemandDriven,
        ] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let roundtrip: InterestPropagationPolicy =
                serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, roundtrip);
        }
    }

    #[test]
    fn ordering_guarantee_all_variants_json_round_trip() {
        for guarantee in [
            OrderingGuarantee::PerSubject,
            OrderingGuarantee::SnapshotConsistent,
            OrderingGuarantee::CheckpointBounded,
        ] {
            let json = serde_json::to_string(&guarantee).expect("serialize");
            let roundtrip: OrderingGuarantee = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(guarantee, roundtrip);
        }
    }

    #[test]
    fn catch_up_policy_all_variants_json_round_trip() {
        for policy in [
            CatchUpPolicy::SnapshotRequired,
            CatchUpPolicy::SnapshotThenDelta,
            CatchUpPolicy::LogOnly,
        ] {
            let json = serde_json::to_string(&policy).expect("serialize");
            let roundtrip: CatchUpPolicy = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(policy, roundtrip);
        }
    }

    #[test]
    fn trace_retention_all_variants_json_round_trip() {
        for retention in [
            TraceRetention::LatestArtifacts { max_artifacts: 42 },
            TraceRetention::DurationWindow {
                retention: Duration::from_secs(3600),
            },
            TraceRetention::UntilAcknowledged,
        ] {
            let json = serde_json::to_string(&retention).expect("serialize");
            let roundtrip: TraceRetention = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(retention, roundtrip);
        }
    }

    // -- FederationBridgeState ordering --------------------------------------

    #[test]
    fn bridge_states_have_consistent_ordering() {
        assert!(FederationBridgeState::Provisioning < FederationBridgeState::Active);
        assert!(FederationBridgeState::Active < FederationBridgeState::Degraded);
        assert!(FederationBridgeState::Degraded < FederationBridgeState::Closed);
    }

    // -- Gateway amplification enforcement -----------------------------------

    #[test]
    fn gateway_bridge_accepts_morphism_within_limit() {
        let mut morphism = derived_view_morphism();
        morphism.quota_policy.max_fanout = 4;
        let bridge = FederationBridge::new(
            FederationRole::GatewayFabric(GatewayConfig {
                amplification_limit: 4,
                ..GatewayConfig::default()
            }),
            vec![morphism],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("gateway should accept morphism at limit boundary");
        assert_eq!(bridge.role.name(), "gateway_fabric");
    }

    // -- Leaf boundary morphism class enforcement ----------------------------

    #[test]
    fn leaf_accepts_egress_morphism() {
        let mut morphism = derived_view_morphism();
        morphism.class = MorphismClass::Egress;
        morphism.response_policy = ResponsePolicy::StripReplies;
        morphism.reversibility = ReversibilityRequirement::Irreversible;
        morphism.sharing_policy = SharingPolicy::Federated;
        let bridge = FederationBridge::new(
            FederationRole::LeafFabric(LeafConfig::default()),
            vec![morphism],
            Vec::new(),
            [FabricCapability::RewriteNamespace],
        )
        .expect("leaf should accept egress morphisms");
        assert_eq!(bridge.role.name(), "leaf_fabric");
    }

    // -- Default enum values -------------------------------------------------

    #[test]
    fn default_enum_values_are_expected() {
        assert_eq!(
            InterestPropagationPolicy::default(),
            InterestPropagationPolicy::DemandDriven
        );
        assert_eq!(OrderingGuarantee::default(), OrderingGuarantee::PerSubject);
        assert_eq!(CatchUpPolicy::default(), CatchUpPolicy::SnapshotThenDelta);
        assert_eq!(
            EvidenceShippingPolicy::default(),
            EvidenceShippingPolicy::OnReconnect
        );
        assert_eq!(
            FederationBridgeState::default(),
            FederationBridgeState::Provisioning
        );
    }
}
