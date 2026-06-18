//! Explicit multi-source ATP fetch planning.
//!
//! Multi-source transfer starts from a receiver-owned list of candidate peers
//! that can serve the same object. This module keeps that protocol decision
//! transport-agnostic: validate the explicit source list, select a deterministic
//! subset, assign complementary source/repair emphasis to reduce waste, and
//! produce the stop fanout once any union of symbols decodes.

use std::collections::{BTreeMap, BTreeSet};

/// Stable object identity used to prove all selected peers serve the same data.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiSourceObjectRef {
    /// Transfer or object identifier shared by the peers.
    pub object_id: String,
    /// Expected Merkle root for the complete logical object.
    pub merkle_root_hex: String,
}

impl MultiSourceObjectRef {
    /// Create an object reference.
    #[must_use]
    pub fn new(object_id: impl Into<String>, merkle_root_hex: impl Into<String>) -> Self {
        Self {
            object_id: object_id.into(),
            merkle_root_hex: merkle_root_hex.into(),
        }
    }

    fn validate(&self) -> Result<(), MultiSourcePlanError> {
        if self.object_id.trim().is_empty() {
            return Err(MultiSourcePlanError::EmptyObjectId);
        }
        if self.merkle_root_hex.trim().is_empty() {
            return Err(MultiSourcePlanError::EmptyMerkleRoot);
        }
        Ok(())
    }
}

/// Per-peer authentication posture for a multi-source candidate.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum MultiSourceAuth {
    /// The peer must authenticate symbols with the named per-transfer key scope.
    SymbolAuth { key_id: String },
    /// Lab-only escape hatch. Production plans reject this unless explicitly allowed.
    UnauthenticatedLab,
}

impl MultiSourceAuth {
    /// Return a stable lower-case identifier for logs and plan artifacts.
    #[must_use]
    pub fn mode_id(&self) -> &'static str {
        match self {
            Self::SymbolAuth { .. } => "symbol_auth",
            Self::UnauthenticatedLab => "unauthenticated_lab",
        }
    }

    fn is_symbol_auth(&self) -> bool {
        matches!(self, Self::SymbolAuth { .. })
    }

    fn validate(&self) -> Result<(), MultiSourcePlanError> {
        match self {
            Self::SymbolAuth { key_id } if key_id.trim().is_empty() => {
                Err(MultiSourcePlanError::EmptyAuthKeyId)
            }
            _ => Ok(()),
        }
    }
}

/// One explicit peer that can serve the object.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiSourcePeer {
    /// Stable peer label or identity digest.
    pub peer_id: String,
    /// Transport endpoint, for example `host:port`.
    pub endpoint: String,
    /// Lower values are selected first.
    pub priority: u32,
    /// Authentication posture required for this source.
    pub auth: MultiSourceAuth,
}

impl MultiSourcePeer {
    /// Create a candidate source peer.
    #[must_use]
    pub fn new(
        peer_id: impl Into<String>,
        endpoint: impl Into<String>,
        priority: u32,
        auth: MultiSourceAuth,
    ) -> Self {
        Self {
            peer_id: peer_id.into(),
            endpoint: endpoint.into(),
            priority,
            auth,
        }
    }

    fn validate(&self) -> Result<(), MultiSourcePlanError> {
        if self.peer_id.trim().is_empty() {
            return Err(MultiSourcePlanError::EmptyPeerId);
        }
        if self.endpoint.trim().is_empty() {
            return Err(MultiSourcePlanError::EmptyEndpoint {
                peer_id: self.peer_id.clone(),
            });
        }
        self.auth.validate()
    }
}

/// How a selected source should bias its first spray.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum MultiSourceSymbolBias {
    /// Prefer systematic/source symbols first.
    SourceFirst,
    /// Prefer repair symbols earlier to complement a source-first peer.
    RepairFirst,
    /// Balanced fallback for additional sources.
    Balanced,
}

impl MultiSourceSymbolBias {
    /// Stable lower-case identifier for logs and plan artifacts.
    #[must_use]
    pub const fn bias_id(self) -> &'static str {
        match self {
            Self::SourceFirst => "source_first",
            Self::RepairFirst => "repair_first",
            Self::Balanced => "balanced",
        }
    }
}

/// Config for deterministic explicit-source selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiSourceSelectionConfig {
    /// Minimum eligible sources needed before the plan is usable.
    pub min_sources: usize,
    /// Maximum selected sources to ask for the object.
    pub max_sources: usize,
    /// Whether `UnauthenticatedLab` peers are admitted.
    pub allow_unauthenticated_lab: bool,
}

impl MultiSourceSelectionConfig {
    /// Production default: at least two authenticated sources, select up to four.
    #[must_use]
    pub const fn production_default() -> Self {
        Self {
            min_sources: 2,
            max_sources: 4,
            allow_unauthenticated_lab: false,
        }
    }

    fn validate(self) -> Result<(), MultiSourcePlanError> {
        if self.min_sources == 0 {
            return Err(MultiSourcePlanError::ZeroMinSources);
        }
        if self.max_sources < self.min_sources {
            return Err(MultiSourcePlanError::MaxSourcesBelowMin {
                min_sources: self.min_sources,
                max_sources: self.max_sources,
            });
        }
        Ok(())
    }
}

impl Default for MultiSourceSelectionConfig {
    fn default() -> Self {
        Self::production_default()
    }
}

/// One selected peer with its deterministic role in the multi-source fetch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiSourceSourcePlan {
    /// Selected source peer.
    pub peer: MultiSourcePeer,
    /// Complementary source/repair bias for this peer.
    pub symbol_bias: MultiSourceSymbolBias,
    /// Stable zero-based order after deterministic selection.
    pub selection_order: u32,
}

/// Stop command emitted for every selected source once the receiver decodes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiSourceStopCommand {
    /// Peer to stop.
    pub peer_id: String,
    /// Endpoint to send the stop/proof signal to.
    pub endpoint: String,
    /// Object the stop applies to.
    pub object_id: String,
    /// Stable reason identifier.
    pub reason: MultiSourceStopReason,
}

/// Why the receiver asks selected sources to stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum MultiSourceStopReason {
    /// Decode, SHA, and Merkle verification completed.
    DecodedAndVerified,
    /// Receiver cancelled the fetch before completion.
    Cancelled,
    /// Receiver failed closed.
    FailedClosed,
}

impl MultiSourceStopReason {
    /// Stable lower-case identifier for logs and plan artifacts.
    #[must_use]
    pub const fn reason_id(self) -> &'static str {
        match self {
            Self::DecodedAndVerified => "decoded_and_verified",
            Self::Cancelled => "cancelled",
            Self::FailedClosed => "failed_closed",
        }
    }
}

/// Complete receiver-side plan for fetching one object from several sources.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct MultiSourceFetchPlan {
    /// Object all selected sources must serve.
    pub object: MultiSourceObjectRef,
    /// Deterministically selected sources.
    pub selected_sources: Vec<MultiSourceSourcePlan>,
}

impl MultiSourceFetchPlan {
    /// Number of selected sources.
    #[must_use]
    pub fn source_count(&self) -> usize {
        self.selected_sources.len()
    }

    /// Build one stop command per selected source in selection order.
    #[must_use]
    pub fn stop_commands(&self, reason: MultiSourceStopReason) -> Vec<MultiSourceStopCommand> {
        self.selected_sources
            .iter()
            .map(|source| MultiSourceStopCommand {
                peer_id: source.peer.peer_id.clone(),
                endpoint: source.peer.endpoint.clone(),
                object_id: self.object.object_id.clone(),
                reason,
            })
            .collect()
    }
}

/// Errors from [`plan_multi_source_fetch`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MultiSourcePlanError {
    /// Object id is empty.
    #[error("multi-source object id must be non-empty")]
    EmptyObjectId,
    /// Merkle root is empty.
    #[error("multi-source merkle root must be non-empty")]
    EmptyMerkleRoot,
    /// Peer id is empty.
    #[error("multi-source peer id must be non-empty")]
    EmptyPeerId,
    /// Endpoint is empty.
    #[error("multi-source endpoint for peer {peer_id} must be non-empty")]
    EmptyEndpoint {
        /// Peer with the empty endpoint.
        peer_id: String,
    },
    /// Symbol-auth key id is empty.
    #[error("multi-source symbol-auth key id must be non-empty")]
    EmptyAuthKeyId,
    /// Duplicate peer id in the explicit source list.
    #[error("multi-source duplicate peer id: {peer_id}")]
    DuplicatePeerId {
        /// Duplicate peer id.
        peer_id: String,
    },
    /// Duplicate endpoint in the explicit source list.
    #[error("multi-source duplicate endpoint: {endpoint}")]
    DuplicateEndpoint {
        /// Duplicate endpoint.
        endpoint: String,
    },
    /// No selected source can be unauthenticated unless lab mode is explicit.
    #[error("multi-source peer {peer_id} is unauthenticated but lab mode is not allowed")]
    UnauthenticatedPeerRejected {
        /// Rejected peer id.
        peer_id: String,
    },
    /// Minimum source count must be positive.
    #[error("multi-source min_sources must be greater than zero")]
    ZeroMinSources,
    /// max_sources must be at least min_sources.
    #[error("multi-source max_sources {max_sources} is below min_sources {min_sources}")]
    MaxSourcesBelowMin {
        /// Required minimum.
        min_sources: usize,
        /// Configured maximum.
        max_sources: usize,
    },
    /// Not enough eligible sources after validation/auth checks.
    #[error("multi-source needs at least {required} eligible sources, got {available}")]
    NotEnoughEligibleSources {
        /// Required eligible source count.
        required: usize,
        /// Available eligible source count.
        available: usize,
    },
    /// More selected sources than can be represented in stable plan artifacts.
    #[error("multi-source selected source count exceeds u32::MAX")]
    TooManySelectedSources,
}

/// Plan an explicit multi-source fetch for one object.
///
/// Selection is deterministic: candidates are first validated and deduplicated,
/// then sorted by `(priority, peer_id, endpoint)`, capped by `max_sources`, and
/// assigned complementary symbol bias by selection order. This is intentionally
/// policy-only; transports map each selected peer into a connection and feed
/// authenticated symbols into the multipath aggregator.
pub fn plan_multi_source_fetch(
    object: MultiSourceObjectRef,
    peers: impl IntoIterator<Item = MultiSourcePeer>,
    config: MultiSourceSelectionConfig,
) -> Result<MultiSourceFetchPlan, MultiSourcePlanError> {
    object.validate()?;
    config.validate()?;

    let mut peer_ids = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut by_key = BTreeMap::new();

    for peer in peers {
        peer.validate()?;
        if !peer_ids.insert(peer.peer_id.clone()) {
            return Err(MultiSourcePlanError::DuplicatePeerId {
                peer_id: peer.peer_id,
            });
        }
        if !endpoints.insert(peer.endpoint.clone()) {
            return Err(MultiSourcePlanError::DuplicateEndpoint {
                endpoint: peer.endpoint,
            });
        }
        if !config.allow_unauthenticated_lab && !peer.auth.is_symbol_auth() {
            return Err(MultiSourcePlanError::UnauthenticatedPeerRejected {
                peer_id: peer.peer_id,
            });
        }
        by_key.insert(
            (peer.priority, peer.peer_id.clone(), peer.endpoint.clone()),
            peer,
        );
    }

    if by_key.len() < config.min_sources {
        return Err(MultiSourcePlanError::NotEnoughEligibleSources {
            required: config.min_sources,
            available: by_key.len(),
        });
    }

    let mut selected_sources = Vec::new();
    for (idx, peer) in by_key.into_values().take(config.max_sources).enumerate() {
        let selection_order =
            u32::try_from(idx).map_err(|_| MultiSourcePlanError::TooManySelectedSources)?;
        selected_sources.push(MultiSourceSourcePlan {
            peer,
            symbol_bias: symbol_bias_for_order(idx),
            selection_order,
        });
    }

    Ok(MultiSourceFetchPlan {
        object,
        selected_sources,
    })
}

fn symbol_bias_for_order(order: usize) -> MultiSourceSymbolBias {
    match order {
        0 => MultiSourceSymbolBias::SourceFirst,
        1 => MultiSourceSymbolBias::RepairFirst,
        _ => MultiSourceSymbolBias::Balanced,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_ref() -> MultiSourceObjectRef {
        MultiSourceObjectRef::new("object-01", "abc123")
    }

    fn auth(key_id: &str) -> MultiSourceAuth {
        MultiSourceAuth::SymbolAuth {
            key_id: key_id.to_string(),
        }
    }

    fn peer(id: &str, endpoint: &str, priority: u32) -> MultiSourcePeer {
        MultiSourcePeer::new(id, endpoint, priority, auth("key-a"))
    }

    #[test]
    fn production_default_requires_two_authenticated_sources() {
        assert_eq!(
            MultiSourceSelectionConfig::production_default(),
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 4,
                allow_unauthenticated_lab: false,
            }
        );
    }

    #[test]
    fn selection_is_priority_then_peer_then_endpoint_deterministic() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-c", "10.0.0.3:8472", 10),
                peer("peer-b", "10.0.0.2:8472", 5),
                peer("peer-a", "10.0.0.1:8472", 5),
            ],
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 2,
                allow_unauthenticated_lab: false,
            },
        )
        .unwrap();

        assert_eq!(plan.source_count(), 2);
        assert_eq!(plan.selected_sources[0].peer.peer_id, "peer-a");
        assert_eq!(plan.selected_sources[1].peer.peer_id, "peer-b");
        assert_eq!(
            plan.selected_sources
                .iter()
                .map(|source| source.selection_order)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn selected_sources_get_complementary_symbol_biases() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-a", "10.0.0.1:8472", 1),
                peer("peer-b", "10.0.0.2:8472", 2),
                peer("peer-c", "10.0.0.3:8472", 3),
            ],
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 3,
                allow_unauthenticated_lab: false,
            },
        )
        .unwrap();

        assert_eq!(
            plan.selected_sources
                .iter()
                .map(|source| source.symbol_bias)
                .collect::<Vec<_>>(),
            vec![
                MultiSourceSymbolBias::SourceFirst,
                MultiSourceSymbolBias::RepairFirst,
                MultiSourceSymbolBias::Balanced,
            ]
        );
        assert_eq!(
            plan.selected_sources[0].symbol_bias.bias_id(),
            "source_first"
        );
    }

    #[test]
    fn stop_commands_cover_every_selected_source_in_selection_order() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-b", "10.0.0.2:8472", 1),
                peer("peer-a", "10.0.0.1:8472", 0),
            ],
            MultiSourceSelectionConfig::production_default(),
        )
        .unwrap();

        let stops = plan.stop_commands(MultiSourceStopReason::DecodedAndVerified);
        assert_eq!(stops.len(), 2);
        assert_eq!(stops[0].peer_id, "peer-a");
        assert_eq!(stops[1].peer_id, "peer-b");
        assert!(stops.iter().all(|stop| {
            stop.object_id == "object-01" && stop.reason.reason_id() == "decoded_and_verified"
        }));
    }

    #[test]
    fn unauthenticated_sources_fail_closed_outside_lab_mode() {
        let err = plan_multi_source_fetch(
            object_ref(),
            [
                peer("peer-a", "10.0.0.1:8472", 0),
                MultiSourcePeer::new(
                    "peer-b",
                    "10.0.0.2:8472",
                    1,
                    MultiSourceAuth::UnauthenticatedLab,
                ),
            ],
            MultiSourceSelectionConfig::production_default(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            MultiSourcePlanError::UnauthenticatedPeerRejected { peer_id }
                if peer_id == "peer-b"
        ));
    }

    #[test]
    fn lab_mode_must_still_meet_minimum_source_count() {
        let plan = plan_multi_source_fetch(
            object_ref(),
            [
                MultiSourcePeer::new(
                    "peer-a",
                    "10.0.0.1:8472",
                    0,
                    MultiSourceAuth::UnauthenticatedLab,
                ),
                MultiSourcePeer::new(
                    "peer-b",
                    "10.0.0.2:8472",
                    1,
                    MultiSourceAuth::UnauthenticatedLab,
                ),
            ],
            MultiSourceSelectionConfig {
                min_sources: 2,
                max_sources: 2,
                allow_unauthenticated_lab: true,
            },
        )
        .unwrap();

        assert_eq!(plan.source_count(), 2);
        assert_eq!(
            plan.selected_sources[0].peer.auth.mode_id(),
            "unauthenticated_lab"
        );
    }

    #[test]
    fn duplicate_peer_ids_and_endpoints_fail_closed() {
        assert!(matches!(
            plan_multi_source_fetch(
                object_ref(),
                [
                    peer("peer-a", "10.0.0.1:8472", 0),
                    peer("peer-a", "10.0.0.2:8472", 1),
                ],
                MultiSourceSelectionConfig::production_default(),
            ),
            Err(MultiSourcePlanError::DuplicatePeerId { .. })
        ));

        assert!(matches!(
            plan_multi_source_fetch(
                object_ref(),
                [
                    peer("peer-a", "10.0.0.1:8472", 0),
                    peer("peer-b", "10.0.0.1:8472", 1),
                ],
                MultiSourceSelectionConfig::production_default(),
            ),
            Err(MultiSourcePlanError::DuplicateEndpoint { .. })
        ));
    }

    #[test]
    fn invalid_config_and_object_identity_fail_closed() {
        assert!(matches!(
            plan_multi_source_fetch(
                MultiSourceObjectRef::new("", "abc"),
                [peer("peer-a", "10.0.0.1:8472", 0)],
                MultiSourceSelectionConfig::production_default(),
            ),
            Err(MultiSourcePlanError::EmptyObjectId)
        ));
        assert!(matches!(
            plan_multi_source_fetch(
                object_ref(),
                [
                    peer("peer-a", "10.0.0.1:8472", 0),
                    peer("peer-b", "10.0.0.2:8472", 1),
                ],
                MultiSourceSelectionConfig {
                    min_sources: 3,
                    max_sources: 2,
                    allow_unauthenticated_lab: false,
                },
            ),
            Err(MultiSourcePlanError::MaxSourcesBelowMin { .. })
        ));
    }
}
