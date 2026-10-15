//! ATP capability grant management.
//!
//! This module provides comprehensive grant lifecycle management: issue, store,
//! list, revoke, rotate, and enforce grants for ATP's capability-based access
//! control system.

use crate::atp::policy::{Capability, CapabilityError};
use crate::net::atp::protocol::PeerId;
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

pub mod manager;
pub mod pairing;
pub mod storage;

pub use manager::GrantManager;
pub use pairing::{PairingCode, PairingFlow, PairingManager};
pub use storage::{GrantRecord, GrantStorage};

/// Grant operation types for audit logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantOperation {
    /// Grant was issued
    Issued,
    /// Grant was received from another peer
    Received,
    /// Grant was revoked by issuer
    Revoked,
    /// Grant was rotated (new version)
    Rotated,
    /// Grant was used for access
    Used,
    /// Grant was delegated to another peer
    Delegated,
}

impl std::fmt::Display for GrantOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Issued => write!(f, "issued"),
            Self::Received => write!(f, "received"),
            Self::Revoked => write!(f, "revoked"),
            Self::Rotated => write!(f, "rotated"),
            Self::Used => write!(f, "used"),
            Self::Delegated => write!(f, "delegated"),
        }
    }
}

/// Audit record for grant operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantAuditRecord {
    /// Grant ID this record relates to
    pub grant_id: String,
    /// Operation performed
    pub operation: GrantOperation,
    /// Peer who performed the operation
    pub actor: PeerId,
    /// Target peer (for delegation/receipt)
    pub target: Option<PeerId>,
    /// When the operation occurred
    pub timestamp: SystemTime,
    /// Additional context
    pub context: HashMap<String, String>,
    /// Redacted capability summary
    pub capability_summary: String,
}

/// Grant lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GrantState {
    /// Grant is pending acceptance
    Pending,
    /// Grant is active and can be used
    Active,
    /// Grant has been revoked
    Revoked,
    /// Grant has expired
    Expired,
    /// Grant has been rotated to new version
    Rotated,
}

/// Extended grant information with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantInfo {
    /// The capability grant
    pub capability: Capability,
    /// Current state
    pub state: GrantState,
    /// Creation timestamp
    pub created_at: SystemTime,
    /// Last used timestamp
    pub last_used: Option<SystemTime>,
    /// Usage count
    pub usage_count: u64,
    /// Parent grant (if this was delegated)
    pub parent_grant_id: Option<String>,
    /// Child grants (delegated from this one)
    pub child_grant_ids: HashSet<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl GrantInfo {
    /// Create new grant info from a capability.
    #[must_use]
    pub fn new(capability: Capability) -> Self {
        Self {
            capability,
            state: GrantState::Active,
            created_at: SystemTime::now(),
            last_used: None,
            usage_count: 0,
            parent_grant_id: None,
            child_grant_ids: HashSet::new(),
            metadata: HashMap::new(),
        }
    }

    /// Check if this grant is currently usable.
    #[must_use]
    pub fn is_usable(&self) -> bool {
        match self.state {
            GrantState::Active => self.capability.is_valid(self.usage_count),
            _ => false,
        }
    }

    /// Record usage of this grant.
    pub fn record_usage(&mut self) {
        self.usage_count = self.usage_count.saturating_add(1);
        self.last_used = Some(SystemTime::now());

        // Check if usage is exhausted
        if let Some(max_uses) = self.capability.temporal.max_uses {
            if self.usage_count >= max_uses {
                self.state = GrantState::Expired;
            }
        }
    }

    /// Mark this grant as revoked.
    pub fn revoke(&mut self) {
        self.state = GrantState::Revoked;
    }

    /// Mark this grant as rotated.
    pub fn rotate(&mut self, new_grant_id: String) {
        self.state = GrantState::Rotated;
        self.metadata.insert("rotated_to".to_string(), new_grant_id);
    }

    /// Create a redacted summary for audit logs.
    #[must_use]
    pub fn redacted_summary(&self) -> String {
        let actions: Vec<String> = self
            .capability
            .actions
            .iter()
            .map(|a| format!("{a:?}"))
            .collect();

        let scope_type = match &self.capability.scope {
            crate::atp::policy::ResourceScope::Any => "any",
            crate::atp::policy::ResourceScope::Object(_) => "object",
            crate::atp::policy::ResourceScope::Path(_) => "path",
            crate::atp::policy::ResourceScope::Inbox => "inbox",
            crate::atp::policy::ResourceScope::Team(_) => "team",
            crate::atp::policy::ResourceScope::Relay { .. } => "relay",
            crate::atp::policy::ResourceScope::Cache { .. } => "cache",
        };

        format!(
            "grant={} scope={} actions=[{}] state={:?} uses={}/{}",
            &self.capability.grant_id[..8.min(self.capability.grant_id.len())],
            scope_type,
            actions.join(","),
            self.state,
            self.usage_count,
            self.capability
                .temporal
                .max_uses
                .map_or("∞".to_string(), |u| u.to_string())
        )
    }
}

/// Result type for grant operations.
pub type GrantResult<T> = Outcome<T, GrantError>;

/// Errors that can occur in grant operations.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// Grant not found
    #[error("grant not found: {grant_id}")]
    NotFound { grant_id: String },

    /// Grant already exists
    #[error("grant already exists: {grant_id}")]
    AlreadyExists { grant_id: String },

    /// Grant is not in a valid state for operation
    #[error("invalid grant state {state:?} for operation")]
    InvalidState { state: GrantState },

    /// Permission denied for operation
    #[error("permission denied: {reason}")]
    PermissionDenied { reason: String },

    /// Capability error
    #[error("capability error: {0}")]
    Capability(#[from] CapabilityError),

    /// Storage error
    #[error("storage error: {0}")]
    Storage(String),

    /// Validation failed
    #[error("validation failed: {issues:?}")]
    ValidationFailed { issues: Vec<String> },

    /// Pairing error
    #[error("pairing error: {reason}")]
    PairingError { reason: String },
}

/// Grant creation request.
#[derive(Debug, Clone)]
pub struct CreateGrantRequest {
    /// Subject peer this grant is for
    pub subject: PeerId,
    /// Resource scope
    pub scope: crate::atp::policy::ResourceScope,
    /// Actions to grant
    pub actions: HashSet<crate::atp::policy::CapabilityAction>,
    /// Time constraints
    pub temporal: crate::atp::policy::TemporalScope,
    /// Additional constraints
    pub constraints: crate::atp::policy::ScopeConstraints,
    /// Optional grant description
    pub description: Option<String>,
    /// Parent grant (for delegation)
    pub parent_grant_id: Option<String>,
}

/// Grant query filters.
#[derive(Debug, Clone, Default)]
pub struct GrantQuery {
    /// Filter by subject peer
    pub subject: Option<PeerId>,
    /// Filter by issuer peer
    pub issuer: Option<PeerId>,
    /// Filter by grant state
    pub state: Option<GrantState>,
    /// Filter by action
    pub action: Option<crate::atp::policy::CapabilityAction>,
    /// Only return usable grants
    pub usable_only: bool,
    /// Limit number of results
    pub limit: Option<usize>,
}

/// Summary statistics for grant management.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantStats {
    /// Total number of grants
    pub total_grants: u64,
    /// Grants by state
    pub grants_by_state: HashMap<GrantState, u64>,
    /// Total usage count across all grants
    pub total_usage: u64,
    /// Number of unique subjects
    pub unique_subjects: u64,
    /// Number of unique issuers
    pub unique_issuers: u64,
}

/// Grant template for common grant patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantTemplate {
    /// Template name
    pub name: String,
    /// Template description
    pub description: String,
    /// Default scope
    pub scope: crate::atp::policy::ResourceScope,
    /// Default actions
    pub actions: HashSet<crate::atp::policy::CapabilityAction>,
    /// Default temporal scope
    pub temporal: crate::atp::policy::TemporalScope,
    /// Default constraints
    pub constraints: crate::atp::policy::ScopeConstraints,
}

impl GrantTemplate {
    /// Create a read-once template.
    #[must_use]
    pub fn read_once() -> Self {
        use crate::atp::policy::{
            CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope,
        };
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::ReadOnce);

        Self {
            name: "read-once".to_string(),
            description: "Single-use read access".to_string(),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::once(),
            constraints: ScopeConstraints::default(),
        }
    }

    /// Create a 24-hour share template.
    #[must_use]
    pub fn share_24h() -> Self {
        use crate::atp::policy::{
            CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope,
        };
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Share);

        Self {
            name: "share-24h".to_string(),
            description: "24-hour sharing capability".to_string(),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(std::time::Duration::from_secs(24 * 3600)),
            constraints: ScopeConstraints::default(),
        }
    }

    /// Create an inbox write template.
    #[must_use]
    pub fn inbox_write() -> Self {
        use crate::atp::policy::{
            CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope,
        };
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::WriteInbox);

        Self {
            name: "inbox-write".to_string(),
            description: "Write access to inbox".to_string(),
            scope: ResourceScope::Inbox,
            actions,
            temporal: TemporalScope::expires_in(std::time::Duration::from_secs(7 * 24 * 3600)), // 7 days
            constraints: ScopeConstraints::default(),
        }
    }

    /// Create a team read template.
    #[must_use]
    pub fn team_read(team: String) -> Self {
        use crate::atp::policy::{
            CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope,
        };
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        Self {
            name: format!("team-{}-read", team),
            description: format!("Read access to team {} resources", team),
            scope: ResourceScope::Team(team),
            actions,
            temporal: TemporalScope::expires_in(std::time::Duration::from_secs(30 * 24 * 3600)), // 30 days
            constraints: ScopeConstraints::default(),
        }
    }

    /// Apply this template to a create request.
    pub fn apply_to_request(&self, request: &mut CreateGrantRequest) {
        request.scope = self.scope.clone();
        request.actions.clone_from(&self.actions);
        request.temporal = self.temporal.clone();
        request.constraints = self.constraints.clone();
        if request.description.is_none() {
            request.description = Some(self.description.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::policy::{CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope};
    use crate::net::atp::protocol::PeerId;
    use std::collections::HashSet;
    use std::time::Duration;

    #[test]
    fn grant_info_tracks_usage() {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let capability = crate::atp::policy::Capability::new(
            "test-grant".to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Any,
            actions,
            TemporalScope::once(),
            ScopeConstraints::default(),
        );

        let mut grant_info = GrantInfo::new(capability);

        assert!(grant_info.is_usable());
        assert_eq!(grant_info.usage_count, 0);

        grant_info.record_usage();
        assert_eq!(grant_info.usage_count, 1);
        assert_eq!(grant_info.state, GrantState::Expired); // Max uses was 1
        assert!(!grant_info.is_usable());
    }

    #[test]
    fn grant_info_usage_count_saturates_at_u64_max() {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let capability = crate::atp::policy::Capability::new(
            "saturating-grant".to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        let mut grant_info = GrantInfo::new(capability);
        grant_info.usage_count = u64::MAX;

        grant_info.record_usage();

        assert_eq!(grant_info.usage_count, u64::MAX);
        assert_eq!(grant_info.state, GrantState::Active);
    }

    #[test]
    fn grant_templates_create_common_patterns() {
        let read_once = GrantTemplate::read_once();
        assert_eq!(read_once.name, "read-once");
        assert!(read_once.actions.contains(&CapabilityAction::ReadOnce));
        assert_eq!(read_once.temporal.max_uses, Some(1));

        let share_24h = GrantTemplate::share_24h();
        assert_eq!(share_24h.name, "share-24h");
        assert!(share_24h.actions.contains(&CapabilityAction::Share));

        let inbox = GrantTemplate::inbox_write();
        assert_eq!(inbox.name, "inbox-write");
        assert!(inbox.actions.contains(&CapabilityAction::WriteInbox));
        assert!(matches!(inbox.scope, ResourceScope::Inbox));

        let team = GrantTemplate::team_read("engineering".to_string());
        assert_eq!(team.name, "team-engineering-read");
        assert!(team.actions.contains(&CapabilityAction::Read));
        assert!(matches!(team.scope, ResourceScope::Team(ref t) if t == "engineering"));
    }

    #[test]
    fn grant_redacted_summary_includes_key_info() {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        actions.insert(CapabilityAction::Share);

        let capability = crate::atp::policy::Capability::new(
            "test-grant-12345".to_string(),
            PeerId::test(1),
            PeerId::test(2),
            ResourceScope::Inbox,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        let grant_info = GrantInfo::new(capability);
        let summary = grant_info.redacted_summary();

        assert!(summary.contains("grant=test-gra"));
        assert!(summary.contains("scope=inbox"));
        assert!(summary.contains("Read"));
        assert!(summary.contains("Share"));
        assert!(summary.contains("state=Active"));
    }

    #[test]
    fn grant_query_provides_filtering() {
        let query = GrantQuery {
            subject: Some(PeerId::test(1)),
            state: Some(GrantState::Active),
            usable_only: true,
            limit: Some(10),
            ..Default::default()
        };

        assert_eq!(query.subject, Some(PeerId::test(1)));
        assert_eq!(query.state, Some(GrantState::Active));
        assert!(query.usable_only);
        assert_eq!(query.limit, Some(10));
    }
}
