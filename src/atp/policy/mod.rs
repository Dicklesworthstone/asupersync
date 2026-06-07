//! ATP capability-based access control policies.
//!
//! This module implements the ATP capability model where all access to objects,
//! paths, and operations requires explicit grants. Capabilities are signed grants
//! that specify peer, resource scope, allowed actions, expiry, and constraints.

pub use crate::atp::object::ObjectId;
use crate::net::atp::protocol::PeerId;
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub mod enforcement;
pub mod scope;
pub mod verification;

pub use enforcement::{
    AccessRequest, AccessResource, EnforcementContext, PolicyDecision, PolicyEnforcer,
    RequestContext,
};
pub use scope::{AtpPath, ResourceScope, ScopeConstraints};

/// Actions that can be granted for ATP operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityAction {
    /// Read object data once
    ReadOnce,
    /// Read object data (reusable)
    Read,
    /// Write to a specific path/object
    Write,
    /// Write to inbox/mailbox
    WriteInbox,
    /// Share object with others
    Share,
    /// Forward/relay through this peer
    Relay,
    /// Seed data in cache
    Seed,
    /// Deliver to mailbox
    MailboxDelivery,
    /// Receive from others
    Receive,
}

impl CapabilityAction {
    /// Check if this action implies another (hierarchy).
    #[must_use]
    pub fn implies(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Write, Self::Read) => true,
            (Self::Share, Self::Read) => true,
            (Self::Seed, Self::Read) => true,
            _ => self == other,
        }
    }

    /// Get all actions implied by this one.
    #[must_use]
    pub fn implied_actions(&self) -> HashSet<Self> {
        let mut actions = HashSet::new();
        actions.insert(*self);
        match self {
            Self::Write => {
                actions.insert(Self::Read);
            }
            Self::Share => {
                actions.insert(Self::Read);
            }
            Self::Seed => {
                actions.insert(Self::Read);
            }
            _ => {}
        }
        actions
    }
}

/// Time-bounded capability scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TemporalScope {
    /// When the capability becomes valid (None = immediately)
    pub not_before: Option<SystemTime>,
    /// When the capability expires (None = never)
    pub not_after: Option<SystemTime>,
    /// Maximum usage count (None = unlimited)
    pub max_uses: Option<u64>,
}

impl TemporalScope {
    /// Create a capability that expires after a duration.
    #[must_use]
    pub fn expires_in(duration: Duration) -> Self {
        Self {
            not_before: None,
            not_after: Some(SystemTime::now() + duration),
            max_uses: None,
        }
    }

    /// Create a one-time capability.
    #[must_use]
    pub fn once() -> Self {
        Self {
            not_before: None,
            not_after: None,
            max_uses: Some(1),
        }
    }

    /// Create a capability valid for a specific time window.
    #[must_use]
    pub fn window(not_before: SystemTime, not_after: SystemTime) -> Self {
        Self {
            not_before: Some(not_before),
            not_after: Some(not_after),
            max_uses: None,
        }
    }

    /// Check if the capability is currently valid.
    #[must_use]
    pub fn is_valid_at(&self, now: SystemTime) -> bool {
        if let Some(not_before) = self.not_before {
            if now < not_before {
                return false;
            }
        }
        if let Some(not_after) = self.not_after {
            if now >= not_after {
                return false;
            }
        }
        true
    }

    /// Check if uses are exhausted.
    #[must_use]
    pub fn uses_exhausted(&self, current_uses: u64) -> bool {
        self.max_uses.is_some_and(|max| current_uses >= max)
    }
}

/// Capability grant binding a peer to resource access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capability {
    /// Grant identifier
    pub grant_id: String,
    /// Peer this grant was issued to
    pub subject: PeerId,
    /// Peer that issued this grant
    pub issuer: PeerId,
    /// Resource scope this grant covers
    pub scope: ResourceScope,
    /// Actions permitted
    pub actions: HashSet<CapabilityAction>,
    /// Time/usage constraints
    pub temporal: TemporalScope,
    /// Additional constraints
    pub constraints: ScopeConstraints,
    /// Grant signature (for verification)
    pub signature: Vec<u8>,
    /// When this grant was issued
    pub issued_at: SystemTime,
}

impl Capability {
    /// Create a new capability grant.
    #[must_use]
    pub fn new(
        grant_id: String,
        subject: PeerId,
        issuer: PeerId,
        scope: ResourceScope,
        actions: HashSet<CapabilityAction>,
        temporal: TemporalScope,
        constraints: ScopeConstraints,
    ) -> Self {
        Self {
            grant_id,
            subject,
            issuer,
            scope,
            actions,
            temporal,
            constraints,
            signature: Vec::new(),        // To be filled by grant signing
            issued_at: SystemTime::now(), // ubs:ignore - non-crypto timestamp
        }
    }

    /// Check if this capability grants a specific action.
    #[must_use]
    pub fn grants_action(&self, action: &CapabilityAction) -> bool {
        self.actions.contains(action) || self.actions.iter().any(|a| a.implies(action))
    }

    /// Get the policy digest for this capability.
    #[must_use]
    pub fn policy_digest(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        scope::update_digest_tag(&mut hasher, b"asupersync.atp.CapabilityPolicy.v2");
        scope::update_digest_bytes(&mut hasher, b"grant_id", self.grant_id.as_bytes());
        scope::update_digest_bytes(&mut hasher, b"subject", self.subject.as_bytes());
        scope::update_digest_bytes(&mut hasher, b"issuer", self.issuer.as_bytes());
        scope::update_digest_bytes(&mut hasher, b"scope_digest", &self.scope.digest());

        // Serialize actions in deterministic order
        let mut actions: Vec<_> = self.actions.iter().collect();
        actions.sort_by_key(|action| capability_action_digest_order(**action));
        scope::update_digest_len(&mut hasher, b"actions.len", actions.len());
        for action in actions {
            scope::update_digest_bytes(
                &mut hasher,
                b"action",
                capability_action_digest_label(*action),
            );
        }

        // Add temporal constraints
        scope::update_digest_option_u64(
            &mut hasher,
            b"not_before",
            self.temporal.not_before.map(system_time_digest_secs),
        );
        scope::update_digest_option_u64(
            &mut hasher,
            b"not_after",
            self.temporal.not_after.map(system_time_digest_secs),
        );
        scope::update_digest_option_u64(&mut hasher, b"max_uses", self.temporal.max_uses);

        scope::update_digest_bytes(
            &mut hasher,
            b"constraints_digest",
            &self.constraints.digest(),
        );
        hasher.finalize().into()
    }

    /// Check if this capability is currently valid.
    #[must_use]
    pub fn is_valid(&self, current_uses: u64) -> bool {
        let now = SystemTime::now();
        self.temporal.is_valid_at(now) && !self.temporal.uses_exhausted(current_uses)
    }
}

/// Policy decision outcome for capability checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityDecision {
    /// Access granted
    Granted {
        /// Capability that authorized the access
        capability: Capability,
        /// Remaining uses (if limited)
        remaining_uses: Option<u64>,
    },
    /// Access denied
    Denied {
        /// Reason for denial
        reason: DenialReason,
        /// Related capability (if any)
        capability: Option<Capability>,
    },
}

/// Reasons capability access can be denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialReason {
    /// No capability found for this peer/resource/action
    NoCapability,
    /// Capability expired
    Expired,
    /// Usage quota exhausted
    UsageExhausted,
    /// Capability not yet valid
    NotYetValid,
    /// Action not permitted by capability
    ActionNotPermitted,
    /// Resource not covered by capability scope
    ResourceNotCovered,
    /// Capability signature invalid
    InvalidSignature,
    /// Capability revoked
    Revoked,
    /// Path traversal attempt
    PathTraversal,
    /// Policy constraint violation
    ConstraintViolation(String),
}

impl std::fmt::Display for DenialReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCapability => write!(f, "no capability found"),
            Self::Expired => write!(f, "capability expired"),
            Self::UsageExhausted => write!(f, "usage quota exhausted"),
            Self::NotYetValid => write!(f, "capability not yet valid"),
            Self::ActionNotPermitted => write!(f, "action not permitted"),
            Self::ResourceNotCovered => write!(f, "resource not covered"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::Revoked => write!(f, "capability revoked"),
            Self::PathTraversal => write!(f, "path traversal attempt"),
            Self::ConstraintViolation(msg) => write!(f, "constraint violation: {msg}"),
        }
    }
}

/// Error types for capability operations.
#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    /// Invalid capability format
    #[error("invalid capability: {reason}")]
    InvalidCapability { reason: String },

    /// Signature verification failed
    #[error("signature verification failed")]
    SignatureVerification,

    /// Capability storage error
    #[error("storage error: {0}")]
    Storage(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Result type for capability operations.
pub type CapabilityResult<T> = Outcome<T, CapabilityError>;

fn capability_action_digest_order(action: CapabilityAction) -> u8 {
    match action {
        CapabilityAction::ReadOnce => 0,
        CapabilityAction::Read => 1,
        CapabilityAction::Write => 2,
        CapabilityAction::WriteInbox => 3,
        CapabilityAction::Share => 4,
        CapabilityAction::Relay => 5,
        CapabilityAction::Seed => 6,
        CapabilityAction::MailboxDelivery => 7,
        CapabilityAction::Receive => 8,
    }
}

fn capability_action_digest_label(action: CapabilityAction) -> &'static [u8] {
    match action {
        CapabilityAction::ReadOnce => b"ReadOnce",
        CapabilityAction::Read => b"Read",
        CapabilityAction::Write => b"Write",
        CapabilityAction::WriteInbox => b"WriteInbox",
        CapabilityAction::Share => b"Share",
        CapabilityAction::Relay => b"Relay",
        CapabilityAction::Seed => b"Seed",
        CapabilityAction::MailboxDelivery => b"MailboxDelivery",
        CapabilityAction::Receive => b"Receive",
    }
}

fn system_time_digest_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::protocol::PeerId;

    #[test]
    fn capability_action_hierarchy() {
        assert!(CapabilityAction::Write.implies(&CapabilityAction::Read));
        assert!(CapabilityAction::Share.implies(&CapabilityAction::Read));
        assert!(CapabilityAction::Seed.implies(&CapabilityAction::Read));
        assert!(!CapabilityAction::Read.implies(&CapabilityAction::Write));
    }

    #[test]
    fn temporal_scope_validation() {
        let now = SystemTime::now();
        let past = now - Duration::from_secs(100);
        let future = now + Duration::from_secs(100);

        let current = TemporalScope::window(past, future);
        assert!(current.is_valid_at(now));

        let expired = TemporalScope::window(past, past + Duration::from_secs(50));
        assert!(!expired.is_valid_at(now));

        let not_yet = TemporalScope::window(future, future + Duration::from_secs(100));
        assert!(!not_yet.is_valid_at(now));

        let once = TemporalScope::once();
        assert!(!once.uses_exhausted(0));
        assert!(once.uses_exhausted(1));
    }

    #[test]
    fn capability_grants_action() {
        let peer_id = PeerId::test(1);
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Write);

        let capability = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        assert!(capability.grants_action(&CapabilityAction::Write));
        assert!(capability.grants_action(&CapabilityAction::Read)); // Implied
        assert!(!capability.grants_action(&CapabilityAction::Share));
    }

    #[test]
    fn capability_policy_digest_stability() {
        let peer_id = PeerId::test(1);
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let cap1 = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions.clone(),
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        let cap2 = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        );

        assert_eq!(cap1.policy_digest(), cap2.policy_digest());
    }

    #[test]
    fn capability_policy_digest_frames_temporal_fields() {
        let peer_id = PeerId::test(1);
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let expires_at_one = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions.clone(),
            TemporalScope {
                not_before: None,
                not_after: Some(UNIX_EPOCH + Duration::from_secs(1)),
                max_uses: None,
            },
            ScopeConstraints::default(),
        );

        let one_use = Capability::new(
            "test-grant".to_string(),
            peer_id,
            peer_id,
            ResourceScope::Any,
            actions,
            TemporalScope {
                not_before: None,
                not_after: None,
                max_uses: Some(1),
            },
            ScopeConstraints::default(),
        );

        assert_ne!(expires_at_one.policy_digest(), one_use.policy_digest());
    }
}
