//! Policy enforcement for ATP capability-based access control.

use super::scope::AtpPath;
use super::{Capability, CapabilityAction, CapabilityDecision, DenialReason, ResourceScope};
use crate::atp::object::ObjectId;
use crate::net::atp::protocol::PeerId;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::SystemTime;

/// Policy decision with enforcement context.
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// The decision outcome
    pub decision: CapabilityDecision,
    /// Request that was evaluated
    pub request: AccessRequest,
    /// Timestamp when decision was made
    pub decided_at: SystemTime,
    /// Enforcement context
    pub context: EnforcementContext,
}

/// Access request to be evaluated against capabilities.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    /// Peer making the request
    pub peer: PeerId,
    /// Resource being accessed
    pub resource: AccessResource,
    /// Action being performed
    pub action: CapabilityAction,
    /// Transfer size (if applicable)
    pub transfer_size: Option<u64>,
    /// Client IP address
    pub client_ip: Option<IpAddr>,
    /// Additional context
    pub context: RequestContext,
}

/// Resource being accessed in a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessResource {
    /// Specific object
    Object(ObjectId),
    /// Path-based resource
    Path(AtpPath),
    /// Inbox access
    Inbox,
    /// Team resource
    Team(String),
    /// Relay destination
    Relay(String),
    /// Cache operation
    Cache {
        /// Object type
        object_type: String,
        /// Size in bytes
        size_bytes: u64,
    },
}

/// Additional context for access requests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestContext {
    /// Session ID
    pub session_id: Option<String>,
    /// Transfer ID
    pub transfer_id: Option<String>,
    /// Source of the request
    pub source: Option<String>,
}

/// Enforcement context for policy decisions.
#[derive(Debug, Clone)]
pub struct EnforcementContext {
    /// Policy version used
    pub policy_version: u32,
    /// Enforcement mode
    pub mode: EnforcementMode,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Policy enforcement modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Enforce policies (default)
    Enforce,
    /// Log violations but allow access
    LogOnly,
    /// Disabled enforcement
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CapabilityPreferenceKey {
    scope_breadth: u32,
    action_breadth: u32,
    constraint_breadth: u64,
    temporal_breadth: u64,
}

impl Default for EnforcementContext {
    fn default() -> Self {
        Self {
            policy_version: 1,
            mode: EnforcementMode::Enforce,
            metadata: HashMap::new(),
        }
    }
}

/// Policy enforcer that evaluates access requests against capabilities.
pub struct PolicyEnforcer {
    /// Current capabilities by peer
    capabilities: HashMap<PeerId, Vec<Capability>>,
    /// Revoked grant IDs
    revoked_grants: HashMap<String, SystemTime>,
    /// Usage tracking by grant ID
    usage_counts: HashMap<String, u64>,
    /// Enforcement context
    context: EnforcementContext,
}

impl PolicyEnforcer {
    /// Create a new policy enforcer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            capabilities: HashMap::new(),
            revoked_grants: HashMap::new(),
            usage_counts: HashMap::new(),
            context: EnforcementContext::default(),
        }
    }

    /// Set enforcement mode.
    pub fn set_enforcement_mode(&mut self, mode: EnforcementMode) {
        self.context.mode = mode;
    }

    /// Add a capability for a peer.
    pub fn add_capability(&mut self, capability: Capability) {
        let peer = capability.subject;
        self.capabilities.entry(peer).or_default().push(capability);
    }

    /// Remove a capability by grant ID.
    pub fn remove_capability(&mut self, grant_id: &str) -> bool {
        for capabilities in self.capabilities.values_mut() {
            if let Some(pos) = capabilities.iter().position(|c| c.grant_id == grant_id) {
                capabilities.remove(pos);
                return true;
            }
        }
        false
    }

    /// Revoke a capability by grant ID.
    pub fn revoke_capability(&mut self, grant_id: &str) {
        self.revoked_grants
            .insert(grant_id.to_string(), SystemTime::now());
        self.remove_capability(grant_id);
    }

    /// Check if a grant is revoked.
    #[must_use]
    pub fn is_revoked(&self, grant_id: &str) -> bool {
        self.revoked_grants.contains_key(grant_id)
    }

    /// Get usage count for a grant.
    #[must_use]
    pub fn get_usage_count(&self, grant_id: &str) -> u64 {
        self.usage_counts.get(grant_id).copied().unwrap_or(0)
    }

    /// Increment usage count for a grant.
    pub fn increment_usage(&mut self, grant_id: &str) {
        let usage_count = self.usage_counts.entry(grant_id.to_string()).or_insert(0);
        *usage_count = usage_count.saturating_add(1);
    }

    /// Evaluate an access request against current capabilities.
    pub fn evaluate_access(&mut self, request: &AccessRequest) -> PolicyDecision {
        let decision = match self.context.mode {
            EnforcementMode::Disabled => CapabilityDecision::Granted {
                capability: self.create_admin_capability(&request.peer),
                remaining_uses: None,
            },
            EnforcementMode::Enforce | EnforcementMode::LogOnly => self.check_capabilities(request),
        };

        // In log-only mode, convert denials to grants but log them
        let final_decision = match (self.context.mode, &decision) {
            (EnforcementMode::LogOnly, CapabilityDecision::Denied { .. }) => {
                // Log the violation but allow access
                CapabilityDecision::Granted {
                    capability: self.create_admin_capability(&request.peer),
                    remaining_uses: None,
                }
            }
            _ => decision,
        };

        PolicyDecision {
            decision: final_decision,
            request: request.clone(),
            decided_at: SystemTime::now(),
            context: self.context.clone(),
        }
    }

    /// Check capabilities for an access request.
    fn check_capabilities(&mut self, request: &AccessRequest) -> CapabilityDecision {
        let peer_capabilities = match self.capabilities.get(&request.peer) {
            Some(caps) => caps,
            None => {
                return CapabilityDecision::Denied {
                    reason: DenialReason::NoCapability,
                    capability: None,
                };
            }
        };

        // Find matching capabilities
        let mut matching_caps = Vec::new();
        for capability in peer_capabilities {
            if self.capability_matches(capability, request) {
                matching_caps.push(capability);
            }
        }

        if matching_caps.is_empty() {
            return CapabilityDecision::Denied {
                reason: DenialReason::NoCapability,
                capability: None,
            };
        }

        // Find the best matching capability
        let best_capability = self.select_best_capability(&matching_caps);
        let usage_count = self.get_usage_count(&best_capability.grant_id);

        // Check if capability is currently valid
        if let Some(denial_reason) =
            self.check_capability_validity(best_capability, request, usage_count)
        {
            return CapabilityDecision::Denied {
                reason: denial_reason,
                capability: Some(best_capability.clone()),
            };
        }

        // Extract needed data before mutating self to avoid borrow conflicts
        let grant_id = best_capability.grant_id.clone();
        let max_uses = best_capability.temporal.max_uses;
        let capability_clone = best_capability.clone();

        // Increment usage count
        self.increment_usage(&grant_id);

        // Calculate remaining uses
        let remaining_uses = max_uses.map(|max| max.saturating_sub(usage_count + 1));

        CapabilityDecision::Granted {
            capability: capability_clone,
            remaining_uses,
        }
    }

    /// Check if a capability matches an access request.
    fn capability_matches(&self, capability: &Capability, request: &AccessRequest) -> bool {
        // Check if capability covers the action
        if !capability.grants_action(&request.action) {
            return false;
        }

        // Check if capability covers the resource
        match &request.resource {
            AccessResource::Object(object_id) => capability.scope.covers_object(object_id),
            AccessResource::Path(path) => capability.scope.covers_path(path),
            AccessResource::Inbox => {
                matches!(capability.scope, ResourceScope::Any | ResourceScope::Inbox)
            }
            AccessResource::Team(team) => {
                capability.scope == ResourceScope::Team(team.clone())
                    || capability.scope == ResourceScope::Any
            }
            AccessResource::Relay(destination) => capability.scope.covers_relay(destination),
            AccessResource::Cache {
                object_type,
                size_bytes,
            } => capability.scope.covers_cache(object_type, *size_bytes),
        }
    }

    /// Check if a capability is currently valid for a request.
    fn check_capability_validity(
        &self,
        capability: &Capability,
        request: &AccessRequest,
        usage_count: u64,
    ) -> Option<DenialReason> {
        // Check if revoked
        if self.is_revoked(&capability.grant_id) {
            return Some(DenialReason::Revoked);
        }

        // Check temporal validity
        if !capability.is_valid(usage_count) {
            let now = SystemTime::now();
            if !capability.temporal.is_valid_at(now) {
                if capability.temporal.not_before.is_some_and(|nb| now < nb) {
                    return Some(DenialReason::NotYetValid);
                }
                return Some(DenialReason::Expired);
            }
            if capability.temporal.uses_exhausted(usage_count) {
                return Some(DenialReason::UsageExhausted);
            }
        }

        // Check constraints
        if let Some(transfer_size) = request.transfer_size {
            if !capability.constraints.check_transfer_size(transfer_size) {
                return Some(DenialReason::ConstraintViolation(
                    "transfer size exceeded".to_string(),
                ));
            }
        }

        if let Some(client_ip) = request.client_ip {
            if !capability
                .constraints
                .check_ip_allowed(&client_ip.to_string())
            {
                return Some(DenialReason::ConstraintViolation(
                    "IP not allowed".to_string(),
                ));
            }
        }

        if !capability.constraints.check_time_allowed() {
            return Some(DenialReason::ConstraintViolation(
                "time restriction".to_string(),
            ));
        }

        // Check for path traversal attempts
        if let AccessResource::Path(path) = &request.resource {
            if self.is_path_traversal_attempt(path) {
                return Some(DenialReason::PathTraversal);
            }
        }

        None
    }

    /// Check if a path contains traversal attempts.
    fn is_path_traversal_attempt(&self, path: &AtpPath) -> bool {
        let path_str = path.as_str();
        path_str.contains("..") || path_str.contains("//") || path_str.starts_with('/')
    }

    /// Select the best capability from matching ones (most restrictive).
    fn select_best_capability<'a>(&self, capabilities: &[&'a Capability]) -> &'a Capability {
        capabilities
            .iter()
            .min_by(|left, right| {
                self.capability_preference_key(left)
                    .cmp(&self.capability_preference_key(right))
                    .then_with(|| left.grant_id.cmp(&right.grant_id))
            })
            .unwrap() // ubs:ignore - capabilities slice is guaranteed non-empty by caller
    }

    fn capability_preference_key(&self, capability: &Capability) -> CapabilityPreferenceKey {
        CapabilityPreferenceKey {
            scope_breadth: self.capability_scope_breadth(&capability.scope),
            action_breadth: capability.actions.len() as u32,
            constraint_breadth: self.capability_constraint_breadth(capability),
            temporal_breadth: self.capability_temporal_breadth(capability),
        }
    }

    /// Get a rough measure of capability scope breadth (lower = more restrictive).
    fn capability_scope_breadth(&self, scope: &ResourceScope) -> u32 {
        match scope {
            ResourceScope::Any => 1000,
            ResourceScope::Team(_) => 500,
            ResourceScope::Cache { .. } | ResourceScope::Relay { .. } => 300,
            ResourceScope::Inbox => 200,
            ResourceScope::Path(_) => 100,
            ResourceScope::Object(_) => 50,
        }
    }

    fn capability_constraint_breadth(&self, capability: &Capability) -> u64 {
        let constraints = &capability.constraints;
        let transfer_size = constraints
            .max_transfer_size
            .map_or(1_000_000_000_000, |max| max.min(1_000_000_000_000));
        let bandwidth = constraints
            .max_bandwidth
            .map_or(1_000_000_000_000, |max| max.min(1_000_000_000_000));
        let ip_breadth = constraints
            .allowed_ips
            .as_ref()
            .map_or(1_000_000, |ips| ips.len() as u64);
        let hour_breadth =
            constraints
                .allowed_hours
                .map_or(24, |(start, end)| match start.cmp(&end) {
                    std::cmp::Ordering::Equal => 24,
                    std::cmp::Ordering::Less => u64::from(end - start),
                    std::cmp::Ordering::Greater => u64::from(24 - start + end),
                });
        let security_breadth = if constraints.min_security_level.is_some() {
            1
        } else {
            1_000
        };

        transfer_size
            .saturating_add(bandwidth)
            .saturating_add(ip_breadth.saturating_mul(1_000))
            .saturating_add(hour_breadth.saturating_mul(10_000))
            .saturating_add(security_breadth)
    }

    fn capability_temporal_breadth(&self, capability: &Capability) -> u64 {
        let now = SystemTime::now();
        let validity_window = capability
            .temporal
            .not_after
            .map_or(1_000_000_000, |not_after| {
                not_after
                    .duration_since(now)
                    .unwrap_or_default()
                    .as_secs()
                    .min(1_000_000_000)
            });
        let use_window = capability.temporal.max_uses.unwrap_or(1_000_000_000);
        validity_window.saturating_add(use_window)
    }

    /// Create an administrative capability for disabled enforcement.
    fn create_admin_capability(&self, peer: &PeerId) -> Capability {
        use super::{CapabilityAction, ScopeConstraints, TemporalScope};
        use std::collections::HashSet;

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        actions.insert(CapabilityAction::Write);

        Capability::new(
            "admin-override".to_string(),
            *peer,
            *peer,
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(std::time::Duration::from_secs(3600)),
            ScopeConstraints::default(),
        )
    }

    /// Get all capabilities for a peer.
    #[must_use]
    pub fn get_peer_capabilities(&self, peer: &PeerId) -> Vec<Capability> {
        self.capabilities.get(peer).cloned().unwrap_or_default()
    }

    /// List all revoked grant IDs.
    #[must_use]
    pub fn list_revoked_grants(&self) -> Vec<String> {
        self.revoked_grants.keys().cloned().collect()
    }
}

impl Default for PolicyEnforcer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::policy::{CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope};
    use std::collections::HashSet;
    use std::time::Duration;

    fn create_test_capability(peer: PeerId, action: CapabilityAction) -> Capability {
        let mut actions = HashSet::new();
        actions.insert(action);

        Capability::new(
            "test-grant".to_string(),
            peer,
            peer,
            ResourceScope::Any,
            actions,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
        )
    }

    #[test]
    fn policy_enforcer_grants_valid_access() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);
        let capability = create_test_capability(peer, CapabilityAction::Read);

        enforcer.add_capability(capability.clone());

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        match decision.decision {
            CapabilityDecision::Granted { .. } => {}
            CapabilityDecision::Denied { reason, .. } => {
                panic!("Expected granted, got denied: {reason}")
            }
        }
    }

    #[test]
    fn policy_enforcer_denies_missing_capability() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        match decision.decision {
            CapabilityDecision::Denied {
                reason: DenialReason::NoCapability,
                ..
            } => {}
            other => panic!("Expected NoCapability denial, got {other:?}"),
        }
    }

    #[test]
    fn policy_enforcer_denies_revoked_capability() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);
        let capability = create_test_capability(peer, CapabilityAction::Read);

        enforcer.add_capability(capability.clone());
        enforcer.revoke_capability(&capability.grant_id);

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        match decision.decision {
            CapabilityDecision::Denied {
                reason: DenialReason::NoCapability,
                ..
            } => {}
            other => panic!("Expected NoCapability denial after revocation, got {other:?}"), // ubs:ignore - test oracle
        }
    }

    #[test]
    fn policy_enforcer_tracks_usage() {
        let mut enforcer = PolicyEnforcer::new();
        let peer = PeerId::test(1);
        let mut capability = create_test_capability(peer, CapabilityAction::Read);
        capability.temporal.max_uses = Some(2);

        enforcer.add_capability(capability.clone());

        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        // First use
        let decision1 = enforcer.evaluate_access(&request);
        assert!(matches!(
            decision1.decision,
            CapabilityDecision::Granted { .. }
        ));

        // Second use
        let decision2 = enforcer.evaluate_access(&request);
        assert!(matches!(
            decision2.decision,
            CapabilityDecision::Granted { .. }
        ));

        // Third use should be denied
        let decision3 = enforcer.evaluate_access(&request);
        assert!(matches!(
            decision3.decision,
            CapabilityDecision::Denied {
                reason: DenialReason::UsageExhausted,
                ..
            }
        ));
    }

    #[test]
    fn policy_enforcer_usage_count_saturates_at_u64_max() {
        let mut enforcer = PolicyEnforcer::new();
        let grant_id = "saturating-grant";

        enforcer.usage_counts.insert(grant_id.to_string(), u64::MAX);
        enforcer.increment_usage(grant_id);

        assert_eq!(enforcer.get_usage_count(grant_id), u64::MAX);
    }

    #[test]
    fn log_only_mode_allows_denied_requests() {
        let mut enforcer = PolicyEnforcer::new();
        enforcer.set_enforcement_mode(EnforcementMode::LogOnly);

        let peer = PeerId::test(1);
        let request = AccessRequest {
            peer,
            resource: AccessResource::Inbox,
            action: CapabilityAction::Read,
            transfer_size: None,
            client_ip: None,
            context: RequestContext::default(),
        };

        let decision = enforcer.evaluate_access(&request);
        // Should be granted even without capabilities in log-only mode
        assert!(matches!(
            decision.decision,
            CapabilityDecision::Granted { .. }
        ));
    }
}
