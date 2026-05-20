//! Comprehensive grant management for ATP capabilities.

use super::storage::{GrantRecord, GrantStorage};
use super::{
    CreateGrantRequest, GrantAuditRecord, GrantError, GrantInfo, GrantOperation, GrantQuery,
    GrantResult, GrantState, GrantStats, GrantTemplate,
};
use crate::atp::identity::DurablePeerIdentity;
use crate::atp::policy::verification::{CapabilitySigner, CapabilityVerifier, ValidationResult};
use crate::atp::policy::{
    AccessRequest, Capability, CapabilityAction, PolicyDecision, PolicyEnforcer,
};
use crate::net::atp::protocol::PeerId;
use crate::security::keys::IdentityKeyStore;
use crate::types::outcome::Outcome;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

/// Comprehensive grant manager for ATP capability system.
pub struct GrantManager {
    /// Storage backend
    storage: GrantStorage,
    /// Capability signer for issuing grants
    signer: CapabilitySigner,
    /// Capability verifier for validating grants
    verifier: CapabilityVerifier,
    /// Policy enforcer
    enforcer: Arc<Mutex<PolicyEnforcer>>,
    /// Local peer identity
    identity: DurablePeerIdentity,
    /// Grant templates
    templates: HashMap<String, GrantTemplate>,
}

impl GrantManager {
    /// Create a new grant manager.
    pub fn new<P: AsRef<Path>>(storage_dir: P, key_store: IdentityKeyStore) -> GrantResult<Self> {
        let storage = GrantStorage::new(storage_dir)?;
        let signer =
            CapabilitySigner::new(key_store).map_err(|e| GrantError::Storage(e.to_string()))?;
        let verifier = CapabilityVerifier::new();
        let enforcer = Arc::new(Mutex::new(PolicyEnforcer::new()));
        let identity = signer.identity().clone();

        let mut templates = HashMap::new();
        Self::load_default_templates(&mut templates);

        let mut manager = Self {
            storage,
            signer,
            verifier,
            enforcer,
            identity,
            templates,
        };

        // Load existing grants into enforcer
        if let Err(e) = manager.load_grants_into_enforcer() {
            eprintln!("Warning: failed to load grants into enforcer: {e}");
        }

        Ok(manager)
    }

    /// Issue a new capability grant.
    pub fn issue_grant(&mut self, mut request: CreateGrantRequest) -> GrantResult<GrantInfo> {
        // Generate unique grant ID
        let grant_id = self.generate_grant_id(&request);

        // Create capability
        let mut capability = Capability::new(
            grant_id.clone(),
            request.subject,
            self.identity.peer_id(),
            request.scope,
            request.actions,
            request.temporal,
            request.constraints,
        );

        // Sign the capability
        self.signer
            .sign_capability(&mut capability)
            .map_err(|e| GrantError::Storage(e.to_string()))?;

        // Create grant info
        let mut grant_info = GrantInfo::new(capability);
        if let Some(parent_id) = request.parent_grant_id {
            grant_info.parent_grant_id = Some(parent_id);
        }

        // Store the grant
        self.storage.store_grant(grant_info.clone())?;

        // Add to policy enforcer
        if let Ok(mut enforcer) = self.enforcer.lock() {
            enforcer.add_capability(grant_info.capability.clone());
        }

        // Record audit event
        let audit_record = GrantAuditRecord {
            grant_id: grant_id.clone(),
            operation: GrantOperation::Issued,
            actor: self.identity.peer_id(),
            target: Some(request.subject),
            timestamp: SystemTime::now(),
            context: self.create_audit_context(&request),
            capability_summary: grant_info.redacted_summary(),
        };

        self.storage.add_audit_record(audit_record)?;

        Ok(grant_info)
    }

    /// Receive a grant from another peer.
    pub fn receive_grant(&mut self, capability: Capability) -> GrantResult<GrantInfo> {
        // Verify the capability
        let validation = self
            .verifier
            .validate_capability(&capability)
            .map_err(|e| GrantError::Storage(e.to_string()))?;

        if !validation.valid {
            let issues: Vec<String> = validation.issues.iter().map(|i| i.to_string()).collect();
            return Outcome::Err(GrantError::ValidationFailed { issues });
        }

        // Check if we already have this grant
        if let Ok(_) = self.storage.get_grant(&capability.grant_id) {
            return Outcome::Err(GrantError::AlreadyExists {
                grant_id: capability.grant_id,
            });
        }

        // Create grant info
        let grant_info = GrantInfo::new(capability.clone());

        // Store the grant
        self.storage.store_grant(grant_info.clone())?;

        // Add to policy enforcer if this grant is for us
        if capability.subject == self.identity.peer_id() {
            if let Ok(mut enforcer) = self.enforcer.lock() {
                enforcer.add_capability(capability.clone());
            }
        }

        // Record audit event
        let audit_record = GrantAuditRecord {
            grant_id: capability.grant_id.clone(),
            operation: GrantOperation::Received,
            actor: self.identity.peer_id(),
            target: Some(capability.issuer),
            timestamp: SystemTime::now(),
            context: HashMap::new(),
            capability_summary: grant_info.redacted_summary(),
        };

        self.storage.add_audit_record(audit_record)?;

        Ok(grant_info)
    }

    /// Revoke a capability grant.
    pub fn revoke_grant(&mut self, grant_id: &str) -> GrantResult<()> {
        // Get the grant
        let mut grant_info = self.storage.get_grant(grant_id)?;

        // Check if we can revoke this grant (we must be the issuer)
        if grant_info.capability.issuer != self.identity.peer_id() {
            return Outcome::Err(GrantError::PermissionDenied {
                reason: "only the issuer can revoke a grant".to_string(),
            });
        }

        // Check current state
        if grant_info.state == GrantState::Revoked {
            return Outcome::Err(GrantError::InvalidState {
                state: grant_info.state,
            });
        }

        // Revoke the grant
        grant_info.revoke();
        self.storage.update_grant(grant_id, grant_info.clone())?;

        // Remove from policy enforcer
        if let Ok(mut enforcer) = self.enforcer.lock() {
            enforcer.revoke_capability(grant_id);
        }

        // Record audit event
        let audit_record = GrantAuditRecord {
            grant_id: grant_id.to_string(),
            operation: GrantOperation::Revoked,
            actor: self.identity.peer_id(),
            target: Some(grant_info.capability.subject),
            timestamp: SystemTime::now(),
            context: HashMap::new(),
            capability_summary: grant_info.redacted_summary(),
        };

        self.storage.add_audit_record(audit_record)?;

        Ok(())
    }

    /// Rotate a capability grant (create new version).
    pub fn rotate_grant(&mut self, grant_id: &str) -> GrantResult<GrantInfo> {
        // Get the existing grant
        let mut old_grant = self.storage.get_grant(grant_id)?;

        // Check if we can rotate this grant
        if old_grant.capability.issuer != self.identity.peer_id() {
            return Outcome::Err(GrantError::PermissionDenied {
                reason: "only the issuer can rotate a grant".to_string(),
            });
        }

        if !matches!(old_grant.state, GrantState::Active | GrantState::Pending) {
            return Outcome::Err(GrantError::InvalidState {
                state: old_grant.state,
            });
        }

        // Create new grant with updated temporal scope
        let new_grant_id = format!(
            "{}-r{}",
            grant_id,
            SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        let mut new_capability = old_grant.capability.clone();
        new_capability.grant_id = new_grant_id.clone();
        new_capability.issued_at = SystemTime::now();

        // Sign the new capability
        self.signer
            .sign_capability(&mut new_capability)
            .map_err(|e| GrantError::Storage(e.to_string()))?;

        // Create new grant info
        let new_grant_info = GrantInfo::new(new_capability);

        // Store new grant
        self.storage.store_grant(new_grant_info.clone())?;

        // Update old grant to mark as rotated
        old_grant.rotate(new_grant_id.clone());
        self.storage.update_grant(grant_id, old_grant)?;

        // Update policy enforcer
        if let Ok(mut enforcer) = self.enforcer.lock() {
            enforcer.remove_capability(grant_id);
            enforcer.add_capability(new_grant_info.capability.clone());
        }

        // Record audit events
        let rotate_record = GrantAuditRecord {
            grant_id: new_grant_id.clone(),
            operation: GrantOperation::Rotated,
            actor: self.identity.peer_id(),
            target: Some(new_grant_info.capability.subject),
            timestamp: SystemTime::now(),
            context: {
                let mut ctx = HashMap::new();
                ctx.insert("previous_grant_id".to_string(), grant_id.to_string());
                ctx
            },
            capability_summary: new_grant_info.redacted_summary(),
        };

        self.storage.add_audit_record(rotate_record)?;

        Ok(new_grant_info)
    }

    /// List grants matching criteria.
    pub fn list_grants(&self, query: &GrantQuery) -> GrantResult<Vec<GrantInfo>> {
        self.storage.list_grants(query)
    }

    /// Get a specific grant.
    pub fn get_grant(&self, grant_id: &str) -> GrantResult<GrantInfo> {
        self.storage.get_grant(grant_id)
    }

    /// Evaluate an access request against current grants.
    pub fn evaluate_access(&mut self, request: &AccessRequest) -> GrantResult<PolicyDecision> {
        let mut enforcer = match self.enforcer.lock() {
            Ok(guard) => guard,
            Err(e) => {
                return Outcome::err(GrantError::Storage(format!("enforcer lock error: {e}")));
            }
        };

        let decision = enforcer.evaluate_access(request);

        // Record usage if access was granted
        if let crate::atp::policy::CapabilityDecision::Granted { ref capability, .. } =
            decision.decision
        {
            // Update usage count in storage
            if let Ok(mut grant_info) = self.storage.get_grant(&capability.grant_id) {
                grant_info.record_usage();

                if let Err(e) = self
                    .storage
                    .update_grant(&capability.grant_id, grant_info.clone())
                {
                    eprintln!("Warning: failed to update grant usage: {e}");
                } else {
                    // Record audit event
                    let audit_record = GrantAuditRecord {
                        grant_id: capability.grant_id.clone(),
                        operation: GrantOperation::Used,
                        actor: request.peer,
                        target: None,
                        timestamp: SystemTime::now(),
                        context: {
                            let mut ctx = HashMap::new();
                            ctx.insert("action".to_string(), format!("{:?}", request.action));
                            if let Some(ref session_id) = request.context.session_id {
                                ctx.insert("session_id".to_string(), session_id.clone());
                            }
                            ctx
                        },
                        capability_summary: grant_info.redacted_summary(),
                    };

                    if let Err(e) = self.storage.add_audit_record(audit_record) {
                        eprintln!("Warning: failed to record usage audit: {e}");
                    }
                }
            }
        }

        Outcome::ok(decision)
    }

    /// Add a trusted peer for grant verification.
    pub fn add_trusted_peer(&mut self, identity: DurablePeerIdentity) {
        self.verifier.add_trusted_peer(identity);
    }

    /// Create a grant from a template.
    pub fn create_from_template(
        &mut self,
        template_name: &str,
        subject: PeerId,
    ) -> GrantResult<GrantInfo> {
        let template = self
            .templates
            .get(template_name)
            .ok_or_else(|| GrantError::Storage(format!("template not found: {template_name}")))?;

        let mut request = CreateGrantRequest {
            subject,
            scope: template.scope.clone(),
            actions: template.actions.clone(),
            temporal: template.temporal.clone(),
            constraints: template.constraints.clone(),
            description: Some(template.description.clone()),
            parent_grant_id: None,
        };

        self.issue_grant(request)
    }

    /// Get grant statistics.
    #[must_use]
    pub fn get_stats(&self) -> GrantStats {
        self.storage.get_stats()
    }

    /// Get audit records for a grant.
    pub fn get_audit_records(&self, grant_id: &str) -> GrantResult<Vec<GrantAuditRecord>> {
        self.storage.get_audit_records(grant_id)
    }

    /// Get global audit records.
    #[must_use]
    pub fn get_global_audit_records(&self) -> Vec<GrantAuditRecord> {
        self.storage.get_global_audit_records()
    }

    /// Load default grant templates.
    fn load_default_templates(templates: &mut HashMap<String, GrantTemplate>) {
        templates.insert("read-once".to_string(), GrantTemplate::read_once());
        templates.insert("share-24h".to_string(), GrantTemplate::share_24h());
        templates.insert("inbox-write".to_string(), GrantTemplate::inbox_write());
    }

    /// Generate a unique grant ID.
    fn generate_grant_id(&self, request: &CreateGrantRequest) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.identity.peer_id().as_bytes());
        hasher.update(request.subject.as_bytes());
        hasher.update(&request.scope.digest());
        hasher.update(
            &SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );

        let hash = hasher.finalize();
        format!("grant-{}", hex::encode(&hash[..16]))
    }

    /// Create audit context from request.
    fn create_audit_context(&self, request: &CreateGrantRequest) -> HashMap<String, String> {
        let mut context = HashMap::new();

        if let Some(ref desc) = request.description {
            context.insert("description".to_string(), desc.clone());
        }

        if let Some(ref parent) = request.parent_grant_id {
            context.insert("parent_grant_id".to_string(), parent.clone());
        }

        context.insert("actions".to_string(), format!("{:?}", request.actions));
        context.insert(
            "scope_type".to_string(),
            match &request.scope {
                crate::atp::policy::ResourceScope::Any => "any".to_string(),
                crate::atp::policy::ResourceScope::Object(_) => "object".to_string(),
                crate::atp::policy::ResourceScope::Path(_) => "path".to_string(),
                crate::atp::policy::ResourceScope::Inbox => "inbox".to_string(),
                crate::atp::policy::ResourceScope::Team(t) => format!("team:{t}"),
                crate::atp::policy::ResourceScope::Relay { .. } => "relay".to_string(),
                crate::atp::policy::ResourceScope::Cache { .. } => "cache".to_string(),
            },
        );

        context
    }

    /// Load existing grants into the policy enforcer.
    fn load_grants_into_enforcer(&mut self) -> GrantResult<()> {
        let query = GrantQuery {
            usable_only: true,
            ..Default::default()
        };

        let grants = self.storage.list_grants(&query)?;

        if let Ok(mut enforcer) = self.enforcer.lock() {
            for grant in grants {
                enforcer.add_capability(grant.capability);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::policy::{CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope};
    use crate::security::keys::IdentityKeyStore;
    use std::collections::HashSet;
    use std::time::Duration;
    use tempfile::tempdir;

    fn create_test_manager() -> GrantManager {
        let temp_dir = tempdir().expect("tempdir");
        let key_store_path = temp_dir.path().join("keys.json");
        let key_store =
            IdentityKeyStore::create(key_store_path, [1; 32], 1).expect("create key store");

        GrantManager::new(temp_dir.path(), key_store).expect("create manager")
    }

    #[test]
    fn grant_manager_issues_and_stores_grants() {
        let mut manager = create_test_manager();

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: Some("test grant".to_string()),
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");

        // Verify grant was stored
        let retrieved = manager
            .get_grant(&grant_info.capability.grant_id)
            .expect("get grant");
        assert_eq!(
            retrieved.capability.grant_id,
            grant_info.capability.grant_id
        );
    }

    #[test]
    fn grant_manager_creates_from_templates() {
        let mut manager = create_test_manager();

        let grant_info = manager
            .create_from_template("read-once", crate::net::atp::protocol::PeerId::test(1))
            .expect("create from template");

        assert!(
            grant_info
                .capability
                .grants_action(&CapabilityAction::ReadOnce)
        );
        assert_eq!(grant_info.capability.temporal.max_uses, Some(1));
    }

    #[test]
    fn grant_manager_revokes_grants() {
        let mut manager = create_test_manager();

        // Issue a grant
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");

        // Revoke the grant
        manager
            .revoke_grant(&grant_info.capability.grant_id)
            .expect("revoke grant");

        // Verify grant is revoked
        let revoked = manager
            .get_grant(&grant_info.capability.grant_id)
            .expect("get grant");
        assert_eq!(revoked.state, GrantState::Revoked);
    }

    #[test]
    fn grant_manager_tracks_audit_records() {
        let mut manager = create_test_manager();

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");

        // Check audit records
        let audit_records = manager
            .get_audit_records(&grant_info.capability.grant_id)
            .expect("get audit records");

        assert_eq!(audit_records.len(), 1);
        assert_eq!(audit_records[0].operation, GrantOperation::Issued);
    }

    #[test]
    fn grant_manager_rotates_grants() {
        let mut manager = create_test_manager();

        // Issue a grant
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let request = CreateGrantRequest {
            subject: crate::net::atp::protocol::PeerId::test(1),
            scope: ResourceScope::Any,
            actions,
            temporal: TemporalScope::expires_in(Duration::from_secs(3600)),
            constraints: ScopeConstraints::default(),
            description: None,
            parent_grant_id: None,
        };

        let grant_info = manager.issue_grant(request).expect("issue grant");
        let original_id = grant_info.capability.grant_id.clone();

        // Rotate the grant
        let new_grant = manager.rotate_grant(&original_id).expect("rotate grant");

        // Verify old grant is marked as rotated
        let old_grant = manager.get_grant(&original_id).expect("get old grant");
        assert_eq!(old_grant.state, GrantState::Rotated);

        // Verify new grant is active
        let retrieved_new = manager
            .get_grant(&new_grant.capability.grant_id)
            .expect("get new grant");
        assert_eq!(retrieved_new.state, GrantState::Active);
    }
}
