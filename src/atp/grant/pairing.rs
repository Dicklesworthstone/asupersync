//! Pairing and share code functionality for ATP capability grants.

use super::{GrantError, GrantResult};
use crate::atp::identity::DurablePeerIdentity;
use crate::atp::policy::{
    Capability, CapabilityAction, ResourceScope, ScopeConstraints, TemporalScope,
};
use crate::net::atp::protocol::PeerId;
use crate::types::outcome::Outcome;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime};

const MAX_PAIRING_CODE_GENERATION_ATTEMPTS: usize = 8;

/// Pairing code for establishing trust between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingCode {
    /// Unique code identifier
    pub code: String,
    /// Peer identity offering the pairing
    pub issuer: PeerId,
    /// Public key for verification
    pub issuer_public_key: String,
    /// Allowed actions for the pairing
    pub actions: HashSet<CapabilityAction>,
    /// Resource scope for the pairing
    pub scope: ResourceScope,
    /// Time constraints
    pub temporal: TemporalScope,
    /// Additional constraints
    pub constraints: ScopeConstraints,
    /// When the code was created
    pub created_at: SystemTime,
    /// Optional description
    pub description: Option<String>,
    /// One-time use flag
    pub one_time: bool,
    /// Number of times used
    pub use_count: u64,
    /// Maximum uses allowed
    pub max_uses: Option<u64>,
}

impl PairingCode {
    /// Create a new pairing code.
    pub fn new(
        issuer_identity: &DurablePeerIdentity,
        actions: HashSet<CapabilityAction>,
        scope: ResourceScope,
        temporal: TemporalScope,
        constraints: ScopeConstraints,
        one_time: bool,
    ) -> GrantResult<Self> {
        let code = match Self::generate_code(issuer_identity, &actions, &scope) {
            Outcome::Ok(code) => code,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        Outcome::ok(Self {
            code,
            issuer: issuer_identity.peer_id(),
            issuer_public_key: issuer_identity.public_key().to_string(),
            actions,
            scope,
            temporal,
            constraints,
            created_at: SystemTime::now(), // ubs:ignore - timestamp recording, not crypto randomness
            description: None,
            one_time,
            use_count: 0,
            max_uses: if one_time { Some(1) } else { None },
        })
    }

    /// Set a description for the pairing code.
    pub fn with_description(mut self, description: String) -> Self {
        self.description = Some(description);
        self
    }

    /// Set maximum uses for the pairing code.
    pub fn with_max_uses(mut self, max_uses: u64) -> Self {
        self.max_uses = Some(max_uses);
        self.one_time = max_uses == 1;
        self
    }

    /// Check if the pairing code is still valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Check time validity
        if !self.temporal.is_valid_at(SystemTime::now()) {
            return false;
        }

        // Check usage limits
        if let Some(max_uses) = self.max_uses {
            if self.use_count >= max_uses {
                return false;
            }
        }

        true
    }

    /// Record usage of this pairing code.
    pub fn record_use(&mut self) -> bool {
        if !self.is_valid() {
            return false;
        }

        self.use_count = self.use_count.saturating_add(1);
        true
    }

    /// Get remaining uses.
    #[must_use]
    pub fn remaining_uses(&self) -> Option<u64> {
        self.max_uses.map(|max| max.saturating_sub(self.use_count))
    }

    /// Generate a unique pairing code.
    fn generate_code(
        identity: &DurablePeerIdentity,
        actions: &HashSet<CapabilityAction>,
        scope: &ResourceScope,
    ) -> GrantResult<String> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(identity.peer_id().as_bytes());
        hasher.update(identity.generation().to_le_bytes());

        // Include actions in deterministic order
        let mut action_strs: Vec<_> = actions.iter().map(|a| format!("{a:?}")).collect();
        action_strs.sort();
        for action in action_strs {
            hasher.update(action.as_bytes());
        }

        hasher.update(scope.digest());

        let mut random_bytes = [0u8; 16];
        if let Err(error) = getrandom::fill(&mut random_bytes) {
            return Outcome::Err(GrantError::PairingError {
                reason: format!("failed to generate secure pairing code entropy: {error}"),
            });
        }
        hasher.update(random_bytes);

        let hash = hasher.finalize();
        let Some(code_bytes) = hash.get(..12) else {
            return Outcome::Err(GrantError::PairingError {
                reason: "sha256 digest shorter than pairing-code prefix".to_string(),
            });
        };

        // Encode as human-readable string
        Outcome::ok(Self::encode_pairing_code(code_bytes))
    }

    /// Encode pairing code bytes as human-readable string.
    fn encode_pairing_code(bytes: &[u8]) -> String {
        const CROCKFORD_BASE32: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
        let mut encoded = String::new();
        let mut accumulator = 0u16;
        let mut bits = 0u8;

        for byte in bytes {
            accumulator = (accumulator << 8) | u16::from(*byte);
            bits += 8;
            while bits >= 5 {
                let shift = bits - 5;
                let index = ((accumulator >> shift) & 0b1_1111) as usize;
                encoded.push(char::from(CROCKFORD_BASE32[index]));
                accumulator &= (1u16 << shift).saturating_sub(1);
                bits = shift;
            }
        }

        if bits > 0 {
            let index = ((accumulator << (5 - bits)) & 0b1_1111) as usize;
            encoded.push(char::from(CROCKFORD_BASE32[index]));
        }

        let mut result = String::new();
        for (i, c) in encoded.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                result.push('-');
            }
            result.push(c);
        }

        result
    }

    /// Create a human-readable summary of the pairing code.
    #[must_use]
    pub fn summary(&self) -> String {
        let actions: Vec<String> = self.actions.iter().map(|a| format!("{a:?}")).collect();

        let scope_desc = match &self.scope {
            ResourceScope::Any => "any resource".to_string(),
            ResourceScope::Object(_) => "specific object".to_string(),
            ResourceScope::Path(_) => "path pattern".to_string(),
            ResourceScope::Inbox => "inbox".to_string(),
            ResourceScope::Team(team) => format!("team {team}"),
            ResourceScope::Relay { .. } => "relay".to_string(),
            ResourceScope::Cache { .. } => "cache".to_string(),
        };

        let expiry_desc = if let Some(not_after) = self.temporal.not_after {
            format!("expires {}", format_duration_from_now(not_after))
        } else {
            "no expiry".to_string()
        };

        let uses_desc = if let Some(remaining) = self.remaining_uses() {
            format!("{remaining} uses remaining")
        } else {
            "unlimited uses".to_string()
        };

        format!(
            "Code: {} | Actions: [{}] | Scope: {} | {} | {}",
            self.code,
            actions.join(", "),
            scope_desc,
            expiry_desc,
            uses_desc
        )
    }
}

/// Pairing flow manager for handling peer trust establishment.
pub struct PairingManager {
    /// Active pairing codes by code string
    active_codes: HashMap<String, PairingCode>,
    /// Completed pairings
    completed_pairings: Vec<CompletedPairing>,
    /// Local peer identity
    identity: DurablePeerIdentity,
}

/// Record of a completed pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedPairing {
    /// Pairing code that was used
    pub code: String,
    /// Peer that used the code
    pub peer: PeerId,
    /// Capability that was granted
    pub capability: Capability,
    /// When the pairing was completed
    pub completed_at: SystemTime,
}

/// Pairing flow states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairingFlowState {
    /// Waiting for peer to use the code
    Pending,
    /// Code has been used
    Used,
    /// Code has expired
    Expired,
    /// Code was manually cancelled
    Cancelled,
}

/// A pairing flow instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingFlow {
    /// The pairing code
    pub pairing_code: PairingCode,
    /// Current state
    pub state: PairingFlowState,
    /// Confirmation required from user
    pub requires_confirmation: bool,
    /// Pending confirmation requests
    pub pending_confirmations: Vec<PairingRequest>,
}

/// A request to use a pairing code.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingRequest {
    /// Code being requested
    pub code: String,
    /// Requesting peer
    pub peer: PeerId,
    /// Peer's public key
    pub peer_public_key: String,
    /// When the request was made
    pub requested_at: SystemTime,
    /// Optional message from requester
    pub message: Option<String>,
}

impl PairingManager {
    /// Create a new pairing manager.
    #[must_use]
    pub fn new(identity: DurablePeerIdentity) -> Self {
        Self {
            active_codes: HashMap::new(),
            completed_pairings: Vec::new(),
            identity,
        }
    }

    /// Generate a new pairing code.
    pub fn generate_pairing_code(
        &mut self,
        actions: HashSet<CapabilityAction>,
        scope: ResourceScope,
        duration: Duration,
        one_time: bool,
    ) -> GrantResult<String> {
        for _ in 0..MAX_PAIRING_CODE_GENERATION_ATTEMPTS {
            let temporal = TemporalScope::expires_in(duration);
            let constraints = ScopeConstraints::default();

            let pairing_code = match PairingCode::new(
                &self.identity,
                actions.clone(),
                scope.clone(),
                temporal,
                constraints,
                one_time,
            ) {
                Outcome::Ok(code) => code,
                Outcome::Err(error) => return Outcome::Err(error),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            };

            if let Some(code) = self.insert_pairing_code_if_vacant(pairing_code) {
                return Outcome::ok(code);
            }
        }

        Outcome::Err(GrantError::PairingError {
            reason: format!(
                "failed to generate a unique pairing code after {MAX_PAIRING_CODE_GENERATION_ATTEMPTS} attempts"
            ),
        })
    }

    /// Generate a share code for quick access.
    pub fn generate_share_code(
        &mut self,
        actions: HashSet<CapabilityAction>,
        scope: ResourceScope,
        duration: Duration,
    ) -> GrantResult<String> {
        // Share codes are typically one-time use
        self.generate_pairing_code(actions, scope, duration, true)
    }

    /// Start a pairing flow with human confirmation.
    pub fn start_pairing_flow(
        &mut self,
        actions: HashSet<CapabilityAction>,
        scope: ResourceScope,
        duration: Duration,
        requires_confirmation: bool,
    ) -> GrantResult<PairingFlow> {
        let code = match self.generate_pairing_code(actions, scope, duration, false) {
            Outcome::Ok(code) => code,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        let Some(pairing_code) = self.active_codes.get(&code).cloned() else {
            return Outcome::Err(GrantError::PairingError {
                reason: "generated pairing code was not inserted".to_string(),
            });
        };

        Outcome::ok(PairingFlow {
            pairing_code,
            state: PairingFlowState::Pending,
            requires_confirmation,
            pending_confirmations: Vec::new(),
        })
    }

    /// Request to use a pairing code.
    pub fn request_pairing(
        &mut self,
        code: &str,
        requester_identity: &DurablePeerIdentity,
        message: Option<String>,
    ) -> GrantResult<PairingRequest> {
        // Check if code exists
        match self.active_codes.get(code) {
            Some(pairing_code) if pairing_code.is_valid() => {}
            Some(_) => {
                return Outcome::Err(GrantError::PairingError {
                    reason: "pairing code is expired or exhausted".to_string(),
                });
            }
            None => {
                return Outcome::Err(GrantError::NotFound {
                    grant_id: code.to_string(),
                });
            }
        }

        let request = PairingRequest {
            code: code.to_string(),
            peer: requester_identity.peer_id(),
            peer_public_key: requester_identity.public_key().to_string(),
            requested_at: SystemTime::now(),
            message,
        };

        Outcome::ok(request)
    }

    /// Use a pairing code to complete pairing.
    pub fn use_pairing_code(
        &mut self,
        code: &str,
        peer_identity: &DurablePeerIdentity,
    ) -> GrantResult<Capability> {
        // Get and remove the pairing code
        let mut pairing_code = match self.active_codes.remove(code) {
            Some(code) => code,
            None => {
                return Outcome::Err(GrantError::NotFound {
                    grant_id: code.to_string(),
                });
            }
        };

        // Reject invalid codes before any fallible grant-id generation, and
        // avoid consuming a live code if system entropy is temporarily
        // unavailable.
        if !pairing_code.is_valid() {
            return Outcome::Err(GrantError::PairingError {
                reason: "pairing code cannot be used".to_string(),
            });
        }

        let grant_id = match self.generate_pairing_grant_id(code, peer_identity.peer_id()) {
            Outcome::Ok(grant_id) => grant_id,
            Outcome::Err(error) => {
                self.restore_pairing_code_if_valid(code, pairing_code);
                return Outcome::Err(error);
            }
            Outcome::Cancelled(reason) => {
                self.restore_pairing_code_if_valid(code, pairing_code);
                return Outcome::Cancelled(reason);
            }
            Outcome::Panicked(payload) => {
                self.restore_pairing_code_if_valid(code, pairing_code);
                return Outcome::Panicked(payload);
            }
        };

        // Create capability for the requesting peer
        if !pairing_code.record_use() {
            if pairing_code.is_valid() {
                self.active_codes.insert(code.to_string(), pairing_code);
            }
            return Outcome::Err(GrantError::PairingError {
                reason: "pairing code cannot be used".to_string(),
            });
        }

        let capability = Capability::new(
            grant_id,
            peer_identity.peer_id(),
            self.identity.peer_id(),
            pairing_code.scope.clone(),
            pairing_code.actions.clone(),
            pairing_code.temporal.clone(),
            pairing_code.constraints.clone(),
        );

        // Record completed pairing
        let completed = CompletedPairing {
            code: code.to_string(),
            peer: peer_identity.peer_id(),
            capability: capability.clone(),
            completed_at: SystemTime::now(),
        };

        self.completed_pairings.push(completed);

        // Keep reusable codes active after successful use; one-time and exhausted
        // limited-use codes become invalid and stay removed.
        if pairing_code.is_valid() {
            self.active_codes.insert(code.to_string(), pairing_code);
        }

        Outcome::ok(capability)
    }

    /// Cancel a pairing code.
    pub fn cancel_pairing_code(&mut self, code: &str) -> GrantResult<()> {
        match self.active_codes.remove(code) {
            Some(_) => Outcome::ok(()),
            None => Outcome::Err(GrantError::NotFound {
                grant_id: code.to_string(),
            }),
        }
    }

    /// List active pairing codes.
    #[must_use]
    pub fn list_active_codes(&self) -> Vec<PairingCode> {
        self.active_codes.values().cloned().collect()
    }

    /// Get a specific pairing code.
    pub fn get_pairing_code(&self, code: &str) -> GrantResult<PairingCode> {
        match self.active_codes.get(code) {
            Some(code) => Outcome::ok(code.clone()),
            None => Outcome::Err(GrantError::NotFound {
                grant_id: code.to_string(),
            }),
        }
    }

    /// List completed pairings.
    #[must_use]
    pub fn list_completed_pairings(&self) -> Vec<CompletedPairing> {
        self.completed_pairings.clone()
    }

    /// Clean up expired pairing codes.
    pub fn cleanup_expired_codes(&mut self) -> u32 {
        let mut removed_count = 0;
        let mut to_remove = Vec::new();

        for (code, pairing_code) in &self.active_codes {
            if !pairing_code.is_valid() {
                to_remove.push(code.clone());
            }
        }

        for code in to_remove {
            self.active_codes.remove(&code);
            removed_count += 1;
        }

        removed_count
    }

    /// Create a quick read-once share code.
    pub fn create_read_once_share(&mut self, scope: ResourceScope) -> GrantResult<String> {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::ReadOnce);

        self.generate_share_code(actions, scope, Duration::from_secs(3600)) // 1 hour
    }

    /// Create a temporary write share code.
    pub fn create_temp_write_share(
        &mut self,
        scope: ResourceScope,
        hours: u64,
    ) -> GrantResult<String> {
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Write);

        let Some(seconds) = hours.checked_mul(3600) else {
            return Outcome::Err(GrantError::PairingError {
                reason: "share duration overflows u64 seconds".to_string(),
            });
        };

        self.generate_share_code(actions, scope, Duration::from_secs(seconds))
    }

    fn insert_pairing_code_if_vacant(&mut self, pairing_code: PairingCode) -> Option<String> {
        let code = pairing_code.code.clone();
        match self.active_codes.entry(code.clone()) {
            Entry::Vacant(entry) => {
                entry.insert(pairing_code);
                Some(code)
            }
            Entry::Occupied(_) => None,
        }
    }

    fn restore_pairing_code_if_valid(&mut self, code: &str, pairing_code: PairingCode) {
        if pairing_code.is_valid() {
            self.active_codes.insert(code.to_string(), pairing_code);
        }
    }

    fn generate_pairing_grant_id(&self, code: &str, peer: PeerId) -> GrantResult<String> {
        use sha2::{Digest, Sha256};

        let mut nonce = [0u8; 16];
        if let Err(error) = getrandom::fill(&mut nonce) {
            return Outcome::Err(GrantError::PairingError {
                reason: format!("failed to generate secure pairing grant entropy: {error}"),
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(b"asupersync-atp-pairing-grant-v1");
        hasher.update(self.identity.peer_id().as_bytes());
        hasher.update(peer.as_bytes());
        hasher.update(code.as_bytes());
        hasher.update((self.completed_pairings.len() as u64).to_le_bytes());
        hasher.update(nonce);

        let digest = hasher.finalize();
        Outcome::ok(format!("paired-{}", hex::encode(&digest[..16])))
    }
}

/// Format a duration from now in human-readable form.
fn format_duration_from_now(time: SystemTime) -> String {
    let now = SystemTime::now();
    if time <= now {
        return "expired".to_string();
    }

    let duration = time.duration_since(now).unwrap_or_default();
    let seconds = duration.as_secs();

    if seconds < 60 {
        format!("in {}s", seconds)
    } else if seconds < 3600 {
        format!("in {}m", seconds / 60)
    } else if seconds < 86400 {
        format!("in {}h", seconds / 3600)
    } else {
        format!("in {}d", seconds / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::keys::IdentityKeyStore;
    use tempfile::tempdir;

    fn create_test_identity() -> DurablePeerIdentity {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("identity.json");
        let seed = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let store = IdentityKeyStore::create(path, seed, 1).expect("create key store");
        DurablePeerIdentity::from_key_store(&store).expect("durable identity")
    }

    #[test]
    fn pairing_code_generates_valid_code() {
        let identity = create_test_identity();
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let pairing_code = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            true,
        )
        .expect("create pairing code");

        assert!(!pairing_code.code.is_empty());
        assert!(pairing_code.is_valid());
        assert_eq!(pairing_code.remaining_uses(), Some(1));
    }

    #[test]
    fn pairing_manager_generates_and_uses_codes() {
        let identity = create_test_identity();
        let peer_identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions.clone(),
                ResourceScope::Any,
                Duration::from_secs(3600),
                true,
            )
            .expect("generate pairing code");

        // Use the pairing code
        let capability = manager
            .use_pairing_code(&code, &peer_identity)
            .expect("use pairing code");

        assert_eq!(capability.subject, peer_identity.peer_id());
        assert!(capability.grants_action(&CapabilityAction::Read));

        // Verify completed pairing was recorded
        let completed = manager.list_completed_pairings();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].peer, peer_identity.peer_id());
    }

    #[test]
    fn pairing_code_enforces_usage_limits() {
        let identity = create_test_identity();
        let peer_identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                true, // one-time use
            )
            .expect("generate pairing code");

        // First use should succeed
        let _capability1 = manager
            .use_pairing_code(&code, &peer_identity)
            .expect("first use");

        // Second use should fail
        let result2 = manager.use_pairing_code(&code, &peer_identity);
        assert!(result2.is_err());
    }

    #[test]
    fn pairing_manager_cleans_up_expired_codes() {
        let identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        // Create expired code (0 second expiry)
        let temporal = TemporalScope::expires_in(Duration::from_secs(0));
        let pairing_code = PairingCode {
            code: "TEST-CODE".to_string(),
            issuer: manager.identity.peer_id(),
            issuer_public_key: manager.identity.public_key().to_string(),
            actions,
            scope: ResourceScope::Any,
            temporal,
            constraints: ScopeConstraints::default(),
            created_at: SystemTime::now(),
            description: None,
            one_time: true,
            use_count: 0,
            max_uses: Some(1),
        };

        manager
            .active_codes
            .insert("TEST-CODE".to_string(), pairing_code);

        // Wait a moment for expiry
        std::thread::sleep(Duration::from_millis(10));

        let removed_count = manager.cleanup_expired_codes();
        assert_eq!(removed_count, 1);
        assert!(manager.active_codes.is_empty());
    }

    #[test]
    fn pairing_code_summary_is_readable() {
        let identity = create_test_identity();
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        actions.insert(CapabilityAction::Share);

        let pairing_code = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Inbox,
            TemporalScope::once(),
            ScopeConstraints::default(),
            true,
        )
        .expect("create pairing code");

        let summary = pairing_code.summary();
        assert!(summary.contains("Code:"));
        assert!(summary.contains("Read"));
        assert!(summary.contains("Share"));
        assert!(summary.contains("inbox"));
        assert!(summary.contains("1 uses remaining"));
    }

    #[test]
    fn reusable_pairing_code_remains_active_after_successful_use() {
        let identity = create_test_identity();
        let first_peer = create_test_identity();
        let second_peer = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                false,
            )
            .expect("generate reusable pairing code");

        let first = manager
            .use_pairing_code(&code, &first_peer)
            .expect("first use should succeed");
        let second = manager
            .use_pairing_code(&code, &second_peer)
            .expect("second use should also succeed for unlimited code");

        assert_eq!(first.subject, first_peer.peer_id());
        assert_eq!(second.subject, second_peer.peer_id());
        assert!(manager.get_pairing_code(&code).is_ok());
    }

    #[test]
    fn pairing_code_collision_does_not_overwrite_active_code() {
        let identity = create_test_identity();
        let mut manager = PairingManager::new(identity.clone());

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let mut first = PairingCode::new(
            &identity,
            actions.clone(),
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            false,
        )
        .expect("create first pairing code")
        .with_description("first".to_string());
        first.code = "DUPL-ICAT-ECOD-E".to_string();

        let mut colliding = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            false,
        )
        .expect("create colliding pairing code")
        .with_description("second".to_string());
        colliding.code.clone_from(&first.code);

        assert_eq!(
            manager.insert_pairing_code_if_vacant(first.clone()),
            Some(first.code.clone())
        );
        assert_eq!(manager.insert_pairing_code_if_vacant(colliding), None);

        let stored = manager
            .get_pairing_code(&first.code)
            .expect("get original pairing code");
        assert_eq!(stored.description.as_deref(), Some("first"));
        assert_eq!(manager.list_active_codes().len(), 1);
    }

    #[test]
    fn reusable_pairing_code_issues_unique_grant_ids_for_same_peer() {
        let identity = create_test_identity();
        let peer = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                false,
            )
            .expect("generate reusable pairing code");

        let first = manager
            .use_pairing_code(&code, &peer)
            .expect("first use should succeed");
        let second = manager
            .use_pairing_code(&code, &peer)
            .expect("second use should succeed for the same peer");

        assert_ne!(first.grant_id, second.grant_id);
        assert!(first.grant_id.starts_with("paired-"));
        assert!(second.grant_id.starts_with("paired-"));
        assert!(!first.grant_id.contains(&code));
        assert!(!second.grant_id.contains(&code));
    }

    #[test]
    fn limited_pairing_code_is_removed_after_last_use() {
        let identity = create_test_identity();
        let peer_identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);

        let code = manager
            .generate_pairing_code(
                actions,
                ResourceScope::Any,
                Duration::from_secs(3600),
                false,
            )
            .expect("generate limited pairing code");
        manager
            .active_codes
            .get_mut(&code)
            .expect("active pairing code")
            .max_uses = Some(2);

        manager
            .use_pairing_code(&code, &peer_identity)
            .expect("first use should succeed");
        assert!(manager.get_pairing_code(&code).is_ok());

        manager
            .use_pairing_code(&code, &peer_identity)
            .expect("last allowed use should succeed");
        assert!(manager.get_pairing_code(&code).is_err());
    }

    #[test]
    fn temporary_write_share_rejects_duration_overflow() {
        let identity = create_test_identity();
        let mut manager = PairingManager::new(identity);

        let result = manager.create_temp_write_share(ResourceScope::Any, u64::MAX);

        assert!(matches!(
            result,
            Outcome::Err(GrantError::PairingError { .. })
        ));
    }

    #[test]
    fn pairing_code_usage_counter_saturates_instead_of_wrapping() {
        let identity = create_test_identity();
        let mut actions = HashSet::new();
        actions.insert(CapabilityAction::Read);
        let mut pairing_code = PairingCode::new(
            &identity,
            actions,
            ResourceScope::Any,
            TemporalScope::expires_in(Duration::from_secs(3600)),
            ScopeConstraints::default(),
            false,
        )
        .expect("create pairing code");

        pairing_code.use_count = u64::MAX;
        pairing_code.max_uses = None;

        assert!(pairing_code.record_use());
        assert_eq!(pairing_code.use_count, u64::MAX);
    }
}
