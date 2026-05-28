//! ATP-G2 Repair symbol receiver with authentication validation.
//!
//! This module implements receiver-side validation logic for RaptorQ repair symbols
//! to ensure symbols match expected manifest, repair group parameters, and authentication
//! requirements as specified in ATP-G2.

use crate::atp::manifest::{
    AuthenticationAlgorithm, AuthenticationDomain, MerkleRoot, RaptorQSymbol, RepairGroup,
    RepairGroupId, TransformOrder,
};
use hmac::KeyInit;
use sha2::Sha256;
use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

const REPAIR_AUTH_UNSUPPORTED_OWNER_BEAD: &str = "asupersync-to7e65.6";

/// Structured authentication failure details for repair-symbol admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairAuthenticationFailure {
    /// The symbol carried no authentication tag.
    MissingTag,
    /// No active authenticated session exists for the repair group.
    NoActiveSession {
        /// Repair group that lacks an active session.
        group_id: RepairGroupId,
    },
    /// The configured authentication key is unusable.
    InvalidAuthKey,
    /// The supplied authentication tag did not verify.
    VerificationFailed {
        /// Algorithm used for verification.
        algorithm: AuthenticationAlgorithm,
        /// Authentication domain identifier.
        domain_id: String,
    },
    /// The manifest requested an algorithm this receive lane must reject.
    UnsupportedAlgorithm {
        /// Unsupported algorithm requested by the manifest.
        algorithm: AuthenticationAlgorithm,
        /// Authentication domain identifier.
        domain_id: String,
        /// Bead that owns the current fail-closed contract.
        owner_bead: &'static str,
    },
}

impl RepairAuthenticationFailure {
    /// Stable machine-readable failure code for logs and proof artifacts.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingTag => "missing_auth_tag",
            Self::NoActiveSession { .. } => "no_active_repair_auth_session",
            Self::InvalidAuthKey => "invalid_repair_auth_key",
            Self::VerificationFailed { .. } => "repair_auth_verification_failed",
            Self::UnsupportedAlgorithm { .. } => "unsupported_repair_auth_algorithm",
        }
    }

    /// Owner bead when this diagnostic intentionally represents deferred work.
    #[must_use]
    pub const fn owner_bead(&self) -> Option<&'static str> {
        match self {
            Self::UnsupportedAlgorithm { owner_bead, .. } => Some(owner_bead),
            Self::MissingTag
            | Self::NoActiveSession { .. }
            | Self::InvalidAuthKey
            | Self::VerificationFailed { .. } => None,
        }
    }
}

impl std::fmt::Display for RepairAuthenticationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTag => write!(f, "{}: missing authentication tag", self.code()),
            Self::NoActiveSession { group_id } => write!(
                f,
                "{}: no active session for repair group {group_id}",
                self.code()
            ),
            Self::InvalidAuthKey => write!(f, "{}: invalid authentication key", self.code()),
            Self::VerificationFailed {
                algorithm,
                domain_id,
            } => write!(
                f,
                "{}: {algorithm:?} verification failed for domain {domain_id}",
                self.code()
            ),
            Self::UnsupportedAlgorithm {
                algorithm,
                domain_id,
                owner_bead,
            } => write!(
                f,
                "{}: {algorithm:?} is fail-closed for repair auth domain {domain_id}; owner bead {owner_bead}",
                self.code()
            ),
        }
    }
}

/// Errors specific to repair symbol reception and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairReceiveError {
    /// Symbol belongs to unknown repair group.
    UnknownRepairGroup(RepairGroupId),
    /// Symbol parameters don't match expected repair group.
    ParameterMismatch {
        /// Field name that mismatched.
        field: String,
        /// Expected value.
        expected: String,
        /// Received value.
        received: String,
    },
    /// Authentication tag verification failed.
    AuthenticationFailed(RepairAuthenticationFailure),
    /// Symbol is replayed (already received).
    ReplayedSymbol {
        /// Symbol ESI.
        esi: u32,
        /// Previous receive timestamp.
        previous_timestamp: SystemTime,
    },
    /// Symbol session has expired.
    ExpiredSession {
        /// Session expiry time.
        expired_at: SystemTime,
        /// Current time.
        current_time: SystemTime,
    },
    /// Symbol object ID doesn't match expected.
    ObjectIdMismatch {
        /// Expected object ID.
        expected: String,
        /// Received object ID.
        received: String,
    },
    /// Manifest root doesn't match expected.
    ManifestRootMismatch {
        /// Expected manifest root.
        expected: MerkleRoot,
        /// Symbol's claimed manifest root.
        received: MerkleRoot,
    },
    /// Transform policy mismatch.
    TransformPolicyMismatch(String),
}

impl std::fmt::Display for RepairReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRepairGroup(id) => {
                write!(f, "unknown repair group: {id}")
            }
            Self::ParameterMismatch {
                field,
                expected,
                received,
            } => {
                write!(
                    f,
                    "parameter mismatch in {field}: expected {expected}, got {received}"
                )
            }
            Self::AuthenticationFailed(reason) => {
                write!(f, "authentication failed: {reason}")
            }
            Self::ReplayedSymbol {
                esi,
                previous_timestamp,
            } => {
                write!(
                    f,
                    "replayed symbol ESI {esi}, previously received at {previous_timestamp:?}"
                )
            }
            Self::ExpiredSession {
                expired_at,
                current_time,
            } => {
                write!(
                    f,
                    "session expired at {expired_at:?}, current time {current_time:?}"
                )
            }
            Self::ObjectIdMismatch { expected, received } => {
                write!(f, "object ID mismatch: expected {expected}, got {received}")
            }
            Self::ManifestRootMismatch { expected, received } => {
                write!(
                    f,
                    "manifest root mismatch: expected {expected}, got {received}"
                )
            }
            Self::TransformPolicyMismatch(msg) => {
                write!(f, "transform policy mismatch: {msg}")
            }
        }
    }
}

impl std::error::Error for RepairReceiveError {}

/// Authentication admission state for a peer offering repair symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairPeerAuthState {
    /// Peer identity and symbol authentication domain were admitted.
    Authenticated,
    /// Peer did not satisfy authentication admission.
    Unauthenticated,
}

/// Freshness state for peer advertisements and repair-symbol offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairPeerFreshness {
    /// Offer is current enough to schedule.
    Current,
    /// Offer is stale and must not be scheduled.
    Stale,
}

/// Replay state for a symbol offered by a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairSymbolState {
    /// Symbol was not already accepted for this repair session.
    New,
    /// Symbol duplicates work already accepted or in flight.
    AlreadySeen,
}

/// Deterministic reason a repair-symbol peer candidate was not selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepairPeerRejection {
    /// Peer failed authentication admission.
    Unauthenticated,
    /// Peer offer is stale.
    StalePeer,
    /// Peer has no upload budget left.
    UploadBudgetExhausted,
    /// Symbol was already seen for this repair session.
    DuplicateSymbol,
    /// Peer is advertising a different manifest root.
    ManifestMismatch,
    /// Peer is advertising a different repair group.
    RepairGroupMismatch,
    /// Peer is advertising a different source symbol count K.
    SourceSymbolsMismatch,
    /// Peer is advertising a different extended source symbol count K-prime.
    KPrimeMismatch,
    /// Peer is advertising a different transform policy.
    TransformPolicyMismatch,
    /// Peer is advertising a different authentication domain.
    AuthDomainMismatch,
    /// Peer symbol has too little expected decode contribution.
    LowDecodeUsefulness,
}

impl RepairPeerRejection {
    /// Stable machine-readable rejection reason for proof artifacts and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::StalePeer => "stale_peer",
            Self::UploadBudgetExhausted => "upload_budget_exhausted",
            Self::DuplicateSymbol => "duplicate_symbol",
            Self::ManifestMismatch => "manifest_mismatch",
            Self::RepairGroupMismatch => "repair_group_mismatch",
            Self::SourceSymbolsMismatch => "source_symbols_mismatch",
            Self::KPrimeMismatch => "k_prime_mismatch",
            Self::TransformPolicyMismatch => "transform_policy_mismatch",
            Self::AuthDomainMismatch => "auth_domain_mismatch",
            Self::LowDecodeUsefulness => "low_decode_usefulness",
        }
    }
}

/// Score vector used to rank valid repair-symbol peer candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepairPeerScore {
    /// Path quality; larger values are better.
    pub path_quality: u16,
    /// Remaining upload budget in bytes.
    pub upload_budget_bytes: u64,
    /// Rarity of the symbol in the current swarm; larger values are better.
    pub rarity: u16,
    /// Expected decode contribution; larger values are better.
    pub decode_usefulness: u16,
    /// Trust score from identity, proof history, and prior validation.
    pub trust: u16,
    /// Relay cost; smaller values are better.
    pub relay_cost: u16,
    /// Estimated churn risk; smaller values are better.
    pub churn_risk: u16,
}

impl RepairPeerScore {
    /// Deterministic ranking tuple. Higher tuples are better.
    #[must_use]
    pub fn rank_tuple(self) -> (u16, u16, u16, u16, u16, u16, u16) {
        (
            self.trust,
            self.decode_usefulness,
            self.rarity,
            self.path_quality,
            Self::upload_budget_rank(self.upload_budget_bytes),
            u16::MAX.saturating_sub(self.relay_cost),
            u16::MAX.saturating_sub(self.churn_risk),
        )
    }

    fn upload_budget_rank(upload_budget_bytes: u64) -> u16 {
        let kibibytes = upload_budget_bytes / 1024;
        u16::try_from(kibibytes).unwrap_or(u16::MAX)
    }
}

/// Peer candidate for a single repair-symbol request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPeerCandidate {
    /// Stable peer identifier used in proof artifacts.
    pub peer_id: String,
    /// Manifest root claimed by the peer.
    pub manifest_root: MerkleRoot,
    /// Repair group claimed by the peer.
    pub repair_group_id: RepairGroupId,
    /// Source symbol count K claimed by the peer.
    pub source_symbols_k: u32,
    /// Extended source symbol count K-prime claimed by the peer.
    pub k_prime: u32,
    /// Transform policy claimed by the peer.
    pub transform_policy: Option<TransformOrder>,
    /// Authentication domain claimed by the peer.
    pub auth_domain: AuthenticationDomain,
    /// Authentication admission state.
    pub auth_state: RepairPeerAuthState,
    /// Freshness admission state.
    pub freshness: RepairPeerFreshness,
    /// Replay state for this symbol.
    pub symbol_state: RepairSymbolState,
    /// Scheduling score vector.
    pub score: RepairPeerScore,
}

/// Deterministic repair-peer scheduling decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairPeerSelection {
    /// Selected peer, if any candidate survived admission.
    pub selected_peer_id: Option<String>,
    /// Score vector for the selected peer.
    pub selected_score: Option<RepairPeerScore>,
    /// Rejected peers and stable reasons.
    pub rejected_peers: BTreeMap<String, RepairPeerRejection>,
}

/// Select one peer for a repair-symbol request after enforcing ATP-G4 domains.
#[must_use]
pub fn select_repair_symbol_peer(
    repair_group: &RepairGroup,
    candidates: &[RepairPeerCandidate],
    min_decode_usefulness: u16,
) -> RepairPeerSelection {
    let mut selected: Option<&RepairPeerCandidate> = None;
    let mut rejected_peers = BTreeMap::new();

    for candidate in candidates {
        if let Some(rejection) =
            repair_peer_rejection(candidate, repair_group, min_decode_usefulness)
        {
            rejected_peers.insert(candidate.peer_id.clone(), rejection);
            continue;
        }

        let should_replace = match selected {
            Some(current) => compare_repair_peer_candidates(candidate, current).is_gt(),
            None => true,
        };

        if should_replace {
            selected = Some(candidate);
        }
    }

    RepairPeerSelection {
        selected_peer_id: selected.map(|candidate| candidate.peer_id.clone()),
        selected_score: selected.map(|candidate| candidate.score),
        rejected_peers,
    }
}

fn repair_peer_rejection(
    candidate: &RepairPeerCandidate,
    repair_group: &RepairGroup,
    min_decode_usefulness: u16,
) -> Option<RepairPeerRejection> {
    if candidate.auth_state == RepairPeerAuthState::Unauthenticated {
        return Some(RepairPeerRejection::Unauthenticated);
    }

    if candidate.freshness == RepairPeerFreshness::Stale {
        return Some(RepairPeerRejection::StalePeer);
    }

    if candidate.score.upload_budget_bytes == 0 {
        return Some(RepairPeerRejection::UploadBudgetExhausted);
    }

    if candidate.symbol_state == RepairSymbolState::AlreadySeen {
        return Some(RepairPeerRejection::DuplicateSymbol);
    }

    if candidate.manifest_root != repair_group.manifest_root {
        return Some(RepairPeerRejection::ManifestMismatch);
    }

    if candidate.repair_group_id != repair_group.group_id {
        return Some(RepairPeerRejection::RepairGroupMismatch);
    }

    if candidate.source_symbols_k != repair_group.source_symbols_k {
        return Some(RepairPeerRejection::SourceSymbolsMismatch);
    }

    if candidate.k_prime != repair_group.k_prime {
        return Some(RepairPeerRejection::KPrimeMismatch);
    }

    if candidate.transform_policy != repair_group.transform_policy {
        return Some(RepairPeerRejection::TransformPolicyMismatch);
    }

    if candidate.auth_domain != repair_group.auth_domain {
        return Some(RepairPeerRejection::AuthDomainMismatch);
    }

    if candidate.score.decode_usefulness < min_decode_usefulness {
        return Some(RepairPeerRejection::LowDecodeUsefulness);
    }

    None
}

fn compare_repair_peer_candidates(
    left: &RepairPeerCandidate,
    right: &RepairPeerCandidate,
) -> std::cmp::Ordering {
    left.score
        .rank_tuple()
        .cmp(&right.score.rank_tuple())
        .then_with(|| right.peer_id.cmp(&left.peer_id))
}

/// Session context for tracking received symbols and preventing replay attacks.
#[derive(Debug, Clone)]
pub struct RepairSessionContext {
    /// Repair group this session belongs to.
    pub repair_group_id: RepairGroupId,
    /// Session start time.
    pub start_time: SystemTime,
    /// Session expiry time.
    pub expiry_time: SystemTime,
    /// Set of received symbol ESIs to prevent replay.
    pub received_esis: std::collections::BTreeSet<u32>,
    /// Authentication key for HMAC verification.
    pub auth_key: Vec<u8>,
    /// Session binding context.
    pub session_binding: Option<Vec<u8>>,
}

impl RepairSessionContext {
    /// Create a new session context.
    pub fn new(
        repair_group_id: RepairGroupId,
        session_duration: Duration,
        auth_key: Vec<u8>,
        session_binding: Option<Vec<u8>>,
    ) -> Self {
        let start_time = SystemTime::now();
        let expiry_time = start_time + session_duration;

        Self {
            repair_group_id,
            start_time,
            expiry_time,
            received_esis: std::collections::BTreeSet::new(),
            auth_key,
            session_binding,
        }
    }

    /// Check if this session has expired.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expiry_time
    }

    /// Mark a symbol ESI as received.
    pub fn mark_received(&mut self, esi: u32) -> bool {
        self.received_esis.insert(esi)
    }

    /// Check if a symbol ESI was already received.
    pub fn was_received(&self, esi: u32) -> Option<SystemTime> {
        if self.received_esis.contains(&esi) {
            // Return approximate receive time (we don't track exact timestamps per ESI)
            Some(self.start_time)
        } else {
            None
        }
    }
}

/// ATP-G2 repair symbol receiver with comprehensive validation.
#[derive(Debug)]
pub struct RepairReceiver {
    /// Expected manifest root for validation.
    expected_manifest_root: MerkleRoot,
    /// Repair group configurations.
    repair_groups: std::collections::BTreeMap<RepairGroupId, RepairGroup>,
    /// Active sessions for replay protection.
    sessions: std::collections::BTreeMap<RepairGroupId, RepairSessionContext>,
}

impl RepairReceiver {
    /// Create a new repair receiver.
    pub fn new(
        expected_manifest_root: MerkleRoot,
        repair_groups: std::collections::BTreeMap<RepairGroupId, RepairGroup>,
    ) -> Self {
        Self {
            expected_manifest_root,
            repair_groups,
            sessions: std::collections::BTreeMap::new(),
        }
    }

    /// Start a new session for a repair group.
    pub fn start_session(
        &mut self,
        repair_group_id: RepairGroupId,
        session_duration: Duration,
        auth_key: Vec<u8>,
        session_binding: Option<Vec<u8>>,
    ) -> Result<(), RepairReceiveError> {
        // Verify repair group exists
        if !self.repair_groups.contains_key(&repair_group_id) {
            return Err(RepairReceiveError::UnknownRepairGroup(repair_group_id));
        }

        let session = RepairSessionContext::new(
            repair_group_id.clone(),
            session_duration,
            auth_key,
            session_binding,
        );

        self.sessions.insert(repair_group_id, session);
        Ok(())
    }

    /// Validate and accept a repair symbol with comprehensive ATP-G2 checks.
    pub fn validate_repair_symbol(
        &mut self,
        symbol: &RaptorQSymbol,
        claimed_manifest_root: &MerkleRoot,
        claimed_object_id: &str,
    ) -> Result<(), RepairReceiveError> {
        // Extract repair group ID from symbol
        let group_id = symbol.repair_group_id.as_ref().ok_or_else(|| {
            RepairReceiveError::ParameterMismatch {
                field: "repair_group_id".to_string(),
                expected: "Some(group_id)".to_string(),
                received: "None".to_string(),
            }
        })?;

        // Verify repair group exists
        let repair_group = self
            .repair_groups
            .get(group_id)
            .ok_or_else(|| RepairReceiveError::UnknownRepairGroup(group_id.clone()))?;

        // Validate manifest root
        if *claimed_manifest_root != self.expected_manifest_root {
            return Err(RepairReceiveError::ManifestRootMismatch {
                expected: self.expected_manifest_root.clone(),
                received: claimed_manifest_root.clone(),
            });
        }

        // Validate object ID
        if claimed_object_id != repair_group.object_id.to_string() {
            return Err(RepairReceiveError::ObjectIdMismatch {
                expected: repair_group.object_id.to_string(),
                received: claimed_object_id.to_string(),
            });
        }

        // Validate symbol parameters against repair group
        self.validate_symbol_parameters(symbol, repair_group)?;

        // Check session and replay protection before authentication, but only
        // commit the ESI after the tag verifies.
        let session = self.sessions.get(group_id).ok_or_else(|| {
            RepairReceiveError::AuthenticationFailed(RepairAuthenticationFailure::NoActiveSession {
                group_id: group_id.clone(),
            })
        })?;
        Self::validate_session_and_replay_static(symbol, session)?;

        // Validate authentication tag
        self.validate_authentication(symbol, repair_group)?;

        let session = self.sessions.get_mut(group_id).ok_or_else(|| {
            RepairReceiveError::AuthenticationFailed(RepairAuthenticationFailure::NoActiveSession {
                group_id: group_id.clone(),
            })
        })?;
        if let Some(previous_timestamp) = session.was_received(symbol.esi) {
            return Err(RepairReceiveError::ReplayedSymbol {
                esi: symbol.esi,
                previous_timestamp,
            });
        }
        session.mark_received(symbol.esi);

        Ok(())
    }

    /// Validate symbol parameters match repair group configuration.
    fn validate_symbol_parameters(
        &self,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
    ) -> Result<(), RepairReceiveError> {
        // Validate ESI is within valid range for this repair group
        let max_esi =
            repair_group.source_symbols_k + repair_group.repair_layout.total_repair_symbols;
        if symbol.esi >= max_esi {
            return Err(RepairReceiveError::ParameterMismatch {
                field: "esi".to_string(),
                expected: format!("< {max_esi}"),
                received: symbol.esi.to_string(),
            });
        }

        // Validate symbol size
        if symbol.size_bytes != repair_group.symbol_size {
            return Err(RepairReceiveError::ParameterMismatch {
                field: "size_bytes".to_string(),
                expected: repair_group.symbol_size.to_string(),
                received: symbol.size_bytes.to_string(),
            });
        }

        // Validate source/repair symbol classification
        let is_source_expected = symbol.esi < repair_group.source_symbols_k;
        if symbol.is_source != is_source_expected {
            return Err(RepairReceiveError::ParameterMismatch {
                field: "is_source".to_string(),
                expected: is_source_expected.to_string(),
                received: symbol.is_source.to_string(),
            });
        }

        Ok(())
    }

    /// Validate session status and check for replay attacks.
    fn validate_session_and_replay_static(
        symbol: &RaptorQSymbol,
        session: &RepairSessionContext,
    ) -> Result<(), RepairReceiveError> {
        let current_time = SystemTime::now(); // ubs:ignore - time check, not crypto randomness // ubs:ignore

        // Check session expiry
        if current_time > session.expiry_time {
            return Err(RepairReceiveError::ExpiredSession {
                expired_at: session.expiry_time,
                current_time,
            });
        }

        // Check for replay
        if let Some(previous_timestamp) = session.was_received(symbol.esi) {
            return Err(RepairReceiveError::ReplayedSymbol {
                esi: symbol.esi,
                previous_timestamp,
            });
        }

        Ok(())
    }

    /// Validate authentication tag.
    fn validate_authentication(
        &self,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
    ) -> Result<(), RepairReceiveError> {
        let auth_tag = symbol.auth_tag.as_ref().ok_or({
            RepairReceiveError::AuthenticationFailed(RepairAuthenticationFailure::MissingTag)
        })?;

        // Get session for auth key
        let session = self.sessions.get(&repair_group.group_id).ok_or_else(|| {
            RepairReceiveError::AuthenticationFailed(RepairAuthenticationFailure::NoActiveSession {
                group_id: repair_group.group_id.clone(),
            })
        })?;

        match repair_group.auth_domain.auth_algorithm {
            AuthenticationAlgorithm::HmacSha256 => {
                let expected_tag = self.compute_hmac_sha256_tag(symbol, repair_group, session)?;
                let tags_match: bool =
                    subtle::ConstantTimeEq::ct_eq(&auth_tag[..], &expected_tag[..]).into();
                if !tags_match {
                    return Err(RepairReceiveError::AuthenticationFailed(
                        RepairAuthenticationFailure::VerificationFailed {
                            algorithm: AuthenticationAlgorithm::HmacSha256,
                            domain_id: repair_group.auth_domain.domain_id.clone(),
                        },
                    ));
                }
            }
            AuthenticationAlgorithm::EdDsa | AuthenticationAlgorithm::X25519Ecdh => {
                return Err(RepairReceiveError::AuthenticationFailed(
                    RepairAuthenticationFailure::UnsupportedAlgorithm {
                        algorithm: repair_group.auth_domain.auth_algorithm,
                        domain_id: repair_group.auth_domain.domain_id.clone(),
                        owner_bead: REPAIR_AUTH_UNSUPPORTED_OWNER_BEAD,
                    },
                ));
            }
        }

        Ok(())
    }

    /// Compute HMAC-SHA256 authentication tag for a symbol.
    fn compute_hmac_sha256_tag(
        &self,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
        session: &RepairSessionContext,
    ) -> Result<[u8; 32], RepairReceiveError> {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&session.auth_key).map_err(|_| {
            RepairReceiveError::AuthenticationFailed(RepairAuthenticationFailure::InvalidAuthKey)
        })?;

        // Include all critical symbol and group parameters in the MAC
        mac.update(b"ATP-G2-RepairSymbol");
        mac.update(repair_group.group_id.as_bytes());
        mac.update(repair_group.manifest_root.hash());
        mac.update(repair_group.object_id.hash_bytes());
        mac.update(&repair_group.source_block_number.to_be_bytes());
        mac.update(&repair_group.source_symbols_k.to_be_bytes());
        mac.update(&repair_group.k_prime.to_be_bytes());
        mac.update(&symbol.esi.to_be_bytes());
        mac.update(&symbol.size_bytes.to_be_bytes());
        mac.update(&symbol.content_hash);
        mac.update(&[u8::from(symbol.is_source)]);

        // Include session binding if present
        if let Some(binding) = &session.session_binding {
            mac.update(b"session_binding:");
            mac.update(binding);
        }

        let result = mac.finalize().into_bytes();
        Ok(result.into())
    }

    /// Clean up expired sessions.
    pub fn cleanup_expired_sessions(&mut self) {
        let current_time = SystemTime::now(); // ubs:ignore - time check, not crypto randomness // ubs:ignore
        self.sessions
            .retain(|_, session| current_time <= session.expiry_time);
    }

    /// Get statistics about active sessions.
    pub fn session_stats(&self) -> (usize, usize) {
        let active_sessions = self.sessions.len();
        let total_received_symbols: usize = self
            .sessions
            .values()
            .map(|session| session.received_esis.len())
            .sum();
        (active_sessions, total_received_symbols)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atp::manifest::*;
    use crate::atp::object::{ContentId, ObjectId};
    use std::collections::BTreeMap;
    use std::time::Duration;

    fn test_object_id(content: &[u8]) -> ObjectId {
        ObjectId::content(ContentId::from_bytes(content))
    }

    fn create_test_repair_group() -> (RepairGroupId, RepairGroup) {
        let object_id = test_object_id(&[1, 2, 3, 4]);
        let group_id = RepairGroupId::new(&object_id, 0, 1024);

        let repair_group = RepairGroup {
            group_id: group_id.clone(),
            object_id,
            source_block_number: 0,
            chunk_range: ChunkRange {
                start_chunk: 0,
                end_chunk: 1,
                start_offset: 0,
                end_offset: 1024,
            },
            source_symbols_k: 1000,
            k_prime: 1024,
            symbol_size: 1024,
            repair_layout: RepairLayout {
                total_repair_symbols: 200,
                overhead_ratio: 0.2,
                systematic_config: SystematicConfig {
                    systematic_rows: 1000,
                    sub_symbols: 1,
                    alignment: 8,
                },
                interleaving: InterleavingPattern {
                    block_size: 1,
                    depth: 1,
                    pattern_type: InterleavingType::None,
                },
            },
            hash_domain: HashDomain {
                domain_id: "test".to_string(),
                hash_algorithm: HashAlgorithm::Sha256,
                context: vec![],
            },
            transform_policy: None,
            auth_domain: AuthenticationDomain {
                domain_id: "test-auth".to_string(),
                required_proof_strength: ProofStrength::Basic,
                auth_algorithm: AuthenticationAlgorithm::HmacSha256,
                peer_identity_required: false,
                transfer_identity_binding: false,
                session_binding: true,
            },
            capability_policy: None,
            manifest_root: MerkleRoot::new([0u8; 32]),
        };

        (group_id, repair_group)
    }

    fn baseline_repair_peer_score() -> RepairPeerScore {
        RepairPeerScore {
            path_quality: 80,
            upload_budget_bytes: 256 * 1024,
            rarity: 16,
            decode_usefulness: 80,
            trust: 80,
            relay_cost: 8,
            churn_risk: 4,
        }
    }

    fn baseline_repair_peer_candidate(
        peer_id: impl Into<String>,
        repair_group: &RepairGroup,
        score: RepairPeerScore,
    ) -> RepairPeerCandidate {
        RepairPeerCandidate {
            peer_id: peer_id.into(),
            manifest_root: repair_group.manifest_root.clone(),
            repair_group_id: repair_group.group_id.clone(),
            source_symbols_k: repair_group.source_symbols_k,
            k_prime: repair_group.k_prime,
            transform_policy: repair_group.transform_policy.clone(),
            auth_domain: repair_group.auth_domain.clone(),
            auth_state: RepairPeerAuthState::Authenticated,
            freshness: RepairPeerFreshness::Current,
            symbol_state: RepairSymbolState::New,
            score,
        }
    }

    fn mismatched_transform_policy() -> TransformOrder {
        TransformOrder {
            transforms: vec![TransformType::Encryption],
            hash_point: HashPoint::Ciphertext,
            verification_boundary: VerificationBoundary {
                relay_verifiable: VerificationLevel::TransferIntegrity,
                mailbox_verifiable: VerificationLevel::TransferIntegrity,
                e2e_verification_required: true,
                privacy_level: PrivacyLevel::FullPrivacy,
            },
        }
    }

    fn build_receiver(
        repair_group: RepairGroup,
    ) -> (RepairGroupId, MerkleRoot, ObjectId, RepairReceiver) {
        let group_id = repair_group.group_id.clone();
        let manifest_root = repair_group.manifest_root.clone();
        let object_id = repair_group.object_id.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        (
            group_id,
            manifest_root.clone(),
            object_id,
            RepairReceiver::new(manifest_root, repair_groups),
        )
    }

    fn source_symbol_for_group(group_id: &RepairGroupId) -> RaptorQSymbol {
        RaptorQSymbol {
            index: 0,
            esi: 500,
            size_bytes: 1024,
            content_hash: [7u8; 32],
            is_source: true,
            repair_group_id: Some(group_id.clone()),
            auth_tag: None,
        }
    }

    fn hmac_tag_for(
        receiver: &RepairReceiver,
        symbol: &RaptorQSymbol,
        repair_group: &RepairGroup,
        auth_key: &[u8],
        session_binding: Option<Vec<u8>>,
    ) -> [u8; 32] {
        let session = RepairSessionContext::new(
            repair_group.group_id.clone(),
            Duration::from_secs(3600),
            auth_key.to_vec(),
            session_binding,
        );
        receiver
            .compute_hmac_sha256_tag(symbol, repair_group, &session)
            .expect("test key should produce an HMAC tag")
    }

    fn start_receiver_session(
        receiver: &mut RepairReceiver,
        group_id: &RepairGroupId,
        auth_key: &[u8],
        session_binding: Option<Vec<u8>>,
    ) {
        receiver
            .start_session(
                group_id.clone(),
                Duration::from_secs(3600),
                auth_key.to_vec(),
                session_binding,
            )
            .expect("test repair group should accept a session");
    }

    #[test]
    fn test_select_repair_symbol_peer_scores_and_tie_breaks() {
        let (_, repair_group) = create_test_repair_group();
        let high_score = RepairPeerScore {
            trust: 95,
            decode_usefulness: 90,
            rarity: 20,
            path_quality: 90,
            upload_budget_bytes: 512 * 1024,
            relay_cost: 2,
            churn_risk: 1,
        };
        let low_score = RepairPeerScore {
            trust: 90,
            decode_usefulness: 90,
            rarity: 20,
            path_quality: 90,
            upload_budget_bytes: 512 * 1024,
            relay_cost: 2,
            churn_risk: 1,
        };
        let candidates = vec![
            baseline_repair_peer_candidate("seed-z", &repair_group, low_score),
            baseline_repair_peer_candidate("seed-b", &repair_group, high_score),
            baseline_repair_peer_candidate("seed-a", &repair_group, high_score),
        ];

        let selection = select_repair_symbol_peer(&repair_group, &candidates, 10);

        assert_eq!(selection.selected_peer_id.as_deref(), Some("seed-a"));
        assert_eq!(selection.selected_score, Some(high_score));
        assert!(selection.rejected_peers.is_empty());
    }

    #[test]
    fn test_select_repair_symbol_peer_rejects_cross_domain_candidates() {
        let (_, repair_group) = create_test_repair_group();
        let mut wrong_auth_domain = repair_group.auth_domain.clone();
        wrong_auth_domain.domain_id = "other-auth-domain".to_string();

        let mut candidates = Vec::new();
        candidates.push(baseline_repair_peer_candidate(
            "valid",
            &repair_group,
            baseline_repair_peer_score(),
        ));

        let mut unauthenticated = baseline_repair_peer_candidate(
            "unauthenticated",
            &repair_group,
            baseline_repair_peer_score(),
        );
        unauthenticated.auth_state = RepairPeerAuthState::Unauthenticated;
        candidates.push(unauthenticated);

        let mut stale =
            baseline_repair_peer_candidate("stale", &repair_group, baseline_repair_peer_score());
        stale.freshness = RepairPeerFreshness::Stale;
        candidates.push(stale);

        let mut no_budget = baseline_repair_peer_candidate(
            "no-budget",
            &repair_group,
            baseline_repair_peer_score(),
        );
        no_budget.score.upload_budget_bytes = 0;
        candidates.push(no_budget);

        let mut duplicate = baseline_repair_peer_candidate(
            "duplicate",
            &repair_group,
            baseline_repair_peer_score(),
        );
        duplicate.symbol_state = RepairSymbolState::AlreadySeen;
        candidates.push(duplicate);

        let mut wrong_manifest = baseline_repair_peer_candidate(
            "wrong-manifest",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_manifest.manifest_root = MerkleRoot::new([1u8; 32]);
        candidates.push(wrong_manifest);

        let mut wrong_group = baseline_repair_peer_candidate(
            "wrong-group",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_group.repair_group_id = RepairGroupId::new(&test_object_id(&[9, 9, 9, 9]), 9, 1024);
        candidates.push(wrong_group);

        let mut wrong_k =
            baseline_repair_peer_candidate("wrong-k", &repair_group, baseline_repair_peer_score());
        wrong_k.source_symbols_k -= 1;
        candidates.push(wrong_k);

        let mut wrong_k_prime = baseline_repair_peer_candidate(
            "wrong-k-prime",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_k_prime.k_prime += 1;
        candidates.push(wrong_k_prime);

        let mut wrong_transform = baseline_repair_peer_candidate(
            "wrong-transform",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_transform.transform_policy = Some(mismatched_transform_policy());
        candidates.push(wrong_transform);

        let mut wrong_auth = baseline_repair_peer_candidate(
            "wrong-auth",
            &repair_group,
            baseline_repair_peer_score(),
        );
        wrong_auth.auth_domain = wrong_auth_domain;
        candidates.push(wrong_auth);

        let mut low_decode = baseline_repair_peer_candidate(
            "low-decode",
            &repair_group,
            baseline_repair_peer_score(),
        );
        low_decode.score.decode_usefulness = 2;
        candidates.push(low_decode);

        let selection = select_repair_symbol_peer(&repair_group, &candidates, 10);

        assert_eq!(selection.selected_peer_id.as_deref(), Some("valid"));
        assert_eq!(
            selection.rejected_peers.get("unauthenticated"),
            Some(&RepairPeerRejection::Unauthenticated)
        );
        assert_eq!(
            selection.rejected_peers.get("stale"),
            Some(&RepairPeerRejection::StalePeer)
        );
        assert_eq!(
            selection.rejected_peers.get("no-budget"),
            Some(&RepairPeerRejection::UploadBudgetExhausted)
        );
        assert_eq!(
            selection.rejected_peers.get("duplicate"),
            Some(&RepairPeerRejection::DuplicateSymbol)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-manifest"),
            Some(&RepairPeerRejection::ManifestMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-group"),
            Some(&RepairPeerRejection::RepairGroupMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-k"),
            Some(&RepairPeerRejection::SourceSymbolsMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-k-prime"),
            Some(&RepairPeerRejection::KPrimeMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-transform"),
            Some(&RepairPeerRejection::TransformPolicyMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("wrong-auth"),
            Some(&RepairPeerRejection::AuthDomainMismatch)
        );
        assert_eq!(
            selection.rejected_peers.get("low-decode"),
            Some(&RepairPeerRejection::LowDecodeUsefulness)
        );
        assert_eq!(
            RepairPeerRejection::SourceSymbolsMismatch.as_str(),
            "source_symbols_mismatch"
        );
    }

    #[test]
    fn test_hmac_authenticated_symbol_is_accepted_and_recorded() {
        let (_, repair_group) = create_test_repair_group();
        let (group_id, manifest_root, object_id, mut receiver) =
            build_receiver(repair_group.clone());
        let auth_key = b"receiver-auth-key";
        let session_binding = Some(b"peer-a-session".to_vec());

        start_receiver_session(&mut receiver, &group_id, auth_key, session_binding.clone());
        let mut symbol = source_symbol_for_group(&group_id);
        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            auth_key,
            session_binding,
        ));

        let result =
            receiver.validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string());

        assert_eq!(result, Ok(()));
        assert!(
            receiver
                .sessions
                .get(&group_id)
                .and_then(|session| session.was_received(symbol.esi))
                .is_some()
        );
    }

    #[test]
    fn test_missing_auth_tag_is_structured_and_does_not_poison_replay() {
        let (_, repair_group) = create_test_repair_group();
        let (group_id, manifest_root, object_id, mut receiver) =
            build_receiver(repair_group.clone());
        let auth_key = b"receiver-auth-key";
        let session_binding = Some(b"peer-a-session".to_vec());

        start_receiver_session(&mut receiver, &group_id, auth_key, session_binding.clone());
        let mut symbol = source_symbol_for_group(&group_id);

        let error = receiver
            .validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string())
            .expect_err("missing tag must fail closed");

        match error {
            RepairReceiveError::AuthenticationFailed(reason) => {
                assert_eq!(reason, RepairAuthenticationFailure::MissingTag);
                assert_eq!(reason.code(), "missing_auth_tag");
                assert_eq!(reason.owner_bead(), None);
            }
            other => panic!("expected missing auth tag, got {other:?}"),
        }
        assert!(
            receiver
                .sessions
                .get(&group_id)
                .and_then(|session| session.was_received(symbol.esi))
                .is_none()
        );

        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            auth_key,
            session_binding,
        ));
        assert_eq!(
            receiver.validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string()),
            Ok(())
        );
    }

    #[test]
    fn test_wrong_key_and_cross_peer_hmac_are_rejected_without_replay_poisoning() {
        let (_, repair_group) = create_test_repair_group();
        let (group_id, manifest_root, object_id, mut receiver) =
            build_receiver(repair_group.clone());
        let auth_key = b"receiver-auth-key";
        let session_binding = Some(b"peer-a-session".to_vec());

        start_receiver_session(&mut receiver, &group_id, auth_key, session_binding.clone());
        let mut symbol = source_symbol_for_group(&group_id);
        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            b"other-peer-key",
            Some(b"peer-b-session".to_vec()),
        ));

        let error = receiver
            .validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string())
            .expect_err("wrong key and peer binding must fail closed");

        match error {
            RepairReceiveError::AuthenticationFailed(
                RepairAuthenticationFailure::VerificationFailed {
                    algorithm,
                    domain_id,
                },
            ) => {
                assert_eq!(algorithm, AuthenticationAlgorithm::HmacSha256);
                assert_eq!(domain_id, "test-auth");
            }
            other => panic!("expected HMAC verification failure, got {other:?}"),
        }
        assert!(
            receiver
                .sessions
                .get(&group_id)
                .and_then(|session| session.was_received(symbol.esi))
                .is_none()
        );

        symbol.auth_tag = Some(hmac_tag_for(
            &receiver,
            &symbol,
            &repair_group,
            auth_key,
            session_binding,
        ));
        assert_eq!(
            receiver.validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string()),
            Ok(())
        );
    }

    #[test]
    fn test_eddsa_and_x25519_are_typed_fail_closed_with_owner_bead() {
        for algorithm in [
            AuthenticationAlgorithm::EdDsa,
            AuthenticationAlgorithm::X25519Ecdh,
        ] {
            let (_, mut repair_group) = create_test_repair_group();
            repair_group.auth_domain.auth_algorithm = algorithm;
            repair_group.auth_domain.peer_identity_required = true;
            repair_group.auth_domain.transfer_identity_binding = true;

            let (group_id, manifest_root, object_id, mut receiver) =
                build_receiver(repair_group.clone());
            start_receiver_session(
                &mut receiver,
                &group_id,
                b"receiver-auth-key",
                Some(b"peer-a-session".to_vec()),
            );

            let mut symbol = source_symbol_for_group(&group_id);
            symbol.auth_tag = Some([9u8; 32]);

            let error = receiver
                .validate_repair_symbol(&symbol, &manifest_root, &object_id.to_string())
                .expect_err("unsupported repair auth algorithms must fail closed");

            match error {
                RepairReceiveError::AuthenticationFailed(
                    RepairAuthenticationFailure::UnsupportedAlgorithm {
                        algorithm: observed_algorithm,
                        domain_id,
                        owner_bead,
                    },
                ) => {
                    assert_eq!(observed_algorithm, algorithm);
                    assert_eq!(domain_id, "test-auth");
                    assert_eq!(owner_bead, REPAIR_AUTH_UNSUPPORTED_OWNER_BEAD);
                    let reason = RepairAuthenticationFailure::UnsupportedAlgorithm {
                        algorithm: observed_algorithm,
                        domain_id,
                        owner_bead,
                    };
                    assert_eq!(reason.code(), "unsupported_repair_auth_algorithm");
                    assert_eq!(reason.owner_bead(), Some("asupersync-to7e65.6"));
                    assert!(reason.to_string().contains("fail-closed"));
                }
                other => panic!("expected typed unsupported algorithm, got {other:?}"),
            }
            assert!(
                receiver
                    .sessions
                    .get(&group_id)
                    .and_then(|session| session.was_received(symbol.esi))
                    .is_none()
            );
        }
    }

    #[test]
    fn test_session_creation() {
        let (group_id, repair_group) = create_test_repair_group();
        let manifest_root = repair_group.manifest_root.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        let mut receiver = RepairReceiver::new(manifest_root, repair_groups);

        // Should succeed
        let result = receiver.start_session(
            group_id.clone(),
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            Some(b"test_session".to_vec()),
        );
        assert!(result.is_ok());

        // Should fail for unknown group
        let unknown_group = RepairGroupId::new(&test_object_id(&[5, 6, 7, 8]), 1, 512);
        let result = receiver.start_session(
            unknown_group,
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            None,
        );
        assert!(matches!(
            result,
            Err(RepairReceiveError::UnknownRepairGroup(_))
        ));
    }

    #[test]
    fn test_symbol_parameter_validation() {
        let (group_id, repair_group) = create_test_repair_group();
        let manifest_root = repair_group.manifest_root.clone();

        let mut repair_groups = BTreeMap::new();
        repair_groups.insert(group_id.clone(), repair_group);

        let receiver = RepairReceiver::new(manifest_root.clone(), repair_groups);

        // Valid symbol
        let valid_symbol = RaptorQSymbol {
            index: 0,
            esi: 500,
            size_bytes: 1024,
            content_hash: [0u8; 32],
            is_source: true,
            repair_group_id: Some(group_id.clone()),
            auth_tag: Some([0u8; 32]),
        };

        // Should pass parameter validation (ignoring session/auth for this test)
        let result =
            receiver.validate_symbol_parameters(&valid_symbol, &receiver.repair_groups[&group_id]);
        assert!(result.is_ok());

        // Invalid ESI (too high)
        let invalid_esi_symbol = RaptorQSymbol {
            esi: 2000, // > k + total_repair_symbols
            ..valid_symbol.clone()
        };

        let result = receiver
            .validate_symbol_parameters(&invalid_esi_symbol, &receiver.repair_groups[&group_id]);
        assert!(
            matches!(result, Err(RepairReceiveError::ParameterMismatch { field, .. }) if field == "esi") // ubs:ignore - error field name comparison
        );

        // Invalid size
        let invalid_size_symbol = RaptorQSymbol {
            size_bytes: 512, // Should be 1024
            ..valid_symbol.clone()
        };

        let result = receiver
            .validate_symbol_parameters(&invalid_size_symbol, &receiver.repair_groups[&group_id]);
        assert!(
            matches!(result, Err(RepairReceiveError::ParameterMismatch { field, .. }) if field == "size_bytes") // ubs:ignore
        );
    }

    #[test]
    fn test_replay_detection() {
        let (group_id, _repair_group) = create_test_repair_group();

        let mut session = RepairSessionContext::new(
            group_id.clone(),
            Duration::from_secs(3600),
            vec![1, 2, 3, 4],
            None,
        );

        // First symbol should be accepted
        assert!(session.mark_received(100));

        // Same ESI should be detected as replay
        assert!(!session.mark_received(100));
        assert!(session.was_received(100).is_some());

        // Different ESI should be accepted
        assert!(session.mark_received(101));
    }

    #[test]
    fn test_session_expiry() {
        let (group_id, _) = create_test_repair_group();

        // Create session with very short duration
        let session =
            RepairSessionContext::new(group_id, Duration::from_millis(1), vec![1, 2, 3, 4], None);

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(10));

        assert!(session.is_expired());
    }
}
