//! Rendezvous exchange model for ATP candidate sharing.

use crate::net::atp::stun::{EndpointObservation, ObservedEndpoint};
use std::collections::{BTreeMap, BTreeSet};

/// ATP peer identity used by rendezvous candidate exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId([u8; 32]);

impl PeerId {
    /// Construct a peer id from canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedPeerId`] when all bytes are zero.
    pub fn new(bytes: [u8; 32]) -> Result<Self, Error> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(Error::MalformedPeerId);
        }
        Ok(Self(bytes))
    }

    /// Return canonical peer id bytes.
    #[must_use]
    pub const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Transfer-scoped nonce for one rendezvous session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransferNonce(u128);

impl TransferNonce {
    /// Construct a non-zero transfer nonce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNonce`] when `raw` is zero.
    pub const fn new(raw: u128) -> Result<Self, Error> {
        if raw == 0 {
            return Err(Error::ZeroNonce);
        }
        Ok(Self(raw))
    }

    /// Return the raw nonce value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// Candidate-scoped nonce used for replay protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateNonce(u128);

impl CandidateNonce {
    /// Construct a non-zero candidate nonce.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ZeroNonce`] when `raw` is zero.
    pub const fn new(raw: u128) -> Result<Self, Error> {
        if raw == 0 {
            return Err(Error::ZeroNonce);
        }
        Ok(Self(raw))
    }

    /// Return the raw nonce value.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// Candidate transport advertised through rendezvous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateTransport {
    /// Direct UDP candidate.
    Udp,
    /// Relay candidate.
    Relay,
    /// IPv6 direct candidate.
    Ipv6,
}

/// Redaction-safe capability context bound into signed candidate exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityContext {
    label: String,
    max_candidate_ttl_micros: u64,
    relay_allowed: bool,
    ipv6_direct_allowed: bool,
}

impl CapabilityContext {
    /// Construct a capability context identifier and transport policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyCapabilityContext`] for blank labels and
    /// [`Error::InvalidCapabilityContext`] when the TTL bound is zero.
    pub fn new(
        label: impl Into<String>,
        max_candidate_ttl_micros: u64,
        relay_allowed: bool,
        ipv6_direct_allowed: bool,
    ) -> Result<Self, Error> {
        let label = label.into();
        if label.trim().is_empty() {
            return Err(Error::EmptyCapabilityContext);
        }
        if max_candidate_ttl_micros == 0 {
            return Err(Error::InvalidCapabilityContext);
        }

        Ok(Self {
            label,
            max_candidate_ttl_micros,
            relay_allowed,
            ipv6_direct_allowed,
        })
    }

    /// Stable context label for path logs.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Maximum candidate TTL accepted under this context.
    #[must_use]
    pub const fn max_candidate_ttl_micros(&self) -> u64 {
        self.max_candidate_ttl_micros
    }

    /// Whether relay candidates are authorized by this context.
    #[must_use]
    pub const fn relay_allowed(&self) -> bool {
        self.relay_allowed
    }

    /// Whether IPv6 direct candidates are authorized by this context.
    #[must_use]
    pub const fn ipv6_direct_allowed(&self) -> bool {
        self.ipv6_direct_allowed
    }
}

impl Default for CapabilityContext {
    fn default() -> Self {
        Self {
            label: "default-atp-rendezvous".to_owned(),
            max_candidate_ttl_micros: 60_000_000,
            relay_allowed: true,
            ipv6_direct_allowed: true,
        }
    }
}

/// Path candidate advertised to peers through rendezvous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    endpoint: ObservedEndpoint,
    transport: CandidateTransport,
    expires_at_micros: u64,
    relay_authorization: Option<RelayAuthorization>,
}

impl Candidate {
    /// Build a candidate endpoint.
    #[must_use]
    pub fn new(
        endpoint: ObservedEndpoint,
        transport: CandidateTransport,
        expires_at_micros: u64,
    ) -> Self {
        Self {
            endpoint,
            transport,
            expires_at_micros,
            relay_authorization: None,
        }
    }

    /// Advertised endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &ObservedEndpoint {
        &self.endpoint
    }

    /// Transport for the candidate.
    #[must_use]
    pub const fn transport(&self) -> CandidateTransport {
        self.transport
    }

    /// Expiry timestamp.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    /// Attach relay authorization to a relay candidate.
    #[must_use]
    pub fn with_relay_authorization(mut self, authorization: RelayAuthorization) -> Self {
        self.relay_authorization = Some(authorization);
        self
    }

    /// Relay authorization bound to this candidate, if any.
    #[must_use]
    pub fn relay_authorization(&self) -> Option<&RelayAuthorization> {
        self.relay_authorization.as_ref()
    }
}

/// Opaque candidate signature bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSignature(Vec<u8>);

impl CandidateSignature {
    /// Construct a non-empty opaque signature.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSignature`] when `bytes` is empty.
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::InvalidSignature);
        }
        Ok(Self(bytes))
    }

    /// Signature bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Relay-issued authorization binding a relay identity to one transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAuthorization {
    relay_peer_id: PeerId,
    subject_peer_id: PeerId,
    transfer_nonce: TransferNonce,
    expires_at_micros: u64,
    signature: CandidateSignature,
}

impl RelayAuthorization {
    /// Build relay authorization.
    #[must_use]
    pub fn new(
        relay_peer_id: PeerId,
        subject_peer_id: PeerId,
        transfer_nonce: TransferNonce,
        expires_at_micros: u64,
        signature: CandidateSignature,
    ) -> Self {
        Self {
            relay_peer_id,
            subject_peer_id,
            transfer_nonce,
            expires_at_micros,
            signature,
        }
    }

    /// Relay peer that issued this authorization.
    #[must_use]
    pub const fn relay_peer_id(&self) -> PeerId {
        self.relay_peer_id
    }

    /// Peer allowed to advertise the relay candidate.
    #[must_use]
    pub const fn subject_peer_id(&self) -> PeerId {
        self.subject_peer_id
    }

    /// Transfer nonce this authorization is scoped to.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Authorization expiry timestamp.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    /// Relay authorization signature.
    #[must_use]
    pub const fn signature(&self) -> &CandidateSignature {
        &self.signature
    }
}

/// Signed rendezvous candidate from one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCandidate {
    peer_id: PeerId,
    transfer_nonce: TransferNonce,
    candidate_nonce: CandidateNonce,
    candidate: Candidate,
    capability_context: CapabilityContext,
    signature: CandidateSignature,
}

impl SignedCandidate {
    /// Build a signed candidate value.
    #[must_use]
    pub fn new(
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        candidate_nonce: CandidateNonce,
        candidate: Candidate,
        signature: CandidateSignature,
    ) -> Self {
        Self {
            peer_id,
            transfer_nonce,
            candidate_nonce,
            candidate,
            capability_context: CapabilityContext::default(),
            signature,
        }
    }

    /// Bind a redaction-safe capability context to this signed candidate.
    #[must_use]
    pub fn with_capability_context(mut self, capability_context: CapabilityContext) -> Self {
        self.capability_context = capability_context;
        self
    }

    /// Peer that signed the candidate.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Transfer nonce this candidate belongs to.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Candidate replay nonce.
    #[must_use]
    pub const fn candidate_nonce(&self) -> CandidateNonce {
        self.candidate_nonce
    }

    /// Candidate endpoint and transport.
    #[must_use]
    pub const fn candidate(&self) -> &Candidate {
        &self.candidate
    }

    /// Capability context carried by this candidate.
    #[must_use]
    pub const fn capability_context(&self) -> &CapabilityContext {
        &self.capability_context
    }

    /// Opaque candidate signature.
    #[must_use]
    pub const fn signature(&self) -> &CandidateSignature {
        &self.signature
    }
}

/// Signature verifier used by the rendezvous service.
pub trait CandidateSignatureVerifier {
    /// Return true when the candidate signature is accepted.
    fn verify(&self, candidate: &SignedCandidate) -> bool;

    /// Return true when relay authorization is accepted.
    fn verify_relay_authorization(
        &self,
        candidate: &SignedCandidate,
        authorization: &RelayAuthorization,
    ) -> bool {
        let _ = (candidate, authorization);
        false
    }
}

impl<F> CandidateSignatureVerifier for F
where
    F: Fn(&SignedCandidate) -> bool,
{
    fn verify(&self, candidate: &SignedCandidate) -> bool {
        self(candidate)
    }
}

/// Quotas for one rendezvous session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quotas {
    /// Maximum candidates accepted per peer.
    pub max_candidates_per_peer: usize,
    /// Maximum total candidates accepted in one session.
    pub max_total_candidates: usize,
    /// Maximum endpoint observations accepted per peer.
    pub max_observations_per_peer: usize,
    /// Maximum total endpoint observations accepted in one session.
    pub max_total_observations: usize,
    /// Maximum hole-punch attempts granted per peer.
    pub max_attempts_per_peer: u32,
}

impl Default for Quotas {
    fn default() -> Self {
        Self {
            max_candidates_per_peer: 8,
            max_total_candidates: 32,
            max_observations_per_peer: 4,
            max_total_observations: 32,
            max_attempts_per_peer: 8,
        }
    }
}

/// Self-hosted rendezvous service configuration.
///
/// The service coordinates metadata only: peer ids, nonces, endpoint
/// observations, candidates, relay authorizations, quotas, and bounded attempt
/// grants. It must not receive plaintext transfer content or long-lived peer
/// secrets. Logs intentionally carry event kinds and peer ids, not endpoint
/// addresses or object identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    service_id: String,
    default_quotas: Quotas,
    log_peer_ids: bool,
    retain_state_on_restart: bool,
}

impl ServiceConfig {
    /// Construct rendezvous service configuration.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptyServiceId`] when the service id is blank.
    pub fn new(service_id: impl Into<String>, default_quotas: Quotas) -> Result<Self, Error> {
        let service_id = service_id.into();
        if service_id.trim().is_empty() {
            return Err(Error::EmptyServiceId);
        }

        Ok(Self {
            service_id,
            default_quotas,
            log_peer_ids: true,
            retain_state_on_restart: true,
        })
    }

    /// Stable service id for operator logs.
    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// Default quotas used by callers that do not provide session-specific
    /// quotas.
    #[must_use]
    pub const fn default_quotas(&self) -> Quotas {
        self.default_quotas
    }

    /// Whether event logs include peer ids.
    #[must_use]
    pub const fn log_peer_ids(&self) -> bool {
        self.log_peer_ids
    }

    /// Configure whether restart snapshots retain active rendezvous state.
    #[must_use]
    pub const fn with_retain_state_on_restart(mut self, retain: bool) -> Self {
        self.retain_state_on_restart = retain;
        self
    }

    /// Configure whether event logs include peer ids.
    #[must_use]
    pub const fn with_log_peer_ids(mut self, enabled: bool) -> Self {
        self.log_peer_ids = enabled;
        self
    }

    /// Whether restart snapshots retain active state.
    #[must_use]
    pub const fn retain_state_on_restart(&self) -> bool {
        self.retain_state_on_restart
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            service_id: "local-atp-rendezvous".to_owned(),
            default_quotas: Quotas::default(),
            log_peer_ids: true,
            retain_state_on_restart: true,
        }
    }
}

/// Redaction-safe rendezvous service event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEventKind {
    /// Session opened or replaced.
    SessionOpened,
    /// Endpoint observation accepted.
    EndpointObservationAccepted,
    /// Candidate accepted.
    CandidateAccepted,
    /// Hole-punch attempt granted.
    AttemptGranted,
}

/// Redaction-safe rendezvous service event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEvent {
    kind: ServiceEventKind,
    transfer_nonce: TransferNonce,
    peer_id: Option<PeerId>,
    at_micros: u64,
}

impl ServiceEvent {
    /// Event kind.
    #[must_use]
    pub const fn kind(&self) -> ServiceEventKind {
        self.kind
    }

    /// Transfer nonce associated with the event.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Peer id, when logging policy permits it.
    #[must_use]
    pub const fn peer_id(&self) -> Option<PeerId> {
        self.peer_id
    }

    /// Deterministic event timestamp supplied by the caller.
    #[must_use]
    pub const fn at_micros(&self) -> u64 {
        self.at_micros
    }
}

/// Receipt returned after endpoint observation registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationReceipt {
    peer_id: PeerId,
    transfer_nonce: TransferNonce,
    observed_endpoint: ObservedEndpoint,
    observed_at_micros: u64,
}

impl ObservationReceipt {
    /// Peer whose endpoint was observed.
    #[must_use]
    pub const fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Transfer nonce for the observation.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Public endpoint reported by the rendezvous observer.
    #[must_use]
    pub const fn observed_endpoint(&self) -> &ObservedEndpoint {
        &self.observed_endpoint
    }

    /// Observation timestamp.
    #[must_use]
    pub const fn observed_at_micros(&self) -> u64 {
        self.observed_at_micros
    }
}

/// Hole-punch attempt grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttemptGrant {
    /// Number of attempts already consumed by this peer.
    pub used_attempts: u32,
    /// Remaining attempts in the session budget.
    pub remaining_attempts: u32,
    /// Session expiry timestamp.
    pub expires_at_micros: u64,
}

/// Candidate and observation view returned to a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RendezvousExchange {
    observed_public_endpoints: Vec<ObservedEndpoint>,
    peer_candidates: Vec<SignedCandidate>,
    remaining_attempts: u32,
    session_expires_at_micros: u64,
}

impl RendezvousExchange {
    /// Endpoints observed for the requesting peer.
    #[must_use]
    pub fn observed_public_endpoints(&self) -> &[ObservedEndpoint] {
        &self.observed_public_endpoints
    }

    /// Other peers' non-expired signed candidates.
    #[must_use]
    pub fn peer_candidates(&self) -> &[SignedCandidate] {
        &self.peer_candidates
    }

    /// Remaining attempt budget for the requesting peer.
    #[must_use]
    pub const fn remaining_attempts(&self) -> u32 {
        self.remaining_attempts
    }

    /// Session expiry timestamp.
    #[must_use]
    pub const fn session_expires_at_micros(&self) -> u64 {
        self.session_expires_at_micros
    }
}

/// Restart snapshot for a self-hosted rendezvous service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartSnapshot {
    config: ServiceConfig,
    sessions: BTreeMap<TransferNonce, Session>,
}

impl RestartSnapshot {
    /// Configuration included in the snapshot.
    #[must_use]
    pub const fn config(&self) -> &ServiceConfig {
        &self.config
    }

    /// Active sessions retained by the snapshot.
    #[must_use]
    pub const fn sessions(&self) -> &BTreeMap<TransferNonce, Session> {
        &self.sessions
    }
}

/// One transfer rendezvous session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    nonce: TransferNonce,
    expires_at_micros: u64,
    quotas: Quotas,
    trusted_relays: BTreeSet<PeerId>,
    candidates: Vec<SignedCandidate>,
    observations: BTreeMap<PeerId, Vec<EndpointObservation>>,
    seen_candidate_nonces: BTreeSet<(PeerId, CandidateNonce)>,
    seen_observation_nonces: BTreeSet<(PeerId, u64)>,
    attempts_by_peer: BTreeMap<PeerId, u32>,
}

impl Session {
    /// Open a rendezvous session.
    #[must_use]
    pub fn new(nonce: TransferNonce, expires_at_micros: u64, quotas: Quotas) -> Self {
        Self {
            nonce,
            expires_at_micros,
            quotas,
            trusted_relays: BTreeSet::new(),
            candidates: Vec::new(),
            observations: BTreeMap::new(),
            seen_candidate_nonces: BTreeSet::new(),
            seen_observation_nonces: BTreeSet::new(),
            attempts_by_peer: BTreeMap::new(),
        }
    }

    /// Trust relay peers for relay candidate authorization.
    #[must_use]
    pub fn with_trusted_relays(mut self, relays: &[PeerId]) -> Self {
        self.trusted_relays = relays.iter().copied().collect();
        self
    }

    /// Transfer nonce for this session.
    #[must_use]
    pub const fn nonce(&self) -> TransferNonce {
        self.nonce
    }

    /// Session expiry timestamp.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    /// Accepted candidates.
    #[must_use]
    pub fn candidates(&self) -> &[SignedCandidate] {
        &self.candidates
    }

    /// Endpoint observations recorded for a peer.
    #[must_use]
    pub fn observations(&self, peer_id: PeerId) -> &[EndpointObservation] {
        self.observations.get(&peer_id).map_or(&[], Vec::as_slice)
    }

    /// Number of hole-punch attempts consumed by a peer.
    #[must_use]
    pub fn attempts_used(&self, peer_id: PeerId) -> u32 {
        self.attempts_by_peer.get(&peer_id).copied().unwrap_or(0)
    }

    /// Session quotas.
    #[must_use]
    pub const fn quotas(&self) -> Quotas {
        self.quotas
    }

    fn is_expired(&self, now_micros: u64) -> bool {
        now_micros >= self.expires_at_micros
    }

    fn peer_candidate_count(&self, peer_id: PeerId) -> usize {
        self.candidates
            .iter()
            .filter(|candidate| candidate.peer_id == peer_id)
            .count()
    }

    fn total_observation_count(&self) -> usize {
        self.observations.values().map(Vec::len).sum()
    }
}

/// In-memory rendezvous validator for deterministic tests and service logic.
#[derive(Debug)]
pub struct Service {
    config: ServiceConfig,
    sessions: BTreeMap<TransferNonce, Session>,
    events: Vec<ServiceEvent>,
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

impl Service {
    /// Construct an empty service.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ServiceConfig::default(),
            sessions: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Construct an empty service from explicit configuration.
    #[must_use]
    pub fn with_config(config: ServiceConfig) -> Self {
        Self {
            config,
            sessions: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    /// Service configuration.
    #[must_use]
    pub const fn config(&self) -> &ServiceConfig {
        &self.config
    }

    /// Redaction-safe event log.
    #[must_use]
    pub fn events(&self) -> &[ServiceEvent] {
        &self.events
    }

    /// Open or replace a session.
    pub fn open_session(&mut self, session: Session) {
        let nonce = session.nonce;
        self.sessions.insert(session.nonce, session);
        self.record_event(ServiceEventKind::SessionOpened, nonce, None, 0);
    }

    /// Return a session by nonce.
    #[must_use]
    pub fn session(&self, nonce: TransferNonce) -> Option<&Session> {
        self.sessions.get(&nonce)
    }

    /// Snapshot active service state for restart.
    #[must_use]
    pub fn snapshot(&self) -> RestartSnapshot {
        RestartSnapshot {
            config: self.config.clone(),
            sessions: if self.config.retain_state_on_restart {
                self.sessions.clone()
            } else {
                BTreeMap::new()
            },
        }
    }

    /// Restore service state after restart. Event logs start empty after
    /// restore so operators can distinguish pre- and post-restart activity.
    #[must_use]
    pub fn restore(snapshot: RestartSnapshot) -> Self {
        Self {
            config: snapshot.config,
            sessions: snapshot.sessions,
            events: Vec::new(),
        }
    }

    /// Record one STUN-like endpoint observation and return the observed public
    /// endpoint to the peer.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the session is missing or expired, the probe
    /// nonce was replayed for this peer, or observation quotas would be
    /// exceeded.
    pub fn record_endpoint_observation(
        &mut self,
        now_micros: u64,
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        observation: EndpointObservation,
    ) -> Result<ObservationReceipt, Error> {
        let observed_endpoint = observation.observed_endpoint().clone();
        let observed_at_micros = observation.observed_at_micros();
        let probe_nonce = observation.probe_nonce();
        {
            let session = self
                .sessions
                .get_mut(&transfer_nonce)
                .ok_or(Error::UnknownSession)?;

            if session.is_expired(now_micros) {
                return Err(Error::ExpiredSession);
            }
            if session
                .seen_observation_nonces
                .contains(&(peer_id, probe_nonce))
            {
                return Err(Error::NonceReplay);
            }
            if session.total_observation_count() >= session.quotas.max_total_observations {
                return Err(Error::QuotaExceeded);
            }
            let peer_observations = session.observations.entry(peer_id).or_default();
            if peer_observations.len() >= session.quotas.max_observations_per_peer {
                return Err(Error::QuotaExceeded);
            }

            session
                .seen_observation_nonces
                .insert((peer_id, probe_nonce));
            peer_observations.push(observation);
        }

        self.record_event(
            ServiceEventKind::EndpointObservationAccepted,
            transfer_nonce,
            Some(peer_id),
            now_micros,
        );

        Ok(ObservationReceipt {
            peer_id,
            transfer_nonce,
            observed_endpoint,
            observed_at_micros,
        })
    }

    /// Reserve one bounded hole-punch attempt for a peer.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the session is missing or expired, or the
    /// peer has exhausted its attempt budget.
    pub fn grant_attempt(
        &mut self,
        now_micros: u64,
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
    ) -> Result<AttemptGrant, Error> {
        let grant = {
            let session = self
                .sessions
                .get_mut(&transfer_nonce)
                .ok_or(Error::UnknownSession)?;

            if session.is_expired(now_micros) {
                return Err(Error::ExpiredSession);
            }

            let used = session.attempts_by_peer.entry(peer_id).or_default();
            if *used >= session.quotas.max_attempts_per_peer {
                return Err(Error::QuotaExceeded);
            }
            *used += 1;
            AttemptGrant {
                used_attempts: *used,
                remaining_attempts: session.quotas.max_attempts_per_peer - *used,
                expires_at_micros: session.expires_at_micros,
            }
        };

        self.record_event(
            ServiceEventKind::AttemptGranted,
            transfer_nonce,
            Some(peer_id),
            now_micros,
        );

        Ok(grant)
    }

    /// Return a peer's current rendezvous view: its observed public endpoints,
    /// other peers' non-expired candidates, and remaining attempt budget.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the session is missing or expired.
    pub fn exchange_for_peer(
        &self,
        now_micros: u64,
        transfer_nonce: TransferNonce,
        peer_id: PeerId,
    ) -> Result<RendezvousExchange, Error> {
        let session = self
            .sessions
            .get(&transfer_nonce)
            .ok_or(Error::UnknownSession)?;

        if session.is_expired(now_micros) {
            return Err(Error::ExpiredSession);
        }

        let observed_public_endpoints = session
            .observations(peer_id)
            .iter()
            .map(|observation| observation.observed_endpoint().clone())
            .collect();
        let peer_candidates = session
            .candidates
            .iter()
            .filter(|candidate| {
                candidate.peer_id != peer_id && now_micros < candidate.candidate.expires_at_micros
            })
            .cloned()
            .collect();
        let used_attempts = session.attempts_used(peer_id);
        let remaining_attempts = session
            .quotas
            .max_attempts_per_peer
            .saturating_sub(used_attempts);

        Ok(RendezvousExchange {
            observed_public_endpoints,
            peer_candidates,
            remaining_attempts,
            session_expires_at_micros: session.expires_at_micros,
        })
    }

    /// Validate and record one signed candidate.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the session is missing or expired, the
    /// candidate is expired, the signature verifier rejects it, relay
    /// authorization fails, the candidate nonce was already used for this peer,
    /// or quotas would be exceeded.
    pub fn register_candidate<V>(
        &mut self,
        now_micros: u64,
        signed: SignedCandidate,
        verifier: &V,
    ) -> Result<(), Error>
    where
        V: CandidateSignatureVerifier,
    {
        let transfer_nonce = signed.transfer_nonce;
        let peer_id = signed.peer_id;
        let session = self
            .sessions
            .get_mut(&transfer_nonce)
            .ok_or(Error::UnknownSession)?;

        if session.is_expired(now_micros) {
            return Err(Error::ExpiredSession);
        }
        if now_micros >= signed.candidate.expires_at_micros {
            return Err(Error::ExpiredCandidate);
        }
        if signed.candidate.expires_at_micros > session.expires_at_micros {
            return Err(Error::CandidateOutlivesSession);
        }
        validate_capability_context(now_micros, &signed)?;
        if !verifier.verify(&signed) {
            return Err(Error::InvalidSignature);
        }
        if let Err(error) = validate_relay_candidate(now_micros, &signed, session, verifier) {
            return Err(error.public_error());
        }
        if session
            .seen_candidate_nonces
            .contains(&(peer_id, signed.candidate_nonce))
        {
            return Err(Error::NonceReplay);
        }
        if session.candidates.len() >= session.quotas.max_total_candidates {
            return Err(Error::QuotaExceeded);
        }
        if session.peer_candidate_count(peer_id) >= session.quotas.max_candidates_per_peer {
            return Err(Error::QuotaExceeded);
        }

        session
            .seen_candidate_nonces
            .insert((peer_id, signed.candidate_nonce));
        session.candidates.push(signed);
        self.record_event(
            ServiceEventKind::CandidateAccepted,
            transfer_nonce,
            Some(peer_id),
            now_micros,
        );
        Ok(())
    }

    fn record_event(
        &mut self,
        kind: ServiceEventKind,
        transfer_nonce: TransferNonce,
        peer_id: Option<PeerId>,
        at_micros: u64,
    ) {
        self.events.push(ServiceEvent {
            kind,
            transfer_nonce,
            peer_id: peer_id.filter(|_| self.config.log_peer_ids),
            at_micros,
        });
    }
}

/// Private relay authorization detail for internal diagnostics.
///
/// Public callers only receive [`Error::RelayAuthorizationFailed`] so they
/// cannot distinguish valid peers, relay trust relationships, or expiry windows
/// by probing the rendezvous service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelayCandidateValidationError {
    UnexpectedAuthorization,
    MissingAuthorization,
    BindingMismatch,
    ExpiredAuthorization,
    UntrustedRelay,
    InvalidSignature,
}

impl RelayCandidateValidationError {
    const fn public_error(self) -> Error {
        match self {
            Self::UnexpectedAuthorization => Error::UnexpectedRelayAuthorization,
            Self::MissingAuthorization
            | Self::BindingMismatch
            | Self::ExpiredAuthorization
            | Self::UntrustedRelay
            | Self::InvalidSignature => Error::RelayAuthorizationFailed,
        }
    }
}

fn validate_relay_candidate<V>(
    now_micros: u64,
    signed: &SignedCandidate,
    session: &Session,
    verifier: &V,
) -> Result<(), RelayCandidateValidationError>
where
    V: CandidateSignatureVerifier,
{
    if !matches!(signed.candidate.transport, CandidateTransport::Relay) {
        if signed.candidate.relay_authorization.is_some() {
            return Err(RelayCandidateValidationError::UnexpectedAuthorization);
        }
        return Ok(());
    }

    let authorization = signed
        .candidate
        .relay_authorization
        .as_ref()
        .ok_or(RelayCandidateValidationError::MissingAuthorization)?;
    let mut mismatch = 0_u8;
    mismatch |= u8::from(!constant_time_peer_id_eq(
        authorization.subject_peer_id,
        signed.peer_id,
    ));
    mismatch |= u8::from(!constant_time_transfer_nonce_eq(
        authorization.transfer_nonce,
        session.nonce,
    ));
    mismatch |= u8::from(constant_time_peer_id_eq(
        authorization.relay_peer_id,
        signed.peer_id,
    ));
    if mismatch != 0 {
        return Err(RelayCandidateValidationError::BindingMismatch);
    }
    if now_micros >= authorization.expires_at_micros {
        return Err(RelayCandidateValidationError::ExpiredAuthorization);
    }
    if !session
        .trusted_relays
        .contains(&authorization.relay_peer_id)
    {
        return Err(RelayCandidateValidationError::UntrustedRelay);
    }
    if !verifier.verify_relay_authorization(signed, authorization) {
        return Err(RelayCandidateValidationError::InvalidSignature);
    }
    Ok(())
}

#[inline]
fn constant_time_peer_id_eq(left: PeerId, right: PeerId) -> bool {
    let left_bytes = left.bytes();
    let right_bytes = right.bytes();
    constant_time_eq(&left_bytes, &right_bytes)
}

#[inline]
fn constant_time_transfer_nonce_eq(left: TransferNonce, right: TransferNonce) -> bool {
    let left_bytes = left.get().to_be_bytes();
    let right_bytes = right.get().to_be_bytes();
    constant_time_eq(&left_bytes, &right_bytes)
}

#[inline]
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn validate_capability_context(now_micros: u64, signed: &SignedCandidate) -> Result<(), Error> {
    let context = signed.capability_context();
    if context.label().trim().is_empty() || context.max_candidate_ttl_micros() == 0 {
        return Err(Error::InvalidCapabilityContext);
    }

    match signed.candidate.transport {
        CandidateTransport::Relay if !context.relay_allowed() => {
            return Err(Error::CapabilityMismatch);
        }
        CandidateTransport::Ipv6 if !context.ipv6_direct_allowed() => {
            return Err(Error::CapabilityMismatch);
        }
        CandidateTransport::Udp | CandidateTransport::Relay | CandidateTransport::Ipv6 => {}
    }

    let candidate_ttl = signed
        .candidate
        .expires_at_micros
        .saturating_sub(now_micros);
    if candidate_ttl > context.max_candidate_ttl_micros() {
        return Err(Error::CandidateTtlExceeded);
    }

    Ok(())
}

/// Rendezvous validation errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Peer id was malformed.
    #[error("malformed peer id")]
    MalformedPeerId,
    /// Nonce value was zero.
    #[error("nonce is zero")]
    ZeroNonce,
    /// Service id was empty.
    #[error("rendezvous service id is empty")]
    EmptyServiceId,
    /// Capability context label was empty.
    #[error("capability context is empty")]
    EmptyCapabilityContext,
    /// Capability context fields are invalid.
    #[error("capability context is invalid")]
    InvalidCapabilityContext,
    /// Candidate transport is not allowed by the capability context.
    #[error("candidate capability context mismatch")]
    CapabilityMismatch,
    /// Candidate TTL exceeds the capability context bound.
    #[error("candidate ttl exceeds capability context")]
    CandidateTtlExceeded,
    /// Candidate signature was invalid.
    #[error("invalid candidate signature")]
    InvalidSignature,
    /// Candidate transfer nonce did not match an open session.
    #[error("unknown rendezvous session")]
    UnknownSession,
    /// Rendezvous session has expired.
    #[error("rendezvous session expired")]
    ExpiredSession,
    /// Candidate has expired.
    #[error("candidate expired")]
    ExpiredCandidate,
    /// Candidate expiry exceeds the rendezvous session expiry.
    #[error("candidate outlives rendezvous session")]
    CandidateOutlivesSession,
    /// Candidate nonce was replayed by the same peer.
    #[error("candidate nonce replay")]
    NonceReplay,
    /// Non-relay candidate carried relay authorization.
    #[error("unexpected relay authorization")]
    UnexpectedRelayAuthorization,
    /// Relay authorization failed. Detailed reasons are kept internal to avoid
    /// exposing valid peer ids, timing windows, or trust relationships.
    #[error("authorization failed")]
    RelayAuthorizationFailed,
    /// Session or peer quota would be exceeded.
    #[error("rendezvous quota exceeded")]
    QuotaExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::atp::stun::{EndpointFamily, ObservationRequest, ObservedEndpoint};

    fn peer(byte: u8) -> PeerId {
        PeerId::new([byte; 32]).expect("peer id")
    }

    fn nonce(raw: u128) -> TransferNonce {
        TransferNonce::new(raw).expect("transfer nonce")
    }

    fn candidate_nonce(raw: u128) -> CandidateNonce {
        CandidateNonce::new(raw).expect("candidate nonce")
    }

    fn endpoint(port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, "198.51.100.10", port).expect("endpoint")
    }

    fn private_endpoint(port: u16) -> ObservedEndpoint {
        ObservedEndpoint::new(EndpointFamily::Ipv4, "10.0.0.2", port).expect("endpoint")
    }

    fn observation(probe_nonce: u64, observed_port: u16) -> EndpointObservation {
        EndpointObservation::from_request(ObservationRequest {
            local_endpoint: private_endpoint(40_000),
            observed_endpoint: endpoint(observed_port),
            observer_id: "rendezvous-a".to_owned(),
            probe_nonce,
            observed_at_micros: 10,
        })
        .expect("observation")
    }

    fn signed_candidate(
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        candidate_nonce: CandidateNonce,
    ) -> SignedCandidate {
        SignedCandidate::new(
            peer_id,
            transfer_nonce,
            candidate_nonce,
            Candidate::new(endpoint(50_000), CandidateTransport::Udp, 1_000),
            CandidateSignature::new(vec![1, 2, 3]).expect("signature"),
        )
    }

    fn relay_authorization(
        relay_peer_id: PeerId,
        subject_peer_id: PeerId,
        transfer_nonce: TransferNonce,
    ) -> RelayAuthorization {
        RelayAuthorization::new(
            relay_peer_id,
            subject_peer_id,
            transfer_nonce,
            1_000,
            CandidateSignature::new(vec![9, 9]).expect("relay signature"),
        )
    }

    fn signed_relay_candidate(
        peer_id: PeerId,
        transfer_nonce: TransferNonce,
        candidate_nonce: CandidateNonce,
        authorization: Option<RelayAuthorization>,
    ) -> SignedCandidate {
        let mut candidate = Candidate::new(endpoint(50_010), CandidateTransport::Relay, 1_000);
        if let Some(authorization) = authorization {
            candidate = candidate.with_relay_authorization(authorization);
        }
        SignedCandidate::new(
            peer_id,
            transfer_nonce,
            candidate_nonce,
            candidate,
            CandidateSignature::new(vec![1, 2, 3]).expect("signature"),
        )
    }

    struct RelayVerifier {
        relay_authorization_valid: bool,
    }

    impl CandidateSignatureVerifier for RelayVerifier {
        fn verify(&self, candidate: &SignedCandidate) -> bool {
            candidate.signature().bytes() == [1, 2, 3] // ubs:ignore - test oracle
        }

        fn verify_relay_authorization(
            &self,
            _candidate: &SignedCandidate,
            authorization: &RelayAuthorization,
        ) -> bool {
            self.relay_authorization_valid && authorization.signature().bytes() == [9, 9] // ubs:ignore - test oracle
        }
    }

    #[test]
    fn relay_authorization_binding_helpers_match_expected_values() {
        let peer_a = peer(1);
        let peer_b = peer(2);
        let nonce_a = nonce(7);
        let nonce_b = nonce(8);

        assert!(constant_time_peer_id_eq(peer_a, peer_a));
        assert!(!constant_time_peer_id_eq(peer_a, peer_b));
        assert!(constant_time_transfer_nonce_eq(nonce_a, nonce_a));
        assert!(!constant_time_transfer_nonce_eq(nonce_a, nonce_b));
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[9, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 3, 4]));
    }

    #[test]
    fn accepts_valid_signed_candidate() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        service
            .register_candidate(10, signed, &|candidate: &SignedCandidate| {
                candidate.signature().bytes() == [1, 2, 3]
            })
            .expect("accepted");

        assert_eq!(
            service
                .session(transfer_nonce)
                .expect("session")
                .candidates()
                .len(),
            1
        );
    }

    #[test]
    fn records_endpoint_observation_and_exchanges_peer_view() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        let peer_b = peer(2);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));

        let receipt = service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("observation accepted");
        assert_eq!(receipt.peer_id(), peer_a);
        assert_eq!(receipt.observed_endpoint().port(), 50_001);

        service
            .register_candidate(
                10,
                signed_candidate(peer_b, transfer_nonce, candidate_nonce(9)),
                &|candidate: &SignedCandidate| candidate.signature().bytes() == [1, 2, 3],
            )
            .expect("peer candidate accepted");

        let exchange = service
            .exchange_for_peer(11, transfer_nonce, peer_a)
            .expect("exchange");
        assert_eq!(exchange.observed_public_endpoints().len(), 1);
        assert_eq!(exchange.observed_public_endpoints()[0].port(), 50_001);
        assert_eq!(exchange.peer_candidates().len(), 1);
        assert_eq!(exchange.peer_candidates()[0].peer_id(), peer_b);
        assert_eq!(
            exchange.remaining_attempts(),
            Quotas::default().max_attempts_per_peer
        );
        assert_eq!(exchange.session_expires_at_micros(), 1_000);
        assert_eq!(
            service
                .events()
                .iter()
                .map(ServiceEvent::kind)
                .collect::<Vec<_>>(),
            vec![
                ServiceEventKind::SessionOpened,
                ServiceEventKind::EndpointObservationAccepted,
                ServiceEventKind::CandidateAccepted,
            ]
        );
    }

    #[test]
    fn exchange_filters_own_and_expired_candidates() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        let peer_b = peer(2);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));

        service
            .register_candidate(
                10,
                signed_candidate(peer_a, transfer_nonce, candidate_nonce(9)),
                &|_: &SignedCandidate| true,
            )
            .expect("own candidate accepted");
        let short_lived_peer_candidate = SignedCandidate::new(
            peer_b,
            transfer_nonce,
            candidate_nonce(10),
            Candidate::new(endpoint(50_020), CandidateTransport::Udp, 20),
            CandidateSignature::new(vec![1, 2, 3]).expect("signature"),
        );
        service
            .register_candidate(10, short_lived_peer_candidate, &|_: &SignedCandidate| true)
            .expect("short-lived peer candidate accepted");

        let exchange = service
            .exchange_for_peer(30, transfer_nonce, peer_a)
            .expect("exchange");
        assert!(exchange.peer_candidates().is_empty());
    }

    #[test]
    fn rejects_malformed_peer_id_and_zero_nonces() {
        assert_eq!(
            PeerId::new([0; 32]).expect_err("zero peer"),
            Error::MalformedPeerId
        );
        assert_eq!(
            TransferNonce::new(0).expect_err("zero transfer"),
            Error::ZeroNonce
        );
        assert_eq!(
            CandidateNonce::new(0).expect_err("zero candidate"),
            Error::ZeroNonce
        );
    }

    #[test]
    fn rejects_bad_signature_and_nonce_replay() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        assert_eq!(
            service
                .register_candidate(10, signed.clone(), &|_: &SignedCandidate| false)
                .expect_err("bad signature"),
            Error::InvalidSignature
        );

        service
            .register_candidate(10, signed.clone(), &|_: &SignedCandidate| true)
            .expect("first use");
        assert_eq!(
            service
                .register_candidate(10, signed, &|_: &SignedCandidate| true)
                .expect_err("replay"),
            Error::NonceReplay
        );
    }

    #[test]
    fn rejects_expired_session_and_candidate() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 20, Quotas::default()));
        let signed = signed_candidate(peer(1), transfer_nonce, candidate_nonce(9));

        assert_eq!(
            service
                .register_candidate(20, signed, &|_: &SignedCandidate| true)
                .expect_err("expired session"),
            Error::ExpiredSession
        );

        let live_nonce = nonce(8);
        service.open_session(Session::new(live_nonce, 1_000, Quotas::default()));
        let expired_candidate = SignedCandidate::new(
            peer(1),
            live_nonce,
            candidate_nonce(10),
            Candidate::new(endpoint(50_001), CandidateTransport::Udp, 20),
            CandidateSignature::new(vec![1]).expect("signature"),
        );
        assert_eq!(
            service
                .register_candidate(20, expired_candidate, &|_: &SignedCandidate| true)
                .expect_err("expired candidate"),
            Error::ExpiredCandidate
        );

        let outliving_candidate = SignedCandidate::new(
            peer(1),
            live_nonce,
            candidate_nonce(11),
            Candidate::new(endpoint(50_002), CandidateTransport::Udp, 1_001),
            CandidateSignature::new(vec![1]).expect("signature"),
        );
        assert_eq!(
            service
                .register_candidate(20, outliving_candidate, &|_: &SignedCandidate| true)
                .expect_err("candidate outlives session"),
            Error::CandidateOutlivesSession
        );
    }

    #[test]
    fn enforces_peer_and_total_quotas() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            Quotas {
                max_candidates_per_peer: 1,
                max_total_candidates: 2,
                max_observations_per_peer: 4,
                max_total_observations: 32,
                max_attempts_per_peer: 8,
            },
        ));

        service
            .register_candidate(
                10,
                signed_candidate(peer(1), transfer_nonce, candidate_nonce(1)),
                &|_: &SignedCandidate| true,
            )
            .expect("first peer candidate");
        assert_eq!(
            service
                .register_candidate(
                    10,
                    signed_candidate(peer(1), transfer_nonce, candidate_nonce(2)),
                    &|_: &SignedCandidate| true,
                )
                .expect_err("peer quota"),
            Error::QuotaExceeded
        );

        service
            .register_candidate(
                10,
                signed_candidate(peer(2), transfer_nonce, candidate_nonce(3)),
                &|_: &SignedCandidate| true,
            )
            .expect("second peer candidate");
        assert_eq!(
            service
                .register_candidate(
                    10,
                    signed_candidate(peer(3), transfer_nonce, candidate_nonce(4)),
                    &|_: &SignedCandidate| true,
                )
                .expect_err("total quota"),
            Error::QuotaExceeded
        );
    }

    #[test]
    fn endpoint_observation_replay_and_quota_are_rejected() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            Quotas {
                max_candidates_per_peer: 8,
                max_total_candidates: 32,
                max_observations_per_peer: 1,
                max_total_observations: 1,
                max_attempts_per_peer: 8,
            },
        ));

        service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("first observation");
        assert_eq!(
            service
                .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
                .expect_err("observation replay"),
            Error::NonceReplay
        );
        assert_eq!(
            service
                .record_endpoint_observation(10, peer_a, transfer_nonce, observation(22, 50_002))
                .expect_err("observation quota"),
            Error::QuotaExceeded
        );
    }

    #[test]
    fn grants_attempts_until_peer_budget_is_exhausted() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(
            transfer_nonce,
            1_000,
            Quotas {
                max_candidates_per_peer: 8,
                max_total_candidates: 32,
                max_observations_per_peer: 4,
                max_total_observations: 32,
                max_attempts_per_peer: 1,
            },
        ));

        let grant = service
            .grant_attempt(10, peer_a, transfer_nonce)
            .expect("first attempt");
        assert_eq!(grant.used_attempts, 1);
        assert_eq!(grant.remaining_attempts, 0);
        assert_eq!(grant.expires_at_micros, 1_000);
        assert_eq!(
            service
                .grant_attempt(11, peer_a, transfer_nonce)
                .expect_err("attempt quota"),
            Error::QuotaExceeded
        );

        let exchange = service
            .exchange_for_peer(12, transfer_nonce, peer_a)
            .expect("exchange");
        assert_eq!(exchange.remaining_attempts(), 0);
    }

    #[test]
    fn capability_context_bounds_transport_and_candidate_ttl() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        service.open_session(
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]),
        );

        let no_relay =
            CapabilityContext::new("direct-only", 1_000, false, true).expect("capability context");
        let relay_candidate = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(1), transfer_nonce)),
        )
        .with_capability_context(no_relay);
        assert_eq!(
            service
                .register_candidate(
                    10,
                    relay_candidate,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("relay disallowed"),
            Error::CapabilityMismatch
        );

        let short_ttl =
            CapabilityContext::new("short-ttl", 5, true, true).expect("capability context");
        let long_ttl_candidate = signed_candidate(peer(1), transfer_nonce, candidate_nonce(10))
            .with_capability_context(short_ttl);
        assert_eq!(
            service
                .register_candidate(10, long_ttl_candidate, &|_: &SignedCandidate| true)
                .expect_err("ttl too long"),
            Error::CandidateTtlExceeded
        );
    }

    #[test]
    fn relay_candidates_require_authorization_and_trusted_relay_identity() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));

        let missing_auth =
            signed_relay_candidate(peer(1), transfer_nonce, candidate_nonce(9), None);
        assert_eq!(
            service
                .register_candidate(
                    10,
                    missing_auth,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("missing relay auth"),
            Error::RelayAuthorizationFailed
        );

        let untrusted_auth = relay_authorization(peer(9), peer(1), transfer_nonce);
        let untrusted = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(10),
            Some(untrusted_auth),
        );
        assert_eq!(
            service
                .register_candidate(
                    10,
                    untrusted,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("untrusted relay"),
            Error::RelayAuthorizationFailed
        );
    }

    #[test]
    fn accepts_relay_candidate_only_with_bound_relay_authorization() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        service.open_session(
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]),
        );

        let signed = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(1), transfer_nonce)),
        );
        service
            .register_candidate(
                10,
                signed,
                &RelayVerifier {
                    relay_authorization_valid: true,
                },
            )
            .expect("relay accepted");

        assert_eq!(
            service
                .session(transfer_nonce)
                .expect("session")
                .candidates()
                .len(),
            1
        );
    }

    #[test]
    fn rejects_relay_authorization_confusion_and_bad_signature() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        service.open_session(
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]),
        );

        let wrong_subject = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(2), transfer_nonce)),
        );
        assert_eq!(
            service
                .register_candidate(
                    10,
                    wrong_subject,
                    &RelayVerifier {
                        relay_authorization_valid: true,
                    },
                )
                .expect_err("wrong relay subject"),
            Error::RelayAuthorizationFailed
        );

        let bad_signature = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(10),
            Some(relay_authorization(relay, peer(1), transfer_nonce)),
        );
        assert_eq!(
            service
                .register_candidate(
                    10,
                    bad_signature,
                    &RelayVerifier {
                        relay_authorization_valid: false,
                    },
                )
                .expect_err("bad relay signature"),
            Error::RelayAuthorizationFailed
        );
    }

    #[test]
    fn relay_authorization_failures_keep_private_diagnostics() {
        let transfer_nonce = nonce(7);
        let relay = peer(9);
        let session =
            Session::new(transfer_nonce, 1_000, Quotas::default()).with_trusted_relays(&[relay]);

        let wrong_subject = signed_relay_candidate(
            peer(1),
            transfer_nonce,
            candidate_nonce(9),
            Some(relay_authorization(relay, peer(2), transfer_nonce)),
        );
        let detail = validate_relay_candidate(
            10,
            &wrong_subject,
            &session,
            &RelayVerifier {
                relay_authorization_valid: true,
            },
        )
        .expect_err("wrong relay subject");

        assert_eq!(detail, RelayCandidateValidationError::BindingMismatch);
        assert_eq!(detail.public_error(), Error::RelayAuthorizationFailed);
        assert_eq!(
            Error::RelayAuthorizationFailed.to_string(),
            "authorization failed"
        );
    }

    #[test]
    fn restart_snapshot_preserves_active_state_and_replay_sets() {
        let mut service = Service::new();
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("observation");
        service
            .register_candidate(
                10,
                signed_candidate(peer(2), transfer_nonce, candidate_nonce(9)),
                &|_: &SignedCandidate| true,
            )
            .expect("candidate");

        let mut restored = Service::restore(service.snapshot());
        let exchange = restored
            .exchange_for_peer(11, transfer_nonce, peer_a)
            .expect("exchange after restart");
        assert_eq!(exchange.observed_public_endpoints()[0].port(), 50_001);
        assert_eq!(exchange.peer_candidates().len(), 1);
        assert!(restored.events().is_empty());
        assert_eq!(
            restored
                .record_endpoint_observation(12, peer_a, transfer_nonce, observation(21, 50_001))
                .expect_err("replay survives restart"),
            Error::NonceReplay
        );
    }

    #[test]
    fn service_config_controls_restart_retention_and_log_redaction() {
        assert_eq!(
            ServiceConfig::new(" ", Quotas::default()).expect_err("blank service id"),
            Error::EmptyServiceId
        );

        let config = ServiceConfig::new("rv-a", Quotas::default())
            .expect("config")
            .with_log_peer_ids(false)
            .with_retain_state_on_restart(false);
        let mut service = Service::with_config(config);
        let transfer_nonce = nonce(7);
        let peer_a = peer(1);
        service.open_session(Session::new(transfer_nonce, 1_000, Quotas::default()));
        service
            .record_endpoint_observation(10, peer_a, transfer_nonce, observation(21, 50_001))
            .expect("observation");

        assert_eq!(service.config().service_id(), "rv-a");
        assert!(
            service
                .events()
                .iter()
                .all(|event| event.peer_id().is_none())
        );

        let restored = Service::restore(service.snapshot());
        assert!(restored.session(transfer_nonce).is_none());
        assert!(!restored.config().retain_state_on_restart());
    }
}
