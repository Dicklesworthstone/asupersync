//! Opaque ATP relay reservation and forwarding model.
//!
//! The relay layer is metadata-only. It authorizes transfer-scoped relay
//! reservations, forwards encrypted ATP packets without parsing object
//! plaintext, records path proof telemetry, and models UDP-first with
//! TCP/TLS port 443 fallback for hostile networks.

use crate::atp::path::{
    PathBudget, PathCandidate, PathCandidateId, PathFailureKind, PathKind, PathOutcome,
    PathSecurity, PathSuccessKind, PathTraceId,
};
use crate::net::atp::rendezvous::{CandidateSignature, PeerId, TransferNonce};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// TCP/TLS fallback port used by locked-down egress networks.
pub const TCP_TLS_443_PORT: u16 = 443;

/// Relay transport policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelayTransport {
    /// UDP relay carrying encrypted ATP datagrams.
    Udp,
    /// TCP/TLS fallback on port 443 with head-of-line blocking caveats.
    TcpTls443,
}

impl RelayTransport {
    /// Stable path/proof code for this transport.
    #[must_use]
    pub const fn path_code(self) -> &'static str {
        match self {
            Self::Udp => "atp_relay_udp",
            Self::TcpTls443 => "atp_relay_tcp_tls_443",
        }
    }

    /// Default network port for this transport.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Udp => 0,
            Self::TcpTls443 => TCP_TLS_443_PORT,
        }
    }

    /// Explicit fallback reason for proof artifacts and operator logs.
    #[must_use]
    pub const fn fallback_reason(self) -> Option<&'static str> {
        match self {
            Self::Udp => None,
            Self::TcpTls443 => Some("udp_unavailable_tcp_tls_443"),
        }
    }

    /// Shared path graph kind represented by this relay transport.
    #[must_use]
    pub const fn path_kind(self) -> PathKind {
        match self {
            Self::Udp => PathKind::AtpRelayUdp,
            Self::TcpTls443 => PathKind::AtpRelayTcpTls443,
        }
    }
}

/// Stable identifier for one relay reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelayReservationId(u128);

impl RelayReservationId {
    /// Construct a non-zero relay reservation id.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::ZeroReservationId`] when `raw` is zero.
    pub const fn new(raw: u128) -> Result<Self, RelayError> {
        if raw == 0 {
            return Err(RelayError::ZeroReservationId);
        }
        Ok(Self(raw))
    }

    /// Return the raw reservation id.
    #[must_use]
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// End-to-end proof tag carried by encrypted ATP packets.
///
/// The relay stores and forwards this tag but does not verify or mint verified
/// chunks. Endpoint verification remains end-to-end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofTag([u8; 32]);

impl ProofTag {
    /// Construct a non-zero proof tag.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidProofTag`] when all bytes are zero.
    pub fn new(bytes: [u8; 32]) -> Result<Self, RelayError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(RelayError::InvalidProofTag);
        }
        Ok(Self(bytes))
    }

    /// Return proof tag bytes.
    #[must_use]
    pub const fn bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// Opaque encrypted packet accepted by the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRelayPacket {
    sequence: u64,
    transport: RelayTransport,
    payload: Vec<u8>,
    proof_tag: ProofTag,
    sent_at_micros: u64,
}

impl OpaqueRelayPacket {
    /// Build an opaque packet.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::EmptyPacket`] when the payload is empty.
    pub fn new(
        sequence: u64,
        transport: RelayTransport,
        payload: Vec<u8>,
        proof_tag: ProofTag,
        sent_at_micros: u64,
    ) -> Result<Self, RelayError> {
        if payload.is_empty() {
            return Err(RelayError::EmptyPacket);
        }

        Ok(Self {
            sequence,
            transport,
            payload,
            proof_tag,
            sent_at_micros,
        })
    }

    /// Packet sequence number within the end-to-end ATP flow.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Transport used for this packet.
    #[must_use]
    pub const fn transport(&self) -> RelayTransport {
        self.transport
    }

    /// Opaque encrypted bytes forwarded by the relay.
    #[must_use]
    pub fn opaque_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// Number of opaque bytes.
    #[must_use]
    pub fn opaque_len(&self) -> usize {
        self.payload.len()
    }

    /// End-to-end proof tag carried unchanged through the relay.
    #[must_use]
    pub const fn proof_tag(&self) -> &ProofTag {
        &self.proof_tag
    }

    /// Sender-side timestamp used for latency summaries.
    #[must_use]
    pub const fn sent_at_micros(&self) -> u64 {
        self.sent_at_micros
    }
}

/// Per-reservation relay quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayQuota {
    /// Maximum packets accepted for one reservation.
    pub max_packets_per_reservation: u64,
    /// Maximum opaque bytes accepted for one reservation.
    pub max_bytes_per_reservation: u64,
    /// Maximum opaque bytes accepted in one packet.
    pub max_packet_bytes: usize,
}

impl RelayQuota {
    /// Validate quota fields.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::InvalidQuota`] when any quota bound is zero.
    pub const fn validate(self) -> Result<Self, RelayError> {
        if self.max_packets_per_reservation == 0
            || self.max_bytes_per_reservation == 0
            || self.max_packet_bytes == 0
        {
            return Err(RelayError::InvalidQuota);
        }
        Ok(self)
    }
}

impl Default for RelayQuota {
    fn default() -> Self {
        Self {
            max_packets_per_reservation: 4_096,
            max_bytes_per_reservation: 64 * 1024 * 1024,
            max_packet_bytes: 64 * 1024,
        }
    }
}

/// Transfer-scoped grant authorizing two peers to use a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayReservationGrant {
    source_peer_id: PeerId,
    destination_peer_id: PeerId,
    transfer_nonce: TransferNonce,
    expires_at_micros: u64,
    quota: RelayQuota,
    allowed_transports: BTreeSet<RelayTransport>,
    signature: CandidateSignature,
}

impl RelayReservationGrant {
    /// Build a relay reservation grant.
    ///
    /// # Errors
    ///
    /// Returns an error for identical peers, invalid quotas, empty transport
    /// policy, or an already-expired grant.
    pub fn new(
        source_peer_id: PeerId,
        destination_peer_id: PeerId,
        transfer_nonce: TransferNonce,
        expires_at_micros: u64,
        quota: RelayQuota,
        allowed_transports: &[RelayTransport],
        signature: CandidateSignature,
    ) -> Result<Self, RelayError> {
        if source_peer_id == destination_peer_id {
            return Err(RelayError::LoopbackReservation);
        }
        if expires_at_micros == 0 {
            return Err(RelayError::ExpiredReservation);
        }

        let allowed_transports = allowed_transports.iter().copied().collect::<BTreeSet<_>>();
        if allowed_transports.is_empty() {
            return Err(RelayError::TransportUnavailable);
        }

        Ok(Self {
            source_peer_id,
            destination_peer_id,
            transfer_nonce,
            expires_at_micros,
            quota: quota.validate()?,
            allowed_transports,
            signature,
        })
    }

    /// Build the normal UDP-first, TCP/TLS 443 fallback grant.
    ///
    /// # Errors
    ///
    /// Propagates [`Self::new`] validation errors.
    pub fn udp_first_tcp_tls_443(
        source_peer_id: PeerId,
        destination_peer_id: PeerId,
        transfer_nonce: TransferNonce,
        expires_at_micros: u64,
        quota: RelayQuota,
        signature: CandidateSignature,
    ) -> Result<Self, RelayError> {
        Self::new(
            source_peer_id,
            destination_peer_id,
            transfer_nonce,
            expires_at_micros,
            quota,
            &[RelayTransport::Udp, RelayTransport::TcpTls443],
            signature,
        )
    }

    /// Source peer allowed to send through this reservation.
    #[must_use]
    pub const fn source_peer_id(&self) -> PeerId {
        self.source_peer_id
    }

    /// Destination peer allowed to send through this reservation.
    #[must_use]
    pub const fn destination_peer_id(&self) -> PeerId {
        self.destination_peer_id
    }

    /// Transfer nonce bound into this grant.
    #[must_use]
    pub const fn transfer_nonce(&self) -> TransferNonce {
        self.transfer_nonce
    }

    /// Grant expiry timestamp.
    #[must_use]
    pub const fn expires_at_micros(&self) -> u64 {
        self.expires_at_micros
    }

    /// Quota bound into this grant.
    #[must_use]
    pub const fn quota(&self) -> RelayQuota {
        self.quota
    }

    /// Grant signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &CandidateSignature {
        &self.signature
    }

    /// Whether a transport is allowed by the endpoint-signed grant.
    #[must_use]
    pub fn allows_transport(&self, transport: RelayTransport) -> bool {
        self.allowed_transports.contains(&transport)
    }
}

/// Authorization verifier for relay grants.
pub trait RelayAuthorizationVerifier {
    /// Return true when the relay grant is authentic and transfer-scoped.
    fn verify(&self, grant: &RelayReservationGrant) -> bool;
}

impl<F> RelayAuthorizationVerifier for F
where
    F: Fn(&RelayReservationGrant) -> bool,
{
    fn verify(&self, grant: &RelayReservationGrant) -> bool {
        self(grant)
    }
}

/// Self-hosted relay service configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayServiceConfig {
    relay_id: String,
    max_active_reservations: usize,
    udp_enabled: bool,
    tcp_tls_443_enabled: bool,
    retain_state_on_restart: bool,
    log_peer_ids: bool,
}

impl RelayServiceConfig {
    /// Construct relay service config.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::EmptyRelayId`] when the relay id is blank and
    /// [`RelayError::InvalidQuota`] when `max_active_reservations` is zero.
    pub fn new(
        relay_id: impl Into<String>,
        max_active_reservations: usize,
    ) -> Result<Self, RelayError> {
        let relay_id = relay_id.into();
        if relay_id.trim().is_empty() {
            return Err(RelayError::EmptyRelayId);
        }
        if max_active_reservations == 0 {
            return Err(RelayError::InvalidQuota);
        }

        Ok(Self {
            relay_id,
            max_active_reservations,
            udp_enabled: true,
            tcp_tls_443_enabled: true,
            retain_state_on_restart: true,
            log_peer_ids: false,
        })
    }

    /// Relay id used in logs and proof artifacts.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Maximum active reservations accepted by this relay.
    #[must_use]
    pub const fn max_active_reservations(&self) -> usize {
        self.max_active_reservations
    }

    /// Whether UDP relay is enabled.
    #[must_use]
    pub const fn udp_enabled(&self) -> bool {
        self.udp_enabled
    }

    /// Whether TCP/TLS 443 fallback is enabled.
    #[must_use]
    pub const fn tcp_tls_443_enabled(&self) -> bool {
        self.tcp_tls_443_enabled
    }

    /// Whether restart snapshots should retain active relay state.
    #[must_use]
    pub const fn retain_state_on_restart(&self) -> bool {
        self.retain_state_on_restart
    }

    /// Whether logs may include redacted peer id prefixes.
    #[must_use]
    pub const fn log_peer_ids(&self) -> bool {
        self.log_peer_ids
    }

    /// Configure UDP availability.
    #[must_use]
    pub const fn with_udp_enabled(mut self, enabled: bool) -> Self {
        self.udp_enabled = enabled;
        self
    }

    /// Configure TCP/TLS 443 fallback availability.
    #[must_use]
    pub const fn with_tcp_tls_443_enabled(mut self, enabled: bool) -> Self {
        self.tcp_tls_443_enabled = enabled;
        self
    }

    /// Configure restart retention.
    #[must_use]
    pub const fn with_retain_state_on_restart(mut self, retain: bool) -> Self {
        self.retain_state_on_restart = retain;
        self
    }

    /// Configure peer id redaction in event logs.
    #[must_use]
    pub const fn with_log_peer_ids(mut self, enabled: bool) -> Self {
        self.log_peer_ids = enabled;
        self
    }
}

impl Default for RelayServiceConfig {
    fn default() -> Self {
        Self {
            relay_id: "local-atp-relay".to_owned(),
            max_active_reservations: 1024,
            udp_enabled: true,
            tcp_tls_443_enabled: true,
            retain_state_on_restart: true,
            log_peer_ids: false,
        }
    }
}

/// Relay path candidate emitted after a reservation is accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPathCandidate {
    reservation_id: RelayReservationId,
    path_id: String,
    primary_transport: RelayTransport,
    fallback_transport: Option<RelayTransport>,
    relay_id: String,
}

impl RelayPathCandidate {
    /// Reservation id backing this path.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.reservation_id
    }

    /// Path id used by path racing and proof artifacts.
    #[must_use]
    pub fn path_id(&self) -> &str {
        &self.path_id
    }

    /// Primary transport, preferring UDP when available.
    #[must_use]
    pub const fn primary_transport(&self) -> RelayTransport {
        self.primary_transport
    }

    /// Optional fallback transport.
    #[must_use]
    pub const fn fallback_transport(&self) -> Option<RelayTransport> {
        self.fallback_transport
    }

    /// Relay id selected for this path.
    #[must_use]
    pub fn relay_id(&self) -> &str {
        &self.relay_id
    }

    /// Shared path graph kind represented by the primary relay transport.
    #[must_use]
    pub const fn path_kind(&self) -> PathKind {
        self.primary_transport.path_kind()
    }

    /// Shared path graph kind represented by the fallback relay transport.
    #[must_use]
    pub fn fallback_path_kind(&self) -> Option<PathKind> {
        self.fallback_transport.map(RelayTransport::path_kind)
    }

    /// Convert this relay reservation into the shared ATP path graph model.
    ///
    /// The caller supplies the path-candidate id and trace id because those are
    /// race-local identities. The relay reservation id remains in the relay
    /// proof artifact, while the path graph receives the transport kind,
    /// security defaults, and deterministic attempt budget it needs for racing
    /// and loser-drain diagnostics.
    #[must_use]
    pub fn to_path_candidate(&self, id: PathCandidateId, trace_id: PathTraceId) -> PathCandidate {
        let kind = self.path_kind();
        PathCandidate::new(id, kind, trace_id)
            .with_budget(PathBudget::default())
            .with_security(PathSecurity::for_kind(kind))
    }
}

/// Packet emitted from a relay queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedPacket {
    reservation_id: RelayReservationId,
    from_peer_id: PeerId,
    to_peer_id: PeerId,
    packet: OpaqueRelayPacket,
    received_at_micros: u64,
}

impl ForwardedPacket {
    /// Reservation id used for the forwarded packet.
    #[must_use]
    pub const fn reservation_id(&self) -> RelayReservationId {
        self.reservation_id
    }

    /// Source peer.
    #[must_use]
    pub const fn from_peer_id(&self) -> PeerId {
        self.from_peer_id
    }

    /// Destination peer.
    #[must_use]
    pub const fn to_peer_id(&self) -> PeerId {
        self.to_peer_id
    }

    /// Opaque packet forwarded unchanged.
    #[must_use]
    pub const fn packet(&self) -> &OpaqueRelayPacket {
        &self.packet
    }

    /// Relay receive timestamp.
    #[must_use]
    pub const fn received_at_micros(&self) -> u64 {
        self.received_at_micros
    }
}

/// Packet loss summary for a reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLossSummary {
    /// Lost packets.
    pub lost_packets: u64,
    /// Total packets considered.
    pub total_packets: u64,
    /// Loss ratio in parts per million.
    pub loss_ppm: u32,
}

/// Per-reservation forwarding counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayUsage {
    /// Forwarded packet count.
    pub forwarded_packets: u64,
    /// Forwarded opaque byte count.
    pub forwarded_bytes: u64,
    /// Packets intentionally dropped or reported lost.
    pub dropped_packets: u64,
    /// Packets forwarded over UDP.
    pub udp_packets: u64,
    /// Packets forwarded over TCP/TLS 443.
    pub tcp_tls_443_packets: u64,
    /// Most recent loss summary.
    pub loss_summary: Option<RelayLossSummary>,
}

/// Redaction-safe relay event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayEventKind {
    /// Reservation accepted.
    ReservationAccepted,
    /// Packet forwarded.
    PacketForwarded,
    /// Packet loss recorded.
    PacketLossRecorded,
    /// Quota rejected a packet or reservation.
    QuotaRejected,
    /// Authorization rejected a grant or packet sender.
    AuthorizationRejected,
    /// Reservation expired.
    ReservationExpired,
    /// Reservation cancelled.
    ReservationCancelled,
    /// State restored after restart.
    RestartRestored,
}

/// Redaction-safe relay event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEvent {
    /// Event kind.
    pub kind: RelayEventKind,
    /// Relay id.
    pub relay_id: String,
    /// Reservation id, when scoped to one reservation.
    pub reservation_id: Option<RelayReservationId>,
    /// Transfer nonce, when scoped to one transfer.
    pub transfer_nonce: Option<TransferNonce>,
    /// Path id, when available.
    pub path_id: Option<String>,
    /// Redacted source peer id.
    pub from_peer: Option<String>,
    /// Redacted destination peer id.
    pub to_peer: Option<String>,
    /// Relay transport, when applicable.
    pub transport: Option<RelayTransport>,
    /// Opaque byte count.
    pub opaque_bytes: u64,
    /// Stable quota decision code.
    pub quota_decision: &'static str,
    /// Fallback reason, when TCP/TLS 443 is used.
    pub fallback_reason: Option<&'static str>,
    /// Deterministic replay pointer.
    pub replay_pointer: u64,
}

/// Proof artifact for path diagnostics and replay logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayProofArtifact {
    /// Relay id.
    pub relay_id: String,
    /// Reservation id.
    pub reservation_id: RelayReservationId,
    /// Transfer nonce.
    pub transfer_nonce: TransferNonce,
    /// Path id used by path racing.
    pub path_id: String,
    /// Primary transport.
    pub primary_transport: RelayTransport,
    /// Optional fallback transport.
    pub fallback_transport: Option<RelayTransport>,
    /// Reservation acceptance time in monotonic microseconds.
    pub accepted_at_micros: u64,
    /// Stable quota decision code.
    pub quota_decision: &'static str,
    /// Stable fallback reason code.
    pub fallback_reason: Option<&'static str>,
    /// Opaque bytes forwarded.
    pub opaque_bytes_forwarded: u64,
    /// Packets forwarded.
    pub packets_forwarded: u64,
    /// Loss summary, if recorded.
    pub loss_summary: Option<RelayLossSummary>,
    /// Redacted source peer id.
    pub redacted_source_peer: String,
    /// Redacted destination peer id.
    pub redacted_destination_peer: String,
    /// Replay pointer for deterministic logs.
    pub replay_pointer: u64,
    /// Relay preserved end-to-end proof tags without minting verified chunks.
    pub e2e_proof_preserved: bool,
}

impl RelayProofArtifact {
    /// Convert relay proof telemetry into a shared path-race success outcome.
    ///
    /// The relay still does not verify object plaintext or mint verified
    /// chunks. The byte counters copied into the path outcome are opaque relay
    /// bytes used for diagnostics and replay correlation.
    #[must_use]
    pub const fn to_path_success_outcome(
        &self,
        completed_at_micros: u64,
        observed_rtt_micros: Option<u64>,
    ) -> PathOutcome {
        PathOutcome::success(
            PathSuccessKind::RelaySelected,
            completed_at_micros,
            observed_rtt_micros,
        )
        .with_bytes(self.opaque_bytes_forwarded, self.opaque_bytes_forwarded)
    }
}

/// Restart snapshot for self-hosted relay recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRestartSnapshot {
    config: RelayServiceConfig,
    reservations: Vec<(RelayReservationId, RelayReservationState)>,
    usage: Vec<(RelayReservationId, RelayUsage)>,
    queues: Vec<(PeerId, Vec<ForwardedPacket>)>,
    events: Vec<RelayEvent>,
    replay_pointer: u64,
}

impl RelayRestartSnapshot {
    /// Number of active reservations captured.
    #[must_use]
    pub fn reservation_count(&self) -> usize {
        self.reservations.len()
    }
}

/// In-memory deterministic relay service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayService {
    config: RelayServiceConfig,
    reservations: BTreeMap<RelayReservationId, RelayReservationState>,
    usage: BTreeMap<RelayReservationId, RelayUsage>,
    queues: BTreeMap<PeerId, VecDeque<ForwardedPacket>>,
    events: Vec<RelayEvent>,
    replay_pointer: u64,
}

impl RelayService {
    /// Construct an empty relay service.
    #[must_use]
    pub fn new(config: RelayServiceConfig) -> Self {
        Self {
            config,
            reservations: BTreeMap::new(),
            usage: BTreeMap::new(),
            queues: BTreeMap::new(),
            events: Vec::new(),
            replay_pointer: 0,
        }
    }

    /// Relay service config.
    #[must_use]
    pub const fn config(&self) -> &RelayServiceConfig {
        &self.config
    }

    /// Redaction-safe event log.
    #[must_use]
    pub fn events(&self) -> &[RelayEvent] {
        &self.events
    }

    /// Per-reservation usage counters.
    #[must_use]
    pub fn usage(&self, reservation_id: RelayReservationId) -> Option<RelayUsage> {
        self.usage.get(&reservation_id).copied()
    }

    /// Accept a relay reservation and emit a path candidate.
    ///
    /// # Errors
    ///
    /// Returns an error when auth, expiry, quota, transport, or path-id
    /// validation fails.
    pub fn reserve<V>(
        &mut self,
        now_micros: u64,
        reservation_id: RelayReservationId,
        path_id: impl Into<String>,
        grant: RelayReservationGrant,
        verifier: &V,
    ) -> Result<RelayPathCandidate, RelayError>
    where
        V: RelayAuthorizationVerifier,
    {
        let path_id = path_id.into();
        if path_id.trim().is_empty() {
            return Err(RelayError::EmptyPathId);
        }
        if !verifier.verify(&grant) {
            self.push_event(RelayEventDraft {
                kind: RelayEventKind::AuthorizationRejected,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(grant.transfer_nonce),
                path_id: Some(path_id.clone()),
                from_peer: Some(grant.source_peer_id),
                to_peer: Some(grant.destination_peer_id),
                transport: None,
                opaque_bytes: 0,
                quota_decision: "grant_authorization_rejected",
                fallback_reason: None,
            });
            return Err(RelayError::InvalidAuthorization);
        }
        if grant.expires_at_micros <= now_micros {
            return Err(RelayError::ExpiredReservation);
        }
        let _expired_reservations = self.expire_reservations(now_micros);
        if self.reservations.contains_key(&reservation_id) {
            return Err(RelayError::DuplicateReservation);
        }
        if self.active_reservation_count(now_micros) >= self.config.max_active_reservations {
            self.push_event(RelayEventDraft {
                kind: RelayEventKind::QuotaRejected,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(grant.transfer_nonce),
                path_id: Some(path_id.clone()),
                from_peer: Some(grant.source_peer_id),
                to_peer: Some(grant.destination_peer_id),
                transport: None,
                opaque_bytes: 0,
                quota_decision: "active_reservation_quota_rejected",
                fallback_reason: None,
            });
            return Err(RelayError::QuotaExceeded);
        }

        let (primary_transport, fallback_transport) = self.select_transports(&grant)?;
        let state = RelayReservationState {
            grant,
            path_id: path_id.clone(),
            accepted_at_micros: now_micros,
            primary_transport,
            fallback_transport,
            cancelled: false,
            expired: false,
        };

        self.push_event(RelayEventDraft {
            kind: RelayEventKind::ReservationAccepted,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(path_id.clone()),
            from_peer: Some(state.grant.source_peer_id),
            to_peer: Some(state.grant.destination_peer_id),
            transport: Some(primary_transport),
            opaque_bytes: 0,
            quota_decision: "reservation_accepted",
            fallback_reason: primary_transport.fallback_reason(),
        });

        let candidate = RelayPathCandidate {
            reservation_id,
            path_id,
            primary_transport,
            fallback_transport,
            relay_id: self.config.relay_id.clone(),
        };
        self.reservations.insert(reservation_id, state);
        self.usage.insert(reservation_id, RelayUsage::default());
        Ok(candidate)
    }

    /// Forward an opaque encrypted packet between authorized peers.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unknown, unauthorized, expired,
    /// cancelled, over quota, or uses an unavailable transport.
    pub fn forward(
        &mut self,
        now_micros: u64,
        reservation_id: RelayReservationId,
        from_peer_id: PeerId,
        packet: OpaqueRelayPacket,
    ) -> Result<ForwardedPacket, RelayError> {
        let state = self
            .reservations
            .get(&reservation_id)
            .cloned()
            .ok_or(RelayError::UnknownReservation)?;

        let to_peer_id = if from_peer_id == state.grant.source_peer_id {
            state.grant.destination_peer_id
        } else if from_peer_id == state.grant.destination_peer_id {
            state.grant.source_peer_id
        } else {
            self.push_event(RelayEventDraft {
                kind: RelayEventKind::AuthorizationRejected,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(state.grant.transfer_nonce),
                path_id: Some(state.path_id.clone()),
                from_peer: Some(from_peer_id),
                to_peer: None,
                transport: Some(packet.transport),
                opaque_bytes: packet.opaque_len() as u64,
                quota_decision: "peer_authorization_rejected",
                fallback_reason: None,
            });
            return Err(RelayError::UnauthorizedPeer);
        };

        if state.cancelled {
            return Err(RelayError::ReservationCancelled);
        }
        if state.expired || state.grant.expires_at_micros <= now_micros {
            self.expire_reservation(reservation_id)?;
            return Err(RelayError::ExpiredReservation);
        }

        if !state.grant.allows_transport(packet.transport)
            || !self.transport_available(packet.transport)
        {
            return Err(RelayError::TransportUnavailable);
        }

        self.apply_quota(reservation_id, &state, from_peer_id, to_peer_id, &packet)?;

        let forwarded = ForwardedPacket {
            reservation_id,
            from_peer_id,
            to_peer_id,
            packet,
            received_at_micros: now_micros,
        };

        self.queues
            .entry(to_peer_id)
            .or_default()
            .push_back(forwarded.clone());

        self.push_event(RelayEventDraft {
            kind: RelayEventKind::PacketForwarded,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(state.path_id.clone()),
            from_peer: Some(from_peer_id),
            to_peer: Some(to_peer_id),
            transport: Some(forwarded.packet.transport),
            opaque_bytes: forwarded.packet.opaque_len() as u64,
            quota_decision: "packet_accepted",
            fallback_reason: forwarded.packet.transport.fallback_reason(),
        });

        Ok(forwarded)
    }

    /// Dequeue the next forwarded packet for a peer.
    #[must_use]
    pub fn dequeue_for_peer(&mut self, peer_id: PeerId) -> Option<ForwardedPacket> {
        let forwarded = self.queues.get_mut(&peer_id).and_then(VecDeque::pop_front);
        if self.queues.get(&peer_id).is_some_and(VecDeque::is_empty) {
            self.queues.remove(&peer_id);
        }
        forwarded
    }

    /// Cancel a reservation under structured cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownReservation`] when the reservation is absent.
    pub fn cancel_reservation(
        &mut self,
        reservation_id: RelayReservationId,
    ) -> Result<(), RelayError> {
        let already_terminal = self
            .reservations
            .get(&reservation_id)
            .ok_or(RelayError::UnknownReservation)?
            .is_terminal();
        if already_terminal {
            return Ok(());
        }

        let (dropped_queued_packets, dropped_queued_bytes) =
            self.drain_queued_packets_for_reservation(reservation_id);
        if let Some(usage) = self.usage.get_mut(&reservation_id) {
            usage.dropped_packets = usage.dropped_packets.saturating_add(dropped_queued_packets);
        }

        let event = {
            let state = self
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            state.cancelled = true;
            let usage_snapshot = self.usage.get(&reservation_id).copied().unwrap_or_default();
            RelayEventDraft {
                kind: RelayEventKind::ReservationCancelled,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(state.grant.transfer_nonce),
                path_id: Some(state.path_id.clone()),
                from_peer: Some(state.grant.source_peer_id),
                to_peer: Some(state.grant.destination_peer_id),
                transport: Some(state.primary_transport),
                opaque_bytes: dropped_queued_bytes,
                quota_decision: if dropped_queued_packets == 0 {
                    "reservation_cancelled"
                } else {
                    "reservation_cancelled_queued_packets_drained"
                },
                fallback_reason: Self::fallback_reason_for_usage(state, usage_snapshot),
            }
        };
        self.push_event(event);
        Ok(())
    }

    /// Expire every live reservation whose grant is no longer valid.
    ///
    /// Expiration is a lifecycle transition, not just a forward-time rejection:
    /// queued packets are drained, drop counters are updated, and restart
    /// snapshots stop retaining the expired reservation.
    #[must_use]
    pub fn expire_reservations(&mut self, now_micros: u64) -> usize {
        let expired_ids = self
            .reservations
            .iter()
            .filter(|(_, state)| {
                !state.is_terminal() && state.grant.expires_at_micros <= now_micros
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut expired_count = 0;

        for reservation_id in expired_ids {
            if self.expire_reservation(reservation_id).is_ok() {
                expired_count += 1;
            }
        }

        expired_count
    }

    /// Record a packet loss summary for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown reservations, invalid totals, or
    /// reservations that already reached a terminal lifecycle state.
    pub fn record_packet_loss(
        &mut self,
        reservation_id: RelayReservationId,
        lost_packets: u64,
        total_packets: u64,
    ) -> Result<RelayLossSummary, RelayError> {
        let state = self
            .reservations
            .get(&reservation_id)
            .cloned()
            .ok_or(RelayError::UnknownReservation)?;
        if state.cancelled {
            return Err(RelayError::ReservationCancelled);
        }
        if state.expired {
            return Err(RelayError::ExpiredReservation);
        }
        if total_packets == 0 || lost_packets > total_packets {
            return Err(RelayError::InvalidLossSummary);
        }

        let loss_ppm_u64 = lost_packets.saturating_mul(1_000_000) / total_packets;
        let loss_ppm = u32::try_from(loss_ppm_u64).map_err(|_| RelayError::InvalidLossSummary)?;
        let summary = RelayLossSummary {
            lost_packets,
            total_packets,
            loss_ppm,
        };
        let usage_snapshot = {
            let usage = self
                .usage
                .get_mut(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            usage.dropped_packets = usage.dropped_packets.saturating_add(lost_packets);
            usage.loss_summary = Some(summary);
            *usage
        };

        self.push_event(RelayEventDraft {
            kind: RelayEventKind::PacketLossRecorded,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(state.path_id.clone()),
            from_peer: Some(state.grant.source_peer_id),
            to_peer: Some(state.grant.destination_peer_id),
            transport: Some(state.primary_transport),
            opaque_bytes: usage_snapshot.forwarded_bytes,
            quota_decision: "loss_summary_recorded",
            fallback_reason: Self::fallback_reason_for_usage(&state, usage_snapshot),
        });

        Ok(summary)
    }

    /// Build a deterministic restart snapshot.
    #[must_use]
    pub fn snapshot(&self) -> RelayRestartSnapshot {
        let (reservations, usage, queues) = if self.config.retain_state_on_restart {
            let retained_reservation_ids = self
                .reservations
                .iter()
                .filter(|(_, state)| !state.is_terminal())
                .map(|(id, _)| *id)
                .collect::<BTreeSet<_>>();
            (
                self.reservations
                    .iter()
                    .filter(|(id, _)| retained_reservation_ids.contains(*id))
                    .map(|(id, state)| (*id, state.clone()))
                    .collect(),
                self.usage
                    .iter()
                    .filter(|(id, _)| retained_reservation_ids.contains(*id))
                    .map(|(id, usage)| (*id, *usage))
                    .collect(),
                self.queues
                    .iter()
                    .filter_map(|(peer, queue)| {
                        let retained_packets = queue
                            .iter()
                            .filter(|packet| {
                                retained_reservation_ids.contains(&packet.reservation_id)
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        if retained_packets.is_empty() {
                            None
                        } else {
                            Some((*peer, retained_packets))
                        }
                    })
                    .collect(),
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        RelayRestartSnapshot {
            config: self.config.clone(),
            reservations,
            usage,
            queues,
            events: self.events.clone(),
            replay_pointer: self.replay_pointer,
        }
    }

    /// Restore relay service state after restart.
    #[must_use]
    pub fn restore(snapshot: RelayRestartSnapshot) -> Self {
        let mut service = Self {
            config: snapshot.config,
            reservations: snapshot.reservations.into_iter().collect(),
            usage: snapshot.usage.into_iter().collect(),
            queues: snapshot
                .queues
                .into_iter()
                .map(|(peer, packets)| (peer, VecDeque::from(packets)))
                .collect(),
            events: snapshot.events,
            replay_pointer: snapshot.replay_pointer,
        };
        service.push_event(RelayEventDraft {
            kind: RelayEventKind::RestartRestored,
            reservation_id: None,
            transfer_nonce: None,
            path_id: None,
            from_peer: None,
            to_peer: None,
            transport: None,
            opaque_bytes: 0,
            quota_decision: "restart_restored",
            fallback_reason: None,
        });
        service
    }

    /// Build a relay proof artifact.
    ///
    /// # Errors
    ///
    /// Returns [`RelayError::UnknownReservation`] when the reservation is absent.
    pub fn proof_artifact(
        &self,
        reservation_id: RelayReservationId,
    ) -> Result<RelayProofArtifact, RelayError> {
        let state = self
            .reservations
            .get(&reservation_id)
            .ok_or(RelayError::UnknownReservation)?;
        let usage = self
            .usage
            .get(&reservation_id)
            .copied()
            .ok_or(RelayError::UnknownReservation)?;

        Ok(RelayProofArtifact {
            relay_id: self.config.relay_id.clone(),
            reservation_id,
            transfer_nonce: state.grant.transfer_nonce,
            path_id: state.path_id.clone(),
            primary_transport: state.primary_transport,
            fallback_transport: state.fallback_transport,
            accepted_at_micros: state.accepted_at_micros,
            quota_decision: "quota_accounted",
            fallback_reason: Self::fallback_reason_for_usage(state, usage),
            opaque_bytes_forwarded: usage.forwarded_bytes,
            packets_forwarded: usage.forwarded_packets,
            loss_summary: usage.loss_summary,
            redacted_source_peer: self.redact_peer(state.grant.source_peer_id),
            redacted_destination_peer: self.redact_peer(state.grant.destination_peer_id),
            replay_pointer: self.replay_pointer,
            e2e_proof_preserved: true,
        })
    }

    fn active_reservation_count(&self, now_micros: u64) -> usize {
        self.reservations
            .values()
            .filter(|state| !state.is_terminal() && state.grant.expires_at_micros > now_micros)
            .count()
    }

    fn select_transports(
        &self,
        grant: &RelayReservationGrant,
    ) -> Result<(RelayTransport, Option<RelayTransport>), RelayError> {
        let udp_available = grant.allows_transport(RelayTransport::Udp) && self.config.udp_enabled;
        let tcp_available =
            grant.allows_transport(RelayTransport::TcpTls443) && self.config.tcp_tls_443_enabled;

        match (udp_available, tcp_available) {
            (true, true) => Ok((RelayTransport::Udp, Some(RelayTransport::TcpTls443))),
            (true, false) => Ok((RelayTransport::Udp, None)),
            (false, true) => Ok((RelayTransport::TcpTls443, None)),
            (false, false) => Err(RelayError::TransportUnavailable),
        }
    }

    fn fallback_reason_for_usage(
        state: &RelayReservationState,
        usage: RelayUsage,
    ) -> Option<&'static str> {
        if state.primary_transport == RelayTransport::TcpTls443 || usage.tcp_tls_443_packets > 0 {
            RelayTransport::TcpTls443.fallback_reason()
        } else {
            None
        }
    }

    fn expire_reservation(&mut self, reservation_id: RelayReservationId) -> Result<(), RelayError> {
        let already_expired_or_cancelled = {
            let state = self
                .reservations
                .get(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            state.is_terminal()
        };
        if already_expired_or_cancelled {
            return Ok(());
        }

        let (dropped_queued_packets, dropped_queued_bytes) =
            self.drain_queued_packets_for_reservation(reservation_id);
        if let Some(usage) = self.usage.get_mut(&reservation_id) {
            usage.dropped_packets = usage.dropped_packets.saturating_add(dropped_queued_packets);
        }

        let event = {
            let state = self
                .reservations
                .get_mut(&reservation_id)
                .ok_or(RelayError::UnknownReservation)?;
            state.expired = true;
            let usage_snapshot = self.usage.get(&reservation_id).copied().unwrap_or_default();
            RelayEventDraft {
                kind: RelayEventKind::ReservationExpired,
                reservation_id: Some(reservation_id),
                transfer_nonce: Some(state.grant.transfer_nonce),
                path_id: Some(state.path_id.clone()),
                from_peer: Some(state.grant.source_peer_id),
                to_peer: Some(state.grant.destination_peer_id),
                transport: Some(state.primary_transport),
                opaque_bytes: dropped_queued_bytes,
                quota_decision: if dropped_queued_packets == 0 {
                    "reservation_expired"
                } else {
                    "reservation_expired_queued_packets_drained"
                },
                fallback_reason: Self::fallback_reason_for_usage(state, usage_snapshot),
            }
        };
        self.push_event(event);
        Ok(())
    }

    fn transport_available(&self, transport: RelayTransport) -> bool {
        match transport {
            RelayTransport::Udp => self.config.udp_enabled,
            RelayTransport::TcpTls443 => self.config.tcp_tls_443_enabled,
        }
    }

    fn apply_quota(
        &mut self,
        reservation_id: RelayReservationId,
        state: &RelayReservationState,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
        packet: &OpaqueRelayPacket,
    ) -> Result<(), RelayError> {
        let packet_len = packet.opaque_len();
        if packet_len > state.grant.quota.max_packet_bytes {
            self.push_quota_rejected(reservation_id, state, from_peer_id, to_peer_id, packet);
            return Err(RelayError::PacketTooLarge);
        }

        let packet_len_u64 = u64::try_from(packet_len).map_err(|_| RelayError::QuotaExceeded)?;
        let usage = self
            .usage
            .get_mut(&reservation_id)
            .ok_or(RelayError::UnknownReservation)?;
        if usage.forwarded_packets >= state.grant.quota.max_packets_per_reservation {
            self.push_quota_rejected(reservation_id, state, from_peer_id, to_peer_id, packet);
            return Err(RelayError::QuotaExceeded);
        }

        let next_bytes = usage
            .forwarded_bytes
            .checked_add(packet_len_u64)
            .ok_or(RelayError::QuotaExceeded)?;
        if next_bytes > state.grant.quota.max_bytes_per_reservation {
            self.push_quota_rejected(reservation_id, state, from_peer_id, to_peer_id, packet);
            return Err(RelayError::QuotaExceeded);
        }

        usage.forwarded_packets += 1;
        usage.forwarded_bytes = next_bytes;
        match packet.transport {
            RelayTransport::Udp => usage.udp_packets += 1,
            RelayTransport::TcpTls443 => usage.tcp_tls_443_packets += 1,
        }
        Ok(())
    }

    fn drain_queued_packets_for_reservation(
        &mut self,
        reservation_id: RelayReservationId,
    ) -> (u64, u64) {
        let mut dropped_packets = 0_u64;
        let mut dropped_bytes = 0_u64;
        let mut empty_peers = Vec::new();

        for (peer_id, queue) in &mut self.queues {
            queue.retain(|forwarded| {
                if forwarded.reservation_id == reservation_id {
                    dropped_packets = dropped_packets.saturating_add(1);
                    dropped_bytes =
                        dropped_bytes.saturating_add(forwarded.packet.opaque_len() as u64);
                    false
                } else {
                    true
                }
            });
            if queue.is_empty() {
                empty_peers.push(*peer_id);
            }
        }

        for peer_id in empty_peers {
            self.queues.remove(&peer_id);
        }

        (dropped_packets, dropped_bytes)
    }

    fn push_quota_rejected(
        &mut self,
        reservation_id: RelayReservationId,
        state: &RelayReservationState,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
        packet: &OpaqueRelayPacket,
    ) {
        self.push_event(RelayEventDraft {
            kind: RelayEventKind::QuotaRejected,
            reservation_id: Some(reservation_id),
            transfer_nonce: Some(state.grant.transfer_nonce),
            path_id: Some(state.path_id.clone()),
            from_peer: Some(from_peer_id),
            to_peer: Some(to_peer_id),
            transport: Some(packet.transport),
            opaque_bytes: packet.opaque_len() as u64,
            quota_decision: "packet_quota_rejected",
            fallback_reason: packet.transport.fallback_reason(),
        });
    }

    fn push_event(&mut self, draft: RelayEventDraft) {
        self.replay_pointer = self.replay_pointer.saturating_add(1);
        self.events.push(RelayEvent {
            kind: draft.kind,
            relay_id: self.config.relay_id.clone(),
            reservation_id: draft.reservation_id,
            transfer_nonce: draft.transfer_nonce,
            path_id: draft.path_id,
            from_peer: draft.from_peer.map(|peer| self.redact_peer(peer)),
            to_peer: draft.to_peer.map(|peer| self.redact_peer(peer)),
            transport: draft.transport,
            opaque_bytes: draft.opaque_bytes,
            quota_decision: draft.quota_decision,
            fallback_reason: draft.fallback_reason,
            replay_pointer: self.replay_pointer,
        });
    }

    fn redact_peer(&self, peer_id: PeerId) -> String {
        if !self.config.log_peer_ids {
            return "peer:redacted".to_owned();
        }

        let bytes = peer_id.bytes();
        format!("peer:{:02x}{:02x}...", bytes[0], bytes[1])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayReservationState {
    grant: RelayReservationGrant,
    path_id: String,
    accepted_at_micros: u64,
    primary_transport: RelayTransport,
    fallback_transport: Option<RelayTransport>,
    cancelled: bool,
    expired: bool,
}

impl RelayReservationState {
    fn is_terminal(&self) -> bool {
        self.cancelled || self.expired
    }
}

#[derive(Debug)]
struct RelayEventDraft {
    kind: RelayEventKind,
    reservation_id: Option<RelayReservationId>,
    transfer_nonce: Option<TransferNonce>,
    path_id: Option<String>,
    from_peer: Option<PeerId>,
    to_peer: Option<PeerId>,
    transport: Option<RelayTransport>,
    opaque_bytes: u64,
    quota_decision: &'static str,
    fallback_reason: Option<&'static str>,
}

/// Relay service errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// Reservation id was zero.
    #[error("relay reservation id is zero")]
    ZeroReservationId,
    /// Relay id was empty.
    #[error("relay id is empty")]
    EmptyRelayId,
    /// Path id was empty.
    #[error("relay path id is empty")]
    EmptyPathId,
    /// Packet payload was empty.
    #[error("relay packet is empty")]
    EmptyPacket,
    /// Quota was invalid.
    #[error("relay quota is invalid")]
    InvalidQuota,
    /// Proof tag was invalid.
    #[error("relay proof tag is invalid")]
    InvalidProofTag,
    /// Reservation connects the same peer to itself.
    #[error("relay reservation cannot loop back to the same peer")]
    LoopbackReservation,
    /// Reservation id already exists.
    #[error("duplicate relay reservation")]
    DuplicateReservation,
    /// Reservation does not exist.
    #[error("unknown relay reservation")]
    UnknownReservation,
    /// Reservation or grant has expired.
    #[error("expired relay reservation")]
    ExpiredReservation,
    /// Reservation was cancelled.
    #[error("relay reservation was cancelled")]
    ReservationCancelled,
    /// Peer is not authorized for this reservation.
    #[error("unauthorized relay peer")]
    UnauthorizedPeer,
    /// Relay authorization failed.
    #[error("invalid relay authorization")]
    InvalidAuthorization,
    /// Transport is not allowed or unavailable.
    #[error("relay transport unavailable")]
    TransportUnavailable,
    /// Quota was exceeded.
    #[error("relay quota exceeded")]
    QuotaExceeded,
    /// Packet exceeds per-packet quota.
    #[error("relay packet too large")]
    PacketTooLarge,
    /// Packet loss summary is invalid.
    #[error("invalid relay loss summary")]
    InvalidLossSummary,
}

impl RelayError {
    /// Map relay-specific failures into the shared path graph failure taxonomy.
    #[must_use]
    pub const fn path_failure_kind(self) -> PathFailureKind {
        match self {
            Self::InvalidAuthorization | Self::UnauthorizedPeer => PathFailureKind::AuthFailure,
            Self::TransportUnavailable
            | Self::UnknownReservation
            | Self::ExpiredReservation
            | Self::ReservationCancelled => PathFailureKind::RelayUnavailable,
            Self::QuotaExceeded | Self::PacketTooLarge | Self::InvalidQuota => {
                PathFailureKind::PolicyDenied
            }
            Self::ZeroReservationId
            | Self::EmptyRelayId
            | Self::EmptyPathId
            | Self::EmptyPacket
            | Self::InvalidProofTag
            | Self::LoopbackReservation
            | Self::DuplicateReservation
            | Self::InvalidLossSummary => PathFailureKind::ProtocolError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::new([seed; 32]).expect("peer")
    }

    fn transfer_nonce(raw: u128) -> TransferNonce {
        TransferNonce::new(raw).expect("transfer nonce")
    }

    fn reservation_id(raw: u128) -> RelayReservationId {
        RelayReservationId::new(raw).expect("reservation id")
    }

    fn proof_tag(seed: u8) -> ProofTag {
        ProofTag::new([seed; 32]).expect("proof tag")
    }

    fn signature() -> CandidateSignature {
        CandidateSignature::new(vec![1, 2, 3]).expect("signature")
    }

    fn grant(expires_at_micros: u64, quota: RelayQuota) -> RelayReservationGrant {
        RelayReservationGrant::udp_first_tcp_tls_443(
            peer(1),
            peer(2),
            transfer_nonce(9),
            expires_at_micros,
            quota,
            signature(),
        )
        .expect("grant")
    }

    fn packet(transport: RelayTransport, payload: &[u8], sequence: u64) -> OpaqueRelayPacket {
        OpaqueRelayPacket::new(sequence, transport, payload.to_vec(), proof_tag(7), 10)
            .expect("packet")
    }

    #[test]
    fn udp_first_reservation_emits_tcp_tls_443_fallback_candidate() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        let candidate = service
            .reserve(
                10,
                reservation_id(1),
                "path-relay-1",
                grant(1_000, RelayQuota::default()),
                &|grant: &RelayReservationGrant| grant.signature().bytes() == [1, 2, 3],
            )
            .expect("reservation");

        assert_eq!(candidate.primary_transport(), RelayTransport::Udp);
        assert_eq!(
            candidate.fallback_transport(),
            Some(RelayTransport::TcpTls443)
        );
        assert_eq!(candidate.path_id(), "path-relay-1");
        assert_eq!(service.events()[0].quota_decision, "reservation_accepted");
        assert_eq!(service.events()[0].fallback_reason, None);
    }

    #[test]
    fn tcp_tls_443_is_selected_when_udp_is_disabled() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);

        let candidate = service
            .reserve(
                10,
                reservation_id(2),
                "path-relay-2",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(candidate.primary_transport(), RelayTransport::TcpTls443);
        assert_eq!(
            candidate.primary_transport().fallback_reason(),
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn relay_candidate_converts_to_path_graph_candidate() {
        let config = RelayServiceConfig::default().with_udp_enabled(false);
        let mut service = RelayService::new(config);
        let relay_candidate = service
            .reserve(
                10,
                reservation_id(33),
                "path-relay-33",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(relay_candidate.path_kind(), PathKind::AtpRelayTcpTls443);
        assert_eq!(relay_candidate.fallback_path_kind(), None);

        let path_candidate =
            relay_candidate.to_path_candidate(PathCandidateId::new(333), PathTraceId::new(333_000));
        assert_eq!(path_candidate.id, PathCandidateId::new(333));
        assert_eq!(path_candidate.kind, PathKind::AtpRelayTcpTls443);
        assert_eq!(path_candidate.trace_id, PathTraceId::new(333_000));
        assert!(path_candidate.security.authenticated_peer);
        assert!(path_candidate.security.end_to_end_encrypted);
        assert!(!path_candidate.security.exposes_local_ip_to_peer);
        assert!(path_candidate.security.relay_metadata_visible);
    }

    #[test]
    fn relay_proof_and_errors_convert_to_path_graph_outcomes() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(34),
                "path-relay-34",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(34),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        let proof = service
            .proof_artifact(reservation_id(34))
            .expect("proof artifact");
        let outcome = proof.to_path_success_outcome(30, Some(10));
        assert!(outcome.is_success());
        assert_eq!(outcome.observed_rtt_micros, Some(10));
        assert_eq!(outcome.bytes_sent, proof.opaque_bytes_forwarded);
        assert_eq!(outcome.bytes_received, proof.opaque_bytes_forwarded);

        assert_eq!(
            RelayError::InvalidAuthorization.path_failure_kind(),
            PathFailureKind::AuthFailure
        );
        assert_eq!(
            RelayError::TransportUnavailable.path_failure_kind(),
            PathFailureKind::RelayUnavailable
        );
        assert_eq!(
            RelayError::PacketTooLarge.path_failure_kind(),
            PathFailureKind::PolicyDenied
        );
        assert_eq!(
            RelayError::InvalidProofTag.path_failure_kind(),
            PathFailureKind::ProtocolError
        );
    }

    #[test]
    fn forwards_opaque_bytes_and_preserves_proof_tag() {
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(3),
                "path-relay-3",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let original = packet(RelayTransport::Udp, b"ciphertext", 42);
        let forwarded = service
            .forward(20, reservation_id(3), peer(1), original.clone())
            .expect("forward");

        assert_eq!(forwarded.to_peer_id(), peer(2));
        assert_eq!(forwarded.packet().opaque_bytes(), b"ciphertext");
        assert_eq!(forwarded.packet().proof_tag(), original.proof_tag());
        assert_eq!(
            service.dequeue_for_peer(peer(2)).expect("queued packet"),
            forwarded
        );
    }

    #[test]
    fn dequeue_removes_empty_peer_queue_from_restart_snapshot() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(25),
                "path-relay-25",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(25),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        assert!(service.dequeue_for_peer(peer(2)).is_some());
        let snapshot = service.snapshot();
        assert!(
            snapshot
                .queues
                .iter()
                .all(|(queued_peer, _)| *queued_peer != peer(2))
        );
        assert!(
            snapshot
                .queues
                .iter()
                .all(|(_, queued_packets)| !queued_packets.is_empty())
        );
    }

    #[test]
    fn rejects_quota_overflow_and_logs_rejection() {
        let quota = RelayQuota {
            max_packets_per_reservation: 1,
            max_bytes_per_reservation: 4,
            max_packet_bytes: 4,
        };
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(4),
                "path-relay-4",
                grant(1_000, quota),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        service
            .forward(
                20,
                reservation_id(4),
                peer(1),
                packet(RelayTransport::Udp, b"abcd", 1),
            )
            .expect("first packet");
        assert_eq!(
            service
                .forward(
                    21,
                    reservation_id(4),
                    peer(1),
                    packet(RelayTransport::Udp, b"e", 2)
                )
                .expect_err("quota"),
            RelayError::QuotaExceeded
        );
        assert!(
            service
                .events()
                .iter()
                .any(|event| event.kind == RelayEventKind::QuotaRejected)
        );
    }

    #[test]
    fn rejects_expired_reservations_and_unauthorized_peers() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    20,
                    reservation_id(5),
                    "expired",
                    grant(20, RelayQuota::default()),
                    &|_: &RelayReservationGrant| true,
                )
                .expect_err("expired"),
            RelayError::ExpiredReservation
        );

        service
            .reserve(
                10,
                reservation_id(6),
                "path-relay-6",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(6),
                    peer(3),
                    packet(RelayTransport::Udp, b"ciphertext", 1)
                )
                .expect_err("unauthorized"),
            RelayError::UnauthorizedPeer
        );
    }

    #[test]
    fn invalid_grant_authorization_is_logged_without_accepting_reservation() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    10,
                    reservation_id(17),
                    "path-relay-17",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("auth"),
            RelayError::InvalidAuthorization
        );

        let event = service.events().last().expect("auth event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(17)));
        assert_eq!(event.path_id.as_deref(), Some("path-relay-17"));
        assert_eq!(event.from_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.to_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.transport, None);
        assert_eq!(event.opaque_bytes, 0);
        assert_eq!(event.quota_decision, "grant_authorization_rejected");
        assert_eq!(
            service
                .proof_artifact(reservation_id(17))
                .expect_err("rejected reservation must not be installed"),
            RelayError::UnknownReservation
        );
    }

    #[test]
    fn invalid_grant_authorization_precedes_duplicate_and_capacity_checks() {
        let config = RelayServiceConfig::new("tiny-relay", 1).expect("config");
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(19),
                "path-relay-19",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .reserve(
                    11,
                    reservation_id(19),
                    "path-relay-duplicate-invalid",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid duplicate grant"),
            RelayError::InvalidAuthorization
        );
        assert_eq!(
            service
                .reserve(
                    12,
                    reservation_id(20),
                    "path-relay-over-capacity-invalid",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid over-capacity grant"),
            RelayError::InvalidAuthorization
        );

        let auth_rejections = service
            .events()
            .iter()
            .filter(|event| event.kind == RelayEventKind::AuthorizationRejected)
            .count();
        assert_eq!(auth_rejections, 2);
        assert!(
            service
                .events()
                .iter()
                .all(|event| event.quota_decision != "active_reservation_quota_rejected")
        );
    }

    #[test]
    fn invalid_grant_authorization_precedes_expiry_check() {
        let mut service = RelayService::new(RelayServiceConfig::default());

        assert_eq!(
            service
                .reserve(
                    20,
                    reservation_id(32),
                    "path-relay-32",
                    grant(20, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("invalid expired grant"),
            RelayError::InvalidAuthorization
        );

        let event = service.events().last().expect("auth rejection event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(32)));
        assert_eq!(event.quota_decision, "grant_authorization_rejected");
        assert_eq!(event.path_id.as_deref(), Some("path-relay-32"));
        assert_eq!(
            service
                .proof_artifact(reservation_id(32))
                .expect_err("invalid grant must not install expired reservation"),
            RelayError::UnknownReservation
        );
    }

    #[test]
    fn unauthorized_peer_rejection_is_logged_before_transport_policy() {
        let config = RelayServiceConfig::default().with_tcp_tls_443_enabled(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(18),
                "path-relay-18",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(18),
                    peer(9),
                    packet(RelayTransport::TcpTls443, b"ciphertext", 1),
                )
                .expect_err("unauthorized"),
            RelayError::UnauthorizedPeer
        );

        let event = service.events().last().expect("auth event");
        assert_eq!(event.kind, RelayEventKind::AuthorizationRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(18)));
        assert_eq!(event.from_peer.as_deref(), Some("peer:redacted"));
        assert_eq!(event.to_peer, None);
        assert_eq!(event.transport, Some(RelayTransport::TcpTls443));
        assert_eq!(event.opaque_bytes, 10);
        assert_eq!(event.quota_decision, "peer_authorization_rejected");
        assert_eq!(event.fallback_reason, None);
        assert_eq!(
            service.usage(reservation_id(18)).expect("usage"),
            RelayUsage::default()
        );
    }

    #[test]
    fn unauthorized_peer_rejection_precedes_lifecycle_state() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(21),
                "path-relay-21",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .cancel_reservation(reservation_id(21))
            .expect("cancel");

        assert_eq!(
            service
                .forward(
                    40,
                    reservation_id(21),
                    peer(9),
                    packet(RelayTransport::Udp, b"ciphertext", 1),
                )
                .expect_err("unauthorized cancellation probe"),
            RelayError::UnauthorizedPeer
        );
        let cancelled_probe_event = service.events().last().expect("auth event");
        assert_eq!(
            cancelled_probe_event.kind,
            RelayEventKind::AuthorizationRejected
        );
        assert_eq!(
            cancelled_probe_event.quota_decision,
            "peer_authorization_rejected"
        );

        service
            .reserve(
                10,
                reservation_id(22),
                "path-relay-22",
                grant(20, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        assert_eq!(
            service
                .forward(
                    30,
                    reservation_id(22),
                    peer(9),
                    packet(RelayTransport::Udp, b"ciphertext", 2),
                )
                .expect_err("unauthorized expiry probe"),
            RelayError::UnauthorizedPeer
        );
        let expired_probe_event = service.events().last().expect("auth event");
        assert_eq!(
            expired_probe_event.kind,
            RelayEventKind::AuthorizationRejected
        );
        assert!(
            service
                .events()
                .iter()
                .filter(|event| event.reservation_id == Some(reservation_id(22)))
                .all(|event| event.kind != RelayEventKind::ReservationExpired)
        );
    }

    #[test]
    fn quota_rejection_logs_actual_packet_direction() {
        let quota = RelayQuota {
            max_packets_per_reservation: 4,
            max_bytes_per_reservation: 4,
            max_packet_bytes: 4,
        };
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(23),
                "path-relay-23",
                grant(1_000, quota),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(23),
                    peer(2),
                    packet(RelayTransport::Udp, b"abcde", 1),
                )
                .expect_err("oversized reverse packet"),
            RelayError::PacketTooLarge
        );

        let event = service.events().last().expect("quota event");
        assert_eq!(event.kind, RelayEventKind::QuotaRejected);
        assert_eq!(event.reservation_id, Some(reservation_id(23)));
        assert_eq!(event.from_peer.as_deref(), Some("peer:0202..."));
        assert_eq!(event.to_peer.as_deref(), Some("peer:0101..."));
        assert_eq!(event.opaque_bytes, 5);
        assert_eq!(event.quota_decision, "packet_quota_rejected");
        assert_eq!(
            service.usage(reservation_id(23)).expect("usage"),
            RelayUsage::default()
        );
    }

    #[test]
    fn rejects_invalid_auth_and_cancelled_reservations() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        assert_eq!(
            service
                .reserve(
                    10,
                    reservation_id(7),
                    "path-relay-7",
                    grant(1_000, RelayQuota::default()),
                    &|_: &RelayReservationGrant| false,
                )
                .expect_err("auth"),
            RelayError::InvalidAuthorization
        );

        service
            .reserve(
                10,
                reservation_id(8),
                "path-relay-8",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .cancel_reservation(reservation_id(8))
            .expect("cancel");
        assert_eq!(
            service
                .forward(
                    20,
                    reservation_id(8),
                    peer(1),
                    packet(RelayTransport::Udp, b"ciphertext", 1)
                )
                .expect_err("cancelled"),
            RelayError::ReservationCancelled
        );
    }

    #[test]
    fn cancellation_drains_queued_packets_for_reservation() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(12),
                "path-relay-12",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(12),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        service
            .cancel_reservation(reservation_id(12))
            .expect("cancel");

        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        let usage = service.usage(reservation_id(12)).expect("usage");
        assert_eq!(usage.dropped_packets, 1);
        assert_eq!(
            service
                .events()
                .last()
                .expect("cancel event")
                .quota_decision,
            "reservation_cancelled_queued_packets_drained"
        );
    }

    #[test]
    fn cancel_reservation_is_idempotent_after_first_drain() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(24),
                "path-relay-24",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(24),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        service
            .cancel_reservation(reservation_id(24))
            .expect("first cancel");
        let events_after_first_cancel = service.events().len();
        let usage_after_first_cancel = service.usage(reservation_id(24)).expect("usage");
        service
            .cancel_reservation(reservation_id(24))
            .expect("second cancel");

        assert_eq!(service.events().len(), events_after_first_cancel);
        assert_eq!(
            service.usage(reservation_id(24)).expect("usage"),
            usage_after_first_cancel
        );
        assert_eq!(usage_after_first_cancel.dropped_packets, 1);
        assert_eq!(service.dequeue_for_peer(peer(2)), None);
    }

    #[test]
    fn expired_reservations_do_not_consume_active_capacity() {
        let config = RelayServiceConfig::new("tiny-relay", 1).expect("config");
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(13),
                "path-relay-13",
                grant(20, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("first reservation");

        let candidate = service
            .reserve(
                30,
                reservation_id(14),
                "path-relay-14",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("expired reservation should not occupy the only active slot");

        assert_eq!(candidate.reservation_id(), reservation_id(14));
        assert_eq!(service.snapshot().reservation_count(), 1);
        assert!(
            service
                .snapshot()
                .reservations
                .iter()
                .all(|(id, _)| *id != reservation_id(13))
        );
        assert!(
            service
                .events()
                .iter()
                .any(|event| event.reservation_id == Some(reservation_id(13))
                    && event.kind == RelayEventKind::ReservationExpired)
        );
    }

    #[test]
    fn forwarding_after_expiry_drains_queued_packets_and_blocks_restart_retention() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(26),
                "path-relay-26",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(26),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");

        assert_eq!(
            service
                .forward(
                    31,
                    reservation_id(26),
                    peer(1),
                    packet(RelayTransport::Udp, b"late", 2),
                )
                .expect_err("expired forward"),
            RelayError::ExpiredReservation
        );

        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        let usage = service.usage(reservation_id(26)).expect("usage");
        assert_eq!(usage.forwarded_packets, 1);
        assert_eq!(usage.dropped_packets, 1);

        let event = service.events().last().expect("expiry event");
        assert_eq!(event.kind, RelayEventKind::ReservationExpired);
        assert_eq!(
            event.quota_decision,
            "reservation_expired_queued_packets_drained"
        );
        assert_eq!(event.opaque_bytes, 10);
        assert_eq!(service.snapshot().reservation_count(), 0);
    }

    #[test]
    fn expire_reservations_drains_only_expired_queues() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(27),
                "path-relay-27",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("expired candidate");
        service
            .reserve(
                10,
                reservation_id(28),
                "path-relay-28",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("active candidate");
        service
            .forward(
                20,
                reservation_id(27),
                peer(1),
                packet(RelayTransport::Udp, b"expired", 1),
            )
            .expect("expired queued before cutoff");
        let active_packet = service
            .forward(
                20,
                reservation_id(28),
                peer(1),
                packet(RelayTransport::Udp, b"active", 2),
            )
            .expect("active queued");

        assert_eq!(service.expire_reservations(31), 1);
        assert_eq!(service.active_reservation_count(20), 1);
        assert_eq!(
            service.dequeue_for_peer(peer(2)).expect("active packet"),
            active_packet
        );
        assert_eq!(service.dequeue_for_peer(peer(2)), None);
        assert_eq!(
            service
                .proof_artifact(reservation_id(27))
                .expect("expired proof remains auditable")
                .packets_forwarded,
            1
        );
        assert_eq!(service.snapshot().reservation_count(), 1);
        assert_eq!(
            service
                .snapshot()
                .reservations
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![reservation_id(28)]
        );
    }

    #[test]
    fn cancellation_after_expiry_is_terminal_idempotent() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(29),
                "path-relay-29",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(29),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");
        assert_eq!(
            service
                .forward(
                    31,
                    reservation_id(29),
                    peer(1),
                    packet(RelayTransport::Udp, b"late", 2),
                )
                .expect_err("expired"),
            RelayError::ExpiredReservation
        );
        let events_after_expiry = service.events().len();
        let usage_after_expiry = service.usage(reservation_id(29)).expect("usage");

        service
            .cancel_reservation(reservation_id(29))
            .expect("cancel after expiry is a no-op");

        assert_eq!(service.events().len(), events_after_expiry);
        assert_eq!(
            service.usage(reservation_id(29)).expect("usage"),
            usage_after_expiry
        );
        assert_eq!(
            service.events().last().expect("expiry event").kind,
            RelayEventKind::ReservationExpired
        );
    }

    #[test]
    fn packet_loss_after_cancellation_does_not_mutate_usage_or_proof() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(30),
                "path-relay-30",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(30),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");
        service
            .cancel_reservation(reservation_id(30))
            .expect("cancel");

        let events_after_cancel = service.events().len();
        let usage_after_cancel = service.usage(reservation_id(30)).expect("usage");
        let proof_after_cancel = service
            .proof_artifact(reservation_id(30))
            .expect("proof artifact");

        assert_eq!(
            service
                .record_packet_loss(reservation_id(30), 1, 10)
                .expect_err("terminal reservations reject loss summaries"),
            RelayError::ReservationCancelled
        );
        assert_eq!(
            service
                .record_packet_loss(reservation_id(30), 1, 0)
                .expect_err("terminal lifecycle wins over malformed loss summary"),
            RelayError::ReservationCancelled
        );

        assert_eq!(service.events().len(), events_after_cancel);
        assert_eq!(
            service.usage(reservation_id(30)).expect("usage"),
            usage_after_cancel
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(30))
                .expect("proof artifact"),
            proof_after_cancel
        );
        assert_eq!(usage_after_cancel.loss_summary, None);
        assert_eq!(
            service.events().last().expect("cancel event").kind,
            RelayEventKind::ReservationCancelled
        );
    }

    #[test]
    fn packet_loss_after_expiry_does_not_mutate_usage_or_proof() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(31),
                "path-relay-31",
                grant(30, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(31),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("queued before expiry");

        assert_eq!(service.expire_reservations(31), 1);
        let events_after_expiry = service.events().len();
        let usage_after_expiry = service.usage(reservation_id(31)).expect("usage");
        let proof_after_expiry = service
            .proof_artifact(reservation_id(31))
            .expect("proof artifact");

        assert_eq!(
            service
                .record_packet_loss(reservation_id(31), 1, 10)
                .expect_err("expired reservations reject loss summaries"),
            RelayError::ExpiredReservation
        );
        assert_eq!(
            service
                .record_packet_loss(reservation_id(31), 1, 0)
                .expect_err("terminal lifecycle wins over malformed loss summary"),
            RelayError::ExpiredReservation
        );

        assert_eq!(service.events().len(), events_after_expiry);
        assert_eq!(
            service.usage(reservation_id(31)).expect("usage"),
            usage_after_expiry
        );
        assert_eq!(
            service
                .proof_artifact(reservation_id(31))
                .expect("proof artifact"),
            proof_after_expiry
        );
        assert_eq!(usage_after_expiry.loss_summary, None);
        assert_eq!(
            service.events().last().expect("expiry event").kind,
            RelayEventKind::ReservationExpired
        );
    }

    #[test]
    fn tcp_tls_fallback_reason_is_reported_only_after_tcp_path_is_used() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(15),
                "path-relay-15",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("pre-forward artifact")
                .fallback_reason,
            None
        );
        service
            .forward(
                20,
                reservation_id(15),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("udp forward");
        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("udp artifact")
                .fallback_reason,
            None
        );
        service
            .forward(
                21,
                reservation_id(15),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 2),
            )
            .expect("tcp fallback forward");
        assert_eq!(
            service
                .proof_artifact(reservation_id(15))
                .expect("tcp artifact")
                .fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn cancellation_event_preserves_tcp_tls_fallback_reason_after_tcp_use() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(16),
                "path-relay-16",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(16),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 1),
            )
            .expect("tcp fallback forward");

        service
            .cancel_reservation(reservation_id(16))
            .expect("cancel");

        let cancel_event = service.events().last().expect("cancel event");
        assert_eq!(cancel_event.kind, RelayEventKind::ReservationCancelled);
        assert_eq!(
            cancel_event.fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
    }

    #[test]
    fn restart_snapshot_recovers_active_reservations_and_queues() {
        let mut service = RelayService::new(RelayServiceConfig::default());
        service
            .reserve(
                10,
                reservation_id(9),
                "path-relay-9",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        let forwarded = service
            .forward(
                20,
                reservation_id(9),
                peer(1),
                packet(RelayTransport::Udp, b"ciphertext", 1),
            )
            .expect("forward");

        let snapshot = service.snapshot();
        assert_eq!(snapshot.reservation_count(), 1);

        let mut restored = RelayService::restore(snapshot);
        assert_eq!(
            restored.dequeue_for_peer(peer(2)).expect("restored packet"),
            forwarded
        );
        assert!(
            restored
                .events()
                .iter()
                .any(|event| event.kind == RelayEventKind::RestartRestored)
        );
    }

    #[test]
    fn packet_loss_and_proof_artifact_are_redaction_safe() {
        let mut service = RelayService::new(RelayServiceConfig::default().with_log_peer_ids(true));
        service
            .reserve(
                10,
                reservation_id(10),
                "path-relay-10",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");
        service
            .forward(
                20,
                reservation_id(10),
                peer(1),
                packet(RelayTransport::TcpTls443, b"ciphertext", 1),
            )
            .expect("forward");
        let loss = service
            .record_packet_loss(reservation_id(10), 1, 10)
            .expect("loss");
        let artifact = service
            .proof_artifact(reservation_id(10))
            .expect("artifact");

        assert_eq!(loss.loss_ppm, 100_000);
        assert_eq!(artifact.loss_summary, Some(loss));
        assert_eq!(artifact.accepted_at_micros, 10);
        assert_eq!(
            artifact.fallback_reason,
            Some("udp_unavailable_tcp_tls_443")
        );
        assert_eq!(artifact.opaque_bytes_forwarded, 10);
        assert_eq!(artifact.redacted_source_peer, "peer:0101...");
        assert!(!artifact.redacted_source_peer.contains("0101010101010101"));
        assert!(artifact.e2e_proof_preserved);
    }

    #[test]
    fn disabled_restart_retention_drops_active_state() {
        let config = RelayServiceConfig::default().with_retain_state_on_restart(false);
        let mut service = RelayService::new(config);
        service
            .reserve(
                10,
                reservation_id(11),
                "path-relay-11",
                grant(1_000, RelayQuota::default()),
                &|_: &RelayReservationGrant| true,
            )
            .expect("reservation");

        let snapshot = service.snapshot();
        assert_eq!(snapshot.reservation_count(), 0);

        let restored = RelayService::restore(snapshot);
        assert_eq!(
            restored
                .proof_artifact(reservation_id(11))
                .expect_err("dropped state"),
            RelayError::UnknownReservation
        );
    }
}
