//! ATP Path Graph candidate and outcome model.
//!
//! The path graph treats every possible route to a peer as a typed candidate
//! with explicit security properties, budgets, trace identity, and terminal
//! outcome. Later NAT traversal, Tailscale, relay, mailbox, and path-racing
//! code should consume these types instead of inventing local enums.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Stable identifier for one path candidate inside a path race.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PathCandidateId(u64);

impl PathCandidateId {
    /// Construct a candidate id from a stable numeric value.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw candidate id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Stable trace identifier used to correlate path attempts with transfer logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathTraceId(u64);

impl PathTraceId {
    /// Construct a path trace id.
    #[must_use]
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw trace id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// ATP path candidate kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathKind {
    /// LAN multicast or local-network discovery candidate.
    LanMulticast,
    /// Explicit user-provided public UDP address.
    ExplicitPublicUdp,
    /// Public IPv6 address without NAT traversal.
    PublicIpv6,
    /// UDP hole-punched path established through rendezvous.
    NatPunchedUdp,
    /// Existing Tailscale/private-route address, if detected.
    TailscaleIp,
    /// ATP relay carrying UDP-like packets.
    AtpRelayUdp,
    /// ATP relay over TCP/TLS on port 443 for UDP-hostile networks.
    AtpRelayTcpTls443,
    /// MASQUE/CONNECT-UDP-style relay adapter.
    ///
    /// ATP still owns peer authentication, payload encryption, and transfer
    /// proof semantics. The proxy only carries UDP-like path traffic through an
    /// authenticated HTTP/3 CONNECT-UDP tunnel, so proxy auth, policy denial,
    /// nested congestion, and timing metadata remain explicit relay caveats
    /// instead of becoming direct-path guarantees.
    MasqueConnectUdp,
    /// Store-and-forward encrypted mailbox path.
    OfflineMailbox,
}

impl PathKind {
    /// Every path kind in deterministic display/preference order.
    pub const ALL: [Self; 9] = [
        Self::LanMulticast,
        Self::ExplicitPublicUdp,
        Self::PublicIpv6,
        Self::NatPunchedUdp,
        Self::TailscaleIp,
        Self::AtpRelayUdp,
        Self::AtpRelayTcpTls443,
        Self::MasqueConnectUdp,
        Self::OfflineMailbox,
    ];

    /// Coarse family used by path diagnostics and selection explanations.
    #[must_use]
    pub const fn family(self) -> PathFamily {
        match self {
            Self::LanMulticast
            | Self::ExplicitPublicUdp
            | Self::PublicIpv6
            | Self::NatPunchedUdp => PathFamily::Direct,
            Self::TailscaleIp => PathFamily::Tailscale,
            Self::AtpRelayUdp | Self::AtpRelayTcpTls443 | Self::MasqueConnectUdp => {
                PathFamily::Relay
            }
            Self::OfflineMailbox => PathFamily::OfflineMailbox,
        }
    }

    /// Total-order preference rank across every path family (lower = preferred).
    ///
    /// The ordering intent mirrors the live discovery ranker: **Tailscale first,
    /// then every direct route, then every relay route, then the offline
    /// mailbox**. Ranks are a strict total order — no two variants tie — so a
    /// sort by `preference_rank` is deterministic. Within the direct band the
    /// order prefers less-NAT-dependent, cheaper-to-validate routes
    /// (public IPv6 > explicit public UDP > LAN multicast > NAT-punched UDP).
    /// The relay band is ordered MASQUE CONNECT-UDP > ATP relay TCP/TLS-443 >
    /// ATP relay UDP; the exact intra-band order only breaks ties and never
    /// crosses a family boundary.
    #[must_use]
    pub const fn preference_rank(self) -> u8 {
        match self {
            // Tailscale / private-route: most preferred.
            Self::TailscaleIp => 10,
            // Direct peer-to-peer band.
            Self::PublicIpv6 => 20,
            Self::ExplicitPublicUdp => 22,
            Self::LanMulticast => 24,
            Self::NatPunchedUdp => 26,
            // Relay band.
            Self::MasqueConnectUdp => 40,
            Self::AtpRelayTcpTls443 => 42,
            Self::AtpRelayUdp => 44,
            // Store-and-forward mailbox: last resort.
            Self::OfflineMailbox => 60,
        }
    }

    /// Whether this candidate is a direct peer-to-peer route.
    #[must_use]
    pub const fn is_direct(self) -> bool {
        matches!(self.family(), PathFamily::Direct)
    }

    /// Whether this candidate uses ATP-owned or MASQUE-style relay transport.
    #[must_use]
    pub const fn is_relay(self) -> bool {
        matches!(self.family(), PathFamily::Relay)
    }

    /// Whether this path tunnels ATP UDP-like traffic through an HTTP proxy.
    #[must_use]
    pub const fn uses_connect_udp_proxy(self) -> bool {
        matches!(self, Self::MasqueConnectUdp)
    }

    /// Whether the selected path introduces a nested congestion-control caveat.
    #[must_use]
    pub const fn has_nested_congestion_caveat(self) -> bool {
        matches!(self, Self::AtpRelayTcpTls443 | Self::MasqueConnectUdp)
    }

    /// Whether an intermediary must authorize the path before ATP can use it.
    #[must_use]
    pub const fn requires_intermediary_authority(self) -> bool {
        matches!(self, Self::MasqueConnectUdp)
    }

    /// Stable label for path proof summaries and audit artifacts.
    #[must_use]
    pub const fn proof_summary_label(self) -> &'static str {
        match self {
            Self::LanMulticast => "lan_multicast",
            Self::ExplicitPublicUdp => "explicit_public_udp",
            Self::PublicIpv6 => "public_ipv6",
            Self::NatPunchedUdp => "nat_punched_udp",
            Self::TailscaleIp => "tailscale_ip",
            Self::AtpRelayUdp => "atp_relay_udp",
            Self::AtpRelayTcpTls443 => "atp_relay_tcp_tls_443",
            Self::MasqueConnectUdp => "masque_connect_udp_adapter",
            Self::OfflineMailbox => "offline_mailbox",
        }
    }

    /// Stable failure-mode hint for diagnostics that explain adapter caveats.
    #[must_use]
    pub const fn adapter_failure_hint(self) -> Option<&'static str> {
        match self {
            Self::MasqueConnectUdp => Some("proxy_auth_policy_or_connect_udp_failure"),
            Self::AtpRelayTcpTls443 => Some("tcp_head_of_line_or_nested_retransmission"),
            _ => None,
        }
    }
}

/// Coarse route family used in path doctor and path trace output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathFamily {
    /// Direct peer-to-peer path.
    Direct,
    /// Optional Tailscale/private-network path.
    Tailscale,
    /// Relay-backed online path.
    Relay,
    /// Store-and-forward offline mailbox path.
    OfflineMailbox,
}

/// Security and privacy properties of a candidate path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathSecurity {
    /// Whether the path requires authenticated ATP peer identity.
    pub authenticated_peer: bool,
    /// Whether ATP payload bytes remain encrypted end to end.
    pub end_to_end_encrypted: bool,
    /// Whether the remote peer can directly see the local public IP.
    pub exposes_local_ip_to_peer: bool,
    /// Whether a third-party relay sees peer metadata or traffic timing.
    pub relay_metadata_visible: bool,
    /// Whether the path can complete while peers are not online together.
    pub store_and_forward: bool,
}

impl PathSecurity {
    /// Conservative security defaults for a path kind.
    #[must_use]
    pub const fn for_kind(kind: PathKind) -> Self {
        match kind {
            PathKind::LanMulticast
            | PathKind::ExplicitPublicUdp
            | PathKind::PublicIpv6
            | PathKind::NatPunchedUdp
            | PathKind::TailscaleIp => Self {
                authenticated_peer: true,
                end_to_end_encrypted: true,
                exposes_local_ip_to_peer: true,
                relay_metadata_visible: false,
                store_and_forward: false,
            },
            PathKind::AtpRelayUdp | PathKind::AtpRelayTcpTls443 | PathKind::MasqueConnectUdp => {
                Self {
                    authenticated_peer: true,
                    end_to_end_encrypted: true,
                    exposes_local_ip_to_peer: false,
                    relay_metadata_visible: true,
                    store_and_forward: false,
                }
            }
            PathKind::OfflineMailbox => Self {
                authenticated_peer: true,
                end_to_end_encrypted: true,
                exposes_local_ip_to_peer: false,
                relay_metadata_visible: true,
                store_and_forward: true,
            },
        }
    }
}

/// Attempt budget for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathBudget {
    /// Maximum time spent establishing the path.
    pub connect_timeout_micros: u64,
    /// Maximum time spent draining a losing attempt after cancellation.
    pub loser_drain_timeout_micros: u64,
    /// Maximum probe bytes allowed before the path is validated.
    pub max_probe_bytes: u64,
}

impl Default for PathBudget {
    fn default() -> Self {
        Self {
            connect_timeout_micros: 3_000_000,
            loser_drain_timeout_micros: 250_000,
            max_probe_bytes: 16 * 1_200,
        }
    }
}

/// Successful path outcome categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSuccessKind {
    /// A direct UDP path was validated.
    DirectValidated,
    /// A Tailscale/private-route path was selected.
    TailscaleSelected,
    /// A relay path was selected.
    RelaySelected,
    /// An encrypted offline mailbox accepted the transfer.
    MailboxAccepted,
}

/// Failed path outcome categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFailureKind {
    /// Candidate exceeded its connection budget.
    Timeout,
    /// NAT behavior prevented a viable punched UDP route.
    HardNat,
    /// UDP appears blocked on this route.
    UdpBlocked,
    /// Peer or relay authentication failed.
    AuthFailure,
    /// Local or remote policy denied this candidate.
    PolicyDenied,
    /// Relay was unavailable or refused the attempt.
    RelayUnavailable,
    /// Platform cannot support this path kind.
    UnsupportedPlatform,
    /// Protocol exchange failed in a non-auth, non-policy way.
    ProtocolError,
}

/// Cancellation reason for a path attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathCancelReason {
    /// Another candidate won the race.
    LoserOfRace,
    /// The owning ATP region was cancelled.
    ParentCancelled,
    /// The candidate exceeded its budget while being cancelled or drained.
    BudgetExceeded,
}

/// Terminal outcome of one path attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathOutcomeResult {
    /// Path was usable.
    Success(PathSuccessKind),
    /// Path failed.
    Failure(PathFailureKind),
    /// Path was cancelled.
    Cancelled(PathCancelReason),
}

/// Measured outcome for one candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathOutcome {
    /// Terminal category.
    pub result: PathOutcomeResult,
    /// Monotonic completion timestamp in microseconds.
    pub completed_at_micros: u64,
    /// Optional observed RTT.
    pub observed_rtt_micros: Option<u64>,
    /// Probe/control bytes sent while establishing the path.
    pub bytes_sent: u64,
    /// Probe/control bytes received while establishing the path.
    pub bytes_received: u64,
}

impl PathOutcome {
    /// Construct a successful outcome.
    #[must_use]
    pub const fn success(
        kind: PathSuccessKind,
        completed_at_micros: u64,
        observed_rtt_micros: Option<u64>,
    ) -> Self {
        Self {
            result: PathOutcomeResult::Success(kind),
            completed_at_micros,
            observed_rtt_micros,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Construct a failed outcome.
    #[must_use]
    pub const fn failure(kind: PathFailureKind, completed_at_micros: u64) -> Self {
        Self {
            result: PathOutcomeResult::Failure(kind),
            completed_at_micros,
            observed_rtt_micros: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Construct a cancelled outcome.
    #[must_use]
    pub const fn cancelled(reason: PathCancelReason, completed_at_micros: u64) -> Self {
        Self {
            result: PathOutcomeResult::Cancelled(reason),
            completed_at_micros,
            observed_rtt_micros: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    /// Attach byte counters to this outcome.
    #[must_use]
    pub const fn with_bytes(mut self, bytes_sent: u64, bytes_received: u64) -> Self {
        self.bytes_sent = bytes_sent;
        self.bytes_received = bytes_received;
        self
    }

    /// Whether the outcome is a success.
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self.result, PathOutcomeResult::Success(_))
    }
}

/// Attempt state for one path candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAttemptState {
    /// Candidate has not started.
    Pending,
    /// Candidate is actively attempting connection.
    Racing,
    /// Candidate completed successfully.
    Succeeded(PathOutcome),
    /// Candidate completed unsuccessfully.
    Failed(PathOutcome),
    /// Candidate was cancelled.
    Cancelled(PathOutcome),
    /// Candidate lost the race and was drained under structured cleanup.
    DrainedLoser {
        /// Candidate that won the race.
        winner: PathCandidateId,
        /// Cleanup outcome recorded for this loser.
        outcome: PathOutcome,
    },
}

impl PathAttemptState {
    /// Whether this state is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded(_) | Self::Failed(_) | Self::Cancelled(_) | Self::DrainedLoser { .. }
        )
    }
}

/// One candidate edge in the ATP path graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCandidate {
    /// Candidate identifier.
    pub id: PathCandidateId,
    /// Path type.
    pub kind: PathKind,
    /// Trace identifier.
    pub trace_id: PathTraceId,
    /// Attempt budget.
    pub budget: PathBudget,
    /// Security properties.
    pub security: PathSecurity,
    /// Current attempt state.
    pub state: PathAttemptState,
}

impl PathCandidate {
    /// Construct a candidate with kind-derived security defaults.
    #[must_use]
    pub fn new(id: PathCandidateId, kind: PathKind, trace_id: PathTraceId) -> Self {
        Self {
            id,
            kind,
            trace_id,
            budget: PathBudget::default(),
            security: PathSecurity::for_kind(kind),
            state: PathAttemptState::Pending,
        }
    }

    /// Override the attempt budget.
    #[must_use]
    pub const fn with_budget(mut self, budget: PathBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Override security metadata.
    #[must_use]
    pub const fn with_security(mut self, security: PathSecurity) -> Self {
        self.security = security;
        self
    }
}

/// Cleanup record emitted when a path candidate loses a race.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathLoserCleanup {
    /// Losing candidate.
    pub candidate_id: PathCandidateId,
    /// Winning candidate.
    pub winner: PathCandidateId,
    /// Whether cancellation was requested.
    pub cancel_requested: bool,
    /// Whether the loser drained to a terminal state.
    pub drained: bool,
}

/// Deterministic explanation for the current path-race selection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathSelectionReason {
    /// Direct LAN/public IPv6/public UDP/NAT-punched path won.
    DirectCandidateValidated,
    /// Tailscale candidate won; Tailscale stays optional.
    TailscaleCandidateValidated,
    /// Relay candidate won after direct/private paths did not win first.
    RelayFallbackValidated,
    /// Offline mailbox path accepted store-and-forward delivery.
    OfflineMailboxAccepted,
    /// No candidate has reached a terminal state yet.
    RaceStillPending,
    /// Every candidate is terminal and none succeeded.
    NoSuccessfulCandidate,
    /// Internal invariant breach: winner id no longer maps to a candidate.
    MissingWinnerCandidate,
}

impl PathSelectionReason {
    /// Stable machine-readable reason code for logs and doctor output.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::DirectCandidateValidated => "direct_candidate_validated",
            Self::TailscaleCandidateValidated => "tailscale_candidate_validated",
            Self::RelayFallbackValidated => "relay_fallback_validated",
            Self::OfflineMailboxAccepted => "offline_mailbox_accepted",
            Self::RaceStillPending => "race_still_pending",
            Self::NoSuccessfulCandidate => "no_successful_candidate",
            Self::MissingWinnerCandidate => "missing_winner_candidate",
        }
    }
}

/// Path-race snapshot for doctor, trace, and deterministic test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathDiagnosticSnapshot {
    /// Winning candidate, if any.
    pub winner: Option<PathCandidateId>,
    /// Winning path kind, if the winner is still present.
    pub selected_kind: Option<PathKind>,
    /// Why this race is currently in its selection state.
    pub reason: PathSelectionReason,
    /// Total candidates in the race.
    pub candidate_count: usize,
    /// Candidates that are still actively racing.
    pub racing_count: usize,
    /// Candidates that succeeded before loser draining.
    pub success_count: usize,
    /// Candidates that failed.
    pub failure_count: usize,
    /// Candidates that were cancelled without becoming drained losers.
    pub cancelled_count: usize,
    /// Candidates drained because a different path won.
    pub drained_loser_count: usize,
    /// Direct path candidates.
    pub direct_count: usize,
    /// Tailscale path candidates.
    pub tailscale_count: usize,
    /// Relay path candidates.
    pub relay_count: usize,
    /// Offline mailbox path candidates.
    pub mailbox_count: usize,
}

impl PathDiagnosticSnapshot {
    /// Coarse family for the selected path, if any.
    #[must_use]
    pub fn selected_family(self) -> Option<PathFamily> {
        self.selected_kind.map(PathKind::family)
    }
}

/// Errors from the deterministic path-race model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathRaceError {
    /// Candidate id already exists.
    DuplicateCandidate(PathCandidateId),
    /// Candidate id was not present in the race.
    UnknownCandidate(PathCandidateId),
    /// A terminal candidate cannot be started again.
    TerminalCandidate(PathCandidateId),
}

impl fmt::Display for PathRaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCandidate(id) => write!(f, "duplicate path candidate {}", id.get()),
            Self::UnknownCandidate(id) => write!(f, "unknown path candidate {}", id.get()),
            Self::TerminalCandidate(id) => {
                write!(
                    f,
                    "terminal path candidate cannot be restarted {}",
                    id.get()
                )
            }
        }
    }
}

impl std::error::Error for PathRaceError {}

/// Deterministic model for racing path candidates.
#[derive(Debug, Clone, Default)]
pub struct PathRace {
    candidates: BTreeMap<PathCandidateId, PathCandidate>,
    winner: Option<PathCandidateId>,
    cleanup: Vec<PathLoserCleanup>,
}

impl PathRace {
    /// Create an empty path race.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate to the race.
    pub fn add_candidate(&mut self, candidate: PathCandidate) -> Result<(), PathRaceError> {
        if self.candidates.contains_key(&candidate.id) {
            return Err(PathRaceError::DuplicateCandidate(candidate.id));
        }
        self.candidates.insert(candidate.id, candidate);
        Ok(())
    }

    /// Start one candidate.
    pub fn start_candidate(&mut self, id: PathCandidateId) -> Result<(), PathRaceError> {
        let candidate = self
            .candidates
            .get_mut(&id)
            .ok_or(PathRaceError::UnknownCandidate(id))?;
        if candidate.state.is_terminal() {
            return Err(PathRaceError::TerminalCandidate(id));
        }
        candidate.state = PathAttemptState::Racing;
        Ok(())
    }

    /// Start every pending candidate.
    pub fn start_all(&mut self) -> Result<(), PathRaceError> {
        let ids = self.candidates.keys().copied().collect::<Vec<_>>();
        for id in ids {
            self.start_candidate(id)?;
        }
        Ok(())
    }

    /// Record a terminal outcome for one candidate.
    ///
    /// The first successful outcome wins. Active non-winning candidates are
    /// immediately marked as drained losers, modeling the structured
    /// cancellation requirement that losers do not remain live after a race.
    pub fn record_outcome(
        &mut self,
        id: PathCandidateId,
        outcome: PathOutcome,
    ) -> Result<(), PathRaceError> {
        let existing_state = self
            .candidates
            .get(&id)
            .ok_or(PathRaceError::UnknownCandidate(id))?
            .state;
        if existing_state.is_terminal() {
            return Ok(());
        }

        if let Some(winner) = self.winner {
            if winner != id {
                self.drain_loser(id, winner, outcome)?;
            }
            return Ok(());
        }

        let candidate = self
            .candidates
            .get_mut(&id)
            .ok_or(PathRaceError::UnknownCandidate(id))?;
        candidate.state = match outcome.result {
            PathOutcomeResult::Success(_) => PathAttemptState::Succeeded(outcome),
            PathOutcomeResult::Failure(_) => PathAttemptState::Failed(outcome),
            PathOutcomeResult::Cancelled(_) => PathAttemptState::Cancelled(outcome),
        };

        if outcome.is_success() && self.winner.is_none() {
            self.winner = Some(id);
            self.drain_active_losers(id, outcome.completed_at_micros)?;
        }
        Ok(())
    }

    /// Winner candidate id, if a path succeeded.
    #[must_use]
    pub const fn winner(&self) -> Option<PathCandidateId> {
        self.winner
    }

    /// Borrow a candidate by id.
    #[must_use]
    pub fn candidate(&self, id: PathCandidateId) -> Option<&PathCandidate> {
        self.candidates.get(&id)
    }

    /// Iterate candidates in deterministic candidate-id order for path doctor
    /// documents, trace logs, and proof summaries.
    #[must_use = "iterators are lazy; consume the returned iterator"]
    pub fn candidates(&self) -> impl Iterator<Item = &PathCandidate> + '_ {
        self.candidates.values()
    }

    /// Cleanup records for candidates that lost after a winner was chosen.
    #[must_use]
    pub fn cleanup_records(&self) -> &[PathLoserCleanup] {
        &self.cleanup
    }

    /// Build a deterministic diagnostic snapshot for path doctor/trace output.
    #[must_use]
    pub fn diagnostic_snapshot(&self) -> PathDiagnosticSnapshot {
        let mut snapshot = PathDiagnosticSnapshot {
            winner: self.winner,
            selected_kind: self
                .winner
                .and_then(|winner| self.candidates.get(&winner).map(|candidate| candidate.kind)),
            reason: PathSelectionReason::RaceStillPending,
            candidate_count: self.candidates.len(),
            racing_count: 0,
            success_count: 0,
            failure_count: 0,
            cancelled_count: 0,
            drained_loser_count: 0,
            direct_count: 0,
            tailscale_count: 0,
            relay_count: 0,
            mailbox_count: 0,
        };

        for candidate in self.candidates.values() {
            match candidate.kind.family() {
                PathFamily::Direct => snapshot.direct_count += 1,
                PathFamily::Tailscale => snapshot.tailscale_count += 1,
                PathFamily::Relay => snapshot.relay_count += 1,
                PathFamily::OfflineMailbox => snapshot.mailbox_count += 1,
            }

            match candidate.state {
                PathAttemptState::Pending => {}
                PathAttemptState::Racing => snapshot.racing_count += 1,
                PathAttemptState::Succeeded(_) => snapshot.success_count += 1,
                PathAttemptState::Failed(_) => snapshot.failure_count += 1,
                PathAttemptState::Cancelled(_) => snapshot.cancelled_count += 1,
                PathAttemptState::DrainedLoser { .. } => snapshot.drained_loser_count += 1,
            }
        }

        snapshot.reason = match (snapshot.winner, snapshot.selected_kind) {
            (Some(_), Some(kind)) => match kind.family() {
                PathFamily::Direct => PathSelectionReason::DirectCandidateValidated,
                PathFamily::Tailscale => PathSelectionReason::TailscaleCandidateValidated,
                PathFamily::Relay => PathSelectionReason::RelayFallbackValidated,
                PathFamily::OfflineMailbox => PathSelectionReason::OfflineMailboxAccepted,
            },
            (Some(_), None) => PathSelectionReason::MissingWinnerCandidate,
            (None, None) if self.all_terminal() => PathSelectionReason::NoSuccessfulCandidate,
            (None, None) => PathSelectionReason::RaceStillPending,
            (None, Some(_)) => PathSelectionReason::MissingWinnerCandidate,
        };

        snapshot
    }

    /// Return true when every candidate is terminal.
    #[must_use]
    pub fn all_terminal(&self) -> bool {
        self.candidates
            .values()
            .all(|candidate| candidate.state.is_terminal())
    }

    fn drain_active_losers(
        &mut self,
        winner: PathCandidateId,
        completed_at_micros: u64,
    ) -> Result<(), PathRaceError> {
        let loser_ids = self
            .candidates
            .keys()
            .copied()
            .filter(|id| *id != winner)
            .collect::<Vec<_>>(); // ubs:ignore - collect needed to drop immutable borrow
        for loser_id in loser_ids {
            let loser_state = self
                .candidates
                .get(&loser_id)
                .ok_or(PathRaceError::UnknownCandidate(loser_id))?
                .state;
            if loser_state.is_terminal() {
                continue;
            }
            let outcome =
                PathOutcome::cancelled(PathCancelReason::LoserOfRace, completed_at_micros);
            self.drain_loser(loser_id, winner, outcome)?;
        }
        Ok(())
    }

    fn drain_loser(
        &mut self,
        loser_id: PathCandidateId,
        winner: PathCandidateId,
        outcome: PathOutcome,
    ) -> Result<(), PathRaceError> {
        let loser = self
            .candidates
            .get_mut(&loser_id)
            .ok_or(PathRaceError::UnknownCandidate(loser_id))?;
        loser.state = PathAttemptState::DrainedLoser { winner, outcome };
        if !self
            .cleanup
            .iter()
            .any(|record| record.candidate_id == loser_id)
        {
            self.cleanup.push(PathLoserCleanup {
                candidate_id: loser_id,
                winner,
                cancel_requested: true,
                drained: true,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "path_inline_tests.rs"]
mod tests;
