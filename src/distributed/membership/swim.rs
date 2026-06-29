//! Pure SWIM + Lifeguard failure-detection protocol state machine.
//!
//! This is the transport-free, clock-free *core* of the membership subsystem
//! (bead `asupersync-dist-otp-completeness-8y37kz.4.1`). It is a deterministic
//! function of its inputs:
//!
//! ```text
//! (incoming Packet | timer tick)  ->  (outgoing Packets + membership events + new state)
//! ```
//!
//! There is **no I/O anywhere** in this module: time is a `u64` millisecond
//! value supplied by the caller, peer selection draws from a seeded
//! [`DetRng`], and every message is a typed value rather than bytes. The lab
//! virtual transport ([`super`] bead `.4.2`) and the UDP adapter (bead `.4.4`)
//! wrap this core; they map a real or virtual clock and a wire format onto the
//! same state machine. This separation (protocol vs. transport) follows the
//! established [`crate::remote`] pattern.
//!
//! # Protocol summary
//!
//! SWIM ([Das, Gupta, Motivala, DSN 2002]) detects failures with `O(1)`
//! per-node probe load instead of the `O(n)` of all-to-all heartbeating:
//!
//! 1. Each protocol period the node directly **pings** one peer (chosen by
//!    randomized round-robin).
//! 2. If no **ack** arrives within the RTT timeout, it asks `k` other peers to
//!    **ping-req** the target indirectly — this distinguishes a target failure
//!    from local-link trouble.
//! 3. If neither the direct nor any indirect probe is acked by period end, the
//!    target is marked **Suspect** and that suspicion is gossiped.
//! 4. A suspected node that hears about its own suspicion **refutes** it by
//!    incrementing its **incarnation** number and flooding an `Alive` rumor
//!    that supersedes the suspicion.
//! 5. If the suspicion is not refuted within the suspicion timeout, the target
//!    is **confirmed dead** and that is gossiped (terminal).
//!
//! Lifeguard ([Dadgar, Phillips, Currey, DSN-W 2018]) adds local-health
//! awareness (see [`super::lifeguard`]) so a degraded *local* node stretches
//! its own timeouts rather than wrongly accusing healthy peers, and shrinks the
//! suspicion window as independent confirmations accumulate.

use super::gossip::GossipBuffer;
use super::lifeguard::{
    Awareness, Millis, max_suspicion_ms, min_suspicion_ms, suspicion_timeout_ms,
};
use crate::remote::NodeId;
use crate::util::det_rng::DetRng;
use std::collections::{BTreeMap, BTreeSet};

/// SWIM precedence comparison over `(terminal, incarnation, rank)` tuples.
///
/// Encodes the SWIM dissemination override rules (§4.2). Non-terminal states
/// (`Alive`, `Suspect`) are ordered lexicographically by `(incarnation, rank)`
/// with ranks `Alive < Suspect`, which yields exactly:
///
/// * `Alive(i)` overrides `Alive(j)` / `Suspect(j)` iff `i > j`;
/// * `Suspect(i)` overrides `Alive(j)` iff `i >= j`, and `Suspect(j)` iff `i > j`.
///
/// Terminal states (`Dead`/`Confirm`, `Left`/`Leave`) override any non-terminal
/// state at *any* incarnation (death is final and cannot be out-incarnated),
/// and order among themselves by `(incarnation, rank)`.
fn supersedes_prec(new: (bool, u64, u8), old: (bool, u64, u8)) -> bool {
    let (nt, ninc, nrank) = new;
    let (ot, oinc, orank) = old;
    match (nt, ot) {
        (true, false) => true,
        (false, true) => false,
        _ => (ninc, nrank) > (oinc, orank),
    }
}

/// A membership update ("rumor") that is piggybacked on probe traffic and
/// gossiped through the cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rumor {
    /// The subject node is alive at the given incarnation.
    Alive {
        /// The node the rumor is about.
        node: NodeId,
        /// The subject's incarnation number at the time of the report.
        incarnation: u64,
    },
    /// The subject node is suspected of failure (accused by `from`).
    Suspect {
        /// The node the rumor is about.
        node: NodeId,
        /// The incarnation being suspected.
        incarnation: u64,
        /// The accusing node (used for independent-confirmation counting).
        from: NodeId,
    },
    /// The subject node is confirmed dead (terminal).
    Confirm {
        /// The node the rumor is about.
        node: NodeId,
        /// The incarnation confirmed dead.
        incarnation: u64,
        /// The node that confirmed the death.
        from: NodeId,
    },
    /// The subject node has voluntarily left (terminal).
    Leave {
        /// The node the rumor is about.
        node: NodeId,
        /// The subject's incarnation at departure.
        incarnation: u64,
    },
}

impl Rumor {
    /// Constructs an `Alive` rumor.
    #[must_use]
    pub fn alive(node: NodeId, incarnation: u64) -> Self {
        Self::Alive { node, incarnation }
    }

    /// Constructs a `Suspect` rumor with the given accuser.
    #[must_use]
    pub fn suspect(node: NodeId, incarnation: u64, from: NodeId) -> Self {
        Self::Suspect {
            node,
            incarnation,
            from,
        }
    }

    /// Constructs a `Confirm` (dead) rumor with the given confirmer.
    #[must_use]
    pub fn confirm(node: NodeId, incarnation: u64, from: NodeId) -> Self {
        Self::Confirm {
            node,
            incarnation,
            from,
        }
    }

    /// Constructs a `Leave` rumor.
    #[must_use]
    pub fn leave(node: NodeId, incarnation: u64) -> Self {
        Self::Leave { node, incarnation }
    }

    /// The node this rumor is about.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        match self {
            Self::Alive { node, .. }
            | Self::Suspect { node, .. }
            | Self::Confirm { node, .. }
            | Self::Leave { node, .. } => node,
        }
    }

    /// The incarnation number carried by this rumor.
    #[must_use]
    pub fn incarnation(&self) -> u64 {
        match self {
            Self::Alive { incarnation, .. }
            | Self::Suspect { incarnation, .. }
            | Self::Confirm { incarnation, .. }
            | Self::Leave { incarnation, .. } => *incarnation,
        }
    }

    /// `(terminal, rank)` used for SWIM precedence ordering.
    fn rank_terminal(&self) -> (bool, u8) {
        match self {
            Self::Alive { .. } => (false, 0),
            Self::Suspect { .. } => (false, 1),
            Self::Leave { .. } => (true, 2),
            Self::Confirm { .. } => (true, 3),
        }
    }

    fn precedence(&self) -> (bool, u64, u8) {
        let (terminal, rank) = self.rank_terminal();
        (terminal, self.incarnation(), rank)
    }

    /// Whether this rumor should override `other` per the SWIM precedence rules.
    #[must_use]
    pub fn supersedes(&self, other: &Self) -> bool {
        supersedes_prec(self.precedence(), other.precedence())
    }

    /// The accusing node, for `Suspect`/`Confirm` rumors.
    fn accuser(&self) -> Option<NodeId> {
        match self {
            Self::Suspect { from, .. } | Self::Confirm { from, .. } => Some(from.clone()),
            _ => None,
        }
    }

    /// The member state this rumor would impose on its subject.
    fn target_state(&self) -> MemberState {
        match self {
            Self::Alive { .. } => MemberState::Alive,
            Self::Suspect { .. } => MemberState::Suspect,
            Self::Confirm { .. } => MemberState::Dead,
            Self::Leave { .. } => MemberState::Left,
        }
    }
}

/// The failure-detection state of a known member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberState {
    /// Believed healthy.
    Alive,
    /// Suspected of failure, awaiting refutation or the suspicion timeout.
    Suspect,
    /// Confirmed dead (terminal).
    Dead,
    /// Voluntarily departed (terminal).
    Left,
}

/// The kind of a published membership transition event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipKind {
    /// A node joined or was refuted back to life.
    Alive,
    /// A node became suspected.
    Suspect,
    /// A node was confirmed dead.
    Dead,
    /// A node voluntarily left.
    Left,
}

impl MembershipKind {
    fn from_state(state: MemberState) -> Self {
        match state {
            MemberState::Alive => Self::Alive,
            MemberState::Suspect => Self::Suspect,
            MemberState::Dead => Self::Dead,
            MemberState::Left => Self::Left,
        }
    }
}

/// A membership transition observable by subscribers (e.g. the lease manager).
///
/// In bead `.4.2` these are published on a watchable stream; in bead `.4.3` the
/// `remote.rs` lease manager consumes them (`Suspect` pauses new grants, `Dead`
/// revokes leases through the obligation protocol).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipEvent {
    /// The node whose state changed.
    pub node: NodeId,
    /// The new high-level state.
    pub kind: MembershipKind,
    /// The incarnation associated with the transition.
    pub incarnation: u64,
}

/// The protocol-level payload of a packet (excluding piggybacked gossip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Direct liveness probe.
    Ping {
        /// Probe sequence number, echoed in the matching ack.
        seq: u64,
    },
    /// Acknowledgement of a `Ping` (direct or relayed indirect).
    Ack {
        /// The sequence number being acknowledged.
        seq: u64,
    },
    /// Indirect-probe request: "ping `target` on my behalf and relay the ack".
    PingReq {
        /// The requester's sequence number to echo back on success.
        seq: u64,
        /// The node the helper should probe.
        target: NodeId,
    },
    /// Lifeguard negative acknowledgement: an indirect probe was attempted but
    /// the target did not ack the helper. Tells the requester the failure is
    /// corroborated (so it need not penalize its own local health as harshly).
    Nack {
        /// The requester's sequence number this nack refers to.
        seq: u64,
    },
}

/// A wire packet: a protocol payload plus piggybacked membership gossip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// The protocol-level payload.
    pub payload: Payload,
    /// Membership rumors piggybacked for dissemination.
    pub gossip: Vec<Rumor>,
}

impl Packet {
    /// Constructs a packet carrying `payload` and no gossip.
    #[must_use]
    pub fn new(payload: Payload) -> Self {
        Self {
            payload,
            gossip: Vec::new(),
        }
    }
}

/// A packet the state machine wants the transport to deliver to `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// Destination node.
    pub to: NodeId,
    /// The packet to send.
    pub packet: Packet,
}

/// Errors returned by [`SwimConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwimConfigError {
    /// `probe_interval_ms` was zero (the protocol period cannot be zero).
    ZeroProbeInterval,
    /// `probe_timeout_ms` was zero (no time would be allowed for an ack).
    ZeroProbeTimeout,
    /// `probe_timeout_ms >= probe_interval_ms`: there would be no room within a
    /// period to escalate to indirect probing before the period ends.
    ProbeTimeoutNotLessThanInterval,
    /// `suspicion_mult` was zero (the suspicion window would collapse to zero).
    ZeroSuspicionMult,
    /// `suspicion_max_timeout_mult` was zero.
    ZeroSuspicionMaxTimeoutMult,
    /// `gossip_retransmit_mult` was zero (rumors would never disseminate).
    ZeroGossipRetransmitMult,
    /// `max_piggyback` was zero (no gossip could ever ride on a packet).
    ZeroMaxPiggyback,
    /// `awareness_max` was below `1` (the health multiplier must be `>= 1`).
    AwarenessMaxTooSmall,
    /// `max_members` was zero (not even the local seed peers could be tracked).
    ZeroMaxMembers,
}

impl std::fmt::Display for SwimConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::ZeroProbeInterval => "probe_interval_ms must be >= 1",
            Self::ZeroProbeTimeout => "probe_timeout_ms must be >= 1",
            Self::ProbeTimeoutNotLessThanInterval => {
                "probe_timeout_ms must be < probe_interval_ms (room for indirect probing)"
            }
            Self::ZeroSuspicionMult => "suspicion_mult must be >= 1",
            Self::ZeroSuspicionMaxTimeoutMult => "suspicion_max_timeout_mult must be >= 1",
            Self::ZeroGossipRetransmitMult => "gossip_retransmit_mult must be >= 1",
            Self::ZeroMaxPiggyback => "max_piggyback must be >= 1",
            Self::AwarenessMaxTooSmall => "awareness_max must be >= 1",
            Self::ZeroMaxMembers => "max_members must be >= 1",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SwimConfigError {}

/// Tunable SWIM + Lifeguard parameters.
///
/// Defaults follow the SWIM paper and HashiCorp memberlist's LAN profile, the
/// most battle-tested deployment of the protocol:
///
/// | Field | Default | Source |
/// |-------|---------|--------|
/// | `probe_interval_ms` | 1000 | SWIM period `T'`; memberlist `ProbeInterval` (LAN) |
/// | `probe_timeout_ms` | 500 | memberlist `ProbeTimeout` (LAN) |
/// | `indirect_probe_count` | 3 | memberlist `IndirectChecks` |
/// | `suspicion_mult` | 4 | memberlist `SuspicionMult` (LAN) |
/// | `suspicion_max_timeout_mult` | 6 | memberlist `SuspicionMaxTimeoutMult` |
/// | `gossip_retransmit_mult` | 4 | memberlist `RetransmitMult` |
/// | `awareness_max` | 8 | memberlist `AwarenessMaxMultiplier` (Lifeguard) |
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwimConfig {
    /// Protocol period `T'`: how often a direct probe is issued.
    pub probe_interval_ms: Millis,
    /// RTT deadline for a direct ack before escalating to indirect probing.
    pub probe_timeout_ms: Millis,
    /// `k`: number of peers asked to perform an indirect probe.
    pub indirect_probe_count: u32,
    /// Multiplier on the base suspicion window (cluster-size scaled).
    pub suspicion_mult: u32,
    /// Ratio of the maximum suspicion window to the minimum.
    pub suspicion_max_timeout_mult: u32,
    /// `lambda`: per-rumor retransmit multiplier for gossip dissemination.
    pub gossip_retransmit_mult: u32,
    /// Maximum number of rumors piggybacked on a single packet.
    pub max_piggyback: usize,
    /// Lifeguard local-health-multiplier cap.
    pub awareness_max: i32,
    /// Fail-closed upper bound on the number of distinct tracked members.
    ///
    /// SWIM has no source authentication on its UDP transport, so a peer (or a
    /// spoofed source) can gossip `Alive` rumors naming arbitrarily many
    /// fabricated node ids. Without a bound, [`adopt`](SwimState::adopt) would
    /// grow the members map (and re-flood each fabricated rumor) without limit.
    /// New members learned past this cap are rejected and not re-disseminated,
    /// which bounds both memory and gossip amplification. Updates to members
    /// already tracked are unaffected. Raise this for clusters larger than the
    /// default (qe0zdf).
    pub max_members: usize,
}

impl Default for SwimConfig {
    fn default() -> Self {
        Self {
            probe_interval_ms: 1000,
            probe_timeout_ms: 500,
            indirect_probe_count: 3,
            suspicion_mult: 4,
            suspicion_max_timeout_mult: 6,
            gossip_retransmit_mult: 4,
            max_piggyback: 8,
            awareness_max: 8,
            // Generous default: well above any realistic cluster so legitimate
            // membership is never rejected, while still bounding the unbounded
            // growth/amplification an unauthenticated gossip flood could cause.
            max_members: 65_536,
        }
    }
}

impl SwimConfig {
    /// Validates the configuration, returning the first invariant violated.
    pub fn validate(&self) -> Result<(), SwimConfigError> {
        if self.probe_interval_ms == 0 {
            return Err(SwimConfigError::ZeroProbeInterval);
        }
        if self.probe_timeout_ms == 0 {
            return Err(SwimConfigError::ZeroProbeTimeout);
        }
        if self.probe_timeout_ms >= self.probe_interval_ms {
            return Err(SwimConfigError::ProbeTimeoutNotLessThanInterval);
        }
        if self.suspicion_mult == 0 {
            return Err(SwimConfigError::ZeroSuspicionMult);
        }
        if self.suspicion_max_timeout_mult == 0 {
            return Err(SwimConfigError::ZeroSuspicionMaxTimeoutMult);
        }
        if self.gossip_retransmit_mult == 0 {
            return Err(SwimConfigError::ZeroGossipRetransmitMult);
        }
        if self.max_piggyback == 0 {
            return Err(SwimConfigError::ZeroMaxPiggyback);
        }
        if self.awareness_max < 1 {
            return Err(SwimConfigError::AwarenessMaxTooSmall);
        }
        if self.max_members == 0 {
            return Err(SwimConfigError::ZeroMaxMembers);
        }
        Ok(())
    }
}

/// Per-member failure-detection bookkeeping.
#[derive(Debug, Clone)]
struct Member {
    state: MemberState,
    incarnation: u64,
    /// Logical time the member entered the current `Suspect` state.
    suspect_since: Millis,
    /// Distinct nodes that have independently accused this member (drives the
    /// Lifeguard suspicion-window shrink). The first accuser is the baseline;
    /// confirmations are counted beyond it.
    suspect_from: BTreeSet<NodeId>,
}

impl Member {
    fn new(state: MemberState, incarnation: u64, now: Millis) -> Self {
        Self {
            state,
            incarnation,
            suspect_since: now,
            suspect_from: BTreeSet::new(),
        }
    }

    fn precedence(&self) -> (bool, u64, u8) {
        let (terminal, rank) = match self.state {
            MemberState::Alive => (false, 0),
            MemberState::Suspect => (false, 1),
            MemberState::Left => (true, 2),
            MemberState::Dead => (true, 3),
        };
        (terminal, self.incarnation, rank)
    }
}

/// Phase of the current period's probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbePhase {
    /// Awaiting the direct ack.
    Direct,
    /// Direct ack timed out; awaiting relayed indirect acks.
    Indirect,
}

/// State for the single in-flight probe of the current protocol period.
#[derive(Debug, Clone)]
struct Probe {
    target: NodeId,
    seq: u64,
    sent_at: Millis,
    phase: ProbePhase,
    /// Number of indirect helpers contacted (== expected nacks).
    indirect_helpers: u32,
    /// Nacks received so far (corroborating the target is unreachable).
    nacks: u32,
    /// Whether an ack (direct or relayed) has been received.
    acked: bool,
}

/// Helper-side record of a ping-req we are relaying on a requester's behalf.
#[derive(Debug, Clone)]
struct Forward {
    requester: NodeId,
    requester_seq: u64,
    helper_seq: u64,
    sent_at: Millis,
}

/// The pure SWIM + Lifeguard membership state machine.
///
/// Drive it with [`Swim::tick`] (advance logical time) and [`Swim::handle`]
/// (deliver an inbound packet); both return the packets to send. Consume
/// membership transitions with [`Swim::drain_events`].
#[derive(Debug, Clone)]
pub struct Swim {
    local: NodeId,
    incarnation: u64,
    config: SwimConfig,
    members: BTreeMap<NodeId, Member>,
    awareness: Awareness,
    gossip: GossipBuffer,
    rng: DetRng,
    seq: u64,
    probe: Option<Probe>,
    /// Shuffled round-robin probe order; refilled when exhausted.
    probe_order: Vec<NodeId>,
    probe_idx: usize,
    last_period_at: Millis,
    forwards: Vec<Forward>,
    started: bool,
    events: Vec<MembershipEvent>,
}

impl Swim {
    /// Creates a new state machine for `local` with the given config and PRNG
    /// seed. The member set starts empty; seed it with [`Swim::add_peer`].
    #[must_use]
    pub fn new(local: NodeId, config: SwimConfig, seed: u64) -> Self {
        let awareness = Awareness::new(config.awareness_max);
        let mut gossip = GossipBuffer::new(config.gossip_retransmit_mult);
        gossip.set_cluster_size(config.gossip_retransmit_mult, 1);
        Self {
            local,
            incarnation: 0,
            config,
            members: BTreeMap::new(),
            awareness,
            gossip,
            rng: DetRng::new(seed),
            seq: 0,
            probe: None,
            probe_order: Vec::new(),
            probe_idx: 0,
            last_period_at: 0,
            forwards: Vec::new(),
            started: false,
            events: Vec::new(),
        }
    }

    /// This node's identifier.
    #[must_use]
    pub fn local(&self) -> &NodeId {
        &self.local
    }

    /// This node's current incarnation number.
    #[must_use]
    pub fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// The active configuration.
    #[must_use]
    pub fn config(&self) -> &SwimConfig {
        &self.config
    }

    /// The known state of `node`, if any.
    #[must_use]
    pub fn state_of(&self, node: &NodeId) -> Option<MemberState> {
        self.members.get(node).map(|m| m.state)
    }

    /// Number of known members (excluding the local node).
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    /// The currently-alive peers, in deterministic id order.
    #[must_use]
    pub fn alive_peers(&self) -> Vec<NodeId> {
        self.members
            .iter()
            .filter(|&(_, m)| m.state == MemberState::Alive)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Takes the membership transition events accumulated so far.
    pub fn drain_events(&mut self) -> Vec<MembershipEvent> {
        std::mem::take(&mut self.events)
    }

    /// Introduces a peer to the local view (a join). Idempotent: a peer that is
    /// already known is left untouched.
    pub fn add_peer(&mut self, now: Millis, peer: NodeId) {
        if peer == self.local || self.members.contains_key(&peer) {
            return;
        }
        if self.adopt(now, peer.clone(), MemberState::Alive, 0, None) {
            self.gossip.queue(Rumor::alive(peer, 0));
        }
    }

    /// Declares that the local node is voluntarily leaving the cluster. Bumps
    /// the local incarnation and floods a `Leave` rumor for dissemination.
    pub fn declare_leave(&mut self) {
        self.incarnation += 1;
        self.gossip
            .queue(Rumor::leave(self.local.clone(), self.incarnation));
    }

    /// Advances logical time to `now`, driving suspicion/forward timeouts and
    /// the probe cycle. Returns packets to send.
    pub fn tick(&mut self, now: Millis) -> Vec<Outgoing> {
        let mut out = Vec::new();
        self.expire_suspicions(now);
        self.expire_forwards(now, &mut out);
        self.advance_probe(now, &mut out);
        self.maybe_start_period(now, &mut out);
        out
    }

    /// Handles an inbound packet from `from`. Returns packets to send.
    pub fn handle(&mut self, now: Millis, from: NodeId, packet: Packet) -> Vec<Outgoing> {
        let mut out = Vec::new();
        self.observe_sender(now, &from);
        let Packet { payload, gossip } = packet;
        for rumor in &gossip {
            self.apply_rumor(now, rumor);
        }
        match payload {
            Payload::Ping { seq } => {
                let pkt = self.packet_to(from, Payload::Ack { seq });
                out.push(pkt);
            }
            Payload::Ack { seq } => self.handle_ack(seq, &mut out),
            Payload::PingReq { seq, target } => {
                self.handle_ping_req(now, &from, seq, target, &mut out);
            }
            Payload::Nack { seq } => self.handle_nack(seq),
        }
        out
    }

    // ---- internals -------------------------------------------------------

    fn cluster_size(&self) -> usize {
        self.members.len() + 1
    }

    fn refresh_cluster_size(&mut self) {
        self.gossip
            .set_cluster_size(self.config.gossip_retransmit_mult, self.cluster_size());
    }

    fn next_seq(&mut self) -> u64 {
        self.seq += 1;
        self.seq
    }

    fn effective_period(&self) -> Millis {
        self.awareness.scale(self.config.probe_interval_ms)
    }

    fn packet_to(&mut self, to: NodeId, payload: Payload) -> Outgoing {
        let gossip = self.gossip.select(self.config.max_piggyback);
        Outgoing {
            to,
            packet: Packet { payload, gossip },
        }
    }

    /// Records a state transition for `node`, emitting an event on a genuine
    /// change. Precedence must be checked by the caller.
    ///
    /// Returns `true` if the state was recorded. A brand-new member is rejected
    /// (returning `false`, recording nothing) once the table already holds
    /// `max_members` entries, so callers must not re-flood a rumor whose subject
    /// was not adopted. Updates to already-tracked members are always recorded.
    fn adopt(
        &mut self,
        now: Millis,
        node: NodeId,
        state: MemberState,
        incarnation: u64,
        accuser: Option<NodeId>,
    ) -> bool {
        let is_new = !self.members.contains_key(&node);
        if is_new && self.members.len() >= self.config.max_members {
            // Fail closed: refuse to grow the membership table past the
            // configured bound. SWIM gossip is unauthenticated, so without this
            // a spoofed flood of `Alive` rumors naming fabricated node ids would
            // grow the map (and the re-flood amplification) without limit
            // (qe0zdf).
            return false;
        }
        let prev_state = {
            let member = self
                .members
                .entry(node.clone())
                .or_insert_with(|| Member::new(MemberState::Alive, incarnation, now));
            let prev = member.state;
            member.state = state;
            member.incarnation = incarnation;
            if state == MemberState::Suspect {
                if prev != MemberState::Suspect {
                    member.suspect_since = now;
                    member.suspect_from.clear();
                }
                if let Some(a) = accuser {
                    member.suspect_from.insert(a);
                }
            } else {
                member.suspect_from.clear();
            }
            prev
        };
        if is_new {
            self.refresh_cluster_size();
        }
        if is_new || prev_state != state {
            self.events.push(MembershipEvent {
                node,
                kind: MembershipKind::from_state(state),
                incarnation,
            });
        }
        true
    }

    /// Applies a piggybacked rumor to the local view.
    fn apply_rumor(&mut self, now: Millis, rumor: &Rumor) {
        if rumor.node() == &self.local {
            self.maybe_refute(rumor);
            return;
        }
        let node = rumor.node().clone();
        let supersede = match self.members.get(&node) {
            Some(m) => supersedes_prec(rumor.precedence(), m.precedence()),
            None => true,
        };
        if supersede {
            // Only re-disseminate the rumor if its subject was actually
            // adopted — a rumor naming a fabricated node past `max_members` is
            // dropped here rather than amplified cluster-wide (qe0zdf).
            if self.adopt(
                now,
                node,
                rumor.target_state(),
                rumor.incarnation(),
                rumor.accuser(),
            ) {
                self.gossip.queue(rumor.clone());
            }
        } else if let Rumor::Suspect {
            incarnation, from, ..
        } = rumor
        {
            // Same-incarnation re-suspicion from a new accuser: count it as an
            // independent confirmation so the suspicion window can shrink.
            if let Some(m) = self.members.get_mut(&node) {
                if m.state == MemberState::Suspect && *incarnation == m.incarnation {
                    m.suspect_from.insert(from.clone());
                }
            }
        }
    }

    /// Handles a rumor about the local node: refute suspicions/death by bumping
    /// our incarnation and flooding `Alive`.
    fn maybe_refute(&mut self, rumor: &Rumor) {
        match rumor {
            Rumor::Suspect { incarnation, .. } | Rumor::Confirm { incarnation, .. } => {
                if *incarnation >= self.incarnation {
                    // `incarnation` is attacker-controlled (read straight off the
                    // wire in `decode_rumor`). A crafted `u64::MAX` would make
                    // `*incarnation + 1` overflow: a panic in debug/overflow-checked
                    // builds (single-datagram DoS of the membership task) or a wrap
                    // to 0 in release, which permanently defeats self-refutation —
                    // the node could no longer out-incarnate the planted suspicion
                    // and would be confirmed Dead while alive. Saturate instead.
                    self.incarnation = incarnation.saturating_add(1);
                }
                self.gossip
                    .queue(Rumor::alive(self.local.clone(), self.incarnation));
            }
            Rumor::Alive { incarnation, .. } => {
                if *incarnation > self.incarnation {
                    self.incarnation = *incarnation;
                }
            }
            Rumor::Leave { .. } => {}
        }
    }

    fn observe_sender(&mut self, now: Millis, from: &NodeId) {
        if from == &self.local || self.members.contains_key(from) {
            return;
        }
        if self.adopt(now, from.clone(), MemberState::Alive, 0, None) {
            self.gossip.queue(Rumor::alive(from.clone(), 0));
        }
    }

    fn handle_ack(&mut self, seq: u64, out: &mut Vec<Outgoing>) {
        let mut matched_probe = false;
        if let Some(p) = self.probe.as_mut() {
            if p.seq == seq && !p.acked {
                p.acked = true;
                matched_probe = true;
            }
        }
        if matched_probe {
            // Successful probe: local health improves.
            self.awareness.apply_delta(-1);
        }
        // Helper role: relay the target's ack back to the original requester.
        if let Some(pos) = self.forwards.iter().position(|f| f.helper_seq == seq) {
            let f = self.forwards.remove(pos);
            let pkt = self.packet_to(
                f.requester,
                Payload::Ack {
                    seq: f.requester_seq,
                },
            );
            out.push(pkt);
        }
    }

    fn handle_ping_req(
        &mut self,
        now: Millis,
        from: &NodeId,
        seq: u64,
        target: NodeId,
        out: &mut Vec<Outgoing>,
    ) {
        if target == self.local {
            // We are obviously alive; ack straight back to the requester.
            let pkt = self.packet_to(from.clone(), Payload::Ack { seq });
            out.push(pkt);
            return;
        }
        let helper_seq = self.next_seq();
        self.forwards.push(Forward {
            requester: from.clone(),
            requester_seq: seq,
            helper_seq,
            sent_at: now,
        });
        let pkt = self.packet_to(target, Payload::Ping { seq: helper_seq });
        out.push(pkt);
    }

    fn handle_nack(&mut self, seq: u64) {
        if let Some(p) = self.probe.as_mut() {
            if p.seq == seq {
                p.nacks += 1;
            }
        }
    }

    fn expire_suspicions(&mut self, now: Millis) {
        let n = self.cluster_size();
        let min = min_suspicion_ms(self.config.suspicion_mult, n, self.config.probe_interval_ms);
        let max = max_suspicion_ms(min, self.config.suspicion_max_timeout_mult);
        let k = self.config.indirect_probe_count;
        let mut to_kill = Vec::new();
        for (id, m) in &self.members {
            if m.state == MemberState::Suspect {
                let confirmations = m.suspect_from.len().saturating_sub(1) as u32;
                let timeout = suspicion_timeout_ms(min, max, confirmations, k);
                if now.saturating_sub(m.suspect_since) >= timeout {
                    to_kill.push((id.clone(), m.incarnation));
                }
            }
        }
        for (id, inc) in to_kill {
            self.adopt(now, id.clone(), MemberState::Dead, inc, None);
            self.gossip
                .queue(Rumor::confirm(id, inc, self.local.clone()));
        }
    }

    fn expire_forwards(&mut self, now: Millis, out: &mut Vec<Outgoing>) {
        let timeout = self.awareness.scale(self.config.probe_timeout_ms);
        let mut expired = Vec::new();
        let mut i = 0;
        while i < self.forwards.len() {
            if now.saturating_sub(self.forwards[i].sent_at) >= timeout {
                expired.push(self.forwards.remove(i));
            } else {
                i += 1;
            }
        }
        for f in expired {
            let pkt = self.packet_to(
                f.requester,
                Payload::Nack {
                    seq: f.requester_seq,
                },
            );
            out.push(pkt);
        }
    }

    fn advance_probe(&mut self, now: Millis, out: &mut Vec<Outgoing>) {
        let (sent_at, phase, target, seq, acked) = match self.probe.as_ref() {
            Some(p) => (p.sent_at, p.phase, p.target.clone(), p.seq, p.acked),
            None => return,
        };
        if acked {
            return;
        }
        let period_deadline = sent_at + self.effective_period();
        if now >= period_deadline {
            self.conclude_failed_probe(now);
            return;
        }
        let direct_deadline = sent_at + self.awareness.scale(self.config.probe_timeout_ms);
        if phase == ProbePhase::Direct && now >= direct_deadline {
            let helpers = self.pick_helpers(&target, self.config.indirect_probe_count as usize);
            for h in &helpers {
                let pkt = self.packet_to(
                    h.clone(),
                    Payload::PingReq {
                        seq,
                        target: target.clone(),
                    },
                );
                out.push(pkt);
            }
            if let Some(p) = self.probe.as_mut() {
                p.phase = ProbePhase::Indirect;
                p.indirect_helpers = helpers.len() as u32;
            }
        }
    }

    /// Concludes the current probe as failed: penalizes local health (less so
    /// if helpers corroborated via nacks) and marks the target `Suspect`.
    fn conclude_failed_probe(&mut self, now: Millis) {
        let Some(probe) = self.probe.take() else {
            return;
        };
        let mut delta = 1;
        if probe.indirect_helpers > 0 && probe.nacks < probe.indirect_helpers {
            // Our own indirect probers did not all respond -> we may be the
            // degraded one; raise local health awareness accordingly. The
            // unanswered-helper count is bounded by the probe fan-out, so the
            // conversion never realistically saturates; saturate rather than
            // wrap on the impossible overflow.
            delta += i32::try_from(probe.indirect_helpers - probe.nacks).unwrap_or(i32::MAX);
        }
        self.awareness.apply_delta(delta);

        let target = probe.target;
        let inc = match self.members.get(&target) {
            Some(m) if m.state == MemberState::Alive => m.incarnation,
            _ => return,
        };
        self.adopt(
            now,
            target.clone(),
            MemberState::Suspect,
            inc,
            Some(self.local.clone()),
        );
        self.gossip
            .queue(Rumor::suspect(target, inc, self.local.clone()));
    }

    fn maybe_start_period(&mut self, now: Millis, out: &mut Vec<Outgoing>) {
        if self.started && now.saturating_sub(self.last_period_at) < self.effective_period() {
            return;
        }
        // Conclude a lingering, unacked probe before starting the next period
        // (defensive; advance_probe normally concludes it at the boundary).
        let lingering = matches!(self.probe.as_ref(), Some(p) if !p.acked);
        if lingering {
            self.conclude_failed_probe(now);
        }
        self.probe = None;

        let Some(target) = self.next_probe_target() else {
            self.last_period_at = now;
            self.started = true;
            return;
        };
        let seq = self.next_seq();
        let pkt = self.packet_to(target.clone(), Payload::Ping { seq });
        self.probe = Some(Probe {
            target,
            seq,
            sent_at: now,
            phase: ProbePhase::Direct,
            indirect_helpers: 0,
            nacks: 0,
            acked: false,
        });
        self.last_period_at = now;
        self.started = true;
        out.push(pkt);
    }

    /// Picks the next probe target via randomized round-robin over probeable
    /// (non-terminal) members, reshuffling each full traversal.
    fn next_probe_target(&mut self) -> Option<NodeId> {
        loop {
            if self.probe_idx >= self.probe_order.len() {
                self.probe_order = self
                    .members
                    .iter()
                    .filter(|&(_, m)| m.state != MemberState::Dead && m.state != MemberState::Left)
                    .map(|(id, _)| id.clone())
                    .collect();
                if self.probe_order.is_empty() {
                    return None;
                }
                self.rng.shuffle(&mut self.probe_order);
                self.probe_idx = 0;
            }
            let cand = self.probe_order[self.probe_idx].clone();
            self.probe_idx += 1;
            if let Some(m) = self.members.get(&cand) {
                if m.state != MemberState::Dead && m.state != MemberState::Left {
                    return Some(cand);
                }
            }
        }
    }

    /// Picks up to `k` distinct alive helpers (excluding `target`) for indirect
    /// probing.
    fn pick_helpers(&mut self, target: &NodeId, k: usize) -> Vec<NodeId> {
        let mut cands: Vec<NodeId> = self
            .members
            .iter()
            .filter(|&(id, m)| id != target && m.state == MemberState::Alive)
            .map(|(id, _)| id.clone())
            .collect();
        self.rng.shuffle(&mut cands);
        cands.truncate(k);
        cands
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    fn cfg() -> SwimConfig {
        SwimConfig::default()
    }

    // ---- config ----------------------------------------------------------

    #[test]
    fn default_config_is_valid_with_cited_defaults() {
        let c = cfg();
        assert!(c.validate().is_ok());
        assert_eq!(c.probe_interval_ms, 1000);
        assert_eq!(c.probe_timeout_ms, 500);
        assert_eq!(c.indirect_probe_count, 3);
        assert_eq!(c.suspicion_mult, 4);
        assert_eq!(c.suspicion_max_timeout_mult, 6);
        assert_eq!(c.gossip_retransmit_mult, 4);
        assert_eq!(c.awareness_max, 8);
        assert_eq!(c.max_members, 65_536);
    }

    #[test]
    fn config_validation_rejects_each_bad_field() {
        let bad = |f: &dyn Fn(&mut SwimConfig)| {
            let mut c = cfg();
            f(&mut c);
            c.validate()
        };
        assert_eq!(
            bad(&|c| c.probe_interval_ms = 0),
            Err(SwimConfigError::ZeroProbeInterval)
        );
        assert_eq!(
            bad(&|c| c.probe_timeout_ms = 0),
            Err(SwimConfigError::ZeroProbeTimeout)
        );
        assert_eq!(
            bad(&|c| c.probe_timeout_ms = c.probe_interval_ms),
            Err(SwimConfigError::ProbeTimeoutNotLessThanInterval)
        );
        assert_eq!(
            bad(&|c| c.suspicion_mult = 0),
            Err(SwimConfigError::ZeroSuspicionMult)
        );
        assert_eq!(
            bad(&|c| c.suspicion_max_timeout_mult = 0),
            Err(SwimConfigError::ZeroSuspicionMaxTimeoutMult)
        );
        assert_eq!(
            bad(&|c| c.gossip_retransmit_mult = 0),
            Err(SwimConfigError::ZeroGossipRetransmitMult)
        );
        assert_eq!(
            bad(&|c| c.max_piggyback = 0),
            Err(SwimConfigError::ZeroMaxPiggyback)
        );
        assert_eq!(
            bad(&|c| c.awareness_max = 0),
            Err(SwimConfigError::AwarenessMaxTooSmall)
        );
        assert_eq!(
            bad(&|c| c.max_members = 0),
            Err(SwimConfigError::ZeroMaxMembers)
        );
    }

    #[test]
    fn members_capped_at_max_members_fail_closed() {
        // SWIM gossip is unauthenticated, so a flood of fabricated node ids must
        // not grow the members table (or the re-flood amplification) without
        // limit. New members past `max_members` are rejected fail-closed, while
        // updates to already-tracked members still apply (qe0zdf).
        let mut config = cfg();
        config.max_members = 3;
        let mut s = Swim::new(node("local"), config, 1);

        // Fill the table up to the cap via the join path.
        for p in ["a", "b", "c"] {
            s.add_peer(0, node(p));
        }
        assert_eq!(s.member_count(), 3);
        let _ = s.drain_events();

        // A brand-new node past the cap is rejected: not tracked, no event.
        s.add_peer(0, node("d"));
        assert_eq!(s.member_count(), 3, "join past the cap must be rejected");
        assert!(
            s.state_of(&node("d")).is_none(),
            "rejected node must not be tracked",
        );

        // The gossip-driven path (the actual attack vector) is bounded too: a
        // superseding Alive rumor about a fabricated node past the cap adopts
        // nothing and emits no membership event to re-flood.
        s.apply_rumor(0, &Rumor::alive(node("evil"), 9));
        assert_eq!(
            s.member_count(),
            3,
            "gossip about a new node past the cap is dropped"
        );
        assert!(s.state_of(&node("evil")).is_none());
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .all(|e| e.node != node("d") && e.node != node("evil")),
            "no membership event for a rejected node (nothing to amplify)",
        );

        // An update to an already-tracked member still applies even at the cap.
        s.apply_rumor(0, &Rumor::suspect(node("a"), 1, node("b")));
        assert_eq!(
            s.state_of(&node("a")),
            Some(MemberState::Suspect),
            "updates to existing members are unaffected by the cap",
        );
        assert_eq!(s.member_count(), 3);
    }

    // ---- precedence (exhaustive) -----------------------------------------

    #[test]
    fn rumor_precedence_table() {
        let n = node("x");
        let a = node("a");
        let alive1 = Rumor::alive(n.clone(), 1);
        let alive2 = Rumor::alive(n.clone(), 2);
        let suspect1 = Rumor::suspect(n.clone(), 1, a.clone());
        let suspect2 = Rumor::suspect(n.clone(), 2, a.clone());
        let dead1 = Rumor::confirm(n.clone(), 1, a.clone());
        let leave1 = Rumor::leave(n.clone(), 1);

        // Alive overrides alive/suspect only at strictly higher incarnation.
        assert!(alive2.supersedes(&alive1));
        assert!(!alive1.supersedes(&alive2));
        assert!(alive2.supersedes(&suspect1));
        assert!(!alive1.supersedes(&suspect1));

        // Suspect overrides alive at >= incarnation; suspect at > incarnation.
        assert!(suspect1.supersedes(&alive1));
        assert!(suspect2.supersedes(&suspect1));
        assert!(!suspect1.supersedes(&suspect2));

        // Death/leave overrides any non-terminal at any incarnation.
        assert!(dead1.supersedes(&alive2));
        assert!(dead1.supersedes(&suspect2));
        assert!(leave1.supersedes(&alive2));
        assert!(!alive2.supersedes(&dead1));
        assert!(!suspect2.supersedes(&dead1));

        // Among terminals, confirm outranks leave at equal incarnation.
        assert!(dead1.supersedes(&leave1));
        assert!(!leave1.supersedes(&dead1));
    }

    // ---- ping/ack --------------------------------------------------------

    #[test]
    fn ping_is_acked_and_sender_is_learned() {
        let mut s = Swim::new(node("self"), cfg(), 1);
        let out = s.handle(0, node("peer"), Packet::new(Payload::Ping { seq: 42 }));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, node("peer"));
        assert_eq!(out[0].packet.payload, Payload::Ack { seq: 42 });
        // Sender learned as alive.
        assert_eq!(s.state_of(&node("peer")), Some(MemberState::Alive));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == node("peer") && e.kind == MembershipKind::Alive)
        );
    }

    #[test]
    fn tick_starts_a_probe_period() {
        let mut s = Swim::new(node("self"), cfg(), 7);
        s.add_peer(0, node("a"));
        let _ = s.drain_events();
        let out = s.tick(0);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, node("a"));
        assert!(matches!(out[0].packet.payload, Payload::Ping { .. }));
    }

    #[test]
    fn direct_ack_keeps_target_alive_and_improves_health() {
        let mut s = Swim::new(node("self"), cfg(), 7);
        s.add_peer(0, node("a"));
        let _ = s.drain_events();
        let out = s.tick(0);
        let Payload::Ping { seq } = out[0].packet.payload else {
            panic!("expected ping");
        };
        // Target acks within RTT.
        let _ = s.handle(100, node("a"), Packet::new(Payload::Ack { seq }));
        // Drive past the period end: no suspicion should be raised.
        let _ = s.tick(1000);
        let events = s.drain_events();
        assert!(!events.iter().any(|e| e.kind == MembershipKind::Suspect));
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Alive));
    }

    // ---- indirect probe + suspicion --------------------------------------

    #[test]
    fn unacked_probe_escalates_to_indirect_then_suspects() {
        let mut s = Swim::new(node("self"), cfg(), 3);
        for p in ["a", "b", "c"] {
            s.add_peer(0, node(p));
        }
        let _ = s.drain_events();
        let out = s.tick(0);
        let target = out[0].to.clone();
        let Payload::Ping { .. } = out[0].packet.payload else {
            panic!("expected ping");
        };

        // No ack within RTT -> indirect ping-reqs go to other peers.
        let out2 = s.tick(500);
        assert!(!out2.is_empty(), "expected indirect ping-reqs");
        for o in &out2 {
            assert_ne!(o.to, target, "helper must not be the target");
            match &o.packet.payload {
                Payload::PingReq { target: t, .. } => assert_eq!(*t, target),
                other => panic!("expected ping-req, got {other:?}"),
            }
        }

        // Still no ack by period end -> target suspected.
        let _ = s.tick(1000);
        assert_eq!(s.state_of(&target), Some(MemberState::Suspect));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == target && e.kind == MembershipKind::Suspect)
        );
    }

    #[test]
    fn suspect_escalates_to_dead_after_timeout() {
        let mut s = Swim::new(node("self"), cfg(), 5);
        s.add_peer(0, node("a"));
        // Suspect "a" via gossip from an accuser.
        let pkt = Packet {
            payload: Payload::Ping { seq: 1 },
            gossip: vec![Rumor::suspect(node("a"), 0, node("acc"))],
        };
        let _ = s.handle(0, node("acc"), pkt);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Suspect));
        let _ = s.drain_events();

        // One accuser => full suspicion window (max). For n=3, min=4000,
        // max=24000ms. Before the window it stays suspect...
        let _ = s.tick(10_000);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Suspect));
        // ...after the window it is confirmed dead.
        let _ = s.tick(30_000);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == node("a") && e.kind == MembershipKind::Dead)
        );
    }

    #[test]
    fn independent_confirmations_shrink_the_window() {
        let mut s = Swim::new(node("self"), cfg(), 5);
        s.add_peer(0, node("a"));
        // The creator plus k=3 independent confirmations at the same
        // incarnation collapses the window to its minimum (4000ms here).
        for acc in ["acc1", "acc2", "acc3", "acc4"] {
            let pkt = Packet {
                payload: Payload::Ping { seq: 1 },
                gossip: vec![Rumor::suspect(node("a"), 0, node(acc))],
            };
            let _ = s.handle(0, node(acc), pkt);
        }
        let _ = s.drain_events();
        // With >= k confirmations the window is the minimum (4000ms), so by
        // 5000ms the node is already dead — far sooner than the lone-accuser
        // case (which survives past 10_000ms above).
        let _ = s.tick(5_000);
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
    }

    // ---- refutation ------------------------------------------------------

    #[test]
    fn alive_rumor_with_higher_incarnation_refutes_suspicion() {
        let mut s = Swim::new(node("self"), cfg(), 5);
        s.add_peer(0, node("a"));
        let _ = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 1 },
                gossip: vec![Rumor::suspect(node("a"), 0, node("acc"))],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Suspect));
        let _ = s.drain_events();

        // "a" refutes by bumping its incarnation and flooding Alive.
        let _ = s.handle(
            10,
            node("a"),
            Packet {
                payload: Payload::Ping { seq: 2 },
                gossip: vec![Rumor::alive(node("a"), 1)],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Alive));
        let events = s.drain_events();
        assert!(
            events
                .iter()
                .any(|e| e.node == node("a") && e.kind == MembershipKind::Alive)
        );
    }

    #[test]
    fn self_suspicion_triggers_incarnation_bump_and_alive_flood() {
        let mut s = Swim::new(node("self"), cfg(), 9);
        assert_eq!(s.incarnation(), 0);
        let out = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 5 },
                gossip: vec![Rumor::suspect(node("self"), 0, node("acc"))],
            },
        );
        // Incarnation bumped past the accusation.
        assert_eq!(s.incarnation(), 1);
        // The ack response piggybacks the refuting Alive(self, 1).
        let ack = &out[0];
        assert!(ack.packet.gossip.iter().any(|r| matches!(
            r,
            Rumor::Alive { node: nn, incarnation: 1 } if nn == &node("self")
        )));
        // We never track ourselves as a member.
        assert_eq!(s.state_of(&node("self")), None);
    }

    #[test]
    fn self_suspicion_with_max_incarnation_saturates_without_overflow() {
        // A crafted rumor carrying incarnation == u64::MAX about the local node
        // must not overflow the self-incarnation bump: in debug/overflow-checked
        // builds `*incarnation + 1` would panic (single-datagram DoS), and in
        // release it would wrap to 0, permanently defeating self-refutation.
        // The bump saturates at u64::MAX instead.
        let mut s = Swim::new(node("self"), cfg(), 9);
        let out = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 5 },
                gossip: vec![Rumor::suspect(node("self"), u64::MAX, node("acc"))],
            },
        );
        // Saturated: did not wrap back to 0, did not panic.
        assert_eq!(s.incarnation(), u64::MAX);
        // The refuting Alive piggybacked on the ack carries the saturated value.
        let ack = &out[0];
        assert!(ack.packet.gossip.iter().any(|r| matches!(
            r,
            Rumor::Alive { node: nn, incarnation } if nn == &node("self") && *incarnation == u64::MAX
        )));
    }

    // ---- gossip dissemination -------------------------------------------

    #[test]
    fn suspicion_is_piggybacked_for_dissemination() {
        let mut s = Swim::new(node("self"), cfg(), 3);
        for p in ["a", "b"] {
            s.add_peer(0, node(p));
        }
        let out = s.tick(0);
        let target = out[0].to.clone();
        let _ = s.tick(500);
        let _ = s.tick(1000); // suspect target

        // The target is still within its suspicion window...
        assert_eq!(s.state_of(&target), Some(MemberState::Suspect));
        // ...and the next protocol period's probe piggybacks the suspicion.
        let later = s.tick(3000);
        let carried = later.iter().any(|o| {
            o.packet
                .gossip
                .iter()
                .any(|r| matches!(r, Rumor::Suspect { node: nn, .. } if *nn == target))
        });
        assert!(
            carried,
            "suspicion must be piggybacked on outbound probe traffic"
        );
    }

    #[test]
    fn declare_leave_floods_leave_rumor() {
        let mut s = Swim::new(node("self"), cfg(), 1);
        s.add_peer(0, node("a"));
        s.declare_leave();
        assert_eq!(s.incarnation(), 1);
        // The leave rumor rides out on the next packet.
        let out = s.handle(0, node("a"), Packet::new(Payload::Ping { seq: 1 }));
        assert!(out[0].packet.gossip.iter().any(|r| matches!(
            r,
            Rumor::Leave { node: nn, .. } if nn == &node("self")
        )));
    }

    #[test]
    fn dead_is_terminal_and_not_resurrected_by_alive() {
        let mut s = Swim::new(node("self"), cfg(), 1);
        s.add_peer(0, node("a"));
        let _ = s.handle(
            0,
            node("acc"),
            Packet {
                payload: Payload::Ping { seq: 1 },
                gossip: vec![Rumor::confirm(node("a"), 5, node("acc"))],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
        // A stale (or even higher) Alive must not resurrect a dead node.
        let _ = s.handle(
            1,
            node("b"),
            Packet {
                payload: Payload::Ping { seq: 2 },
                gossip: vec![Rumor::alive(node("a"), 99)],
            },
        );
        assert_eq!(s.state_of(&node("a")), Some(MemberState::Dead));
    }

    #[test]
    fn indirect_helper_relays_ack_to_requester() {
        // Acting as a helper: receive a ping-req, ping the target, then on the
        // target's ack relay it back to the requester.
        let mut s = Swim::new(node("helper"), cfg(), 1);
        let out = s.handle(
            0,
            node("req"),
            Packet::new(Payload::PingReq {
                seq: 77,
                target: node("tgt"),
            }),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].to, node("tgt"));
        let Payload::Ping { seq: helper_seq } = out[0].packet.payload else {
            panic!("expected ping to target");
        };
        // Target acks the helper.
        let relayed = s.handle(
            10,
            node("tgt"),
            Packet::new(Payload::Ack { seq: helper_seq }),
        );
        assert_eq!(relayed.len(), 1);
        assert_eq!(relayed[0].to, node("req"));
        assert_eq!(relayed[0].packet.payload, Payload::Ack { seq: 77 });
    }

    #[test]
    fn helper_nacks_requester_when_target_silent() {
        let mut s = Swim::new(node("helper"), cfg(), 1);
        let _ = s.handle(
            0,
            node("req"),
            Packet::new(Payload::PingReq {
                seq: 88,
                target: node("tgt"),
            }),
        );
        // Target never acks; after the probe timeout the helper nacks. (The
        // same tick may also open a new probe period, so select the nack.)
        let out = s.tick(600);
        let nack = out
            .iter()
            .find(|o| matches!(o.packet.payload, Payload::Nack { .. }))
            .expect("helper should nack the requester");
        assert_eq!(nack.to, node("req"));
        assert_eq!(nack.packet.payload, Payload::Nack { seq: 88 });
    }
}
