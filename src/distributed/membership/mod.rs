//! SWIM-style cluster membership and failure detection.
//!
//! This module implements the SWIM weakly-consistent failure detector
//! ([Das, Gupta, Motivala, "SWIM: Scalable Weakly-consistent Infection-style
//! Process Group Membership Protocol", DSN 2002]) hardened with the Lifeguard
//! local-health extensions ([Dadgar, Phillips, Currey, "Lifeguard: Local Health
//! Awareness for More Accurate Failure Detection", DSN-W 2018; arXiv:1707.00788]).
//!
//! It exists because, prior to it, the distributed layer could *grant* leases
//! and run sagas across nodes but had **no active failure detector**: a dead
//! node was only noticed passively, when its leases eventually expired. SWIM
//! gives `O(1)` per-node probe load, indirect probes that distinguish a network
//! partition from a process death, and infection-style gossip dissemination.
//!
//! # Layering
//!
//! - [`swim`] — the pure, transport-free, clock-free protocol state machine:
//!   `(packet | tick) -> (packets + membership events + state)`. No I/O.
//! - [`lifeguard`] — the local-health-aware timing policy (probe/ack timeout
//!   scaling via the Local Health Multiplier, and the confirmation-driven
//!   suspicion-window shrink).
//! - [`gossip`] — the bounded, retransmission-limited piggyback buffer.
//!
//! The lab virtual-transport integration, the watchable membership-event
//! stream plus peer process-group, the `remote.rs` lease-manager subscription,
//! and the UDP adapter are layered *on top of* this core in sibling beads
//! (`.4.2`–`.4.4`); none of them belong in this transport-free state machine.
//!
//! # Design note: suspicion → obligation-revocation (the novel contribution)
//!
//! SWIM's suspicion lifecycle maps cleanly onto the runtime's obligation model,
//! which is what lets failure detection drive lease revocation *without
//! inventing a new failure path*:
//!
//! | SWIM state | Obligation-side meaning |
//! |------------|-------------------------|
//! | `Alive`    | Leases to the node may be granted and held normally. |
//! | `Suspect`  | The node's leases enter a *revocation-pending* state: no **new** grants are issued to it, but existing obligations are not yet discharged (a refutation can still rescue them). |
//! | `Dead`     | Confirmed failure revokes the node's leases through the **normal** obligation protocol (commit/abort), which in turn triggers any attached saga compensation. |
//! | `Left`     | Graceful departure revokes leases the same way, but is not treated as a fault for chaos/false-positive accounting. |
//!
//! Because `Dead`/`Left` revoke via the existing obligation discharge path, no
//! novel "node died" cleanup code is required — death is just another reason an
//! obligation is aborted, and the structured-concurrency leak invariants
//! (no obligation leaks) continue to hold. The `MembershipEvent` stream is the
//! seam: bead `.4.3` subscribes the lease manager to it.

pub mod cluster;
pub mod gossip;
pub mod lease_reactor;
pub mod lifeguard;
pub mod swim;
pub mod udp;
pub mod view;
pub mod wire;

pub use cluster::{ClusterConfig, VirtualCluster};
pub use gossip::GossipBuffer;
pub use lease_reactor::{LeaseAction, MembershipLeaseReactor, lease_action_for};
pub use lifeguard::{
    Awareness, Millis, max_suspicion_ms, min_suspicion_ms, node_scale, suspicion_timeout_ms,
};
pub use swim::{
    MemberState, MembershipEvent, MembershipKind, Outgoing, Packet, Payload, Rumor, Swim,
    SwimConfig, SwimConfigError,
};
pub use udp::{UdpMembershipError, UdpMembershipTransport};
pub use view::MembershipView;
pub use wire::{
    DEFAULT_MTU, EncodedDatagram, WIRE_VERSION, WireError, decode_packet, encode_packet,
};
