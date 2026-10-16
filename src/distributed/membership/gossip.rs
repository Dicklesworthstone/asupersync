//! Infection-style gossip dissemination buffer with bounded retransmission.
//!
//! SWIM disseminates membership updates ("rumors") not through a dedicated
//! multicast round but by *piggybacking* a bounded number of them on the
//! regular probe / ack / ping-req traffic. Each rumor is retransmitted a
//! limited number of times before it is discarded, after which the underlying
//! member state continues to spread anti-entropy-style through later probes.
//!
//! The retransmit limit follows the SWIM paper's `lambda * log(n + 1)` rule
//! (HashiCorp memberlist's `RetransmitMult`): a rumor about a single event is
//! gossiped `retransmit_mult * ceil(log10(n + 1))` times. This guarantees
//! whp dissemination to the whole cluster in `O(log n)` protocol periods while
//! keeping per-packet overhead bounded.
//!
//! The buffer keeps at most one rumor per node: a newly-queued rumor about a
//! node *supersedes* the buffered one (per the SWIM precedence rules in
//! [`super::swim::Rumor::supersedes`]) and resets its transmit counter, so the
//! freshest information always wins the limited piggyback budget.

use super::swim::Rumor;
use crate::remote::NodeId;
use std::collections::HashMap;

/// A buffered rumor together with how many times it has been piggybacked.
#[derive(Debug, Clone)]
struct Buffered {
    rumor: Rumor,
    transmits: u32,
}

/// Bounded, retransmission-limited gossip buffer.
#[derive(Debug, Clone)]
pub struct GossipBuffer {
    /// At most one rumor per subject node; the freshest supersedes.
    rumors: HashMap<NodeId, Buffered>,
    /// Per-rumor retransmit cap, recomputed from the cluster size.
    retransmit_limit: u32,
}

impl GossipBuffer {
    /// Creates an empty buffer with the given per-rumor retransmit cap.
    #[must_use]
    pub fn new(retransmit_limit: u32) -> Self {
        Self {
            rumors: HashMap::new(),
            retransmit_limit: retransmit_limit.max(1),
        }
    }

    /// Recomputes the retransmit cap for a cluster of `n` members.
    ///
    /// `limit = retransmit_mult * ceil(log10(n + 1))`, floored at `1`.
    pub fn set_cluster_size(&mut self, retransmit_mult: u32, n: usize) {
        let scale = (((n + 1) as f64).log10().ceil() as u32).max(1);
        self.retransmit_limit = retransmit_mult.saturating_mul(scale).max(1);
    }

    /// The current per-rumor retransmit cap.
    #[must_use]
    pub fn retransmit_limit(&self) -> u32 {
        self.retransmit_limit
    }

    /// Queues a rumor for dissemination.
    ///
    /// If a rumor about the same node is already buffered, the new one replaces
    /// it (and its transmit counter resets to `0`) only when it supersedes the
    /// existing one; otherwise the new rumor is dropped as stale.
    pub fn queue(&mut self, rumor: Rumor) {
        let node = rumor.node().clone();
        match self.rumors.get_mut(&node) {
            Some(existing) => {
                if rumor.supersedes(&existing.rumor) {
                    existing.rumor = rumor;
                    existing.transmits = 0;
                }
            }
            None => {
                self.rumors.insert(
                    node,
                    Buffered {
                        rumor,
                        transmits: 0,
                    },
                );
            }
        }
    }

    /// Selects up to `max` rumors to piggyback on an outgoing packet.
    ///
    /// Rumors with the fewest prior transmissions are chosen first (so a fresh
    /// rumor is favoured over a nearly-exhausted one), with `NodeId` as a
    /// deterministic tie-breaker. Selected rumors have their transmit counter
    /// incremented; any rumor that reaches the retransmit limit is then evicted.
    pub fn select(&mut self, max: usize) -> Vec<Rumor> {
        if max == 0 || self.rumors.is_empty() {
            return Vec::new();
        }

        // Deterministic order: fewest transmits first, then by node id.
        let mut order: Vec<NodeId> = self.rumors.keys().cloned().collect();
        order.sort_by(|a, b| {
            let ta = self.rumors[a].transmits;
            let tb = self.rumors[b].transmits;
            ta.cmp(&tb).then_with(|| a.cmp(b))
        });

        let mut selected = Vec::with_capacity(max.min(order.len()));
        for node in order.into_iter().take(max) {
            if let Some(buffered) = self.rumors.get_mut(&node) {
                buffered.transmits += 1;
                selected.push(buffered.rumor.clone());
            }
        }

        // Evict fully-disseminated rumors.
        let limit = self.retransmit_limit;
        self.rumors.retain(|_, b| b.transmits < limit);

        selected
    }

    /// Number of distinct rumors currently buffered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rumors.len()
    }

    /// Whether the buffer holds no rumors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rumors.is_empty()
    }
}

#[cfg(test)]
#[path = "gossip_inline_tests.rs"]
mod tests;
