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
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId::new(s)
    }

    #[test]
    fn retransmit_limit_scales_with_cluster() {
        let mut g = GossipBuffer::new(4);
        g.set_cluster_size(4, 7); // ceil(log10(8)) = 1 => 4
        assert_eq!(g.retransmit_limit(), 4);
        g.set_cluster_size(4, 100); // ceil(log10(101)) = 3 => 12
        assert_eq!(g.retransmit_limit(), 12);
        g.set_cluster_size(4, 0); // ceil(log10(1)) = 0 -> floored to 1 => 4
        assert_eq!(g.retransmit_limit(), 4);
    }

    #[test]
    fn fresher_rumor_supersedes_and_resets_counter() {
        let mut g = GossipBuffer::new(3);
        g.queue(Rumor::alive(node("a"), 1));
        // Transmit it once.
        let _ = g.select(8);
        // A suspicion at the same incarnation supersedes alive.
        g.queue(Rumor::suspect(node("a"), 1, node("b")));
        assert_eq!(g.len(), 1);
        let out = g.select(8);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Rumor::Suspect { .. }));
    }

    #[test]
    fn stale_rumor_is_dropped() {
        let mut g = GossipBuffer::new(3);
        g.queue(Rumor::suspect(node("a"), 5, node("b")));
        // An older alive (lower incarnation) must not overwrite the suspicion.
        g.queue(Rumor::alive(node("a"), 4));
        let out = g.select(8);
        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Rumor::Suspect { .. }));
    }

    #[test]
    fn rumor_is_evicted_after_retransmit_limit() {
        let mut g = GossipBuffer::new(2);
        g.queue(Rumor::alive(node("a"), 1));
        assert_eq!(g.select(8).len(), 1); // transmit 1
        assert_eq!(g.select(8).len(), 1); // transmit 2 -> hits limit, evicted
        assert!(g.is_empty());
        assert!(g.select(8).is_empty());
    }

    #[test]
    fn select_prefers_fewest_transmits() {
        let mut g = GossipBuffer::new(10);
        g.queue(Rumor::alive(node("a"), 1));
        // Give "a" a head start in transmissions.
        let _ = g.select(8);
        let _ = g.select(8);
        g.queue(Rumor::alive(node("b"), 1));
        // With max=1, the less-transmitted "b" must be chosen.
        let out = g.select(1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].node().as_str(), "b");
    }

    #[test]
    fn empty_and_zero_budget() {
        let mut g = GossipBuffer::new(3);
        assert!(g.select(8).is_empty());
        g.queue(Rumor::alive(node("a"), 1));
        assert!(g.select(0).is_empty());
        assert_eq!(g.len(), 1);
    }
}
