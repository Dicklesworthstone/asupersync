//! Deterministic in-memory SWIM cluster simulator (lab virtual transport).
//!
//! Drives a set of [`Swim`] state machines over a virtual message bus with
//! virtual time and injectable faults (node death, network partition). It is
//! the lab-transport binding for the pure protocol core (bead
//! `asupersync-dist-otp-completeness-8y37kz.4.2`): everything is deterministic
//! and reproducible — no real clock, no real sockets, all peer selection and
//! timing flow through the seeded [`Swim`] instances and a fixed-step clock —
//! so convergence under churn/partition is a *repeatable* property, not a flaky
//! integration test.
//!
//! Messages are delivered with a fixed one-way latency a configurable number of
//! virtual milliseconds after they are sent. Each step advances the clock by a
//! tick, delivers all due messages (feeding them into the recipient's
//! [`Swim::handle`]), then ticks every live node ([`Swim::tick`]); the resulting
//! outgoing packets are enqueued for future delivery. A killed node stops
//! ticking and all traffic to/from it is dropped; a partition drops every
//! message that would cross between groups.

use super::lifeguard::Millis;
use super::swim::{MemberState, MembershipEvent, Outgoing, Packet, Swim, SwimConfig};
use crate::remote::NodeId;
use crate::util::det_rng::DetRng;
use std::collections::{BTreeMap, BTreeSet};

/// Virtual-transport timing for a [`VirtualCluster`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterConfig {
    /// Virtual milliseconds advanced per simulation step.
    pub tick_ms: Millis,
    /// One-way message delivery latency, in virtual milliseconds. Keep it below
    /// the SWIM probe timeout so probe/ack round-trips can complete.
    pub latency_ms: Millis,
    /// Per-message drop probability, in per-mille (0 = lossless). Applied at
    /// delivery via the cluster's seeded PRNG, modelling a best-effort transport
    /// for false-positive-rate measurement.
    pub loss_permille: u16,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            tick_ms: 100,
            latency_ms: 20,
            loss_permille: 0,
        }
    }
}

#[derive(Debug, Clone)]
struct InFlight {
    deliver_at: Millis,
    from: NodeId,
    to: NodeId,
    packet: Packet,
}

/// A deterministic, fault-injectable in-memory SWIM cluster.
#[derive(Debug)]
pub struct VirtualCluster {
    nodes: BTreeMap<NodeId, Swim>,
    config: ClusterConfig,
    now: Millis,
    queue: Vec<InFlight>,
    dead: BTreeSet<NodeId>,
    partition: BTreeMap<NodeId, u8>,
    events: BTreeMap<NodeId, Vec<MembershipEvent>>,
    rng: DetRng,
    /// A degraded node and the extra one-way latency (ms) applied to every
    /// message to or from it — models induced local slowness for Lifeguard tests.
    slow_node: Option<(NodeId, Millis)>,
}

impl VirtualCluster {
    /// Builds a cluster of the given nodes, each seeded deterministically and
    /// bootstrapped knowing every other node as alive.
    #[must_use]
    pub fn new(
        node_ids: &[NodeId],
        swim_config: SwimConfig,
        config: ClusterConfig,
        seed: u64,
    ) -> Self {
        let mut nodes = BTreeMap::new();
        let mut partition = BTreeMap::new();
        let mut events = BTreeMap::new();
        for (index, id) in node_ids.iter().enumerate() {
            let mut swim = Swim::new(
                id.clone(),
                swim_config.clone(),
                seed.wrapping_add(index as u64),
            );
            for other in node_ids {
                if other != id {
                    swim.add_peer(0, other.clone());
                }
            }
            // Discard bootstrap (join) events so observers see only runtime
            // membership transitions.
            let _ = swim.drain_events();
            nodes.insert(id.clone(), swim);
            partition.insert(id.clone(), 0);
            events.insert(id.clone(), Vec::new());
        }
        Self {
            nodes,
            config,
            now: 0,
            queue: Vec::new(),
            dead: BTreeSet::new(),
            partition,
            events,
            // Decorrelate the loss PRNG from the per-node Swim seeds.
            rng: DetRng::new(seed ^ 0xA7C3_5E91_D24B_8F60),
            slow_node: None,
        }
    }

    /// Marks `node` as locally degraded: every message to or from it incurs
    /// `extra_ms` of additional one-way latency (induced local slowness).
    pub fn set_slow_node(&mut self, node: &NodeId, extra_ms: Millis) {
        self.slow_node = Some((node.clone(), extra_ms));
    }

    /// The current virtual time.
    #[must_use]
    pub const fn now(&self) -> Millis {
        self.now
    }

    /// `viewer`'s belief about `subject`'s state.
    #[must_use]
    pub fn view(&self, viewer: &NodeId, subject: &NodeId) -> Option<MemberState> {
        self.nodes
            .get(viewer)
            .and_then(|swim| swim.state_of(subject))
    }

    /// The membership events `node` has observed so far.
    #[must_use]
    pub fn events_of(&self, node: &NodeId) -> &[MembershipEvent] {
        self.events.get(node).map_or(&[], |log| log.as_slice())
    }

    /// Permanently kills `node`: it stops ticking and all its traffic is dropped.
    pub fn kill(&mut self, node: &NodeId) {
        self.dead.insert(node.clone());
        self.queue.retain(|m| &m.from != node && &m.to != node);
    }

    /// Splits the cluster into partitions; messages that would cross between
    /// groups are dropped until [`Self::heal`]. Nodes not listed stay in group 0.
    pub fn partition_groups(&mut self, groups: &[&[NodeId]]) {
        for (gid, group) in groups.iter().enumerate() {
            for id in group.iter() {
                self.partition.insert(id.clone(), gid as u8);
            }
        }
        let partition = &self.partition;
        self.queue
            .retain(|m| partition.get(&m.from) == partition.get(&m.to));
    }

    /// Heals all partitions (everyone back into one group).
    pub fn heal(&mut self) {
        for group in self.partition.values_mut() {
            *group = 0;
        }
    }

    /// Whether every live, non-target node believes each `dead` node is `Dead`.
    #[must_use]
    pub fn all_living_agree_dead(&self, dead: &[NodeId]) -> bool {
        for (id, swim) in &self.nodes {
            if self.dead.contains(id) || dead.iter().any(|d| d == id) {
                continue;
            }
            for d in dead {
                if swim.state_of(d) != Some(MemberState::Dead) {
                    return false;
                }
            }
        }
        true
    }

    /// Whether every live node believes each `subject` is `Alive` (used to check
    /// that a partition heal restored membership rather than killing the
    /// minority).
    #[must_use]
    pub fn all_living_agree_alive(&self, subjects: &[NodeId]) -> bool {
        for (id, swim) in &self.nodes {
            if self.dead.contains(id) {
                continue;
            }
            for subject in subjects {
                if id == subject {
                    continue;
                }
                if swim.state_of(subject) != Some(MemberState::Alive) {
                    return false;
                }
            }
        }
        true
    }

    /// Advances the simulation by `duration_ms` virtual milliseconds.
    pub fn advance(&mut self, duration_ms: Millis) {
        let target = self.now.saturating_add(duration_ms);
        while self.now < target {
            self.step();
        }
    }

    fn step(&mut self) {
        self.now = self.now.saturating_add(self.config.tick_ms);
        self.deliver_due();
        self.tick_nodes();
    }

    fn deliver_due(&mut self) {
        let now = self.now;
        let mut due = Vec::new();
        let mut remaining = Vec::new();
        for message in std::mem::take(&mut self.queue) {
            if message.deliver_at <= now {
                due.push(message);
            } else {
                remaining.push(message);
            }
        }
        self.queue = remaining;
        // Deterministic delivery order regardless of enqueue order.
        due.sort_by(|a, b| {
            a.deliver_at
                .cmp(&b.deliver_at)
                .then_with(|| a.from.cmp(&b.from))
                .then_with(|| a.to.cmp(&b.to))
        });

        for message in due {
            if !self.reachable(&message.from, &message.to) {
                continue;
            }
            // Seeded packet loss (best-effort transport model).
            if self.config.loss_permille > 0
                && (self.rng.next_usize(1000) as u16) < self.config.loss_permille
            {
                continue;
            }
            let outcome = if let Some(node) = self.nodes.get_mut(&message.to) {
                let out = node.handle(now, message.from.clone(), message.packet);
                let drained = node.drain_events();
                Some((out, drained))
            } else {
                None
            };
            if let Some((out, drained)) = outcome {
                self.collect_events(&message.to, drained);
                self.enqueue(&message.to, out);
            }
        }
    }

    fn tick_nodes(&mut self) {
        let now = self.now;
        let live: Vec<NodeId> = self
            .nodes
            .keys()
            .filter(|id| !self.dead.contains(*id))
            .cloned()
            .collect();
        for id in live {
            let outcome = if let Some(node) = self.nodes.get_mut(&id) {
                let out = node.tick(now);
                let drained = node.drain_events();
                Some((out, drained))
            } else {
                None
            };
            if let Some((out, drained)) = outcome {
                self.collect_events(&id, drained);
                self.enqueue(&id, out);
            }
        }
    }

    fn enqueue(&mut self, from: &NodeId, outgoing: Vec<Outgoing>) {
        for packet in outgoing {
            if !self.reachable(from, &packet.to) {
                continue;
            }
            let mut latency = self.config.latency_ms;
            if let Some((slow, extra)) = self.slow_node.as_ref() {
                if from == slow || &packet.to == slow {
                    latency = latency.saturating_add(*extra);
                }
            }
            let deliver_at = self.now.saturating_add(latency);
            self.queue.push(InFlight {
                deliver_at,
                from: from.clone(),
                to: packet.to,
                packet: packet.packet,
            });
        }
    }

    fn collect_events(&mut self, node: &NodeId, drained: Vec<MembershipEvent>) {
        if let Some(log) = self.events.get_mut(node) {
            log.extend(drained);
        }
    }

    fn reachable(&self, from: &NodeId, to: &NodeId) -> bool {
        !self.dead.contains(from)
            && !self.dead.contains(to)
            && self.partition.get(from) == self.partition.get(to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: usize) -> Vec<NodeId> {
        (0..n).map(|i| NodeId::new(format!("n{i}"))).collect()
    }

    #[test]
    fn cluster_stabilizes_with_no_faults() {
        let nodes = ids(5);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 7);
        cluster.advance(10_000);
        // No deaths: everyone still sees everyone else alive (no false positives).
        assert!(cluster.all_living_agree_alive(&nodes));
    }

    #[test]
    fn seven_node_kill_two_converges_to_dead() {
        // Parent AC2 (death half): kill 2 of 7, the survivors converge on Dead.
        let nodes = ids(7);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 42);
        cluster.advance(3_000); // settle
        cluster.kill(&nodes[5]);
        cluster.kill(&nodes[6]);
        // Advance well past the suspicion window (max ~24s for small clusters).
        cluster.advance(120_000);
        assert!(cluster.all_living_agree_dead(&[nodes[5].clone(), nodes[6].clone()]));
    }

    #[test]
    fn partition_heal_refutes_suspicion() {
        // Parent AC2 (heal half): a transient partition that heals before the
        // suspicion timeout must not leave anyone permanently dead.
        let nodes = ids(5);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 11);
        cluster.advance(3_000);
        // Split off the last two nodes.
        let majority = [nodes[0].clone(), nodes[1].clone(), nodes[2].clone()];
        let minority = [nodes[3].clone(), nodes[4].clone()];
        cluster.partition_groups(&[&majority, &minority]);
        // Hold the partition briefly (under the suspicion timeout), then heal.
        cluster.advance(3_000);
        cluster.heal();
        cluster.advance(15_000);
        // Refutation restored everyone; no node was wrongly confirmed dead.
        assert!(cluster.all_living_agree_alive(&nodes));
    }

    #[test]
    fn killed_node_traffic_is_dropped() {
        let nodes = ids(3);
        let mut cluster =
            VirtualCluster::new(&nodes, SwimConfig::default(), ClusterConfig::default(), 5);
        cluster.advance(1_000);
        cluster.kill(&nodes[2]);
        // The killed node no longer responds, so survivors confirm it dead.
        cluster.advance(120_000);
        assert_eq!(cluster.view(&nodes[0], &nodes[2]), Some(MemberState::Dead));
        assert_eq!(cluster.view(&nodes[1], &nodes[2]), Some(MemberState::Dead));
    }
}
