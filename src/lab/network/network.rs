//! Deterministic network simulation.

use super::config::{NetworkConditions, NetworkConfig};
use crate::bytes::Bytes;
use crate::types::Time;
use crate::util::DetRng;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::Duration;

/// Identifier for a simulated host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostId(u64);

impl HostId {
    /// Creates a host id from a raw integer.
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the raw host identifier.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A simulated packet.
#[derive(Debug, Clone)]
pub struct Packet {
    /// Source host.
    pub src: HostId,
    /// Destination host.
    pub dst: HostId,
    /// Packet payload.
    pub payload: Bytes,
    /// Time when the packet was sent.
    pub sent_at: Time,
    /// Time when the packet was delivered.
    pub received_at: Time,
    /// Whether corruption was injected.
    pub corrupted: bool,
}

/// Fault injection event for the simulated network.
#[derive(Debug, Clone)]
pub enum Fault {
    /// Partition hosts into two sets.
    Partition {
        /// First host set.
        hosts_a: Vec<HostId>,
        /// Second host set.
        hosts_b: Vec<HostId>,
    },
    /// Heal a partition between two sets.
    Heal {
        /// First host set.
        hosts_a: Vec<HostId>,
        /// Second host set.
        hosts_b: Vec<HostId>,
    },
    /// Crash a host (clears inbox, drops future deliveries).
    HostCrash {
        /// Host to crash.
        host: HostId,
    },
    /// Restart a host (clears crash flag, keeps inbox empty).
    HostRestart {
        /// Host to restart.
        host: HostId,
    },
}

/// Network metrics for diagnostics.
#[derive(Debug, Default, Clone)]
pub struct NetworkMetrics {
    /// Total packets submitted.
    pub packets_sent: u64,
    /// Total packets delivered.
    pub packets_delivered: u64,
    /// Total packets dropped.
    pub packets_dropped: u64,
    /// Total packets corrupted.
    pub packets_corrupted: u64,
}

/// Simple trace event for network simulation.
#[derive(Debug, Clone)]
pub struct NetworkTraceEvent {
    /// Event timestamp.
    pub time: Time,
    /// Event kind.
    pub kind: NetworkTraceKind,
    /// Source host.
    pub src: HostId,
    /// Destination host.
    pub dst: HostId,
}

/// Trace event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTraceKind {
    /// Packet send attempt.
    Send,
    /// Packet delivered.
    Deliver,
    /// Packet dropped.
    Drop,
}

#[derive(Debug)]
struct SimulatedHost {
    name: String,
    inbox: Vec<Packet>,
    crashed: bool,
}

impl SimulatedHost {
    fn new(name: String) -> Self {
        Self {
            name,
            inbox: Vec::new(),
            crashed: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LinkKey {
    src: HostId,
    dst: HostId,
}

impl LinkKey {
    fn new(src: HostId, dst: HostId) -> Self {
        Self { src, dst }
    }
}

#[derive(Debug, Clone)]
struct ScheduledPacket {
    deliver_at: Time,
    sequence: u64,
    packet: Packet,
}

impl Ord for ScheduledPacket {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .deliver_at
            .cmp(&self.deliver_at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for ScheduledPacket {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ScheduledPacket {
    fn eq(&self, other: &Self) -> bool {
        self.deliver_at == other.deliver_at && self.sequence == other.sequence
    }
}

impl Eq for ScheduledPacket {}

/// Deterministic network simulator.
#[derive(Debug)]
pub struct SimulatedNetwork {
    config: NetworkConfig,
    rng: DetRng,
    now: Time,
    next_host: u64,
    next_sequence: u64,
    hosts: HashMap<HostId, SimulatedHost>,
    links: HashMap<LinkKey, NetworkConditions>,
    partitions: HashSet<LinkKey>,
    queue: BinaryHeap<ScheduledPacket>,
    link_next_available: HashMap<LinkKey, Time>,
    metrics: NetworkMetrics,
    trace: Vec<NetworkTraceEvent>,
}

impl SimulatedNetwork {
    /// Creates a new simulated network with the given configuration.
    #[must_use]
    pub fn new(config: NetworkConfig) -> Self {
        let rng = DetRng::new(config.seed);
        Self {
            config,
            rng,
            now: Time::ZERO,
            next_host: 1,
            next_sequence: 0,
            hosts: HashMap::new(),
            links: HashMap::new(),
            partitions: HashSet::new(),
            queue: BinaryHeap::new(),
            link_next_available: HashMap::new(),
            metrics: NetworkMetrics::default(),
            trace: Vec::new(),
        }
    }

    /// Returns the current simulated time.
    #[must_use]
    pub const fn now(&self) -> Time {
        self.now
    }

    /// Returns the collected network metrics.
    #[must_use]
    pub fn metrics(&self) -> &NetworkMetrics {
        &self.metrics
    }

    /// Returns the trace buffer.
    #[must_use]
    pub fn trace(&self) -> &[NetworkTraceEvent] {
        &self.trace
    }

    /// Adds a new host and returns its id.
    pub fn add_host(&mut self, name: impl Into<String>) -> HostId {
        let id = HostId::new(self.next_host);
        self.next_host = self.next_host.saturating_add(1);
        self.hosts.insert(id, SimulatedHost::new(name.into()));
        id
    }

    /// Returns a reference to a host's inbox.
    #[must_use]
    pub fn inbox(&self, host: HostId) -> Option<&[Packet]> {
        self.hosts.get(&host).map(|h| h.inbox.as_slice())
    }

    /// Sets custom network conditions for a link.
    pub fn set_link_conditions(&mut self, src: HostId, dst: HostId, conditions: NetworkConditions) {
        self.links.insert(LinkKey::new(src, dst), conditions);
    }

    /// Sends a packet from src to dst.
    pub fn send(&mut self, src: HostId, dst: HostId, payload: Bytes) {
        self.metrics.packets_sent = self.metrics.packets_sent.saturating_add(1);
        self.trace_event(NetworkTraceKind::Send, src, dst);

        if self.queue.len() >= self.config.max_queue_depth {
            self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
            self.trace_event(NetworkTraceKind::Drop, src, dst);
            return;
        }

        if self.is_partitioned(src, dst) {
            self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
            self.trace_event(NetworkTraceKind::Drop, src, dst);
            return;
        }

        let Some(src_host) = self.hosts.get(&src) else {
            self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
            self.trace_event(NetworkTraceKind::Drop, src, dst);
            return;
        };
        let Some(dst_host) = self.hosts.get(&dst) else {
            self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
            self.trace_event(NetworkTraceKind::Drop, src, dst);
            return;
        };
        if src_host.crashed || dst_host.crashed {
            self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
            self.trace_event(NetworkTraceKind::Drop, src, dst);
            return;
        }

        let conditions = self.link_conditions(src, dst);
        if self.should_drop(conditions.packet_loss) {
            self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
            self.trace_event(NetworkTraceKind::Drop, src, dst);
            return;
        }

        let (payload, corrupted) = self.maybe_corrupt(payload, conditions.packet_corrupt);
        let base_latency = conditions.latency.sample(&mut self.rng);
        let jitter = conditions
            .jitter
            .as_ref()
            .map_or(Duration::ZERO, |j| j.sample(&mut self.rng));
        let mut deliver_at = self.now + base_latency + jitter;

        if self.config.enable_bandwidth {
            if let Some(bw) = conditions.bandwidth.or(Some(self.config.default_bandwidth)) {
                if bw > 0 {
                    let link = LinkKey::new(src, dst);
                    let next_available = self
                        .link_next_available
                        .get(&link)
                        .copied()
                        .unwrap_or(self.now);
                    if next_available > deliver_at {
                        deliver_at = next_available;
                    }
                    let tx_nanos = bytes_to_nanos(payload.len(), bw);
                    deliver_at = deliver_at.saturating_add_nanos(tx_nanos);
                    self.link_next_available.insert(link, deliver_at);
                }
            }
        }

        if self.should_drop(conditions.packet_reorder) {
            let reorder_jitter = Duration::from_micros(self.rng.next_u64() % 1000);
            deliver_at = deliver_at + reorder_jitter;
        }

        let packet = Packet {
            src,
            dst,
            payload,
            sent_at: self.now,
            received_at: deliver_at,
            corrupted,
        };
        let scheduled = ScheduledPacket {
            deliver_at,
            sequence: self.next_sequence,
            packet,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.queue.push(scheduled);
    }

    /// Runs the simulation for the given duration.
    pub fn run_for(&mut self, duration: Duration) {
        let target = self.now + duration;
        self.run_until(target);
    }

    /// Runs the simulation until the given time.
    pub fn run_until(&mut self, target: Time) {
        while let Some(next) = self.queue.peek() {
            if next.deliver_at > target {
                break;
            }
            let next = self.queue.pop().expect("pop queued packet");
            self.now = next.deliver_at;
            self.deliver(next.packet);
        }
        self.now = target;
    }

    /// Runs until the queue is empty.
    pub fn run_until_idle(&mut self) {
        while let Some(next) = self.queue.pop() {
            self.now = next.deliver_at;
            self.deliver(next.packet);
        }
    }

    /// Injects a fault into the simulated network.
    pub fn inject_fault(&mut self, fault: &Fault) {
        match fault {
            Fault::Partition { hosts_a, hosts_b } => {
                for a in hosts_a {
                    for b in hosts_b {
                        self.partitions.insert(LinkKey::new(*a, *b));
                        self.partitions.insert(LinkKey::new(*b, *a));
                    }
                }
            }
            Fault::Heal { hosts_a, hosts_b } => {
                for a in hosts_a {
                    for b in hosts_b {
                        self.partitions.remove(&LinkKey::new(*a, *b));
                        self.partitions.remove(&LinkKey::new(*b, *a));
                    }
                }
            }
            Fault::HostCrash { host } => {
                if let Some(h) = self.hosts.get_mut(host) {
                    h.crashed = true;
                    h.inbox.clear();
                }
            }
            Fault::HostRestart { host } => {
                if let Some(h) = self.hosts.get_mut(host) {
                    h.crashed = false;
                    h.inbox.clear();
                }
            }
        }
    }

    fn deliver(&mut self, packet: Packet) {
        if self.is_partitioned(packet.src, packet.dst) {
            self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
            self.trace_event(NetworkTraceKind::Drop, packet.src, packet.dst);
            return;
        }

        let (trace_src, trace_dst) = {
            let Some(host) = self.hosts.get_mut(&packet.dst) else {
                self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
                return;
            };

            if host.crashed {
                self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
                self.trace_event(NetworkTraceKind::Drop, packet.src, packet.dst);
                return;
            }

            let src = packet.src;
            let dst = packet.dst;
            host.inbox.push(packet);
            self.metrics.packets_delivered = self.metrics.packets_delivered.saturating_add(1);
            host.inbox
                .last()
                .map_or((src, dst), |last| (last.src, last.dst))
        };
        self.trace_event(NetworkTraceKind::Deliver, trace_src, trace_dst);
    }

    fn link_conditions(&self, src: HostId, dst: HostId) -> NetworkConditions {
        self.links
            .get(&LinkKey::new(src, dst))
            .cloned()
            .unwrap_or_else(|| self.config.default_conditions.clone())
    }

    fn is_partitioned(&self, src: HostId, dst: HostId) -> bool {
        self.partitions.contains(&LinkKey::new(src, dst))
    }

    #[allow(clippy::cast_precision_loss)]
    fn should_drop(&mut self, prob: f64) -> bool {
        if prob <= 0.0 {
            return false;
        }
        if prob >= 1.0 {
            return true;
        }
        let sample = (self.rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        sample < prob
    }

    fn maybe_corrupt(&mut self, payload: Bytes, prob: f64) -> (Bytes, bool) {
        if prob <= 0.0 {
            return (payload, false);
        }
        if prob >= 1.0 || self.should_drop(prob) {
            let mut data = payload[..].to_vec();
            if !data.is_empty() {
                data[0] ^= 0x1;
            }
            let corrupted = !data.is_empty();
            let bytes = Bytes::copy_from_slice(&data);
            if corrupted {
                self.metrics.packets_corrupted = self.metrics.packets_corrupted.saturating_add(1);
            }
            return (bytes, corrupted);
        }
        (payload, false)
    }

    fn trace_event(&mut self, kind: NetworkTraceKind, src: HostId, dst: HostId) {
        if self.config.capture_trace {
            self.trace.push(NetworkTraceEvent {
                time: self.now,
                kind,
                src,
                dst,
            });
        }
    }
}

fn bytes_to_nanos(len: usize, bandwidth: u64) -> u64 {
    if len == 0 || bandwidth == 0 {
        return 0;
    }
    let nanos = (len as u128)
        .saturating_mul(1_000_000_000u128)
        .saturating_div(u128::from(bandwidth));
    nanos.min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::network::NetworkConfig;

    #[test]
    fn deterministic_delivery_same_seed() {
        let config = NetworkConfig {
            seed: 123,
            ..Default::default()
        };
        let mut net1 = SimulatedNetwork::new(config.clone());
        let mut net2 = SimulatedNetwork::new(config);

        let a1 = net1.add_host("a");
        let b1 = net1.add_host("b");
        let a2 = net2.add_host("a");
        let b2 = net2.add_host("b");

        let payload = Bytes::copy_from_slice(b"hello");
        for _ in 0..10 {
            net1.send(a1, b1, payload.clone());
            net2.send(a2, b2, payload.clone());
        }

        net1.run_until_idle();
        net2.run_until_idle();

        let inbox1 = net1.inbox(b1).unwrap();
        let inbox2 = net2.inbox(b2).unwrap();
        assert_eq!(inbox1.len(), inbox2.len());
        for (p1, p2) in inbox1.iter().zip(inbox2.iter()) {
            assert_eq!(p1.received_at, p2.received_at);
            assert_eq!(p1.payload[..], p2.payload[..]);
        }
    }

    #[test]
    fn partition_drops_packets() {
        let mut net = SimulatedNetwork::new(NetworkConfig::default());
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.inject_fault(&Fault::Partition {
            hosts_a: vec![h1],
            hosts_b: vec![h2],
        });

        net.send(h1, h2, Bytes::copy_from_slice(b"drop"));
        net.run_for(Duration::from_millis(10));

        assert!(net.inbox(h2).unwrap().is_empty());
        assert_eq!(net.metrics().packets_dropped, 1);
    }
}
