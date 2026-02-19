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
    /// Total packets duplicated.
    pub packets_duplicated: u64,
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
    /// Packet duplication injected.
    Duplicate,
    /// Packet reordering injected.
    Reorder,
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
    in_flight: HashMap<LinkKey, usize>,
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
            in_flight: HashMap::new(),
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

        if self.queue.len() >= self.config.max_queue_depth
            || self.is_partitioned(src, dst)
            || !self.endpoints_ready(src, dst)
        {
            self.drop_packet(src, dst);
            return;
        }

        let conditions = self.link_conditions(src, dst);
        let link = LinkKey::new(src, dst);
        if !self.check_in_flight(link, &conditions, src, dst) {
            return;
        }
        if self.should_drop(conditions.packet_loss) {
            self.drop_packet(src, dst);
            return;
        }

        let (payload, corrupted) = self.maybe_corrupt(payload, conditions.packet_corrupt);
        let mut deliver_at = self.compute_delivery_time(link, &conditions, payload.len());
        deliver_at = self.maybe_reorder(deliver_at, src, dst, &conditions);

        let base_packet = Packet {
            src,
            dst,
            payload,
            sent_at: self.now,
            received_at: deliver_at,
            corrupted,
        };
        if !self.try_schedule_packet(link, base_packet.clone(), src, dst) {
            return;
        }

        if self.should_drop(conditions.packet_duplicate) {
            self.metrics.packets_duplicated = self.metrics.packets_duplicated.saturating_add(1);
            self.trace_event(NetworkTraceKind::Duplicate, src, dst);
            let duplicate_delay = Duration::from_micros(self.rng.next_u64() % 1000);
            let duplicate = Packet {
                received_at: deliver_at + duplicate_delay,
                ..base_packet
            };
            if !self.check_in_flight(link, &conditions, src, dst) {
                return;
            }
            let _ = self.try_schedule_packet(link, duplicate, src, dst);
        }
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
        self.decrement_in_flight(LinkKey::new(packet.src, packet.dst));
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

    fn endpoints_ready(&self, src: HostId, dst: HostId) -> bool {
        let Some(src_host) = self.hosts.get(&src) else {
            return false;
        };
        let Some(dst_host) = self.hosts.get(&dst) else {
            return false;
        };
        !src_host.crashed && !dst_host.crashed
    }

    fn drop_packet(&mut self, src: HostId, dst: HostId) {
        self.metrics.packets_dropped = self.metrics.packets_dropped.saturating_add(1);
        self.trace_event(NetworkTraceKind::Drop, src, dst);
    }

    fn check_in_flight(
        &mut self,
        link: LinkKey,
        conditions: &NetworkConditions,
        src: HostId,
        dst: HostId,
    ) -> bool {
        if conditions.max_in_flight == usize::MAX {
            return true;
        }
        let in_flight = self.in_flight.get(&link).copied().unwrap_or(0);
        if in_flight >= conditions.max_in_flight {
            self.drop_packet(src, dst);
            return false;
        }
        true
    }

    fn compute_delivery_time(
        &mut self,
        link: LinkKey,
        conditions: &NetworkConditions,
        payload_len: usize,
    ) -> Time {
        let base_latency = conditions.latency.sample(&mut self.rng);
        let jitter = conditions
            .jitter
            .as_ref()
            .map_or(Duration::ZERO, |j| j.sample(&mut self.rng));
        let mut deliver_at = self.now + base_latency + jitter;

        if self.config.enable_bandwidth {
            if let Some(bw) = conditions.bandwidth.or(Some(self.config.default_bandwidth)) {
                if bw > 0 {
                    let next_available = self
                        .link_next_available
                        .get(&link)
                        .copied()
                        .unwrap_or(self.now);
                    if next_available > deliver_at {
                        deliver_at = next_available;
                    }
                    let tx_nanos = bytes_to_nanos(payload_len, bw);
                    deliver_at = deliver_at.saturating_add_nanos(tx_nanos);
                    self.link_next_available.insert(link, deliver_at);
                }
            }
        }

        deliver_at
    }

    fn maybe_reorder(
        &mut self,
        deliver_at: Time,
        src: HostId,
        dst: HostId,
        conditions: &NetworkConditions,
    ) -> Time {
        if self.should_drop(conditions.packet_reorder) {
            let reorder_jitter = Duration::from_micros(self.rng.next_u64() % 1000);
            self.trace_event(NetworkTraceKind::Reorder, src, dst);
            return deliver_at + reorder_jitter;
        }
        deliver_at
    }

    fn try_schedule_packet(
        &mut self,
        link: LinkKey,
        packet: Packet,
        src: HostId,
        dst: HostId,
    ) -> bool {
        if self.queue.len() >= self.config.max_queue_depth {
            self.drop_packet(src, dst);
            return false;
        }
        let scheduled = ScheduledPacket {
            deliver_at: packet.received_at,
            sequence: self.next_sequence,
            packet,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.queue.push(scheduled);
        self.increment_in_flight(link);
        true
    }

    fn increment_in_flight(&mut self, link: LinkKey) {
        let count = self.in_flight.entry(link).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn decrement_in_flight(&mut self, link: LinkKey) {
        let Some(count) = self.in_flight.get_mut(&link) else {
            return;
        };
        if *count > 1 {
            *count -= 1;
        } else {
            self.in_flight.remove(&link);
        }
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
    let nanos = u128::from(len as u64)
        .saturating_mul(1_000_000_000u128)
        .saturating_div(u128::from(bandwidth));
    nanos.min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lab::network::{JitterModel, LatencyModel, NetworkConfig};

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
    fn multiple_hosts_receive() {
        let mut net = SimulatedNetwork::new(NetworkConfig::default());
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");
        let h3 = net.add_host("h3");

        net.send(h1, h2, Bytes::copy_from_slice(b"one"));
        net.send(h1, h3, Bytes::copy_from_slice(b"two"));
        net.run_until_idle();

        assert_eq!(net.inbox(h2).unwrap().len(), 1);
        assert_eq!(net.inbox(h3).unwrap().len(), 1);
    }

    #[test]
    fn fixed_latency_respected() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Fixed(Duration::from_millis(10)),
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"delay"));
        net.run_for(Duration::from_millis(9));
        assert!(net.inbox(h2).unwrap().is_empty());

        net.run_for(Duration::from_millis(1));
        assert_eq!(net.inbox(h2).unwrap().len(), 1);
    }

    #[test]
    fn uniform_latency_within_bounds() {
        let min = Duration::from_millis(5);
        let max = Duration::from_millis(15);
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Uniform { min, max },
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        for _ in 0..50 {
            net.send(h1, h2, Bytes::copy_from_slice(b"x"));
        }
        net.run_until_idle();

        for packet in net.inbox(h2).unwrap() {
            let nanos = packet.received_at.duration_since(packet.sent_at);
            let latency = Duration::from_nanos(nanos);
            assert!(latency >= min && latency <= max);
        }
    }

    #[test]
    fn packet_loss_drops_all() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                packet_loss: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"drop"));
        net.run_until_idle();

        assert!(net.inbox(h2).unwrap().is_empty());
        assert_eq!(net.metrics().packets_dropped, 1);
    }

    #[test]
    fn packet_corruption_marks_payload() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                packet_corrupt: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        let payload = Bytes::copy_from_slice(&[0b0000_0001]);
        net.send(h1, h2, payload.clone());
        net.run_until_idle();

        let packet = &net.inbox(h2).unwrap()[0];
        assert!(packet.corrupted);
        assert_ne!(packet.payload[..], payload[..]);
        assert_eq!(net.metrics().packets_corrupted, 1);
    }

    #[test]
    fn bandwidth_limiting_spaces_packets() {
        let config = NetworkConfig {
            enable_bandwidth: true,
            default_bandwidth: 1_000,
            default_conditions: NetworkConditions::ideal(),
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        let payload = Bytes::copy_from_slice(&vec![0u8; 1000]);
        net.send(h1, h2, payload.clone());
        net.send(h1, h2, payload);
        net.run_until_idle();

        let inbox = net.inbox(h2).unwrap();
        assert_eq!(inbox.len(), 2);
        assert_eq!(inbox[0].received_at.as_nanos(), 1_000_000_000);
        assert_eq!(inbox[1].received_at.as_nanos(), 2_000_000_000);
    }

    #[test]
    fn max_in_flight_limits_enforced() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Fixed(Duration::from_millis(10)),
                max_in_flight: 1,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"first"));
        net.send(h1, h2, Bytes::copy_from_slice(b"second"));
        net.run_until_idle();

        let inbox = net.inbox(h2).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(net.metrics().packets_dropped, 1);
    }

    #[test]
    fn trace_capture_records_events() {
        let config = NetworkConfig {
            capture_trace: true,
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"trace"));
        net.run_until_idle();

        let trace = net.trace();
        assert!(trace.iter().any(|e| e.kind == NetworkTraceKind::Send));
        assert!(trace.iter().any(|e| e.kind == NetworkTraceKind::Deliver));
    }

    #[test]
    fn host_crash_and_restart() {
        let mut net = SimulatedNetwork::new(NetworkConfig::default());
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"first"));
        net.run_until_idle();
        assert_eq!(net.inbox(h2).unwrap().len(), 1);

        net.inject_fault(&Fault::HostCrash { host: h2 });
        net.send(h1, h2, Bytes::copy_from_slice(b"drop"));
        net.run_until_idle();
        assert!(net.inbox(h2).unwrap().is_empty());

        net.inject_fault(&Fault::HostRestart { host: h2 });
        net.send(h1, h2, Bytes::copy_from_slice(b"after"));
        net.run_until_idle();
        assert_eq!(net.inbox(h2).unwrap().len(), 1);
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

    #[test]
    fn packet_duplication_delivers_twice() {
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                packet_duplicate: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"dup"));
        net.run_until_idle();

        let inbox = net.inbox(h2).unwrap();
        assert_eq!(inbox.len(), 2);
        assert_eq!(net.metrics().packets_duplicated, 1);
    }

    #[test]
    fn reorder_trace_records_event() {
        let config = NetworkConfig {
            capture_trace: true,
            default_conditions: NetworkConditions {
                packet_reorder: 1.0,
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        net.send(h1, h2, Bytes::copy_from_slice(b"reorder"));
        net.run_until_idle();

        let trace = net.trace();
        assert!(trace.iter().any(|e| e.kind == NetworkTraceKind::Reorder));
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let max = Duration::from_millis(5);
        let config = NetworkConfig {
            default_conditions: NetworkConditions {
                latency: LatencyModel::Fixed(Duration::ZERO),
                jitter: Some(JitterModel::Uniform { max }),
                ..NetworkConditions::ideal()
            },
            ..Default::default()
        };
        let mut net = SimulatedNetwork::new(config);
        let h1 = net.add_host("h1");
        let h2 = net.add_host("h2");

        for _ in 0..10 {
            net.send(h1, h2, Bytes::copy_from_slice(b"j"));
        }
        net.run_until_idle();

        for packet in net.inbox(h2).unwrap() {
            let nanos = packet.received_at.duration_since(packet.sent_at);
            let jitter = Duration::from_nanos(nanos);
            assert!(jitter <= max);
        }
    }

    // Pure data-type tests (wave 35 – CyanBarn)

    #[test]
    fn host_id_debug_copy_ord_hash() {
        use std::collections::HashSet;
        let h1 = HostId::new(1);
        let h2 = HostId::new(2);
        let h3 = HostId::new(1);

        let dbg = format!("{h1:?}");
        assert!(dbg.contains("HostId"));

        // Copy
        let h1_copy = h1;
        assert_eq!(h1, h1_copy);

        // Ord
        assert!(h1 < h2);
        assert_eq!(h1.cmp(&h3), std::cmp::Ordering::Equal);

        // Hash
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2);
        set.insert(h3); // duplicate of h1
        assert_eq!(set.len(), 2);

        // raw accessor
        assert_eq!(h1.raw(), 1);
        assert_eq!(h2.raw(), 2);
    }

    #[test]
    fn packet_debug_clone() {
        let pkt = Packet {
            src: HostId::new(1),
            dst: HostId::new(2),
            payload: Bytes::copy_from_slice(b"test"),
            sent_at: Time::ZERO,
            received_at: Time::from_nanos(1000),
            corrupted: false,
        };
        let dbg = format!("{pkt:?}");
        assert!(dbg.contains("Packet"));

        let cloned = pkt.clone();
        assert_eq!(cloned.src, HostId::new(1));
        assert_eq!(cloned.dst, HostId::new(2));
        assert!(!cloned.corrupted);
    }

    #[test]
    fn fault_debug_clone() {
        let partition = Fault::Partition {
            hosts_a: vec![HostId::new(1)],
            hosts_b: vec![HostId::new(2)],
        };
        let dbg = format!("{partition:?}");
        assert!(dbg.contains("Partition"));
        let cloned = partition.clone();
        let dbg2 = format!("{cloned:?}");
        assert_eq!(dbg, dbg2);

        let crash = Fault::HostCrash { host: HostId::new(5) };
        let dbg = format!("{crash:?}");
        assert!(dbg.contains("HostCrash"));
    }

    #[test]
    fn network_metrics_debug_default_clone() {
        let metrics = NetworkMetrics::default();
        assert_eq!(metrics.packets_sent, 0);
        assert_eq!(metrics.packets_delivered, 0);
        assert_eq!(metrics.packets_dropped, 0);
        assert_eq!(metrics.packets_duplicated, 0);
        assert_eq!(metrics.packets_corrupted, 0);

        let dbg = format!("{metrics:?}");
        assert!(dbg.contains("NetworkMetrics"));

        let cloned = metrics.clone();
        assert_eq!(cloned.packets_sent, 0);
    }

    #[test]
    fn network_trace_event_debug_clone() {
        let event = NetworkTraceEvent {
            time: Time::from_nanos(500),
            kind: NetworkTraceKind::Send,
            src: HostId::new(1),
            dst: HostId::new(2),
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("NetworkTraceEvent"));

        let cloned = event.clone();
        assert_eq!(cloned.kind, NetworkTraceKind::Send);
        assert_eq!(cloned.src, HostId::new(1));
    }

    #[test]
    fn network_trace_kind_debug_copy_eq() {
        let kinds = [
            NetworkTraceKind::Send,
            NetworkTraceKind::Deliver,
            NetworkTraceKind::Drop,
            NetworkTraceKind::Duplicate,
            NetworkTraceKind::Reorder,
        ];
        for kind in &kinds {
            let dbg = format!("{kind:?}");
            assert!(!dbg.is_empty());

            // Copy
            let copy = *kind;
            assert_eq!(*kind, copy);
        }

        // Distinct variants
        assert_ne!(NetworkTraceKind::Send, NetworkTraceKind::Deliver);
        assert_ne!(NetworkTraceKind::Drop, NetworkTraceKind::Duplicate);
    }
}
