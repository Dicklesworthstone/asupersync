//! Deterministic virtual network.

use super::config::{NetworkConditions, NetworkConfig};
use crate::bytes::Bytes;
use crate::types::Time;
use crate::util::DetRng;
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::time::Duration;

pub(super) const MAX_DUPLICATE_PACKET_DELAY: Duration = Duration::from_millis(1);
const EXTRA_PACKET_DELAY_WINDOW_MICROS: u64 = 1_000;

/// Identifier for a virtual host.
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

/// A virtual network packet.
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

/// Fault injection event for the deterministic virtual network.
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

/// Simple trace event for deterministic virtual networking.
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
struct VirtualHost {
    #[allow(dead_code)] // retained for debug diagnostics
    name: String,
    inbox: Vec<Packet>,
    crashed: bool,
}

impl VirtualHost {
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
pub struct DeterministicNetwork {
    config: NetworkConfig,
    rng: DetRng,
    now: Time,
    next_host: u64,
    next_sequence: u64,
    hosts: HashMap<HostId, VirtualHost>,
    links: HashMap<LinkKey, NetworkConditions>,
    partitions: HashSet<LinkKey>,
    queue: BinaryHeap<ScheduledPacket>,
    in_flight: HashMap<LinkKey, usize>,
    link_next_available: HashMap<LinkKey, Time>,
    metrics: NetworkMetrics,
    trace: Vec<NetworkTraceEvent>,
}

impl DeterministicNetwork {
    /// Creates a new deterministic virtual network with the given configuration.
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

    /// Returns the current virtual network time.
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
        self.hosts.insert(id, VirtualHost::new(name.into()));
        id
    }

    /// Returns a reference to a host's inbox.
    #[must_use]
    pub fn inbox(&self, host: HostId) -> Option<&[Packet]> {
        self.hosts.get(&host).map(|h| h.inbox.as_slice())
    }

    /// Drains and returns all packets currently in a host's inbox.
    ///
    /// This is useful for harness-style consumers that must process each
    /// packet exactly once without repeatedly scanning historical deliveries.
    pub fn take_inbox(&mut self, host: HostId) -> Option<Vec<Packet>> {
        self.hosts
            .get_mut(&host)
            .map(|h| std::mem::take(&mut h.inbox))
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
            let duplicate_delay =
                Duration::from_micros(self.rng.next_u64() % EXTRA_PACKET_DELAY_WINDOW_MICROS);
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

    /// Injects a fault into the deterministic virtual network.
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
                self.drop_queued_packets_for_host(*host);
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
            let reorder_jitter =
                Duration::from_micros(self.rng.next_u64() % EXTRA_PACKET_DELAY_WINDOW_MICROS);
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

    fn drop_queued_packets_for_host(&mut self, host: HostId) {
        let mut retained = BinaryHeap::with_capacity(self.queue.len());
        while let Some(scheduled) = self.queue.pop() {
            if scheduled.packet.dst == host {
                self.decrement_in_flight(LinkKey::new(scheduled.packet.src, scheduled.packet.dst));
                self.drop_packet(scheduled.packet.src, scheduled.packet.dst);
            } else {
                retained.push(scheduled);
            }
        }
        self.queue = retained;
        self.link_next_available.retain(|link, _| link.dst != host);
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
#[path = "network_inline_tests.rs"]
mod tests;
