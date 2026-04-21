//! Fuzz target for LabNetwork virtual message routing.
//!
//! Exercises `SimulatedNetwork` with topology mutations, host crashes, and
//! adversarial link-condition churn. The harness replays the same scenario
//! twice to assert deterministic routing under a fixed seed and checks that
//! duplicate deliveries never exceed the simulator's own duplication metric.

#![no_main]

use arbitrary::Arbitrary;
use asupersync::bytes::Bytes;
use asupersync::lab::network::{
    Fault, JitterModel, LatencyModel, NetworkConditions, NetworkConfig, NetworkTraceKind,
    SimulatedNetwork,
};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

const MAX_HOSTS: usize = 6;
const MAX_OPERATIONS: usize = 64;
const MAX_PAYLOAD_SIZE: usize = 96;

#[derive(Arbitrary, Debug, Clone)]
struct FuzzInput {
    host_count: u8,
    seed: u64,
    max_queue_depth: u16,
    enable_bandwidth: bool,
    default_bandwidth: u32,
    default_conditions: FuzzLinkConditions,
    operations: Vec<Operation>,
}

#[derive(Arbitrary, Debug, Clone)]
struct FuzzLinkConditions {
    profile: LatencyProfile,
    loss_permille: u16,
    corrupt_permille: u16,
    duplicate_permille: u16,
    reorder_permille: u16,
    max_in_flight: u8,
    bandwidth: OptionalBandwidth,
    jitter: JitterProfile,
}

#[derive(Arbitrary, Debug, Clone)]
enum OptionalBandwidth {
    Inherit,
    Disabled,
    Explicit(u32),
}

#[derive(Arbitrary, Debug, Clone)]
enum LatencyProfile {
    Ideal,
    Local,
    Lan,
    Wan,
    Lossy,
    Congested,
    Satellite,
    FixedMicros(u16),
    UniformMicros { min: u16, max: u16 },
}

#[derive(Arbitrary, Debug, Clone)]
enum JitterProfile {
    None,
    UniformMicros(u16),
    Bursty {
        normal_micros: u16,
        burst_micros: u16,
        burst_permille: u16,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum Operation {
    SetLink {
        src: u8,
        dst: u8,
        conditions: FuzzLinkConditions,
    },
    Send {
        src: u8,
        dst: u8,
        payload: Vec<u8>,
    },
    Partition {
        hosts_a: Vec<u8>,
        hosts_b: Vec<u8>,
    },
    Heal {
        hosts_a: Vec<u8>,
        hosts_b: Vec<u8>,
    },
    Crash {
        host: u8,
    },
    Restart {
        host: u8,
    },
    Advance {
        millis: u16,
    },
    Flush,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeliveryRecord {
    host: u64,
    src: u64,
    dst: u64,
    message_id: u32,
    sent_at_nanos: u64,
    received_at_nanos: u64,
    corrupted: bool,
    payload_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceRecord {
    time_nanos: u64,
    kind: u8,
    src: u64,
    dst: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScenarioSummary {
    deliveries: Vec<DeliveryRecord>,
    trace: Vec<TraceRecord>,
    packets_sent: u64,
    packets_delivered: u64,
    packets_dropped: u64,
    packets_duplicated: u64,
    packets_corrupted: u64,
    duplicate_deliveries: usize,
    duplicate_possible: bool,
}

impl FuzzLinkConditions {
    fn to_network_conditions(&self) -> NetworkConditions {
        let mut conditions = match &self.profile {
            LatencyProfile::Ideal => NetworkConditions::ideal(),
            LatencyProfile::Local => NetworkConditions::local(),
            LatencyProfile::Lan => NetworkConditions::lan(),
            LatencyProfile::Wan => NetworkConditions::wan(),
            LatencyProfile::Lossy => NetworkConditions::lossy(),
            LatencyProfile::Congested => NetworkConditions::congested(),
            LatencyProfile::Satellite => NetworkConditions::satellite(),
            LatencyProfile::FixedMicros(micros) => NetworkConditions {
                latency: LatencyModel::Fixed(Duration::from_micros(u64::from((*micros).max(1)))),
                ..NetworkConditions::ideal()
            },
            LatencyProfile::UniformMicros { min, max } => {
                let raw_min = (*min).min(*max).max(1);
                let raw_max = (*max).max(*min).max(1);
                let min = u64::from(raw_min);
                let max = u64::from(raw_max);
                NetworkConditions {
                    latency: LatencyModel::Uniform {
                        min: Duration::from_micros(min),
                        max: Duration::from_micros(max),
                    },
                    ..NetworkConditions::ideal()
                }
            }
        };

        conditions.packet_loss = probability(self.loss_permille);
        conditions.packet_corrupt = probability(self.corrupt_permille);
        conditions.packet_duplicate = probability(self.duplicate_permille);
        conditions.packet_reorder = probability(self.reorder_permille);
        conditions.max_in_flight = usize::from(self.max_in_flight).max(1);
        conditions.bandwidth = match self.bandwidth {
            OptionalBandwidth::Inherit => None,
            OptionalBandwidth::Disabled => Some(0),
            OptionalBandwidth::Explicit(bytes_per_sec) => Some(u64::from(bytes_per_sec.max(1))),
        };
        conditions.jitter = match &self.jitter {
            JitterProfile::None => None,
            JitterProfile::UniformMicros(max) => Some(JitterModel::Uniform {
                max: Duration::from_micros(u64::from((*max).max(1))),
            }),
            JitterProfile::Bursty {
                normal_micros,
                burst_micros,
                burst_permille,
            } => Some(JitterModel::Bursty {
                normal_jitter: Duration::from_micros(u64::from((*normal_micros).max(1))),
                burst_jitter: Duration::from_micros(u64::from((*burst_micros).max(1))),
                burst_probability: probability(*burst_permille),
            }),
        };
        conditions
    }
}

fn probability(permille: u16) -> f64 {
    f64::from(permille.min(1_000)) / 1_000.0
}

fn normalize_host_count(count: u8) -> usize {
    usize::from(count).clamp(2, MAX_HOSTS)
}

fn host_at(
    hosts: &[asupersync::lab::network::HostId],
    index: u8,
) -> asupersync::lab::network::HostId {
    hosts[usize::from(index) % hosts.len()]
}

fn normalize_host_set(
    indexes: &[u8],
    hosts: &[asupersync::lab::network::HostId],
    forbidden: Option<&BTreeSet<u64>>,
) -> Vec<asupersync::lab::network::HostId> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for index in indexes.iter().take(MAX_HOSTS) {
        let host = host_at(hosts, *index);
        let raw = host.raw();
        if forbidden.is_some_and(|set| set.contains(&raw)) || !seen.insert(raw) {
            continue;
        }
        result.push(host);
    }
    result
}

fn make_payload(message_id: u32, payload: &[u8]) -> Bytes {
    let mut bytes = Vec::with_capacity(payload.len().min(MAX_PAYLOAD_SIZE) + 5);
    bytes.push(0xA5);
    bytes.extend_from_slice(&payload[..payload.len().min(MAX_PAYLOAD_SIZE)]);
    bytes.extend_from_slice(&message_id.to_le_bytes());
    Bytes::copy_from_slice(&bytes)
}

fn extract_message_id(payload: &[u8]) -> u32 {
    if payload.len() < 4 {
        return 0;
    }
    let start = payload.len() - 4;
    let mut id = [0u8; 4];
    id.copy_from_slice(&payload[start..]);
    u32::from_le_bytes(id)
}

fn trace_kind_code(kind: NetworkTraceKind) -> u8 {
    match kind {
        NetworkTraceKind::Send => 0,
        NetworkTraceKind::Deliver => 1,
        NetworkTraceKind::Drop => 2,
        NetworkTraceKind::Duplicate => 3,
        NetworkTraceKind::Reorder => 4,
    }
}

fn run_scenario(input: &FuzzInput) -> ScenarioSummary {
    let default_conditions = input.default_conditions.to_network_conditions();
    let config = NetworkConfig {
        seed: input.seed,
        default_conditions,
        capture_trace: true,
        max_queue_depth: usize::from(input.max_queue_depth).max(1),
        tick_resolution: Duration::from_micros(100),
        enable_bandwidth: input.enable_bandwidth,
        default_bandwidth: u64::from(input.default_bandwidth.max(1)),
    };
    let mut network = SimulatedNetwork::new(config);
    let host_count = normalize_host_count(input.host_count);
    let hosts = (0..host_count)
        .map(|index| network.add_host(format!("host-{index}")))
        .collect::<Vec<_>>();
    let mut overrides = BTreeMap::<(u64, u64), FuzzLinkConditions>::new();
    let mut next_message_id = 1u32;
    let mut duplicate_possible = false;

    for operation in input.operations.iter().take(MAX_OPERATIONS) {
        match operation {
            Operation::SetLink {
                src,
                dst,
                conditions,
            } => {
                let src = host_at(&hosts, *src);
                let dst = host_at(&hosts, *dst);
                overrides.insert((src.raw(), dst.raw()), conditions.clone());
                network.set_link_conditions(src, dst, conditions.to_network_conditions());
            }
            Operation::Send { src, dst, payload } => {
                let src = host_at(&hosts, *src);
                let dst = host_at(&hosts, *dst);
                let active_conditions = overrides
                    .get(&(src.raw(), dst.raw()))
                    .cloned()
                    .unwrap_or_else(|| input.default_conditions.clone());
                if active_conditions.duplicate_permille > 0 {
                    duplicate_possible = true;
                }
                let bytes = make_payload(next_message_id, payload);
                next_message_id = next_message_id.saturating_add(1);
                network.send(src, dst, bytes);
            }
            Operation::Partition { hosts_a, hosts_b } => {
                let left = normalize_host_set(hosts_a, &hosts, None);
                let left_raw = left.iter().map(|host| host.raw()).collect::<BTreeSet<_>>();
                let right = normalize_host_set(hosts_b, &hosts, Some(&left_raw));
                network.inject_fault(&Fault::Partition {
                    hosts_a: left,
                    hosts_b: right,
                });
            }
            Operation::Heal { hosts_a, hosts_b } => {
                let left = normalize_host_set(hosts_a, &hosts, None);
                let left_raw = left.iter().map(|host| host.raw()).collect::<BTreeSet<_>>();
                let right = normalize_host_set(hosts_b, &hosts, Some(&left_raw));
                network.inject_fault(&Fault::Heal {
                    hosts_a: left,
                    hosts_b: right,
                });
            }
            Operation::Crash { host } => {
                network.inject_fault(&Fault::HostCrash {
                    host: host_at(&hosts, *host),
                });
            }
            Operation::Restart { host } => {
                network.inject_fault(&Fault::HostRestart {
                    host: host_at(&hosts, *host),
                });
            }
            Operation::Advance { millis } => {
                network.run_for(Duration::from_millis(u64::from(*millis)));
            }
            Operation::Flush => network.run_until_idle(),
        }
    }

    network.run_until_idle();

    let mut deliveries = Vec::new();
    let mut delivered_ids = BTreeMap::<u32, usize>::new();
    for host in &hosts {
        if let Some(inbox) = network.inbox(*host) {
            for packet in inbox {
                let message_id = extract_message_id(&packet.payload);
                *delivered_ids.entry(message_id).or_insert(0) += 1;
                deliveries.push(DeliveryRecord {
                    host: host.raw(),
                    src: packet.src.raw(),
                    dst: packet.dst.raw(),
                    message_id,
                    sent_at_nanos: packet.sent_at.as_nanos(),
                    received_at_nanos: packet.received_at.as_nanos(),
                    corrupted: packet.corrupted,
                    payload_len: packet.payload.len(),
                });
            }
        }
    }

    let duplicate_deliveries = delivered_ids
        .values()
        .map(|count| count.saturating_sub(1))
        .sum::<usize>();

    let trace = network
        .trace()
        .iter()
        .map(|event| TraceRecord {
            time_nanos: event.time.as_nanos(),
            kind: trace_kind_code(event.kind),
            src: event.src.raw(),
            dst: event.dst.raw(),
        })
        .collect::<Vec<_>>();

    let metrics = network.metrics();
    ScenarioSummary {
        deliveries,
        trace,
        packets_sent: metrics.packets_sent,
        packets_delivered: metrics.packets_delivered,
        packets_dropped: metrics.packets_dropped,
        packets_duplicated: metrics.packets_duplicated,
        packets_corrupted: metrics.packets_corrupted,
        duplicate_deliveries,
        duplicate_possible,
    }
}

fuzz_target!(|input: FuzzInput| {
    let first = run_scenario(&input);
    let second = run_scenario(&input);
    assert_eq!(
        first, second,
        "same seed and topology mutations must replay identically"
    );

    assert!(
        first.packets_delivered <= first.packets_sent.saturating_add(first.packets_duplicated),
        "deliveries exceeded sends plus duplicate injections"
    );
    assert!(
        first.duplicate_deliveries <= first.packets_duplicated as usize,
        "observed duplicate deliveries exceeded duplicate injection metric"
    );
    if !first.duplicate_possible {
        assert_eq!(
            first.duplicate_deliveries, 0,
            "duplicate deliveries appeared even though all active links had packet_duplicate=0"
        );
    }

    let mut trace_counts = [0usize; 5];
    for record in &first.trace {
        let index = usize::from(record.kind);
        if index < trace_counts.len() {
            trace_counts[index] += 1;
        }
    }
    assert_eq!(
        trace_counts[trace_kind_code(NetworkTraceKind::Send) as usize],
        first.packets_sent as usize,
        "send trace count diverged from packets_sent"
    );
    assert_eq!(
        trace_counts[trace_kind_code(NetworkTraceKind::Deliver) as usize],
        first.packets_delivered as usize,
        "deliver trace count diverged from packets_delivered"
    );
    assert_eq!(
        trace_counts[trace_kind_code(NetworkTraceKind::Drop) as usize],
        first.packets_dropped as usize,
        "drop trace count diverged from packets_dropped"
    );
    assert_eq!(
        trace_counts[trace_kind_code(NetworkTraceKind::Duplicate) as usize],
        first.packets_duplicated as usize,
        "duplicate trace count diverged from packets_duplicated"
    );
});
