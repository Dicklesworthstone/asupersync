//! Deterministic network simulation for distributed testing.

mod config;
pub mod harness;
mod network;

pub use config::{JitterModel, LatencyModel, NetworkConditions, NetworkConfig};
pub use harness::{
    DistributedHarness, FaultScript, HarnessFault, HarnessTraceEvent, HarnessTraceKind, NodeEvent,
    SimNode,
};
pub use network::{
    Fault, HostId, NetworkMetrics, NetworkTraceEvent, NetworkTraceKind, Packet, SimulatedNetwork,
};
