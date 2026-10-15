//! QUIC DATAGRAM Frame Support (RFC 9221)
//!
//! Implements unreliable DATAGRAM frames for ATP path probes, beacons,
//! and non-critical telemetry. Never used for correctness-critical transfers.

pub mod beacons;
pub mod congestion;
pub mod frame;
pub mod probes;
pub mod transport;

#[cfg(test)]
mod tests;

pub use beacons::*;
pub use congestion::*;
pub use frame::*;
pub use probes::*;
pub use transport::*;
