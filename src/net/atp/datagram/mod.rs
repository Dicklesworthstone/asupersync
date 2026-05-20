//! QUIC DATAGRAM Frame Support (RFC 9221)
//!
//! Implements unreliable DATAGRAM frames for ATP path probes, beacons,
//! and non-critical telemetry. Never used for correctness-critical transfers.

pub mod frame;
pub mod transport;
pub mod beacons;
pub mod probes;
pub mod congestion;

#[cfg(test)]
mod tests;

pub use frame::*;
pub use transport::*;
pub use beacons::*;
pub use probes::*;
pub use congestion::*;