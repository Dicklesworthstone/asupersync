//! ATP End-to-End Proof Suite Module
//!
//! Comprehensive testing for ATP object graph, manifest, disk, journal,
//! verifier, and crash-resume functionality. This module implements the
//! receiver trust boundary where ATP proves itself or fails.

#![allow(unused_imports)]

pub mod crash_injection;
pub mod e2e_proof_suite;
pub mod forensics;
pub mod multi_peer;
pub mod obligation_tracking;
pub mod quic;
pub mod security;

pub use crash_injection::*;
pub use e2e_proof_suite::*;
pub use forensics::*;
pub use multi_peer::*;
pub use obligation_tracking::*;
pub use quic::*;
pub use security::*;
