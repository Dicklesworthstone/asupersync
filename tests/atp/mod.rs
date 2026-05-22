//! ATP End-to-End Proof Suite Module
//!
//! Comprehensive testing for ATP object graph, manifest, disk, journal,
//! verifier, and crash-resume functionality. This module implements the
//! receiver trust boundary where ATP proves itself or fails.

pub mod crash_injection;
pub mod e2e_proof_suite;
pub mod forensics;
pub mod obligation_tracking;
pub mod quic;

pub use crash_injection::*;
pub use e2e_proof_suite::*;
pub use forensics::*;
pub use obligation_tracking::*;
pub use quic::*;
