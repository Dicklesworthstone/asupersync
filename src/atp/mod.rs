//! Asupersync Transfer Protocol data movement primitives.
//!
//! ATP is the project-owned data movement layer that combines native QUIC,
//! verified object graphs, resumable transfer journals, adaptive RaptorQ
//! repair, path establishment, and deterministic replay. The module starts
//! small on purpose: each submodule should expose a reusable, testable model
//! before endpoint, CLI, daemon, or relay code depends on it.

pub mod actor;
#[cfg(not(target_arch = "wasm32"))]
pub mod doctor;
pub mod grant;
pub mod identity;
pub mod journal;
pub mod manifest;
pub mod object;
pub mod path;
#[cfg(not(target_arch = "wasm32"))]
pub mod platform;
pub mod policy;
pub mod proof;
pub mod repair_receiver;
pub mod sdk;
pub mod stream_object;
pub mod transfer;
pub mod verifier;
pub mod verify;
pub mod writer;

pub use grant::{GrantManager, PairingCode, PairingManager, GrantInfo, GrantQuery, GrantStats};
pub use identity::{DurablePeerIdentity, IdentityError};
pub use policy::{Capability, CapabilityAction, PolicyEnforcer, ResourceScope, TemporalScope, PolicyDecision};
