//! RaptorQ integration layer.
//!
//! This module wires together the encoding, decoding, transport, security,
//! and observability subsystems into cohesive sender/receiver pipelines.
//!
//! # Architecture
//!
//! ```text
//! Application
//!     │
//!     ▼
//! RaptorQSender / RaptorQReceiver   ← this module
//!     │                 │
//!     ▼                 ▼
//! EncodingPipeline  DecodingPipeline  (src/encoding.rs, src/decoding.rs)
//!     │                 │
//!     ▼                 ▼
//! SecurityContext    SecurityContext    (src/security/)
//!     │                 │
//!     ▼                 ▼
//! SymbolSink         SymbolStream      (src/transport/)
//! ```

pub mod builder;
pub mod decoder;
pub mod gf256;
pub mod linalg;
pub mod pipeline;
pub mod proof;
pub mod rfc6330;
pub mod systematic;

pub use builder::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
pub use pipeline::{RaptorQReceiver, RaptorQSender, ReceiveOutcome, SendOutcome, SendProgress};
pub use proof::{DecodeConfig, DecodeProof, DecodeProofBuilder, FailureReason, ProofOutcome};

#[cfg(any(test, feature = "test-internals"))]
pub mod test_log_schema;

#[cfg(test)]
mod tests;
