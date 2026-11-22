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

#[cfg(feature = "full-runtime")]
pub mod builder;
#[cfg(feature = "full-runtime")]
pub mod decision_contract;
pub mod decoder;
pub mod gf256;
pub mod linalg;
#[cfg(feature = "full-runtime")]
pub mod offline_tuner;
#[cfg(feature = "full-runtime")]
pub mod pipeline;
#[cfg(feature = "full-runtime")]
pub mod proof;
#[cfg(feature = "full-runtime")]
pub mod regression;
pub mod rfc6330;
pub mod systematic;

#[cfg(feature = "full-runtime")]
pub use builder::{RaptorQReceiverBuilder, RaptorQSenderBuilder};
#[cfg(feature = "full-runtime")]
pub use pipeline::{
    RaptorQOffloadedSendSession, RaptorQReceiveSession, RaptorQReceiver, RaptorQSendSession,
    RaptorQSender, RaptorQSymbolSendSession, ReceiveAuthenticationSummary, ReceiveOutcome,
    SendOutcome, SendProgress,
};
#[cfg(feature = "full-runtime")]
pub use proof::{DecodeConfig, DecodeProof, DecodeProofBuilder, FailureReason, ProofOutcome};

#[cfg(any(test, feature = "test-internals"))]
pub mod test_log_schema;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod metamorphic_tests;

#[cfg(test)]
mod gf256_tests;
