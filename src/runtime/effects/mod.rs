//! Two-phase effect system for cancel-safe network operations.
//!
//! The asupersync runtime enforces structured concurrency and cancel-safety through
//! a two-phase effect pattern. All effects that modify external state must follow
//! the reserve/commit pattern to ensure no data loss on cancellation.
//!
//! # Two-Phase Pattern
//!
//! 1. **Reserve**: Create an effect permit that reserves resources/capacity
//! 2. **Commit**: Execute the effect using the permit, or **Abort** to cancel
//!
//! This ensures that:
//! - Resources are reserved before use (preventing oversubscription)
//! - Effects can be cancelled without data loss
//! - Proper obligation tracking for region quiescence
//!
//! # Network Operations
//!
//! Network operations MUST use this pattern:
//!
//! ```ignore
//! // WRONG: Direct send (not cancel-safe)
//! stream.send(data).await?;
//!
//! // CORRECT: Two-phase send (cancel-safe)
//! let permit = stream.reserve_send().await?;
//! permit.commit(data)?;
//! ```

pub mod atp_stream_example;
pub mod network;
pub mod send_permit;

pub use atp_stream_example::TwoPhasedAtpStream;
pub use network::{DirectSend, TwoPhaseNetworkSend};
pub use send_permit::SendPermit;
