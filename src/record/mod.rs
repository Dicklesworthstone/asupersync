//! Internal records for runtime entities.
//!
//! This module contains the internal record types used by the runtime
//! to track tasks, regions, and obligations.
//!
//! These are internal implementation details and not part of the public API.

pub mod finalizer;
pub mod obligation;
pub mod region;
pub mod task;

pub use finalizer::{Finalizer, FinalizerEscalation, FinalizerStack};
pub use obligation::{ObligationKind, ObligationRecord, ObligationState};
pub use region::RegionRecord;
pub use task::TaskRecord;
