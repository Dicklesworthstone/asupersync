//! Metamorphic tests for asupersync components.
//!
//! These tests validate properties of the system using metamorphic relations
//! rather than oracle-based testing, following the one rule: "When you can't
//! verify what the output is, verify how outputs relate to each other under
//! known input transformations."

pub mod evidence_serialization;
pub mod rwlock;
pub mod scheduler_migration;