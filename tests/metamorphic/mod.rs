//! Metamorphic tests for asupersync components.
//!
//! These tests validate properties of the system using metamorphic relations
//! rather than oracle-based testing, following the one rule: "When you can't
//! verify what the output is, verify how outputs relate to each other under
//! known input transformations."

pub mod blocking_pool;
pub mod evidence_serialization;
pub mod metrics;
pub mod monad_laws;
pub mod obligation_eprocess;
pub mod obligation_marking;
pub mod plan_analysis;
pub mod quic_packet_number;
pub mod runtime_waker;
pub mod rwlock;
pub mod scheduler_migration;
pub mod separation_logic;
pub mod symbol_cancel;
pub mod task_table;
pub mod types_budget;
pub mod vclock_merge;
