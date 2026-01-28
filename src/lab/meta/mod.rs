//! Meta-testing infrastructure for verifying the test oracles themselves.
//!
//! Meta-tests run a baseline scenario and a mutation scenario, then confirm that
//! the appropriate oracle trips. This helps validate that the oracle suite
//! actually detects the kinds of violations we rely on in CI.

pub mod mutation;
pub mod runner;

pub use mutation::{
    builtin_mutations, invariant_from_violation, BuiltinMutation, ALL_ORACLE_INVARIANTS,
};
pub use runner::{MetaCoverageEntry, MetaCoverageReport, MetaReport, MetaResult, MetaRunner};
