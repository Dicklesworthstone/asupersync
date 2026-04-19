//! Canonical integration target for `tests/metamorphic/io_copy.rs`.
//!
//! `tests/io_copy_metamorphic_test_suite.rs` is kept as the historical alias
//! and intentionally left empty so the expensive proptest suite only runs once.

include!("metamorphic/io_copy.rs");
