#![allow(clippy::all)]
//! Legacy placeholder for the renamed `metamorphic_io_copy` integration target.
//!
//! The actual `io::copy` metamorphic suite now lives in
//! `tests/metamorphic_io_copy.rs`. Keeping this file empty avoids running the
//! same expensive proptest suite twice under two different test target names.
