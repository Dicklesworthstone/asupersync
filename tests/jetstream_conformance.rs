//! JetStream conformance test suite
//!
//! Run with: rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_jetstream_conformance cargo test --test jetstream_conformance

#[path = "conformance/jetstream/mod.rs"]
mod jetstream_conformance;
