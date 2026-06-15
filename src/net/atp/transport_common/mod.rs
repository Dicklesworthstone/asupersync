//! Shared ATP transport helpers.
//!
//! `transport_common` owns transport-agnostic bounded-memory primitives that
//! TCP, RaptorQ, and native QUIC can reuse without copying private helpers.

pub mod streaming;

pub use streaming::{
    EntryDigest, SourceEntry, StagedEntryReceive, StreamingError, collect_entries,
    flat_merkle_root_from_digests, flat_merkle_root_from_slices, hash_file_streaming, hex_encode,
};
