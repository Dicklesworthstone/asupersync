//! Shared ATP transport helpers.
//!
//! `transport_common` owns transport-agnostic bounded-memory primitives that
//! TCP, RaptorQ, and native QUIC can reuse without copying private helpers.

pub mod compression;
pub mod filter;
pub mod metadata;
pub mod mirror;
pub mod multi_object;
pub mod progress;
pub mod streaming;

pub use compression::{
    CompressionAlgorithm, CompressionDescriptor, CompressionError, CompressionPolicy,
    CompressionSkipReason, PreEncodeCompression, decompress_pre_encoded, maybe_compress_pre_encode,
};
pub use filter::{FilterAction, FilterDecision, FilterError, FilterRule, FilterSet};
pub use metadata::{
    DirtyPathSet, EntryMetadata, FileIdentity, FileKind, MetadataApplyReport, SimilaritySignature,
    ZeroScanDecision, ZeroScanEntry, ZeroScanFingerprint, ZeroScanHashReason, ZeroScanPlan,
    ZeroScanPolicy, ZeroScanPrefilter, apply_entry_metadata, metadata_commitment,
    read_entry_metadata,
};
pub use mirror::{
    MirrorEntryKind, MirrorError, MirrorExtra, MirrorPolicy, MirrorReport, mirror_dest,
};
pub use multi_object::{
    ATP_RQ_DEFAULT_MULTI_OBJECT_BLOCK_SIZE, ATP_RQ_MAX_SOURCE_BLOCKS_PER_OBJECT, MultiObjectPlan,
    MultiObjectShard, MultiObjectSplitConfig, MultiObjectSplitError, plan_multi_object_split,
};
pub use progress::{
    PlanEntry, PlanError, ProgressSnapshot, TransferPlan, TransferProgress, plan_transfer,
};
pub use streaming::{
    EntryDigest, SourceEntry, StagedEntryReceive, StreamingError, collect_entries,
    flat_merkle_root_from_digests, flat_merkle_root_from_slices, hash_file_streaming, hex_encode,
};
