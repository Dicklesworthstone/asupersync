//! Shared wire types for receiver-driven ATP delta negotiation.
//!
//! The sender advertises a bounded chunk manifest in `ObjectManifest`; the
//! receiver answers with an `ObjectRequest` selecting a full transfer, an
//! explicit missing-chunk set, or a live already-in-sync receipt path. Keeping
//! these types transport-neutral lets TCP, authenticated QUIC, and protected RQ
//! use one fail-closed control schema. These data-transfer objects do not
//! authenticate themselves: each transport must bind them to its current
//! session, transfer, destination, and terminal committed receipt.

use serde::{Deserialize, Serialize};

/// Canonical schema tag for ATP's receiver-driven delta chunk manifest.
pub const ATP_DELTA_CHUNK_MANIFEST_SCHEMA: &str = "asupersync.atp.tcp.delta-chunk-manifest.v1";

/// Sender-side chunk manifest used by receiver-driven delta planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeltaManifestWire {
    /// Stable schema tag for fail-closed receiver decoding.
    pub schema: String,
    /// Planner tree id. Bound to the transfer root name.
    pub tree_id: String,
    /// Fixed chunk size used to derive all chunk refs.
    pub chunk_size: usize,
    /// Total logical bytes represented by `chunks`.
    pub total_size_bytes: u64,
    /// Planner Merkle root over ordered content-addressed chunks.
    pub merkle_root_hex: String,
    /// Chunk refs in logical transfer order.
    pub chunks: Vec<DeltaChunkWire>,
}

/// One chunk ref in the sender delta manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct DeltaChunkWire {
    /// Planner chunk index in logical transfer order.
    pub index: u32,
    /// Manifest entry index this chunk belongs to.
    pub entry_index: u32,
    /// Transfer-relative path for diagnostics and receiver assembly.
    pub rel_path: String,
    /// Chunk offset within `rel_path`.
    pub entry_offset: u64,
    /// Chunk offset within the logical transfer stream.
    pub stream_offset: u64,
    /// Chunk length in bytes.
    pub size_bytes: u64,
    /// Hex-encoded domain-separated content id for the chunk bytes.
    pub content_id_hex: String,
}

/// Receiver-selected wire mode for one delta-capable object request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeltaWireMode {
    /// Send every object byte through the transport's ordinary full path.
    FullObject,
    /// Send only the receiver-selected missing chunks.
    DeltaChunks,
    /// Send no object bytes, but still require a live committed receipt.
    AlreadyInSync,
}

/// Receiver response to a sender's delta-capable object manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeltaObjectRequest {
    pub(crate) mode: DeltaWireMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fallback_reason: Option<String>,
    pub(crate) sender_merkle_root_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) receiver_merkle_root_hex: Option<String>,
    pub(crate) missing_bytes: u64,
    pub(crate) shared_chunks: u64,
    pub(crate) stale_chunks: u64,
    pub(crate) missing_chunks: Vec<DeltaChunkWire>,
}

impl DeltaObjectRequest {
    pub(crate) fn full(
        sender_merkle_root_hex: impl Into<String>,
        receiver_merkle_root_hex: Option<String>,
        fallback_reason: impl Into<String>,
    ) -> Self {
        Self {
            mode: DeltaWireMode::FullObject,
            fallback_reason: Some(fallback_reason.into()),
            sender_merkle_root_hex: sender_merkle_root_hex.into(),
            receiver_merkle_root_hex,
            missing_bytes: 0,
            shared_chunks: 0,
            stale_chunks: 0,
            missing_chunks: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn assert_legacy_request_fixture(fixture: Value, expected_mode: DeltaWireMode) {
        let decoded: DeltaObjectRequest =
            serde_json::from_value(fixture.clone()).expect("decode legacy delta request fixture");
        assert_eq!(decoded.mode, expected_mode);
        assert_eq!(
            serde_json::to_value(decoded).expect("encode legacy delta request fixture"),
            fixture
        );
    }

    #[test]
    fn legacy_delta_object_request_json_schema_is_stable() {
        assert_legacy_request_fixture(
            json!({
                "mode": "full_object",
                "fallback_reason": "receiver_delta_state_unavailable",
                "sender_merkle_root_hex": "11".repeat(32),
                "receiver_merkle_root_hex": "22".repeat(32),
                "missing_bytes": 0,
                "shared_chunks": 0,
                "stale_chunks": 0,
                "missing_chunks": []
            }),
            DeltaWireMode::FullObject,
        );
        assert_legacy_request_fixture(
            json!({
                "mode": "delta_chunks",
                "sender_merkle_root_hex": "33".repeat(32),
                "receiver_merkle_root_hex": "44".repeat(32),
                "missing_bytes": 7,
                "shared_chunks": 3,
                "stale_chunks": 1,
                "missing_chunks": [{
                    "index": 4,
                    "entry_index": 2,
                    "rel_path": "tree/leaf.bin",
                    "entry_offset": 9,
                    "stream_offset": 15,
                    "size_bytes": 7,
                    "content_id_hex": "55".repeat(32)
                }]
            }),
            DeltaWireMode::DeltaChunks,
        );
        assert_legacy_request_fixture(
            json!({
                "mode": "already_in_sync",
                "sender_merkle_root_hex": "66".repeat(32),
                "missing_bytes": 0,
                "shared_chunks": 9,
                "stale_chunks": 0,
                "missing_chunks": []
            }),
            DeltaWireMode::AlreadyInSync,
        );
    }

    #[test]
    fn legacy_delta_manifest_json_schema_is_stable() {
        let fixture = json!({
            "schema": "asupersync.atp.tcp.delta-chunk-manifest.v1",
            "tree_id": "tree-a",
            "chunk_size": 65536,
            "total_size_bytes": 7,
            "merkle_root_hex": "77".repeat(32),
            "chunks": [{
                "index": 4,
                "entry_index": 2,
                "rel_path": "tree/leaf.bin",
                "entry_offset": 9,
                "stream_offset": 15,
                "size_bytes": 7,
                "content_id_hex": "88".repeat(32)
            }]
        });
        let decoded: DeltaManifestWire =
            serde_json::from_value(fixture.clone()).expect("decode legacy delta manifest fixture");

        assert_eq!(
            serde_json::to_value(decoded).expect("encode legacy delta manifest fixture"),
            fixture
        );
    }
}
