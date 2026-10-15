//! Locked dual-version consumer for typed-format historical compatibility.
//!
//! The registry dependency is the published v0.3.9 writer. The path dependency
//! is the current reader/migrator. Keeping them in one process proves that the
//! committed bytes came from the historical public API rather than a
//! hand-authored approximation.

use asupersync_current::distributed::RegionSnapshot as CurrentRegionSnapshot;
use asupersync_current::lab::snapshot_restore::{
    SnapshotArtifact as CurrentSnapshotArtifact, SnapshotLimits as CurrentSnapshotLimits,
};
use asupersync_current::trace::file::{
    TRACE_FILE_VERSION as CURRENT_TRACE_FILE_VERSION, TraceReader as CurrentTraceReader,
    migrate_trace_file as current_migrate_trace_file,
};
use asupersync_current::trace::replay::ReplayTrace as CurrentReplayTrace;
use asupersync_current::types::{
    DeserializationError as CurrentDeserializationError, Deserializer as CurrentDeserializer,
    LegacyTypedSymbolIdentity, ObjectId, SerializationError as CurrentSerializationError,
    SerializationFormat as CurrentFormat, Serializer as CurrentSerializer, Symbol, SymbolId,
    SymbolKind, TypedSymbol as CurrentTypedSymbol,
};
use asupersync_v039::distributed::RegionSnapshot as HistoricalRegionSnapshot;
use asupersync_v039::lab::snapshot_restore::RestorableSnapshot as HistoricalSnapshot;
use asupersync_v039::runtime::state::RuntimeSnapshot as HistoricalRuntimeSnapshot;
use asupersync_v039::trace::file::{
    TRACE_FILE_VERSION as HISTORICAL_TRACE_FILE_VERSION, write_trace as historical_write_trace,
};
use asupersync_v039::trace::replay::{
    ReplayEvent as HistoricalReplayEvent, ReplayTrace as HistoricalReplayTrace,
    TraceMetadata as HistoricalTraceMetadata,
};
use asupersync_v039::types::{
    RegionId as HistoricalRegionId, SerializationFormat as HistoricalFormat,
    TypedSymbol as HistoricalTypedSymbol,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HistoricalRecord {
    sequence: u64,
    label: String,
    payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpaqueRecord {
    sequence: u32,
    payload: Vec<u8>,
}

struct OpaqueCodec;

impl CurrentSerializer<OpaqueRecord> for OpaqueCodec {
    fn serialize(
        &self,
        value: &OpaqueRecord,
        format: CurrentFormat,
    ) -> Result<Vec<u8>, CurrentSerializationError> {
        if format != CurrentFormat::Custom {
            return Err(CurrentSerializationError::SerializationFailed {
                reason: "opaque codec requires Custom".to_string(),
            });
        }
        let payload_len = u32::try_from(value.payload.len()).map_err(|_| {
            CurrentSerializationError::SerializationFailed {
                reason: "opaque payload length exceeds u32".to_string(),
            }
        })?;
        let mut bytes = Vec::with_capacity(8 + value.payload.len());
        bytes.extend_from_slice(&value.sequence.to_le_bytes());
        bytes.extend_from_slice(&payload_len.to_le_bytes());
        bytes.extend_from_slice(&value.payload);
        Ok(bytes)
    }
}

impl CurrentDeserializer<OpaqueRecord> for OpaqueCodec {
    fn deserialize(
        &self,
        bytes: &[u8],
        format: CurrentFormat,
    ) -> Result<OpaqueRecord, CurrentDeserializationError> {
        if format != CurrentFormat::Custom || bytes.len() < 8 {
            return Err(CurrentDeserializationError::CorruptData);
        }
        let sequence = u32::from_le_bytes(bytes[..4].try_into().expect("sequence"));
        let payload_len =
            u32::from_le_bytes(bytes[4..8].try_into().expect("payload length")) as usize;
        let expected_len = 8usize
            .checked_add(payload_len)
            .ok_or(CurrentDeserializationError::CorruptData)?;
        if bytes.len() != expected_len {
            return Err(CurrentDeserializationError::CorruptData);
        }
        Ok(OpaqueRecord {
            sequence,
            payload: bytes[8..].to_vec(),
        })
    }
}

fn historical_record() -> HistoricalRecord {
    HistoricalRecord {
        sequence: 0x0309,
        label: "published-v0.3.9".to_string(),
        payload: vec![0, 1, 2, 127, 128, 254, 255],
    }
}

fn legacy_identity(bytes: &[u8]) -> LegacyTypedSymbolIdentity {
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    let type_id = u64::from_le_bytes(bytes[6..14].try_into().expect("type id"));
    let schema_hash = u64::from_le_bytes(bytes[15..23].try_into().expect("schema hash"));
    LegacyTypedSymbolIdentity::new(version, type_id, schema_hash)
}

fn current_symbol(bytes: &[u8]) -> Symbol {
    Symbol::new(
        SymbolId::new(ObjectId::new(0x0309, 0xA7), 0, 0),
        bytes.to_vec(),
        SymbolKind::Source,
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut rendered, "{byte:02x}").expect("write to String");
    }
    rendered
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn artifact(
    artifact_id: &str,
    surface_id: &str,
    format: &str,
    source_version: Value,
    bytes: &[u8],
    semantics: &Value,
    extra: Value,
) -> Value {
    let semantic_bytes = serde_json::to_vec(semantics).expect("semantic fingerprint input");
    json!({
        "artifact_id": artifact_id,
        "surface_id": surface_id,
        "format": format,
        "source_version": source_version,
        "byte_len": bytes.len(),
        "sha256": sha256_hex(bytes),
        "semantic_fingerprint": sha256_hex(&semantic_bytes),
        "bytes_hex": hex(bytes),
        "extra": extra,
    })
}

fn historical_events(count: usize) -> Vec<HistoricalReplayEvent> {
    let mut events = Vec::with_capacity(count.max(1));
    events.push(HistoricalReplayEvent::RngSeed { seed: 0x0309_A7 });
    for value in 1..count {
        events.push(HistoricalReplayEvent::RngValue {
            value: u64::try_from(value).expect("fixture count fits u64"),
        });
    }
    events
}

fn capture_manifest(artifacts: Vec<Value>) -> Value {
    json!({
        "schema_version": "typed-format-historical-corpus-v1",
        "bead_id": "asupersync-5z2scg.3.7",
        "source_release": {
            "crate": "asupersync",
            "version": "0.3.9",
            "crate_checksum_sha256": "1cbadf37dce3015a059ffe058804d958026e8b276d665116015e3126d2673cfe",
            "git_tag": "v0.3.9",
            "git_commit": "e7e0af2fe0fc5037a087296e22e5eb57a2c1d50a",
            "cargo_source": "registry+https://github.com/rust-lang/crates.io-index",
            "writer_fixture": "tests/fixtures/typed-format-cross-version-consumer",
        },
        "current_reader": {
            "crate_source": "path:../../..",
            "typed_symbol_admission": "explicit trusted LegacyTypedSymbolIdentity",
            "trace_target_version": CURRENT_TRACE_FILE_VERSION,
        },
        "artifacts": artifacts,
        "no_claim_boundaries": [
            "Proves only the exact published-writer artifacts and current readers exercised here.",
            "Does not prove arbitrary third-party type identity portability across old Rust toolchains.",
            "Does not authorize dependency, format, feature, or API removal.",
            "Does not prove performance or broad workspace health."
        ],
    })
}

/// Produce and verify the version-provenanced v0.3.9 artifact corpus.
#[must_use]
pub fn historical_corpus() -> Value {
    let expected = historical_record();
    let mut artifacts = Vec::new();

    for (historical_format, current_format) in [
        (HistoricalFormat::MessagePack, CurrentFormat::MessagePack),
        (HistoricalFormat::Bincode, CurrentFormat::Bincode),
    ] {
        let historical = HistoricalTypedSymbol::from_value(&expected, historical_format)
            .expect("published writer");
        let historical_bytes = historical.symbol().data();
        let identity = legacy_identity(historical_bytes);
        let admitted = CurrentTypedSymbol::<HistoricalRecord>::try_from_legacy_symbol(
            current_symbol(historical_bytes),
            identity,
        )
        .expect("provenance-bound legacy admission");
        let decoded = admitted.into_value().expect("current payload reader");
        assert_eq!(decoded, expected);

        let current = CurrentTypedSymbol::from_value(&decoded, current_format)
            .expect("current stable writer");
        assert_eq!(current.value().expect("current stable reader"), expected);
        assert_ne!(
            &current.symbol().data()[6..23],
            &historical_bytes[6..23],
            "migration must replace the legacy build-sensitive identity",
        );

        let format_name = match historical_format {
            HistoricalFormat::MessagePack => "MessagePack",
            HistoricalFormat::Bincode => "Bincode",
            _ => unreachable!("fixture uses binary formats"),
        };
        artifacts.push(artifact(
            &format!("typed-symbol-v039-{}", format_name.to_ascii_lowercase()),
            "PERSIST-TYPED-SYMBOL",
            format_name,
            json!(identity.version),
            historical_bytes,
            &serde_json::to_value(&expected).expect("record semantics"),
            json!({
                "legacy_type_id": identity.type_id,
                "legacy_schema_hash": identity.schema_hash,
                "current_migrated_sha256": sha256_hex(current.symbol().data()),
                "current_migrated_byte_len": current.symbol().data().len(),
            }),
        ));
    }

    let metadata = HistoricalTraceMetadata::new(0x0309_A7)
        .with_config_hash(0xA7_0309)
        .with_description("published-v0.3.9-cross-version-fixture");
    let events = historical_events(4);
    let mut replay = HistoricalReplayTrace::new(metadata.clone());
    for event in &events {
        replay.push(event.clone());
    }
    let replay_bytes = replay.to_bytes().expect("published replay writer");
    let current_replay =
        CurrentReplayTrace::from_bytes(&replay_bytes).expect("current replay reader");
    assert_eq!(
        serde_json::to_value(&current_replay).expect("current replay semantics"),
        serde_json::to_value(&replay).expect("historical replay semantics"),
    );
    artifacts.push(artifact(
        "replay-blob-v039",
        "PERSIST-REPLAY-BLOB",
        "MessagePack",
        json!(metadata.version),
        &replay_bytes,
        &serde_json::to_value(&replay).expect("replay semantics"),
        json!({"event_count": events.len()}),
    ));

    for (artifact_id, event_count) in [("trace-v2-boundary", 4), ("trace-v2-large", 4096)] {
        let events = historical_events(event_count);
        let directory = tempfile::tempdir().expect("trace fixture directory");
        let historical_path = directory.path().join("historical-v2.trace");
        let migrated_path = directory.path().join("migrated-v3.trace");
        historical_write_trace(&historical_path, &metadata, &events)
            .expect("published trace writer");
        let historical_bytes = std::fs::read(&historical_path).expect("historical trace bytes");

        let current_reader =
            CurrentTraceReader::open(&historical_path).expect("current trace reader");
        assert_eq!(current_reader.file_version(), HISTORICAL_TRACE_FILE_VERSION,);
        let current_events = current_reader.load_all().expect("load historical events");
        assert_eq!(
            serde_json::to_value(&current_events).expect("current event semantics"),
            serde_json::to_value(&events).expect("historical event semantics"),
        );

        let receipt = current_migrate_trace_file(&historical_path, &migrated_path)
            .expect("current trace migrator");
        assert_eq!(receipt.source_version, HISTORICAL_TRACE_FILE_VERSION);
        assert_eq!(receipt.target_version, CURRENT_TRACE_FILE_VERSION);
        assert_eq!(receipt.events_copied, event_count as u64);
        assert_eq!(
            std::fs::read(&historical_path).expect("rollback source"),
            historical_bytes,
        );

        artifacts.push(artifact(
            artifact_id,
            "PERSIST-TRACE-FILE",
            "ASUPERTRACE",
            json!(HISTORICAL_TRACE_FILE_VERSION),
            &historical_bytes,
            &json!({
                "metadata": metadata,
                "events": events,
            }),
            json!({
                "event_count": event_count,
                "target_version": receipt.target_version,
                "migrated_sha256": sha256_hex(
                    &std::fs::read(&migrated_path).expect("migrated trace"),
                ),
                "rollback_source_preserved": true,
            }),
        ));
    }

    let historical_runtime = HistoricalRuntimeSnapshot {
        timestamp: 0x0309,
        regions: Vec::new(),
        tasks: Vec::new(),
        obligations: Vec::new(),
        recent_events: Vec::new(),
        finalizer_history: Vec::new(),
        loser_drain_history: Vec::new(),
    };
    let historical_snapshot = HistoricalSnapshot::new(historical_runtime);
    let historical_snapshot_bytes =
        serde_json::to_vec_pretty(&historical_snapshot).expect("published snapshot writer");
    let current_snapshot = CurrentSnapshotArtifact::from_bytes(&historical_snapshot_bytes)
        .expect("current legacy snapshot reader")
        .materialize(None, CurrentSnapshotLimits::DEFAULT)
        .expect("materialize legacy snapshot");
    assert_eq!(current_snapshot.schema_version, 1);
    let migrated_snapshot = current_snapshot
        .clone()
        .migrate_to_current()
        .expect("current snapshot migration");
    assert_eq!(
        serde_json::to_value(&migrated_snapshot.snapshot).expect("current snapshot semantics"),
        serde_json::to_value(&historical_snapshot.snapshot).expect("historical snapshot semantics"),
    );
    artifacts.push(artifact(
        "runtime-snapshot-v1",
        "PERSIST-LAB-SNAPSHOT-HASH",
        "JSON",
        json!(historical_snapshot.schema_version),
        &historical_snapshot_bytes,
        &serde_json::to_value(&historical_snapshot.snapshot).expect("runtime snapshot semantics"),
        json!({
            "target_schema_version": migrated_snapshot.schema_version,
            "rollback_source_preserved": true,
        }),
    ));

    let historical_distributed =
        HistoricalRegionSnapshot::empty(HistoricalRegionId::testing_default());
    let historical_distributed_bytes = historical_distributed.to_bytes();
    let current_distributed = CurrentRegionSnapshot::from_bytes(&historical_distributed_bytes)
        .expect("current distributed snapshot reader");
    assert_eq!(current_distributed.to_bytes(), historical_distributed_bytes);
    artifacts.push(artifact(
        "distributed-snapshot-v2",
        "PERSIST-DISTRIBUTED-SNAPSHOT",
        "SNAP+Bincode",
        json!(2),
        &historical_distributed_bytes,
        &json!({
            "region_index": 0,
            "region_generation": 0,
            "state": "Open",
            "sequence": 0,
        }),
        json!({
            "current_reserialization_exact": true,
            "authentication": "stored zero tag; secure consumers must use from_bytes_with_key",
        }),
    ));

    let opaque = OpaqueRecord {
        sequence: 0xA7,
        payload: vec![0, 255, 1, 254, 2, 253],
    };
    let custom = CurrentTypedSymbol::from_value_with_serializer(
        &opaque,
        CurrentFormat::Custom,
        1,
        &OpaqueCodec,
    )
    .expect("current custom writer");
    assert_eq!(
        custom
            .value_with_deserializer(&OpaqueCodec)
            .expect("current custom reader"),
        opaque,
    );

    let mut manifest = capture_manifest(artifacts);
    manifest["artifacts"]
        .as_array_mut()
        .expect("artifact array")
        .iter_mut()
        .filter(|artifact| artifact["artifact_id"] == "trace-v2-large")
        .for_each(|artifact| {
            artifact["bytes_hex"] = Value::Null;
            artifact["extra"]["committed_representation"] =
                json!("digest-and-published-writer-recipe");
        });
    assert_eq!(
        manifest["artifacts"]
            .as_array()
            .expect("artifact array")
            .len(),
        7,
    );
    manifest
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    fn artifact<'a>(manifest: &'a Value, artifact_id: &str) -> &'a Value {
        manifest["artifacts"]
            .as_array()
            .expect("artifact array")
            .iter()
            .find(|artifact| artifact["artifact_id"] == artifact_id)
            .unwrap_or_else(|| panic!("missing artifact {artifact_id}"))
    }

    fn decoded_hex(value: &Value) -> Vec<u8> {
        let encoded = value
            .as_str()
            .expect("committed small artifact must contain hex");
        assert_eq!(encoded.len() % 2, 0);
        encoded
            .as_bytes()
            .chunks_exact(2)
            .map(|digits| {
                let digits = std::str::from_utf8(digits).expect("ASCII hex");
                u8::from_str_radix(digits, 16).expect("valid hex")
            })
            .collect()
    }

    #[test]
    fn published_writer_corpus_decodes_and_migrates_under_current_readers() {
        let manifest = super::historical_corpus();
        assert_eq!(manifest["source_release"]["version"], "0.3.9");
        let committed: serde_json::Value = serde_json::from_str(include_str!(
            "../../typed-format-historical-corpus/v0.3.9.json"
        ))
        .expect("committed historical corpus");

        let mut generated_metadata = manifest.clone();
        generated_metadata["artifacts"] = Value::Null;
        let mut committed_metadata = committed.clone();
        committed_metadata["artifacts"] = Value::Null;
        assert_eq!(generated_metadata, committed_metadata);

        for committed_artifact in committed["artifacts"]
            .as_array()
            .expect("committed artifact array")
        {
            let artifact_id = committed_artifact["artifact_id"]
                .as_str()
                .expect("artifact id");
            let generated_artifact = artifact(&manifest, artifact_id);
            if artifact_id.starts_with("typed-symbol-v039-") {
                // v0.3.9 derived these two header fields from Rust TypeId and
                // DefaultHasher. They are exact within the committed capture,
                // but deliberately not reproducible in a different build.
                for field in [
                    "artifact_id",
                    "surface_id",
                    "format",
                    "source_version",
                    "byte_len",
                    "semantic_fingerprint",
                ] {
                    assert_eq!(
                        generated_artifact[field], committed_artifact[field],
                        "{artifact_id} stable field {field} drifted",
                    );
                }
                assert_eq!(
                    generated_artifact["extra"]["current_migrated_sha256"],
                    committed_artifact["extra"]["current_migrated_sha256"],
                );
                assert_eq!(
                    generated_artifact["extra"]["current_migrated_byte_len"],
                    committed_artifact["extra"]["current_migrated_byte_len"],
                );

                let mut generated_bytes = decoded_hex(&generated_artifact["bytes_hex"]);
                let mut committed_bytes = decoded_hex(&committed_artifact["bytes_hex"]);
                generated_bytes[6..14].fill(0);
                generated_bytes[15..23].fill(0);
                committed_bytes[6..14].fill(0);
                committed_bytes[15..23].fill(0);
                assert_eq!(
                    generated_bytes, committed_bytes,
                    "{artifact_id} framing or payload drifted",
                );

                let exact_committed_bytes = decoded_hex(&committed_artifact["bytes_hex"]);
                let identity = super::legacy_identity(&exact_committed_bytes);
                let admitted =
                    super::CurrentTypedSymbol::<super::HistoricalRecord>::try_from_legacy_symbol(
                        super::current_symbol(&exact_committed_bytes),
                        identity,
                    )
                    .expect("committed provenance tuple admits exact historical bytes");
                assert_eq!(
                    admitted.into_value().expect("committed payload decodes"),
                    super::historical_record(),
                );
            } else {
                assert_eq!(
                    generated_artifact, committed_artifact,
                    "{artifact_id} must remain byte-reproducible",
                );
            }
        }
    }
}
