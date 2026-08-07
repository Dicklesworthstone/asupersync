//! Published v0.3.9 artifact -> current reader/migrator/CLI journey.
//!
//! The source bytes are committed under `tests/fixtures/typed-format-historical-corpus`.
//! Their independent writer recipe is the locked standalone consumer fixture.

#![cfg(all(
    feature = "cli",
    feature = "test-internals",
    feature = "trace-compression"
))]

use asupersync::distributed::RegionSnapshot;
use asupersync::fs::{FilesystemOperationProbe, stage_write_atomic_with_probe_for_test};
use asupersync::lab::snapshot_restore::{SnapshotArtifact, SnapshotCodecError, SnapshotLimits};
use asupersync::trace::StreamingReplayer;
use asupersync::trace::file::{
    TRACE_FILE_VERSION, TraceFileError, TraceReader, migrate_trace_file,
};
use asupersync::trace::replay::{ReplayTrace, ReplayTraceError};
use asupersync::types::{
    LegacyTypedSymbolIdentity, ObjectId, SerializationFormat, Symbol, SymbolId, SymbolKind,
    TypeMismatchError, TypedSymbol,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;

const CORPUS: &str = include_str!("fixtures/typed-format-historical-corpus/v0.3.9.json");
const RERUN: &str = "RCH_REQUIRE_REMOTE=1 bash scripts/run_dependency_sovereignty_e2e.sh --scenario dep-sovereignty-asupersync_5z2scg_3_7_94b694387988";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HistoricalRecord {
    sequence: u64,
    label: String,
    payload: Vec<u8>,
}

fn artifact<'a>(corpus: &'a Value, artifact_id: &str) -> &'a Value {
    corpus["artifacts"]
        .as_array()
        .expect("artifact array")
        .iter()
        .find(|artifact| artifact["artifact_id"] == artifact_id)
        .unwrap_or_else(|| panic!("missing artifact {artifact_id}"))
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "hex length");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("ASCII hex");
            u8::from_str_radix(pair, 16).expect("valid hex byte")
        })
        .collect()
}

fn bytes(artifact: &Value) -> Vec<u8> {
    let bytes = decode_hex(
        artifact["bytes_hex"]
            .as_str()
            .expect("artifact carries committed bytes"),
    );
    assert_eq!(
        bytes.len(),
        artifact["byte_len"].as_u64().expect("byte length") as usize
    );
    assert_eq!(
        digest_hex(&bytes),
        artifact["sha256"].as_str().expect("artifact digest")
    );
    bytes
}

fn digest_hex(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut rendered, "{byte:02x}").expect("write to String");
    }
    rendered
}

fn current_symbol(bytes: Vec<u8>) -> Symbol {
    Symbol::new(
        SymbolId::new(ObjectId::new(0x0309, 0xA7), 0, 0),
        bytes,
        SymbolKind::Source,
    )
}

fn legacy_identity(artifact: &Value) -> LegacyTypedSymbolIdentity {
    LegacyTypedSymbolIdentity::new(
        u16::try_from(artifact["source_version"].as_u64().expect("source version"))
            .expect("u16 version"),
        artifact["extra"]["legacy_type_id"]
            .as_u64()
            .expect("legacy type id"),
        artifact["extra"]["legacy_schema_hash"]
            .as_u64()
            .expect("legacy schema hash"),
    )
}

fn run_cli<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args(args)
        .output()
        .expect("execute current asupersync CLI")
}

fn cli_success<I, S>(label: &str, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_cli(args);
    assert!(
        output.status.success(),
        "{label} failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn cli_failure<I, S>(label: &str, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_cli(args);
    assert!(
        !output.status.success(),
        "{label} unexpectedly succeeded: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    output
}

fn record_step(steps: &mut Vec<Value>, step: &str, details: Value) {
    let event = json!({
        "schema_version": "typed-format-cross-version-event-v1",
        "bead_id": "asupersync-5z2scg.3.7",
        "step": step,
        "outcome": "PASSED",
        "details": details,
    });
    println!("{}", serde_json::to_string(&event).expect("event JSON"));
    steps.push(event);
}

#[test]
fn published_v039_artifacts_survive_current_migration_replay_and_cli_journey() {
    let corpus: Value = serde_json::from_str(CORPUS).expect("historical corpus JSON");
    assert_eq!(
        corpus["schema_version"],
        "typed-format-historical-corpus-v1"
    );
    assert_eq!(corpus["source_release"]["version"], "0.3.9");
    assert_eq!(
        corpus["source_release"]["crate_checksum_sha256"],
        "1cbadf37dce3015a059ffe058804d958026e8b276d665116015e3126d2673cfe"
    );
    let workspace = tempfile::tempdir().expect("cross-version workspace");
    let mut steps = Vec::new();

    for (artifact_id, format) in [
        (
            "typed-symbol-v039-messagepack",
            SerializationFormat::MessagePack,
        ),
        ("typed-symbol-v039-bincode", SerializationFormat::Bincode),
    ] {
        let fixture = artifact(&corpus, artifact_id);
        let source = bytes(fixture);
        let identity = legacy_identity(fixture);
        let admitted = TypedSymbol::<HistoricalRecord>::try_from_legacy_symbol(
            current_symbol(source.clone()),
            identity,
        )
        .expect("trusted published identity admits legacy symbol");
        let value = admitted.into_value().expect("current generic reader");
        assert_eq!(value.sequence, 0x0309);
        assert_eq!(value.label, "published-v0.3.9");

        let migrated = TypedSymbol::from_value(&value, format).expect("current stable writer");
        assert_eq!(migrated.value().expect("current stable reader"), value);
        assert_ne!(
            &migrated.symbol().data()[6..23],
            &source[6..23],
            "current rewrite must replace the legacy build-sensitive identity"
        );
        let current_reader_sha256 = digest_hex(migrated.symbol().data());

        let mut invalid_magic = source.clone();
        invalid_magic[0] ^= 1;
        assert!(matches!(
            TypedSymbol::<HistoricalRecord>::try_from_legacy_symbol(
                current_symbol(invalid_magic),
                identity,
            ),
            Err(TypeMismatchError::InvalidMagic)
        ));
        assert!(matches!(
            TypedSymbol::<HistoricalRecord>::try_from_legacy_symbol(
                current_symbol(source),
                LegacyTypedSymbolIdentity::new(
                    identity.version.saturating_add(1),
                    identity.type_id,
                    identity.schema_hash,
                ),
            ),
            Err(TypeMismatchError::VersionMismatch { .. })
        ));
        record_step(
            &mut steps,
            artifact_id,
            json!({
                "source_version": identity.version,
                "source_sha256": fixture["sha256"],
                "source_size": fixture["byte_len"],
                "semantic_fingerprint": fixture["semantic_fingerprint"],
                "fixture_writer_target_sha256": fixture["extra"]["current_migrated_sha256"],
                "root_consumer_target_sha256": current_reader_sha256,
                "malformed_magic_rejected": true,
                "unknown_version_rejected": true,
            }),
        );
    }

    let replay_fixture = artifact(&corpus, "replay-blob-v039");
    let replay_bytes = bytes(replay_fixture);
    let replay = ReplayTrace::from_bytes(&replay_bytes).expect("current replay-blob reader");
    assert_eq!(
        replay.len(),
        replay_fixture["extra"]["event_count"]
            .as_u64()
            .expect("event count") as usize
    );
    assert!(ReplayTrace::from_bytes(&replay_bytes[..replay_bytes.len() - 1]).is_err());
    let mut unsupported_replay = replay.clone();
    unsupported_replay.metadata.version = u32::MAX;
    let unsupported_replay_bytes = unsupported_replay
        .to_bytes()
        .expect("encode unknown schema");
    assert!(matches!(
        ReplayTrace::from_bytes(&unsupported_replay_bytes),
        Err(ReplayTraceError::IncompatibleVersion { .. })
    ));
    record_step(
        &mut steps,
        "replay-blob-v039",
        json!({
            "source_version": replay.metadata.version,
            "source_sha256": replay_fixture["sha256"],
            "source_size": replay_fixture["byte_len"],
            "semantic_fingerprint": replay_fixture["semantic_fingerprint"],
            "truncation_rejected": true,
            "unknown_version_rejected": true,
        }),
    );

    let trace_fixture = artifact(&corpus, "trace-v2-boundary");
    let trace_bytes = bytes(trace_fixture);
    let legacy_trace = workspace.path().join("trace-v2-boundary.trace");
    std::fs::write(&legacy_trace, &trace_bytes).expect("materialize committed trace");
    let source_before = std::fs::read(&legacy_trace).expect("rollback source");
    let ordinary = TraceReader::open(&legacy_trace).expect("ordinary legacy trace reader");
    assert_eq!(ordinary.file_version(), 2);
    let ordinary_events = ordinary.load_all().expect("ordinary legacy events");

    let mut streaming = StreamingReplayer::open(&legacy_trace).expect("streaming legacy reader");
    let mut streamed_events = Vec::new();
    while let Some(event) = streaming.next_event().expect("stream legacy event") {
        streamed_events.push(event);
    }
    assert_eq!(streamed_events, ordinary_events);
    assert!(streaming.is_complete());

    let library_migrated = workspace.path().join("library-migrated-v3.trace");
    let receipt =
        migrate_trace_file(&legacy_trace, &library_migrated).expect("atomic library migration");
    assert_eq!(receipt.source_version, 2);
    assert_eq!(receipt.target_version, TRACE_FILE_VERSION);
    assert_eq!(receipt.events_copied, ordinary_events.len() as u64);
    assert_eq!(
        std::fs::read(&legacy_trace).expect("source after migration"),
        source_before
    );
    let migrated_events = TraceReader::open(&library_migrated)
        .expect("current trace reader")
        .load_all()
        .expect("checksummed migrated events");
    assert_eq!(migrated_events, ordinary_events);

    let info = cli_success(
        "trace info",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("info"),
            legacy_trace.as_os_str(),
        ],
    );
    let info: Value = serde_json::from_slice(&info.stdout).expect("trace info JSON");
    assert_eq!(info["file_version"], 2);
    assert_eq!(info["event_count"], ordinary_events.len());

    let events = cli_success(
        "trace events",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("events"),
            legacy_trace.as_os_str(),
        ],
    );
    let events: Vec<Value> = serde_json::from_slice(&events.stdout).expect("trace events JSON");
    assert_eq!(events.len(), ordinary_events.len());

    let verify = cli_success(
        "trace verify",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("verify"),
            legacy_trace.as_os_str(),
            OsStr::new("--strict"),
        ],
    );
    let verify: Value = serde_json::from_slice(&verify.stdout).expect("trace verify JSON");
    assert_eq!(verify["valid"], true);

    let cli_migrated = workspace.path().join("cli-migrated-v3.trace");
    let migrate = cli_success(
        "trace migrate",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("migrate"),
            legacy_trace.as_os_str(),
            cli_migrated.as_os_str(),
        ],
    );
    let migrate: Value = serde_json::from_slice(&migrate.stdout).expect("trace migrate JSON");
    assert_eq!(migrate["source_version"], 2);
    assert_eq!(migrate["target_version"], TRACE_FILE_VERSION);
    assert_eq!(migrate["rollback_source_preserved"], true);

    cli_success(
        "trace diff",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("diff"),
            legacy_trace.as_os_str(),
            cli_migrated.as_os_str(),
        ],
    );
    let export = cli_success(
        "trace export ndjson",
        [
            OsStr::new("trace"),
            OsStr::new("export"),
            cli_migrated.as_os_str(),
            OsStr::new("--format"),
            OsStr::new("ndjson"),
        ],
    );
    let exported_event_count = String::from_utf8(export.stdout)
        .expect("UTF-8 NDJSON")
        .lines()
        .inspect(|line| {
            serde_json::from_str::<Value>(line).expect("exported NDJSON event");
        })
        .count();
    assert_eq!(exported_event_count, ordinary_events.len());

    let compressed = workspace.path().join("cli-compressed-v3.trace");
    cli_success(
        "trace compress",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("compress"),
            cli_migrated.as_os_str(),
            compressed.as_os_str(),
            OsStr::new("--level"),
            OsStr::new("1"),
        ],
    );
    let compressed_reader = TraceReader::open(&compressed).expect("compressed current trace");
    assert!(compressed_reader.is_compressed());
    assert_eq!(
        compressed_reader.load_all().expect("compressed events"),
        ordinary_events
    );

    let existing_output = workspace.path().join("existing.trace");
    std::fs::write(&existing_output, b"sentinel").expect("seed existing output");
    cli_failure(
        "trace migrate refuses overwrite",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("migrate"),
            legacy_trace.as_os_str(),
            existing_output.as_os_str(),
        ],
    );
    assert_eq!(
        std::fs::read(&existing_output).expect("read existing output"),
        b"sentinel"
    );

    let truncated_trace = workspace.path().join("truncated-v2.trace");
    std::fs::write(&truncated_trace, &trace_bytes[..trace_bytes.len() - 1])
        .expect("write truncated trace");
    let truncated_target = workspace.path().join("truncated-target.trace");
    cli_failure(
        "truncated trace migration",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("migrate"),
            truncated_trace.as_os_str(),
            truncated_target.as_os_str(),
        ],
    );
    assert!(
        !truncated_target.exists(),
        "failed migration must not publish a partial output"
    );

    let invalid_magic_trace = workspace.path().join("invalid-magic.trace");
    let mut invalid_magic = trace_bytes.clone();
    invalid_magic[0] ^= 1;
    std::fs::write(&invalid_magic_trace, invalid_magic).expect("write invalid magic trace");
    cli_failure(
        "invalid trace magic",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("info"),
            invalid_magic_trace.as_os_str(),
        ],
    );

    let unknown_version_trace = workspace.path().join("unknown-version.trace");
    let mut unknown_version = trace_bytes.clone();
    unknown_version[11..13].copy_from_slice(&u16::MAX.to_le_bytes());
    std::fs::write(&unknown_version_trace, unknown_version).expect("write unknown trace version");
    cli_failure(
        "unknown trace version",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("info"),
            unknown_version_trace.as_os_str(),
        ],
    );

    let corrupt_checksum_trace = workspace.path().join("corrupt-checksum-v3.trace");
    let mut corrupt_checksum =
        std::fs::read(&cli_migrated).expect("read current checksummed trace");
    *corrupt_checksum.last_mut().expect("last event byte") ^= 1;
    std::fs::write(&corrupt_checksum_trace, corrupt_checksum)
        .expect("write checksum-corrupt trace");
    assert!(matches!(
        TraceReader::open(&corrupt_checksum_trace)
            .expect("header remains readable")
            .load_all(),
        Err(TraceFileError::ChecksumMismatch { .. } | TraceFileError::Deserialize(_))
    ));
    cli_failure(
        "corrupt trace checksum",
        [
            OsStr::new("-f"),
            OsStr::new("json"),
            OsStr::new("trace"),
            OsStr::new("verify"),
            corrupt_checksum_trace.as_os_str(),
        ],
    );

    let missing_parent_target = workspace
        .path()
        .join("missing-parent")
        .join("migrated.trace");
    assert!(migrate_trace_file(&legacy_trace, &missing_parent_target).is_err());
    assert!(!missing_parent_target.exists());
    assert_eq!(
        std::fs::read(&legacy_trace).expect("source after disk/path failure"),
        source_before
    );
    assert!(
        std::fs::read_dir(workspace.path())
            .expect("read workspace")
            .all(|entry| {
                !entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .contains(".asupersync-migrate-")
            }),
        "migration staging paths must be cleaned"
    );
    record_step(
        &mut steps,
        "trace-v2-boundary-current-cli",
        json!({
            "source_version": 2,
            "target_version": TRACE_FILE_VERSION,
            "source_sha256": trace_fixture["sha256"],
            "source_size": trace_fixture["byte_len"],
            "semantic_fingerprint": trace_fixture["semantic_fingerprint"],
            "ordinary_reader": true,
            "streaming_reader": true,
            "cli_paths": ["info", "events", "verify", "diff", "migrate", "export-ndjson", "compress"],
            "truncation_rejected": true,
            "invalid_magic_rejected": true,
            "unknown_version_rejected": true,
            "checksum_rejected": true,
            "existing_output_preserved": true,
            "disk_failure_target_absent": true,
            "rollback_source_preserved": true,
        }),
    );

    let snapshot_fixture = artifact(&corpus, "runtime-snapshot-v1");
    let legacy_snapshot_bytes = bytes(snapshot_fixture);
    let legacy_snapshot_path = workspace.path().join("runtime-snapshot-v1.json");
    std::fs::write(&legacy_snapshot_path, &legacy_snapshot_bytes)
        .expect("materialize legacy snapshot");
    let decoded_snapshot = SnapshotArtifact::from_bytes(&legacy_snapshot_bytes)
        .expect("current legacy snapshot reader")
        .materialize(None, SnapshotLimits::DEFAULT)
        .expect("materialize legacy snapshot");
    assert_eq!(decoded_snapshot.schema_version, 1);
    let migrated_snapshot = decoded_snapshot
        .migrate_to_current()
        .expect("migrate runtime snapshot");
    let current_snapshot_bytes =
        SnapshotArtifact::full(migrated_snapshot.clone(), SnapshotLimits::DEFAULT)
            .expect("current full snapshot")
            .to_bytes()
            .expect("current snapshot envelope");
    let current_snapshot_path = workspace.path().join("runtime-snapshot-v2.asup");
    futures_lite::future::block_on(async {
        asupersync::fs::write_atomic(&current_snapshot_path, &current_snapshot_bytes)
            .await
            .expect("atomic current snapshot install");
    });
    assert_eq!(
        std::fs::read(&legacy_snapshot_path).expect("legacy snapshot rollback source"),
        legacy_snapshot_bytes
    );
    let installed_snapshot =
        SnapshotArtifact::from_bytes(&std::fs::read(&current_snapshot_path).expect("target bytes"))
            .expect("installed current snapshot")
            .materialize(None, SnapshotLimits::DEFAULT)
            .expect("materialize installed snapshot");
    assert_eq!(
        serde_json::to_value(&installed_snapshot.snapshot).expect("installed semantics"),
        serde_json::to_value(&migrated_snapshot.snapshot).expect("migrated semantics")
    );

    assert!(SnapshotArtifact::from_bytes(&current_snapshot_bytes[..8]).is_err());
    let mut corrupt_snapshot = current_snapshot_bytes.clone();
    *corrupt_snapshot.last_mut().expect("snapshot payload byte") ^= 1;
    assert!(matches!(
        SnapshotArtifact::from_bytes(&corrupt_snapshot),
        Err(SnapshotCodecError::ChecksumMismatch)
    ));
    let mut unknown_snapshot = current_snapshot_bytes.clone();
    unknown_snapshot[8..10].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(
        SnapshotArtifact::from_bytes(&unknown_snapshot),
        Err(SnapshotCodecError::UnsupportedArtifactVersion { .. })
    ));

    let cancellation_target = workspace.path().join("cancelled-snapshot-target.asup");
    std::fs::write(&cancellation_target, b"installed-before-cancellation")
        .expect("seed cancellation target");
    let cancellation_before =
        std::fs::read(&cancellation_target).expect("target before cancellation");
    let probe = Arc::new(FilesystemOperationProbe::new());
    futures_lite::future::block_on(async {
        let mut staged = Box::pin(stage_write_atomic_with_probe_for_test(
            &cancellation_target,
            &current_snapshot_bytes,
            Arc::clone(&probe),
        ));
        assert!(
            futures_lite::future::poll_once(staged.as_mut())
                .await
                .is_none()
        );
        assert!(
            probe.wait_until_blocked(Duration::from_secs(5)),
            "atomic staging reached cancellation gate"
        );
        assert_eq!(
            std::fs::read(&cancellation_target).expect("target during cancellation"),
            cancellation_before
        );
        drop(staged);
        probe.release();
        assert!(
            probe.wait_until_completed(Duration::from_secs(5)),
            "discarded staging cleaned up"
        );
    });
    assert_eq!(
        std::fs::read(&cancellation_target).expect("target after cancellation"),
        cancellation_before
    );

    let snapshot_disk_failure = workspace
        .path()
        .join("missing-snapshot-parent")
        .join("snapshot.asup");
    let disk_failure = futures_lite::future::block_on(asupersync::fs::write_atomic(
        &snapshot_disk_failure,
        &current_snapshot_bytes,
    ));
    assert!(disk_failure.is_err());
    assert!(!snapshot_disk_failure.exists());
    assert_eq!(
        std::fs::read(&legacy_snapshot_path).expect("snapshot source after failures"),
        legacy_snapshot_bytes
    );
    record_step(
        &mut steps,
        "runtime-snapshot-v1-to-v2",
        json!({
            "source_version": 1,
            "target_version": migrated_snapshot.schema_version,
            "source_sha256": snapshot_fixture["sha256"],
            "source_size": snapshot_fixture["byte_len"],
            "semantic_fingerprint": snapshot_fixture["semantic_fingerprint"],
            "truncation_rejected": true,
            "checksum_rejected": true,
            "unknown_version_rejected": true,
            "cancellation_preserved_target": true,
            "disk_failure_target_absent": true,
            "atomic_target_installed": true,
            "rollback_source_preserved": true,
        }),
    );

    let distributed_fixture = artifact(&corpus, "distributed-snapshot-v2");
    let distributed_bytes = bytes(distributed_fixture);
    let distributed =
        RegionSnapshot::from_bytes(&distributed_bytes).expect("current distributed reader");
    assert_eq!(distributed.to_bytes(), distributed_bytes);
    assert!(RegionSnapshot::from_bytes(&distributed_bytes[..8]).is_err());
    let mut unknown_distributed = distributed_bytes.clone();
    unknown_distributed[4..6].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(RegionSnapshot::from_bytes(&unknown_distributed).is_err());
    record_step(
        &mut steps,
        "distributed-snapshot-v2",
        json!({
            "source_version": 2,
            "source_sha256": distributed_fixture["sha256"],
            "source_size": distributed_fixture["byte_len"],
            "semantic_fingerprint": distributed_fixture["semantic_fingerprint"],
            "current_reserialization_exact": true,
            "truncation_rejected": true,
            "unknown_version_rejected": true,
        }),
    );

    let large_trace = artifact(&corpus, "trace-v2-large");
    assert_eq!(large_trace["byte_len"], 69_332);
    assert_eq!(large_trace["bytes_hex"], Value::Null);
    assert_eq!(large_trace["extra"]["event_count"], 4_096);
    assert_eq!(
        large_trace["extra"]["committed_representation"],
        "digest-and-published-writer-recipe"
    );
    record_step(
        &mut steps,
        "trace-v2-large-published-writer-recipe",
        json!({
            "source_version": 2,
            "source_sha256": large_trace["sha256"],
            "source_size": large_trace["byte_len"],
            "semantic_fingerprint": large_trace["semantic_fingerprint"],
            "event_count": large_trace["extra"]["event_count"],
            "writer_fixture": corpus["source_release"]["writer_fixture"],
        }),
    );

    let summary = json!({
        "schema_version": "typed-format-cross-version-summary-v1",
        "bead_id": "asupersync-5z2scg.3.7",
        "source_release": corpus["source_release"],
        "current_trace_version": TRACE_FILE_VERSION,
        "artifact_count": corpus["artifacts"].as_array().expect("artifacts").len(),
        "steps": steps,
        "outcome": "PASSED",
        "cleanup": {
            "partial_targets_absent": true,
            "staging_paths_absent": true,
            "rollback_sources_preserved": true,
        },
        "rerun": RERUN,
        "no_claim_boundaries": corpus["no_claim_boundaries"],
    });
    println!(
        "typed-format-cross-version-summary={}",
        serde_json::to_string(&summary).expect("summary JSON")
    );
    assert_eq!(summary["artifact_count"], 7);
}
