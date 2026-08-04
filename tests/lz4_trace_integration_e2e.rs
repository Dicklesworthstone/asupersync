//! Retained trace integration, replay, malformed-input, and measurement receipt
//! for the owned size-prepended LZ4 block codec.
//!
//! Bead: asupersync-0h6myr.4.4
//! Capability: CAP-TRACE-LZ4

#![cfg(all(
    feature = "cli",
    feature = "test-internals",
    feature = "trace-compression"
))]

use asupersync::trace::file::lz4_integration_harness as owned;
use asupersync::trace::file::{
    CompressionMode, FLAG_COMPRESSED, HEADER_SIZE, LEGACY_HEADER_SIZE, MAX_COMPRESSED_CHUNK_LEN,
    TRACE_CHECKSUM_LEN, TRACE_FILE_VERSION, TRACE_MAGIC, TraceFileConfig, TraceFileError,
    TraceReader, migrate_trace_file, write_trace, write_trace_with_config,
};
use asupersync::trace::replay::{
    CompactTaskId, REPLAY_SCHEMA_VERSION, ReplayEvent, ReplayTrace, TraceMetadata,
};
use asupersync::trace::replayer::TraceReplayer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

const BEAD_ID: &str = "asupersync-0h6myr.4.4";
const CAPABILITY_ID: &str = "CAP-TRACE-LZ4";
const CORPUS_PATH: &str = "tests/fixtures/lz4-trace-historical-corpus/v0.3.9.json";
const RECEIPT_PATH: &str = "artifacts/lz4_trace_integration_go_no_go_v1.json";
const DOC_PATH: &str = "docs/lz4_trace_integration_go_no_go.md";
const RUNNER_PATH: &str = "scripts/run_dependency_sovereignty_e2e.sh";
const CORPUS: &str = include_str!("fixtures/lz4-trace-historical-corpus/v0.3.9.json");
const RECEIPT: &str = include_str!("../artifacts/lz4_trace_integration_go_no_go_v1.json");

fn repo_path(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn fixed_metadata() -> TraceMetadata {
    TraceMetadata {
        version: REPLAY_SCHEMA_VERSION,
        seed: 0xA4_1A_04,
        recorded_at: 1_726_133_456_789_000_000,
        config_hash: 0xA4A4_0404_C0DE_CAFE,
        description: Some("retained LZ4 trace integration corpus".to_string()),
    }
}

fn corpus_events() -> Vec<ReplayEvent> {
    vec![
        ReplayEvent::RngSeed { seed: 0xA4 },
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(7),
            at_tick: 0,
        },
        ReplayEvent::TimeAdvanced {
            from_nanos: 0,
            to_nanos: 1_000,
        },
        ReplayEvent::TaskYielded {
            task: CompactTaskId(7),
        },
        ReplayEvent::TaskScheduled {
            task: CompactTaskId(7),
            at_tick: 1,
        },
        ReplayEvent::TaskCompleted {
            task: CompactTaskId(7),
            outcome: 0,
        },
    ]
}

fn large_events(count: u64) -> Vec<ReplayEvent> {
    (0..count)
        .map(|index| ReplayEvent::TaskScheduled {
            task: CompactTaskId(index % 257),
            at_tick: index,
        })
        .collect()
}

fn canonical_event_frames(events: &[ReplayEvent]) -> Vec<u8> {
    let mut frames = Vec::new();
    for event in events {
        let bytes = rmp_serde::to_vec(event).expect("serialize replay event");
        let len = u32::try_from(bytes.len()).expect("fixture event fits u32");
        frames.extend_from_slice(&len.to_le_bytes());
        frames.extend_from_slice(&bytes);
    }
    frames
}

fn manual_v2_incumbent_trace(metadata: &TraceMetadata, events: &[ReplayEvent]) -> Vec<u8> {
    let metadata_bytes = rmp_serde::to_vec(metadata).expect("serialize metadata");
    let frames = canonical_event_frames(events);
    let compressed = lz4_flex::compress_prepend_size(&frames);
    let mut trace = Vec::new();
    trace.extend_from_slice(TRACE_MAGIC);
    trace.extend_from_slice(&2u16.to_le_bytes());
    trace.extend_from_slice(&FLAG_COMPRESSED.to_le_bytes());
    trace.push(1);
    trace.extend_from_slice(
        &u32::try_from(metadata_bytes.len())
            .expect("metadata fits u32")
            .to_le_bytes(),
    );
    trace.extend_from_slice(&metadata_bytes);
    trace.extend_from_slice(
        &u64::try_from(events.len())
            .expect("event count fits u64")
            .to_le_bytes(),
    );
    trace.extend_from_slice(
        &u32::try_from(compressed.len())
            .expect("compressed chunk fits u32")
            .to_le_bytes(),
    );
    trace.extend_from_slice(&compressed);
    trace
}

fn current_trace_bytes(use_owned: bool) -> Vec<u8> {
    let temp = tempfile::NamedTempFile::new().expect("create current trace");
    let config = TraceFileConfig::new()
        .with_compression(CompressionMode::Lz4 { level: 1 })
        .with_chunk_size(4 * 1024);
    if use_owned {
        owned::write_owned_trace(temp.path(), &fixed_metadata(), &corpus_events(), config)
            .expect("write owned current trace");
    } else {
        write_trace_with_config(temp.path(), &fixed_metadata(), &corpus_events(), config)
            .expect("write incumbent current trace");
    }
    std::fs::read(temp.path()).expect("read current trace")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut output, "{byte:02x}").expect("write digest");
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("write hex");
    }
    output
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "hex must contain complete bytes");
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("valid hex byte")
        })
        .collect()
}

fn corpus() -> Value {
    serde_json::from_str(CORPUS).expect("retained corpus must be valid JSON")
}

fn receipt() -> Value {
    serde_json::from_str(RECEIPT).expect("A4 receipt must be valid JSON")
}

fn artifact_bytes(artifact: &Value) -> Vec<u8> {
    let bytes = decode_hex(
        artifact["bytes_hex"]
            .as_str()
            .expect("artifact bytes_hex must be text"),
    );
    assert_eq!(
        bytes.len(),
        artifact["byte_len"]
            .as_u64()
            .expect("artifact byte_len must be an integer") as usize
    );
    assert_eq!(
        sha256_hex(&bytes),
        artifact["sha256"]
            .as_str()
            .expect("artifact sha256 must be text")
    );
    bytes
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write retained trace artifact");
}

fn replay(metadata: TraceMetadata, events: Vec<ReplayEvent>) {
    let expected = events.len();
    let mut trace = ReplayTrace::new(metadata);
    trace.events = events;
    let mut replayer = TraceReplayer::new(trace);
    assert_eq!(replayer.run().expect("deterministic replay"), expected);
    assert!(replayer.is_completed());
}

fn cli_success<I, S>(label: &str, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(env!("CARGO_BIN_EXE_asupersync"))
        .args(args)
        .output()
        .expect("execute current CLI");
    assert!(
        output.status.success(),
        "{label} failed: status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn decode_with_incumbent(path: &Path) -> Result<Vec<ReplayEvent>, TraceFileError> {
    TraceReader::open(path)?.load_all()
}

fn decode_with_owned(path: &Path) -> Result<Vec<ReplayEvent>, TraceFileError> {
    owned::open_owned_reader(path)?.load_all()
}

fn current_chunk_offset(bytes: &[u8]) -> usize {
    assert_eq!(&bytes[..TRACE_MAGIC.len()], TRACE_MAGIC);
    let version = u16::from_le_bytes(
        bytes[TRACE_MAGIC.len()..TRACE_MAGIC.len() + 2]
            .try_into()
            .expect("version bytes"),
    );
    let meta_len_offset = TRACE_MAGIC.len() + 2 + 2 + usize::from(version >= 2);
    let meta_len = u32::from_le_bytes(
        bytes[meta_len_offset..meta_len_offset + 4]
            .try_into()
            .expect("metadata length bytes"),
    ) as usize;
    let header = if version >= 3 {
        HEADER_SIZE
    } else {
        LEGACY_HEADER_SIZE
    };
    header + meta_len + 8 + usize::from(version >= 3) * TRACE_CHECKSUM_LEN
}

fn linux_value_kib(field: &str) -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let value = line.strip_prefix(field)?.trim();
        value
            .strip_suffix(" kB")
            .unwrap_or(value)
            .trim()
            .parse()
            .ok()
    })
}

fn linux_cpu_model() -> Option<String> {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    cpuinfo.lines().find_map(|line| {
        line.strip_prefix("model name")
            .and_then(|rest| rest.split_once(':'))
            .map(|(_, value)| value.trim().to_string())
    })
}

#[test]
#[ignore = "operator helper: emits the frozen corpus candidate for checked-in review"]
fn emit_retained_corpus_candidate() {
    let metadata = fixed_metadata();
    let events = corpus_events();
    let rows = [
        (
            "trace-v2-manual-incumbent",
            "manual ASUPERTRACE v2 container plus lz4_flex 0.14.0 block",
            manual_v2_incumbent_trace(&metadata, &events),
        ),
        (
            "trace-v3-v039-incumbent",
            "asupersync v0.3.9 TraceWriter plus lz4_flex 0.14.0 block",
            current_trace_bytes(false),
        ),
    ];
    let artifacts = rows
        .into_iter()
        .map(|(artifact_id, producer, bytes)| {
            json!({
                "artifact_id": artifact_id,
                "producer": producer,
                "file_version": if artifact_id.contains("v2") { 2 } else { 3 },
                "compression_byte": 1,
                "event_count": events.len(),
                "byte_len": bytes.len(),
                "sha256": sha256_hex(&bytes),
                "bytes_hex": hex(&bytes),
            })
        })
        .collect::<Vec<_>>();
    let candidate = json!({
        "schema_version": "lz4-trace-historical-corpus-v1",
        "bead_id": BEAD_ID,
        "capability_id": CAPABILITY_ID,
        "source_release": {
            "version": "0.3.9",
            "trace_file_version": TRACE_FILE_VERSION,
            "incumbent": "lz4_flex 0.14.0"
        },
        "semantic_fixture": {
            "metadata": metadata,
            "events": events,
        },
        "artifacts": artifacts,
    });
    println!(
        "LZ4_A4_CORPUS={}",
        serde_json::to_string(&candidate).expect("serialize corpus candidate")
    );
}

#[test]
fn lz4_cross_version_artifact() {
    let corpus = corpus();
    assert_eq!(corpus["schema_version"], "lz4-trace-historical-corpus-v1");
    assert_eq!(corpus["bead_id"], BEAD_ID);
    assert_eq!(corpus["capability_id"], CAPABILITY_ID);
    let expected_metadata = fixed_metadata();
    let expected_events = corpus_events();
    let workspace = tempfile::tempdir().expect("cross-version workspace");

    for artifact in corpus["artifacts"].as_array().expect("artifact array") {
        let id = artifact["artifact_id"].as_str().expect("artifact id");
        let bytes = artifact_bytes(artifact);
        let path = workspace.path().join(format!("{id}.trace"));
        write_bytes(&path, &bytes);

        let incumbent = TraceReader::open(&path).expect("incumbent header");
        assert_eq!(
            incumbent.file_version(),
            artifact["file_version"].as_u64().expect("file version") as u16
        );
        assert_eq!(incumbent.metadata(), &expected_metadata);
        let incumbent_events = incumbent.load_all().expect("incumbent decode");
        let (owned_metadata, owned_events) = owned::read_owned_trace(&path).expect("owned decode");
        assert_eq!(owned_metadata, expected_metadata);
        assert_eq!(incumbent_events, expected_events);
        assert_eq!(owned_events, expected_events);
        replay(owned_metadata, owned_events);

        if artifact["file_version"] == 2 {
            let incumbent_output = workspace.path().join("migrated-incumbent-v3.trace");
            let owned_output = workspace.path().join("migrated-owned-v3.trace");
            let source_before = std::fs::read(&path).expect("read rollback source");
            migrate_trace_file(&path, &incumbent_output).expect("incumbent migration");
            owned::migrate_owned_trace(&path, &owned_output).expect("owned migration");
            assert_eq!(
                std::fs::read(&path).expect("read preserved source"),
                source_before
            );
            for migrated in [&incumbent_output, &owned_output] {
                assert_eq!(
                    TraceReader::open(migrated)
                        .expect("open migrated trace")
                        .file_version(),
                    TRACE_FILE_VERSION
                );
                assert_eq!(decode_with_incumbent(migrated).unwrap(), expected_events);
                assert_eq!(decode_with_owned(migrated).unwrap(), expected_events);
            }
            let cli_output = workspace.path().join("cli-migrated-v3.trace");
            cli_success(
                "trace migrate",
                [
                    OsStr::new("trace"),
                    OsStr::new("migrate"),
                    path.as_os_str(),
                    cli_output.as_os_str(),
                ],
            );
        }
    }

    assert_eq!(
        manual_v2_incumbent_trace(&expected_metadata, &expected_events),
        artifact_bytes(&corpus["artifacts"][0])
    );
    assert_eq!(
        current_trace_bytes(false),
        artifact_bytes(&corpus["artifacts"][1])
    );
}

#[test]
fn lz4_trace_replay() {
    let workspace = tempfile::tempdir().expect("trace replay workspace");
    let metadata = fixed_metadata();
    let events = large_events(8_192);
    let incumbent_path = workspace.path().join("incumbent-v3.trace");
    let owned_path = workspace.path().join("owned-v3.trace");
    let owned_repeat_path = workspace.path().join("owned-repeat-v3.trace");
    let interrupted_path = workspace.path().join("owned-interrupted-v3.trace");
    let uncompressed_path = workspace.path().join("uncompressed-v3.trace");
    let cli_compressed_path = workspace.path().join("cli-compressed-v3.trace");
    let config = TraceFileConfig::new()
        .with_compression(CompressionMode::Lz4 { level: 1 })
        .with_chunk_size(4 * 1024);

    write_trace_with_config(&incumbent_path, &metadata, &events, config.clone())
        .expect("incumbent trace");
    owned::write_owned_trace(&owned_path, &metadata, &events, config.clone()).expect("owned trace");
    owned::write_owned_trace(&owned_repeat_path, &metadata, &events, config.clone())
        .expect("repeat owned trace");
    assert_eq!(
        std::fs::read(&owned_path).expect("read owned trace"),
        std::fs::read(&owned_repeat_path).expect("read repeat owned trace"),
        "owned trace integration must be deterministic"
    );

    {
        let mut writer =
            owned::create_owned_writer(&interrupted_path, config).expect("interrupted writer");
        writer
            .write_metadata(&metadata)
            .expect("interrupted metadata");
        for event in &events[..64] {
            writer.write_event(event).expect("interrupted event");
        }
    }
    assert_eq!(
        decode_with_incumbent(&interrupted_path).expect("incumbent interrupted decode"),
        events[..64]
    );
    assert_eq!(
        decode_with_owned(&interrupted_path).expect("owned interrupted decode"),
        events[..64]
    );
    write_trace(&uncompressed_path, &metadata, &events).expect("uncompressed trace");

    for path in [&incumbent_path, &owned_path] {
        let incumbent = decode_with_incumbent(path).expect("incumbent cross-decode");
        let owned_events = decode_with_owned(path).expect("owned cross-decode");
        assert_eq!(incumbent, events);
        assert_eq!(owned_events, events);
        replay(metadata.clone(), owned_events);
    }

    cli_success(
        "trace info",
        [
            OsStr::new("trace"),
            OsStr::new("info"),
            owned_path.as_os_str(),
        ],
    );
    cli_success(
        "trace verify",
        [
            OsStr::new("trace"),
            OsStr::new("verify"),
            OsStr::new("--strict"),
            owned_path.as_os_str(),
        ],
    );
    cli_success(
        "trace events",
        [
            OsStr::new("trace"),
            OsStr::new("events"),
            OsStr::new("--limit"),
            OsStr::new("8"),
            owned_path.as_os_str(),
        ],
    );
    cli_success(
        "trace diff",
        [
            OsStr::new("trace"),
            OsStr::new("diff"),
            incumbent_path.as_os_str(),
            owned_path.as_os_str(),
        ],
    );
    cli_success(
        "trace compress",
        [
            OsStr::new("trace"),
            OsStr::new("compress"),
            uncompressed_path.as_os_str(),
            cli_compressed_path.as_os_str(),
            OsStr::new("--level"),
            OsStr::new("1"),
        ],
    );
    assert_eq!(
        decode_with_owned(&cli_compressed_path).expect("owned reads CLI output"),
        events
    );
}

#[test]
fn lz4_malformed_limits() {
    let baseline = current_trace_bytes(true);
    let chunk_offset = current_chunk_offset(&baseline);
    let workspace = tempfile::tempdir().expect("malformed workspace");
    let path = workspace.path().join("candidate.trace");
    let structural_boundaries = [
        0,
        TRACE_MAGIC.len() - 1,
        TRACE_MAGIC.len() + 1,
        LEGACY_HEADER_SIZE - 1,
        HEADER_SIZE - 1,
        chunk_offset - 1,
        chunk_offset + 2,
        baseline.len() - 1,
    ];

    for boundary in structural_boundaries {
        write_bytes(&path, &baseline[..boundary]);
        assert!(
            decode_with_incumbent(&path).is_err(),
            "incumbent accepted truncation at {boundary}"
        );
        assert!(
            decode_with_owned(&path).is_err(),
            "owned codec accepted truncation at {boundary}"
        );
    }

    let mut zero_chunk = baseline.clone();
    zero_chunk[chunk_offset..chunk_offset + 4].fill(0);
    write_bytes(&path, &zero_chunk);
    assert!(matches!(
        decode_with_incumbent(&path),
        Err(TraceFileError::Truncated)
    ));
    assert!(matches!(
        decode_with_owned(&path),
        Err(TraceFileError::Truncated)
    ));

    let mut oversized_chunk = baseline.clone();
    oversized_chunk[chunk_offset..chunk_offset + 4].copy_from_slice(
        &u32::try_from(MAX_COMPRESSED_CHUNK_LEN + 1)
            .expect("limit fits u32")
            .to_le_bytes(),
    );
    write_bytes(&path, &oversized_chunk);
    for error in [
        decode_with_incumbent(&path).expect_err("incumbent compressed limit"),
        decode_with_owned(&path).expect_err("owned compressed limit"),
    ] {
        assert!(matches!(
            error,
            TraceFileError::OversizedField {
                field: "compressed_chunk_len",
                ..
            }
        ));
    }

    let mut bomb = baseline.clone();
    bomb[chunk_offset + 4..chunk_offset + 8].copy_from_slice(
        &u32::try_from(MAX_COMPRESSED_CHUNK_LEN + 1)
            .expect("limit fits u32")
            .to_le_bytes(),
    );
    write_bytes(&path, &bomb);
    for error in [
        decode_with_incumbent(&path).expect_err("incumbent output limit"),
        decode_with_owned(&path).expect_err("owned output limit"),
    ] {
        assert!(matches!(
            error,
            TraceFileError::OversizedField {
                field: "decompressed_chunk_len",
                ..
            }
        ));
    }

    let meta_len = rmp_serde::to_vec(&fixed_metadata())
        .expect("serialize metadata")
        .len();
    let event_digest_offset = HEADER_SIZE + meta_len + 8;
    let mut checksum_corrupt = baseline.clone();
    checksum_corrupt[event_digest_offset] ^= 1;
    write_bytes(&path, &checksum_corrupt);
    for error in [
        decode_with_incumbent(&path).expect_err("incumbent checksum"),
        decode_with_owned(&path).expect_err("owned checksum"),
    ] {
        assert!(matches!(
            error,
            TraceFileError::ChecksumMismatch {
                section: "event stream"
            }
        ));
    }

    let mut trailing = baseline;
    trailing.extend_from_slice(b"retained-trailing-data");
    write_bytes(&path, &trailing);
    assert_eq!(decode_with_incumbent(&path).unwrap(), corpus_events());
    assert_eq!(decode_with_owned(&path).unwrap(), corpus_events());
}

#[test]
fn measured_go_no_go_probe() {
    let payload = canonical_event_frames(&large_events(4_096));
    let iterations = 64u64;
    let hwm_before_kib = linux_value_kib("VmHWM:").unwrap_or(0);

    let incumbent_start = Instant::now();
    let mut incumbent = Vec::new();
    for _ in 0..iterations {
        incumbent = lz4_flex::compress_prepend_size(black_box(&payload));
    }
    let incumbent_encode_nanos = incumbent_start.elapsed().as_nanos();

    let owned_start = Instant::now();
    let mut candidate = Vec::new();
    for _ in 0..iterations {
        candidate = owned::encode_owned_chunk(black_box(&payload)).expect("owned encode");
    }
    let owned_encode_nanos = owned_start.elapsed().as_nanos();

    let incumbent_decode_start = Instant::now();
    for _ in 0..iterations {
        assert_eq!(
            lz4_flex::decompress_size_prepended(black_box(&candidate))
                .expect("incumbent decodes owned"),
            payload
        );
    }
    let incumbent_decode_nanos = incumbent_decode_start.elapsed().as_nanos();

    let owned_decode_start = Instant::now();
    for _ in 0..iterations {
        assert_eq!(
            owned::decode_owned_chunk(black_box(&incumbent)).expect("owned decodes incumbent"),
            payload
        );
    }
    let owned_decode_nanos = owned_decode_start.elapsed().as_nanos();
    let hwm_after_kib = linux_value_kib("VmHWM:").unwrap_or(hwm_before_kib);

    println!(
        "LZ4_A4_MEASUREMENT={}",
        serde_json::to_string(&json!({
            "schema_version": "lz4-a4-measurement-v1",
            "payload_bytes": payload.len(),
            "iterations": iterations,
            "incumbent_encoded_bytes": incumbent.len(),
            "owned_encoded_bytes": candidate.len(),
            "incumbent_encode_nanos": incumbent_encode_nanos,
            "owned_encode_nanos": owned_encode_nanos,
            "incumbent_decode_nanos": incumbent_decode_nanos,
            "owned_decode_nanos": owned_decode_nanos,
            "compressed_plus_decompressed_peak_bytes": {
                "incumbent_block": incumbent.len() + payload.len(),
                "owned_block": candidate.len() + payload.len(),
            },
            "process_vm_hwm_before_kib": hwm_before_kib,
            "process_vm_hwm_after_kib": hwm_after_kib,
            "cpu_model": linux_cpu_model().unwrap_or_else(|| "unavailable".to_string()),
        }))
        .expect("serialize measurement")
    );
}

#[test]
fn a4_receipt_and_runner_contract() {
    let receipt = receipt();
    assert_eq!(receipt["schema_version"], 1);
    assert_eq!(receipt["bead_id"], BEAD_ID);
    assert_eq!(receipt["capability_id"], CAPABILITY_ID);
    assert_eq!(receipt["decision"]["verdict"], "KEEP_INCUMBENT");
    assert_eq!(
        receipt["decision"]["production_default_changed"],
        Value::Bool(false)
    );
    assert_eq!(
        receipt["source_transition"]["a4_trace_file_sha256"],
        sha256_hex(&std::fs::read(repo_path("src/trace/file.rs")).expect("read trace source"))
    );
    assert_eq!(
        receipt["retained_corpus"]["sha256"],
        sha256_hex(&std::fs::read(repo_path(CORPUS_PATH)).expect("read retained corpus"))
    );
    for evidence in receipt["evidence_files"]
        .as_array()
        .expect("evidence file array")
    {
        let path = evidence["path"].as_str().expect("evidence path");
        assert_eq!(
            evidence["sha256"],
            sha256_hex(&std::fs::read(repo_path(path)).expect("read evidence file")),
            "evidence hash drift for {path}"
        );
    }

    let scenarios = receipt["canonical_scenarios"]
        .as_array()
        .expect("canonical scenario array");
    let runner = std::fs::read_to_string(repo_path(RUNNER_PATH)).expect("read E2E runner");
    for scenario in [
        "lz4_trace_replay",
        "lz4_cross_version_artifact",
        "lz4_malformed_limits",
    ] {
        assert!(
            scenarios.iter().any(|row| row["scenario_id"] == scenario),
            "receipt missing {scenario}"
        );
        assert!(runner.contains(scenario), "runner missing {scenario}");
    }

    let measurement = &receipt["measurement_receipt"];
    assert_eq!(measurement["status"], "PASS");
    assert_eq!(measurement["iterations"], 64);
    assert_eq!(measurement["payload_bytes"], 95_887);
    assert_eq!(measurement["incumbent_encoded_bytes"], 29_688);
    assert_eq!(measurement["owned_encoded_bytes"], 28_953);
    assert_eq!(measurement["incumbent_encode_nanos"], 479_433_053);
    assert_eq!(measurement["owned_encode_nanos"], 720_550_247);
    assert_eq!(measurement["incumbent_decode_nanos"], 95_060_587);
    assert_eq!(measurement["owned_decode_nanos"], 195_354_661);
    assert!(
        measurement["method_limits"]
            .as_array()
            .expect("measurement method limits")
            .iter()
            .any(|limit| limit == "no allocation-count instrumentation")
    );

    let blocker_ids = receipt["decision"]["blockers"]
        .as_array()
        .expect("decision blockers")
        .iter()
        .map(|row| row["gap_id"].as_str().expect("gap id"))
        .collect::<Vec<_>>();
    for required in [
        "LZ4-GAP-01",
        "LZ4-GAP-02",
        "LZ4-GAP-03",
        "LZ4-GAP-09",
        "A4-MEASUREMENT-SCOPE",
        "A4-ATP-OUT-OF-SCOPE",
    ] {
        assert!(
            blocker_ids.contains(&required),
            "missing blocker {required}"
        );
    }

    let corpus = corpus();
    for artifact in corpus["artifacts"].as_array().expect("artifact array") {
        let _ = artifact_bytes(artifact);
    }

    let source =
        std::fs::read_to_string(repo_path("src/trace/file.rs")).expect("read trace source");
    assert!(source.contains("Self::from_file_with_lz4_codec(file, config, Lz4Codec::Incumbent)"));
    assert!(source.contains("Self::open_with_lz4_codec(path, Lz4Codec::Incumbent)"));
    assert!(
        source.contains("migrate_trace_file_with_lz4_codec(input, output, Lz4Codec::Incumbent)")
    );
    assert!(
        source
            .contains("#[cfg(all(feature = \"trace-compression\", feature = \"test-internals\"))]")
    );

    let doc = std::fs::read_to_string(repo_path(DOC_PATH)).expect("read operator doc");
    for marker in [
        BEAD_ID,
        CAPABILITY_ID,
        CORPUS_PATH,
        RECEIPT_PATH,
        "KEEP_INCUMBENT",
        "No production cutover",
        "No permission to delete files",
    ] {
        assert!(doc.contains(marker), "operator doc missing {marker}");
    }
}
