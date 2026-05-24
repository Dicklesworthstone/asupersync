#![allow(missing_docs)]

use asupersync::atp::logging::{
    ATP_LOG_EVENT_SCHEMA_VERSION, AtpEvent, AtpLogger, AtpSubsystem, EventContext,
};
use asupersync::observability::LogLevel;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const FIXTURE_REL_PATH: &str = "tests/atp/fixtures/direct_success_seed_90057b12.json";
const GOLDEN_REL_PATH: &str = "tests/atp/golden_logs/direct_success.jsonl";
const FIXTURE_SCHEMA_VERSION: &str = "asupersync.atp.fixture_corpus.v1";
const FIXTURE_ID: &str = "atp-direct-success-seed-90057b12";
const TEST_CASE_ID: &str = "asupersync-vk4kcf.12";
const FIXTURE_SEED: u64 = 0x9005_7B12;
const TIMESTAMP: &str = "2026-05-24T00:00:00Z";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FixtureGeneration {
    strategy: String,
    seed: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FixtureObject {
    path: String,
    kind: String,
    logical_size: u64,
    content_hash: String,
    generation: FixtureGeneration,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FixtureManifest {
    schema_version: String,
    fixture_id: String,
    seed: u64,
    shape: String,
    object_graph: Vec<FixtureObject>,
    expected_manifest_root: String,
    platform_capability_assumptions: Vec<String>,
    large_data_policy: String,
}

#[test]
fn direct_success_fixture_is_deterministic_and_hash_stable() {
    let fixture = load_fixture();
    let expected = expected_manifest();

    assert_eq!(fixture, expected);
    assert_eq!(fixture.schema_version, FIXTURE_SCHEMA_VERSION);
    assert_eq!(fixture.seed, FIXTURE_SEED);
    assert_eq!(
        fixture.large_data_policy,
        "generate_on_demand_no_large_binary_blobs"
    );

    for object in &fixture.object_graph {
        assert_eq!(object.generation.strategy, "xorshift64");
        let generated = deterministic_bytes(object.generation.seed, object.logical_size);
        assert_eq!(sha256_hex(&generated), object.content_hash);
    }

    assert_eq!(
        manifest_root(&fixture.object_graph),
        fixture.expected_manifest_root
    );

    let metadata = fs::metadata(repo_path(FIXTURE_REL_PATH)).expect("fixture metadata");
    assert!(
        metadata.len() < 16 * 1024,
        "fixture corpus must not commit large binary blobs"
    );
}

#[test]
fn direct_success_golden_log_matches_structured_logging_contract() {
    let fixture = load_fixture();
    let expected_log = fs::read_to_string(repo_path(GOLDEN_REL_PATH)).expect("golden log");
    let rendered_log = render_direct_success_log(&fixture);

    assert_eq!(rendered_log, expected_log);

    let mut event_types = Vec::new();
    for line in rendered_log.lines() {
        let event: Value = serde_json::from_str(line).expect("golden log event is JSON");
        assert_eq!(
            event["schema_version"].as_str(),
            Some(ATP_LOG_EVENT_SCHEMA_VERSION)
        );
        event_types.push(
            event["event_type"]
                .as_str()
                .expect("event_type is present")
                .to_string(),
        );
    }

    assert_eq!(
        event_types,
        [
            "test_started",
            "seed_selected",
            "fixture_loaded",
            "oracle_checked",
            "test_completed"
        ]
    );

    for marker in [
        "[REDACTED_CAPABILITY]",
        "[REDACTED_CONTENT_HASH]",
        "[REDACTED_PATH]",
        "[REDACTED_PEER_ID]",
        "[REDACTED_PRIVATE_KEY]",
        "[REDACTED_TOKEN]",
    ] {
        assert!(
            rendered_log.contains(marker),
            "golden log must contain redaction marker {marker}"
        );
    }

    for secret in [
        "token=fixture-secret-grant",
        "cap://fixture-corpus-capability-secret",
        "/home/alice/asupersync",
        "peer-secret-alpha",
        "-----BEGIN PRIVATE KEY-----",
        "raw-control-payload",
        &fixture.object_graph[0].content_hash,
    ] {
        assert!(
            !rendered_log.contains(secret),
            "golden log leaked sensitive value {secret}"
        );
    }
}

fn load_fixture() -> FixtureManifest {
    let fixture = fs::read_to_string(repo_path(FIXTURE_REL_PATH)).expect("fixture manifest");
    serde_json::from_str(&fixture).expect("fixture manifest schema")
}

fn expected_manifest() -> FixtureManifest {
    let object_graph = expected_objects();
    let expected_manifest_root = manifest_root(&object_graph);

    FixtureManifest {
        schema_version: FIXTURE_SCHEMA_VERSION.to_string(),
        fixture_id: FIXTURE_ID.to_string(),
        seed: FIXTURE_SEED,
        shape: "direct_success_tree_v1".to_string(),
        object_graph,
        expected_manifest_root,
        platform_capability_assumptions: vec![
            "deterministic_xorshift64".to_string(),
            "large_data_generated_on_demand".to_string(),
            "utf8_paths".to_string(),
        ],
        large_data_policy: "generate_on_demand_no_large_binary_blobs".to_string(),
    }
}

fn expected_objects() -> Vec<FixtureObject> {
    [
        (
            "payload/control.txt",
            "small_file",
            64,
            FIXTURE_SEED,
            "b695a6ab26514c2ad8a93441d523753bf692dbd050b077015380623ee7456b52",
        ),
        (
            "payload/model-prefix.bin",
            "media_model_prefix",
            4096,
            FIXTURE_SEED ^ 0xA7,
            "44f0726489e46b03963a2385a6bc7c73c16bde2c6a4866c036048012fb5fce7f",
        ),
        (
            "payload/logical-large.bin",
            "generated_large_file",
            1_048_576,
            FIXTURE_SEED ^ 0x5A5A,
            "b4f3b8de702db52b45a491840ce7e1575ac6346eb640cb9675507e9a88ee974c",
        ),
    ]
    .into_iter()
    .map(
        |(path, kind, logical_size, seed, content_hash)| FixtureObject {
            path: path.to_string(),
            kind: kind.to_string(),
            logical_size,
            content_hash: content_hash.to_string(),
            generation: FixtureGeneration {
                strategy: "xorshift64".to_string(),
                seed,
            },
        },
    )
    .collect()
}

fn render_direct_success_log(manifest: &FixtureManifest) -> String {
    let logger = AtpLogger::new();
    [
        render_log_event(
            &logger,
            "test_started",
            json!({
                "fixture_id": manifest.fixture_id,
                "scenario": "direct_success",
            }),
        ),
        render_log_event(
            &logger,
            "seed_selected",
            json!({
                "generator": "xorshift64",
                "seed": manifest.seed,
            }),
        ),
        render_log_event(
            &logger,
            "fixture_loaded",
            json!({
                "capability_secret": "cap://fixture-corpus-capability-secret-000000000000000000000000000000",
                "content_hash": manifest.object_graph[0].content_hash,
                "fixture_id": manifest.fixture_id,
                "fixture_path": "/home/alice/asupersync/tests/atp/fixtures/direct_success_seed_90057b12.json",
                "grant_token": "token=fixture-secret-grant",
                "manifest_root": manifest.expected_manifest_root,
                "object_count": manifest.object_graph.len(),
                "private_key": "-----BEGIN PRIVATE KEY-----\nfixture-secret\n-----END PRIVATE KEY-----",
            }),
        ),
        render_log_event(
            &logger,
            "oracle_checked",
            json!({
                "large_data_generated_on_demand": true,
                "manifest_root": manifest.expected_manifest_root,
                "oracle": "direct_success_fixture_corpus",
                "zero_raw_content_committed": true,
            }),
        ),
        render_log_event(
            &logger,
            "test_completed",
            json!({
                "fixture_id": manifest.fixture_id,
                "passed": true,
            }),
        ),
    ]
    .join("\n")
        + "\n"
}

fn render_log_event(logger: &AtpLogger, event_type: &str, data: Value) -> String {
    let event = AtpEvent {
        schema_version: ATP_LOG_EVENT_SCHEMA_VERSION.to_string(),
        timestamp: TIMESTAMP.to_string(),
        level: LogLevel::Info,
        subsystem: AtpSubsystem::E2eTest,
        event_type: event_type.to_string(),
        data,
        context: event_context(),
        redacted_fields: Vec::new(),
    };

    logger.render_event(&event).expect("render ATP log event")
}

fn event_context() -> EventContext {
    EventContext {
        session_id: "atp-nr4-fixture-corpus".to_string(),
        transfer_id: Some("transfer-direct-success".to_string()),
        connection_id: Some("direct-quic-0001".to_string()),
        peer_id: Some("peer-secret-alpha".to_string()),
        test_case_id: Some(TEST_CASE_ID.to_string()),
        trace_id: "trace-atp-fixture-corpus-v1".to_string(),
        span_id: "root".to_string(),
    }
}

fn manifest_root(objects: &[FixtureObject]) -> String {
    let mut hasher = Sha256::new();
    for object in objects {
        hasher.update(object.path.as_bytes());
        hasher.update([0]);
        hasher.update(object.kind.as_bytes());
        hasher.update([0]);
        hasher.update(object.logical_size.to_string().as_bytes());
        hasher.update([0]);
        hasher.update(object.content_hash.as_bytes());
        hasher.update([0]);
    }
    hex(&hasher.finalize())
}

fn deterministic_bytes(seed: u64, len: u64) -> Vec<u8> {
    let len = usize::try_from(len).expect("fixture size fits usize");
    let mut state = seed;
    let mut out = Vec::with_capacity(len);

    for index in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push((state >> ((index % 8) * 8)) as u8);
    }

    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }

    out
}

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}
