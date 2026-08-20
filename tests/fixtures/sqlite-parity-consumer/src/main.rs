//! Neutral, independently resolved SQLite parity consumer.
//!
//! The binary consumes the versioned vector checked into the asupersync
//! repository, executes it once through each engine, and emits one deterministic
//! JSON evidence document. It intentionally lives in a standalone Cargo
//! workspace so FrankenSQLite never enters asupersync's dependency graph.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use asupersync::database::sqlite::{
    SqliteErrorCategory, SqliteOperationError, SqliteRetryDisposition,
    validate_checked_sql_statement,
};
use asupersync::database::transaction::SqliteSavepoint;
use asupersync::database::{
    SqliteConnection, SqliteError, SqliteTransaction, SqliteValue as AsupersyncValue,
};
use asupersync::runtime::{BlockingPoolHandle, RuntimeBuilder};
use asupersync::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use asupersync::{Cx, Outcome};
use asupersync_compat::Cx as CompatCx;
use asupersync_compat::runtime::{
    BlockingPoolHandle as CompatBlockingPoolHandle, RuntimeBuilder as CompatRuntimeBuilder,
};
use asupersync_compat::sync::{
    AcquireError as CompatAcquireError, OwnedSemaphorePermit as CompatOwnedSemaphorePermit,
    Semaphore as CompatSemaphore,
};
use fsqlite::{
    AsyncConnection as FrankenConnection, FrankenError, SqliteValue as FrankenValue, compat::RowExt,
};
use fsqlite_types::cx::Cx as FrankenCx;
use serde::{Deserialize, Serialize};

const VECTOR_JSON: &str = include_str!("../../../../artifacts/sqlite_conformance_vectors_v1.json");
const FSQLITE_REVISION: &str = "92f9e9833f859ebcbe27e9fef16d9cad4372bbd7";
const P3_BUSY_CHILD_ENV: &str = "SQLITE_PARITY_P3_BUSY_CHILD";
const P3_BUSY_WATCHDOG: Duration = Duration::from_secs(5);
const P6_PROFILE_MAX_VALUE_BYTES: usize = 1024 * 1024;
const P6_VALUE_QUERY: &str = "SELECT ?1 AS null_value, ?2 AS integer_min, ?3 AS integer_max, ?4 AS integer_beyond_exact_f64, ?5 AS negative_zero, ?6 AS positive_infinity, ?7 AS negative_infinity, ?8 AS nan_value, ?9 AS empty_text, ?10 AS unicode_nul_text, ?11 AS empty_blob, ?12 AS binary_blob, ?13 AS large_text, ?14 AS large_blob";
const P6_VALUE_CASE_IDS: [&str; 14] = [
    "SQLITE-PARITY-P6-NULL-001",
    "SQLITE-PARITY-P6-I64-MIN-002",
    "SQLITE-PARITY-P6-I64-MAX-003",
    "SQLITE-PARITY-P6-I64-BEYOND-EXACT-F64-004",
    "SQLITE-PARITY-P6-NEGATIVE-ZERO-005",
    "SQLITE-PARITY-P6-POSITIVE-INFINITY-006",
    "SQLITE-PARITY-P6-NEGATIVE-INFINITY-007",
    "SQLITE-PARITY-P6-NAN-TO-NULL-008",
    "SQLITE-PARITY-P6-EMPTY-TEXT-009",
    "SQLITE-PARITY-P6-UNICODE-NUL-TEXT-010",
    "SQLITE-PARITY-P6-EMPTY-BLOB-011",
    "SQLITE-PARITY-P6-BINARY-BLOB-012",
    "SQLITE-PARITY-P6-LARGE-TEXT-013",
    "SQLITE-PARITY-P6-LARGE-BLOB-014",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VectorSuite {
    schema_version: u64,
    suite_id: String,
    capability_id: String,
    normalization: Normalization,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Normalization {
    integer: String,
    real: String,
    text: String,
    blob: String,
    null: String,
    error: String,
    column_order: String,
    row_order: String,
    pool: String,
    quiescence: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    id: String,
    family: String,
    description: String,
    scenario: Scenario,
    expected: ScenarioOutcome,
    unsupported: Vec<UnsupportedCapability>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Scenario {
    InMemoryConfiguration { busy_timeout_ms: u64 },
    FilePathRoundTrip,
    MissingParentPath,
    PreCancelledOpen,
    AdmissionExhaustion { capacity: usize },
    UriFilenameUnsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Ok,
    Error,
    Cancelled,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioOutcome {
    status: Status,
    error_class: Option<String>,
    open_state: String,
    configuration_state: String,
    admission_state: String,
    blocking_bridge_state: String,
    cancellation_state: String,
    close_state: String,
    resource_state: ResourceState,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceState {
    connection: String,
    open_transactions: u64,
    admission_capacity: u64,
    admission_available: u64,
    admission_waiters: u64,
    admission_cancellations: u64,
    blocking_pending: u64,
    blocking_busy: u64,
    blocking_active: u64,
    region_state: String,
    background_work: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsupportedCapability {
    engine: String,
    capability: String,
    reason: String,
}

#[derive(Debug, Serialize)]
struct HarnessEvidence<'a> {
    evidence_schema_version: u64,
    vector_schema_version: u64,
    suite_id: &'a str,
    capability_id: &'a str,
    provenance: Provenance<'a>,
    engine_results: Vec<EngineResult>,
    prepared_statement_parity: PreparedStatementParityEvidence,
    value_parity: ValueParityEvidence,
    transaction_parity: TransactionParityEvidence,
    security_policy: SecurityPolicyEvidence,
    error_parity: ErrorParityEvidence,
    comparison: Comparison,
}

#[derive(Debug, Serialize)]
struct PreparedStatementParityEvidence {
    bead_id: &'static str,
    matrix_id: &'static str,
    status: &'static str,
    compared_cases: usize,
    asupersync: PreparedEngineEvidence,
    frankensqlite: PreparedEngineEvidence,
    mismatches: Vec<String>,
    intentional_differences: Vec<PreparedDifferenceEvidence>,
    unsupported: Vec<PreparedUnsupportedEvidence>,
}

#[derive(Debug, Serialize)]
struct PreparedEngineEvidence {
    cases: Vec<PreparedCaseResult>,
    runtime_quiescent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PreparedCaseResult {
    case_id: &'static str,
    observation: String,
    error_class: Option<&'static str>,
    connection_reusable: bool,
    cleanup_state: &'static str,
}

#[derive(Debug, Serialize)]
struct PreparedUnsupportedEvidence {
    engine: &'static str,
    capability: &'static str,
    reason: &'static str,
}

#[derive(Debug, Serialize)]
struct PreparedDifferenceEvidence {
    case_id: &'static str,
    boundary: &'static str,
    asupersync: &'static str,
    frankensqlite: &'static str,
    rationale: &'static str,
}

#[derive(Debug, Serialize)]
struct ValueParityEvidence {
    bead_id: &'static str,
    matrix_id: &'static str,
    status: &'static str,
    profile_max_value_bytes: usize,
    compared_values: usize,
    asupersync: ValueEngineEvidence,
    frankensqlite: ValueEngineEvidence,
    mismatches: Vec<String>,
    unsupported: Vec<ValueUnsupportedEvidence>,
}

#[derive(Debug, Serialize)]
struct ValueEngineEvidence {
    values: Vec<ValueCaseResult>,
    owned_after_close: bool,
    type_mismatch_class: &'static str,
    out_of_bounds_class: &'static str,
    row_metadata: RowMetadataEvidence,
    runtime_quiescent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ValueCaseResult {
    case_id: &'static str,
    storage_class: &'static str,
    exact_scalar: Option<String>,
    byte_len: Option<usize>,
    fnv1a64: String,
}

#[derive(Debug, Serialize)]
struct RowMetadataEvidence {
    status: &'static str,
    ordered_names: Vec<String>,
    legacy_sorted_unique_names: Vec<String>,
    first_ascii_case_insensitive_dup_index: Option<usize>,
    legacy_exact_dup_value: Option<i64>,
    missing_name_class: &'static str,
}

#[derive(Debug, Serialize)]
struct ValueUnsupportedEvidence {
    engine: &'static str,
    capability: &'static str,
    reason: &'static str,
}

#[derive(Debug)]
enum ExpectedValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Debug, Serialize)]
struct TransactionParityEvidence {
    bead_id: &'static str,
    matrix_id: &'static str,
    status: &'static str,
    compared_cases: usize,
    asupersync: Vec<TransactionCaseResult>,
    frankensqlite: Vec<TransactionCaseResult>,
    mismatches: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TransactionCaseResult {
    case_id: &'static str,
    terminal_state: &'static str,
    visible_labels: Vec<String>,
    conflict_class: Option<&'static str>,
    connection_reusable: bool,
    open_transactions: u64,
}

#[derive(Clone, Copy)]
struct TransactionCase {
    id: &'static str,
    kind: TransactionCaseKind,
}

#[derive(Clone, Copy)]
enum TransactionCaseKind {
    DeferredCommit,
    ImmediateRollback,
    ExclusiveCommit,
    SavepointPartialRollback,
    ConflictRecovery,
}

#[derive(Debug, Serialize)]
struct SecurityPolicyEvidence {
    policy_id: &'static str,
    status: &'static str,
    bounded_cases: usize,
    asupersync: Vec<SecurityCaseResult>,
    frankensqlite_adapter: Vec<SecurityCaseResult>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct SecurityCaseResult {
    id: &'static str,
    decision: &'static str,
}

struct SecurityCase {
    id: &'static str,
    sql: String,
    expected: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorParityEvidence {
    bead_id: &'static str,
    matrix_id: &'static str,
    status: &'static str,
    asupersync: ErrorEngineEvidence,
    frankensqlite: ErrorEngineEvidence,
    compared_cases: usize,
    mismatches: Vec<String>,
    intentional_differences: Vec<ErrorDifferenceEvidence>,
    inherited_busy_case: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorEngineEvidence {
    cases: Vec<ErrorCaseResult>,
    connection_reusable: bool,
    connection_closed: bool,
    open_transactions: u64,
    live_statements: u64,
    live_connections: u64,
    runtime_quiescent: bool,
    blocking_pending: u64,
    blocking_busy: u64,
    blocking_active: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ErrorCaseResult {
    case_id: &'static str,
    operation: &'static str,
    category: &'static str,
    primary_code: Option<&'static str>,
    extended_code: Option<i32>,
    retry: &'static str,
    cancellation_delivery: &'static str,
    source_preserved: bool,
    stable_evidence_redacted: bool,
}

#[derive(Debug, Serialize)]
struct ErrorDifferenceEvidence {
    case_id: &'static str,
    boundary: &'static str,
    asupersync: &'static str,
    frankensqlite: &'static str,
    rationale: &'static str,
}

#[derive(Debug, Serialize)]
struct Provenance<'a> {
    asupersync_revision: &'a str,
    frankensqlite_revision: &'a str,
    asupersync_features: [&'a str; 1],
    frankensqlite_features: [&'a str; 2],
    cargo_profile: &'a str,
    target: &'a str,
    host: &'a str,
}

#[derive(Debug, Serialize)]
struct EngineResult {
    engine: &'static str,
    vectors: Vec<VectorResult>,
}

#[derive(Debug, Serialize)]
struct VectorResult {
    vector_id: String,
    outcome: ScenarioOutcome,
    unsupported: Vec<UnsupportedCapability>,
}

#[derive(Debug, Serialize)]
struct Comparison {
    comparable: bool,
    compared_vectors: usize,
    mismatches: Vec<String>,
}

fn main() {
    if std::env::var_os(P3_BUSY_CHILD_ENV).is_some() {
        if let Err(error) = run_frankensqlite_busy_child() {
            eprintln!("sqlite P3 busy child failed: {error}");
            std::process::exit(1);
        }
        return;
    }

    if let Err(error) = run() {
        eprintln!("sqlite parity harness failed: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
#[test]
fn sqlite_parity_aggregate() {
    if std::env::var_os(P3_BUSY_CHILD_ENV).is_some() {
        run_frankensqlite_busy_child().expect("SQLite P3 busy child");
        return;
    }

    run().expect("SQLite parity aggregate");
}

fn run() -> Result<(), String> {
    let suite: VectorSuite =
        serde_json::from_str(VECTOR_JSON).map_err(|error| format!("parse vectors: {error}"))?;
    validate_suite(&suite)?;

    let asupersync = EngineResult {
        engine: "asupersync",
        vectors: suite
            .vectors
            .iter()
            .map(run_asupersync)
            .collect::<Result<Vec<_>, _>>()?,
    };
    let frankensqlite = EngineResult {
        engine: "frankensqlite",
        vectors: suite
            .vectors
            .iter()
            .map(run_frankensqlite)
            .collect::<Result<Vec<_>, _>>()?,
    };

    let mismatches = compare_results(&suite, &asupersync, &frankensqlite);
    let comparable = mismatches.is_empty();
    let prepared_statement_parity = run_prepared_statement_parity()?;
    let value_parity = run_value_parity()?;
    let transaction_parity = run_transaction_parity()?;
    let security_policy = run_security_policy()?;
    let error_parity = run_error_parity(&prepared_statement_parity)?;
    let evidence = HarnessEvidence {
        evidence_schema_version: 1,
        vector_schema_version: suite.schema_version,
        suite_id: &suite.suite_id,
        capability_id: &suite.capability_id,
        provenance: Provenance {
            asupersync_revision: env!("ASUPERSYNC_SOURCE_REVISION"),
            frankensqlite_revision: FSQLITE_REVISION,
            asupersync_features: ["sqlite"],
            frankensqlite_features: ["native", "async-api"],
            cargo_profile: "dev",
            target: env!("SQLITE_PARITY_TARGET"),
            host: env!("SQLITE_PARITY_HOST"),
        },
        engine_results: vec![asupersync, frankensqlite],
        prepared_statement_parity,
        value_parity,
        transaction_parity,
        security_policy,
        error_parity,
        comparison: Comparison {
            comparable,
            compared_vectors: suite.vectors.len(),
            mismatches,
        },
    };

    let rendered =
        serde_json::to_string_pretty(&evidence).map_err(|error| format!("render: {error}"))?;
    println!("{rendered}");
    if comparable {
        Ok(())
    } else {
        Err("engine evidence did not match the declared vector contract".to_owned())
    }
}

fn run_prepared_statement_parity() -> Result<PreparedStatementParityEvidence, String> {
    let asupersync = run_asupersync_prepared_matrix()?;
    let frankensqlite = run_frankensqlite_prepared_matrix()?;
    let expected_busy_timeout = asupersync
        .cases
        .iter()
        .zip(&frankensqlite.cases)
        .any(|(native, franken)| expected_franken_busy_timeout(native, franken));
    let mut mismatches = Vec::new();
    if asupersync.cases.len() != frankensqlite.cases.len() {
        mismatches.push(format!(
            "case-count differs: asupersync={} frankensqlite={}",
            asupersync.cases.len(),
            frankensqlite.cases.len()
        ));
    }
    mismatches.extend(
        asupersync
            .cases
            .iter()
            .zip(&frankensqlite.cases)
            .filter_map(|(native, franken)| {
                (native != franken && !expected_franken_busy_timeout(native, franken)).then(|| {
                    format!(
                        "{} differs: asupersync={native:?} frankensqlite={franken:?}",
                        native.case_id
                    )
                })
            }),
    );
    if !mismatches.is_empty() {
        return Err(format!(
            "SQLite P3 prepared-statement parity failed: {}",
            mismatches.join("; ")
        ));
    }

    let mut intentional_differences = vec![PreparedDifferenceEvidence {
        case_id: "SQLITE-PARITY-P3-INVALID-USE-006",
        boundary: "surplus_parameter_binding",
        asupersync: "typed_sql_rejection",
        frankensqlite: "accepts_and_ignores_surplus_parameter",
        rationale: "The neutral adapter records the pinned engines' observable behavior without weakening Asupersync's fail-closed arity contract or claiming cross-engine equivalence for this cell.",
    }];
    if expected_busy_timeout {
        intentional_differences.push(PreparedDifferenceEvidence {
            case_id: "SQLITE-PARITY-P3-BUSY-008",
            boundary: "zero_busy_timeout_contention",
            asupersync: "typed_busy_or_locked_then_recovered",
            frankensqlite: "operation_did_not_complete_within_5s",
            rationale: "The pinned FrankenSQLite async call did not honor PRAGMA busy_timeout=0 under two-connection write contention. The neutral harness executes it in a child process, kills and reaps that child at the five-second watchdog, and makes no cleanup or typed-error parity claim for that engine cell.",
        });
    }

    Ok(PreparedStatementParityEvidence {
        bead_id: "asupersync-ym2wtv.2.3",
        matrix_id: "sqlite-neutral-prepared-statement-parity-v1",
        status: "PASS_BOUNDED_COMMON_OBSERVABLE_MATRIX_WITH_EXPLICIT_DIFFERENCES_AND_UNSUPPORTED",
        compared_cases: asupersync.cases.len(),
        asupersync,
        frankensqlite,
        mismatches,
        intentional_differences,
        unsupported: vec![
            PreparedUnsupportedEvidence {
                engine: "frankensqlite",
                capability: "async_prepared_statement_object_and_cache_capacity_control",
                reason: "The pinned AsyncConnection exposes query_with_params and execute_with_params but no async prepared-statement object, cache-capacity control, or cache telemetry; the neutral matrix compares repeated observable execution without inventing cache internals.",
            },
            PreparedUnsupportedEvidence {
                engine: "frankensqlite",
                capability: "async_row_stream_drop_finalize_boundary",
                reason: "The pinned AsyncConnection materializes Vec<Row> and exposes no public async row-stream object whose partial drop can be compared with Asupersync row-stream finalization.",
            },
        ],
    })
}

fn expected_franken_busy_timeout(
    native: &PreparedCaseResult,
    franken: &PreparedCaseResult,
) -> bool {
    native.case_id == "SQLITE-PARITY-P3-BUSY-008"
        && native.observation == "contender_rejected_then_recovered"
        && native.error_class == Some("busy_or_locked")
        && native.connection_reusable
        && native.cleanup_state == "statement_state_released"
        && franken.case_id == native.case_id
        && franken.observation == "operation_did_not_complete_within_5s"
        && franken.error_class == Some("watchdog_timeout")
        && !franken.connection_reusable
        && franken.cleanup_state == "isolated_child_killed_and_reaped"
}

fn run_asupersync_prepared_matrix() -> Result<PreparedEngineEvidence, String> {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build Asupersync P3 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "Asupersync P3 runtime has no blocking pool".to_owned())?;
    let cases = runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "Asupersync P3 runtime has no Cx".to_owned())?;
        let connection = asupersync_open_memory(&cx).await?;
        asupersync_outcome(
            connection
                .execute_batch(
                    &cx,
                    "CREATE TABLE p3_bind (
                        id INTEGER PRIMARY KEY,
                        int_value INTEGER,
                        real_value REAL,
                        text_value TEXT,
                        blob_value BLOB,
                        null_value INTEGER
                    );
                    CREATE TABLE p3_named (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE p3_reset (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO p3_reset VALUES (1, 'first'), (2, 'second');
                    CREATE TABLE p3_schema (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO p3_schema VALUES (1, 'before');
                    CREATE TABLE p3_cancel (value TEXT NOT NULL);",
                )
                .await,
            "set up Asupersync P3 matrix",
        )?;

        let positional = asupersync_prepared_positional_case(&connection, &cx).await?;
        let named = asupersync_prepared_named_case(&connection, &cx).await?;
        let reset = asupersync_prepared_reset_case(&connection, &cx).await?;
        let schema = asupersync_prepared_schema_case(&connection, &cx).await?;
        let invalid = asupersync_prepared_invalid_case(&connection, &cx).await?;
        let cancelled = asupersync_prepared_cancel_case(&connection, &cx).await?;
        asupersync_close(&connection, &cx).await?;
        let busy = asupersync_prepared_busy_case(&cx).await?;
        Ok::<_, String>(vec![
            positional, named, reset, schema, invalid, cancelled, busy,
        ])
    })?;
    drop(runtime);
    require_runtime_quiescence(&blocking, "asupersync-p3")?;
    Ok(PreparedEngineEvidence {
        cases,
        runtime_quiescent: true,
    })
}

fn run_frankensqlite_prepared_matrix() -> Result<PreparedEngineEvidence, String> {
    let runtime = CompatRuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build FrankenSQLite P3 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "FrankenSQLite P3 runtime has no blocking pool".to_owned())?;
    let cases = runtime.block_on(async {
        let native_cx = CompatCx::current()
            .ok_or_else(|| "FrankenSQLite P3 compatibility runtime has no Cx".to_owned())?;
        let cx = attached_franken_cx(&native_cx);
        let mut connection = FrankenConnection::open(&cx, ":memory:")
            .await
            .map_err(|error| format!("FrankenSQLite P3 open: {error}"))?;
        connection
            .execute_batch(
                &cx,
                "CREATE TABLE p3_bind (
                    id INTEGER PRIMARY KEY,
                    int_value INTEGER,
                    real_value REAL,
                    text_value TEXT,
                    blob_value BLOB,
                    null_value INTEGER
                );
                CREATE TABLE p3_named (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE p3_reset (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO p3_reset VALUES (1, 'first'), (2, 'second');
                CREATE TABLE p3_schema (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                INSERT INTO p3_schema VALUES (1, 'before');
                CREATE TABLE p3_cancel (value TEXT NOT NULL);",
            )
            .await
            .map_err(|error| format!("set up FrankenSQLite P3 matrix: {error}"))?;

        let positional = frankensqlite_prepared_positional_case(&connection, &cx).await?;
        let named = frankensqlite_prepared_named_case(&connection, &cx).await?;
        let reset = frankensqlite_prepared_reset_case(&connection, &cx).await?;
        let schema = frankensqlite_prepared_schema_case(&connection, &cx).await?;
        let invalid = frankensqlite_prepared_invalid_case(&connection, &cx).await?;
        let cancelled = frankensqlite_prepared_cancel_case(&connection, &native_cx, &cx).await?;
        franken_close(&mut connection, &cx).await?;
        let busy = frankensqlite_prepared_busy_case()?;
        Ok::<_, String>(vec![
            positional, named, reset, schema, invalid, cancelled, busy,
        ])
    })?;
    drop(runtime);
    require_compat_runtime_quiescence(&blocking, "frankensqlite-p3")?;
    Ok(PreparedEngineEvidence {
        cases,
        runtime_quiescent: true,
    })
}

fn prepared_case(
    case_id: &'static str,
    observation: impl Into<String>,
    error_class: Option<&'static str>,
) -> PreparedCaseResult {
    PreparedCaseResult {
        case_id,
        observation: observation.into(),
        error_class,
        connection_reusable: true,
        cleanup_state: "statement_state_released",
    }
}

async fn asupersync_prepared_positional_case(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<PreparedCaseResult, String> {
    let text = "line-one\nline-two 'quoted'";
    let blob = vec![0, 1, 254, 255];
    let params = vec![
        AsupersyncValue::Integer(1),
        AsupersyncValue::Integer(i64::MIN),
        AsupersyncValue::Real(3.25),
        AsupersyncValue::Text(text.to_owned()),
        AsupersyncValue::Blob(blob.clone()),
        AsupersyncValue::Null,
    ];
    let affected = asupersync_outcome(
        connection
            .execute(
                cx,
                "INSERT INTO p3_bind VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                &params,
            )
            .await,
        "Asupersync P3 positional insert",
    )?;
    if affected != 1 {
        return Err(format!(
            "Asupersync P3 positional insert affected {affected} rows"
        ));
    }
    let row = asupersync_outcome(
        connection
            .query_row(
                cx,
                "SELECT * FROM p3_bind WHERE id = ?1",
                &[AsupersyncValue::Integer(1)],
            )
            .await,
        "Asupersync P3 positional query",
    )?
    .ok_or_else(|| "Asupersync P3 positional query returned no row".to_owned())?;
    let matches = row
        .get_i64("int_value")
        .is_ok_and(|value| value == i64::MIN)
        && row
            .get_f64("real_value")
            .is_ok_and(|value| value.to_bits() == 3.25_f64.to_bits())
        && row.get_str("text_value").is_ok_and(|value| value == text)
        && row
            .get_blob("blob_value")
            .is_ok_and(|value| value == blob.as_slice())
        && row.get("null_value").is_ok_and(AsupersyncValue::is_null);
    if !matches {
        return Err(format!("Asupersync P3 positional row drifted: {row:?}"));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-POSITIONAL-BIND-001",
        "null_integer_real_text_blob_round_trip",
        None,
    ))
}

async fn frankensqlite_prepared_positional_case(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<PreparedCaseResult, String> {
    let text = "line-one\nline-two 'quoted'";
    let blob = vec![0, 1, 254, 255];
    let params = vec![
        FrankenValue::Integer(1),
        FrankenValue::Integer(i64::MIN),
        FrankenValue::Float(3.25),
        FrankenValue::Text(text.into()),
        FrankenValue::Blob(Arc::from(blob.clone())),
        FrankenValue::Null,
    ];
    let affected = connection
        .execute_with_params(
            cx,
            "INSERT INTO p3_bind VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            &params,
        )
        .await
        .map_err(|error| format!("FrankenSQLite P3 positional insert: {error}"))?;
    if affected != 1 {
        return Err(format!(
            "FrankenSQLite P3 positional insert affected {affected} rows"
        ));
    }
    let row = connection
        .query_row_with_params(
            cx,
            "SELECT * FROM p3_bind WHERE id = ?1",
            &[FrankenValue::Integer(1)],
        )
        .await
        .map_err(|error| format!("FrankenSQLite P3 positional query: {error}"))?;
    let matches = matches!(row.get(1), Some(FrankenValue::Integer(i64::MIN)))
        && matches!(row.get(2), Some(FrankenValue::Float(value)) if value.to_bits() == 3.25_f64.to_bits())
        && matches!(row.get(3), Some(FrankenValue::Text(value)) if value.as_ref() == text)
        && matches!(row.get(4), Some(FrankenValue::Blob(value)) if value.as_ref() == blob.as_slice())
        && matches!(row.get(5), Some(FrankenValue::Null));
    if !matches {
        return Err(format!("FrankenSQLite P3 positional row drifted: {row:?}"));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-POSITIONAL-BIND-001",
        "null_integer_real_text_blob_round_trip",
        None,
    ))
}

async fn asupersync_prepared_named_case(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<PreparedCaseResult, String> {
    asupersync_outcome(
        connection
            .execute(
                cx,
                "INSERT INTO p3_named (id, value) VALUES (:id, :value)",
                &[
                    AsupersyncValue::Integer(7),
                    AsupersyncValue::Text("named-value".to_owned()),
                ],
            )
            .await,
        "Asupersync P3 named insert",
    )?;
    let row = asupersync_outcome(
        connection
            .query_row(
                cx,
                "SELECT value FROM p3_named WHERE id = :id",
                &[AsupersyncValue::Integer(7)],
            )
            .await,
        "Asupersync P3 named query",
    )?
    .ok_or_else(|| "Asupersync P3 named query returned no row".to_owned())?;
    if !row
        .get_str("value")
        .is_ok_and(|value| value == "named-value")
    {
        return Err(format!("Asupersync P3 named row drifted: {row:?}"));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-NAMED-BIND-002",
        "named_placeholders_bound_by_parameter_index",
        None,
    ))
}

async fn frankensqlite_prepared_named_case(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<PreparedCaseResult, String> {
    connection
        .execute_with_params(
            cx,
            "INSERT INTO p3_named (id, value) VALUES (:id, :value)",
            &[
                FrankenValue::Integer(7),
                FrankenValue::Text("named-value".into()),
            ],
        )
        .await
        .map_err(|error| format!("FrankenSQLite P3 named insert: {error}"))?;
    let row = connection
        .query_row_with_params(
            cx,
            "SELECT value FROM p3_named WHERE id = :id",
            &[FrankenValue::Integer(7)],
        )
        .await
        .map_err(|error| format!("FrankenSQLite P3 named query: {error}"))?;
    if !matches!(row.get(0), Some(FrankenValue::Text(value)) if value.as_ref() == "named-value") {
        return Err(format!("FrankenSQLite P3 named row drifted: {row:?}"));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-NAMED-BIND-002",
        "named_placeholders_bound_by_parameter_index",
        None,
    ))
}

async fn asupersync_prepared_reset_case(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<PreparedCaseResult, String> {
    let query = "SELECT value FROM p3_reset WHERE id = ?1";
    let mut observed = Vec::new();
    for id in [1, 2, 99, 1] {
        let rows = asupersync_outcome(
            connection
                .query(cx, query, &[AsupersyncValue::Integer(id)])
                .await,
            "Asupersync P3 repeated query",
        )?;
        observed.push(if rows.is_empty() {
            "missing".to_owned()
        } else {
            exactly_one(rows, "Asupersync P3 repeated query")?
                .get_str("value")
                .map(str::to_owned)
                .map_err(|error| format!("Asupersync P3 repeated value: {error}"))?
        });
    }
    if observed != ["first", "second", "missing", "first"] {
        return Err(format!(
            "Asupersync P3 repeated results drifted: {observed:?}"
        ));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-RESET-CACHE-HIT-003",
        observed.join(","),
        None,
    ))
}

async fn frankensqlite_prepared_reset_case(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<PreparedCaseResult, String> {
    let query = "SELECT value FROM p3_reset WHERE id = ?1";
    let mut observed = Vec::new();
    for id in [1, 2, 99, 1] {
        let rows = connection
            .query_with_params(cx, query, &[FrankenValue::Integer(id)])
            .await
            .map_err(|error| format!("FrankenSQLite P3 repeated query: {error}"))?;
        observed.push(if rows.is_empty() {
            "missing".to_owned()
        } else {
            match exactly_one(rows, "FrankenSQLite P3 repeated query")?.get(0) {
                Some(FrankenValue::Text(value)) => value.to_string(),
                other => {
                    return Err(format!(
                        "FrankenSQLite P3 repeated value drifted: {other:?}"
                    ));
                }
            }
        });
    }
    if observed != ["first", "second", "missing", "first"] {
        return Err(format!(
            "FrankenSQLite P3 repeated results drifted: {observed:?}"
        ));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-RESET-CACHE-HIT-003",
        observed.join(","),
        None,
    ))
}

async fn asupersync_prepared_schema_case(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<PreparedCaseResult, String> {
    let query = "SELECT value FROM p3_schema WHERE id = 1";
    let before = asupersync_outcome(
        connection.query(cx, query, &[]).await,
        "Asupersync P3 schema before",
    )?;
    let before = exactly_one(before, "Asupersync P3 schema before")?
        .get_str("value")
        .map(str::to_owned)
        .map_err(|error| format!("Asupersync P3 schema before value: {error}"))?;
    asupersync_outcome(
        connection
            .execute_batch(
                cx,
                "DROP TABLE p3_schema;
                 CREATE TABLE p3_schema (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO p3_schema VALUES (1, 'after');",
            )
            .await,
        "Asupersync P3 schema rebuild",
    )?;
    let after = asupersync_outcome(
        connection.query(cx, query, &[]).await,
        "Asupersync P3 schema after",
    )?;
    let after = exactly_one(after, "Asupersync P3 schema after")?
        .get_str("value")
        .map(str::to_owned)
        .map_err(|error| format!("Asupersync P3 schema after value: {error}"))?;
    if before != "before" || after != "after" {
        return Err(format!(
            "Asupersync P3 schema sequence drifted: {before}->{after}"
        ));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-SCHEMA-CHANGE-005",
        "before->after",
        None,
    ))
}

async fn frankensqlite_prepared_schema_case(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<PreparedCaseResult, String> {
    let query = "SELECT value FROM p3_schema WHERE id = 1";
    let before = connection
        .query_row(cx, query)
        .await
        .map_err(|error| format!("FrankenSQLite P3 schema before: {error}"))?;
    let before = match before.get(0) {
        Some(FrankenValue::Text(value)) => value.to_string(),
        other => return Err(format!("FrankenSQLite P3 schema before drifted: {other:?}")),
    };
    connection
        .execute_batch(
            cx,
            "DROP TABLE p3_schema;
             CREATE TABLE p3_schema (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO p3_schema VALUES (1, 'after');",
        )
        .await
        .map_err(|error| format!("FrankenSQLite P3 schema rebuild: {error}"))?;
    let after = connection
        .query_row(cx, query)
        .await
        .map_err(|error| format!("FrankenSQLite P3 schema after: {error}"))?;
    let after = match after.get(0) {
        Some(FrankenValue::Text(value)) => value.to_string(),
        other => return Err(format!("FrankenSQLite P3 schema after drifted: {other:?}")),
    };
    if before != "before" || after != "after" {
        return Err(format!(
            "FrankenSQLite P3 schema sequence drifted: {before}->{after}"
        ));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-SCHEMA-CHANGE-005",
        "before->after",
        None,
    ))
}

async fn asupersync_prepared_invalid_case(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<PreparedCaseResult, String> {
    for (label, outcome) in [
        ("malformed", connection.execute(cx, "SELEKT 1", &[]).await),
        (
            "too_few",
            connection
                .execute(cx, "SELECT ?1 + ?2", &[AsupersyncValue::Integer(1)])
                .await,
        ),
    ] {
        if !matches!(
            outcome,
            Outcome::Err(SqliteError::Sqlite(_) | SqliteError::UnsafeSql(_))
        ) {
            return Err(format!("Asupersync P3 {label} error drifted: {outcome:?}"));
        }
    }
    let too_many = connection
        .execute(
            cx,
            "SELECT ?1",
            &[AsupersyncValue::Integer(1), AsupersyncValue::Integer(2)],
        )
        .await;
    if !matches!(
        too_many,
        Outcome::Err(SqliteError::Sqlite(_) | SqliteError::UnsafeSql(_))
    ) {
        return Err(format!(
            "Asupersync P3 surplus-parameter contract drifted: {too_many:?}"
        ));
    }
    let reusable = asupersync_outcome(
        connection.query(cx, "SELECT 1", &[]).await,
        "Asupersync P3 invalid-use recovery",
    )?;
    exactly_one(reusable, "Asupersync P3 invalid-use recovery")?;
    Ok(prepared_case(
        "SQLITE-PARITY-P3-INVALID-USE-006",
        "malformed,too_few_rejected",
        Some("sql_rejected"),
    ))
}

async fn frankensqlite_prepared_invalid_case(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<PreparedCaseResult, String> {
    let malformed = connection.execute(cx, "SELEKT 1").await;
    let too_few = connection
        .execute_with_params(cx, "SELECT ?1 + ?2", &[FrankenValue::Integer(1)])
        .await;
    let too_many = connection
        .execute_with_params(
            cx,
            "SELECT ?1",
            &[FrankenValue::Integer(1), FrankenValue::Integer(2)],
        )
        .await;
    for (label, result) in [("malformed", malformed), ("too_few", too_few)] {
        if result.is_ok() {
            return Err(format!("FrankenSQLite P3 {label} unexpectedly succeeded"));
        }
    }
    too_many.map_err(|error| {
        format!("FrankenSQLite P3 surplus-parameter acceptance drifted: {error}")
    })?;
    connection
        .query(cx, "SELECT 1")
        .await
        .map_err(|error| format!("FrankenSQLite P3 invalid-use recovery: {error}"))?;
    Ok(prepared_case(
        "SQLITE-PARITY-P3-INVALID-USE-006",
        "malformed,too_few_rejected",
        Some("sql_rejected"),
    ))
}

async fn asupersync_prepared_cancel_case(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<PreparedCaseResult, String> {
    cx.set_cancel_requested(true);
    let result = connection
        .execute(
            cx,
            "INSERT INTO p3_cancel VALUES (?1)",
            &[AsupersyncValue::Text("must-not-commit".to_owned())],
        )
        .await;
    cx.set_cancel_requested(false);
    match result {
        Outcome::Cancelled(_) => {}
        other => return Err(format!("Asupersync P3 pre-cancel drifted: {other:?}")),
    }
    let rows = asupersync_outcome(
        connection
            .query(cx, "SELECT COUNT(*) FROM p3_cancel", &[])
            .await,
        "Asupersync P3 pre-cancel count",
    )?;
    let count = exactly_one(rows, "Asupersync P3 pre-cancel count")?
        .get_idx(0)
        .map_err(|error| format!("Asupersync P3 pre-cancel count value: {error}"))?
        .as_integer();
    if count != Some(0) {
        return Err(format!("Asupersync P3 pre-cancel mutated state: {count:?}"));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-FINALIZE-CANCEL-007",
        "pre_cancelled_without_mutation",
        Some("cancelled"),
    ))
}

async fn frankensqlite_prepared_cancel_case(
    connection: &FrankenConnection,
    native_cx: &CompatCx,
    cx: &FrankenCx,
) -> Result<PreparedCaseResult, String> {
    native_cx.set_cancel_requested(true);
    let cancelled_cx = attached_franken_cx(native_cx);
    let result = connection
        .execute_with_params(
            &cancelled_cx,
            "INSERT INTO p3_cancel VALUES (?1)",
            &[FrankenValue::Text("must-not-commit".into())],
        )
        .await;
    native_cx.set_cancel_requested(false);
    if !matches!(result, Err(FrankenError::Interrupt)) {
        return Err(format!("FrankenSQLite P3 pre-cancel drifted: {result:?}"));
    }
    let row = connection
        .query_row(cx, "SELECT COUNT(*) FROM p3_cancel")
        .await
        .map_err(|error| format!("FrankenSQLite P3 pre-cancel count: {error}"))?;
    if !matches!(row.get(0), Some(FrankenValue::Integer(0))) {
        return Err(format!(
            "FrankenSQLite P3 pre-cancel mutated state: {row:?}"
        ));
    }
    Ok(prepared_case(
        "SQLITE-PARITY-P3-FINALIZE-CANCEL-007",
        "pre_cancelled_without_mutation",
        Some("cancelled"),
    ))
}

async fn asupersync_prepared_busy_case(cx: &Cx) -> Result<PreparedCaseResult, String> {
    let path = scratch_database_path("asupersync-p3-busy");
    let holder = asupersync_outcome(
        SqliteConnection::open(cx, &path).await,
        "Asupersync P3 busy holder open",
    )?;
    let contender = asupersync_outcome(
        SqliteConnection::open(cx, &path).await,
        "Asupersync P3 busy contender open",
    )?;
    asupersync_outcome(
        holder
            .execute_batch(cx, "CREATE TABLE busy (value TEXT NOT NULL);")
            .await,
        "Asupersync P3 busy schema",
    )?;
    asupersync_outcome(
        contender.set_busy_timeout(cx, Duration::ZERO).await,
        "Asupersync P3 busy timeout",
    )?;
    let transaction =
        asupersync_outcome(holder.begin_immediate(cx).await, "Asupersync P3 busy begin")?;
    asupersync_outcome(
        transaction
            .execute(
                cx,
                "INSERT INTO busy VALUES (?1)",
                &[AsupersyncValue::Text("holder".to_owned())],
            )
            .await,
        "Asupersync P3 busy holder write",
    )?;
    match contender
        .execute(
            cx,
            "INSERT INTO busy VALUES (?1)",
            &[AsupersyncValue::Text("contender".to_owned())],
        )
        .await
    {
        Outcome::Err(error) if error.is_busy() || error.is_locked() => {}
        other => return Err(format!("Asupersync P3 busy contender drifted: {other:?}")),
    }
    asupersync_outcome(
        transaction.rollback(cx).await,
        "Asupersync P3 busy rollback",
    )?;
    asupersync_outcome(
        contender
            .execute(
                cx,
                "INSERT INTO busy VALUES (?1)",
                &[AsupersyncValue::Text("after".to_owned())],
            )
            .await,
        "Asupersync P3 busy recovery write",
    )?;
    asupersync_close(&holder, cx).await?;
    asupersync_close(&contender, cx).await?;
    Ok(prepared_case(
        "SQLITE-PARITY-P3-BUSY-008",
        "contender_rejected_then_recovered",
        Some("busy_or_locked"),
    ))
}

fn run_frankensqlite_busy_child() -> Result<(), String> {
    let runtime = CompatRuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build FrankenSQLite P3 busy-child runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "FrankenSQLite P3 busy-child runtime has no blocking pool".to_owned())?;
    runtime.block_on(async {
        let native_cx = CompatCx::current()
            .ok_or_else(|| "FrankenSQLite P3 busy-child runtime has no Cx".to_owned())?;
        let cx = attached_franken_cx(&native_cx);
        frankensqlite_prepared_busy_case_inner(&cx)
            .await
            .map(|_| ())
    })?;
    drop(runtime);
    require_compat_runtime_quiescence(&blocking, "frankensqlite-p3-busy-child")
}

fn frankensqlite_prepared_busy_case() -> Result<PreparedCaseResult, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("resolve SQLite P3 consumer executable: {error}"))?;
    let mut child = Command::new(executable)
        .env_clear()
        .env(P3_BUSY_CHILD_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("spawn FrankenSQLite P3 busy child: {error}"))?;
    let deadline = Instant::now() + P3_BUSY_WATCHDOG;
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("poll FrankenSQLite P3 busy child: {error}"))?
        {
            if status.success() {
                return Ok(prepared_case(
                    "SQLITE-PARITY-P3-BUSY-008",
                    "contender_rejected_then_recovered",
                    Some("busy_or_locked"),
                ));
            }
            return Err(format!(
                "FrankenSQLite P3 busy child failed before watchdog: {status}"
            ));
        }
        if Instant::now() >= deadline {
            let kill_result = child.kill();
            let status = child
                .wait()
                .map_err(|error| format!("reap FrankenSQLite P3 busy child: {error}"))?;
            if status.success() {
                return Ok(prepared_case(
                    "SQLITE-PARITY-P3-BUSY-008",
                    "contender_rejected_then_recovered",
                    Some("busy_or_locked"),
                ));
            }
            kill_result.map_err(|error| format!("kill FrankenSQLite P3 busy child: {error}"))?;
            return Ok(PreparedCaseResult {
                case_id: "SQLITE-PARITY-P3-BUSY-008",
                observation: "operation_did_not_complete_within_5s".to_owned(),
                error_class: Some("watchdog_timeout"),
                connection_reusable: false,
                cleanup_state: "isolated_child_killed_and_reaped",
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn frankensqlite_prepared_busy_case_inner(
    cx: &FrankenCx,
) -> Result<PreparedCaseResult, String> {
    let path = path_to_string(&scratch_database_path("frankensqlite-p3-busy"))?.to_owned();
    let mut holder = FrankenConnection::open(cx, path.clone())
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy holder open: {error}"))?;
    let mut contender = FrankenConnection::open(cx, path)
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy contender open: {error}"))?;
    holder
        .execute_batch(cx, "CREATE TABLE busy (value TEXT NOT NULL);")
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy schema: {error}"))?;
    contender
        .execute_batch(cx, "PRAGMA busy_timeout = 0;")
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy timeout: {error}"))?;
    holder
        .execute_batch(cx, "BEGIN IMMEDIATE;")
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy begin: {error}"))?;
    holder
        .execute_with_params(
            cx,
            "INSERT INTO busy VALUES (?1)",
            &[FrankenValue::Text("holder".into())],
        )
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy holder write: {error}"))?;
    let contender_result = contender
        .execute_with_params(
            cx,
            "INSERT INTO busy VALUES (?1)",
            &[FrankenValue::Text("contender".into())],
        )
        .await;
    match contender_result {
        Err(FrankenError::Busy | FrankenError::BusyRecovery)
        | Err(FrankenError::BusySnapshot { .. })
        | Err(FrankenError::DatabaseLocked { .. })
        | Err(FrankenError::LockFailed { .. })
        | Err(FrankenError::WriteConflict { .. })
        | Err(FrankenError::SerializationFailure { .. }) => {}
        other => {
            return Err(format!(
                "FrankenSQLite P3 busy contender drifted: {other:?}"
            ));
        }
    }
    holder
        .execute_batch(cx, "ROLLBACK;")
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy rollback: {error}"))?;
    contender
        .execute_with_params(
            cx,
            "INSERT INTO busy VALUES (?1)",
            &[FrankenValue::Text("after".into())],
        )
        .await
        .map_err(|error| format!("FrankenSQLite P3 busy recovery write: {error}"))?;
    franken_close(&mut holder, cx).await?;
    franken_close(&mut contender, cx).await?;
    Ok(prepared_case(
        "SQLITE-PARITY-P3-BUSY-008",
        "contender_rejected_then_recovered",
        Some("busy_or_locked"),
    ))
}

fn run_value_parity() -> Result<ValueParityEvidence, String> {
    let asupersync = run_asupersync_value_matrix()?;
    let frankensqlite = run_frankensqlite_value_matrix()?;
    let mismatches = if asupersync.values == frankensqlite.values {
        Vec::new()
    } else {
        vec!["normalized common value rows differ".to_owned()]
    };
    if !mismatches.is_empty() {
        return Err(format!(
            "SQLite P6 value parity failed: {}",
            mismatches.join(", ")
        ));
    }

    Ok(ValueParityEvidence {
        bead_id: "asupersync-ym2wtv.2.6",
        matrix_id: "sqlite-neutral-value-row-parity-v1",
        status: "PASS_BOUNDED_COMMON_VALUES_WITH_EXPLICIT_ROW_METADATA_UNSUPPORTED",
        profile_max_value_bytes: P6_PROFILE_MAX_VALUE_BYTES,
        compared_values: P6_VALUE_CASE_IDS.len(),
        asupersync,
        frankensqlite,
        mismatches,
        unsupported: vec![ValueUnsupportedEvidence {
            engine: "frankensqlite",
            capability: "async_row_column_names_and_name_lookup",
            reason: "The pinned AsyncConnection Row exposes owned values by index but no public result-column metadata or name lookup; the neutral adapter does not infer aliases from SQL text.",
        }],
    })
}

fn run_asupersync_value_matrix() -> Result<ValueEngineEvidence, String> {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build Asupersync P6 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "Asupersync P6 runtime has no blocking pool".to_owned())?;
    let evidence = runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "Asupersync P6 runtime has no Cx".to_owned())?;
        let connection = asupersync_open_memory(&cx).await?;
        let params = asupersync_p6_params();
        let rows = asupersync_outcome(
            connection.query(&cx, P6_VALUE_QUERY, &params).await,
            "query Asupersync P6 values",
        )?;
        let row = exactly_one(rows, "Asupersync P6 value row")?;
        let metadata_rows = asupersync_outcome(
            connection
                .query(&cx, "SELECT 1 AS dup, 2 AS Other, 3 AS dup, 4 AS Tail", &[])
                .await,
            "query Asupersync P6 row metadata",
        )?;
        let metadata_row = exactly_one(metadata_rows, "Asupersync P6 metadata row")?;
        asupersync_close(&connection, &cx).await?;

        let expected = p6_expected_values();
        verify_asupersync_values(&row, &expected)?;
        let type_mismatch_class = match row.get_i64("large_text") {
            Err(SqliteError::TypeMismatch { .. }) => "type_mismatch",
            other => return Err(format!("Asupersync P6 type mismatch drifted: {other:?}")),
        };
        let out_of_bounds_class = match row.get_idx(expected.len()) {
            Err(SqliteError::ColumnNotFound(_)) => "index_out_of_bounds",
            other => return Err(format!("Asupersync P6 out-of-bounds drifted: {other:?}")),
        };
        let ordered_names = metadata_row
            .column_names_in_order()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let legacy_sorted_unique_names = metadata_row
            .column_names()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let legacy_exact_dup_value = match metadata_row.get_i64("dup") {
            Ok(value) => Some(value),
            Err(error) => return Err(format!("Asupersync P6 duplicate lookup failed: {error}")),
        };
        let missing_name_class = match metadata_row.get("missing") {
            Err(SqliteError::ColumnNotFound(_)) => "column_not_found",
            other => return Err(format!("Asupersync P6 missing-name drifted: {other:?}")),
        };
        Ok::<_, String>(ValueEngineEvidence {
            values: value_case_results(&expected),
            owned_after_close: true,
            type_mismatch_class,
            out_of_bounds_class,
            row_metadata: RowMetadataEvidence {
                status: "PASS",
                ordered_names,
                legacy_sorted_unique_names,
                first_ascii_case_insensitive_dup_index: metadata_row.column_index("DUP"),
                legacy_exact_dup_value,
                missing_name_class,
            },
            runtime_quiescent: true,
        })
    })?;
    drop(runtime);
    require_runtime_quiescence(&blocking, "asupersync-p6")?;
    Ok(evidence)
}

fn run_frankensqlite_value_matrix() -> Result<ValueEngineEvidence, String> {
    let runtime = CompatRuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build FrankenSQLite P6 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "FrankenSQLite P6 runtime has no blocking pool".to_owned())?;
    let evidence = runtime.block_on(async {
        let native_cx = CompatCx::current()
            .ok_or_else(|| "FrankenSQLite P6 compatibility runtime has no Cx".to_owned())?;
        let cx = attached_franken_cx(&native_cx);
        let mut connection = FrankenConnection::open(&cx, ":memory:")
            .await
            .map_err(|error| format!("FrankenSQLite P6 open: {error}"))?;
        let rows = connection
            .query_with_params(&cx, P6_VALUE_QUERY, &frankensqlite_p6_params())
            .await
            .map_err(|error| format!("FrankenSQLite P6 value query: {error}"))?;
        let row = exactly_one(rows, "FrankenSQLite P6 value row")?;
        franken_close(&mut connection, &cx).await?;

        let expected = p6_expected_values();
        verify_frankensqlite_values(&row, &expected)?;
        let type_mismatch_class = match row.get_typed::<i64>(12) {
            Err(FrankenError::TypeMismatch { .. }) => "type_mismatch",
            other => return Err(format!("FrankenSQLite P6 type mismatch drifted: {other:?}")),
        };
        let out_of_bounds_class = match row.get_typed::<i64>(expected.len()) {
            Err(FrankenError::NoSuchColumn { .. }) => "index_out_of_bounds",
            other => return Err(format!("FrankenSQLite P6 out-of-bounds drifted: {other:?}")),
        };
        Ok::<_, String>(ValueEngineEvidence {
            values: value_case_results(&expected),
            owned_after_close: true,
            type_mismatch_class,
            out_of_bounds_class,
            row_metadata: RowMetadataEvidence {
                status: "UNSUPPORTED_NO_PUBLIC_ASYNC_ROW_METADATA",
                ordered_names: Vec::new(),
                legacy_sorted_unique_names: Vec::new(),
                first_ascii_case_insensitive_dup_index: None,
                legacy_exact_dup_value: None,
                missing_name_class: "unsupported",
            },
            runtime_quiescent: true,
        })
    })?;
    drop(runtime);
    require_compat_runtime_quiescence(&blocking, "frankensqlite-p6")?;
    Ok(evidence)
}

fn p6_expected_values() -> Vec<ExpectedValue> {
    vec![
        ExpectedValue::Null,
        ExpectedValue::Integer(i64::MIN),
        ExpectedValue::Integer(i64::MAX),
        ExpectedValue::Integer(9_007_199_254_740_993),
        ExpectedValue::Real(-0.0),
        ExpectedValue::Real(f64::INFINITY),
        ExpectedValue::Real(f64::NEG_INFINITY),
        ExpectedValue::Null,
        ExpectedValue::Text(String::new()),
        ExpectedValue::Text("Delta-Δ\0emoji-🙂".to_owned()),
        ExpectedValue::Blob(Vec::new()),
        ExpectedValue::Blob(vec![0, 255, 1, 254, 2, 253, 128, 127]),
        ExpectedValue::Text("L".repeat(P6_PROFILE_MAX_VALUE_BYTES)),
        ExpectedValue::Blob(
            (0..P6_PROFILE_MAX_VALUE_BYTES)
                .map(|index| ((index * 131 + 17) & 0xff) as u8)
                .collect(),
        ),
    ]
}

fn asupersync_p6_params() -> Vec<AsupersyncValue> {
    let expected = p6_expected_values();
    expected
        .into_iter()
        .enumerate()
        .map(|(index, value)| match (index, value) {
            (7, ExpectedValue::Null) => AsupersyncValue::Real(f64::NAN),
            (_, ExpectedValue::Null) => AsupersyncValue::Null,
            (_, ExpectedValue::Integer(value)) => AsupersyncValue::Integer(value),
            (_, ExpectedValue::Real(value)) => AsupersyncValue::Real(value),
            (_, ExpectedValue::Text(value)) => AsupersyncValue::Text(value),
            (_, ExpectedValue::Blob(value)) => AsupersyncValue::Blob(value),
        })
        .collect()
}

fn frankensqlite_p6_params() -> Vec<FrankenValue> {
    let expected = p6_expected_values();
    expected
        .into_iter()
        .enumerate()
        .map(|(index, value)| match (index, value) {
            (7, ExpectedValue::Null) => FrankenValue::Float(f64::NAN),
            (_, ExpectedValue::Null) => FrankenValue::Null,
            (_, ExpectedValue::Integer(value)) => FrankenValue::Integer(value),
            (_, ExpectedValue::Real(value)) => FrankenValue::Float(value),
            (_, ExpectedValue::Text(value)) => FrankenValue::Text(value.into()),
            (_, ExpectedValue::Blob(value)) => FrankenValue::Blob(Arc::from(value)),
        })
        .collect()
}

fn verify_asupersync_values(
    row: &asupersync::database::SqliteRow,
    expected: &[ExpectedValue],
) -> Result<(), String> {
    if row.len() != expected.len() {
        return Err(format!(
            "Asupersync P6 returned {} columns, expected {}",
            row.len(),
            expected.len()
        ));
    }
    for (index, expected) in expected.iter().enumerate() {
        let actual = row
            .get_idx(index)
            .map_err(|error| format!("Asupersync P6 column {index}: {error}"))?;
        if !asupersync_value_matches(actual, expected) {
            return Err(format!(
                "Asupersync P6 {} mismatch: actual {actual:?}, expected {expected:?}",
                P6_VALUE_CASE_IDS[index]
            ));
        }
    }
    Ok(())
}

fn verify_frankensqlite_values(
    row: &fsqlite::Row,
    expected: &[ExpectedValue],
) -> Result<(), String> {
    if row.values().len() != expected.len() {
        return Err(format!(
            "FrankenSQLite P6 returned {} columns, expected {}",
            row.values().len(),
            expected.len()
        ));
    }
    for (index, expected) in expected.iter().enumerate() {
        let actual = row
            .get(index)
            .ok_or_else(|| format!("FrankenSQLite P6 column {index} is missing"))?;
        if !frankensqlite_value_matches(actual, expected) {
            return Err(format!(
                "FrankenSQLite P6 {} mismatch: actual {actual:?}, expected {expected:?}",
                P6_VALUE_CASE_IDS[index]
            ));
        }
    }
    Ok(())
}

fn asupersync_value_matches(actual: &AsupersyncValue, expected: &ExpectedValue) -> bool {
    match (actual, expected) {
        (AsupersyncValue::Null, ExpectedValue::Null) => true,
        (AsupersyncValue::Integer(actual), ExpectedValue::Integer(expected)) => actual == expected,
        (AsupersyncValue::Real(actual), ExpectedValue::Real(expected)) => {
            actual.to_bits() == expected.to_bits()
        }
        (AsupersyncValue::Text(actual), ExpectedValue::Text(expected)) => actual == expected,
        (AsupersyncValue::Blob(actual), ExpectedValue::Blob(expected)) => actual == expected,
        _ => false,
    }
}

fn frankensqlite_value_matches(actual: &FrankenValue, expected: &ExpectedValue) -> bool {
    match (actual, expected) {
        (FrankenValue::Null, ExpectedValue::Null) => true,
        (FrankenValue::Integer(actual), ExpectedValue::Integer(expected)) => actual == expected,
        (FrankenValue::Float(actual), ExpectedValue::Real(expected)) => {
            actual.to_bits() == expected.to_bits()
        }
        (FrankenValue::Text(actual), ExpectedValue::Text(expected)) => actual.as_str() == expected,
        (FrankenValue::Blob(actual), ExpectedValue::Blob(expected)) => actual.as_ref() == expected,
        _ => false,
    }
}

fn value_case_results(expected: &[ExpectedValue]) -> Vec<ValueCaseResult> {
    expected
        .iter()
        .zip(P6_VALUE_CASE_IDS)
        .map(|(value, case_id)| {
            let (storage_class, exact_scalar, byte_len, fingerprint) = match value {
                ExpectedValue::Null => ("null", Some("null".to_owned()), None, fnv1a64(b"null")),
                ExpectedValue::Integer(value) => (
                    "integer",
                    Some(value.to_string()),
                    None,
                    fnv1a64(&value.to_le_bytes()),
                ),
                ExpectedValue::Real(value) => (
                    "real",
                    Some(format!("0x{:016x}", value.to_bits())),
                    None,
                    fnv1a64(&value.to_bits().to_le_bytes()),
                ),
                ExpectedValue::Text(value) => (
                    "text",
                    (value.len() <= 64).then(|| value.clone()),
                    Some(value.len()),
                    fnv1a64(value.as_bytes()),
                ),
                ExpectedValue::Blob(value) => ("blob", None, Some(value.len()), fnv1a64(value)),
            };
            ValueCaseResult {
                case_id,
                storage_class,
                exact_scalar,
                byte_len,
                fnv1a64: format!("{fingerprint:016x}"),
            }
        })
        .collect()
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn exactly_one<T>(mut values: Vec<T>, context: &str) -> Result<T, String> {
    if values.len() != 1 {
        return Err(format!(
            "{context} returned {} rows, expected 1",
            values.len()
        ));
    }
    Ok(values.remove(0))
}

fn transaction_cases() -> [TransactionCase; 5] {
    [
        TransactionCase {
            id: "SQLITE-PARITY-P4-DEFERRED-COMMIT-001",
            kind: TransactionCaseKind::DeferredCommit,
        },
        TransactionCase {
            id: "SQLITE-PARITY-P4-IMMEDIATE-ROLLBACK-002",
            kind: TransactionCaseKind::ImmediateRollback,
        },
        TransactionCase {
            id: "SQLITE-PARITY-P4-EXCLUSIVE-COMMIT-003",
            kind: TransactionCaseKind::ExclusiveCommit,
        },
        TransactionCase {
            id: "SQLITE-PARITY-P4-SAVEPOINT-PARTIAL-ROLLBACK-004",
            kind: TransactionCaseKind::SavepointPartialRollback,
        },
        TransactionCase {
            id: "SQLITE-PARITY-P4-CONSTRAINT-CONFLICT-RECOVERY-005",
            kind: TransactionCaseKind::ConflictRecovery,
        },
    ]
}

fn run_transaction_parity() -> Result<TransactionParityEvidence, String> {
    let cases = transaction_cases();
    let asupersync = run_asupersync_transaction_cases(&cases)?;
    let frankensqlite = run_frankensqlite_transaction_cases(&cases)?;
    let mismatches = asupersync
        .iter()
        .zip(&frankensqlite)
        .filter_map(|(native, franken)| {
            (native != franken)
                .then(|| format!("{}: normalized transaction outcomes differ", native.case_id))
        })
        .collect::<Vec<_>>();
    if !mismatches.is_empty() {
        return Err(format!(
            "SQLite P4 transaction parity failed: {}",
            mismatches.join(", ")
        ));
    }
    Ok(TransactionParityEvidence {
        bead_id: "asupersync-ym2wtv.2.4",
        matrix_id: "sqlite-neutral-transaction-parity-v1",
        status: "PASS",
        compared_cases: cases.len(),
        asupersync,
        frankensqlite,
        mismatches,
    })
}

fn run_asupersync_transaction_cases(
    cases: &[TransactionCase],
) -> Result<Vec<TransactionCaseResult>, String> {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build asupersync transaction runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "asupersync transaction runtime has no blocking pool".to_owned())?;
    let results = runtime.block_on(async {
        let cx = Cx::current()
            .ok_or_else(|| "asupersync transaction runtime did not install Cx".to_owned())?;
        let mut results = Vec::with_capacity(cases.len());
        for case in cases {
            results.push(run_asupersync_transaction_case(*case, &cx).await?);
        }
        Ok::<_, String>(results)
    })?;
    drop(runtime);
    require_runtime_quiescence(&blocking, "asupersync transaction matrix")?;
    Ok(results)
}

async fn run_asupersync_transaction_case(
    case: TransactionCase,
    cx: &Cx,
) -> Result<TransactionCaseResult, String> {
    if matches!(case.kind, TransactionCaseKind::ConflictRecovery) {
        return run_asupersync_conflict_case(case.id, cx).await;
    }

    let connection = asupersync_open_memory(cx).await?;
    asupersync_outcome(
        connection
            .execute_batch(
                cx,
                "CREATE TABLE p4_tx (id INTEGER PRIMARY KEY, label TEXT NOT NULL);",
            )
            .await,
        "create transaction parity table",
    )?;

    let terminal_state = match case.kind {
        TransactionCaseKind::DeferredCommit => {
            let transaction = asupersync_outcome(connection.begin(cx).await, "begin deferred")?;
            asupersync_insert_label(&transaction, cx, 1, "deferred").await?;
            asupersync_outcome(transaction.commit(cx).await, "commit deferred")?;
            "committed"
        }
        TransactionCaseKind::ImmediateRollback => {
            let transaction =
                asupersync_outcome(connection.begin_immediate(cx).await, "begin immediate")?;
            asupersync_insert_label(&transaction, cx, 1, "immediate").await?;
            asupersync_outcome(transaction.rollback(cx).await, "rollback immediate")?;
            "rolled_back"
        }
        TransactionCaseKind::ExclusiveCommit => {
            let transaction =
                asupersync_outcome(connection.begin_exclusive(cx).await, "begin exclusive")?;
            asupersync_insert_label(&transaction, cx, 1, "exclusive").await?;
            asupersync_outcome(transaction.commit(cx).await, "commit exclusive")?;
            "committed"
        }
        TransactionCaseKind::SavepointPartialRollback => {
            let transaction = asupersync_outcome(connection.begin(cx).await, "begin savepoint")?;
            asupersync_insert_label(&transaction, cx, 1, "base").await?;
            let savepoint = asupersync_outcome(
                SqliteSavepoint::new(&transaction, cx, "p4_partial").await,
                "create savepoint",
            )?;
            asupersync_insert_label(&transaction, cx, 2, "discarded").await?;
            asupersync_outcome(savepoint.rollback(cx).await, "rollback savepoint")?;
            asupersync_insert_label(&transaction, cx, 3, "after").await?;
            asupersync_outcome(transaction.commit(cx).await, "commit savepoint transaction")?;
            "committed_after_savepoint_rollback"
        }
        TransactionCaseKind::ConflictRecovery => unreachable!("handled above"),
    };

    let visible_labels = collect_asupersync_labels(&connection, cx).await?;
    prove_asupersync_connection_reusable(&connection, cx).await?;
    asupersync_close(&connection, cx).await?;
    Ok(TransactionCaseResult {
        case_id: case.id,
        terminal_state,
        visible_labels,
        conflict_class: None,
        connection_reusable: true,
        open_transactions: 0,
    })
}

async fn asupersync_insert_label(
    transaction: &SqliteTransaction<'_>,
    cx: &Cx,
    id: i64,
    label: &str,
) -> Result<(), String> {
    let affected = asupersync_outcome(
        transaction
            .execute(
                cx,
                "INSERT INTO p4_tx (id, label) VALUES (?1, ?2)",
                &[
                    AsupersyncValue::Integer(id),
                    AsupersyncValue::Text(label.to_owned()),
                ],
            )
            .await,
        "insert transaction parity row",
    )?;
    if affected != 1 {
        return Err(format!(
            "asupersync transaction insert affected {affected} rows"
        ));
    }
    Ok(())
}

async fn collect_asupersync_labels(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<Vec<String>, String> {
    let rows = asupersync_outcome(
        connection
            .query(cx, "SELECT label FROM p4_tx ORDER BY id", &[])
            .await,
        "query transaction parity labels",
    )?;
    rows.iter()
        .map(|row| match row.get_idx(0) {
            Ok(AsupersyncValue::Text(label)) => Ok(label.clone()),
            other => Err(format!(
                "asupersync transaction label was not text: {other:?}"
            )),
        })
        .collect()
}

async fn prove_asupersync_connection_reusable(
    connection: &SqliteConnection,
    cx: &Cx,
) -> Result<(), String> {
    let transaction = asupersync_outcome(connection.begin(cx).await, "begin reuse probe")?;
    asupersync_outcome(transaction.rollback(cx).await, "rollback reuse probe")
}

async fn run_asupersync_conflict_case(
    case_id: &'static str,
    cx: &Cx,
) -> Result<TransactionCaseResult, String> {
    let connection = asupersync_open_memory(cx).await?;
    asupersync_outcome(
        connection
            .execute_batch(
                cx,
                "CREATE TABLE p4_tx (id INTEGER PRIMARY KEY, label TEXT NOT NULL);",
            )
            .await,
        "create constraint-conflict table",
    )?;

    let transaction = asupersync_outcome(connection.begin(cx).await, "begin conflict case")?;
    asupersync_insert_label(&transaction, cx, 1, "first").await?;
    match transaction
        .execute(
            cx,
            "INSERT INTO p4_tx (id, label) VALUES (?1, ?2)",
            &[
                AsupersyncValue::Integer(1),
                AsupersyncValue::Text("duplicate".to_owned()),
            ],
        )
        .await
    {
        Outcome::Err(error) if error.is_constraint_violation() => {}
        Outcome::Err(error) => {
            return Err(format!(
                "asupersync duplicate key returned non-constraint error: {error}"
            ));
        }
        Outcome::Ok(_) => {
            return Err("asupersync duplicate key unexpectedly succeeded".to_owned());
        }
        Outcome::Cancelled(_) => {
            return Err("asupersync duplicate key was cancelled".to_owned());
        }
        Outcome::Panicked(_) => return Err("asupersync duplicate key panicked".to_owned()),
    }
    asupersync_outcome(transaction.rollback(cx).await, "rollback conflict case")?;
    let visible_labels = collect_asupersync_labels(&connection, cx).await?;
    prove_asupersync_connection_reusable(&connection, cx).await?;
    asupersync_close(&connection, cx).await?;
    Ok(TransactionCaseResult {
        case_id,
        terminal_state: "constraint_rejected_then_recovered",
        visible_labels,
        conflict_class: Some("constraint_violation"),
        connection_reusable: true,
        open_transactions: 0,
    })
}

fn run_frankensqlite_transaction_cases(
    cases: &[TransactionCase],
) -> Result<Vec<TransactionCaseResult>, String> {
    let runtime = CompatRuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build FrankenSQLite transaction runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "FrankenSQLite transaction runtime has no blocking pool".to_owned())?;
    let results = runtime.block_on(async {
        let native_cx = CompatCx::current().ok_or_else(|| {
            "FrankenSQLite transaction runtime did not install native Cx".to_owned()
        })?;
        let cx = attached_franken_cx(&native_cx);
        let mut results = Vec::with_capacity(cases.len());
        for case in cases {
            results.push(run_frankensqlite_transaction_case(*case, &cx).await?);
        }
        Ok::<_, String>(results)
    })?;
    drop(runtime);
    require_compat_runtime_quiescence(&blocking, "FrankenSQLite transaction matrix")?;
    Ok(results)
}

async fn run_frankensqlite_transaction_case(
    case: TransactionCase,
    cx: &FrankenCx,
) -> Result<TransactionCaseResult, String> {
    if matches!(case.kind, TransactionCaseKind::ConflictRecovery) {
        return run_frankensqlite_conflict_case(case.id, cx).await;
    }

    let mut connection = FrankenConnection::open(cx, ":memory:")
        .await
        .map_err(|error| format!("FrankenSQLite transaction open: {error}"))?;
    connection
        .execute_batch(
            cx,
            "CREATE TABLE p4_tx (id INTEGER PRIMARY KEY, label TEXT NOT NULL);",
        )
        .await
        .map_err(|error| format!("FrankenSQLite create transaction parity table: {error}"))?;

    let terminal_state = match case.kind {
        TransactionCaseKind::DeferredCommit => {
            connection
                .begin_transaction(cx)
                .await
                .map_err(|error| format!("FrankenSQLite begin deferred: {error}"))?;
            franken_insert_label(&connection, cx, 1, "deferred").await?;
            connection
                .commit_transaction(cx)
                .await
                .map_err(|error| format!("FrankenSQLite commit deferred: {error}"))?;
            "committed"
        }
        TransactionCaseKind::ImmediateRollback => {
            connection
                .execute(cx, "BEGIN IMMEDIATE")
                .await
                .map_err(|error| format!("FrankenSQLite begin immediate: {error}"))?;
            franken_insert_label(&connection, cx, 1, "immediate").await?;
            connection
                .execute(cx, "ROLLBACK")
                .await
                .map_err(|error| format!("FrankenSQLite rollback immediate: {error}"))?;
            "rolled_back"
        }
        TransactionCaseKind::ExclusiveCommit => {
            connection
                .execute(cx, "BEGIN EXCLUSIVE")
                .await
                .map_err(|error| format!("FrankenSQLite begin exclusive: {error}"))?;
            franken_insert_label(&connection, cx, 1, "exclusive").await?;
            connection
                .execute(cx, "COMMIT")
                .await
                .map_err(|error| format!("FrankenSQLite commit exclusive: {error}"))?;
            "committed"
        }
        TransactionCaseKind::SavepointPartialRollback => {
            connection
                .begin_transaction(cx)
                .await
                .map_err(|error| format!("FrankenSQLite begin savepoint: {error}"))?;
            franken_insert_label(&connection, cx, 1, "base").await?;
            connection
                .execute(cx, "SAVEPOINT p4_partial")
                .await
                .map_err(|error| format!("FrankenSQLite create savepoint: {error}"))?;
            franken_insert_label(&connection, cx, 2, "discarded").await?;
            connection
                .execute_batch(
                    cx,
                    "ROLLBACK TO SAVEPOINT p4_partial; RELEASE SAVEPOINT p4_partial;",
                )
                .await
                .map_err(|error| format!("FrankenSQLite rollback savepoint: {error}"))?;
            franken_insert_label(&connection, cx, 3, "after").await?;
            connection
                .commit_transaction(cx)
                .await
                .map_err(|error| format!("FrankenSQLite commit savepoint transaction: {error}"))?;
            "committed_after_savepoint_rollback"
        }
        TransactionCaseKind::ConflictRecovery => unreachable!("handled above"),
    };

    if connection.in_transaction() {
        return Err(format!(
            "FrankenSQLite {} retained an open transaction",
            case.id
        ));
    }
    let visible_labels = collect_franken_labels(&connection, cx).await?;
    prove_franken_connection_reusable(&connection, cx).await?;
    franken_close(&mut connection, cx).await?;
    Ok(TransactionCaseResult {
        case_id: case.id,
        terminal_state,
        visible_labels,
        conflict_class: None,
        connection_reusable: true,
        open_transactions: 0,
    })
}

async fn franken_insert_label(
    connection: &FrankenConnection,
    cx: &FrankenCx,
    id: i64,
    label: &str,
) -> Result<(), String> {
    let affected = connection
        .execute_with_params(
            cx,
            "INSERT INTO p4_tx (id, label) VALUES (?1, ?2)",
            &[FrankenValue::Integer(id), FrankenValue::Text(label.into())],
        )
        .await
        .map_err(|error| format!("FrankenSQLite insert transaction parity row: {error}"))?;
    if affected != 1 {
        return Err(format!(
            "FrankenSQLite transaction insert affected {affected} rows"
        ));
    }
    Ok(())
}

async fn collect_franken_labels(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<Vec<String>, String> {
    let rows = connection
        .query(cx, "SELECT label FROM p4_tx ORDER BY id")
        .await
        .map_err(|error| format!("FrankenSQLite query transaction parity labels: {error}"))?;
    rows.iter()
        .map(|row| match row.get(0) {
            Some(FrankenValue::Text(label)) => Ok(label.to_string()),
            other => Err(format!(
                "FrankenSQLite transaction label was not text: {other:?}"
            )),
        })
        .collect()
}

async fn prove_franken_connection_reusable(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<(), String> {
    connection
        .begin_transaction(cx)
        .await
        .map_err(|error| format!("FrankenSQLite begin reuse probe: {error}"))?;
    connection
        .rollback_transaction(cx)
        .await
        .map_err(|error| format!("FrankenSQLite rollback reuse probe: {error}"))?;
    if connection.in_transaction() {
        return Err("FrankenSQLite reuse probe retained an open transaction".to_owned());
    }
    Ok(())
}

async fn run_frankensqlite_conflict_case(
    case_id: &'static str,
    cx: &FrankenCx,
) -> Result<TransactionCaseResult, String> {
    let mut connection = FrankenConnection::open(cx, ":memory:")
        .await
        .map_err(|error| format!("FrankenSQLite conflict-case open: {error}"))?;
    connection
        .execute_batch(
            cx,
            "CREATE TABLE p4_tx (id INTEGER PRIMARY KEY, label TEXT NOT NULL);",
        )
        .await
        .map_err(|error| format!("FrankenSQLite create constraint-conflict table: {error}"))?;
    connection
        .begin_transaction(cx)
        .await
        .map_err(|error| format!("FrankenSQLite begin conflict case: {error}"))?;
    franken_insert_label(&connection, cx, 1, "first").await?;
    match connection
        .execute_with_params(
            cx,
            "INSERT INTO p4_tx (id, label) VALUES (?1, ?2)",
            &[
                FrankenValue::Integer(1),
                FrankenValue::Text("duplicate".into()),
            ],
        )
        .await
    {
        Err(error) if is_franken_constraint_conflict(&error) => {}
        Err(error) => {
            return Err(format!(
                "FrankenSQLite duplicate key returned non-constraint error: {error}"
            ));
        }
        Ok(_) => {
            return Err("FrankenSQLite duplicate key unexpectedly succeeded".to_owned());
        }
    }
    connection
        .rollback_transaction(cx)
        .await
        .map_err(|error| format!("FrankenSQLite rollback conflict case: {error}"))?;
    let visible_labels = collect_franken_labels(&connection, cx).await?;
    prove_franken_connection_reusable(&connection, cx).await?;
    franken_close(&mut connection, cx).await?;
    Ok(TransactionCaseResult {
        case_id,
        terminal_state: "constraint_rejected_then_recovered",
        visible_labels,
        conflict_class: Some("constraint_violation"),
        connection_reusable: true,
        open_transactions: 0,
    })
}

fn is_franken_constraint_conflict(error: &FrankenError) -> bool {
    matches!(
        error,
        FrankenError::UniqueViolation { .. } | FrankenError::PrimaryKeyViolation
    )
}

fn security_cases() -> Vec<SecurityCase> {
    vec![
        SecurityCase {
            id: "SQLITE-PARITY-P7-ALLOW-SELECT-001",
            sql: "SELECT 1 AS value".to_owned(),
            expected: "allowed",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-ALLOW-QUOTED-CONTROL-WORDS-002",
            sql: "SELECT 'ATTACH PRAGMA VACUUM load_extension(' AS inert_text".to_owned(),
            expected: "allowed",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-ALLOW-UNICODE-DATA-003",
            sql: "SELECT 'Δatabase-\u{2019}-\u{200b}' AS unicode_text".to_owned(),
            expected: "allowed",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-MULTI-STATEMENT-004",
            sql: "SELECT 1; ATTACH ':memory:' AS tenant".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-COMMENT-PRAGMA-005",
            sql: "/* looks harmless */ PRAGMA writable_schema=ON".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-ATTACH-006",
            sql: "ATTACH '/tmp/tenant.db' AS tenant".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-DETACH-007",
            sql: "DETACH DATABASE tenant".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-VACUUM-INTO-008",
            sql: "VACUUM INTO '/tmp/export.db'".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-TRANSACTION-CONTROL-009",
            sql: "BEGIN IMMEDIATE".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-EXTENSION-LOADING-010",
            sql: "SELECT load_extension('/tmp/evil.so')".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-MALFORMED-011",
            sql: "SELECT FROM".to_owned(),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-OVERSIZED-012",
            sql: format!("SELECT '{}'", "x".repeat(1024 * 1024)),
            expected: "rejected_unsafe_sql",
        },
        SecurityCase {
            id: "SQLITE-PARITY-P7-DENY-RECURSION-013",
            sql: format!("SELECT {}1{}", "(".repeat(140), ")".repeat(140)),
            expected: "rejected_unsafe_sql",
        },
    ]
}

fn run_security_policy() -> Result<SecurityPolicyEvidence, String> {
    let cases = security_cases();
    let mut ids = BTreeSet::new();
    if cases.iter().any(|case| !ids.insert(case.id)) {
        return Err("duplicate SQLite P7 security case id".to_owned());
    }

    let asupersync = run_asupersync_security_cases(&cases)?;
    let frankensqlite_adapter = run_frankensqlite_security_cases(&cases)?;
    for ((case, native), franken) in cases.iter().zip(&asupersync).zip(&frankensqlite_adapter) {
        if native.decision != case.expected
            || franken.decision != case.expected
            || native != franken
        {
            return Err(format!(
                "SQLite P7 policy mismatch for {}: expected {}, asupersync {}, FrankenSQLite adapter {}",
                case.id, case.expected, native.decision, franken.decision
            ));
        }
    }

    Ok(SecurityPolicyEvidence {
        policy_id: "sqlite-checked-sql-policy-v1",
        status: "PASS",
        bounded_cases: cases.len(),
        asupersync,
        frankensqlite_adapter,
    })
}

fn run_asupersync_security_cases(
    cases: &[SecurityCase],
) -> Result<Vec<SecurityCaseResult>, String> {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build Asupersync P7 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "Asupersync P7 runtime has no blocking pool".to_owned())?;
    let results = runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "Asupersync P7 runtime has no Cx".to_owned())?;
        let connection = asupersync_open_memory(&cx).await?;
        let mut results = Vec::with_capacity(cases.len());
        for case in cases {
            let decision = match connection.query_row(&cx, &case.sql, &[]).await {
                Outcome::Ok(Some(_)) => "allowed",
                Outcome::Err(SqliteError::UnsafeSql(_)) => "rejected_unsafe_sql",
                Outcome::Ok(None) => {
                    return Err(format!("Asupersync P7 case {} returned no row", case.id));
                }
                Outcome::Err(error) => {
                    return Err(format!(
                        "Asupersync P7 case {} escaped policy as engine error: {error}",
                        case.id
                    ));
                }
                Outcome::Cancelled(_) => {
                    return Err(format!("Asupersync P7 case {} was cancelled", case.id));
                }
                Outcome::Panicked(_) => {
                    return Err(format!("Asupersync P7 case {} panicked", case.id));
                }
            };
            results.push(SecurityCaseResult {
                id: case.id,
                decision,
            });
        }
        asupersync_close(&connection, &cx).await?;
        Ok(results)
    })?;
    drop(runtime);
    require_runtime_quiescence(&blocking, "asupersync-p7")?;
    Ok(results)
}

fn run_frankensqlite_security_cases(
    cases: &[SecurityCase],
) -> Result<Vec<SecurityCaseResult>, String> {
    let runtime = CompatRuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build FrankenSQLite P7 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "FrankenSQLite P7 runtime has no blocking pool".to_owned())?;
    let results = runtime.block_on(async {
        let native_cx = CompatCx::current()
            .ok_or_else(|| "FrankenSQLite P7 compatibility runtime has no Cx".to_owned())?;
        let local_cx = attached_franken_cx(&native_cx);
        let mut connection = FrankenConnection::open(&local_cx, ":memory:")
            .await
            .map_err(|error| format!("FrankenSQLite P7 open: {error}"))?;
        let mut results = Vec::with_capacity(cases.len());
        for case in cases {
            let decision = match validate_checked_sql_statement(&case.sql) {
                Err(SqliteError::UnsafeSql(_)) => "rejected_unsafe_sql",
                Err(error) => {
                    return Err(format!(
                        "FrankenSQLite adapter P7 case {} policy error: {error}",
                        case.id
                    ));
                }
                Ok(()) => match connection.query(&local_cx, &case.sql).await {
                    Ok(rows) if !rows.is_empty() => "allowed",
                    Ok(_) => {
                        return Err(format!(
                            "FrankenSQLite adapter P7 case {} returned no row",
                            case.id
                        ));
                    }
                    Err(error) => {
                        return Err(format!(
                            "FrankenSQLite adapter P7 case {} escaped policy as engine error: {error}",
                            case.id
                        ));
                    }
                },
            };
            results.push(SecurityCaseResult {
                id: case.id,
                decision,
            });
        }
        franken_close(&mut connection, &local_cx).await?;
        Ok(results)
    })?;
    drop(runtime);
    require_compat_runtime_quiescence(&blocking, "frankensqlite-p7")?;
    Ok(results)
}

fn run_error_parity(
    prepared: &PreparedStatementParityEvidence,
) -> Result<ErrorParityEvidence, String> {
    let asupersync_busy = prepared
        .asupersync
        .cases
        .iter()
        .find(|case| case.case_id == "SQLITE-PARITY-P3-BUSY-008")
        .ok_or_else(|| "P8 could not find Asupersync's executed busy case".to_owned())?;
    let frankensqlite_busy = prepared
        .frankensqlite
        .cases
        .iter()
        .find(|case| case.case_id == "SQLITE-PARITY-P3-BUSY-008")
        .ok_or_else(|| "P8 could not find FrankenSQLite's executed busy case".to_owned())?;
    if asupersync_busy.error_class != Some("busy_or_locked") || !asupersync_busy.connection_reusable
    {
        return Err(format!(
            "P8 inherited Asupersync busy evidence is not typed and reusable: {asupersync_busy:?}"
        ));
    }
    if !((frankensqlite_busy.error_class == Some("busy_or_locked")
        && frankensqlite_busy.connection_reusable)
        || (frankensqlite_busy.error_class == Some("watchdog_timeout")
            && !frankensqlite_busy.connection_reusable))
    {
        return Err(format!(
            "P8 inherited FrankenSQLite busy evidence is neither typed-and-reusable nor a bounded watchdog refusal: {frankensqlite_busy:?}"
        ));
    }

    let asupersync = run_asupersync_error_matrix()?;
    let frankensqlite = run_frankensqlite_error_matrix()?;
    let mut mismatches = Vec::new();
    for case_id in [
        "SQLITE-PARITY-P8-PREPARE-001",
        "SQLITE-PARITY-P8-CONSTRAINT-002",
    ] {
        let native = find_error_case(&asupersync.cases, case_id)?;
        let franken = find_error_case(&frankensqlite.cases, case_id)?;
        if native.operation != franken.operation
            || native.category != franken.category
            || native.primary_code != franken.primary_code
            || native.retry != franken.retry
        {
            mismatches.push(format!(
                "{case_id}: asupersync=({},{},{:?},{}) frankensqlite=({},{},{:?},{})",
                native.operation,
                native.category,
                native.primary_code,
                native.retry,
                franken.operation,
                franken.category,
                franken.primary_code,
                franken.retry
            ));
        }
    }
    if !mismatches.is_empty() {
        return Err(format!(
            "SQLite P8 stable error parity failed: {}",
            mismatches.join("; ")
        ));
    }

    Ok(ErrorParityEvidence {
        bead_id: "asupersync-ym2wtv.2.8",
        matrix_id: "sqlite-neutral-stable-error-and-quiescence-v1",
        status: "PASS_BOUNDED_STABLE_CODES_CANCELLATION_DISTINCTION_AND_RUNTIME_QUIESCENCE",
        compared_cases: 2,
        asupersync,
        frankensqlite,
        mismatches,
        intentional_differences: vec![
            ErrorDifferenceEvidence {
                case_id: "SQLITE-PARITY-P8-CANCEL-003",
                boundary: "public_cancellation_delivery",
                asupersync: "outer Outcome::Cancelled with no engine error",
                frankensqlite: "typed FrankenError::Interrupt",
                rationale: "The engines expose different async result lattices; normalization preserves the distinction instead of converting caller cancellation into a retryable database failure.",
            },
            ErrorDifferenceEvidence {
                case_id: "SQLITE-PARITY-P3-BUSY-008",
                boundary: "busy-lock-completion",
                asupersync: "typed busy_or_locked and connection reusable",
                frankensqlite: "typed busy_or_locked and reusable, or bounded watchdog refusal with the connection quarantined",
                rationale: "P8 inherits the already-executed P3 lock row without misrepresenting a bounded FrankenSQLite non-return as successful connection reuse.",
            },
        ],
        inherited_busy_case: "SQLITE-PARITY-P3-BUSY-008_EXECUTED_WITH_TYPED_ASUPERSYNC_RECOVERY_AND_BOUNDED_FRANKENSQLITE_WATCHDOG",
    })
}

fn find_error_case<'a>(
    cases: &'a [ErrorCaseResult],
    case_id: &str,
) -> Result<&'a ErrorCaseResult, String> {
    cases
        .iter()
        .find(|case| case.case_id == case_id)
        .ok_or_else(|| format!("missing SQLite P8 error case {case_id}"))
}

fn run_asupersync_error_matrix() -> Result<ErrorEngineEvidence, String> {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build Asupersync P8 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "Asupersync P8 runtime has no blocking pool".to_owned())?;
    let cases = runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "Asupersync P8 runtime has no Cx".to_owned())?;
        let connection = match SqliteConnection::open_in_memory_diagnosed(&cx).await {
            Outcome::Ok(connection) => connection,
            Outcome::Err(error) => return Err(format!("Asupersync P8 open: {error}")),
            Outcome::Cancelled(_) => return Err("Asupersync P8 open was cancelled".to_owned()),
            Outcome::Panicked(_) => return Err("Asupersync P8 open panicked".to_owned()),
        };
        diagnosed_outcome(
            connection
                .execute_batch_diagnosed(
                    &cx,
                    "CREATE TABLE p8_sensitive_error_table (id INTEGER PRIMARY KEY, value TEXT UNIQUE NOT NULL);",
                )
                .await,
            "create Asupersync P8 table",
        )?;
        diagnosed_outcome(
            connection
                .execute_diagnosed(
                    &cx,
                    "INSERT INTO p8_sensitive_error_table(id, value) VALUES (?1, ?2)",
                    &[
                        AsupersyncValue::Integer(1),
                        AsupersyncValue::Text("first".to_owned()),
                    ],
                )
                .await,
            "seed Asupersync P8 table",
        )?;

        let prepare = match connection
            .query_unchecked_diagnosed(&cx, "SELEKT p8_sensitive_payload", &[])
            .await
        {
            Outcome::Err(error) => asupersync_error_case(
                "SQLITE-PARITY-P8-PREPARE-001",
                &error,
                &["SELEKT", "p8_sensitive_payload"],
            ),
            other => return Err(outcome_drift("Asupersync P8 prepare", other)),
        };
        let constraint = match connection
            .execute_diagnosed(
                &cx,
                "INSERT INTO p8_sensitive_error_table(id, value) VALUES (?1, ?2)",
                &[
                    AsupersyncValue::Integer(2),
                    AsupersyncValue::Text("first".to_owned()),
                ],
            )
            .await
        {
            Outcome::Err(error) => asupersync_error_case(
                "SQLITE-PARITY-P8-CONSTRAINT-002",
                &error,
                &["p8_sensitive_error_table", "value"],
            ),
            other => return Err(outcome_drift("Asupersync P8 constraint", other)),
        };

        cx.set_cancel_requested(true);
        let cancelled = connection
            .execute_diagnosed(
                &cx,
                "INSERT INTO p8_sensitive_error_table(id, value) VALUES (?1, ?2)",
                &[
                    AsupersyncValue::Integer(3),
                    AsupersyncValue::Text("must_not_commit".to_owned()),
                ],
            )
            .await;
        cx.set_cancel_requested(false);
        let cancel = match cancelled {
            Outcome::Cancelled(_) => ErrorCaseResult {
                case_id: "SQLITE-PARITY-P8-CANCEL-003",
                operation: "step",
                category: "cancelled",
                primary_code: None,
                extended_code: None,
                retry: "never",
                cancellation_delivery: "outer_outcome_cancelled",
                source_preserved: false,
                stable_evidence_redacted: true,
            },
            other => return Err(outcome_drift("Asupersync P8 cancellation", other)),
        };
        let cancelled_count = diagnosed_outcome(
            connection
                .query_row_diagnosed(
                    &cx,
                    "SELECT COUNT(*) AS count FROM p8_sensitive_error_table WHERE id = ?1",
                    &[AsupersyncValue::Integer(3)],
                )
                .await,
            "verify Asupersync P8 cancellation",
        )?
        .ok_or_else(|| "Asupersync P8 cancellation count returned no row".to_owned())?
        .get_i64("count")
        .map_err(|error| format!("read Asupersync P8 cancellation count: {error}"))?;
        if cancelled_count != 0 {
            return Err(format!(
                "Asupersync P8 cancelled operation mutated {cancelled_count} rows"
            ));
        }
        diagnosed_outcome(
            connection.query_unchecked_diagnosed(&cx, "SELECT 1", &[]).await,
            "reuse Asupersync P8 connection",
        )?;
        diagnosed_outcome(
            connection.close_async_diagnosed(&cx).await,
            "close Asupersync P8 connection",
        )?;
        let closed = match connection
            .query_unchecked_diagnosed(&cx, "SELECT 1", &[])
            .await
        {
            Outcome::Err(error) => asupersync_error_case(
                "SQLITE-PARITY-P8-CLOSED-004",
                &error,
                &[],
            ),
            other => return Err(outcome_drift("Asupersync P8 closed connection", other)),
        };
        Ok::<_, String>(vec![prepare, constraint, cancel, closed])
    })?;
    drop(runtime);
    require_runtime_quiescence(&blocking, "asupersync-p8")?;
    Ok(ErrorEngineEvidence {
        cases,
        connection_reusable: true,
        connection_closed: true,
        open_transactions: 0,
        live_statements: 0,
        live_connections: 0,
        runtime_quiescent: true,
        blocking_pending: blocking.pending_count() as u64,
        blocking_busy: blocking.busy_threads() as u64,
        blocking_active: blocking.active_threads() as u64,
    })
}

fn run_frankensqlite_error_matrix() -> Result<ErrorEngineEvidence, String> {
    let runtime = CompatRuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build FrankenSQLite P8 runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "FrankenSQLite P8 runtime has no blocking pool".to_owned())?;
    let cases = runtime.block_on(async {
        let native_cx = CompatCx::current()
            .ok_or_else(|| "FrankenSQLite P8 compatibility runtime has no Cx".to_owned())?;
        let cx = attached_franken_cx(&native_cx);
        let mut connection = FrankenConnection::open(&cx, ":memory:")
            .await
            .map_err(|error| format!("FrankenSQLite P8 open: {error}"))?;
        connection
            .execute_batch(
                &cx,
                "CREATE TABLE p8_sensitive_error_table (id INTEGER PRIMARY KEY, value TEXT UNIQUE NOT NULL);",
            )
            .await
            .map_err(|error| format!("FrankenSQLite P8 schema: {error}"))?;
        connection
            .execute_with_params(
                &cx,
                "INSERT INTO p8_sensitive_error_table(id, value) VALUES (?1, ?2)",
                &[
                    FrankenValue::Integer(1),
                    FrankenValue::Text("first".into()),
                ],
            )
            .await
            .map_err(|error| format!("FrankenSQLite P8 seed: {error}"))?;

        let prepare_error = connection
            .query(&cx, "SELEKT p8_sensitive_payload")
            .await
            .expect_err("FrankenSQLite P8 malformed query must fail");
        let prepare = frankensqlite_error_case(
            "SQLITE-PARITY-P8-PREPARE-001",
            "prepare",
            &prepare_error,
            "not_cancelled",
            &["SELEKT", "p8_sensitive_payload"],
        );
        let constraint_error = connection
            .execute_with_params(
                &cx,
                "INSERT INTO p8_sensitive_error_table(id, value) VALUES (?1, ?2)",
                &[
                    FrankenValue::Integer(2),
                    FrankenValue::Text("first".into()),
                ],
            )
            .await
            .expect_err("FrankenSQLite P8 duplicate must fail");
        let constraint = frankensqlite_error_case(
            "SQLITE-PARITY-P8-CONSTRAINT-002",
            "step",
            &constraint_error,
            "not_cancelled",
            &["p8_sensitive_error_table", "value"],
        );

        native_cx.set_cancel_requested(true);
        let cancelled_cx = attached_franken_cx(&native_cx);
        let cancelled = connection
            .execute_with_params(
                &cancelled_cx,
                "INSERT INTO p8_sensitive_error_table(id, value) VALUES (?1, ?2)",
                &[
                    FrankenValue::Integer(3),
                    FrankenValue::Text("must_not_commit".into()),
                ],
            )
            .await;
        native_cx.set_cancel_requested(false);
        let cancel_error = cancelled
            .expect_err("FrankenSQLite P8 pre-cancelled operation must return an error");
        if !matches!(cancel_error, FrankenError::Interrupt) {
            return Err(format!(
                "FrankenSQLite P8 cancellation was not a typed interrupt: {cancel_error:?}"
            ));
        }
        let cancel = frankensqlite_error_case(
            "SQLITE-PARITY-P8-CANCEL-003",
            "step",
            &cancel_error,
            "engine_interrupt_error",
            &[],
        );
        let cancelled_count = connection
            .query_row(
                &cx,
                "SELECT COUNT(*) FROM p8_sensitive_error_table WHERE id = 3",
            )
            .await
            .map_err(|error| format!("FrankenSQLite P8 cancellation count: {error}"))?;
        if !matches!(cancelled_count.get(0), Some(FrankenValue::Integer(0))) {
            return Err(format!(
                "FrankenSQLite P8 cancelled operation mutated state: {cancelled_count:?}"
            ));
        }
        connection
            .query(&cx, "SELECT 1")
            .await
            .map_err(|error| format!("FrankenSQLite P8 reuse: {error}"))?;
        connection
            .close(&cx)
            .await
            .map_err(|error| format!("FrankenSQLite P8 close: {error}"))?;
        let closed_error = connection
            .query(&cx, "SELECT 1")
            .await
            .expect_err("FrankenSQLite P8 closed connection must reject query");
        let closed = frankensqlite_error_case(
            "SQLITE-PARITY-P8-CLOSED-004",
            "step",
            &closed_error,
            "not_cancelled",
            &[],
        );
        Ok::<_, String>(vec![prepare, constraint, cancel, closed])
    })?;
    drop(runtime);
    require_compat_runtime_quiescence(&blocking, "frankensqlite-p8")?;
    Ok(ErrorEngineEvidence {
        cases,
        connection_reusable: true,
        connection_closed: true,
        open_transactions: 0,
        live_statements: 0,
        live_connections: 0,
        runtime_quiescent: true,
        blocking_pending: blocking.pending_count() as u64,
        blocking_busy: blocking.busy_threads() as u64,
        blocking_active: blocking.active_threads() as u64,
    })
}

fn asupersync_error_case(
    case_id: &'static str,
    error: &SqliteOperationError,
    sensitive_markers: &[&str],
) -> ErrorCaseResult {
    let diagnostic = error.diagnostic();
    let rendered = format!("{error:?} {error}");
    ErrorCaseResult {
        case_id,
        operation: asupersync_operation(diagnostic.operation()),
        category: asupersync_error_category(diagnostic.category()),
        primary_code: diagnostic.primary_code(),
        extended_code: diagnostic.extended_code(),
        retry: asupersync_retry_disposition(diagnostic.retry_disposition()),
        cancellation_delivery: "not_cancelled",
        source_preserved: error.engine_source().is_some(),
        stable_evidence_redacted: sensitive_markers
            .iter()
            .all(|marker| !rendered.contains(marker)),
    }
}

fn asupersync_operation(operation: asupersync::database::sqlite::SqliteOperation) -> &'static str {
    match operation {
        asupersync::database::sqlite::SqliteOperation::Open => "open",
        asupersync::database::sqlite::SqliteOperation::Prepare => "prepare",
        asupersync::database::sqlite::SqliteOperation::Bind => "bind",
        asupersync::database::sqlite::SqliteOperation::Step => "step",
        asupersync::database::sqlite::SqliteOperation::ExecuteBatch => "execute_batch",
        asupersync::database::sqlite::SqliteOperation::TransactionBegin => "transaction_begin",
        asupersync::database::sqlite::SqliteOperation::TransactionCommit => "transaction_commit",
        asupersync::database::sqlite::SqliteOperation::TransactionRollback => {
            "transaction_rollback"
        }
        asupersync::database::sqlite::SqliteOperation::Configure => "configure",
        asupersync::database::sqlite::SqliteOperation::Close => "close",
        asupersync::database::sqlite::SqliteOperation::BlockingPool => "blocking_pool",
        asupersync::database::sqlite::SqliteOperation::Validation => "validation",
        _ => "unknown_future_operation",
    }
}

fn asupersync_error_category(category: SqliteErrorCategory) -> &'static str {
    match category {
        SqliteErrorCategory::Busy => "busy",
        SqliteErrorCategory::Locked => "locked",
        SqliteErrorCategory::Constraint => "constraint",
        SqliteErrorCategory::Interrupted => "interrupted",
        SqliteErrorCategory::Timeout => "timeout",
        SqliteErrorCategory::PermissionDenied => "permission_denied",
        SqliteErrorCategory::ReadOnly => "read_only",
        SqliteErrorCategory::Io => "io",
        SqliteErrorCategory::Corrupt => "corrupt",
        SqliteErrorCategory::ResourceExhausted => "resource_exhausted",
        SqliteErrorCategory::InvalidInput => "invalid_input",
        SqliteErrorCategory::NotFound => "not_found",
        SqliteErrorCategory::Closed => "closed",
        SqliteErrorCategory::Cancelled => "cancelled",
        SqliteErrorCategory::Internal => "internal",
        SqliteErrorCategory::Unknown => "unknown",
        _ => "unknown_future_category",
    }
}

fn asupersync_retry_disposition(retry: SqliteRetryDisposition) -> &'static str {
    match retry {
        SqliteRetryDisposition::Never => "never",
        SqliteRetryDisposition::RetryOperation => "retry_operation",
        SqliteRetryDisposition::ReopenConnection => "reopen_connection",
        _ => "unknown_future_disposition",
    }
}

fn frankensqlite_error_case(
    case_id: &'static str,
    operation: &'static str,
    error: &FrankenError,
    cancellation_delivery: &'static str,
    sensitive_markers: &[&str],
) -> ErrorCaseResult {
    let primary_code = error.error_code() as i32;
    let rendered = format!("{error:?} {error}");
    ErrorCaseResult {
        case_id,
        operation,
        category: sqlite_primary_category(primary_code, operation),
        primary_code: sqlite_primary_code_name(primary_code),
        extended_code: Some(error.extended_error_code()),
        retry: sqlite_primary_retry(primary_code),
        cancellation_delivery,
        source_preserved: true,
        stable_evidence_redacted: sensitive_markers
            .iter()
            .all(|marker| !rendered.contains(marker)),
    }
}

fn sqlite_primary_code_name(primary_code: i32) -> Option<&'static str> {
    match primary_code {
        1 => Some("SQLITE_ERROR"),
        2 => Some("SQLITE_INTERNAL"),
        3 => Some("SQLITE_PERM"),
        4 => Some("SQLITE_ABORT"),
        5 => Some("SQLITE_BUSY"),
        6 => Some("SQLITE_LOCKED"),
        7 => Some("SQLITE_NOMEM"),
        8 => Some("SQLITE_READONLY"),
        9 => Some("SQLITE_INTERRUPT"),
        10 => Some("SQLITE_IOERR"),
        11 => Some("SQLITE_CORRUPT"),
        12 => Some("SQLITE_NOTFOUND"),
        13 => Some("SQLITE_FULL"),
        14 => Some("SQLITE_CANTOPEN"),
        15 => Some("SQLITE_PROTOCOL"),
        17 => Some("SQLITE_SCHEMA"),
        18 => Some("SQLITE_TOOBIG"),
        19 => Some("SQLITE_CONSTRAINT"),
        20 => Some("SQLITE_MISMATCH"),
        21 => Some("SQLITE_MISUSE"),
        22 => Some("SQLITE_NOLFS"),
        23 => Some("SQLITE_AUTH"),
        25 => Some("SQLITE_RANGE"),
        26 => Some("SQLITE_NOTADB"),
        _ => None,
    }
}

fn sqlite_primary_category(primary_code: i32, operation: &str) -> &'static str {
    match primary_code {
        1 if matches!(operation, "prepare" | "bind") => "invalid_input",
        3 | 23 => "permission_denied",
        5 => "busy",
        6 => "locked",
        7 | 13 | 18 => "resource_exhausted",
        8 => "read_only",
        9 => "interrupted",
        10 | 14 | 15 => "io",
        11 | 26 => "corrupt",
        12 => "not_found",
        19 => "constraint",
        20 | 25 => "invalid_input",
        2 | 4 | 17 | 21 | 22 => "internal",
        _ => "unknown",
    }
}

fn sqlite_primary_retry(primary_code: i32) -> &'static str {
    match primary_code {
        5 | 6 | 17 => "retry_operation",
        10 | 11 | 14 | 15 | 26 => "reopen_connection",
        _ => "never",
    }
}

fn diagnosed_outcome<T>(
    outcome: Outcome<T, SqliteOperationError>,
    operation: &str,
) -> Result<T, String> {
    match outcome {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(error) => Err(format!("{operation}: {error}")),
        Outcome::Cancelled(_) => Err(format!("{operation} was cancelled")),
        Outcome::Panicked(_) => Err(format!("{operation} panicked")),
    }
}

fn outcome_drift<T>(operation: &str, outcome: Outcome<T, SqliteOperationError>) -> String {
    match outcome {
        Outcome::Ok(_) => format!("{operation} unexpectedly succeeded"),
        Outcome::Err(error) => format!("{operation} returned unexpected error: {error}"),
        Outcome::Cancelled(_) => format!("{operation} was unexpectedly cancelled"),
        Outcome::Panicked(_) => format!("{operation} panicked"),
    }
}

fn validate_suite(suite: &VectorSuite) -> Result<(), String> {
    if suite.schema_version != 2 {
        return Err(format!(
            "unsupported vector schema version {}",
            suite.schema_version
        ));
    }
    if suite.suite_id.is_empty() || suite.capability_id != "CAP-SQLITE" {
        return Err("suite identity or capability is invalid".to_owned());
    }
    for value in [
        &suite.normalization.integer,
        &suite.normalization.real,
        &suite.normalization.text,
        &suite.normalization.blob,
        &suite.normalization.null,
        &suite.normalization.error,
        &suite.normalization.column_order,
        &suite.normalization.row_order,
        &suite.normalization.pool,
        &suite.normalization.quiescence,
    ] {
        if value.is_empty() {
            return Err("normalization fields must be non-empty".to_owned());
        }
    }
    if suite.vectors.is_empty() {
        return Err("at least one vector is required".to_owned());
    }

    let mut vector_ids = BTreeSet::new();
    for vector in &suite.vectors {
        if !vector_ids.insert(&vector.id) {
            return Err(format!("duplicate vector id {}", vector.id));
        }
        if vector.family.is_empty() || vector.description.is_empty() {
            return Err(format!("vector {} has incomplete metadata", vector.id));
        }
        validate_outcome(&vector.expected)?;
        if !matches!(
            vector.expected.resource_state.connection.as_str(),
            "closed" | "not_opened"
        ) || vector.expected.resource_state.open_transactions != 0
            || vector.expected.resource_state.admission_waiters != 0
            || vector.expected.resource_state.blocking_pending != 0
            || vector.expected.resource_state.blocking_busy != 0
            || vector.expected.resource_state.blocking_active != 0
            || vector.expected.resource_state.region_state != "closed"
        {
            return Err(format!(
                "vector {} must finish closed/not-opened and fully quiescent",
                vector.id
            ));
        }
        match &vector.scenario {
            Scenario::InMemoryConfiguration { busy_timeout_ms }
                if *busy_timeout_ms > 0 && vector.unsupported.is_empty() => {}
            Scenario::AdmissionExhaustion { capacity }
                if *capacity == 1 && vector.unsupported.is_empty() => {}
            Scenario::UriFilenameUnsupported if vector.unsupported.len() == 2 => {}
            Scenario::FilePathRoundTrip
            | Scenario::MissingParentPath
            | Scenario::PreCancelledOpen
                if vector.unsupported.is_empty() => {}
            _ => {
                return Err(format!(
                    "vector {} has invalid scenario parameters",
                    vector.id
                ));
            }
        }
        for unsupported in &vector.unsupported {
            if !matches!(unsupported.engine.as_str(), "asupersync" | "frankensqlite")
                || unsupported.capability.is_empty()
                || unsupported.reason.is_empty()
            {
                return Err(format!(
                    "vector {} has malformed unsupported capability",
                    vector.id
                ));
            }
        }
    }
    Ok(())
}

fn validate_outcome(outcome: &ScenarioOutcome) -> Result<(), String> {
    match outcome.status {
        Status::Ok if outcome.error_class.is_some() => {
            Err("successful outcomes cannot carry an error class".to_owned())
        }
        Status::Error | Status::Cancelled | Status::Unsupported
            if outcome
                .error_class
                .as_deref()
                .unwrap_or_default()
                .is_empty() =>
        {
            Err("non-success outcomes require a stable error class".to_owned())
        }
        _ => Ok(()),
    }
}

fn run_asupersync(vector: &Vector) -> Result<VectorResult, String> {
    let runtime = RuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build asupersync runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "asupersync parity runtime has no blocking pool".to_owned())?;
    let outcome = runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "asupersync runtime did not install Cx".to_owned())?;
        run_asupersync_scenario(vector, &cx).await
    })?;
    drop(runtime);
    let outcome = finalize_runtime_quiescence(outcome, &blocking, "asupersync")?;
    Ok(VectorResult {
        vector_id: vector.id.clone(),
        outcome,
        unsupported: unsupported_for_engine(vector, "asupersync"),
    })
}

async fn run_asupersync_scenario(vector: &Vector, cx: &Cx) -> Result<ScenarioOutcome, String> {
    match &vector.scenario {
        Scenario::InMemoryConfiguration { busy_timeout_ms } => {
            let connection = asupersync_open_memory(cx).await?;
            configure_and_probe_asupersync(&connection, cx, *busy_timeout_ms).await?;
            asupersync_close(&connection, cx).await?;
            Ok(success_outcome(
                "private_memory_opened",
                &format!("foreign_keys_on_busy_timeout_{busy_timeout_ms}"),
                "not_exercised",
                "not_requested",
                "explicit_close_confirmed",
                0,
                0,
            ))
        }
        Scenario::FilePathRoundTrip => {
            let path = scratch_database_path("asupersync");
            let connection = asupersync_outcome(SqliteConnection::open(cx, &path).await, "open")?;
            common_probe_asupersync(&connection, cx).await?;
            asupersync_close(&connection, cx).await?;
            Ok(success_outcome(
                "file_path_opened",
                "common_defaults_accepted",
                "not_exercised",
                "not_requested",
                "explicit_close_confirmed",
                0,
                0,
            ))
        }
        Scenario::MissingParentPath => {
            let path = missing_parent_database_path("asupersync");
            match SqliteConnection::open(cx, &path).await {
                Outcome::Err(_) => {}
                Outcome::Ok(connection) => {
                    let _ = connection.close_async(cx).await;
                    return Err(format!(
                        "asupersync unexpectedly opened missing-parent path {}",
                        path.display()
                    ));
                }
                Outcome::Cancelled(_) => {
                    return Err(
                        "asupersync missing-parent open was cancelled, not rejected".to_owned()
                    );
                }
                Outcome::Panicked(_) => {
                    return Err("asupersync missing-parent open panicked".to_owned());
                }
            }
            Ok(non_success_outcome(
                Status::Error,
                "open_rejected",
                "rejected",
                "not_started",
                "not_exercised",
                "worker_completed",
                "not_requested",
                "not_opened",
            ))
        }
        Scenario::PreCancelledOpen => {
            cx.set_cancel_requested(true);
            let open_result = SqliteConnection::open_in_memory(cx).await;
            cx.set_cancel_requested(false);
            match open_result {
                Outcome::Cancelled(_) => {}
                Outcome::Ok(connection) => {
                    drop(connection);
                    return Err("asupersync opened after pre-cancellation".to_owned());
                }
                Outcome::Err(_) => {
                    return Err("asupersync pre-cancelled open mapped to error".to_owned());
                }
                Outcome::Panicked(_) => {
                    return Err("asupersync pre-cancelled open panicked".to_owned());
                }
            }
            Ok(non_success_outcome(
                Status::Cancelled,
                "cancelled",
                "cancelled_before_open",
                "not_started",
                "not_exercised",
                "not_started",
                "native_cx_observed",
                "not_opened",
            ))
        }
        Scenario::AdmissionExhaustion { capacity } => {
            let semaphore = Arc::new(Semaphore::new(*capacity));
            let holder = OwnedSemaphorePermit::acquire(Arc::clone(&semaphore), cx, 1)
                .await
                .map_err(|error| format!("asupersync acquire holder: {error}"))?;
            let connection = asupersync_open_memory(cx).await?;
            if semaphore.try_acquire(1).is_ok() {
                return Err("consumer admission pool was not saturated".to_owned());
            }
            let waiter_cx = Cx::detached_cancel_context();
            let mut waiter = std::pin::pin!(semaphore.acquire(&waiter_cx, 1));
            if !poll_once(waiter.as_mut()).is_pending()
                || semaphore.telemetry_snapshot(0x53514c32).waiter_count != 1
            {
                return Err("checkout did not register on the saturated admission queue".to_owned());
            }
            asupersync_close(&connection, cx).await?;
            if semaphore.telemetry_snapshot(0x53514c32).waiter_count != 1 {
                return Err("checkout was not in flight when connection close completed".to_owned());
            }
            waiter_cx.set_cancel_requested(true);
            match poll_once(waiter.as_mut()) {
                Poll::Ready(Err(AcquireError::Cancelled)) => {}
                other => {
                    return Err(format!(
                        "parked checkout did not drain as graceful cancellation: {other:?}"
                    ));
                }
            }
            drop(waiter);
            drop(holder);
            let telemetry = semaphore.telemetry_snapshot(0x53514c32);
            verify_admission_recovered(&telemetry, *capacity)?;
            Ok(success_outcome(
                "private_memory_opened",
                "common_defaults_accepted",
                "saturated_waiter_cancelled_and_capacity_restored",
                "checkout_cancelled_after_parked",
                "closed_with_checkout_in_flight_then_drained",
                *capacity,
                telemetry.cancellation_count,
            ))
        }
        Scenario::UriFilenameUnsupported => Ok(unsupported_outcome()),
    }
}

fn run_frankensqlite(vector: &Vector) -> Result<VectorResult, String> {
    let runtime = CompatRuntimeBuilder::current_thread()
        .blocking_threads(2, 2)
        .build()
        .map_err(|error| format!("build FrankenSQLite parity runtime: {error}"))?;
    let blocking = runtime
        .handle()
        .blocking_handle()
        .ok_or_else(|| "FrankenSQLite parity runtime has no blocking pool".to_owned())?;
    let outcome = runtime.block_on(async {
        let native_cx = CompatCx::current().ok_or_else(|| {
            "FrankenSQLite compatibility runtime did not install native Cx".to_owned()
        })?;
        run_frankensqlite_scenario(vector, &native_cx).await
    })?;
    drop(runtime);
    let outcome = finalize_compat_runtime_quiescence(outcome, &blocking, "frankensqlite")?;
    Ok(VectorResult {
        vector_id: vector.id.clone(),
        outcome,
        unsupported: unsupported_for_engine(vector, "frankensqlite"),
    })
}

async fn run_frankensqlite_scenario(
    vector: &Vector,
    native_cx: &CompatCx,
) -> Result<ScenarioOutcome, String> {
    match &vector.scenario {
        Scenario::InMemoryConfiguration { busy_timeout_ms } => {
            let local_cx = attached_franken_cx(native_cx);
            let mut connection = FrankenConnection::open(&local_cx, ":memory:")
                .await
                .map_err(|error| format!("FrankenSQLite in-memory open: {error}"))?;
            configure_and_probe_frankensqlite(&connection, &local_cx, *busy_timeout_ms).await?;
            franken_close(&mut connection, &local_cx).await?;
            Ok(success_outcome(
                "private_memory_opened",
                &format!("foreign_keys_on_busy_timeout_{busy_timeout_ms}"),
                "not_exercised",
                "not_requested",
                "explicit_close_confirmed",
                0,
                0,
            ))
        }
        Scenario::FilePathRoundTrip => {
            let local_cx = attached_franken_cx(native_cx);
            let path = scratch_database_path("frankensqlite");
            let mut connection = FrankenConnection::open(&local_cx, path_to_string(&path)?)
                .await
                .map_err(|error| format!("FrankenSQLite file-path open: {error}"))?;
            common_probe_frankensqlite(&connection, &local_cx).await?;
            franken_close(&mut connection, &local_cx).await?;
            Ok(success_outcome(
                "file_path_opened",
                "common_defaults_accepted",
                "not_exercised",
                "not_requested",
                "explicit_close_confirmed",
                0,
                0,
            ))
        }
        Scenario::MissingParentPath => {
            let local_cx = attached_franken_cx(native_cx);
            let path = missing_parent_database_path("frankensqlite");
            match FrankenConnection::open(&local_cx, path_to_string(&path)?).await {
                Err(FrankenError::Interrupt) => {
                    return Err("FrankenSQLite missing-parent open was cancelled".to_owned());
                }
                Err(_) => {}
                Ok(mut connection) => {
                    let _ = connection.close(&local_cx).await;
                    return Err(format!(
                        "FrankenSQLite unexpectedly opened missing-parent path {}",
                        path.display()
                    ));
                }
            }
            Ok(non_success_outcome(
                Status::Error,
                "open_rejected",
                "rejected",
                "not_started",
                "not_exercised",
                "worker_completed",
                "not_requested",
                "not_opened",
            ))
        }
        Scenario::PreCancelledOpen => {
            native_cx.set_cancel_requested(true);
            let local_cx = attached_franken_cx(native_cx);
            let open_result = FrankenConnection::open(&local_cx, ":memory:").await;
            native_cx.set_cancel_requested(false);
            match open_result {
                Err(FrankenError::Interrupt) => {}
                Err(_) => {
                    return Err(
                        "FrankenSQLite pre-cancelled open mapped to non-interrupt".to_owned()
                    );
                }
                Ok(connection) => {
                    drop(connection);
                    return Err("FrankenSQLite opened after native Cx cancellation".to_owned());
                }
            }
            Ok(non_success_outcome(
                Status::Cancelled,
                "cancelled",
                "cancelled_before_open",
                "not_started",
                "not_exercised",
                "not_started",
                "native_cx_observed",
                "not_opened",
            ))
        }
        Scenario::AdmissionExhaustion { capacity } => {
            let local_cx = attached_franken_cx(native_cx);
            let semaphore = Arc::new(CompatSemaphore::new(*capacity));
            let holder = CompatOwnedSemaphorePermit::acquire(Arc::clone(&semaphore), native_cx, 1)
                .await
                .map_err(|error| format!("FrankenSQLite acquire holder: {error}"))?;
            let mut connection = FrankenConnection::open(&local_cx, ":memory:")
                .await
                .map_err(|error| format!("FrankenSQLite pool scenario open: {error}"))?;
            if semaphore.try_acquire(1).is_ok() {
                return Err("consumer compatibility admission pool was not saturated".to_owned());
            }
            let waiter_cx = CompatCx::detached_cancel_context();
            let mut waiter = std::pin::pin!(semaphore.acquire(&waiter_cx, 1));
            if !poll_once(waiter.as_mut()).is_pending()
                || semaphore.telemetry_snapshot(0x53514c32).waiter_count != 1
            {
                return Err(
                    "compatibility checkout did not register on the saturated admission queue"
                        .to_owned(),
                );
            }
            franken_close(&mut connection, &local_cx).await?;
            if semaphore.telemetry_snapshot(0x53514c32).waiter_count != 1 {
                return Err(
                    "compatibility checkout was not in flight when connection close completed"
                        .to_owned(),
                );
            }
            waiter_cx.set_cancel_requested(true);
            match poll_once(waiter.as_mut()) {
                Poll::Ready(Err(CompatAcquireError::Cancelled)) => {}
                other => {
                    return Err(format!(
                        "parked compatibility checkout did not drain as graceful cancellation: {other:?}"
                    ));
                }
            }
            drop(waiter);
            drop(holder);
            let telemetry = semaphore.telemetry_snapshot(0x53514c32);
            verify_compat_admission_recovered(&telemetry, *capacity)?;
            Ok(success_outcome(
                "private_memory_opened",
                "common_defaults_accepted",
                "saturated_waiter_cancelled_and_capacity_restored",
                "checkout_cancelled_after_parked",
                "closed_with_checkout_in_flight_then_drained",
                *capacity,
                telemetry.cancellation_count,
            ))
        }
        Scenario::UriFilenameUnsupported => Ok(unsupported_outcome()),
    }
}

fn success_outcome(
    open_state: &str,
    configuration_state: &str,
    admission_state: &str,
    cancellation_state: &str,
    close_state: &str,
    admission_capacity: usize,
    admission_cancellations: u64,
) -> ScenarioOutcome {
    ScenarioOutcome {
        status: Status::Ok,
        error_class: None,
        open_state: open_state.to_owned(),
        configuration_state: configuration_state.to_owned(),
        admission_state: admission_state.to_owned(),
        blocking_bridge_state: "worker_completed".to_owned(),
        cancellation_state: cancellation_state.to_owned(),
        close_state: close_state.to_owned(),
        resource_state: ResourceState {
            connection: "closed".to_owned(),
            open_transactions: 0,
            admission_capacity: admission_capacity as u64,
            admission_available: admission_capacity as u64,
            admission_waiters: 0,
            admission_cancellations,
            blocking_pending: 0,
            blocking_busy: 0,
            blocking_active: 0,
            region_state: "closing".to_owned(),
            background_work: "adapter_work_drained".to_owned(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn non_success_outcome(
    status: Status,
    error_class: &str,
    open_state: &str,
    configuration_state: &str,
    admission_state: &str,
    blocking_bridge_state: &str,
    cancellation_state: &str,
    close_state: &str,
) -> ScenarioOutcome {
    ScenarioOutcome {
        status,
        error_class: Some(error_class.to_owned()),
        open_state: open_state.to_owned(),
        configuration_state: configuration_state.to_owned(),
        admission_state: admission_state.to_owned(),
        blocking_bridge_state: blocking_bridge_state.to_owned(),
        cancellation_state: cancellation_state.to_owned(),
        close_state: close_state.to_owned(),
        resource_state: ResourceState {
            connection: "not_opened".to_owned(),
            open_transactions: 0,
            admission_capacity: 0,
            admission_available: 0,
            admission_waiters: 0,
            admission_cancellations: 0,
            blocking_pending: 0,
            blocking_busy: 0,
            blocking_active: 0,
            region_state: "closing".to_owned(),
            background_work: "adapter_work_drained".to_owned(),
        },
    }
}

fn unsupported_outcome() -> ScenarioOutcome {
    non_success_outcome(
        Status::Unsupported,
        "unsupported_by_common_contract",
        "not_attempted",
        "not_started",
        "not_exercised",
        "not_started",
        "not_requested",
        "not_opened",
    )
}

fn require_runtime_quiescence(blocking: &BlockingPoolHandle, engine: &str) -> Result<(), String> {
    let pending = blocking.pending_count();
    let busy = blocking.busy_threads();
    let active = blocking.active_threads();
    if !blocking.is_shutdown() || pending != 0 || busy != 0 || active != 0 {
        return Err(format!(
            "{engine} runtime did not quiesce: shutdown={} pending={pending} busy={busy} active={active}",
            blocking.is_shutdown()
        ));
    }
    Ok(())
}

fn require_compat_runtime_quiescence(
    blocking: &CompatBlockingPoolHandle,
    engine: &str,
) -> Result<(), String> {
    let pending = blocking.pending_count();
    let busy = blocking.busy_threads();
    let active = blocking.active_threads();
    if !blocking.is_shutdown() || pending != 0 || busy != 0 || active != 0 {
        return Err(format!(
            "{engine} compatibility runtime did not quiesce: shutdown={} pending={pending} busy={busy} active={active}",
            blocking.is_shutdown()
        ));
    }
    Ok(())
}

fn finalize_runtime_quiescence(
    mut outcome: ScenarioOutcome,
    blocking: &BlockingPoolHandle,
    engine: &str,
) -> Result<ScenarioOutcome, String> {
    let pending = blocking.pending_count();
    let busy = blocking.busy_threads();
    let active = blocking.active_threads();
    require_runtime_quiescence(blocking, engine)?;
    outcome.resource_state.blocking_pending = pending as u64;
    outcome.resource_state.blocking_busy = busy as u64;
    outcome.resource_state.blocking_active = active as u64;
    outcome.resource_state.region_state = "closed".to_owned();
    outcome.resource_state.background_work = "none_observed_after_runtime_shutdown".to_owned();
    Ok(outcome)
}

fn finalize_compat_runtime_quiescence(
    mut outcome: ScenarioOutcome,
    blocking: &CompatBlockingPoolHandle,
    engine: &str,
) -> Result<ScenarioOutcome, String> {
    let pending = blocking.pending_count();
    let busy = blocking.busy_threads();
    let active = blocking.active_threads();
    require_compat_runtime_quiescence(blocking, engine)?;
    outcome.resource_state.blocking_pending = pending as u64;
    outcome.resource_state.blocking_busy = busy as u64;
    outcome.resource_state.blocking_active = active as u64;
    outcome.resource_state.region_state = "closed".to_owned();
    outcome.resource_state.background_work = "none_observed_after_runtime_shutdown".to_owned();
    Ok(outcome)
}

async fn asupersync_open_memory(cx: &Cx) -> Result<SqliteConnection, String> {
    asupersync_outcome(SqliteConnection::open_in_memory(cx).await, "in-memory open")
}

fn asupersync_outcome<T, E: std::fmt::Display>(
    outcome: Outcome<T, E>,
    operation: &str,
) -> Result<T, String> {
    match outcome {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(error) => Err(format!("asupersync {operation}: {error}")),
        Outcome::Cancelled(_) => Err(format!("asupersync {operation} was cancelled")),
        Outcome::Panicked(_) => Err(format!("asupersync {operation} panicked")),
    }
}

async fn configure_and_probe_asupersync(
    connection: &SqliteConnection,
    cx: &Cx,
    busy_timeout_ms: u64,
) -> Result<(), String> {
    asupersync_outcome(
        connection
            .execute_batch_unchecked(
                cx,
                &format!("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = {busy_timeout_ms};"),
            )
            .await,
        "apply common configuration",
    )?;
    let foreign_keys = query_asupersync_i64(connection, cx, "PRAGMA foreign_keys;").await?;
    let busy_timeout = query_asupersync_i64(connection, cx, "PRAGMA busy_timeout;").await?;
    if foreign_keys != 1 || busy_timeout != busy_timeout_ms as i64 {
        return Err(format!(
            "asupersync configuration readback drifted: foreign_keys={foreign_keys} busy_timeout={busy_timeout}"
        ));
    }
    common_probe_asupersync(connection, cx).await
}

async fn common_probe_asupersync(connection: &SqliteConnection, cx: &Cx) -> Result<(), String> {
    asupersync_outcome(
        connection
            .execute_batch(
                cx,
                "CREATE TABLE p2_probe (id INTEGER PRIMARY KEY, label TEXT NOT NULL);",
            )
            .await,
        "create probe table",
    )?;
    let affected = asupersync_outcome(
        connection
            .execute(
                cx,
                "INSERT INTO p2_probe (id, label) VALUES (7, 'bridge-ok')",
                &[],
            )
            .await,
        "insert probe row",
    )?;
    if affected != 1 {
        return Err(format!("asupersync probe affected {affected} rows"));
    }
    let row = asupersync_outcome(
        connection
            .query_row(cx, "SELECT id, label FROM p2_probe WHERE id = 7", &[])
            .await,
        "query probe row",
    )?
    .ok_or_else(|| "asupersync probe query returned no row".to_owned())?;
    match (row.get_idx(0), row.get_idx(1)) {
        (Ok(AsupersyncValue::Integer(7)), Ok(AsupersyncValue::Text(label)))
            if label == "bridge-ok" =>
        {
            Ok(())
        }
        other => Err(format!("asupersync probe row drifted: {other:?}")),
    }
}

async fn query_asupersync_i64(
    connection: &SqliteConnection,
    cx: &Cx,
    sql: &str,
) -> Result<i64, String> {
    let row = asupersync_outcome(
        connection.query_row_unchecked(cx, sql, &[]).await,
        "query PRAGMA",
    )?
    .ok_or_else(|| "asupersync PRAGMA returned no row".to_owned())?;
    match row.get_idx(0) {
        Ok(AsupersyncValue::Integer(value)) => Ok(*value),
        other => Err(format!("asupersync PRAGMA returned non-integer: {other:?}")),
    }
}

async fn asupersync_close(connection: &SqliteConnection, cx: &Cx) -> Result<(), String> {
    asupersync_outcome(connection.close_async(cx).await, "close")?;
    if connection.is_open() {
        return Err("asupersync connection remained open after close".to_owned());
    }
    Ok(())
}

fn attached_franken_cx(native_cx: &CompatCx) -> FrankenCx {
    let local_cx = FrankenCx::new();
    local_cx.set_native_cx(native_cx.clone());
    local_cx
}

async fn configure_and_probe_frankensqlite(
    connection: &FrankenConnection,
    cx: &FrankenCx,
    busy_timeout_ms: u64,
) -> Result<(), String> {
    connection
        .execute_batch(
            cx,
            &format!("PRAGMA foreign_keys = ON; PRAGMA busy_timeout = {busy_timeout_ms};"),
        )
        .await
        .map_err(|error| format!("FrankenSQLite apply common configuration: {error}"))?;
    let foreign_keys = query_franken_i64(connection, cx, "PRAGMA foreign_keys;").await?;
    let busy_timeout = query_franken_i64(connection, cx, "PRAGMA busy_timeout;").await?;
    if foreign_keys != 1 || busy_timeout != busy_timeout_ms as i64 {
        return Err(format!(
            "FrankenSQLite configuration readback drifted: foreign_keys={foreign_keys} busy_timeout={busy_timeout}"
        ));
    }
    common_probe_frankensqlite(connection, cx).await
}

async fn common_probe_frankensqlite(
    connection: &FrankenConnection,
    cx: &FrankenCx,
) -> Result<(), String> {
    connection
        .execute_batch(
            cx,
            "CREATE TABLE p2_probe (id INTEGER PRIMARY KEY, label TEXT NOT NULL);",
        )
        .await
        .map_err(|error| format!("FrankenSQLite create probe table: {error}"))?;
    let affected = connection
        .execute(
            cx,
            "INSERT INTO p2_probe (id, label) VALUES (7, 'bridge-ok')",
        )
        .await
        .map_err(|error| format!("FrankenSQLite insert probe row: {error}"))?;
    if affected != 1 {
        return Err(format!("FrankenSQLite probe affected {affected} rows"));
    }
    let row = connection
        .query_row(cx, "SELECT id, label FROM p2_probe WHERE id = 7")
        .await
        .map_err(|error| format!("FrankenSQLite query probe row: {error}"))?;
    match (row.get(0), row.get(1)) {
        (Some(FrankenValue::Integer(7)), Some(FrankenValue::Text(label)))
            if label.as_ref() == "bridge-ok" =>
        {
            Ok(())
        }
        other => Err(format!("FrankenSQLite probe row drifted: {other:?}")),
    }
}

async fn query_franken_i64(
    connection: &FrankenConnection,
    cx: &FrankenCx,
    sql: &str,
) -> Result<i64, String> {
    let row = connection
        .query_row(cx, sql)
        .await
        .map_err(|error| format!("FrankenSQLite query PRAGMA: {error}"))?;
    match row.get(0) {
        Some(FrankenValue::Integer(value)) => Ok(*value),
        other => Err(format!(
            "FrankenSQLite PRAGMA returned non-integer: {other:?}"
        )),
    }
}

async fn franken_close(connection: &mut FrankenConnection, cx: &FrankenCx) -> Result<(), String> {
    connection
        .close(cx)
        .await
        .map_err(|error| format!("FrankenSQLite close: {error}"))?;
    if connection.query(cx, "SELECT 1").await.is_ok() {
        return Err("FrankenSQLite accepted a query after close".to_owned());
    }
    Ok(())
}

fn poll_once<F>(future: Pin<&mut F>) -> Poll<F::Output>
where
    F: Future,
{
    let mut context = Context::from_waker(Waker::noop());
    future.poll(&mut context)
}

fn verify_admission_recovered(
    telemetry: &asupersync::sync::SyncTelemetrySnapshot,
    capacity: usize,
) -> Result<(), String> {
    if telemetry.capacity != capacity
        || telemetry.available_units != capacity
        || telemetry.occupied_units != 0
        || telemetry.waiter_count != 0
        || telemetry.cancellation_count != 1
    {
        return Err(format!(
            "consumer admission pool did not recover: {telemetry:?}"
        ));
    }
    Ok(())
}

fn verify_compat_admission_recovered(
    telemetry: &asupersync_compat::sync::SyncTelemetrySnapshot,
    capacity: usize,
) -> Result<(), String> {
    if telemetry.capacity != capacity
        || telemetry.available_units != capacity
        || telemetry.occupied_units != 0
        || telemetry.waiter_count != 0
        || telemetry.cancellation_count != 1
    {
        return Err(format!(
            "consumer compatibility admission pool did not recover: {telemetry:?}"
        ));
    }
    Ok(())
}

fn scratch_database_path(engine: &str) -> PathBuf {
    let root = std::env::var_os("SQLITE_PARITY_SCRATCH_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let run_stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    root.join(format!(
        "asupersync-sqlite-p2-{engine}-{}-{run_stamp}.db",
        std::process::id()
    ))
}

fn missing_parent_database_path(engine: &str) -> PathBuf {
    scratch_database_path(engine)
        .with_extension("missing-parent")
        .join("database.db")
}

fn path_to_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "SQLite parity scratch path is not UTF-8".to_owned())
}

fn unsupported_for_engine(vector: &Vector, engine: &str) -> Vec<UnsupportedCapability> {
    vector
        .unsupported
        .iter()
        .filter(|row| row.engine == engine)
        .cloned()
        .collect()
}

fn compare_results(
    suite: &VectorSuite,
    asupersync: &EngineResult,
    frankensqlite: &EngineResult,
) -> Vec<String> {
    let mut mismatches = Vec::new();
    for (index, vector) in suite.vectors.iter().enumerate() {
        let asupersync_result = &asupersync.vectors[index];
        let frankensqlite_result = &frankensqlite.vectors[index];
        if asupersync_result.outcome != frankensqlite_result.outcome {
            mismatches.push(format!("{}: normalized engine outcomes differ", vector.id));
        }
        if asupersync_result.outcome != vector.expected {
            mismatches.push(format!(
                "{}: outcome differs from vector expectation",
                vector.id
            ));
        }
        for (engine, result) in [
            ("asupersync", asupersync_result),
            ("frankensqlite", frankensqlite_result),
        ] {
            let expected = unsupported_for_engine(vector, engine);
            if result.unsupported != expected {
                mismatches.push(format!("{}:{engine}: unsupported rows drifted", vector.id));
            }
        }
    }
    mismatches
}
