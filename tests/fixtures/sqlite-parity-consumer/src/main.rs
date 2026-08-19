//! Neutral, independently resolved SQLite parity consumer.
//!
//! The binary consumes the versioned vector checked into the asupersync
//! repository, executes it once through each engine, and emits one deterministic
//! JSON evidence document. It intentionally lives in a standalone Cargo
//! workspace so FrankenSQLite never enters asupersync's dependency graph.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use asupersync::database::sqlite::validate_checked_sql_statement;
use asupersync::database::{SqliteConnection, SqliteError, SqliteValue as AsupersyncValue};
use asupersync::runtime::{BlockingPoolHandle, RuntimeBuilder, yield_now};
use asupersync::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use asupersync::{Cx, Outcome};
use asupersync_compat::Cx as CompatCx;
use asupersync_compat::runtime::{
    BlockingPoolHandle as CompatBlockingPoolHandle, RuntimeBuilder as CompatRuntimeBuilder,
    yield_now as compat_yield_now,
};
use asupersync_compat::sync::{
    AcquireError as CompatAcquireError, OwnedSemaphorePermit as CompatOwnedSemaphorePermit,
    Semaphore as CompatSemaphore,
};
use fsqlite::{AsyncConnection as FrankenConnection, FrankenError, SqliteValue as FrankenValue};
use fsqlite_types::cx::Cx as FrankenCx;
use serde::{Deserialize, Serialize};

const VECTOR_JSON: &str = include_str!("../../../../artifacts/sqlite_conformance_vectors_v1.json");
const FSQLITE_REVISION: &str = "92f9e9833f859ebcbe27e9fef16d9cad4372bbd7";

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
    security_policy: SecurityPolicyEvidence,
    comparison: Comparison,
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
    if let Err(error) = run() {
        eprintln!("sqlite parity harness failed: {error}");
        std::process::exit(1);
    }
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
    let security_policy = run_security_policy()?;
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
        security_policy,
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
    for ((case, native), franken) in cases
        .iter()
        .zip(&asupersync)
        .zip(&frankensqlite_adapter)
    {
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
            let mut waiter = spawn_parked_checkout(cx, Arc::clone(&semaphore)).await?;
            asupersync_close(&connection, cx).await?;
            abort_and_drain_checkout(cx, &semaphore, &mut waiter).await?;
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
            let mut waiter =
                spawn_parked_compat_checkout(native_cx, Arc::clone(&semaphore)).await?;
            franken_close(&mut connection, &local_cx).await?;
            abort_and_drain_compat_checkout(native_cx, &semaphore, &mut waiter).await?;
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

fn require_runtime_quiescence(
    blocking: &BlockingPoolHandle,
    engine: &str,
) -> Result<(), String> {
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

async fn spawn_parked_checkout(
    cx: &Cx,
    semaphore: Arc<Semaphore>,
) -> Result<asupersync::runtime::TaskHandle<Result<(), AcquireError>>, String> {
    if semaphore.try_acquire(1).is_ok() {
        return Err("consumer admission pool was not saturated".to_owned());
    }
    let waiter_semaphore = Arc::clone(&semaphore);
    let mut waiter = cx
        .spawn(move |waiter_cx| async move {
            OwnedSemaphorePermit::acquire(waiter_semaphore, &waiter_cx, 1)
                .await
                .map(drop)
        })
        .map_err(|error| format!("spawn checkout waiter: {error}"))?;
    for _ in 0..256 {
        if semaphore.telemetry_snapshot(0x53514c32).waiter_count == 1 {
            return Ok(waiter);
        }
        yield_now().await;
    }
    waiter.abort();
    let _ = waiter.join(cx).await;
    Err("checkout waiter never reached the saturated admission queue".to_owned())
}

async fn abort_and_drain_checkout(
    cx: &Cx,
    semaphore: &Semaphore,
    waiter: &mut asupersync::runtime::TaskHandle<Result<(), AcquireError>>,
) -> Result<(), String> {
    if semaphore.telemetry_snapshot(0x53514c32).waiter_count != 1 {
        return Err("checkout was not in flight when connection close completed".to_owned());
    }
    waiter.abort();
    match waiter.join(cx).await {
        Ok(Err(AcquireError::Cancelled)) => {}
        other => {
            return Err(format!(
                "parked checkout did not drain as graceful cancellation: {other:?}"
            ));
        }
    }
    Ok(())
}

async fn spawn_parked_compat_checkout(
    cx: &CompatCx,
    semaphore: Arc<CompatSemaphore>,
) -> Result<asupersync_compat::runtime::TaskHandle<Result<(), CompatAcquireError>>, String> {
    if semaphore.try_acquire(1).is_ok() {
        return Err("consumer compatibility admission pool was not saturated".to_owned());
    }
    let waiter_semaphore = Arc::clone(&semaphore);
    let mut waiter = cx
        .spawn(move |waiter_cx| async move {
            CompatOwnedSemaphorePermit::acquire(waiter_semaphore, &waiter_cx, 1)
                .await
                .map(drop)
        })
        .map_err(|error| format!("spawn compatibility checkout waiter: {error}"))?;
    for _ in 0..256 {
        if semaphore.telemetry_snapshot(0x53514c32).waiter_count == 1 {
            return Ok(waiter);
        }
        compat_yield_now().await;
    }
    waiter.abort();
    let _ = waiter.join(cx).await;
    Err("compatibility checkout waiter never reached the saturated admission queue".to_owned())
}

async fn abort_and_drain_compat_checkout(
    cx: &CompatCx,
    semaphore: &CompatSemaphore,
    waiter: &mut asupersync_compat::runtime::TaskHandle<Result<(), CompatAcquireError>>,
) -> Result<(), String> {
    if semaphore.telemetry_snapshot(0x53514c32).waiter_count != 1 {
        return Err(
            "compatibility checkout was not in flight when connection close completed".to_owned(),
        );
    }
    waiter.abort();
    match waiter.join(cx).await {
        Ok(Err(CompatAcquireError::Cancelled))
        | Err(asupersync_compat::runtime::JoinError::Cancelled(_)) => {}
        other => {
            return Err(format!(
                "parked compatibility checkout did not drain as a recognized cancellation: {other:?}"
            ));
        }
    }
    Ok(())
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
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    root.join(format!(
        "asupersync-sqlite-p2-{engine}-{}-{nonce}.db",
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
