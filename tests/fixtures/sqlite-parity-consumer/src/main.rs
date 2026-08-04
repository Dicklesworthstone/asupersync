//! Neutral, independently resolved SQLite parity consumer.
//!
//! The binary consumes the versioned vector checked into the asupersync
//! repository, executes it once through each engine, and emits one deterministic
//! JSON evidence document. It intentionally lives in a standalone Cargo
//! workspace so FrankenSQLite never enters asupersync's dependency graph.

use std::collections::BTreeSet;

use asupersync::database::{SqliteConnection, SqliteValue as AsupersyncValue};
use asupersync::runtime::RuntimeBuilder;
use asupersync::{Cx, Outcome};
use fsqlite::{Connection as FrankenConnection, SqliteValue as FrankenValue};
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
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vector {
    id: String,
    family: String,
    description: String,
    setup: Vec<SetupStep>,
    operations: Vec<Operation>,
    expected_final_state: FinalState,
    unsupported: Vec<UnsupportedCapability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupStep {
    id: String,
    kind: String,
    sql: String,
    expected_status: Status,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Operation {
    sequence: u64,
    id: String,
    kind: String,
    sql: String,
    expected: OperationOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Ok,
    Error,
    Cancelled,
    Panicked,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperationOutcome {
    status: Status,
    affected_rows: Option<u64>,
    values: Vec<NormalizedValue>,
    error_class: Option<String>,
    transaction_state: String,
    cancellation_state: String,
    resource_state: ResourceState,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
enum NormalizedValue {
    Null,
    Integer(i64),
    Real(String),
    Text(String),
    BlobHex(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResourceState {
    connection: String,
    open_transactions: u64,
    background_work: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FinalState {
    transaction_state: String,
    cancellation_state: String,
    resource_state: ResourceState,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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
    comparison: Comparison,
}

#[derive(Debug, Serialize)]
struct Provenance<'a> {
    asupersync_revision: &'a str,
    frankensqlite_revision: &'a str,
    asupersync_features: [&'a str; 1],
    frankensqlite_features: [&'a str; 1],
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
    setup: Vec<SetupResult>,
    operations: Vec<OperationResult>,
    final_state: FinalState,
    unsupported: Vec<UnsupportedCapability>,
}

#[derive(Debug, PartialEq, Serialize)]
struct SetupResult {
    id: String,
    status: Status,
}

#[derive(Debug, PartialEq, Serialize)]
struct OperationResult {
    sequence: u64,
    id: String,
    outcome: OperationOutcome,
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
    let evidence = HarnessEvidence {
        evidence_schema_version: 1,
        vector_schema_version: suite.schema_version,
        suite_id: &suite.suite_id,
        capability_id: &suite.capability_id,
        provenance: Provenance {
            asupersync_revision: env!("ASUPERSYNC_SOURCE_REVISION"),
            frankensqlite_revision: FSQLITE_REVISION,
            asupersync_features: ["sqlite"],
            frankensqlite_features: ["native"],
            cargo_profile: "dev",
            target: env!("SQLITE_PARITY_TARGET"),
            host: env!("SQLITE_PARITY_HOST"),
        },
        engine_results: vec![asupersync, frankensqlite],
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

fn validate_suite(suite: &VectorSuite) -> Result<(), String> {
    if suite.schema_version != 1 {
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
        if vector.family.is_empty() || vector.description.is_empty() || vector.setup.is_empty() {
            return Err(format!(
                "vector {} has incomplete metadata/setup",
                vector.id
            ));
        }
        let mut step_ids = BTreeSet::new();
        for setup in &vector.setup {
            if !step_ids.insert(&setup.id)
                || setup.kind != "execute_batch"
                || setup.sql.trim().is_empty()
                || setup.expected_status != Status::Ok
            {
                return Err(format!("vector {} has invalid setup", vector.id));
            }
        }
        for (index, operation) in vector.operations.iter().enumerate() {
            let expected_sequence =
                u64::try_from(index + 1).map_err(|_| "operation count overflow".to_owned())?;
            if operation.sequence != expected_sequence
                || !step_ids.insert(&operation.id)
                || !matches!(operation.kind.as_str(), "execute" | "query_one")
                || operation.sql.trim().is_empty()
            {
                return Err(format!(
                    "vector {} has invalid operation sequence/id/kind",
                    vector.id
                ));
            }
            validate_outcome(&operation.expected)?;
        }
        if vector.expected_final_state.resource_state.connection != "closed"
            || vector.expected_final_state.resource_state.open_transactions != 0
        {
            return Err(format!(
                "vector {} must finish closed and transaction-free",
                vector.id
            ));
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

fn validate_outcome(outcome: &OperationOutcome) -> Result<(), String> {
    match outcome.status {
        Status::Ok if outcome.error_class.is_some() => {
            Err("successful outcomes cannot carry an error class".to_owned())
        }
        Status::Error | Status::Cancelled | Status::Panicked
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
        .build()
        .map_err(|error| format!("build asupersync runtime: {error}"))?;
    runtime.block_on(async {
        let cx = Cx::current().ok_or_else(|| "asupersync runtime did not install Cx".to_owned())?;
        let connection = SqliteConnection::open_in_memory(&cx)
            .await
            .into_result()
            .map_err(|error| format!("asupersync open: {error}"))?;

        let mut setup_results = Vec::with_capacity(vector.setup.len());
        for setup in &vector.setup {
            let status = match connection.execute_batch(&cx, &setup.sql).await {
                Outcome::Ok(()) => Status::Ok,
                Outcome::Err(_) => Status::Error,
                Outcome::Cancelled(_) => Status::Cancelled,
                Outcome::Panicked(_) => Status::Panicked,
            };
            setup_results.push(SetupResult {
                id: setup.id.clone(),
                status,
            });
        }

        let mut operation_results = Vec::with_capacity(vector.operations.len());
        for operation in &vector.operations {
            let outcome = match operation.kind.as_str() {
                "execute" => match connection.execute(&cx, &operation.sql, &[]).await {
                    Outcome::Ok(affected_rows) => {
                        successful_outcome(Some(affected_rows), Vec::new())
                    }
                    Outcome::Err(_) => failed_outcome(Status::Error, "sqlite_error"),
                    Outcome::Cancelled(_) => failed_outcome(Status::Cancelled, "cancelled"),
                    Outcome::Panicked(_) => failed_outcome(Status::Panicked, "panicked"),
                },
                "query_one" => match connection.query_row(&cx, &operation.sql, &[]).await {
                    Outcome::Ok(Some(row)) => {
                        let values = (0..row.len())
                            .map(|index| {
                                row.get_idx(index).map(normalize_asupersync_value).map_err(
                                    |error| format!("asupersync row value {index}: {error}"),
                                )
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        successful_outcome(None, values)
                    }
                    Outcome::Ok(None) => failed_outcome(Status::Error, "no_row"),
                    Outcome::Err(_) => failed_outcome(Status::Error, "sqlite_error"),
                    Outcome::Cancelled(_) => failed_outcome(Status::Cancelled, "cancelled"),
                    Outcome::Panicked(_) => failed_outcome(Status::Panicked, "panicked"),
                },
                _ => return Err(format!("unsupported operation kind {}", operation.kind)),
            };
            operation_results.push(OperationResult {
                sequence: operation.sequence,
                id: operation.id.clone(),
                outcome,
            });
        }
        drop(connection);

        Ok(VectorResult {
            vector_id: vector.id.clone(),
            setup: setup_results,
            operations: operation_results,
            final_state: observed_final_state(),
            unsupported: vector.unsupported.clone(),
        })
    })
}

fn run_frankensqlite(vector: &Vector) -> Result<VectorResult, String> {
    let connection = FrankenConnection::open(":memory:")
        .map_err(|error| format!("frankensqlite open: {error}"))?;

    let mut setup_results = Vec::with_capacity(vector.setup.len());
    for setup in &vector.setup {
        let status = if connection.execute_batch(&setup.sql).is_ok() {
            Status::Ok
        } else {
            Status::Error
        };
        setup_results.push(SetupResult {
            id: setup.id.clone(),
            status,
        });
    }

    let mut operation_results = Vec::with_capacity(vector.operations.len());
    for operation in &vector.operations {
        let outcome = match operation.kind.as_str() {
            "execute" => match connection.execute(&operation.sql) {
                Ok(affected_rows) => successful_outcome(
                    Some(
                        u64::try_from(affected_rows)
                            .map_err(|_| "frankensqlite affected-row overflow".to_owned())?,
                    ),
                    Vec::new(),
                ),
                Err(_) => failed_outcome(Status::Error, "sqlite_error"),
            },
            "query_one" => match connection.query_row(&operation.sql) {
                Ok(row) => successful_outcome(
                    None,
                    row.values()
                        .iter()
                        .map(normalize_frankensqlite_value)
                        .collect(),
                ),
                Err(_) => failed_outcome(Status::Error, "sqlite_error"),
            },
            _ => return Err(format!("unsupported operation kind {}", operation.kind)),
        };
        operation_results.push(OperationResult {
            sequence: operation.sequence,
            id: operation.id.clone(),
            outcome,
        });
    }
    drop(connection);

    Ok(VectorResult {
        vector_id: vector.id.clone(),
        setup: setup_results,
        operations: operation_results,
        final_state: observed_final_state(),
        unsupported: vector.unsupported.clone(),
    })
}

fn successful_outcome(
    affected_rows: Option<u64>,
    values: Vec<NormalizedValue>,
) -> OperationOutcome {
    OperationOutcome {
        status: Status::Ok,
        affected_rows,
        values,
        error_class: None,
        transaction_state: "none".to_owned(),
        cancellation_state: "not_requested".to_owned(),
        resource_state: ResourceState {
            connection: "open".to_owned(),
            open_transactions: 0,
            background_work: "none_observed".to_owned(),
        },
    }
}

fn failed_outcome(status: Status, error_class: &str) -> OperationOutcome {
    OperationOutcome {
        status,
        affected_rows: None,
        values: Vec::new(),
        error_class: Some(error_class.to_owned()),
        transaction_state: "unknown".to_owned(),
        cancellation_state: "terminal".to_owned(),
        resource_state: ResourceState {
            connection: "open".to_owned(),
            open_transactions: 0,
            background_work: "none_observed".to_owned(),
        },
    }
}

fn observed_final_state() -> FinalState {
    FinalState {
        transaction_state: "none".to_owned(),
        cancellation_state: "not_requested".to_owned(),
        resource_state: ResourceState {
            connection: "closed".to_owned(),
            open_transactions: 0,
            background_work: "none_observed".to_owned(),
        },
    }
}

fn normalize_asupersync_value(value: &AsupersyncValue) -> NormalizedValue {
    match value {
        AsupersyncValue::Null => NormalizedValue::Null,
        AsupersyncValue::Integer(value) => NormalizedValue::Integer(*value),
        AsupersyncValue::Real(value) => NormalizedValue::Real(canonical_real(*value)),
        AsupersyncValue::Text(value) => NormalizedValue::Text(value.clone()),
        AsupersyncValue::Blob(value) => NormalizedValue::BlobHex(lower_hex(value)),
    }
}

fn normalize_frankensqlite_value(value: &FrankenValue) -> NormalizedValue {
    match value {
        FrankenValue::Null => NormalizedValue::Null,
        FrankenValue::Integer(value) => NormalizedValue::Integer(*value),
        FrankenValue::Float(value) => NormalizedValue::Real(canonical_real(*value)),
        FrankenValue::Text(value) => NormalizedValue::Text(value.to_string()),
        FrankenValue::Blob(value) => NormalizedValue::BlobHex(lower_hex(value)),
    }
}

fn canonical_real(value: f64) -> String {
    if value == 0.0 {
        "0".to_owned()
    } else {
        value.to_string()
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut rendered = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(rendered, "{byte:02x}").expect("writing to a String cannot fail");
    }
    rendered
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
        if asupersync_result.setup != frankensqlite_result.setup {
            mismatches.push(format!("{}: engine setup results differ", vector.id));
        }
        if asupersync_result.operations != frankensqlite_result.operations {
            mismatches.push(format!("{}: engine operation results differ", vector.id));
        }
        if asupersync_result.final_state != frankensqlite_result.final_state {
            mismatches.push(format!("{}: engine final states differ", vector.id));
        }
        for (operation, actual) in vector.operations.iter().zip(&asupersync_result.operations) {
            if operation.expected != actual.outcome {
                mismatches.push(format!(
                    "{}:{}: result differs from vector expectation",
                    vector.id, operation.id
                ));
            }
        }
        if vector.expected_final_state != asupersync_result.final_state {
            mismatches.push(format!(
                "{}: final state differs from expectation",
                vector.id
            ));
        }
        if asupersync_result
            .setup
            .iter()
            .zip(&vector.setup)
            .any(|(actual, expected)| actual.status != expected.expected_status)
        {
            mismatches.push(format!("{}: setup differs from expectation", vector.id));
        }
    }
    mismatches
}
