//! Structure-aware fuzz target for SQLite prepared-statement bind paths.
//!
//! Focus:
//! - bind value round-trips for NULL / INTEGER / REAL / TEXT / BLOB
//! - cached prepared statements reused across different bind types
//! - parameter-count mismatches return clean errors
//! - constrained integer-only inserts reject non-integer bind values
//! - row accessors surface type mismatches without panicking

#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    cx::Cx,
    database::sqlite::{SqliteConnection, SqliteError, SqliteRow, SqliteValue},
    types::Outcome,
};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;

const MAX_TEXT_CHARS: usize = 256;
const MAX_BLOB_BYTES: usize = 1024;
const MAX_PARAM_VALUES: usize = 5;

#[derive(Arbitrary, Debug, Clone)]
enum BindValueInput {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

impl BindValueInput {
    fn sanitize(self) -> Self {
        match self {
            Self::Null => Self::Null,
            Self::Integer(value) => Self::Integer(value),
            Self::Real(value) => {
                let value = if value.is_finite() { value } else { 0.0 };
                Self::Real(value)
            }
            Self::Text(value) => Self::Text(value.chars().take(MAX_TEXT_CHARS).collect()),
            Self::Blob(value) => Self::Blob(value.into_iter().take(MAX_BLOB_BYTES).collect()),
        }
    }

    fn to_sqlite_value(&self) -> SqliteValue {
        match self {
            Self::Null => SqliteValue::Null,
            Self::Integer(value) => SqliteValue::Integer(*value),
            Self::Real(value) => SqliteValue::Real(*value),
            Self::Text(value) => SqliteValue::Text(value.clone()),
            Self::Blob(value) => SqliteValue::Blob(value.clone()),
        }
    }

    fn storage_class(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Integer(_) => "integer",
            Self::Real(_) => "real",
            Self::Text(_) => "text",
            Self::Blob(_) => "blob",
        }
    }

    fn is_integer(&self) -> bool {
        matches!(self, Self::Integer(_))
    }
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum Accessor {
    Raw,
    Integer,
    Real,
    Text,
    Blob,
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum CountMismatchKind {
    QueryTwo,
    QueryThree,
    InsertTwo,
}

#[derive(Arbitrary, Debug)]
enum Scenario {
    EchoValue {
        value: BindValueInput,
    },
    AccessorMismatch {
        value: BindValueInput,
        accessor: Accessor,
    },
    PreparedCacheReuse {
        first: BindValueInput,
        second: BindValueInput,
    },
    CountMismatch {
        kind: CountMismatchKind,
        provided: Vec<BindValueInput>,
    },
    StrictIntegerInsert {
        raw_a: BindValueInput,
        raw_b: BindValueInput,
        raw_c: BindValueInput,
        raw_d: BindValueInput,
        strict_integer: BindValueInput,
    },
    StatementReuseAfterError {
        first: BindValueInput,
        second: BindValueInput,
        raw_a: BindValueInput,
        strict_integer: i64,
    },
}

struct SqliteHarness {
    conn: SqliteConnection,
    cx: Cx,
}

impl SqliteHarness {
    async fn new() -> Result<Self, SqliteError> {
        let cx = Cx::for_testing();

        let conn = match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(conn) => conn,
            Outcome::Err(error) => return Err(error),
            Outcome::Cancelled(reason) => return Err(SqliteError::Cancelled(reason)),
            Outcome::Panicked(_) => panic!("sqlite open_in_memory panicked"),
        };

        let schema = r#"
            CREATE TABLE bind_probe (
                id INTEGER PRIMARY KEY,
                raw_a,
                raw_b,
                raw_c,
                raw_d,
                strict_integer NOT NULL CHECK(typeof(strict_integer) = 'integer')
            );
        "#;

        match conn.execute_batch(&cx, schema).await {
            Outcome::Ok(()) => Ok(Self { conn, cx }),
            Outcome::Err(error) => Err(error),
            Outcome::Cancelled(reason) => Err(SqliteError::Cancelled(reason)),
            Outcome::Panicked(_) => panic!("sqlite execute_batch panicked"),
        }
    }

    async fn execute(&self, sql: &str, params: &[SqliteValue]) -> Result<u64, SqliteError> {
        match self.conn.execute(&self.cx, sql, params).await {
            Outcome::Ok(rows) => Ok(rows),
            Outcome::Err(error) => Err(error),
            Outcome::Cancelled(reason) => Err(SqliteError::Cancelled(reason)),
            Outcome::Panicked(_) => panic!("sqlite execute panicked"),
        }
    }

    async fn query_row(
        &self,
        sql: &str,
        params: &[SqliteValue],
    ) -> Result<Option<SqliteRow>, SqliteError> {
        match self.conn.query_row(&self.cx, sql, params).await {
            Outcome::Ok(row) => Ok(row),
            Outcome::Err(error) => Err(error),
            Outcome::Cancelled(reason) => Err(SqliteError::Cancelled(reason)),
            Outcome::Panicked(_) => panic!("sqlite query_row panicked"),
        }
    }

    async fn table_row_count(&self) -> Result<i64, SqliteError> {
        let row = self
            .query_row("SELECT COUNT(*) AS row_count FROM bind_probe", &[])
            .await?
            .expect("COUNT(*) query should always return a row");
        row.get_i64("row_count")
    }
}

fn bind_error_message(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("parameter")
        || message.contains("bind")
        || message.contains("count")
        || message.contains("wrong number")
}

fn expect_type_mismatch<T>(result: Result<T, SqliteError>, expected: &'static str) {
    match result {
        Err(SqliteError::TypeMismatch {
            column,
            expected: actual,
            ..
        }) => {
            assert_eq!(column, "value");
            assert_eq!(actual, expected);
        }
        _ => panic!("expected type mismatch for {expected}"),
    }
}

fn assert_round_trip_value(row: &SqliteRow, column: &str, expected: &BindValueInput) {
    match expected {
        BindValueInput::Null => {
            let value = row.get(column).expect("NULL column should exist");
            assert!(matches!(value, SqliteValue::Null));
        }
        BindValueInput::Integer(expected) => {
            assert_eq!(
                row.get(column).expect("integer column should exist"),
                &SqliteValue::Integer(*expected)
            );
            assert_eq!(
                row.get_i64(column)
                    .expect("integer accessor should succeed"),
                *expected
            );
            assert!(
                row.get_f64(column).is_ok(),
                "integer values should widen through get_f64"
            );
        }
        BindValueInput::Real(expected) => {
            let value = row.get(column).expect("real column should exist");
            match value {
                SqliteValue::Real(actual) => assert_eq!(actual.to_bits(), expected.to_bits()),
                other => panic!("expected real value, got {other:?}"),
            }
            let widened = row.get_f64(column).expect("real accessor should succeed");
            assert_eq!(widened.to_bits(), expected.to_bits());
        }
        BindValueInput::Text(expected) => {
            assert_eq!(
                row.get(column).expect("text column should exist"),
                &SqliteValue::Text(expected.clone())
            );
            assert_eq!(
                row.get_str(column).expect("text accessor should succeed"),
                expected
            );
        }
        BindValueInput::Blob(expected) => {
            assert_eq!(
                row.get(column).expect("blob column should exist"),
                &SqliteValue::Blob(expected.clone())
            );
            assert_eq!(
                row.get_blob(column).expect("blob accessor should succeed"),
                expected.as_slice()
            );
        }
    }
}

fn mismatch_statement(kind: CountMismatchKind) -> (&'static str, usize, bool) {
    match kind {
        CountMismatchKind::QueryTwo => ("SELECT ?1 AS value, ?2 AS other", 2, false),
        CountMismatchKind::QueryThree => ("SELECT ?1, ?2, ?3", 3, false),
        CountMismatchKind::InsertTwo => (
            "INSERT INTO bind_probe (raw_a, strict_integer) VALUES (?1, ?2)",
            2,
            true,
        ),
    }
}

fn mismatched_params(values: Vec<BindValueInput>, expected: usize) -> Vec<SqliteValue> {
    let mut params: Vec<_> = values
        .into_iter()
        .take(MAX_PARAM_VALUES)
        .map(BindValueInput::sanitize)
        .map(|value| value.to_sqlite_value())
        .collect();

    if params.len() == expected {
        if expected > 0 {
            let _ = params.pop();
        } else {
            params.push(SqliteValue::Null);
        }
    }

    params
}

async fn run_scenario(scenario: Scenario) {
    let harness = match SqliteHarness::new().await {
        Ok(harness) => harness,
        Err(_) => return,
    };

    match scenario {
        Scenario::EchoValue { value } => {
            let value = value.sanitize();
            let params = [value.to_sqlite_value()];
            let row = harness
                .query_row(
                    "SELECT ?1 AS value, typeof(?1) AS value_type",
                    params.as_slice(),
                )
                .await
                .expect("echo query should not fail")
                .expect("echo query should return a row");

            assert_round_trip_value(&row, "value", &value);
            assert_eq!(
                row.get_str("value_type")
                    .expect("typeof column should exist"),
                value.storage_class()
            );
        }
        Scenario::AccessorMismatch { value, accessor } => {
            let value = value.sanitize();
            let params = [value.to_sqlite_value()];
            let row = harness
                .query_row("SELECT ?1 AS value", params.as_slice())
                .await
                .expect("accessor probe query should not fail")
                .expect("accessor probe should return a row");

            match accessor {
                Accessor::Raw => assert_round_trip_value(&row, "value", &value),
                Accessor::Integer => match value {
                    BindValueInput::Integer(expected) => {
                        assert_eq!(row.get_i64("value").expect("integer accessor"), expected);
                    }
                    _ => expect_type_mismatch(row.get_i64("value"), "integer"),
                },
                Accessor::Real => match value {
                    BindValueInput::Integer(_) => {
                        assert!(
                            row.get_f64("value").is_ok(),
                            "integer values should widen through get_f64"
                        );
                    }
                    BindValueInput::Real(expected) => {
                        let actual = row.get_f64("value").expect("real accessor");
                        assert_eq!(actual.to_bits(), expected.to_bits());
                    }
                    _ => expect_type_mismatch(row.get_f64("value"), "real"),
                },
                Accessor::Text => match value {
                    BindValueInput::Text(expected) => {
                        assert_eq!(row.get_str("value").expect("text accessor"), expected);
                    }
                    _ => expect_type_mismatch(row.get_str("value"), "text"),
                },
                Accessor::Blob => match value {
                    BindValueInput::Blob(expected) => {
                        assert_eq!(
                            row.get_blob("value").expect("blob accessor"),
                            expected.as_slice()
                        );
                    }
                    _ => expect_type_mismatch(row.get_blob("value"), "blob"),
                },
            }
        }
        Scenario::PreparedCacheReuse { first, second } => {
            let first = first.sanitize();
            let second = second.sanitize();
            let sql = "SELECT ?1 AS value, typeof(?1) AS value_type";

            let first_params = [first.to_sqlite_value()];
            let first_row = harness
                .query_row(sql, first_params.as_slice())
                .await
                .expect("first cached query should not fail")
                .expect("first cached query should return a row");
            assert_round_trip_value(&first_row, "value", &first);
            assert_eq!(
                first_row
                    .get_str("value_type")
                    .expect("first typeof column should exist"),
                first.storage_class()
            );

            let second_params = [second.to_sqlite_value()];
            let second_row = harness
                .query_row(sql, second_params.as_slice())
                .await
                .expect("second cached query should not fail")
                .expect("second cached query should return a row");
            assert_round_trip_value(&second_row, "value", &second);
            assert_eq!(
                second_row
                    .get_str("value_type")
                    .expect("second typeof column should exist"),
                second.storage_class()
            );
        }
        Scenario::CountMismatch { kind, provided } => {
            let (sql, expected, use_execute) = mismatch_statement(kind);
            let params = mismatched_params(provided, expected);

            assert_ne!(
                params.len(),
                expected,
                "count-mismatch helper must always produce a mismatched parameter list"
            );

            if use_execute {
                match harness.execute(sql, params.as_slice()).await {
                    Err(SqliteError::Sqlite(message)) => {
                        assert!(
                            bind_error_message(&message),
                            "expected bind-count error, got: {message}"
                        );
                        assert_eq!(
                            harness
                                .table_row_count()
                                .await
                                .expect("row-count query should succeed"),
                            0,
                            "failed bind-count inserts must not leave partial rows behind"
                        );
                    }
                    other => panic!("expected sqlite bind-count error, got {other:?}"),
                }
            } else {
                match harness.query_row(sql, params.as_slice()).await {
                    Err(SqliteError::Sqlite(message)) => {
                        assert!(
                            bind_error_message(&message),
                            "expected bind-count error, got: {message}"
                        );
                    }
                    _ => panic!("expected sqlite bind-count error from query_row"),
                }
            }
        }
        Scenario::StrictIntegerInsert {
            raw_a,
            raw_b,
            raw_c,
            raw_d,
            strict_integer,
        } => {
            let raw_a = raw_a.sanitize();
            let raw_b = raw_b.sanitize();
            let raw_c = raw_c.sanitize();
            let raw_d = raw_d.sanitize();
            let strict_integer = strict_integer.sanitize();

            let params = [
                raw_a.to_sqlite_value(),
                raw_b.to_sqlite_value(),
                raw_c.to_sqlite_value(),
                raw_d.to_sqlite_value(),
                strict_integer.to_sqlite_value(),
            ];

            let insert = harness
                .execute(
                    "INSERT INTO bind_probe (raw_a, raw_b, raw_c, raw_d, strict_integer) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params.as_slice(),
                )
                .await;

            if strict_integer.is_integer() {
                let affected = insert.expect("integer strict value should insert cleanly");
                assert_eq!(affected, 1, "one row should be inserted");

                let row = harness
                    .query_row(
                        "SELECT raw_a, raw_b, raw_c, raw_d, strict_integer FROM bind_probe ORDER BY id DESC LIMIT 1",
                        &[],
                    )
                    .await
                    .expect("querying inserted row should succeed")
                    .expect("inserted row should exist");

                assert_round_trip_value(&row, "raw_a", &raw_a);
                assert_round_trip_value(&row, "raw_b", &raw_b);
                assert_round_trip_value(&row, "raw_c", &raw_c);
                assert_round_trip_value(&row, "raw_d", &raw_d);
                assert_round_trip_value(&row, "strict_integer", &strict_integer);
            } else {
                match insert {
                    Err(SqliteError::Sqlite(_)) => {
                        assert_eq!(
                            harness
                                .table_row_count()
                                .await
                                .expect("row-count query should succeed"),
                            0,
                            "failed strict-type inserts must not leave rows behind"
                        );
                    }
                    other => panic!("non-integer strict bind should fail cleanly, got {other:?}"),
                }
            }
        }
        Scenario::StatementReuseAfterError {
            first,
            second,
            raw_a,
            strict_integer,
        } => {
            let first = first.sanitize();
            let second = second.sanitize();
            let raw_a = raw_a.sanitize();

            let query_sql = "SELECT ?1 AS value, ?2 AS other";
            let bad_params = [first.to_sqlite_value()];
            match harness.query_row(query_sql, bad_params.as_slice()).await {
                Err(SqliteError::Sqlite(message)) => {
                    assert!(
                        bind_error_message(&message),
                        "expected bind-count error, got: {message}"
                    );
                }
                other => panic!("expected bind-count error before statement reuse, got {other:?}"),
            }

            let ok_params = [first.to_sqlite_value(), second.to_sqlite_value()];
            let row = harness
                .query_row(query_sql, ok_params.as_slice())
                .await
                .expect("statement should be reusable after bind-count error")
                .expect("reused statement should return a row");
            assert_round_trip_value(&row, "value", &first);
            assert_round_trip_value(&row, "other", &second);

            let insert_sql = "INSERT INTO bind_probe (raw_a, strict_integer) VALUES (?1, ?2)";
            let rejected_params = [raw_a.to_sqlite_value(), SqliteValue::Text("oops".into())];
            match harness
                .execute(insert_sql, rejected_params.as_slice())
                .await
            {
                Err(SqliteError::Sqlite(_)) => {
                    assert_eq!(
                        harness
                            .table_row_count()
                            .await
                            .expect("row-count query should succeed"),
                        0,
                        "rejected strict-type inserts must not leak partial rows"
                    );
                }
                other => {
                    panic!("expected strict-type rejection before statement reuse, got {other:?}")
                }
            }

            let ok_insert_params = [
                raw_a.to_sqlite_value(),
                SqliteValue::Integer(strict_integer),
            ];
            let affected = harness
                .execute(insert_sql, ok_insert_params.as_slice())
                .await
                .expect("statement should be reusable after strict-type error");
            assert_eq!(affected, 1, "reused insert statement should affect one row");

            let row = harness
                .query_row(
                    "SELECT raw_a, strict_integer FROM bind_probe ORDER BY id DESC LIMIT 1",
                    &[],
                )
                .await
                .expect("querying reused insert should succeed")
                .expect("inserted row should exist");
            assert_round_trip_value(&row, "raw_a", &raw_a);
            assert_eq!(
                row.get_i64("strict_integer")
                    .expect("strict_integer accessor should succeed"),
                strict_integer
            );
        }
    }
}

fuzz_target!(|scenario: Scenario| {
    block_on(run_scenario(scenario));
});
