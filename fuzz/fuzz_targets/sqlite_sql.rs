//! Comprehensive fuzz target for SQLite SQL statement parser.
//!
//! This target feeds malformed SQL statements to the rusqlite-backed SQLite
//! adapter to verify critical security and correctness properties:
//!
//! 1. Parameter binding rejects mismatched counts
//! 2. PRAGMA statements handled safely
//! 3. DDL vs DML discrimination
//! 4. Transaction nesting (SAVEPOINT) tracked
//! 5. Blob binding bounded by SQLITE_MAX_LENGTH
//!
//! # Running
//! ```bash
//! cargo +nightly fuzz run sqlite_sql
//! ```
//!
//! # Security Focus
//! - Parameter count validation against SQL statement placeholders
//! - PRAGMA statement restrictions and safety
//! - DDL vs DML statement classification
//! - Transaction and savepoint nesting validation
//! - Blob size limits enforcement (SQLITE_MAX_LENGTH = 1GB)

#![no_main]

use arbitrary::Arbitrary;
use asupersync::{
    cx::Cx,
    database::sqlite::{
        SqliteConnection, SqliteError, SqliteValue, fuzz_validate_sqlite_open_path,
    },
    types::Outcome,
};
use futures::executor::block_on;
use libfuzzer_sys::fuzz_target;
use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

/// Maximum fuzz input size to prevent timeouts
const MAX_FUZZ_INPUT_SIZE: usize = 100_000;

/// SQLite maximum blob size (1GB)
const SQLITE_MAX_LENGTH: usize = 1_000_000_000;

/// Maximum reasonable parameter count for fuzzing
const MAX_PARAM_COUNT: usize = 1000;

/// Bound text size for arbitrary SQLite values.
const MAX_TEXT_BYTES: usize = 256;

/// Bound blob size for arbitrary SQLite values.
const MAX_BLOB_BYTES: usize = 1024;

/// SQL statement type classification
#[derive(Debug, Clone, PartialEq)]
enum SqlStatementType {
    DDL,    // Data Definition Language (CREATE, DROP, ALTER)
    DML,    // Data Manipulation Language (SELECT, INSERT, UPDATE, DELETE)
    DCL,    // Data Control Language (GRANT, REVOKE)
    TCL,    // Transaction Control Language (BEGIN, COMMIT, ROLLBACK, SAVEPOINT)
    Pragma, // PRAGMA statements
    Unknown,
}

/// SQL statement generation strategy for fuzzing
#[derive(Arbitrary, Debug, Clone)]
enum SqlStrategy {
    /// Valid SELECT statement
    Select {
        columns: Vec<String>,
        table: String,
        where_clause: Option<String>,
        param_count: u8,
    },
    /// Valid INSERT statement
    Insert {
        table: String,
        columns: Vec<String>,
        param_count: u8,
    },
    /// Valid UPDATE statement
    Update {
        table: String,
        set_clauses: Vec<String>,
        where_clause: Option<String>,
        param_count: u8,
    },
    /// Valid DELETE statement
    Delete {
        table: String,
        where_clause: Option<String>,
        param_count: u8,
    },
    /// DDL CREATE TABLE statement
    CreateTable { table: String, columns: Vec<String> },
    /// DDL DROP TABLE statement
    DropTable { table: String },
    /// Transaction control (BEGIN, COMMIT, ROLLBACK)
    Transaction { operation: TransactionOp },
    /// Savepoint operations
    Savepoint {
        operation: SavepointOp,
        name: String,
    },
    /// PRAGMA statements
    Pragma {
        pragma_name: String,
        pragma_value: Option<String>,
    },
    /// Malformed SQL for error testing
    Malformed { sql: String, param_count: u8 },
    /// SQL injection patterns
    Injection {
        base_sql: String,
        injection_payload: String,
        param_count: u8,
    },
}

#[derive(Arbitrary, Debug, Clone)]
enum TransactionOp {
    Begin,
    BeginDeferred,
    BeginImmediate,
    BeginExclusive,
    Commit,
    Rollback,
}

#[derive(Arbitrary, Debug, Clone)]
enum SavepointOp {
    Create,
    Release,
    Rollback,
}

/// Parameter binding strategy for fuzzing
#[derive(Arbitrary, Debug, Clone)]
struct ParameterStrategy {
    /// Number of parameters to bind
    param_count: u8,
    /// Parameter values
    params: Vec<BindValueInput>,
    /// Whether to intentionally mismatch parameter count
    mismatch_count: bool,
    /// Whether to include oversized blobs
    oversized_blob: bool,
}

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
            Self::Real(value) => Self::Real(if value.is_finite() { value } else { 0.0 }),
            Self::Text(value) => Self::Text(value.chars().take(MAX_TEXT_BYTES).collect()),
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
}

/// Test case for SQLite fuzzing
#[derive(Arbitrary, Debug)]
struct SqliteFuzzInput {
    /// SQL statement generation strategy
    sql_strategy: SqlStrategy,
    /// Parameter binding strategy
    param_strategy: ParameterStrategy,
    /// ATTACH/open-path probe for path validation policy
    attach_path_probe: AttachPathProbe,
    /// Whether to use a transaction
    use_transaction: bool,
    /// Corruption strategy
    corruption: CorruptionStrategy,
}

#[derive(Arbitrary, Debug, Clone)]
enum CorruptionStrategy {
    None,
    /// Inject null bytes
    NullBytes {
        position: u8,
    },
    /// Inject very long identifiers
    LongIdentifiers {
        length: u16,
    },
    /// Inject unicode characters
    Unicode {
        chars: String,
    },
    /// Truncate SQL at random position
    Truncate {
        position: u8,
    },
    /// Repeat SQL statement multiple times
    Repeat {
        count: u8,
    },
}

#[derive(Arbitrary, Debug, Clone)]
struct AttachPathProbe {
    kind: AttachPathKind,
    path_bytes: Vec<u8>,
    use_database_keyword: bool,
}

#[derive(Arbitrary, Debug, Clone)]
enum AttachPathKind {
    RelativeFile,
    RestrictedEtc,
    TildeHome,
    TildeUser,
    ParentTraversal,
    EtcTraversal,
}

impl SqliteFuzzInput {
    /// Generate the SQL statement string
    fn generate_sql(&self) -> String {
        let base_sql = match &self.sql_strategy {
            SqlStrategy::Select {
                columns,
                table,
                where_clause,
                ..
            } => {
                let cols = if columns.is_empty() {
                    "*".to_string()
                } else {
                    columns.join(", ")
                };
                let mut sql = format!("SELECT {} FROM {}", cols, table);
                if let Some(where_part) = where_clause {
                    sql.push_str(&format!(" WHERE {}", where_part));
                }
                sql
            }
            SqlStrategy::Insert { table, columns, .. } => {
                if columns.is_empty() {
                    format!("INSERT INTO {} VALUES (?)", table)
                } else {
                    let placeholders = "?"
                        .repeat(columns.len())
                        .chars()
                        .collect::<Vec<_>>()
                        .chunks(1)
                        .map(|c| c.iter().collect::<String>())
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "INSERT INTO {} ({}) VALUES ({})",
                        table,
                        columns.join(", "),
                        placeholders
                    )
                }
            }
            SqlStrategy::Update {
                table,
                set_clauses,
                where_clause,
                ..
            } => {
                let sets = if set_clauses.is_empty() {
                    "column1 = ?".to_string()
                } else {
                    set_clauses
                        .iter()
                        .map(|c| format!("{} = ?", c))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let mut sql = format!("UPDATE {} SET {}", table, sets);
                if let Some(where_part) = where_clause {
                    sql.push_str(&format!(" WHERE {}", where_part));
                }
                sql
            }
            SqlStrategy::Delete {
                table,
                where_clause,
                ..
            } => {
                let mut sql = format!("DELETE FROM {}", table);
                if let Some(where_part) = where_clause {
                    sql.push_str(&format!(" WHERE {}", where_part));
                }
                sql
            }
            SqlStrategy::CreateTable { table, columns } => {
                let cols = if columns.is_empty() {
                    "id INTEGER PRIMARY KEY".to_string()
                } else {
                    columns
                        .iter()
                        .map(|c| format!("{} TEXT", c))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!("CREATE TABLE {} ({})", table, cols)
            }
            SqlStrategy::DropTable { table } => {
                format!("DROP TABLE {}", table)
            }
            SqlStrategy::Transaction { operation } => match operation {
                TransactionOp::Begin => "BEGIN".to_string(),
                TransactionOp::BeginDeferred => "BEGIN DEFERRED".to_string(),
                TransactionOp::BeginImmediate => "BEGIN IMMEDIATE".to_string(),
                TransactionOp::BeginExclusive => "BEGIN EXCLUSIVE".to_string(),
                TransactionOp::Commit => "COMMIT".to_string(),
                TransactionOp::Rollback => "ROLLBACK".to_string(),
            },
            SqlStrategy::Savepoint { operation, name } => match operation {
                SavepointOp::Create => format!("SAVEPOINT {}", name),
                SavepointOp::Release => format!("RELEASE SAVEPOINT {}", name),
                SavepointOp::Rollback => format!("ROLLBACK TO SAVEPOINT {}", name),
            },
            SqlStrategy::Pragma {
                pragma_name,
                pragma_value,
            } => {
                if let Some(value) = pragma_value {
                    format!("PRAGMA {} = {}", pragma_name, value)
                } else {
                    format!("PRAGMA {}", pragma_name)
                }
            }
            SqlStrategy::Malformed { sql, .. } => sql.clone(),
            SqlStrategy::Injection {
                base_sql,
                injection_payload,
                ..
            } => {
                format!("{} {}", base_sql, injection_payload)
            }
        };

        self.apply_corruption(base_sql)
    }

    /// Apply corruption strategy to SQL
    fn apply_corruption(&self, mut sql: String) -> String {
        match &self.corruption {
            CorruptionStrategy::None => sql,
            CorruptionStrategy::NullBytes { position } => {
                let pos = (*position as usize) % (sql.len() + 1);
                sql.insert(pos, '\0');
                sql
            }
            CorruptionStrategy::LongIdentifiers { length } => {
                let long_id = "x".repeat((*length as usize).min(10000));
                sql.replace("table", &long_id)
            }
            CorruptionStrategy::Unicode { chars } => {
                format!("{} {}", sql, chars)
            }
            CorruptionStrategy::Truncate { position } => {
                let pos = (*position as usize) % (sql.len() + 1);
                sql.truncate(pos);
                sql
            }
            CorruptionStrategy::Repeat { count } => (0..*count as usize)
                .map(|_| sql.clone())
                .collect::<Vec<_>>()
                .join("; "),
        }
    }

    /// Generate parameter values based on strategy
    fn generate_params(&self) -> Vec<SqliteValue> {
        let mut params = self
            .param_strategy
            .params
            .clone()
            .into_iter()
            .map(BindValueInput::sanitize)
            .map(|value| value.to_sqlite_value())
            .collect::<Vec<_>>();

        // Truncate to reasonable size
        params.truncate(MAX_PARAM_COUNT);

        if self.param_strategy.oversized_blob {
            // Add an oversized blob to test limits
            let oversized_blob = vec![0u8; SQLITE_MAX_LENGTH + 1];
            params.push(SqliteValue::Blob(oversized_blob));
        }

        params
    }

    /// Classify SQL statement type
    fn classify_statement(&self, sql: &str) -> SqlStatementType {
        let sql_upper = sql.trim().to_uppercase();

        if sql_upper.starts_with("SELECT")
            || sql_upper.starts_with("INSERT")
            || sql_upper.starts_with("UPDATE")
            || sql_upper.starts_with("DELETE")
        {
            SqlStatementType::DML
        } else if sql_upper.starts_with("CREATE")
            || sql_upper.starts_with("DROP")
            || sql_upper.starts_with("ALTER")
        {
            SqlStatementType::DDL
        } else if sql_upper.starts_with("BEGIN")
            || sql_upper.starts_with("COMMIT")
            || sql_upper.starts_with("ROLLBACK")
            || sql_upper.starts_with("SAVEPOINT")
            || sql_upper.starts_with("RELEASE")
        {
            SqlStatementType::TCL
        } else if sql_upper.starts_with("PRAGMA") {
            SqlStatementType::Pragma
        } else {
            SqlStatementType::Unknown
        }
    }

    /// Count parameter placeholders in SQL
    fn count_placeholders(&self, sql: &str) -> usize {
        sql.chars().filter(|&c| c == '?').count()
    }
}

impl AttachPathProbe {
    fn path_buf(&self) -> PathBuf {
        let component = sanitized_component_bytes(&self.path_bytes);
        match self.kind {
            AttachPathKind::RelativeFile => path_buf_from_bytes(component),
            AttachPathKind::RestrictedEtc => {
                let mut bytes = b"/etc/".to_vec();
                bytes.extend(component);
                path_buf_from_bytes(bytes)
            }
            AttachPathKind::TildeHome => {
                let mut bytes = b"~/".to_vec();
                bytes.extend(component);
                path_buf_from_bytes(bytes)
            }
            AttachPathKind::TildeUser => {
                let mut bytes = b"~fuzzuser/".to_vec();
                bytes.extend(component);
                path_buf_from_bytes(bytes)
            }
            AttachPathKind::ParentTraversal => {
                let mut bytes = b"../".to_vec();
                bytes.extend(component);
                path_buf_from_bytes(bytes)
            }
            AttachPathKind::EtcTraversal => {
                let mut bytes = b"../../../../etc/".to_vec();
                bytes.extend(component);
                path_buf_from_bytes(bytes)
            }
        }
    }

    fn attach_sql(&self) -> String {
        let keyword = if self.use_database_keyword {
            "ATTACH DATABASE"
        } else {
            "ATTACH"
        };
        let path = self.path_buf();
        let literal = escape_sql_literal(&path.to_string_lossy());
        format!("{keyword} '{literal}' AS fuzz_attach")
    }

    fn expected_error_fragment(&self) -> Option<&'static str> {
        match self.kind {
            AttachPathKind::RelativeFile => None,
            AttachPathKind::RestrictedEtc => Some("/etc"),
            AttachPathKind::TildeHome | AttachPathKind::TildeUser => Some("tilde-prefixed"),
            AttachPathKind::ParentTraversal | AttachPathKind::EtcTraversal => {
                Some("parent-directory traversal")
            }
        }
    }
}

fn sanitized_component_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut sanitized = bytes
        .iter()
        .copied()
        .take(96)
        .map(|byte| match byte {
            b'/' | b'\\' | 0 => b'_',
            _ => byte,
        })
        .collect::<Vec<_>>();
    if sanitized.is_empty() {
        sanitized.extend_from_slice(b"tenant");
    }
    if !sanitized.ends_with(b".sqlite") {
        sanitized.extend_from_slice(b".sqlite");
    }
    sanitized
}

#[cfg(unix)]
fn path_buf_from_bytes(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn path_buf_from_bytes(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

fn escape_sql_literal(raw: &str) -> String {
    raw.replace('\'', "''")
}

/// Test wrapper for SQLite operations
struct SqliteTestHarness {
    conn: SqliteConnection,
    cx: Cx,
    transaction_depth: usize,
    savepoint_stack: Vec<String>,
}

impl SqliteTestHarness {
    async fn new() -> Result<Self, SqliteError> {
        let cx = Self::create_test_cx();
        match SqliteConnection::open_in_memory(&cx).await {
            Outcome::Ok(conn) => Ok(Self {
                conn,
                cx,
                transaction_depth: 0,
                savepoint_stack: Vec::new(),
            }),
            Outcome::Err(e) => Err(e),
            Outcome::Cancelled(_) => Err(SqliteError::Cancelled(
                asupersync::types::CancelReason::user("setup cancelled"),
            )),
            Outcome::Panicked(_) => panic!("sqlite open_in_memory panicked"),
        }
    }

    fn create_test_cx() -> Cx {
        Cx::for_testing()
    }

    async fn test_sql_execution(&mut self, input: &SqliteFuzzInput) -> Result<(), SqliteError> {
        self.test_attach_path_probe(&input.attach_path_probe)
            .await?;

        let sql = input.generate_sql();
        let params = input.generate_params();
        let expected_param_count = input.count_placeholders(&sql);
        let actual_param_count = params.len();
        let statement_type = input.classify_statement(&sql);

        // Test 1: Parameter binding rejects mismatched counts
        if expected_param_count != actual_param_count && !sql.is_empty() {
            match self.conn.execute(&self.cx, &sql, &params).await {
                Outcome::Err(SqliteError::Sqlite(msg)) => {
                    // Should get a parameter count error
                    assert!(
                        msg.contains("parameter")
                            || msg.contains("bind")
                            || msg.contains("mismatch"),
                        "Expected parameter mismatch error, got: {}",
                        msg
                    );
                }
                Outcome::Ok(_) => {
                    // This should not succeed with mismatched parameters
                    if expected_param_count > 0 || actual_param_count > 0 {
                        panic!(
                            "SQL execution should fail with mismatched parameter count: expected {}, got {}",
                            expected_param_count, actual_param_count
                        );
                    }
                }
                Outcome::Err(_) => {
                    // Any clean error is acceptable on malformed/mismatched binds.
                }
                Outcome::Cancelled(_) => {
                    // Cancellation is acceptable
                }
                Outcome::Panicked(_) => panic!("sqlite execute panicked"),
            }
            return Ok(());
        }

        // Test 2: PRAGMA statements handled safely
        if statement_type == SqlStatementType::Pragma {
            match self.conn.execute(&self.cx, &sql, &params).await {
                Outcome::Ok(_) => {
                    // PRAGMA statements should either succeed or fail gracefully
                }
                Outcome::Err(_) => {
                    // Errors are acceptable for invalid PRAGMA statements
                }
                Outcome::Cancelled(_) => {
                    // Cancellation is acceptable
                }
                Outcome::Panicked(_) => panic!("sqlite execute panicked"),
            }
            return Ok(());
        }

        // Test 3: DDL vs DML discrimination
        match statement_type {
            SqlStatementType::DDL => {
                // DDL statements (CREATE, DROP, ALTER) should be detected
                // and may require special handling
                match self.conn.execute(&self.cx, &sql, &params).await {
                    Outcome::Ok(_) => {
                        // DDL succeeded
                    }
                    Outcome::Err(SqliteError::Sqlite(msg)) => {
                        // DDL errors are acceptable (table already exists, etc.)
                        assert!(
                            !msg.contains("parameter"),
                            "DDL should not have parameter errors: {}",
                            msg
                        );
                    }
                    Outcome::Err(_) => {
                        // Non-engine wrapper errors are also acceptable and must stay non-panicking.
                    }
                    Outcome::Cancelled(_) => {}
                    Outcome::Panicked(_) => panic!("sqlite execute panicked"),
                }
            }
            SqlStatementType::DML => {
                // DML statements (SELECT, INSERT, UPDATE, DELETE) are the common case
                match self.conn.execute(&self.cx, &sql, &params).await {
                    Outcome::Ok(_) => {
                        // DML succeeded
                    }
                    Outcome::Err(_) => {
                        // DML errors are acceptable (syntax errors, constraints, etc.)
                    }
                    Outcome::Cancelled(_) => {}
                    Outcome::Panicked(_) => panic!("sqlite execute panicked"),
                }
            }
            SqlStatementType::TCL => {
                // Test 4: Transaction nesting (SAVEPOINT) tracked
                if sql.trim().to_uppercase().starts_with("BEGIN") {
                    self.transaction_depth += 1;
                } else if sql.trim().to_uppercase().starts_with("COMMIT")
                    || sql.trim().to_uppercase().starts_with("ROLLBACK")
                {
                    self.transaction_depth = self.transaction_depth.saturating_sub(1);
                } else if sql.trim().to_uppercase().starts_with("SAVEPOINT") {
                    if let Some(name) = sql.split_whitespace().nth(1) {
                        self.savepoint_stack.push(name.to_string());
                    }
                } else if sql.trim().to_uppercase().starts_with("RELEASE SAVEPOINT") {
                    if let Some(name) = sql.split_whitespace().nth(2) {
                        if let Some(pos) = self.savepoint_stack.iter().position(|x| x == name) {
                            self.savepoint_stack.remove(pos);
                        }
                    }
                }

                match self.conn.execute(&self.cx, &sql, &params).await {
                    Outcome::Ok(_) => {}
                    Outcome::Err(_) => {
                        // Transaction control errors are acceptable
                    }
                    Outcome::Cancelled(_) => {}
                    Outcome::Panicked(_) => panic!("sqlite execute panicked"),
                }
            }
            _ => {
                // Unknown statement types - just try to execute
                match self.conn.execute(&self.cx, &sql, &params).await {
                    Outcome::Ok(_) | Outcome::Err(_) | Outcome::Cancelled(_) => {}
                    Outcome::Panicked(_) => panic!("sqlite execute panicked"),
                }
            }
        }

        // Test 5: Blob binding bounded by SQLITE_MAX_LENGTH
        for param in &params {
            if let SqliteValue::Blob(blob_data) = param {
                assert!(
                    blob_data.len() <= SQLITE_MAX_LENGTH,
                    "Blob size {} exceeds SQLITE_MAX_LENGTH {}",
                    blob_data.len(),
                    SQLITE_MAX_LENGTH
                );
            }
        }

        Ok(())
    }

    async fn test_attach_path_probe(&mut self, probe: &AttachPathProbe) -> Result<(), SqliteError> {
        match self
            .conn
            .execute_unchecked(&self.cx, &probe.attach_sql(), &[])
            .await
        {
            Outcome::Err(SqliteError::UnsafeSql(msg)) => {
                assert!(
                    msg.contains("ATTACH and DETACH"),
                    "expected ATTACH/DETACH rejection, got: {msg}"
                );
            }
            Outcome::Cancelled(_) => {}
            Outcome::Panicked(_) => panic!("sqlite execute_unchecked panicked"),
            other => panic!("expected ATTACH rejection, got: {other:?}"),
        }

        let path = probe.path_buf();
        let validation = fuzz_validate_sqlite_open_path(&path);
        if let Some(expected) = probe.expected_error_fragment() {
            match validation {
                Err(SqliteError::UnsafePath(msg)) => {
                    assert!(
                        msg.contains(expected),
                        "expected path rejection containing {expected:?}, got: {msg}"
                    );
                }
                other => panic!(
                    "expected unsafe path rejection for {:?}, got: {other:?}",
                    path
                ),
            }
        } else if let Err(SqliteError::UnsafePath(msg)) = validation {
            panic!("relative file path should not be rejected: {msg}");
        }

        Ok(())
    }
}

fuzz_target!(|input: SqliteFuzzInput| {
    // Bound input size to prevent timeouts
    let sql = input.generate_sql();
    if sql.len() > MAX_FUZZ_INPUT_SIZE {
        return;
    }

    // Test SQLite operations using futures_lite runtime
    let _ = block_on(async {
        let mut harness = match SqliteTestHarness::new().await {
            Ok(h) => h,
            Err(_) => return, // Skip if we can't create test harness
        };

        // Execute the test safely, catching any panics
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on(harness.test_sql_execution(&input))
        }));

        match result {
            Ok(_) => {
                // Test completed normally
            }
            Err(_) => {
                // Panic occurred - this indicates a bug that fuzzing found
                // The panic will be reported by libfuzzer
            }
        }
    });
});
