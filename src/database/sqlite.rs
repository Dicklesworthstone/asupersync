//! SQLite async wrapper with blocking pool integration.
//!
//! This module provides an async wrapper around SQLite using the blocking pool
//! for synchronous operations, with full Cx integration and cancel-correct semantics.
//!
//! # Design
//!
//! SQLite is inherently synchronous (single file, no network protocol). We wrap
//! it with the blocking pool to provide async semantics while maintaining correctness.
//! All operations integrate with [`Cx`] for checkpointing and cancellation.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::database::SqliteConnection;
//!
//! async fn example(cx: &Cx) -> Result<(), SqliteError> {
//!     let conn = SqliteConnection::open_in_memory(cx).await?;
//!
//!     conn.execute_batch(cx, "
//!         CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT);
//!         INSERT INTO users (name) VALUES ('Alice');
//!     ").await?;
//!
//!     let rows = conn.query(cx, "SELECT * FROM users", &[]).await?;
//!     for row in rows {
//!         println!("User: {}", row.get_str("name")?);
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! [`Cx`]: crate::cx::Cx

use crate::cx::Cx;
use crate::runtime::blocking_pool::{BlockingPool, BlockingPoolHandle};
use crate::types::{CancelReason, Outcome};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

/// Global blocking pool for SQLite operations.
///
/// Keep the pool itself alive for the process lifetime. Storing only
/// `BlockingPoolHandle` would drop the pool immediately and put the
/// handle into permanent shutdown state.
static SQLITE_POOL: OnceLock<BlockingPool> = OnceLock::new();

fn get_sqlite_pool() -> BlockingPoolHandle {
    SQLITE_POOL.get_or_init(|| BlockingPool::new(1, 4)).handle()
}

/// Error type for SQLite operations.
#[derive(Debug)]
pub enum SqliteError {
    /// SQLite error from rusqlite.
    Sqlite(String),
    /// Operation was cancelled.
    Cancelled(CancelReason),
    /// Connection is closed.
    ConnectionClosed,
    /// Column not found.
    ColumnNotFound(String),
    /// Type mismatch when accessing column.
    TypeMismatch {
        /// Column name or index.
        column: String,
        /// Expected type.
        expected: &'static str,
        /// Actual type.
        actual: String,
    },
    /// I/O error.
    Io(std::io::Error),
    /// Transaction already committed or rolled back.
    TransactionFinished,
    /// Lock poisoned.
    LockPoisoned,
}

impl fmt::Display for SqliteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(msg) => write!(f, "SQLite error: {msg}"),
            Self::Cancelled(reason) => write!(f, "SQLite operation cancelled: {reason:?}"),
            Self::ConnectionClosed => write!(f, "SQLite connection is closed"),
            Self::ColumnNotFound(name) => write!(f, "Column not found: {name}"),
            Self::TypeMismatch {
                column,
                expected,
                actual,
            } => write!(
                f,
                "Type mismatch for column {column}: expected {expected}, got {actual}"
            ),
            Self::Io(e) => write!(f, "SQLite I/O error: {e}"),
            Self::TransactionFinished => write!(f, "Transaction already finished"),
            Self::LockPoisoned => write!(f, "SQLite connection lock poisoned"),
        }
    }
}

impl std::error::Error for SqliteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SqliteError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// A value from a SQLite row.
#[derive(Debug, Clone, PartialEq)]
pub enum SqliteValue {
    /// NULL value.
    Null,
    /// Integer value.
    Integer(i64),
    /// Real (floating point) value.
    Real(f64),
    /// Text value.
    Text(String),
    /// Blob (binary) value.
    Blob(Vec<u8>),
}

impl SqliteValue {
    /// Returns true if this is a NULL value.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Tries to get the value as an integer.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Tries to get the value as a real (floating point).
    pub fn as_real(&self) -> Option<f64> {
        match self {
            Self::Real(v) => Some(*v),
            Self::Integer(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Tries to get the value as text.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v),
            _ => None,
        }
    }

    /// Tries to get the value as a blob.
    pub fn as_blob(&self) -> Option<&[u8]> {
        match self {
            Self::Blob(v) => Some(v),
            _ => None,
        }
    }
}

impl fmt::Display for SqliteValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "NULL"),
            Self::Integer(v) => write!(f, "{v}"),
            Self::Real(v) => write!(f, "{v}"),
            Self::Text(v) => write!(f, "{v}"),
            Self::Blob(v) => write!(f, "<blob {} bytes>", v.len()),
        }
    }
}

/// A row from a SQLite query result.
#[derive(Debug, Clone)]
pub struct SqliteRow {
    /// Column names to indices mapping.
    columns: Arc<HashMap<String, usize>>,
    /// Row values.
    values: Vec<SqliteValue>,
}

impl SqliteRow {
    /// Creates a new row from column names and values.
    fn new(columns: Arc<HashMap<String, usize>>, values: Vec<SqliteValue>) -> Self {
        Self { columns, values }
    }

    /// Gets a value by column name.
    pub fn get(&self, column: &str) -> Result<&SqliteValue, SqliteError> {
        let idx = self
            .columns
            .get(column)
            .ok_or_else(|| SqliteError::ColumnNotFound(column.to_string()))?;
        self.values
            .get(*idx)
            .ok_or_else(|| SqliteError::ColumnNotFound(column.to_string()))
    }

    /// Gets a value by column index.
    pub fn get_idx(&self, idx: usize) -> Result<&SqliteValue, SqliteError> {
        self.values
            .get(idx)
            .ok_or_else(|| SqliteError::ColumnNotFound(format!("index {idx}")))
    }

    /// Gets an integer value by column name.
    pub fn get_i64(&self, column: &str) -> Result<i64, SqliteError> {
        self.get(column)?
            .as_integer()
            .ok_or_else(|| SqliteError::TypeMismatch {
                column: column.to_string(),
                expected: "integer",
                actual: format!("{:?}", self.get(column).unwrap()),
            })
    }

    /// Gets a real value by column name.
    pub fn get_f64(&self, column: &str) -> Result<f64, SqliteError> {
        self.get(column)?
            .as_real()
            .ok_or_else(|| SqliteError::TypeMismatch {
                column: column.to_string(),
                expected: "real",
                actual: format!("{:?}", self.get(column).unwrap()),
            })
    }

    /// Gets a text value by column name.
    pub fn get_str(&self, column: &str) -> Result<&str, SqliteError> {
        self.get(column)?
            .as_text()
            .ok_or_else(|| SqliteError::TypeMismatch {
                column: column.to_string(),
                expected: "text",
                actual: format!("{:?}", self.get(column).unwrap()),
            })
    }

    /// Gets a blob value by column name.
    pub fn get_blob(&self, column: &str) -> Result<&[u8], SqliteError> {
        self.get(column)?
            .as_blob()
            .ok_or_else(|| SqliteError::TypeMismatch {
                column: column.to_string(),
                expected: "blob",
                actual: format!("{:?}", self.get(column).unwrap()),
            })
    }

    /// Returns the number of columns in this row.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if this row has no columns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns an iterator over column names.
    pub fn column_names(&self) -> impl Iterator<Item = &str> {
        self.columns.keys().map(String::as_str)
    }
}

/// Inner connection state.
struct SqliteConnectionInner {
    /// The actual SQLite connection. None if closed.
    conn: Option<rusqlite::Connection>,
}

impl SqliteConnectionInner {
    fn new(conn: rusqlite::Connection) -> Self {
        Self { conn: Some(conn) }
    }

    fn get(&self) -> Result<&rusqlite::Connection, SqliteError> {
        self.conn.as_ref().ok_or(SqliteError::ConnectionClosed)
    }

    fn get_mut(&mut self) -> Result<&mut rusqlite::Connection, SqliteError> {
        self.conn.as_mut().ok_or(SqliteError::ConnectionClosed)
    }

    fn close(&mut self) {
        self.conn = None;
    }
}

/// An async SQLite connection using the blocking pool.
///
/// All operations are executed on the blocking pool to avoid blocking
/// the async runtime. Operations integrate with [`Cx`] for checkpointing
/// and cancellation.
///
/// [`Cx`]: crate::cx::Cx
pub struct SqliteConnection {
    /// Inner connection state (behind Arc<Mutex> for sharing).
    inner: Arc<Mutex<SqliteConnectionInner>>,
    /// Handle to the blocking pool.
    pool: BlockingPoolHandle,
}

impl fmt::Debug for SqliteConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteConnection")
            .field(
                "open",
                &self.inner.lock().map(|g| g.conn.is_some()).unwrap_or(false),
            )
            .finish()
    }
}

impl SqliteConnection {
    /// Opens a SQLite database at the given path.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    /// If cancelled during execution, the connection may or may not be opened.
    pub async fn open(cx: &Cx, path: impl AsRef<Path>) -> Outcome<Self, SqliteError> {
        // Check for cancellation
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let path = path.as_ref().to_path_buf();
        let pool = get_sqlite_pool();
        let pool_clone = pool.clone();

        // Use oneshot channel pattern for result
        let (tx, rx) = std::sync::mpsc::channel();

        let handle = pool.spawn(move || {
            let result =
                rusqlite::Connection::open(&path).map_err(|e| SqliteError::Sqlite(e.to_string()));
            let _ = tx.send(result);
        });

        // Wait for completion (could be improved with async notification)
        handle.wait();

        match rx.recv() {
            Ok(Ok(conn)) => Outcome::Ok(Self {
                inner: Arc::new(Mutex::new(SqliteConnectionInner::new(conn))),
                pool: pool_clone,
            }),
            Ok(Err(e)) => Outcome::Err(e),
            Err(_) => Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string())),
        }
    }

    /// Opens an in-memory SQLite database.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn open_in_memory(cx: &Cx) -> Outcome<Self, SqliteError> {
        // Check for cancellation
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let pool = get_sqlite_pool();
        let pool_clone = pool.clone();

        let (tx, rx) = std::sync::mpsc::channel();

        let handle = pool.spawn(move || {
            let result = rusqlite::Connection::open_in_memory()
                .map_err(|e| SqliteError::Sqlite(e.to_string()));
            let _ = tx.send(result);
        });

        handle.wait();

        match rx.recv() {
            Ok(Ok(conn)) => Outcome::Ok(Self {
                inner: Arc::new(Mutex::new(SqliteConnectionInner::new(conn))),
                pool: pool_clone,
            }),
            Ok(Err(e)) => Outcome::Err(e),
            Err(_) => Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string())),
        }
    }

    /// Executes a SQL statement that returns no rows.
    ///
    /// Returns the number of rows affected.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    /// If cancelled during execution, the statement may or may not complete.
    pub async fn execute(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<u64, SqliteError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let inner = Arc::clone(&self.inner);
        let sql = sql.to_string();
        let params: Vec<SqliteValue> = params.to_vec();

        let (tx, rx) = std::sync::mpsc::channel();

        let handle = self.pool.spawn(move || {
            let result = (|| {
                let guard = inner.lock().map_err(|_| SqliteError::LockPoisoned)?;
                let conn = guard.get()?;

                let params_refs: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

                conn.execute(&sql, params_refs.as_slice())
                    .map(|n| n as u64)
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))
            })();
            let _ = tx.send(result);
        });

        handle.wait();

        match rx.recv() {
            Ok(Ok(n)) => Outcome::Ok(n),
            Ok(Err(e)) => Outcome::Err(e),
            Err(_) => Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string())),
        }
    }

    /// Executes a batch of SQL statements.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn execute_batch(&self, cx: &Cx, sql: &str) -> Outcome<(), SqliteError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let inner = Arc::clone(&self.inner);
        let sql = sql.to_string();

        let (tx, rx) = std::sync::mpsc::channel();

        let handle = self.pool.spawn(move || {
            let result = (|| {
                let guard = inner.lock().map_err(|_| SqliteError::LockPoisoned)?;
                let conn = guard.get()?;
                conn.execute_batch(&sql)
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))
            })();
            let _ = tx.send(result);
        });

        handle.wait();

        match rx.recv() {
            Ok(Ok(())) => Outcome::Ok(()),
            Ok(Err(e)) => Outcome::Err(e),
            Err(_) => Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string())),
        }
    }

    /// Executes a query and returns all rows.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn query(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Vec<SqliteRow>, SqliteError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let inner = Arc::clone(&self.inner);
        let sql = sql.to_string();
        let params: Vec<SqliteValue> = params.to_vec();

        let (tx, rx) = std::sync::mpsc::channel();

        let handle = self.pool.spawn(move || {
            let result = (|| {
                let guard = inner.lock().map_err(|_| SqliteError::LockPoisoned)?;
                let conn = guard.get()?;

                let params_refs: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

                // Build column map
                let column_names: Vec<String> =
                    stmt.column_names().iter().map(|s| s.to_string()).collect();
                let columns: HashMap<String, usize> = column_names
                    .iter()
                    .enumerate()
                    .map(|(i, name)| (name.clone(), i))
                    .collect();
                let columns = Arc::new(columns);

                let column_count = stmt.column_count();

                let mut rows = stmt
                    .query(params_refs.as_slice())
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

                let mut result = Vec::new();
                while let Some(row) = rows
                    .next()
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))?
                {
                    let mut values = Vec::with_capacity(column_count);
                    for i in 0..column_count {
                        let value = row
                            .get_ref(i)
                            .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
                        values.push(convert_value(value));
                    }
                    result.push(SqliteRow::new(Arc::clone(&columns), values));
                }

                Ok(result)
            })();
            let _ = tx.send(result);
        });

        handle.wait();

        match rx.recv() {
            Ok(Ok(rows)) => Outcome::Ok(rows),
            Ok(Err(e)) => Outcome::Err(e),
            Err(_) => Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string())),
        }
    }

    /// Executes a query and returns the first row, if any.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn query_row(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Option<SqliteRow>, SqliteError> {
        match self.query(cx, sql, params).await {
            Outcome::Ok(mut rows) => {
                if rows.is_empty() {
                    Outcome::Ok(None)
                } else {
                    Outcome::Ok(Some(rows.remove(0)))
                }
            }
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Begins a new transaction.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn begin(&self, cx: &Cx) -> Outcome<SqliteTransaction<'_>, SqliteError> {
        match self.execute(cx, "BEGIN", &[]).await {
            Outcome::Ok(_) => Outcome::Ok(SqliteTransaction {
                conn: self,
                finished: false,
            }),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Begins an immediate transaction (acquires write lock immediately).
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn begin_immediate(&self, cx: &Cx) -> Outcome<SqliteTransaction<'_>, SqliteError> {
        match self.execute(cx, "BEGIN IMMEDIATE", &[]).await {
            Outcome::Ok(_) => Outcome::Ok(SqliteTransaction {
                conn: self,
                finished: false,
            }),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Begins an exclusive transaction (acquires exclusive lock immediately).
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn begin_exclusive(&self, cx: &Cx) -> Outcome<SqliteTransaction<'_>, SqliteError> {
        match self.execute(cx, "BEGIN EXCLUSIVE", &[]).await {
            Outcome::Ok(_) => Outcome::Ok(SqliteTransaction {
                conn: self,
                finished: false,
            }),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Closes the connection.
    pub fn close(&self) -> Result<(), SqliteError> {
        let mut guard = self.inner.lock().map_err(|_| SqliteError::LockPoisoned)?;
        guard.close();
        Ok(())
    }

    /// Returns true if the connection is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.inner.lock().map(|g| g.conn.is_some()).unwrap_or(false)
    }
}

/// A SQLite transaction.
///
/// The transaction will be rolled back on drop if not committed.
pub struct SqliteTransaction<'a> {
    conn: &'a SqliteConnection,
    finished: bool,
}

impl<'a> SqliteTransaction<'a> {
    /// Commits the transaction.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn commit(mut self, cx: &Cx) -> Outcome<(), SqliteError> {
        if self.finished {
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        self.finished = true;
        match self.conn.execute(cx, "COMMIT", &[]).await {
            Outcome::Ok(_) => Outcome::Ok(()),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Rolls back the transaction.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), SqliteError> {
        if self.finished {
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        self.finished = true;
        match self.conn.execute(cx, "ROLLBACK", &[]).await {
            Outcome::Ok(_) => Outcome::Ok(()),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Executes a SQL statement within this transaction.
    pub async fn execute(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<u64, SqliteError> {
        if self.finished {
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        self.conn.execute(cx, sql, params).await
    }

    /// Executes a query within this transaction.
    pub async fn query(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Vec<SqliteRow>, SqliteError> {
        if self.finished {
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        self.conn.query(cx, sql, params).await
    }
}

impl Drop for SqliteTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Best-effort rollback on drop
            // We can't await here, so we do a blocking operation
            let inner = Arc::clone(&self.conn.inner);
            let pool = self.conn.pool.clone();

            let handle = pool.spawn(move || {
                if let Ok(guard) = inner.lock() {
                    if let Ok(conn) = guard.get() {
                        let _ = conn.execute("ROLLBACK", []);
                    }
                }
            });

            // Wait for rollback to complete (best-effort)
            handle.wait();
        }
    }
}

/// Converts a rusqlite value reference to our SqliteValue.
fn convert_value(value: rusqlite::types::ValueRef<'_>) -> SqliteValue {
    match value {
        rusqlite::types::ValueRef::Null => SqliteValue::Null,
        rusqlite::types::ValueRef::Integer(v) => SqliteValue::Integer(v),
        rusqlite::types::ValueRef::Real(v) => SqliteValue::Real(v),
        rusqlite::types::ValueRef::Text(v) => {
            SqliteValue::Text(String::from_utf8_lossy(v).to_string())
        }
        rusqlite::types::ValueRef::Blob(v) => SqliteValue::Blob(v.to_vec()),
    }
}

// Implement ToSql for SqliteValue to use it as a parameter
impl rusqlite::ToSql for SqliteValue {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        use rusqlite::types::ToSqlOutput;
        match self {
            SqliteValue::Null => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Null)),
            SqliteValue::Integer(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Integer(*v))),
            SqliteValue::Real(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Real(*v))),
            SqliteValue::Text(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Text(v.clone()))),
            SqliteValue::Blob(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Blob(v.clone()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cx::Cx;
    use crate::types::Budget;
    use crate::types::Outcome;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use futures_lite::future::block_on;

    fn create_test_cx() -> Cx {
        Cx::new(
            RegionId::from_arena(ArenaIndex::new(0, 0)),
            TaskId::from_arena(ArenaIndex::new(0, 0)),
            Budget::INFINITE,
        )
    }

    #[test]
    fn test_sqlite_value_display() {
        assert_eq!(SqliteValue::Null.to_string(), "NULL");
        assert_eq!(SqliteValue::Integer(42).to_string(), "42");
        assert_eq!(SqliteValue::Real(3.14).to_string(), "3.14");
        assert_eq!(SqliteValue::Text("hello".to_string()).to_string(), "hello");
        assert_eq!(
            SqliteValue::Blob(vec![1, 2, 3]).to_string(),
            "<blob 3 bytes>"
        );
    }

    #[test]
    fn test_sqlite_value_accessors() {
        assert!(SqliteValue::Null.is_null());
        assert!(!SqliteValue::Integer(42).is_null());

        assert_eq!(SqliteValue::Integer(42).as_integer(), Some(42));
        assert_eq!(SqliteValue::Text("hi".to_string()).as_integer(), None);

        assert_eq!(SqliteValue::Real(3.14).as_real(), Some(3.14));
        assert_eq!(SqliteValue::Integer(42).as_real(), Some(42.0));

        assert_eq!(
            SqliteValue::Text("hello".to_string()).as_text(),
            Some("hello")
        );
        assert_eq!(SqliteValue::Integer(42).as_text(), None);

        assert_eq!(
            SqliteValue::Blob(vec![1, 2, 3]).as_blob(),
            Some(&[1, 2, 3][..])
        );
    }

    #[test]
    fn test_sqlite_row_accessors() {
        let mut columns = HashMap::new();
        columns.insert("id".to_string(), 0);
        columns.insert("name".to_string(), 1);
        let columns = Arc::new(columns);

        let values = vec![
            SqliteValue::Integer(1),
            SqliteValue::Text("Alice".to_string()),
        ];
        let row = SqliteRow::new(columns, values);

        assert_eq!(row.len(), 2);
        assert!(!row.is_empty());
        assert_eq!(row.get_i64("id").unwrap(), 1);
        assert_eq!(row.get_str("name").unwrap(), "Alice");
        assert!(row.get("missing").is_err());
    }

    #[test]
    fn test_open_in_memory_exec_query_round_trip() {
        let cx = create_test_cx();

        block_on(async {
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute_batch(&cx, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);")
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("create table failed: {other:?}"),
            }

            match conn
                .execute(
                    &cx,
                    "INSERT INTO t(name) VALUES (?1)",
                    &[SqliteValue::Text("alice".to_string())],
                )
                .await
            {
                Outcome::Ok(1) => {}
                other => panic!("insert failed: {other:?}"),
            }

            let rows = match conn.query(&cx, "SELECT name FROM t", &[]).await {
                Outcome::Ok(rows) => rows,
                other => panic!("query failed: {other:?}"),
            };

            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].get_str("name").unwrap(), "alice");
        });
    }
}
