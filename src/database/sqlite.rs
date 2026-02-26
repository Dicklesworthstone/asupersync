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
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::{Arc, OnceLock};

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
    #[must_use]
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(v) => Some(*v),
            _ => None,
        }
    }

    /// Tries to get the value as a real (floating point).
    #[must_use]
    pub fn as_real(&self) -> Option<f64> {
        match self {
            Self::Real(v) => Some(*v),
            Self::Integer(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Tries to get the value as text.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v),
            _ => None,
        }
    }

    /// Tries to get the value as a blob.
    #[must_use]
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
    columns: Arc<BTreeMap<String, usize>>,
    /// Row values.
    values: Vec<SqliteValue>,
}

impl SqliteRow {
    /// Creates a new row from column names and values.
    fn new(columns: Arc<BTreeMap<String, usize>>, values: Vec<SqliteValue>) -> Self {
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
            .field("open", &self.inner.lock().conn.is_some())
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

        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = tx.reserve(cx);

        let handle = pool.spawn(move || {
            let result =
                rusqlite::Connection::open(&path).map_err(|e| SqliteError::Sqlite(e.to_string()));
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(conn)) => Outcome::Ok(Self {
                inner: Arc::new(Mutex::new(SqliteConnectionInner::new(conn))),
                pool: pool_clone,
            }),
            Ok(Err(e)) => Outcome::Err(e),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                handle.cancel();
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(crate::channel::oneshot::RecvError::Closed) => {
                Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string()))
            }
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

        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = tx.reserve(cx);

        let handle = pool.spawn(move || {
            let result = rusqlite::Connection::open_in_memory()
                .map_err(|e| SqliteError::Sqlite(e.to_string()));
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(conn)) => Outcome::Ok(Self {
                inner: Arc::new(Mutex::new(SqliteConnectionInner::new(conn))),
                pool: pool_clone,
            }),
            Ok(Err(e)) => Outcome::Err(e),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                handle.cancel();
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(crate::channel::oneshot::RecvError::Closed) => {
                Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string()))
            }
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

        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = tx.reserve(cx);

        let handle = self.pool.spawn(move || {
            let result = (|| {
                let guard = inner.lock();
                let conn = guard.get()?;

                let params_refs: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

                conn.execute(&sql, params_refs.as_slice())
                    .map(|n| n as u64)
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))
            })();
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(n)) => Outcome::Ok(n),
            Ok(Err(e)) => Outcome::Err(e),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                handle.cancel();
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(crate::channel::oneshot::RecvError::Closed) => {
                Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string()))
            }
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

        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = tx.reserve(cx);

        let handle = self.pool.spawn(move || {
            let result = (|| {
                let guard = inner.lock();
                let conn = guard.get()?;
                conn.execute_batch(&sql)
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))
            })();
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(())) => Outcome::Ok(()),
            Ok(Err(e)) => Outcome::Err(e),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                handle.cancel();
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(crate::channel::oneshot::RecvError::Closed) => {
                Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string()))
            }
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

        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = tx.reserve(cx);

        let handle = self.pool.spawn(move || {
            let result = (|| {
                let guard = inner.lock();
                let conn = guard.get()?;

                let params_refs: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

                // Build column map
                let column_names: Vec<String> = stmt
                    .column_names()
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                let columns: BTreeMap<String, usize> = column_names
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
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(rows)) => Outcome::Ok(rows),
            Ok(Err(e)) => Outcome::Err(e),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                handle.cancel();
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(crate::channel::oneshot::RecvError::Closed) => {
                Outcome::Err(SqliteError::Sqlite("failed to receive result".to_string()))
            }
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
        let mut guard = self.inner.lock();
        guard.close();
        Ok(())
    }

    /// Returns true if the connection is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.inner.lock().conn.is_some()
    }
}

/// A SQLite transaction.
///
/// The transaction will be rolled back on drop if not committed.
pub struct SqliteTransaction<'a> {
    conn: &'a SqliteConnection,
    finished: bool,
}

impl SqliteTransaction<'_> {
    /// Commits the transaction.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn commit(mut self, cx: &Cx) -> Outcome<(), SqliteError> {
        if self.finished {
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        match self.conn.execute(cx, "COMMIT", &[]).await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
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
        match self.conn.execute(cx, "ROLLBACK", &[]).await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
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
            // Synchronous best-effort rollback on drop.
            // This must complete before the connection is reusable to prevent
            // a race where a subsequent BEGIN arrives before the ROLLBACK.
            let guard = self.conn.inner.lock();
            if let Ok(conn) = guard.get() {
                let _ = conn.execute("ROLLBACK", []);
            }
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
            Self::Null => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Null)),
            Self::Integer(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Integer(*v))),
            Self::Real(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Real(*v))),
            Self::Text(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Text(v.clone()))),
            Self::Blob(v) => Ok(ToSqlOutput::Owned(rusqlite::types::Value::Blob(v.clone()))),
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
        assert_eq!(SqliteValue::Real(3.5).to_string(), "3.5");
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

        assert_eq!(SqliteValue::Real(3.5).as_real(), Some(3.5));
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
        let mut columns = BTreeMap::new();
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

    // ---- SqliteError Display ----

    #[test]
    fn sqlite_error_display_sqlite() {
        let err = SqliteError::Sqlite("connection refused".into());
        assert_eq!(err.to_string(), "SQLite error: connection refused");
    }

    #[test]
    fn sqlite_error_display_cancelled() {
        let err = SqliteError::Cancelled(CancelReason::user("timeout"));
        let msg = err.to_string();
        assert!(msg.starts_with("SQLite operation cancelled:"), "{msg}");
    }

    #[test]
    fn sqlite_error_display_connection_closed() {
        assert_eq!(
            SqliteError::ConnectionClosed.to_string(),
            "SQLite connection is closed"
        );
    }

    #[test]
    fn sqlite_error_display_column_not_found() {
        let err = SqliteError::ColumnNotFound("missing_col".into());
        assert_eq!(err.to_string(), "Column not found: missing_col");
    }

    #[test]
    fn sqlite_error_display_type_mismatch() {
        let err = SqliteError::TypeMismatch {
            column: "age".into(),
            expected: "integer",
            actual: "Text(\"hello\")".into(),
        };
        assert_eq!(
            err.to_string(),
            "Type mismatch for column age: expected integer, got Text(\"hello\")"
        );
    }

    #[test]
    fn sqlite_error_display_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = SqliteError::Io(io_err);
        assert!(err.to_string().starts_with("SQLite I/O error:"), "{err}");
    }

    #[test]
    fn sqlite_error_display_transaction_finished() {
        assert_eq!(
            SqliteError::TransactionFinished.to_string(),
            "Transaction already finished"
        );
    }

    #[test]
    fn sqlite_error_display_lock_poisoned() {
        assert_eq!(
            SqliteError::LockPoisoned.to_string(),
            "SQLite connection lock poisoned"
        );
    }

    // ---- SqliteError source() ----

    #[test]
    fn sqlite_error_source_io_returns_some() {
        use std::error::Error;
        let io_err = std::io::Error::other("disk failure");
        let err = SqliteError::Io(io_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn sqlite_error_source_non_io_returns_none() {
        use std::error::Error;
        assert!(SqliteError::ConnectionClosed.source().is_none());
        assert!(SqliteError::Sqlite("oops".into()).source().is_none());
        assert!(SqliteError::LockPoisoned.source().is_none());
        assert!(SqliteError::TransactionFinished.source().is_none());
        assert!(SqliteError::ColumnNotFound("x".into()).source().is_none());
    }

    // ---- SqliteError From<io::Error> ----

    #[test]
    fn sqlite_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err: SqliteError = io_err.into();
        assert!(matches!(err, SqliteError::Io(_)));
    }

    // ---- SqliteValue PartialEq ----

    #[test]
    fn sqlite_value_partial_eq() {
        assert_eq!(SqliteValue::Null, SqliteValue::Null);
        assert_eq!(SqliteValue::Integer(10), SqliteValue::Integer(10));
        assert_ne!(SqliteValue::Integer(10), SqliteValue::Integer(20));
        assert_eq!(SqliteValue::Real(1.5), SqliteValue::Real(1.5));
        assert_eq!(SqliteValue::Text("a".into()), SqliteValue::Text("a".into()));
        assert_ne!(SqliteValue::Text("a".into()), SqliteValue::Text("b".into()));
        assert_eq!(SqliteValue::Blob(vec![1, 2]), SqliteValue::Blob(vec![1, 2]));
        assert_ne!(SqliteValue::Null, SqliteValue::Integer(0));
    }

    // ---- SqliteValue accessor edge cases ----

    #[test]
    fn sqlite_value_as_real_returns_none_for_text() {
        assert_eq!(SqliteValue::Text("nope".into()).as_real(), None);
    }

    #[test]
    fn sqlite_value_as_real_returns_none_for_blob() {
        assert_eq!(SqliteValue::Blob(vec![1]).as_real(), None);
    }

    #[test]
    fn sqlite_value_as_real_returns_none_for_null() {
        assert_eq!(SqliteValue::Null.as_real(), None);
    }

    #[test]
    fn sqlite_value_as_integer_returns_none_for_real() {
        assert_eq!(SqliteValue::Real(3.5).as_integer(), None);
    }

    #[test]
    fn sqlite_value_as_text_returns_none_for_blob() {
        assert_eq!(SqliteValue::Blob(vec![0]).as_text(), None);
    }

    #[test]
    fn sqlite_value_as_blob_returns_none_for_text() {
        assert_eq!(SqliteValue::Text("x".into()).as_blob(), None);
    }

    #[test]
    fn sqlite_value_as_blob_returns_none_for_null() {
        assert_eq!(SqliteValue::Null.as_blob(), None);
    }

    #[test]
    fn sqlite_value_display_empty_blob() {
        assert_eq!(SqliteValue::Blob(vec![]).to_string(), "<blob 0 bytes>");
    }

    #[test]
    fn sqlite_value_display_negative_integer() {
        assert_eq!(SqliteValue::Integer(-99).to_string(), "-99");
    }

    // ---- SqliteRow ----

    fn make_test_sqlite_row(names: &[&str], values: Vec<SqliteValue>) -> SqliteRow {
        let mut columns = BTreeMap::new();
        for (i, name) in names.iter().enumerate() {
            columns.insert(name.to_string(), i);
        }
        SqliteRow::new(Arc::new(columns), values)
    }

    #[test]
    fn sqlite_row_get_idx_valid() {
        let row = make_test_sqlite_row(
            &["a", "b"],
            vec![SqliteValue::Integer(1), SqliteValue::Text("two".into())],
        );
        assert_eq!(row.get_idx(0).unwrap(), &SqliteValue::Integer(1));
        assert_eq!(row.get_idx(1).unwrap(), &SqliteValue::Text("two".into()));
    }

    #[test]
    fn sqlite_row_get_idx_out_of_bounds() {
        let row = make_test_sqlite_row(&["a"], vec![SqliteValue::Null]);
        assert!(row.get_idx(5).is_err());
    }

    #[test]
    fn sqlite_row_get_f64_success() {
        let row = make_test_sqlite_row(&["val"], vec![SqliteValue::Real(3.5)]);
        assert!((row.get_f64("val").unwrap() - 3.5).abs() < f64::EPSILON);
    }

    #[test]
    fn sqlite_row_get_f64_widens_from_integer() {
        let row = make_test_sqlite_row(&["val"], vec![SqliteValue::Integer(7)]);
        assert!((row.get_f64("val").unwrap() - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn sqlite_row_get_f64_type_mismatch() {
        let row = make_test_sqlite_row(&["name"], vec![SqliteValue::Text("alice".into())]);
        let err = row.get_f64("name").unwrap_err();
        assert!(matches!(err, SqliteError::TypeMismatch { .. }));
    }

    #[test]
    fn sqlite_row_get_blob_success() {
        let row = make_test_sqlite_row(&["data"], vec![SqliteValue::Blob(vec![0xDE, 0xAD])]);
        assert_eq!(row.get_blob("data").unwrap(), &[0xDE, 0xAD]);
    }

    #[test]
    fn sqlite_row_get_blob_type_mismatch() {
        let row = make_test_sqlite_row(&["num"], vec![SqliteValue::Integer(42)]);
        let err = row.get_blob("num").unwrap_err();
        assert!(matches!(err, SqliteError::TypeMismatch { .. }));
    }

    #[test]
    fn sqlite_row_get_i64_type_mismatch() {
        let row = make_test_sqlite_row(&["name"], vec![SqliteValue::Text("not_a_number".into())]);
        let err = row.get_i64("name").unwrap_err();
        assert!(matches!(err, SqliteError::TypeMismatch { .. }));
    }

    #[test]
    fn sqlite_row_get_str_type_mismatch() {
        let row = make_test_sqlite_row(&["id"], vec![SqliteValue::Integer(1)]);
        let err = row.get_str("id").unwrap_err();
        assert!(matches!(err, SqliteError::TypeMismatch { .. }));
    }

    #[test]
    fn sqlite_row_column_names() {
        let row = make_test_sqlite_row(
            &["alpha", "beta", "gamma"],
            vec![SqliteValue::Null, SqliteValue::Null, SqliteValue::Null],
        );
        let names: Vec<&str> = row.column_names().collect();
        // BTreeMap yields sorted order
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn sqlite_row_empty() {
        let row = make_test_sqlite_row(&[], vec![]);
        assert_eq!(row.len(), 0);
        assert!(row.is_empty());
        assert!(row.get_idx(0).is_err());
        assert_eq!(row.column_names().count(), 0);
    }

    #[test]
    fn sqlite_row_get_column_not_found() {
        let row = make_test_sqlite_row(&["exists"], vec![SqliteValue::Integer(1)]);
        let err = row.get("nope").unwrap_err();
        assert!(matches!(err, SqliteError::ColumnNotFound(_)));
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

    #[test]
    fn transaction_commit_cancelled_does_not_mark_finished_before_commit_runs() {
        let cx = create_test_cx();
        let cancelled_cx = create_test_cx();
        cancelled_cx.cancel_fast(crate::types::CancelKind::User);

        block_on(async {
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute_batch(&cx, "CREATE TABLE t (id INTEGER PRIMARY KEY);")
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("create table failed: {other:?}"),
            }

            let tx = match conn.begin(&cx).await {
                Outcome::Ok(tx) => tx,
                _ => panic!("begin failed"),
            };

            match tx.commit(&cancelled_cx).await {
                Outcome::Cancelled(_) => {}
                other => panic!("expected cancelled commit, got: {other:?}"),
            }

            // The cancelled commit path must keep `finished=false` so Drop can enqueue
            // a best-effort rollback; otherwise the connection stays in-transaction.
            for _ in 0..8 {
                if conn
                    .inner
                    .lock()
                    .get()
                    .is_ok_and(rusqlite::Connection::is_autocommit)
                {
                    break;
                }

                match conn.query(&cx, "SELECT 1", &[]).await {
                    Outcome::Ok(_) => {}
                    other => panic!("probe query failed: {other:?}"),
                }
            }

            assert!(
                conn.inner
                    .lock()
                    .get()
                    .is_ok_and(rusqlite::Connection::is_autocommit),
                "connection should return to autocommit after cancelled commit drop path"
            );
        });
    }
}
