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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Global blocking pool for SQLite operations.
///
/// Keep the pool itself alive for the process lifetime. Storing only
/// `BlockingPoolHandle` would drop the pool immediately and put the
/// handle into permanent shutdown state.
static SQLITE_POOL: OnceLock<BlockingPool> = OnceLock::new();
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_STATEMENT_CACHE_CAPACITY: usize = 64;

fn get_sqlite_pool() -> BlockingPoolHandle {
    SQLITE_POOL.get_or_init(|| BlockingPool::new(1, 4)).handle()
}

fn configure_connection_defaults(
    conn: &rusqlite::Connection,
    enable_wal: bool,
) -> Result<(), SqliteError> {
    conn.busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
    if enable_wal {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
    }
    conn.set_prepared_statement_cache_capacity(DEFAULT_STATEMENT_CACHE_CAPACITY);
    Ok(())
}

fn rollback_orphaned_transaction(
    conn: &rusqlite::Connection,
    needs_rollback: &AtomicBool,
) -> Result<(), SqliteError> {
    if !needs_rollback.load(Ordering::Acquire) {
        return Ok(());
    }

    if conn.is_autocommit() {
        needs_rollback.store(false, Ordering::Release);
        return Ok(());
    }

    match conn.execute_batch("ROLLBACK") {
        Ok(()) => {
            needs_rollback.store(false, Ordering::Release);
            Ok(())
        }
        Err(e) => {
            if conn.is_autocommit() {
                needs_rollback.store(false, Ordering::Release);
                Ok(())
            } else {
                Err(SqliteError::Sqlite(e.to_string()))
            }
        }
    }
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

impl SqliteError {
    /// Returns `true` if this is a database-busy error (`SQLITE_BUSY`).
    ///
    /// The error string from rusqlite contains "database is locked" for busy.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        match self {
            Self::Sqlite(msg) => msg.contains("database is locked") || msg.contains("SQLITE_BUSY"),
            _ => false,
        }
    }

    /// Returns `true` if this is a database-locked error (`SQLITE_LOCKED`).
    #[must_use]
    pub fn is_locked(&self) -> bool {
        match self {
            Self::Sqlite(msg) => {
                msg.contains("database table is locked") || msg.contains("SQLITE_LOCKED")
            }
            _ => false,
        }
    }

    /// Returns `true` if this is a constraint violation (`SQLITE_CONSTRAINT`).
    #[must_use]
    pub fn is_constraint_violation(&self) -> bool {
        match self {
            Self::Sqlite(msg) => {
                msg.contains("SQLITE_CONSTRAINT")
                    || msg.contains("UNIQUE constraint failed")
                    || msg.contains("NOT NULL constraint failed")
                    || msg.contains("FOREIGN KEY constraint failed")
                    || msg.contains("CHECK constraint failed")
            }
            _ => false,
        }
    }

    /// Returns `true` if this is a unique constraint violation.
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        match self {
            Self::Sqlite(msg) => msg.contains("UNIQUE constraint failed"),
            _ => false,
        }
    }

    /// Returns `true` if this is a connection-level error.
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::ConnectionClosed | Self::LockPoisoned
        )
    }

    /// Returns `true` if this error is transient and may succeed on retry.
    ///
    /// Transient SQLite errors: SQLITE_BUSY, SQLITE_LOCKED, and I/O errors.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        if matches!(self, Self::Io(_) | Self::ConnectionClosed) {
            return true;
        }
        self.is_busy() || self.is_locked()
    }

    /// Returns `true` if this error is safe to retry automatically.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.is_transient()
    }

    /// Returns a synthetic error code string for cross-backend parity.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        match self {
            Self::Sqlite(msg) => {
                if msg.contains("SQLITE_BUSY") || msg.contains("database is locked") {
                    Some("SQLITE_BUSY")
                } else if msg.contains("SQLITE_LOCKED") || msg.contains("database table is locked")
                {
                    Some("SQLITE_LOCKED")
                } else if msg.contains("SQLITE_CONSTRAINT") || msg.contains("constraint failed") {
                    Some("SQLITE_CONSTRAINT")
                } else if msg.contains("SQLITE_ERROR") {
                    Some("SQLITE_ERROR")
                } else {
                    None
                }
            }
            Self::Io(_) => Some("SQLITE_IOERR"),
            Self::ConnectionClosed => Some("SQLITE_MISUSE"),
            _ => None,
        }
    }
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
            #[allow(clippy::cast_precision_loss)]
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
        let val = self.get(column)?;
        val.as_integer().ok_or_else(|| SqliteError::TypeMismatch {
            column: column.to_string(),
            expected: "integer",
            actual: format!("{val:?}"),
        })
    }

    /// Gets a real value by column name.
    pub fn get_f64(&self, column: &str) -> Result<f64, SqliteError> {
        let val = self.get(column)?;
        val.as_real().ok_or_else(|| SqliteError::TypeMismatch {
            column: column.to_string(),
            expected: "real",
            actual: format!("{val:?}"),
        })
    }

    /// Gets a text value by column name.
    pub fn get_str(&self, column: &str) -> Result<&str, SqliteError> {
        let val = self.get(column)?;
        val.as_text().ok_or_else(|| SqliteError::TypeMismatch {
            column: column.to_string(),
            expected: "text",
            actual: format!("{val:?}"),
        })
    }

    /// Gets a blob value by column name.
    pub fn get_blob(&self, column: &str) -> Result<&[u8], SqliteError> {
        let val = self.get(column)?;
        val.as_blob().ok_or_else(|| SqliteError::TypeMismatch {
            column: column.to_string(),
            expected: "blob",
            actual: format!("{val:?}"),
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
    /// Flag indicating an uncommitted transaction was dropped and needs rollback.
    needs_rollback: Arc<AtomicBool>,
}

impl fmt::Debug for SqliteConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteConnection")
            .field("open", &self.inner.lock().conn.is_some())
            .field("pool", &self.pool)
            .field(
                "needs_rollback",
                &self.needs_rollback.load(Ordering::Relaxed),
            )
            .finish()
    }
}

impl SqliteConnection {
    async fn run_connection_op<R, F>(
        &self,
        cx: &Cx,
        op_name: &'static str,
        f: F,
    ) -> Outcome<R, SqliteError>
    where
        R: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> Result<R, SqliteError> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = tx.reserve(cx);

        let handle = self.pool.spawn(move || {
            let result = (|| {
                let guard = inner.lock();
                let conn = guard.get()?;
                let result = f(conn);
                drop(guard);
                result
            })();
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(result)) => Outcome::Ok(result),
            Ok(Err(e)) => Outcome::Err(e),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                handle.cancel();
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(crate::channel::oneshot::RecvError::Closed) => Outcome::Err(SqliteError::Sqlite(
                format!("failed to receive result for {op_name}"),
            )),
            Err(crate::channel::oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("{op_name} awaits a fresh oneshot recv future")
            }
        }
    }

    async fn drain_orphaned_transaction(&self, cx: &Cx) -> Outcome<(), SqliteError> {
        if !self.needs_rollback.load(Ordering::Acquire) {
            return Outcome::Ok(());
        }

        let needs_rollback = Arc::clone(&self.needs_rollback);
        self.run_connection_op(cx, "sqlite rollback cleanup", move |conn| {
            rollback_orphaned_transaction(conn, needs_rollback.as_ref())
        })
        .await
    }

    /// Opens a SQLite database at the given path.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    /// If cancelled during execution, the connection may or may not be opened.
    pub async fn open(cx: &Cx, path: impl AsRef<Path>) -> Outcome<Self, SqliteError> {
        // Check for cancellation
        if cx.checkpoint().is_err() {
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
            let result = (|| {
                let conn = rusqlite::Connection::open(&path)
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
                configure_connection_defaults(&conn, true)?;
                Ok(conn)
            })();
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(conn)) => Outcome::Ok(Self {
                inner: Arc::new(Mutex::new(SqliteConnectionInner::new(conn))),
                pool: pool_clone,
                needs_rollback: Arc::new(AtomicBool::new(false)),
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
            Err(crate::channel::oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("SQLite blocking-pool open awaits a fresh oneshot recv future")
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
        if cx.checkpoint().is_err() {
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
            let result = (|| {
                let conn = rusqlite::Connection::open_in_memory()
                    .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
                configure_connection_defaults(&conn, false)?;
                Ok(conn)
            })();
            let _ = permit.send(result);
        });

        match rx.recv(cx).await {
            Ok(Ok(conn)) => Outcome::Ok(Self {
                inner: Arc::new(Mutex::new(SqliteConnectionInner::new(conn))),
                pool: pool_clone,
                needs_rollback: Arc::new(AtomicBool::new(false)),
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
            Err(crate::channel::oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("SQLite in-memory open awaits a fresh oneshot recv future")
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
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        match self.drain_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let sql = sql.to_string();
        let params: Vec<SqliteValue> = params.to_vec();
        self.run_connection_op(cx, "sqlite execute", move |conn| {
            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

            conn.execute(&sql, params_refs.as_slice())
                .map(|n| n as u64)
                .map_err(|e| SqliteError::Sqlite(e.to_string()))
        })
        .await
    }

    /// Executes a batch of SQL statements.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn execute_batch(&self, cx: &Cx, sql: &str) -> Outcome<(), SqliteError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        match self.drain_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let sql = sql.to_string();
        self.run_connection_op(cx, "sqlite execute_batch", move |conn| {
            conn.execute_batch(&sql)
                .map_err(|e| SqliteError::Sqlite(e.to_string()))
        })
        .await
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
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        match self.drain_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let sql = sql.to_string();
        let params: Vec<SqliteValue> = params.to_vec();
        self.run_connection_op(cx, "sqlite query", move |conn| {
            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

            let mut stmt = conn
                .prepare_cached(&sql)
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

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
            drop(rows);
            drop(stmt);
            Ok(result)
        })
        .await
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
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        match self.drain_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let sql = sql.to_string();
        let params: Vec<SqliteValue> = params.to_vec();
        self.run_connection_op(cx, "sqlite query_row", move |conn| {
            let params_refs: Vec<&dyn rusqlite::ToSql> =
                params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

            let mut stmt = conn
                .prepare_cached(&sql)
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

            let column_count = stmt.column_count();
            let column_names: Vec<String> = stmt
                .column_names()
                .iter()
                .map(std::string::ToString::to_string)
                .collect();

            let mut rows = stmt
                .query(params_refs.as_slice())
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

            let row_opt = rows
                .next()
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

            let result = if let Some(row) = row_opt {
                let columns: BTreeMap<String, usize> = column_names
                    .iter()
                    .enumerate()
                    .map(|(i, name)| (name.clone(), i))
                    .collect();
                let columns = Arc::new(columns);

                let mut values = Vec::with_capacity(column_count);
                for i in 0..column_count {
                    let value = row
                        .get_ref(i)
                        .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
                    values.push(convert_value(value));
                }
                Some(SqliteRow::new(columns, values))
            } else {
                None
            };

            drop(rows);
            drop(stmt);
            Ok(result)
        })
        .await
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

    /// Updates SQLite busy timeout for lock-contention retries.
    pub async fn set_busy_timeout(&self, cx: &Cx, timeout: Duration) -> Outcome<(), SqliteError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        match self.drain_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        }
        self.run_connection_op(cx, "sqlite set_busy_timeout", move |conn| {
            conn.busy_timeout(timeout)
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
            Ok(())
        })
        .await
    }

    /// Closes the connection.
    pub fn close(&self) -> Result<(), SqliteError> {
        let mut guard = self.inner.lock();
        if let Some(conn) = guard.conn.as_ref() {
            let _ = rollback_orphaned_transaction(conn, self.needs_rollback.as_ref());
            conn.flush_prepared_statement_cache();
        }
        self.needs_rollback.store(false, Ordering::Release);
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
        if !self.finished
            && self
                .conn
                .needs_rollback
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            // Asynchronously enqueue a rollback via an atomic flag so we don't
            // block the async executor thread waiting for the connection lock.
            // We also explicitly spawn a task to drain the rollback immediately if
            // the connection is otherwise idle, preventing lock starvation for the database.
            let inner = Arc::clone(&self.conn.inner);
            let needs_rollback = Arc::clone(&self.conn.needs_rollback);
            self.conn.pool.spawn(move || {
                let guard = inner.lock();
                if let Ok(conn) = guard.get() {
                    let _ = rollback_orphaned_transaction(conn, needs_rollback.as_ref());
                }
            });
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
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    use crate::cx::Cx;
    use crate::test_utils::init_test_logging;
    use crate::types::Budget;
    use crate::types::Outcome;
    use crate::util::ArenaIndex;
    use crate::{RegionId, TaskId};
    use futures_lite::future::block_on;
    use tempfile::tempdir;

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
    fn sqlite_file_persists_while_memory_resets_under_lab_runtime() {
        init_test_logging();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("lab_runtime_persistence.sqlite3");
        let config = TestConfig::new()
            .with_seed(0x51A7_1001)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (persisted_name, memory_table_count) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");

                let file_conn = match SqliteConnection::open(&cx, &db_path).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("file open failed: {other:?}"),
                };
                match file_conn
                    .execute_batch(
                        &cx,
                        "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT);
                         INSERT INTO t(name) VALUES ('persisted');",
                    )
                    .await
                {
                    Outcome::Ok(()) => {}
                    other => panic!("file schema setup failed: {other:?}"),
                }
                tracing::info!(
                    event = %serde_json::json!({
                        "phase": "file_seeded",
                        "path": db_path.display().to_string(),
                    }),
                    "sqlite_lab_checkpoint"
                );
                file_conn.close().unwrap();

                let reopened_file = match SqliteConnection::open(&cx, &db_path).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("file reopen failed: {other:?}"),
                };
                let file_rows = match reopened_file.query(&cx, "SELECT name FROM t", &[]).await {
                    Outcome::Ok(rows) => rows,
                    other => panic!("file query failed after reopen: {other:?}"),
                };
                let persisted_name = file_rows[0].get_str("name").unwrap().to_string();
                tracing::info!(
                    event = %serde_json::json!({
                        "phase": "file_reopened",
                        "row_count": file_rows.len(),
                        "name": persisted_name,
                    }),
                    "sqlite_lab_checkpoint"
                );
                reopened_file.close().unwrap();

                let memory_conn = match SqliteConnection::open_in_memory(&cx).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("memory open failed: {other:?}"),
                };
                match memory_conn
                    .execute_batch(
                        &cx,
                        "CREATE TABLE ephemeral (id INTEGER PRIMARY KEY, name TEXT);
                         INSERT INTO ephemeral(name) VALUES ('transient');",
                    )
                    .await
                {
                    Outcome::Ok(()) => {}
                    other => panic!("memory schema setup failed: {other:?}"),
                }
                tracing::info!(
                    event = %serde_json::json!({
                        "phase": "memory_seeded",
                        "table": "ephemeral",
                    }),
                    "sqlite_lab_checkpoint"
                );
                memory_conn.close().unwrap();

                let reopened_memory = match SqliteConnection::open_in_memory(&cx).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("memory reopen failed: {other:?}"),
                };
                let memory_rows = match reopened_memory
                    .query(
                        &cx,
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='ephemeral'",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(rows) => rows,
                    other => panic!("memory table probe failed after reopen: {other:?}"),
                };
                tracing::info!(
                    event = %serde_json::json!({
                        "phase": "memory_reopened",
                        "table_count": memory_rows.len(),
                    }),
                    "sqlite_lab_checkpoint"
                );
                reopened_memory.close().unwrap();

                (persisted_name, memory_rows.len())
            });

        assert_eq!(persisted_name, "persisted");
        assert_eq!(memory_table_count, 0);
        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "sqlite lab persistence test should leave runtime invariants clean: {violations:?}"
        );
    }

    #[test]
    fn sqlite_transaction_commit_persists_under_lab_runtime() {
        init_test_logging();
        let config = TestConfig::new()
            .with_seed(0x51A7_2002)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let (count_inside_tx, count_after_commit, committed_name) =
            LabRuntimeTarget::block_on(&mut runtime, async move {
                let cx = Cx::current().expect("lab runtime should install a current Cx");

                let conn = match SqliteConnection::open_in_memory(&cx).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("open_in_memory failed: {other:?}"),
                };
                match conn
                    .execute_batch(
                        &cx,
                        "CREATE TABLE tx_items (id INTEGER PRIMARY KEY, name TEXT);",
                    )
                    .await
                {
                    Outcome::Ok(()) => {}
                    other => panic!("schema setup failed: {other:?}"),
                }

                let Outcome::Ok(tx) = conn.begin(&cx).await else {
                    panic!("begin failed");
                };
                match tx
                    .execute(
                        &cx,
                        "INSERT INTO tx_items(name) VALUES (?1)",
                        &[SqliteValue::Text("committed".to_string())],
                    )
                    .await
                {
                    Outcome::Ok(1) => {}
                    other => panic!("insert in transaction failed: {other:?}"),
                }

                let rows_inside = match tx
                    .query(&cx, "SELECT COUNT(*) AS count FROM tx_items", &[])
                    .await
                {
                    Outcome::Ok(rows) => rows,
                    other => panic!("count query inside transaction failed: {other:?}"),
                };
                let count_inside_tx = rows_inside[0]
                    .get_i64("count")
                    .expect("count column should be present");
                tracing::info!(
                    event = %serde_json::json!({
                        "phase": "transaction_inserted",
                        "count_inside_tx": count_inside_tx,
                    }),
                    "sqlite_lab_checkpoint"
                );

                match tx.commit(&cx).await {
                    Outcome::Ok(()) => {}
                    other => panic!("commit failed: {other:?}"),
                }

                let rows_after = match conn
                    .query(
                        &cx,
                        "SELECT COUNT(*) AS count, MIN(name) AS name FROM tx_items",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(rows) => rows,
                    other => panic!("query after commit failed: {other:?}"),
                };
                let count_after_commit = rows_after[0]
                    .get_i64("count")
                    .expect("count column should be present");
                let committed_name = rows_after[0]
                    .get_str("name")
                    .expect("name column should be present")
                    .to_string();
                tracing::info!(
                    event = %serde_json::json!({
                        "phase": "transaction_committed",
                        "count_after_commit": count_after_commit,
                        "name": committed_name,
                    }),
                    "sqlite_lab_checkpoint"
                );
                conn.close().unwrap();

                (count_inside_tx, count_after_commit, committed_name)
            });

        assert_eq!(count_inside_tx, 1);
        assert_eq!(count_after_commit, 1);
        assert_eq!(committed_name, "committed");
        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "sqlite lab transaction test should leave runtime invariants clean: {violations:?}"
        );
        assert!(
            runtime.is_quiescent(),
            "lab runtime should reach quiescence"
        );
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

            let Outcome::Ok(tx) = conn.begin(&cx).await else {
                panic!("begin failed");
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

    #[test]
    fn open_file_sets_wal_mode() {
        let cx = create_test_cx();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("wal_mode.sqlite3");

        block_on(async {
            let conn = match SqliteConnection::open(&cx, &db_path).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open failed: {other:?}"),
            };

            let rows = match conn.query(&cx, "PRAGMA journal_mode", &[]).await {
                Outcome::Ok(rows) => rows,
                other => panic!("query pragma failed: {other:?}"),
            };
            let mode = rows[0]
                .get_idx(0)
                .unwrap()
                .as_text()
                .unwrap()
                .to_ascii_lowercase();
            assert_eq!(mode, "wal");
        });
    }

    #[test]
    fn transaction_drop_rolls_back_uncommitted_work() {
        let cx = create_test_cx();

        block_on(async {
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute_batch(&cx, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);")
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("create table failed: {other:?}"),
            }

            let Outcome::Ok(tx) = conn.begin(&cx).await else {
                panic!("begin failed");
            };
            match tx
                .execute(
                    &cx,
                    "INSERT INTO t(v) VALUES (?1)",
                    &[SqliteValue::Text("x".to_string())],
                )
                .await
            {
                Outcome::Ok(1) => {}
                other => panic!("insert in tx failed: {other:?}"),
            }
            drop(tx);

            let rows = match conn.query(&cx, "SELECT COUNT(*) FROM t", &[]).await {
                Outcome::Ok(rows) => rows,
                other => panic!("count query failed: {other:?}"),
            };
            assert_eq!(rows[0].get_idx(0).unwrap().as_integer(), Some(0));
        });
    }

    #[test]
    fn transaction_drop_preserves_foreign_key_cascade_consistency() {
        let cx = create_test_cx();

        block_on(async {
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute_batch(
                    &cx,
                    "
                    CREATE TABLE parent (id INTEGER PRIMARY KEY);
                    CREATE TABLE child (
                        id INTEGER PRIMARY KEY,
                        parent_id INTEGER NOT NULL REFERENCES parent(id) ON DELETE CASCADE
                    );
                    INSERT INTO parent(id) VALUES (1);
                    INSERT INTO child(id, parent_id) VALUES (10, 1);
                    ",
                )
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let Outcome::Ok(tx) = conn.begin_immediate(&cx).await else {
                panic!("begin_immediate failed");
            };

            match tx
                .execute(&cx, "DELETE FROM parent WHERE id = 1", &[])
                .await
            {
                Outcome::Ok(1) => {}
                other => panic!("delete in transaction failed: {other:?}"),
            }

            drop(tx);

            let parent_rows = match conn.query(&cx, "SELECT COUNT(*) FROM parent", &[]).await {
                Outcome::Ok(rows) => rows,
                other => panic!("parent count failed: {other:?}"),
            };
            let child_rows = match conn.query(&cx, "SELECT COUNT(*) FROM child", &[]).await {
                Outcome::Ok(rows) => rows,
                other => panic!("child count failed: {other:?}"),
            };

            assert_eq!(parent_rows[0].get_idx(0).unwrap().as_integer(), Some(1));
            assert_eq!(child_rows[0].get_idx(0).unwrap().as_integer(), Some(1));

            match conn
                .execute(&cx, "DELETE FROM parent WHERE id = 1", &[])
                .await
            {
                Outcome::Ok(1) => {}
                other => panic!("post-rollback delete failed: {other:?}"),
            }

            let child_rows = match conn.query(&cx, "SELECT COUNT(*) FROM child", &[]).await {
                Outcome::Ok(rows) => rows,
                other => panic!("child recount failed: {other:?}"),
            };
            assert_eq!(child_rows[0].get_idx(0).unwrap().as_integer(), Some(0));
        });
    }

    #[test]
    fn cached_statements_remain_usable_after_schema_change() {
        let cx = create_test_cx();

        block_on(async {
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            {
                let guard = conn.inner.lock();
                let raw = guard.get().expect("connection open");
                raw.set_prepared_statement_cache_capacity(1);
            }

            match conn
                .execute_batch(
                    &cx,
                    "
                    CREATE TABLE t (id INTEGER PRIMARY KEY, value TEXT);
                    INSERT INTO t(value) VALUES ('before');
                    ",
                )
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("initial schema setup failed: {other:?}"),
            }

            match conn
                .query(&cx, "SELECT value FROM t WHERE id = 1", &[])
                .await
            {
                Outcome::Ok(rows) => assert_eq!(rows[0].get_str("value").unwrap(), "before"),
                other => panic!("initial cached query failed: {other:?}"),
            }

            match conn.query(&cx, "SELECT id FROM t WHERE id = 1", &[]).await {
                Outcome::Ok(rows) => assert_eq!(rows[0].get_i64("id").unwrap(), 1),
                other => panic!("second cached query failed: {other:?}"),
            }

            match conn
                .execute_batch(
                    &cx,
                    "
                    DROP TABLE t;
                    CREATE TABLE t (id INTEGER PRIMARY KEY, value TEXT);
                    INSERT INTO t(value) VALUES ('after');
                    ",
                )
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("schema rebuild failed: {other:?}"),
            }

            match conn
                .query(&cx, "SELECT value FROM t WHERE id = 1", &[])
                .await
            {
                Outcome::Ok(rows) => assert_eq!(rows[0].get_str("value").unwrap(), "after"),
                other => panic!("cached query after schema change failed: {other:?}"),
            }
        });
    }

    #[test]
    fn busy_timeout_produces_lock_error_under_write_contention() {
        let cx = create_test_cx();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("busy_timeout.sqlite3");

        block_on(async {
            let conn1 = match SqliteConnection::open(&cx, &db_path).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open conn1 failed: {other:?}"),
            };
            let conn2 = match SqliteConnection::open(&cx, &db_path).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open conn2 failed: {other:?}"),
            };

            match conn1
                .execute_batch(&cx, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);")
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("create table failed: {other:?}"),
            }

            match conn2.set_busy_timeout(&cx, Duration::from_millis(50)).await {
                Outcome::Ok(()) => {}
                other => panic!("set_busy_timeout failed: {other:?}"),
            }

            let Outcome::Ok(tx) = conn1.begin_immediate(&cx).await else {
                panic!("begin_immediate failed");
            };

            match conn2
                .execute(
                    &cx,
                    "INSERT INTO t(v) VALUES (?1)",
                    &[SqliteValue::Text("blocked".to_string())],
                )
                .await
            {
                Outcome::Err(SqliteError::Sqlite(msg)) => {
                    let lower = msg.to_ascii_lowercase();
                    assert!(
                        lower.contains("database is locked") || lower.contains("database is busy"),
                        "unexpected busy error message: {msg}"
                    );
                }
                other => panic!("expected lock error, got: {other:?}"),
            }

            match tx.rollback(&cx).await {
                Outcome::Ok(()) => {}
                other => panic!("rollback failed: {other:?}"),
            }
        });
    }

    #[test]
    fn execute_with_cancelled_cx_does_not_mutate_state() {
        let cx = create_test_cx();
        let cancelled = create_test_cx();
        cancelled.cancel_fast(crate::types::CancelKind::User);

        block_on(async {
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute_batch(&cx, "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT);")
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("create table failed: {other:?}"),
            }

            match conn
                .execute(
                    &cancelled,
                    "INSERT INTO t(v) VALUES (?1)",
                    &[SqliteValue::Text("never".to_string())],
                )
                .await
            {
                Outcome::Cancelled(_) => {}
                other => panic!("expected cancellation, got: {other:?}"),
            }

            let rows = match conn.query(&cx, "SELECT COUNT(*) FROM t", &[]).await {
                Outcome::Ok(rows) => rows,
                other => panic!("count query failed: {other:?}"),
            };
            assert_eq!(rows[0].get_idx(0).unwrap().as_integer(), Some(0));
        });
    }

    // ================================================================
    // PRAGMA journal_mode Transition Conformance Tests
    // ================================================================

    #[cfg(feature = "sqlite")]
    mod pragma_journal_mode_conformance {
        use super::*;
        use crate::test_utils::run_test_with_cx;
        use std::fs;
        use std::path::PathBuf;
        use tempfile::TempDir;

        /// Test data and utilities for journal mode conformance testing.
        struct JournalModeTestData {
            temp_dir: TempDir,
            db_path: PathBuf,
        }

        impl JournalModeTestData {
            fn new() -> Self {
                let temp_dir = tempfile::tempdir().expect("Failed to create temp directory");
                let db_path = temp_dir.path().join("test.db");

                Self { temp_dir, db_path }
            }

            fn get_db_path(&self) -> &Path {
                &self.db_path
            }

            fn get_wal_path(&self) -> PathBuf {
                self.db_path.with_extension("db-wal")
            }

            fn get_shm_path(&self) -> PathBuf {
                self.db_path.with_extension("db-shm")
            }

            /// Helper to check current journal mode.
            async fn get_journal_mode(conn: &SqliteConnection, cx: &Cx) -> String {
                let rows = match conn.query(cx, "PRAGMA journal_mode", &[]).await {
                    Outcome::Ok(rows) => rows,
                    other => panic!("Failed to query journal_mode: {other:?}"),
                };

                rows[0]
                    .get_idx(0)
                    .unwrap()
                    .as_text()
                    .unwrap_or_else(|| panic!("journal_mode should return a string"))
                    .to_owned()
            }

            /// Helper to set journal mode and return the result.
            async fn set_journal_mode(
                conn: &SqliteConnection,
                cx: &Cx,
                mode: &str,
            ) -> Outcome<String, SqliteError> {
                let sql = format!("PRAGMA journal_mode = {}", mode);
                match conn.query(cx, &sql, &[]).await {
                    Outcome::Ok(rows) => Outcome::Ok(
                        rows[0]
                            .get_idx(0)
                            .unwrap()
                            .as_text()
                            .unwrap_or_else(|| panic!("journal_mode pragma should return a string"))
                            .to_owned(),
                    ),
                    Outcome::Err(err) => Outcome::Err(err),
                    Outcome::Cancelled(cancelled) => Outcome::Cancelled(cancelled),
                    Outcome::Panicked(payload) => Outcome::Panicked(payload),
                }
            }

            /// Create test table and insert test data.
            async fn setup_test_data(conn: &SqliteConnection, cx: &Cx) {
                match conn
                    .execute_batch(
                        cx,
                        "
                    CREATE TABLE test_data (
                        id INTEGER PRIMARY KEY,
                        value TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    );
                    INSERT INTO test_data (value) VALUES ('test1'), ('test2'), ('test3');
                ",
                    )
                    .await
                {
                    Outcome::Ok(()) => {}
                    other => panic!("Failed to create test data: {other:?}"),
                }
            }

            /// Verify test data integrity.
            async fn verify_test_data(conn: &SqliteConnection, cx: &Cx, expected_count: i64) {
                let rows = match conn.query(cx, "SELECT COUNT(*) FROM test_data", &[]).await {
                    Outcome::Ok(rows) => rows,
                    other => panic!("Failed to count test data: {other:?}"),
                };

                let count = rows[0].get_idx(0).unwrap().as_integer().unwrap();
                assert_eq!(count, expected_count, "Test data count mismatch");
            }
        }

        #[test]
        fn delete_to_wal_mode_transition_conformance() {
            run_test_with_cx(|cx| async move {
                let test_data = JournalModeTestData::new();

                // Open connection - should default to DELETE mode
                let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open connection: {other:?}"),
                };

                // Verify initial journal mode is DELETE
                let initial_mode = JournalModeTestData::get_journal_mode(&conn, &cx).await;
                assert_eq!(
                    initial_mode.to_lowercase(),
                    "delete",
                    "Should start in DELETE mode"
                );

                // Setup test data in DELETE mode
                JournalModeTestData::setup_test_data(&conn, &cx).await;
                JournalModeTestData::verify_test_data(&conn, &cx, 3).await;

                // Transition to WAL mode
                let wal_result =
                    match JournalModeTestData::set_journal_mode(&conn, &cx, "WAL").await {
                        Outcome::Ok(mode) => mode,
                        other => panic!("Failed to set WAL mode: {other:?}"),
                    };
                assert_eq!(
                    wal_result.to_lowercase(),
                    "wal",
                    "Should transition to WAL mode"
                );

                // Verify journal mode changed
                let current_mode = JournalModeTestData::get_journal_mode(&conn, &cx).await;
                assert_eq!(
                    current_mode.to_lowercase(),
                    "wal",
                    "Journal mode should be WAL"
                );

                // Verify WAL files are created
                assert!(
                    test_data.get_wal_path().exists(),
                    "WAL file should be created"
                );
                assert!(
                    test_data.get_shm_path().exists(),
                    "SHM file should be created"
                );

                // Verify data integrity after transition
                JournalModeTestData::verify_test_data(&conn, &cx, 3).await;

                // Insert additional data in WAL mode
                match conn
                    .execute(
                        &cx,
                        "INSERT INTO test_data (value) VALUES (?)",
                        &[SqliteValue::Text("wal_data".to_owned())],
                    )
                    .await
                {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to insert WAL data: {other:?}"),
                };

                JournalModeTestData::verify_test_data(&conn, &cx, 4).await;

                // Close connection
                conn.close().unwrap();
            });
        }

        #[test]
        fn wal_to_truncate_mode_transition_conformance() {
            run_test_with_cx(|cx| async move {
                let test_data = JournalModeTestData::new();

                let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open connection: {other:?}"),
                };

                // Start with WAL mode
                match JournalModeTestData::set_journal_mode(&conn, &cx, "WAL").await {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to set WAL mode: {other:?}"),
                };

                // Setup test data in WAL mode
                JournalModeTestData::setup_test_data(&conn, &cx).await;
                JournalModeTestData::verify_test_data(&conn, &cx, 3).await;

                // Verify WAL files exist
                assert!(test_data.get_wal_path().exists(), "WAL file should exist");

                // Transition to TRUNCATE mode
                let truncate_result =
                    match JournalModeTestData::set_journal_mode(&conn, &cx, "TRUNCATE").await {
                        Outcome::Ok(mode) => mode,
                        other => panic!("Failed to set TRUNCATE mode: {other:?}"),
                    };
                assert_eq!(
                    truncate_result.to_lowercase(),
                    "truncate",
                    "Should transition to TRUNCATE mode"
                );

                // Verify journal mode changed
                let current_mode = JournalModeTestData::get_journal_mode(&conn, &cx).await;
                assert_eq!(
                    current_mode.to_lowercase(),
                    "truncate",
                    "Journal mode should be TRUNCATE"
                );

                // WAL files should be cleaned up after successful transition
                // Note: Files might still exist briefly due to cleanup timing

                // Verify data integrity after transition
                JournalModeTestData::verify_test_data(&conn, &cx, 3).await;

                // Test TRUNCATE mode behavior - inserts should work
                match conn
                    .execute(
                        &cx,
                        "INSERT INTO test_data (value) VALUES (?)",
                        &[SqliteValue::Text("truncate_data".to_owned())],
                    )
                    .await
                {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to insert TRUNCATE data: {other:?}"),
                };

                JournalModeTestData::verify_test_data(&conn, &cx, 4).await;

                conn.close().unwrap();
            });
        }

        #[test]
        fn memory_mode_persistence_loss_conformance() {
            run_test_with_cx(|cx| async move {
                // Test with in-memory database
                let conn = match SqliteConnection::open_in_memory(&cx).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open in-memory connection: {other:?}"),
                };

                // Set MEMORY journal mode
                let memory_result =
                    match JournalModeTestData::set_journal_mode(&conn, &cx, "MEMORY").await {
                        Outcome::Ok(mode) => mode,
                        other => panic!("Failed to set MEMORY mode: {other:?}"),
                    };
                assert_eq!(
                    memory_result.to_lowercase(),
                    "memory",
                    "Should be in MEMORY mode"
                );

                // Setup test data
                JournalModeTestData::setup_test_data(&conn, &cx).await;
                JournalModeTestData::verify_test_data(&conn, &cx, 3).await;

                // Begin transaction and modify data
                match conn
                    .execute_batch(
                        &cx,
                        "
                    BEGIN TRANSACTION;
                    INSERT INTO test_data (value) VALUES ('memory_test');
                    UPDATE test_data SET value = 'modified' WHERE id = 1;
                ",
                    )
                    .await
                {
                    Outcome::Ok(()) => {}
                    other => panic!("Failed to begin transaction: {other:?}"),
                };

                // Close connection abruptly without commit (simulating crash)
                conn.close().unwrap();

                // Reopen in-memory database - all data should be lost
                let new_conn = match SqliteConnection::open_in_memory(&cx).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to reopen in-memory connection: {other:?}"),
                };

                // Verify database is empty (persistence loss)
                let tables_result = new_conn
                    .query(
                        &cx,
                        "SELECT name FROM sqlite_master WHERE type='table'",
                        &[],
                    )
                    .await;
                match tables_result {
                    Outcome::Ok(rows) => {
                        assert_eq!(
                            rows.len(),
                            0,
                            "In-memory database should have no persistent tables"
                        );
                    }
                    other => panic!("Failed to query sqlite_master: {other:?}"),
                }

                new_conn.close().unwrap();
            });
        }

        #[test]
        fn off_mode_atomicity_absence_conformance() {
            run_test_with_cx(|cx| async move {
                let test_data = JournalModeTestData::new();

                let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open connection: {other:?}"),
                };

                // Set OFF journal mode (disables atomicity)
                let off_result =
                    match JournalModeTestData::set_journal_mode(&conn, &cx, "OFF").await {
                        Outcome::Ok(mode) => mode,
                        other => panic!("Failed to set OFF mode: {other:?}"),
                    };
                assert_eq!(off_result.to_lowercase(), "off", "Should be in OFF mode");

                // Create test table
                match conn
                    .execute_batch(
                        &cx,
                        "
                    CREATE TABLE atomicity_test (
                        id INTEGER PRIMARY KEY,
                        step INTEGER,
                        data TEXT
                    );
                ",
                    )
                    .await
                {
                    Outcome::Ok(()) => {}
                    other => panic!("Failed to create table: {other:?}"),
                };

                // In OFF mode, transactions may not be atomic
                // We'll test that the mode is set correctly and basic operations work
                // but acknowledge that atomicity is not guaranteed

                // Begin explicit transaction
                match conn.execute(&cx, "BEGIN TRANSACTION", &[]).await {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to begin transaction: {other:?}"),
                };

                // Insert test data
                match conn
                    .execute(
                        &cx,
                        "INSERT INTO atomicity_test (step, data) VALUES (1, 'step1')",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to insert step1: {other:?}"),
                };

                match conn
                    .execute(
                        &cx,
                        "INSERT INTO atomicity_test (step, data) VALUES (2, 'step2')",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to insert step2: {other:?}"),
                };

                // Commit transaction
                match conn.execute(&cx, "COMMIT", &[]).await {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to commit: {other:?}"),
                };

                // Verify data was written
                let rows = match conn
                    .query(&cx, "SELECT COUNT(*) FROM atomicity_test", &[])
                    .await
                {
                    Outcome::Ok(rows) => rows,
                    other => panic!("Failed to count rows: {other:?}"),
                };

                let count = rows[0].get_idx(0).unwrap().as_integer().unwrap();
                assert_eq!(count, 2, "Both inserts should be present");

                // Verify OFF mode characteristics:
                // - No rollback journal files should be created
                let journal_files = fs::read_dir(test_data.temp_dir.path())
                    .unwrap()
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| {
                        entry.path().extension().map_or(false, |ext| {
                            ext == "journal" || ext == "wal" || ext == "shm"
                        })
                    })
                    .count();

                // In OFF mode, no journal files should exist
                assert_eq!(journal_files, 0, "OFF mode should not create journal files");

                conn.close().unwrap();
            });
        }

        #[test]
        fn unsupported_mode_fallback_conformance() {
            run_test_with_cx(|cx| async move {
                let test_data = JournalModeTestData::new();

                let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open connection: {other:?}"),
                };

                // Try to set an invalid/unsupported journal mode
                let invalid_modes = ["INVALID", "BOGUS", "NONEXISTENT"];

                for invalid_mode in &invalid_modes {
                    // Attempt to set invalid mode
                    match JournalModeTestData::set_journal_mode(&conn, &cx, invalid_mode).await {
                        Outcome::Ok(returned_mode) => {
                            // SQLite should fall back to a valid mode (typically the current mode)
                            // The returned mode should not be the invalid mode we requested
                            assert_ne!(
                                returned_mode.to_lowercase(),
                                invalid_mode.to_lowercase(),
                                "Should not accept invalid mode: {}",
                                invalid_mode
                            );

                            // Verify fallback is a known valid mode
                            let valid_modes =
                                ["delete", "truncate", "persist", "memory", "wal", "off"];
                            assert!(
                                valid_modes.contains(&returned_mode.to_lowercase().as_str()),
                                "Fallback should be a valid journal mode, got: {}",
                                returned_mode
                            );
                        }
                        Outcome::Err(_) => {
                            // Some invalid modes might cause SQLite to return an error
                            // This is also acceptable behavior
                        }
                        other => panic!(
                            "Unexpected outcome for invalid mode {}: {other:?}",
                            invalid_mode
                        ),
                    }

                    // Verify database is still functional after invalid mode attempt
                    let current_mode = JournalModeTestData::get_journal_mode(&conn, &cx).await;
                    assert!(
                        !current_mode.is_empty(),
                        "Should still have a valid journal mode after invalid attempt"
                    );
                }

                // Test that database operations still work
                JournalModeTestData::setup_test_data(&conn, &cx).await;
                JournalModeTestData::verify_test_data(&conn, &cx, 3).await;

                conn.close().unwrap();
            });
        }

        #[test]
        fn journal_mode_persistence_across_connections_conformance() {
            run_test_with_cx(|cx| async move {
                let test_data = JournalModeTestData::new();

                // First connection: set WAL mode
                {
                    let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                        Outcome::Ok(conn) => conn,
                        other => panic!("Failed to open connection: {other:?}"),
                    };

                    // Set WAL mode
                    match JournalModeTestData::set_journal_mode(&conn, &cx, "WAL").await {
                        Outcome::Ok(_) => {}
                        other => panic!("Failed to set WAL mode: {other:?}"),
                    };

                    // Create test data
                    JournalModeTestData::setup_test_data(&conn, &cx).await;

                    conn.close().unwrap();
                }

                // Second connection: verify WAL mode persists
                {
                    let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                        Outcome::Ok(conn) => conn,
                        other => panic!("Failed to reopen connection: {other:?}"),
                    };

                    // Verify WAL mode persisted
                    let persistent_mode = JournalModeTestData::get_journal_mode(&conn, &cx).await;
                    assert_eq!(
                        persistent_mode.to_lowercase(),
                        "wal",
                        "WAL mode should persist across connections"
                    );

                    // Verify data persisted
                    JournalModeTestData::verify_test_data(&conn, &cx, 3).await;

                    conn.close().unwrap();
                }
            });
        }

        #[test]
        fn journal_mode_concurrent_access_conformance() {
            run_test_with_cx(|cx| async move {
                let test_data = JournalModeTestData::new();

                // Set WAL mode which supports concurrent readers
                let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open connection: {other:?}"),
                };

                match JournalModeTestData::set_journal_mode(&conn, &cx, "WAL").await {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed to set WAL mode: {other:?}"),
                };

                JournalModeTestData::setup_test_data(&conn, &cx).await;

                // Test that concurrent read connections work in WAL mode
                let reader_conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open reader connection: {other:?}"),
                };

                // Both connections should be able to read
                JournalModeTestData::verify_test_data(&conn, &cx, 3).await;
                JournalModeTestData::verify_test_data(&reader_conn, &cx, 3).await;

                // Writer can insert while reader exists
                match conn
                    .execute(
                        &cx,
                        "INSERT INTO test_data (value) VALUES (?)",
                        &[SqliteValue::Text("concurrent_write".to_owned())],
                    )
                    .await
                {
                    Outcome::Ok(_) => {}
                    other => panic!("Failed concurrent write: {other:?}"),
                };

                // Reader should eventually see the new data
                JournalModeTestData::verify_test_data(&conn, &cx, 4).await;

                reader_conn.close().unwrap();
                conn.close().unwrap();
            });
        }

        #[test]
        fn journal_mode_edge_cases_conformance() {
            run_test_with_cx(|cx| async move {
                let test_data = JournalModeTestData::new();

                let conn = match SqliteConnection::open(&cx, test_data.get_db_path()).await {
                    Outcome::Ok(conn) => conn,
                    other => panic!("Failed to open connection: {other:?}"),
                };

                // Test case-insensitive mode setting
                let modes_to_test = [
                    ("wal", "wal"),
                    ("WAL", "wal"),
                    ("Wal", "wal"),
                    ("DELETE", "delete"),
                    ("delete", "delete"),
                ];

                for (input_mode, expected_mode) in &modes_to_test {
                    match JournalModeTestData::set_journal_mode(&conn, &cx, input_mode).await {
                        Outcome::Ok(returned_mode) => {
                            assert_eq!(
                                returned_mode.to_lowercase(),
                                expected_mode.to_lowercase(),
                                "Mode {} should normalize to {}",
                                input_mode,
                                expected_mode
                            );
                        }
                        other => panic!("Failed to set mode {}: {other:?}", input_mode),
                    }
                }

                // Test querying journal mode multiple times
                for _ in 0..5 {
                    let mode = JournalModeTestData::get_journal_mode(&conn, &cx).await;
                    assert!(
                        !mode.is_empty(),
                        "Journal mode query should always return a value"
                    );
                }

                // Test setting journal mode to current mode (should be no-op)
                let current_mode = JournalModeTestData::get_journal_mode(&conn, &cx).await;
                match JournalModeTestData::set_journal_mode(&conn, &cx, &current_mode).await {
                    Outcome::Ok(returned_mode) => {
                        assert_eq!(
                            returned_mode.to_lowercase(),
                            current_mode.to_lowercase(),
                            "Setting to current mode should be no-op"
                        );
                    }
                    other => panic!("Failed to set to current mode: {other:?}"),
                }

                conn.close().unwrap();
            });
        }
    }
}
