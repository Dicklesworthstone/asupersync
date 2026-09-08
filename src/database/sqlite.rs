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

use crate::channel::mpsc;
use crate::cx::Cx;
use crate::database::transaction::trace_database_transaction;
use crate::obligation::graded::{ObligationToken, TransactionKind};
use crate::runtime::blocking_pool::{BlockingPool, BlockingPoolHandle};
use crate::time::{sleep, wall_now};
use crate::types::{CancelReason, Outcome};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::fmt;
use std::future::poll_fn;
use std::marker::PhantomData;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::Poll;
use std::time::Duration;

/// Global blocking pool for SQLite operations.
///
/// Keep the pool itself alive for the process lifetime. Storing only
/// `BlockingPoolHandle` would drop the pool immediately and put the
/// handle into permanent shutdown state.
static SQLITE_POOL: OnceLock<BlockingPool> = OnceLock::new();
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_STATEMENT_CACHE_CAPACITY: usize = 64;
const SQLITE_ROW_STREAM_CHANNEL_CAPACITY: usize = 1;
const SQLITE_ROW_STREAM_FULL_BACKOFF: Duration = Duration::from_millis(1);

fn sqlite_cancelled_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason()
        .unwrap_or_else(|| CancelReason::user("cancelled"))
}

/// True when a [`SqliteError`] carries SQLITE_INTERRUPT. Call sites map
/// rusqlite errors to strings, so this matches the canonical "interrupted"
/// message text (br-asupersync-server-stack-hardening-eeexl1.1.2). Used to
/// relabel an interrupt caused by the armed deadline progress handler as
/// [`SqliteError::StatementTimeout`].
fn sqlite_error_is_interrupt(err: &SqliteError) -> bool {
    match err {
        SqliteError::Sqlite(msg) => {
            let msg = msg.to_ascii_lowercase();
            msg.contains("interrupt")
        }
        _ => false,
    }
}

async fn sqlite_wait_retry_delay(cx: &Cx, delay: Duration) -> Result<(), CancelReason> {
    if delay.is_zero() {
        cx.checkpoint().map_err(|_| sqlite_cancelled_reason(cx))?;
        crate::runtime::yield_now().await;
        return cx.checkpoint().map_err(|_| sqlite_cancelled_reason(cx));
    }

    let now = cx
        .timer_driver()
        .map_or_else(wall_now, |driver| driver.now());
    let mut sleeper = sleep(now, delay);
    poll_fn(|task_cx| {
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(sqlite_cancelled_reason(cx)));
        }
        Pin::new(&mut sleeper).poll(task_cx).map(Ok)
    })
    .await
}

fn wal_checkpoint_i64(row: &SqliteRow, column: &str) -> Result<i64, SqliteError> {
    row.get_i64(column).map_err(|err| {
        SqliteError::WalCheckpointFailed(format!(
            "WAL checkpoint status column {column:?} was missing or non-integer: {err}"
        ))
    })
}

fn get_sqlite_pool() -> BlockingPoolHandle {
    SQLITE_POOL.get_or_init(|| BlockingPool::new(1, 4)).handle()
}

fn configure_connection_defaults(
    conn: &rusqlite::Connection,
    enable_wal: bool,
) -> Result<(), SqliteError> {
    configure_connection_defaults_with(conn, enable_wal, |_, error| {
        SqliteError::Sqlite(error.to_string())
    })
}

fn configure_connection_defaults_with<E, F>(
    conn: &rusqlite::Connection,
    enable_wal: bool,
    mut map_error: F,
) -> Result<(), E>
where
    F: FnMut(SqliteOperation, rusqlite::Error) -> E,
{
    conn.busy_timeout(DEFAULT_BUSY_TIMEOUT)
        .map_err(|error| map_error(SqliteOperation::Configure, error))?;
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|error| map_error(SqliteOperation::Configure, error))?;
    if enable_wal {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|error| map_error(SqliteOperation::Configure, error))?;
    }
    conn.set_prepared_statement_cache_capacity(DEFAULT_STATEMENT_CACHE_CAPACITY);
    Ok(())
}

/// SECURITY FIX: Mutex-guarded transaction state tracking to prevent race conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    Autocommit,
    InTransaction,
    NeedsRollback,
    RollingBack, // Intermediate state to prevent concurrent rollbacks
}

#[derive(Debug, Default)]
struct BeginLifecycle {
    abandoned: bool,
    opened: bool,
    generation: Option<u64>,
}

#[derive(Clone)]
struct BeginAttempt {
    lifecycle: Arc<Mutex<BeginLifecycle>>,
    transaction_state: Arc<Mutex<TransactionState>>,
    transaction_generation: Arc<AtomicU64>,
}

impl BeginAttempt {
    fn new(
        transaction_state: Arc<Mutex<TransactionState>>,
        transaction_generation: Arc<AtomicU64>,
    ) -> Self {
        Self {
            lifecycle: Arc::new(Mutex::new(BeginLifecycle::default())),
            transaction_state,
            transaction_generation,
        }
    }

    fn abandon(&self) {
        // Keep the lifecycle lock through the mirror poison so the async
        // consumer and blocking worker form one ordered handoff. If the worker
        // already opened the transaction, this attempt owns the physical state
        // and must poison even when an older operation left a stale mirror.
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.abandoned = true;

        let mut state = self.transaction_state.lock();
        let owns_current_generation = lifecycle.generation.is_some_and(|generation| {
            self.transaction_generation.load(Ordering::Acquire) == generation
        });
        if owns_current_generation || (!lifecycle.opened && *state == TransactionState::Autocommit)
        {
            *state = TransactionState::NeedsRollback;
        }
    }

    fn finish_worker(
        &self,
        conn: &rusqlite::Connection,
        result: Result<u64, SqliteError>,
    ) -> Result<u64, SqliteError> {
        if result.is_ok() {
            let mut lifecycle = self.lifecycle.lock();
            lifecycle.opened = true;
            let Some(generation) =
                advance_transaction_generation(self.transaction_generation.as_ref())
            else {
                drop(lifecycle);
                rollback_abandoned_begin_mutex_guarded(
                    conn,
                    self.transaction_state.as_ref(),
                    self.transaction_generation.as_ref(),
                )?;
                return Err(SqliteError::Sqlite(
                    "managed SQLite transaction generation exhausted".to_string(),
                ));
            };
            lifecycle.generation = Some(generation);
            if lifecycle.abandoned {
                drop(lifecycle);
                rollback_abandoned_begin_mutex_guarded(
                    conn,
                    self.transaction_state.as_ref(),
                    self.transaction_generation.as_ref(),
                )?;
            } else {
                // Publish the mirror before releasing the lifecycle lock. A
                // later hard drop then observes `opened` and cannot miss the
                // need for cleanup.
                *self.transaction_state.lock() = TransactionState::InTransaction;
            }
        }
        result
    }

    fn finish_worker_diagnosed(
        &self,
        conn: &rusqlite::Connection,
        operation: SqliteOperation,
        result: Result<u64, SqliteOperationError>,
    ) -> Result<u64, SqliteOperationError> {
        if result.is_ok() {
            let mut lifecycle = self.lifecycle.lock();
            lifecycle.opened = true;
            let Some(generation) =
                advance_transaction_generation(self.transaction_generation.as_ref())
            else {
                drop(lifecycle);
                rollback_abandoned_begin_mutex_guarded(
                    conn,
                    self.transaction_state.as_ref(),
                    self.transaction_generation.as_ref(),
                )
                .map_err(|error| SqliteOperationError::from_legacy(operation, error))?;
                return Err(SqliteOperationError::from_legacy(
                    operation,
                    SqliteError::Sqlite(
                        "managed SQLite transaction generation exhausted".to_string(),
                    ),
                ));
            };
            lifecycle.generation = Some(generation);
            if lifecycle.abandoned {
                drop(lifecycle);
                rollback_abandoned_begin_mutex_guarded(
                    conn,
                    self.transaction_state.as_ref(),
                    self.transaction_generation.as_ref(),
                )
                .map_err(|error| SqliteOperationError::from_legacy(operation, error))?;
            } else {
                *self.transaction_state.lock() = TransactionState::InTransaction;
            }
        }
        result
    }
}

enum TransactionWorkerEffect {
    Begin(BeginAttempt),
    Finish(TransactionFinishEffect),
}

impl TransactionWorkerEffect {
    fn execute_worker(self, conn: &rusqlite::Connection, sql: &str) -> Result<u64, SqliteError> {
        match self {
            Self::Begin(attempt) => {
                if attempt.transaction_generation.load(Ordering::Acquire) >= u64::MAX - 1 {
                    return Err(SqliteError::Sqlite(
                        "managed SQLite transaction generation exhausted".to_string(),
                    ));
                }
                let result = conn
                    .execute(sql, [])
                    .map(|rows| rows as u64)
                    .map_err(|error| SqliteError::Sqlite(error.to_string()));
                attempt.finish_worker(conn, result)
            }
            Self::Finish(mut effect) => effect.execute_worker(conn, sql),
        }
    }

    fn execute_worker_diagnosed(
        self,
        conn: &rusqlite::Connection,
        sql: &str,
        operation: SqliteOperation,
    ) -> Result<u64, SqliteOperationError> {
        match self {
            Self::Begin(attempt) => {
                if attempt.transaction_generation.load(Ordering::Acquire) >= u64::MAX - 1 {
                    return Err(SqliteOperationError::from_legacy(
                        operation,
                        SqliteError::Sqlite(
                            "managed SQLite transaction generation exhausted".to_string(),
                        ),
                    ));
                }
                let result = conn
                    .execute(sql, [])
                    .map(|rows| rows as u64)
                    .map_err(|error| SqliteOperationError::from_rusqlite(operation, error));
                attempt.finish_worker_diagnosed(conn, operation, result)
            }
            Self::Finish(mut effect) => effect.execute_worker_diagnosed(conn, sql, operation),
        }
    }
}

#[derive(Clone, Copy)]
enum TransactionFinishKind {
    Commit,
    Rollback,
}

struct TransactionFinishEffect {
    transaction_state: Arc<Mutex<TransactionState>>,
    transaction_generation: Arc<AtomicU64>,
    expected_generation: u64,
    kind: TransactionFinishKind,
    obligation: Option<ObligationToken<TransactionKind>>,
}

impl TransactionFinishEffect {
    fn new(
        transaction_state: Arc<Mutex<TransactionState>>,
        transaction_generation: Arc<AtomicU64>,
        expected_generation: u64,
        kind: TransactionFinishKind,
        obligation: Option<ObligationToken<TransactionKind>>,
    ) -> Self {
        Self {
            transaction_state,
            transaction_generation,
            expected_generation,
            kind,
            obligation,
        }
    }

    fn execute_worker(
        &mut self,
        conn: &rusqlite::Connection,
        sql: &str,
    ) -> Result<u64, SqliteError> {
        if self.transaction_generation.load(Ordering::Acquire) != self.expected_generation {
            if let Some(token) = self.obligation.take() {
                let _ = token.abort();
            }
            return Err(SqliteError::TransactionFinished);
        }
        if conn.is_autocommit() {
            let _ = advance_transaction_generation(self.transaction_generation.as_ref());
            *self.transaction_state.lock() = TransactionState::Autocommit;
            if let Some(token) = self.obligation.take() {
                let _ = token.abort();
            }
            return Err(SqliteError::TransactionFinished);
        }

        let result = conn
            .execute(sql, [])
            .map(|rows| rows as u64)
            .map_err(|error| SqliteError::Sqlite(error.to_string()));
        if result.is_ok() {
            let _ = advance_transaction_generation(self.transaction_generation.as_ref());
            *self.transaction_state.lock() = TransactionState::Autocommit;
            if let Some(token) = self.obligation.take() {
                match self.kind {
                    TransactionFinishKind::Commit => {
                        let _ = token.commit();
                    }
                    TransactionFinishKind::Rollback => {
                        let _ = token.abort();
                    }
                }
            }
        } else if let Some(token) = self.obligation.take() {
            let _ = token.abort();
        }
        result
    }

    fn execute_worker_diagnosed(
        &mut self,
        conn: &rusqlite::Connection,
        sql: &str,
        operation: SqliteOperation,
    ) -> Result<u64, SqliteOperationError> {
        if self.transaction_generation.load(Ordering::Acquire) != self.expected_generation {
            if let Some(token) = self.obligation.take() {
                let _ = token.abort();
            }
            return Err(SqliteOperationError::from_legacy(
                operation,
                SqliteError::TransactionFinished,
            ));
        }
        if conn.is_autocommit() {
            let _ = advance_transaction_generation(self.transaction_generation.as_ref());
            *self.transaction_state.lock() = TransactionState::Autocommit;
            if let Some(token) = self.obligation.take() {
                let _ = token.abort();
            }
            return Err(SqliteOperationError::from_legacy(
                operation,
                SqliteError::TransactionFinished,
            ));
        }

        let result = conn
            .execute(sql, [])
            .map(|rows| rows as u64)
            .map_err(|error| SqliteOperationError::from_rusqlite(operation, error));
        if result.is_ok() {
            let _ = advance_transaction_generation(self.transaction_generation.as_ref());
            *self.transaction_state.lock() = TransactionState::Autocommit;
            if let Some(token) = self.obligation.take() {
                match self.kind {
                    TransactionFinishKind::Commit => {
                        let _ = token.commit();
                    }
                    TransactionFinishKind::Rollback => {
                        let _ = token.abort();
                    }
                }
            }
        } else if let Some(token) = self.obligation.take() {
            let _ = token.abort();
        }
        result
    }
}

impl Drop for TransactionFinishEffect {
    fn drop(&mut self) {
        if let Some(token) = self.obligation.take() {
            let _ = token.abort();
        }
    }
}

struct BeginDropGuard {
    attempt: BeginAttempt,
    armed: bool,
}

impl BeginDropGuard {
    fn new(
        transaction_state: Arc<Mutex<TransactionState>>,
        transaction_generation: Arc<AtomicU64>,
    ) -> Self {
        Self {
            attempt: BeginAttempt::new(transaction_state, transaction_generation),
            armed: true,
        }
    }

    fn attempt(&self) -> BeginAttempt {
        self.attempt.clone()
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn opened_generation(&self) -> Option<u64> {
        self.attempt.lifecycle.lock().generation
    }

    fn abandon(&mut self) {
        if std::mem::replace(&mut self.armed, false) {
            self.attempt.abandon();
        }
    }
}

impl Drop for BeginDropGuard {
    fn drop(&mut self) {
        self.abandon();
    }
}

fn rollback_abandoned_begin_mutex_guarded(
    conn: &rusqlite::Connection,
    transaction_state: &Mutex<TransactionState>,
    transaction_generation: &AtomicU64,
) -> Result<(), SqliteError> {
    // `run_connection_op` still owns the connection mutex here. Do not gate on
    // the mirror: a cleanup or older transaction completion may have overtaken
    // this worker. Holding the state lock across the forced rollback prevents a
    // lagging completion from clearing the poison between publication and I/O.
    let mut state = transaction_state.lock();
    *state = TransactionState::RollingBack;

    if conn.is_autocommit() {
        let _ = advance_transaction_generation(transaction_generation);
        *state = TransactionState::Autocommit;
        return Ok(());
    }

    match conn.execute_batch("ROLLBACK") {
        Ok(()) => {
            let _ = advance_transaction_generation(transaction_generation);
            *state = TransactionState::Autocommit;
            Ok(())
        }
        Err(_) if conn.is_autocommit() => {
            let _ = advance_transaction_generation(transaction_generation);
            *state = TransactionState::Autocommit;
            Ok(())
        }
        Err(error) => {
            *state = TransactionState::NeedsRollback;
            Err(SqliteError::Sqlite(error.to_string()))
        }
    }
}

// `fetch_update` was renamed to `try_update` in nightly-2026-08-31 (the pinned
// toolchain), which makes the old name a `-D warnings` error in the
// all-features lint gate. The new name does not exist on the stable subset the
// audited stable lane builds, so keep the stable-compatible call and allow the
// deprecation until that lane's toolchain carries the rename.
#[allow(deprecated)]
fn advance_transaction_generation(transaction_generation: &AtomicU64) -> Option<u64> {
    transaction_generation
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |generation| {
            generation.checked_add(1)
        })
        .ok()
        .and_then(|generation| generation.checked_add(1))
}

fn rollback_orphaned_transaction_generation_guarded(
    conn: &rusqlite::Connection,
    transaction_state: &Mutex<TransactionState>,
    transaction_generation: &AtomicU64,
) -> Result<(), SqliteError> {
    if *transaction_state.lock() != TransactionState::NeedsRollback {
        return Ok(());
    }
    rollback_orphaned_transaction_mutex_guarded(conn, transaction_state)?;
    let _ = advance_transaction_generation(transaction_generation);
    *transaction_state.lock() = TransactionState::Autocommit;
    Ok(())
}

fn rollback_orphaned_transaction_mutex_guarded(
    conn: &rusqlite::Connection,
    transaction_state: &Mutex<TransactionState>,
) -> Result<(), SqliteError> {
    // Use mutex guard for proper synchronization
    let mut state_guard = transaction_state.lock();

    // Only proceed if state is NeedsRollback
    if *state_guard != TransactionState::NeedsRollback {
        return Ok(());
    }

    // Set to RollingBack state to prevent concurrent rollbacks
    *state_guard = TransactionState::RollingBack;

    // Drop the guard temporarily for the actual rollback operation
    // This allows other threads to see we're in the RollingBack state
    drop(state_guard);

    // Perform the rollback operation
    let final_state = if conn.is_autocommit() {
        TransactionState::Autocommit
    } else {
        match conn.execute_batch("ROLLBACK") {
            Ok(()) => TransactionState::Autocommit,
            Err(e) => {
                if conn.is_autocommit() {
                    TransactionState::Autocommit
                } else {
                    // Rollback failed, restore NeedsRollback state
                    let mut state_guard = transaction_state.lock();
                    *state_guard = TransactionState::NeedsRollback;
                    return Err(SqliteError::Sqlite(e.to_string()));
                }
            }
        }
    };

    // Re-acquire the guard and update to final state
    let mut state_guard = transaction_state.lock();
    *state_guard = final_state;
    Ok(())
}

// SECURITY FIX: Removed skip_sql_trivia and skip_sql_quoted functions
// These were part of the vulnerable custom SQL parser (asupersync-dn5hn8)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlSurfaceViolation {
    Pragma,
    TransactionControl,
    AttachDetach,
    Vacuum,
    ExtensionLoading,
    ParserRejected,
    StatementCount,
    ResourceLimit,
}

impl SqlSurfaceViolation {
    fn checked_surface_message(self) -> &'static str {
        match self {
            Self::Pragma => "PRAGMA statements require the explicit *_unchecked SQLite APIs",
            Self::TransactionControl => {
                "transaction or connection control statements require the explicit *_unchecked SQLite APIs"
            }
            Self::AttachDetach => "ATTACH and DETACH are disabled on the checked SQLite APIs",
            Self::Vacuum => {
                "VACUUM requires the explicit *_unchecked SQLite APIs because VACUUM INTO can write an arbitrary filesystem path"
            }
            Self::ExtensionLoading => {
                "SQLite extension loading is disabled on the checked SQLite APIs"
            }
            Self::ParserRejected => {
                "checked SQLite SQL must be accepted by the bounded policy parser; audited engine-specific SQL requires an explicit *_unchecked API"
            }
            Self::StatementCount => "this checked SQLite API requires exactly one SQL statement",
            Self::ResourceLimit => "SQLite SQL exceeds the checked-surface parser resource limits",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckedSqlCardinality {
    ExactlyOne,
    Batch,
}

const MAX_CHECKED_SQL_BYTES: usize = 1024 * 1024;
const MAX_CHECKED_SQL_RECURSION: usize = 128;

// SECURITY FIX: Removed TriggerScanState enum - no longer needed
// after replacing vulnerable custom SQL parser (asupersync-dn5hn8)

#[cfg(test)]
fn classify_sql_surface_violation(sql: &str) -> Option<SqlSurfaceViolation> {
    match parse_checked_sql(sql) {
        Ok(statements) => check_parsed_statements(&statements),
        Err(violation) => Some(violation),
    }
}

fn contains_extension_loading_call(sql: &str) -> Result<bool, SqlSurfaceViolation> {
    use sqlparser::dialect::SQLiteDialect;
    use sqlparser::tokenizer::{Token, Tokenizer};

    let dialect = SQLiteDialect {};
    let tokens = Tokenizer::new(&dialect, sql)
        .tokenize()
        .map_err(|_| SqlSurfaceViolation::ParserRejected)?;
    let mut significant = tokens
        .iter()
        .filter(|token| !matches!(token, Token::Whitespace(_)))
        .peekable();

    while let Some(token) = significant.next() {
        let Token::Word(word) = token else {
            continue;
        };
        if word.value.eq_ignore_ascii_case("load_extension")
            && significant
                .peek()
                .is_some_and(|next| matches!(next, Token::LParen))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn unchecked_sql_contains_attach_detach(sql: &str) -> bool {
    use sqlparser::ast::Statement;
    use sqlparser::dialect::SQLiteDialect;
    use sqlparser::parser::Parser;

    let dialect = SQLiteDialect {};
    match Parser::new(&dialect)
        .with_recursion_limit(MAX_CHECKED_SQL_RECURSION)
        .try_with_sql(sql)
        .and_then(|mut parser| parser.parse_statements())
    {
        Ok(statements) => statements.iter().any(|statement| {
            matches!(
                statement,
                Statement::AttachDatabase { .. }
                    | Statement::AttachDuckDBDatabase { .. }
                    | Statement::DetachDuckDBDatabase { .. }
            )
        }),
        Err(_) => remove_sql_comments(sql).split(';').any(|statement| {
            let statement = statement.trim().to_ascii_uppercase();
            starts_with_sql_keyword(&statement, "ATTACH")
                || starts_with_sql_keyword(&statement, "DETACH")
        }),
    }
}

/// Check parsed SQL AST statements for violations
fn check_parsed_statements(
    statements: &[sqlparser::ast::Statement],
) -> Option<SqlSurfaceViolation> {
    use sqlparser::ast::Statement;

    for statement in statements {
        match statement {
            // PRAGMA statements are always blocked on checked surface.
            Statement::Pragma { .. } => {
                return Some(SqlSurfaceViolation::Pragma);
            }
            // Older sqlparser versions and non-SQLite dialect paths represented
            // some session-control forms as `SET` assignments (now unified under
            // `Statement::Set`). Keep this defensive guard so future parser drift
            // does not silently reopen PRAGMA-like checked-surface control
            // statements.
            Statement::Set(_) if is_pragma_statement(statement) => {
                return Some(SqlSurfaceViolation::Pragma);
            }
            // ATTACH/DETACH statements are always blocked
            Statement::AttachDatabase { .. }
            | Statement::AttachDuckDBDatabase { .. }
            | Statement::DetachDuckDBDatabase { .. } => {
                return Some(SqlSurfaceViolation::AttachDetach);
            }
            // Plain VACUUM is connection control, while SQLite's `VACUUM
            // INTO` form can create or replace a filesystem path. Keep both
            // behind the explicit unchecked surface.
            Statement::Vacuum(_) => {
                return Some(SqlSurfaceViolation::Vacuum);
            }
            // Transaction control statements are blocked on checked surface
            Statement::StartTransaction { .. }
            | Statement::Commit { .. }
            | Statement::Rollback { .. }
            | Statement::Savepoint { .. }
            | Statement::ReleaseSavepoint { .. } => {
                return Some(SqlSurfaceViolation::TransactionControl);
            }
            // CREATE TRIGGER can contain BEGIN/END but should be allowed
            Statement::CreateTrigger { .. } => {
                // Allow triggers - they have their own transaction scope
            }
            _ => {}
        }
    }
    None
}

/// Check if a statement is a PRAGMA (SQLite-specific)
fn is_pragma_statement(statement: &sqlparser::ast::Statement) -> bool {
    use sqlparser::ast::{ObjectName, Set, Statement};

    // sqlparser unified the various `SET ...` forms under `Statement::Set(Set)`.
    // SQLite PRAGMAs normally parse as `Statement::Pragma`, but keep this guard so
    // any PRAGMA-like assignment form (parser drift / non-SQLite dialect paths) is
    // still classified as checked-surface PRAGMA control.
    fn name_is_pragma(name: &ObjectName) -> bool {
        name.to_string().to_uppercase().starts_with("PRAGMA")
    }

    let Statement::Set(set) = statement else {
        return false;
    };
    match set {
        Set::SingleAssignment { variable, .. } => name_is_pragma(variable),
        Set::ParenthesizedAssignments { variables, .. } => variables.iter().any(name_is_pragma),
        Set::MultipleAssignments { assignments } => {
            assignments.iter().any(|a| name_is_pragma(&a.name))
        }
        _ => false,
    }
}

/// Fallback keyword detection when SQL parsing fails
fn check_sql_keywords_fallback(sql: &str) -> Option<SqlSurfaceViolation> {
    let sql_upper = sql.to_uppercase();

    // Remove comments for keyword detection
    let sql_clean = remove_sql_comments(&sql_upper);

    // Check for dangerous keywords at statement boundaries
    let statements: Vec<&str> = sql_clean.split(';').map(|s| s.trim()).collect();

    for stmt in statements {
        if stmt.is_empty() {
            continue;
        }

        // Check for PRAGMA
        if starts_with_sql_keyword(stmt, "PRAGMA") {
            return Some(SqlSurfaceViolation::Pragma);
        }

        // Check for ATTACH/DETACH
        if starts_with_sql_keyword(stmt, "ATTACH") || starts_with_sql_keyword(stmt, "DETACH") {
            return Some(SqlSurfaceViolation::AttachDetach);
        }

        // `sqlparser` does not model every SQLite-specific VACUUM form (most
        // importantly VACUUM INTO), so the fail-closed fallback must retain
        // this boundary even when the primary parser rejects the statement.
        if starts_with_sql_keyword(stmt, "VACUUM") {
            return Some(SqlSurfaceViolation::Vacuum);
        }

        // Check for transaction control (excluding CREATE TRIGGER)
        if !stmt.contains(" TRIGGER ") {
            if starts_with_sql_keyword(stmt, "BEGIN")
                || starts_with_sql_keyword(stmt, "COMMIT")
                || starts_with_sql_keyword(stmt, "ROLLBACK")
                || starts_with_sql_keyword(stmt, "SAVEPOINT")
                || starts_with_sql_keyword(stmt, "RELEASE")
                || starts_with_sql_keyword(stmt, "END")
            {
                return Some(SqlSurfaceViolation::TransactionControl);
            }
        }
    }

    None
}

fn starts_with_sql_keyword(statement: &str, keyword: &str) -> bool {
    statement.strip_prefix(keyword).is_some_and(|suffix| {
        suffix
            .chars()
            .next()
            .is_none_or(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$')))
    })
}

/// Remove SQL comments (fallback implementation)
fn remove_sql_comments(sql: &str) -> String {
    let mut result = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '-' if chars.peek() == Some(&'-') => {
                // Skip line comment
                chars.next(); // Skip second '-'
                for ch in chars.by_ref() {
                    if ch == '\n' || ch == '\r' {
                        result.push(' ');
                        break;
                    }
                }
            }
            '/' if chars.peek() == Some(&'*') => {
                // Skip block comment
                chars.next(); // Skip '*'
                while let Some(ch) = chars.next() {
                    if ch == '*' && chars.peek() == Some(&'/') {
                        chars.next(); // Skip '/'
                        break;
                    }
                }
                result.push(' ');
            }
            '\'' | '"' | '`' => {
                // Handle quoted strings - preserve them but don't process inside
                let quote = ch;
                result.push(ch);
                while let Some(ch) = chars.next() {
                    result.push(ch);
                    if ch == quote {
                        // Check for escaped quote
                        if chars.peek() == Some(&quote) {
                            chars.next(); // Skip escaped quote
                            result.push(quote);
                        } else {
                            break;
                        }
                    }
                }
            }
            _ => result.push(ch),
        }
    }

    result
}

// SECURITY FIX: Removed old custom parsing functions that were vulnerable
// to parser divergence attacks. Replaced with sqlparser-rs integration.

fn parse_checked_sql(sql: &str) -> Result<Vec<sqlparser::ast::Statement>, SqlSurfaceViolation> {
    use sqlparser::dialect::SQLiteDialect;
    use sqlparser::parser::Parser;

    if sql.len() > MAX_CHECKED_SQL_BYTES {
        return Err(SqlSurfaceViolation::ResourceLimit);
    }

    let dialect = SQLiteDialect {};
    let statements = Parser::new(&dialect)
        .with_recursion_limit(MAX_CHECKED_SQL_RECURSION)
        .try_with_sql(sql)
        .and_then(|mut parser| parser.parse_statements())
        .map_err(|_| {
            check_sql_keywords_fallback(sql).unwrap_or(SqlSurfaceViolation::ParserRejected)
        })?;
    if contains_extension_loading_call(sql)? {
        return Err(SqlSurfaceViolation::ExtensionLoading);
    }
    Ok(statements)
}

fn ensure_checked_sql_surface(
    sql: &str,
    cardinality: CheckedSqlCardinality,
) -> Result<(), SqliteError> {
    let statements = parse_checked_sql(sql).map_err(|violation| {
        SqliteError::UnsafeSql(violation.checked_surface_message().to_string())
    })?;

    if cardinality == CheckedSqlCardinality::ExactlyOne && statements.len() != 1 {
        return Err(SqliteError::UnsafeSql(
            SqlSurfaceViolation::StatementCount
                .checked_surface_message()
                .to_string(),
        ));
    }

    if let Some(violation) = check_parsed_statements(&statements) {
        return Err(SqliteError::UnsafeSql(
            violation.checked_surface_message().to_string(),
        ));
    }
    Ok(())
}

/// Validate one statement against the checked SQLite SQL policy without
/// executing it.
///
/// This is the same bounded, fail-closed admission used by [`SqliteConnection::execute`],
/// [`SqliteConnection::query`], [`SqliteConnection::query_row`], and
/// [`SqliteConnection::query_stream`]. It is public so companion adapters can
/// apply the identical policy before dispatching SQL to another SQLite engine.
pub fn validate_checked_sql_statement(sql: &str) -> Result<(), SqliteError> {
    ensure_checked_sql_surface(sql, CheckedSqlCardinality::ExactlyOne)
}

/// Validate zero or more statements against the checked SQLite batch policy
/// without executing them.
///
/// Batch validation retains the same parser size, recursion, control-statement,
/// attachment, vacuum, and extension-loading restrictions as the one-statement
/// policy; only the statement-count restriction differs.
pub fn validate_checked_sql_batch(sql: &str) -> Result<(), SqliteError> {
    ensure_checked_sql_surface(sql, CheckedSqlCardinality::Batch)
}

fn ensure_unchecked_sql_surface(sql: &str) -> Result<(), SqliteError> {
    if unchecked_sql_contains_attach_detach(sql) {
        return Err(SqliteError::UnsafeSql(
            "ATTACH and DETACH are disabled on SQLite connections; open a separate validated connection instead"
                .to_string(),
        ));
    }
    Ok(())
}

fn resolve_sqlite_open_path(path: &Path) -> Result<PathBuf, SqliteError> {
    if path.exists() {
        return std::fs::canonicalize(path).map_err(SqliteError::Io);
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent).map_err(SqliteError::Io)?;
    let file_name = path.file_name().ok_or_else(|| {
        SqliteError::UnsafePath("SQLite database path must resolve to a file name".to_string())
    })?;
    Ok(canonical_parent.join(file_name))
}

/// Lexical path checks that must run on the raw, pre-resolution input:
/// canonicalization erases `~` and `..` components, so running these after
/// resolution would either mask the rejection (traversal that resolves to an
/// allowed directory) or surface it as an unrelated Io error (tilde paths
/// whose literal `~` parent does not exist).
fn validate_sqlite_open_path_lexical(path: &Path) -> Result<(), SqliteError> {
    let raw = path.as_os_str().to_string_lossy();
    if raw.starts_with('~') {
        return Err(SqliteError::UnsafePath(
            "tilde-prefixed SQLite paths are rejected; pass an explicit validated path".to_string(),
        ));
    }

    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SqliteError::UnsafePath(
            "parent-directory traversal in SQLite paths is rejected; pass a normalized validated path"
                .to_string(),
        ));
    }

    Ok(())
}

#[cfg(any(test, feature = "test-internals"))]
fn validate_sqlite_open_path(path: &Path) -> Result<(), SqliteError> {
    validate_sqlite_open_path_lexical(path)?;
    let resolved = resolve_sqlite_open_path(path)?;
    validate_resolved_sqlite_path(&resolved)
}

/// Validate a resolved (canonicalized) SQLite path for security restrictions
/// This function operates on already-resolved paths to avoid TOCTOU vulnerabilities
fn validate_resolved_sqlite_path(resolved_path: &Path) -> Result<(), SqliteError> {
    // SECURITY: Check resolved path against restricted system directories.
    // The candidate is canonical, so compare against the canonical form of
    // each restricted root too: on macOS /etc is a symlink to /private/etc
    // and a resolved path never starts with the literal "/etc"
    // (br-asupersync-bi2462.21.3).
    fn resolves_into(resolved_path: &Path, restricted: &str) -> bool {
        resolved_path.starts_with(Path::new(restricted))
            || std::fs::canonicalize(restricted)
                .is_ok_and(|canonical| resolved_path.starts_with(&canonical))
    }
    if resolves_into(resolved_path, "/etc") {
        return Err(SqliteError::UnsafePath(format!(
            "SQLite database path resolves into restricted system directory: {}",
            resolved_path.display()
        )));
    }

    // SECURITY: Additional system directory restrictions
    if resolved_path.starts_with(Path::new("/sys")) {
        return Err(SqliteError::UnsafePath(format!(
            "SQLite database path resolves into restricted /sys directory: {}",
            resolved_path.display()
        )));
    }

    if resolved_path.starts_with(Path::new("/proc")) {
        return Err(SqliteError::UnsafePath(format!(
            "SQLite database path resolves into restricted /proc directory: {}",
            resolved_path.display()
        )));
    }

    if resolved_path.starts_with(Path::new("/dev")) {
        return Err(SqliteError::UnsafePath(format!(
            "SQLite database path resolves into restricted /dev directory: {}",
            resolved_path.display()
        )));
    }

    Ok(())
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_validate_sqlite_open_path(path: &Path) -> Result<(), SqliteError> {
    validate_sqlite_open_path(path)
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
    /// Raw engine-control SQL hit a restricted binding surface.
    UnsafeSql(String),
    /// Database path was rejected by the validated open surface.
    UnsafePath(String),
    /// TEXT value was not valid UTF-8.
    InvalidTextEncoding {
        /// Column name or index.
        column: String,
        /// UTF-8 decoding error.
        source: std::str::Utf8Error,
    },
    /// WAL checkpoint operation failed.
    WalCheckpointFailed(String),
    /// Statement aborted by the budget-derived statement timeout
    /// (br-asupersync-server-stack-hardening-eeexl1.1.2). The deadline
    /// progress handler interrupted the statement once
    /// `min(remaining Cx budget, per-connection override)` elapsed.
    StatementTimeout {
        /// Effective limit that fired.
        limit: std::time::Duration,
    },
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
            Self::UnsafePath(_) => Some("SQLITE_PERM"),
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
            Self::UnsafeSql(msg) => {
                write!(
                    f,
                    "Unsafe SQLite control SQL on SQLite binding surface: {msg}"
                )
            }
            Self::UnsafePath(msg) => write!(f, "Unsafe SQLite database path: {msg}"),
            Self::InvalidTextEncoding { column, source } => {
                write!(
                    f,
                    "SQLite text column {column} contained invalid UTF-8: {source}"
                )
            }
            Self::WalCheckpointFailed(msg) => write!(f, "WAL checkpoint failed: {msg}"),
            Self::StatementTimeout { limit } => write!(
                f,
                "statement aborted by budget-derived statement timeout ({limit:?})"
            ),
        }
    }
}

impl std::error::Error for SqliteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::InvalidTextEncoding { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SqliteError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

/// Stage of a SQLite operation that produced a structured diagnostic.
///
/// This is an additive companion to the v0.4.3-compatible [`SqliteError`]
/// surface. It deliberately describes the operation boundary rather than
/// exposing rusqlite implementation types.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteOperation {
    /// Opening a database connection.
    Open,
    /// Preparing SQL for execution.
    Prepare,
    /// Binding caller-supplied parameters.
    Bind,
    /// Stepping a prepared statement.
    Step,
    /// Executing a batch of statements.
    ExecuteBatch,
    /// Beginning a transaction.
    TransactionBegin,
    /// Committing a transaction.
    TransactionCommit,
    /// Rolling back a transaction.
    TransactionRollback,
    /// Configuring a connection.
    Configure,
    /// Closing or draining a connection.
    Close,
    /// Communicating with the blocking-pool worker.
    BlockingPool,
    /// Rejecting input before it reaches SQLite.
    Validation,
}

impl SqliteOperation {
    #[must_use]
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Prepare => "prepare",
            Self::Bind => "bind",
            Self::Step => "step",
            Self::ExecuteBatch => "execute_batch",
            Self::TransactionBegin => "transaction_begin",
            Self::TransactionCommit => "transaction_commit",
            Self::TransactionRollback => "transaction_rollback",
            Self::Configure => "configure",
            Self::Close => "close",
            Self::BlockingPool => "blocking_pool",
            Self::Validation => "validation",
        }
    }
}

/// Stable, engine-neutral classification for a SQLite failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteErrorCategory {
    /// The database is busy and the operation may be retried.
    Busy,
    /// A table or schema object is locked and the operation may be retried.
    Locked,
    /// A database constraint rejected the operation.
    Constraint,
    /// SQLite reported `SQLITE_INTERRUPT`.
    Interrupted,
    /// A caller budget or configured statement timeout expired.
    Timeout,
    /// SQLite or the validated path policy denied access.
    PermissionDenied,
    /// The database is read-only for the attempted operation.
    ReadOnly,
    /// An operating-system or database I/O operation failed.
    Io,
    /// SQLite reported corrupt or non-database bytes.
    Corrupt,
    /// Memory, disk, or a configured size limit was exhausted.
    ResourceExhausted,
    /// SQL, parameters, a path, or a row conversion was invalid.
    InvalidInput,
    /// A requested database object was not found.
    NotFound,
    /// The connection is closed or no longer usable.
    Closed,
    /// The structured operation was cancelled.
    Cancelled,
    /// An internal invariant, lock, or API contract failed.
    Internal,
    /// The legacy error did not retain enough structured information.
    Unknown,
}

impl SqliteErrorCategory {
    #[must_use]
    const fn operator_code(self) -> &'static str {
        match self {
            Self::Busy => "sqlite.busy",
            Self::Locked => "sqlite.locked",
            Self::Constraint => "sqlite.constraint",
            Self::Interrupted => "sqlite.interrupted",
            Self::Timeout => "sqlite.timeout",
            Self::PermissionDenied => "sqlite.permission_denied",
            Self::ReadOnly => "sqlite.read_only",
            Self::Io => "sqlite.io",
            Self::Corrupt => "sqlite.corrupt",
            Self::ResourceExhausted => "sqlite.resource_exhausted",
            Self::InvalidInput => "sqlite.invalid_input",
            Self::NotFound => "sqlite.not_found",
            Self::Closed => "sqlite.closed",
            Self::Cancelled => "sqlite.cancelled",
            Self::Internal => "sqlite.internal",
            Self::Unknown => "sqlite.unknown",
        }
    }
}

/// Whether retrying a failed SQLite operation is appropriate.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteRetryDisposition {
    /// Retrying would repeat a terminal or caller-directed outcome.
    Never,
    /// The same operation may be retried subject to caller policy.
    RetryOperation,
    /// Reopen the connection before retrying.
    ReopenConnection,
}

/// Structured SQLite diagnostic captured before the legacy string conversion.
///
/// The diagnostic intentionally excludes SQL text, bound values, paths, and
/// engine messages so `Debug` output is safe for ordinary telemetry. The
/// original v0.4.3-compatible error remains available through
/// [`SqliteOperationError::legacy_error`] when a caller explicitly needs it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteErrorDiagnostic {
    operation: SqliteOperation,
    category: SqliteErrorCategory,
    primary_code: Option<&'static str>,
    extended_code: Option<i32>,
    retry: SqliteRetryDisposition,
    connection_error: bool,
}

impl SqliteErrorDiagnostic {
    /// Operation stage that failed.
    #[must_use]
    pub const fn operation(&self) -> SqliteOperation {
        self.operation
    }

    /// Stable engine-neutral category.
    #[must_use]
    pub const fn category(&self) -> SqliteErrorCategory {
        self.category
    }

    /// Stable operator-facing token that does not contain user data.
    #[must_use]
    pub const fn operator_code(&self) -> &'static str {
        self.category.operator_code()
    }

    /// Primary SQLite code name, such as `SQLITE_BUSY`, when SQLite supplied
    /// one directly.
    #[must_use]
    pub const fn primary_code(&self) -> Option<&'static str> {
        self.primary_code
    }

    /// Raw extended SQLite result code, when SQLite supplied one directly.
    #[must_use]
    pub const fn extended_code(&self) -> Option<i32> {
        self.extended_code
    }

    /// Retry policy implied by the structured failure.
    #[must_use]
    pub const fn retry_disposition(&self) -> SqliteRetryDisposition {
        self.retry
    }

    /// Whether retrying the same operation is permitted by the diagnostic.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self.retry, SqliteRetryDisposition::RetryOperation)
    }

    /// Whether recovery should replace or reopen the connection.
    #[must_use]
    pub const fn is_connection_error(&self) -> bool {
        self.connection_error
    }

    fn from_legacy(operation: SqliteOperation, error: &SqliteError) -> Self {
        let (category, retry, connection_error) = match error {
            SqliteError::Cancelled(_) => (
                SqliteErrorCategory::Cancelled,
                SqliteRetryDisposition::Never,
                false,
            ),
            SqliteError::ConnectionClosed => (
                SqliteErrorCategory::Closed,
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            SqliteError::ColumnNotFound(_) => (
                SqliteErrorCategory::NotFound,
                SqliteRetryDisposition::Never,
                false,
            ),
            SqliteError::TypeMismatch { .. }
            | SqliteError::UnsafeSql(_)
            | SqliteError::InvalidTextEncoding { .. }
            | SqliteError::TransactionFinished => (
                SqliteErrorCategory::InvalidInput,
                SqliteRetryDisposition::Never,
                false,
            ),
            SqliteError::UnsafePath(_) => (
                SqliteErrorCategory::PermissionDenied,
                SqliteRetryDisposition::Never,
                false,
            ),
            SqliteError::Io(_) => (
                SqliteErrorCategory::Io,
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            SqliteError::LockPoisoned => (
                SqliteErrorCategory::Internal,
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            SqliteError::StatementTimeout { .. } => (
                SqliteErrorCategory::Timeout,
                SqliteRetryDisposition::Never,
                false,
            ),
            SqliteError::WalCheckpointFailed(_) => (
                SqliteErrorCategory::Io,
                SqliteRetryDisposition::RetryOperation,
                false,
            ),
            // The legacy public variant intentionally retains its v0.4.3
            // payload. It cannot be classified without parsing prose, which
            // this additive surface refuses to do.
            SqliteError::Sqlite(_) => (
                SqliteErrorCategory::Unknown,
                SqliteRetryDisposition::Never,
                false,
            ),
        };
        Self {
            operation,
            category,
            primary_code: None,
            extended_code: None,
            retry,
            connection_error,
        }
    }

    fn from_rusqlite(operation: SqliteOperation, error: &rusqlite::Error) -> Self {
        // rusqlite exposes parser failures as `SqlInputError`, which retains
        // SQLite's structured code but is intentionally not returned by the
        // `sqlite_error_*` accessors (those only match `SqliteFailure`). Keep
        // that structured source instead of degrading malformed SQL to an
        // unclassified, code-less input error.
        let (code, extended_code) = match error {
            rusqlite::Error::SqlInputError { error, .. } => {
                (Some(error.code), Some(error.extended_code))
            }
            _ => (
                error.sqlite_error_code(),
                error.sqlite_extended_error_code(),
            ),
        };
        let (category, primary_code, retry, connection_error) = match code {
            Some(rusqlite::ffi::ErrorCode::DatabaseBusy) => (
                SqliteErrorCategory::Busy,
                Some("SQLITE_BUSY"),
                SqliteRetryDisposition::RetryOperation,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::DatabaseLocked) => (
                SqliteErrorCategory::Locked,
                Some("SQLITE_LOCKED"),
                SqliteRetryDisposition::RetryOperation,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::ConstraintViolation) => (
                SqliteErrorCategory::Constraint,
                Some("SQLITE_CONSTRAINT"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::OperationInterrupted) => (
                SqliteErrorCategory::Interrupted,
                Some("SQLITE_INTERRUPT"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::PermissionDenied) => (
                SqliteErrorCategory::PermissionDenied,
                Some("SQLITE_PERM"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::AuthorizationForStatementDenied) => (
                SqliteErrorCategory::PermissionDenied,
                Some("SQLITE_AUTH"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::ReadOnly) => (
                SqliteErrorCategory::ReadOnly,
                Some("SQLITE_READONLY"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::SystemIoFailure) => (
                SqliteErrorCategory::Io,
                Some("SQLITE_IOERR"),
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            Some(rusqlite::ffi::ErrorCode::DatabaseCorrupt) => (
                SqliteErrorCategory::Corrupt,
                Some("SQLITE_CORRUPT"),
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            Some(rusqlite::ffi::ErrorCode::NotADatabase) => (
                SqliteErrorCategory::Corrupt,
                Some("SQLITE_NOTADB"),
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            Some(rusqlite::ffi::ErrorCode::OutOfMemory) => (
                SqliteErrorCategory::ResourceExhausted,
                Some("SQLITE_NOMEM"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::DiskFull) => (
                SqliteErrorCategory::ResourceExhausted,
                Some("SQLITE_FULL"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::TooBig) => (
                SqliteErrorCategory::ResourceExhausted,
                Some("SQLITE_TOOBIG"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::CannotOpen) => (
                SqliteErrorCategory::Io,
                Some("SQLITE_CANTOPEN"),
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            Some(rusqlite::ffi::ErrorCode::NotFound) => (
                SqliteErrorCategory::NotFound,
                Some("SQLITE_NOTFOUND"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::SchemaChanged) => (
                SqliteErrorCategory::Internal,
                Some("SQLITE_SCHEMA"),
                SqliteRetryDisposition::RetryOperation,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::TypeMismatch) => (
                SqliteErrorCategory::InvalidInput,
                Some("SQLITE_MISMATCH"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::ParameterOutOfRange) => (
                SqliteErrorCategory::InvalidInput,
                Some("SQLITE_RANGE"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::ApiMisuse) => (
                SqliteErrorCategory::Internal,
                Some("SQLITE_MISUSE"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::OperationAborted) => (
                SqliteErrorCategory::Internal,
                Some("SQLITE_ABORT"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::FileLockingProtocolFailed) => (
                SqliteErrorCategory::Io,
                Some("SQLITE_PROTOCOL"),
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            Some(rusqlite::ffi::ErrorCode::InternalMalfunction) => (
                SqliteErrorCategory::Internal,
                Some("SQLITE_INTERNAL"),
                SqliteRetryDisposition::ReopenConnection,
                true,
            ),
            Some(rusqlite::ffi::ErrorCode::NoLargeFileSupport) => (
                SqliteErrorCategory::Internal,
                Some("SQLITE_NOLFS"),
                SqliteRetryDisposition::Never,
                false,
            ),
            Some(rusqlite::ffi::ErrorCode::Unknown) => (
                if matches!(
                    operation,
                    SqliteOperation::Prepare
                        | SqliteOperation::Bind
                        | SqliteOperation::TransactionBegin
                ) {
                    SqliteErrorCategory::InvalidInput
                } else {
                    SqliteErrorCategory::Unknown
                },
                Some("SQLITE_ERROR"),
                SqliteRetryDisposition::Never,
                false,
            ),
            None => {
                let operation = match error {
                    rusqlite::Error::InvalidParameterCount(_, _)
                    | rusqlite::Error::InvalidParameterName(_)
                    | rusqlite::Error::NulError(_)
                    | rusqlite::Error::ToSqlConversionFailure(_) => SqliteOperation::Bind,
                    _ => operation,
                };
                return Self {
                    operation,
                    category: SqliteErrorCategory::InvalidInput,
                    primary_code: None,
                    extended_code: None,
                    retry: SqliteRetryDisposition::Never,
                    connection_error: false,
                };
            }
            Some(_) => (
                SqliteErrorCategory::Unknown,
                None,
                SqliteRetryDisposition::Never,
                false,
            ),
        };
        Self {
            operation,
            category,
            primary_code,
            extended_code,
            retry,
            connection_error,
        }
    }
}

/// Additive structured error for the `*_diagnosed` SQLite APIs.
///
/// Existing methods continue to return [`SqliteError`] exactly as they did in
/// v0.4.3. This wrapper keeps that legacy value available while exposing the
/// structured diagnostic captured before rusqlite renders an engine failure
/// into prose. For engine-originated failures, [`Self::engine_source`] retains
/// the original error behind an explicit accessor; ordinary `Debug`,
/// `Display`, and automatic error-chain traversal deliberately omit that
/// potentially sensitive source.
pub struct SqliteOperationError {
    diagnostic: SqliteErrorDiagnostic,
    legacy: SqliteError,
    engine_source: Option<rusqlite::Error>,
}

impl SqliteOperationError {
    fn from_rusqlite(operation: SqliteOperation, error: rusqlite::Error) -> Self {
        let diagnostic = SqliteErrorDiagnostic::from_rusqlite(operation, &error);
        let rendered = error.to_string();
        Self {
            diagnostic,
            legacy: SqliteError::Sqlite(rendered),
            engine_source: Some(error),
        }
    }

    fn from_legacy(operation: SqliteOperation, legacy: SqliteError) -> Self {
        let diagnostic = SqliteErrorDiagnostic::from_legacy(operation, &legacy);
        Self {
            diagnostic,
            legacy,
            engine_source: None,
        }
    }

    /// Structured, redaction-safe diagnostic.
    #[must_use]
    pub const fn diagnostic(&self) -> &SqliteErrorDiagnostic {
        &self.diagnostic
    }

    /// Original v0.4.3-compatible error value.
    #[must_use]
    pub const fn legacy_error(&self) -> &SqliteError {
        &self.legacy
    }

    /// Original engine error, when SQLite produced the failure directly.
    ///
    /// Access is explicit because the engine message can contain SQL fragments
    /// or schema names. Automatic error-chain reporters do not receive it.
    #[must_use]
    pub fn engine_source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.engine_source
            .as_ref()
            .map(|error| error as &(dyn std::error::Error + 'static))
    }

    /// Consume the wrapper and recover the original error value.
    #[must_use]
    pub fn into_legacy(self) -> SqliteError {
        self.legacy
    }
}

impl fmt::Debug for SqliteOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteOperationError")
            .field("diagnostic", &self.diagnostic)
            .field("legacy", &"<redacted; call legacy_error() explicitly>")
            .finish()
    }
}

impl fmt::Display for SqliteOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] SQLite {} failed",
            self.diagnostic.operator_code(),
            self.diagnostic.operation().as_str()
        )?;
        if let Some(primary) = self.diagnostic.primary_code() {
            write!(f, " ({primary}")?;
            if let Some(extended) = self.diagnostic.extended_code() {
                write!(f, ", extended={extended}")?;
            }
            write!(f, ")")?;
        }
        Ok(())
    }
}

impl std::error::Error for SqliteOperationError {}

fn diagnose_legacy_outcome<T>(
    operation: SqliteOperation,
    outcome: Outcome<T, SqliteError>,
) -> Outcome<T, SqliteOperationError> {
    match outcome {
        Outcome::Ok(value) => Outcome::Ok(value),
        Outcome::Err(error) => Outcome::Err(SqliteOperationError::from_legacy(operation, error)),
        Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
        Outcome::Panicked(payload) => Outcome::Panicked(payload),
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
    ///
    /// For compatibility with v0.4.3, integer values are widened with Rust's
    /// `i64 as f64` conversion. That conversion can lose precision outside the
    /// exactly representable binary64 integer range. Use
    /// [`SqliteValue::as_real_strict`] when integer coercion is not acceptable.
    #[must_use]
    pub fn as_real(&self) -> Option<f64> {
        match self {
            Self::Real(v) => Some(*v),
            #[allow(clippy::cast_precision_loss)]
            Self::Integer(v) => Some(*v as f64),
            _ => None,
        }
    }

    /// Tries to get only a SQLite REAL value without coercing INTEGER values.
    #[must_use]
    pub fn as_real_strict(&self) -> Option<f64> {
        match self {
            Self::Real(v) => Some(*v),
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
#[derive(Clone)]
pub struct SqliteRow {
    /// Legacy exact-name mapping. Duplicate names intentionally resolve to the
    /// last matching column for compatibility with the v0.4.3 API.
    columns: Arc<BTreeMap<String, usize>>,
    /// Column names in SQLite result-set order, including duplicates.
    ordered_columns: Arc<[String]>,
    /// Row values.
    values: Vec<SqliteValue>,
}

impl fmt::Debug for SqliteRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep the v0.4.3 derived-Debug shape stable; ordered metadata is an
        // additive implementation detail, not a new diagnostic contract.
        f.debug_struct("SqliteRow")
            .field("columns", &self.columns)
            .field("values", &self.values)
            .finish()
    }
}

impl SqliteRow {
    /// Creates a new row from column names and values.
    fn new(
        columns: Arc<BTreeMap<String, usize>>,
        ordered_columns: Arc<[String]>,
        values: Vec<SqliteValue>,
    ) -> Self {
        Self {
            columns,
            ordered_columns,
            values,
        }
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
    ///
    /// For compatibility with v0.4.3, this accepts INTEGER values via the
    /// potentially lossy widening performed by [`SqliteValue::as_real`]. Use
    /// [`SqliteRow::get_f64_strict`] to require the SQLite REAL storage class.
    pub fn get_f64(&self, column: &str) -> Result<f64, SqliteError> {
        let val = self.get(column)?;
        val.as_real().ok_or_else(|| SqliteError::TypeMismatch {
            column: column.to_string(),
            expected: "real",
            actual: format!("{val:?}"),
        })
    }

    /// Gets a SQLite REAL value by column name without coercing INTEGER values.
    pub fn get_f64_strict(&self, column: &str) -> Result<f64, SqliteError> {
        let val = self.get(column)?;
        val.as_real_strict()
            .ok_or_else(|| SqliteError::TypeMismatch {
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

    /// Returns an iterator over unique column names in sorted order.
    ///
    /// This preserves the v0.4.3 behavior. Use
    /// [`SqliteRow::column_names_in_order`] when result-set order and duplicate
    /// names matter.
    pub fn column_names(&self) -> impl Iterator<Item = &str> {
        self.columns.keys().map(String::as_str)
    }

    /// Returns an iterator over column names in result-set order.
    ///
    /// Unlike [`SqliteRow::column_names`], this retains duplicate names.
    pub fn column_names_in_order(&self) -> impl ExactSizeIterator<Item = &str> {
        self.ordered_columns.iter().map(String::as_str)
    }

    /// Returns the name of the column at `index` in result-set order.
    #[must_use]
    pub fn column_name(&self, index: usize) -> Option<&str> {
        self.ordered_columns.get(index).map(String::as_str)
    }

    /// Returns the first column index matching `name` using SQLite's
    /// ASCII-case-insensitive name comparison.
    ///
    /// This is the duplicate-preserving counterpart to the legacy
    /// exact-name, last-match behavior of [`SqliteRow::get`].
    #[must_use]
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.ordered_columns
            .iter()
            .position(|column| column.eq_ignore_ascii_case(name))
    }
}

#[derive(Debug, Default)]
struct SqliteRowStreamCounters {
    rows_stepped: AtomicUsize,
    rows_yielded: AtomicUsize,
    buffered_rows: AtomicUsize,
    peak_buffered_rows: AtomicUsize,
}

impl SqliteRowStreamCounters {
    fn record_buffered_row(&self) {
        // Use saturating arithmetic to prevent overflow in row buffering metrics
        let buffered = self
            .buffered_rows
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);
        let observed = buffered.min(SQLITE_ROW_STREAM_CHANNEL_CAPACITY);
        let mut peak = self.peak_buffered_rows.load(Ordering::Acquire);
        while observed > peak {
            match self.peak_buffered_rows.compare_exchange_weak(
                peak,
                observed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => peak = current,
            }
        }
    }

    fn record_yielded_row(&self) {
        self.buffered_rows.fetch_sub(1, Ordering::AcqRel);
        self.rows_yielded.fetch_add(1, Ordering::AcqRel);
    }

    fn snapshot(&self) -> SqliteRowStreamStats {
        SqliteRowStreamStats {
            rows_stepped: self.rows_stepped.load(Ordering::Acquire),
            rows_yielded: self.rows_yielded.load(Ordering::Acquire),
            buffered_rows: self.buffered_rows.load(Ordering::Acquire),
            peak_buffered_rows: self.peak_buffered_rows.load(Ordering::Acquire),
            channel_capacity: SQLITE_ROW_STREAM_CHANNEL_CAPACITY,
        }
    }
}

/// Bounded-memory progress counters for a SQLite row stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteRowStreamStats {
    /// Rows stepped by the blocking SQLite worker.
    pub rows_stepped: usize,
    /// Rows yielded to the async caller.
    pub rows_yielded: usize,
    /// Rows currently buffered between the blocking worker and async caller.
    pub buffered_rows: usize,
    /// Highest observed buffered row count for this stream.
    pub peak_buffered_rows: usize,
    /// Fixed channel capacity used by the stream.
    pub channel_capacity: usize,
}

type SqliteRowStreamMessage = Result<SqliteRow, SqliteError>;

fn send_sqlite_stream_message(
    sender: &mpsc::Sender<SqliteRowStreamMessage>,
    counters: &SqliteRowStreamCounters,
    mut message: SqliteRowStreamMessage,
) -> bool {
    let is_row = message.is_ok();
    loop {
        match sender.try_reserve() {
            Ok(permit) => {
                if is_row {
                    counters.record_buffered_row();
                }
                match permit.send(message) {
                    Outcome::Ok(()) => return true,
                    Outcome::Err(
                        mpsc::SendError::Disconnected(_) | mpsc::SendError::Cancelled(_),
                    ) => {
                        if is_row {
                            counters.buffered_rows.fetch_sub(1, Ordering::AcqRel);
                        }
                        return false;
                    }
                    Outcome::Err(mpsc::SendError::Full(value)) => {
                        if is_row {
                            counters.buffered_rows.fetch_sub(1, Ordering::AcqRel);
                        }
                        message = value;
                    }
                    Outcome::Cancelled(_) | Outcome::Panicked(_) => return false,
                }
            }
            Err(mpsc::SendError::Disconnected(()) | mpsc::SendError::Cancelled(())) => {
                return false;
            }
            Err(mpsc::SendError::Full(())) => {
                // The SQLite statement still borrows its connection here.
                // `SqliteRowStream` therefore carries the originating
                // connection's exclusive lifetime until drop, preventing a
                // same-connection operation from waiting behind this producer
                // while the caller waits for that operation (br-asupersync-n0lnu2).
                std::thread::sleep(SQLITE_ROW_STREAM_FULL_BACKOFF);
            }
        }
    }
}

fn sqlite_row_from_rusqlite_row(
    row: &rusqlite::Row<'_>,
    column_names: &Arc<[String]>,
    columns: &Arc<BTreeMap<String, usize>>,
) -> Result<SqliteRow, SqliteError> {
    let column_count = column_names.len();
    let mut values = Vec::with_capacity(column_count);
    for i in 0..column_count {
        let value = row
            .get_ref(i)
            .map_err(|e| SqliteError::Sqlite(e.to_string()))?;
        let column = column_name_or_index(column_names, i);
        values.push(convert_value(value, &column)?);
    }
    Ok(SqliteRow::new(
        Arc::clone(columns),
        Arc::clone(column_names),
        values,
    ))
}

fn sqlite_row_metadata(row: &rusqlite::Row<'_>) -> (Arc<[String]>, Arc<BTreeMap<String, usize>>) {
    // SQLite can automatically reprepare a statement during its first step
    // after a schema change. Read metadata from the already-stepped row so the
    // names describe the values we are about to expose.
    let column_names: Arc<[String]> = row
        .as_ref()
        .column_names()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>()
        .into();
    let columns = column_names
        .iter()
        .enumerate()
        .map(|(index, name)| (name.clone(), index))
        .collect();
    (column_names, Arc::new(columns))
}

/// Streaming SQLite query result with bounded row buffering.
///
/// The stream exclusively borrows its originating [`SqliteConnection`]. A
/// SQLite statement borrows that physical connection while rows are stepped,
/// so another operation cannot safely start until the stream is dropped. The
/// lifetime makes that constraint explicit and prevents same-connection
/// lock-order deadlocks in safe Rust (br-asupersync-n0lnu2).
pub struct SqliteRowStream<'connection> {
    receiver: mpsc::Receiver<SqliteRowStreamMessage>,
    handle: crate::runtime::blocking_pool::BlockingTaskHandle,
    counters: Arc<SqliteRowStreamCounters>,
    phase: Arc<Mutex<SqliteConnectionOpPhase>>,
    finished: bool,
    /// br-asupersync-1cjrtx: interrupt handle shared with the owning
    /// connection so abandoning or cancelling the stream aborts an
    /// in-flight long VM step instead of letting it run to the next
    /// row boundary.
    interrupt: Arc<rusqlite::InterruptHandle>,
    /// Type-level ownership of the connection for the statement lifetime.
    _connection_lease: PhantomData<&'connection mut SqliteConnection>,
}

impl fmt::Debug for SqliteRowStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteRowStream")
            .field("stats", &self.stats())
            .field("finished", &self.finished)
            .finish()
    }
}

impl SqliteRowStream<'_> {
    fn request_cancel(&self) -> SqliteConnectionOpPhase {
        let mut phase = self.phase.lock();
        let observed = *phase;
        match observed {
            SqliteConnectionOpPhase::Queued => {
                *phase = SqliteConnectionOpPhase::CancelRequested;
            }
            SqliteConnectionOpPhase::Running => {
                *phase = SqliteConnectionOpPhase::CancelRequested;
                // Keep the phase lock held until sqlite3_interrupt returns so
                // the worker cannot publish Completed and release the
                // connection to a neighbouring operation during the handoff.
                self.interrupt.interrupt();
            }
            SqliteConnectionOpPhase::CancelRequested | SqliteConnectionOpPhase::Completed => {}
        }
        observed
    }

    /// Returns the next row, or `None` once the SQLite statement is exhausted.
    pub async fn next(&mut self, cx: &Cx) -> Outcome<Option<SqliteRow>, SqliteError> {
        if self.finished {
            return Outcome::Ok(None);
        }

        if cx.checkpoint().is_err() {
            self.cancel_in_drain(cx).await;
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        match self.receiver.recv(cx).await {
            Ok(Ok(row)) => {
                self.counters.record_yielded_row();
                Outcome::Ok(Some(row))
            }
            Ok(Err(err)) => {
                self.finish();
                Outcome::Err(err)
            }
            Err(mpsc::RecvError::Disconnected) => {
                self.finished = true;
                Outcome::Ok(None)
            }
            Err(mpsc::RecvError::Cancelled) => {
                self.cancel_in_drain(cx).await;
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(mpsc::RecvError::Empty) => Outcome::Err(SqliteError::Sqlite(
                "sqlite row stream receive unexpectedly returned empty".to_string(),
            )),
        }
    }

    /// br-asupersync-1cjrtx: drain-phase wire cancel for the row stream —
    /// mirrors `run_connection_op`'s cancelled-receive path. Interrupts the
    /// in-flight statement, then waits (bounded, cancellation-masked) for
    /// the worker to acknowledge before the stream resolves Cancelled, so
    /// the connection mutex is free when the caller observes the outcome.
    async fn cancel_in_drain(&mut self, cx: &Cx) {
        /// Bounded drain window for awaiting the interrupted worker.
        const MASKED_DRAIN_POLLS: u32 = 1024;

        if self.finished {
            return;
        }
        self.finished = true;
        let cancel_phase = self.request_cancel();
        self.handle.cancel();
        if !self.handle.is_done() {
            match cancel_phase {
                SqliteConnectionOpPhase::Running => cx.trace(
                    "client.wire_cancel proto=sqlite outcome=interrupt_sent op=row_stream",
                ),
                SqliteConnectionOpPhase::Queued => cx.trace(
                    "client.wire_cancel proto=sqlite outcome=skipped op=row_stream reason=queued",
                ),
                SqliteConnectionOpPhase::Completed => cx.trace(
                    "client.wire_cancel proto=sqlite outcome=skipped op=row_stream reason=completed",
                ),
                SqliteConnectionOpPhase::CancelRequested => {}
            }
            let drained = crate::combinator::commit_section(cx, MASKED_DRAIN_POLLS, async {
                loop {
                    match self.receiver.recv(cx).await {
                        // Discard in-flight rows / the worker's terminal
                        // error while waiting for it to wind down.
                        Ok(_) => {
                            if self.handle.is_done() {
                                break true;
                            }
                        }
                        Err(mpsc::RecvError::Disconnected) => break true,
                        // Masked-poll budget exhausted (or anomalous recv
                        // state): stop draining rather than spinning.
                        Err(_) => break false,
                    }
                }
            })
            .await;
            if drained {
                cx.trace("client.wire_cancel proto=sqlite drain=job_completed op=row_stream");
            } else {
                cx.trace(
                    "client.wire_cancel proto=sqlite drain=masked_poll_budget_exhausted \
                     fallback=abandon_job op=row_stream",
                );
            }
        }
        self.receiver.close();
    }

    /// Returns bounded-memory counters for this stream.
    #[must_use]
    pub fn stats(&self) -> SqliteRowStreamStats {
        self.counters.snapshot()
    }

    fn finish(&mut self) {
        if !self.finished {
            self.finished = true;
            self.receiver.close();
            self.request_cancel();
            self.handle.cancel();
        }
    }
}

impl Drop for SqliteRowStream<'_> {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Inner connection state.
struct SqliteConnectionInner {
    /// The actual SQLite connection. None if closed.
    conn: Option<rusqlite::Connection>,
}

/// Lifecycle of one blocking-pool operation against a SQLite connection.
///
/// SQLite's interrupt handle is connection-global. Tracking whether this
/// particular operation is merely queued, actively owns the connection, or
/// has already finished prevents cancellation of one waiter from interrupting
/// an unrelated statement that currently owns the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqliteConnectionOpPhase {
    Queued,
    Running,
    CancelRequested,
    Completed,
}

enum SqliteConnectionOpCompletion<R, E> {
    Finished(Result<R, E>),
    Cancelled,
}

trait SqliteConnectionOpError: Send + 'static {
    fn from_legacy(operation: SqliteOperation, error: SqliteError) -> Self;
    fn is_interrupt(&self) -> bool;
    fn statement_timeout(operation: SqliteOperation, limit: Duration) -> Self;
}

impl SqliteConnectionOpError for SqliteError {
    fn from_legacy(_operation: SqliteOperation, error: SqliteError) -> Self {
        error
    }

    fn is_interrupt(&self) -> bool {
        sqlite_error_is_interrupt(self)
    }

    fn statement_timeout(_operation: SqliteOperation, limit: Duration) -> Self {
        Self::StatementTimeout { limit }
    }
}

impl SqliteConnectionOpError for SqliteOperationError {
    fn from_legacy(operation: SqliteOperation, error: SqliteError) -> Self {
        SqliteOperationError::from_legacy(operation, error)
    }

    fn is_interrupt(&self) -> bool {
        self.diagnostic.category() == SqliteErrorCategory::Interrupted
    }

    fn statement_timeout(operation: SqliteOperation, limit: Duration) -> Self {
        SqliteOperationError::from_legacy(operation, SqliteError::StatementTimeout { limit })
    }
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
    /// Inner connection state (behind `Arc<Mutex<_>>` for sharing).
    inner: Arc<Mutex<SqliteConnectionInner>>,
    /// Handle to the blocking pool.
    pool: BlockingPoolHandle,
    /// Mutex-guarded transaction state to prevent concurrency races.
    transaction_state: Arc<Mutex<TransactionState>>,
    /// Generation of the physical transaction currently owned by a managed
    /// [`SqliteTransaction`]. Blocking-pool workers validate this while they
    /// own `inner` so a stale finish job cannot affect a newer transaction.
    transaction_generation: Arc<AtomicU64>,
    /// br-asupersync-server-stack-hardening-eeexl1.1.2: SQLite interrupt
    /// handle captured at open. Lets the async side abort an in-flight
    /// blocking statement (`sqlite3_interrupt`) when the `Cx` is cancelled
    /// while the connection mutex is held by a pool worker — the handle is
    /// `Send + Sync` and safe to invoke after the connection closed.
    /// `Arc` so row streams can carry their own reference
    /// (br-asupersync-1cjrtx).
    interrupt: Arc<rusqlite::InterruptHandle>,
    /// br-asupersync-server-stack-hardening-eeexl1.1.2: per-connection
    /// statement-timeout override. The effective per-operation timeout is
    /// `min(remaining Cx budget, this override)`; see
    /// [`SqliteConnection::set_statement_timeout_override`].
    statement_timeout_override: Option<std::time::Duration>,
}

impl fmt::Debug for SqliteConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = *self.transaction_state.lock();
        f.debug_struct("SqliteConnection")
            .field("open", &self.inner.lock().conn.is_some())
            .field("pool", &self.pool)
            .field("transaction_state", &state)
            .field(
                "transaction_generation",
                &self.transaction_generation.load(Ordering::Acquire),
            )
            .finish()
    }
}

impl SqliteConnection {
    /// Interrupts the SQLite statement currently executing on this connection.
    ///
    /// This is an immediate, thread-safe request backed by
    /// `sqlite3_interrupt`. If no statement is running, it has no effect. An
    /// interrupted operation reports its ordinary SQLite interruption error;
    /// use [`Cx`] cancellation when the caller needs a structured
    /// [`Outcome::Cancelled`] result and the corresponding drain guarantee.
    pub fn interrupt(&self) {
        self.interrupt.interrupt();
    }

    /// Sets the per-connection statement-timeout override
    /// (br-asupersync-server-stack-hardening-eeexl1.1.2).
    ///
    /// The effective timeout for each operation is `min(remaining Cx
    /// budget, this override)` — meet semantics: the override can only
    /// tighten what the ambient budget allows, and vice versa. `None` (the
    /// default) leaves the ambient budget as the only source. Delivery is a
    /// deadline-checking SQLite progress handler registered around each
    /// blocking-pool operation; an aborted statement surfaces as
    /// [`SqliteError::StatementTimeout`].
    ///
    /// Caveat: the progress handler only runs while the SQLite VM is
    /// executing, so time spent waiting on a locked database (bounded by
    /// `busy_timeout`) can overshoot the deadline by up to that wait.
    pub fn set_statement_timeout_override(&mut self, timeout: Option<std::time::Duration>) {
        self.statement_timeout_override = timeout;
    }

    /// Current per-connection statement-timeout override; see
    /// [`Self::set_statement_timeout_override`].
    #[must_use]
    pub fn statement_timeout_override(&self) -> Option<std::time::Duration> {
        self.statement_timeout_override
    }

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
        self.run_connection_op_inner(cx, op_name, SqliteOperation::BlockingPool, f)
            .await
    }

    async fn run_connection_op_diagnosed<R, F>(
        &self,
        cx: &Cx,
        op_name: &'static str,
        operation: SqliteOperation,
        f: F,
    ) -> Outcome<R, SqliteOperationError>
    where
        R: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> Result<R, SqliteOperationError> + Send + 'static,
    {
        self.run_connection_op_inner(cx, op_name, operation, f)
            .await
    }

    async fn run_connection_op_inner<R, E, F>(
        &self,
        cx: &Cx,
        op_name: &'static str,
        operation: SqliteOperation,
        f: F,
    ) -> Outcome<R, E>
    where
        R: Send + 'static,
        E: SqliteConnectionOpError,
        F: FnOnce(&rusqlite::Connection) -> Result<R, E> + Send + 'static,
    {
        /// SQLite VM instructions between deadline checks in the timeout
        /// progress handler — small enough for prompt aborts, large enough
        /// to keep the per-op overhead negligible.
        const TIMEOUT_PROGRESS_OPS: i32 = 1000;
        /// Bounded drain window for awaiting the interrupted job's
        /// completion after a cancelled receive.
        const MASKED_DRAIN_POLLS: u32 = 1024;

        let timeout =
            crate::database::effective_statement_timeout(cx, self.statement_timeout_override);
        if let Some(limit) = timeout {
            let remaining_ns = crate::database::remaining_budget(cx)
                .map_or_else(|| "none".to_string(), |d| d.as_nanos().to_string());
            let base_ms = self.statement_timeout_override.map_or_else(
                || "none".to_string(),
                |d| crate::database::statement_timeout_millis(d).to_string(),
            );
            cx.trace(&format!(
                "client.budget_forwarded proto=sqlite base_ms={base_ms} \
                 remaining_ns={remaining_ns} statement_timeout_ms={}",
                crate::database::statement_timeout_millis(limit)
            ));
        }

        let inner = Arc::clone(&self.inner);
        let phase = Arc::new(Mutex::new(SqliteConnectionOpPhase::Queued));
        let worker_phase = Arc::clone(&phase);
        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = match tx.reserve(cx) {
            Ok(permit) => permit,
            Err(crate::channel::oneshot::SendError::Cancelled(())) => {
                return Outcome::Cancelled(sqlite_cancelled_reason(cx));
            }
            Err(crate::channel::oneshot::SendError::Disconnected(())) => {
                return Outcome::Err(E::from_legacy(
                    operation,
                    SqliteError::Sqlite(format!("failed to reserve result channel for {op_name}")),
                ));
            }
        };

        let handle = self.pool.spawn(move || {
            let completion = (|| {
                let guard = inner.lock();
                {
                    let mut phase = worker_phase.lock();
                    match *phase {
                        SqliteConnectionOpPhase::Queued => {
                            *phase = SqliteConnectionOpPhase::Running;
                        }
                        SqliteConnectionOpPhase::CancelRequested => {
                            *phase = SqliteConnectionOpPhase::Completed;
                            drop(phase);
                            drop(guard);
                            return SqliteConnectionOpCompletion::Cancelled;
                        }
                        SqliteConnectionOpPhase::Running | SqliteConnectionOpPhase::Completed => {
                            unreachable!("a SQLite connection operation starts exactly once")
                        }
                    }
                }

                let result = (|| {
                    let conn = guard
                        .get()
                        .map_err(|error| E::from_legacy(operation, error))?;
                    // br-asupersync-server-stack-hardening-eeexl1.1.2: arm the
                    // budget-derived statement timeout for the duration of this
                    // operation. Wall-clock by necessity — the deadline fires on
                    // a blocking-pool thread that has no virtual-time access.
                    // Arming must succeed before the op runs: silently running
                    // without the requested bound would void the contract.
                    if let Some(limit) = timeout {
                        let deadline = std::time::Instant::now() + limit;
                        conn.progress_handler(
                            TIMEOUT_PROGRESS_OPS,
                            Some(move || std::time::Instant::now() >= deadline),
                        )
                        .map_err(|e| {
                            E::from_legacy(
                                operation,
                                SqliteError::Sqlite(format!(
                                    "failed to arm statement timeout: {e}"
                                )),
                            )
                        })?;
                    }
                    let result = f(conn);
                    if timeout.is_some() {
                        // Best-effort disarm; failure here implies a broken db
                        // handle, which every subsequent operation will surface.
                        let _ = conn.progress_handler(0, None::<fn() -> bool>);
                    }
                    result
                })();
                let cancellation_requested = {
                    let mut phase = worker_phase.lock();
                    let cancellation_requested = *phase == SqliteConnectionOpPhase::CancelRequested;
                    *phase = SqliteConnectionOpPhase::Completed;
                    cancellation_requested
                };
                let result = match (cancellation_requested, timeout, result) {
                    (true, _, Err(err)) if err.is_interrupt() => {
                        drop(guard);
                        return SqliteConnectionOpCompletion::Cancelled;
                    }
                    (_, Some(limit), Err(err)) if err.is_interrupt() => {
                        Err(E::statement_timeout(operation, limit))
                    }
                    (_, _, result) => result,
                };
                drop(guard);
                SqliteConnectionOpCompletion::Finished(result)
            })();
            let _ = permit.send(completion);
        });

        match rx.recv(cx).await {
            Ok(SqliteConnectionOpCompletion::Finished(Ok(result))) => Outcome::Ok(result),
            Ok(SqliteConnectionOpCompletion::Finished(Err(e))) => Outcome::Err(e),
            Ok(SqliteConnectionOpCompletion::Cancelled) => Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            ),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                let cancel_phase = {
                    let mut phase = phase.lock();
                    let observed = *phase;
                    match observed {
                        SqliteConnectionOpPhase::Queued => {
                            *phase = SqliteConnectionOpPhase::CancelRequested;
                        }
                        SqliteConnectionOpPhase::Running => {
                            *phase = SqliteConnectionOpPhase::CancelRequested;
                            // Hold the phase lock across sqlite3_interrupt so
                            // the worker cannot publish Completed and release
                            // the connection to a neighbouring operation in the
                            // middle of this cancellation handoff.
                            self.interrupt.interrupt();
                        }
                        SqliteConnectionOpPhase::CancelRequested
                        | SqliteConnectionOpPhase::Completed => {}
                    }
                    observed
                };
                handle.cancel();
                // br-asupersync-server-stack-hardening-eeexl1.1.2: wire-level
                // cancel in the drain phase. `sqlite3_interrupt` aborts the
                // in-flight statement promptly; the masked re-receive then
                // waits for the blocking job to acknowledge before this
                // operation resolves Cancelled, so the connection mutex is
                // free and no statement keeps running unobserved. The
                // masked-poll budget keeps the drain step bounded.
                match cancel_phase {
                    SqliteConnectionOpPhase::Running => cx.trace(&format!(
                        "client.wire_cancel proto=sqlite outcome=interrupt_sent op={op_name}"
                    )),
                    SqliteConnectionOpPhase::Queued => cx.trace(&format!(
                        "client.wire_cancel proto=sqlite outcome=skipped op={op_name} reason=queued"
                    )),
                    SqliteConnectionOpPhase::Completed => cx.trace(&format!(
                        "client.wire_cancel proto=sqlite outcome=skipped op={op_name} reason=completed"
                    )),
                    SqliteConnectionOpPhase::CancelRequested => {}
                }
                let drained =
                    crate::combinator::commit_section(cx, MASKED_DRAIN_POLLS, rx.recv(cx)).await;
                match drained {
                    Ok(SqliteConnectionOpCompletion::Finished(result)) => {
                        cx.trace(
                            "client.wire_cancel proto=sqlite drain=job_completed completion=won",
                        );
                        return match result {
                            Ok(result) => Outcome::Ok(result),
                            Err(err) => Outcome::Err(err),
                        };
                    }
                    Ok(SqliteConnectionOpCompletion::Cancelled) => {
                        cx.trace("client.wire_cancel proto=sqlite drain=job_cancelled");
                    }
                    Err(crate::channel::oneshot::RecvError::Closed) => {
                        cx.trace("client.wire_cancel proto=sqlite drain=job_not_started");
                    }
                    Err(_) => cx.trace(
                        "client.wire_cancel proto=sqlite drain=masked_poll_budget_exhausted \
                         fallback=abandon_job",
                    ),
                }
                Outcome::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| CancelReason::user("cancelled")),
                )
            }
            Err(crate::channel::oneshot::RecvError::Closed) => Outcome::Err(E::from_legacy(
                operation,
                SqliteError::Sqlite(format!("failed to receive result for {op_name}")),
            )),
            Err(crate::channel::oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("{op_name} awaits a fresh oneshot recv future")
            }
        }
    }

    async fn drain_orphaned_transaction(&self, cx: &Cx) -> Outcome<(), SqliteError> {
        let current_state = *self.transaction_state.lock();

        // Only drain if transaction needs rollback
        if current_state != TransactionState::NeedsRollback {
            return Outcome::Ok(());
        }

        let transaction_state = Arc::clone(&self.transaction_state);
        let transaction_generation = Arc::clone(&self.transaction_generation);
        self.run_connection_op(cx, "sqlite rollback cleanup", move |conn| {
            rollback_orphaned_transaction_generation_guarded(
                conn,
                transaction_state.as_ref(),
                transaction_generation.as_ref(),
            )
        })
        .await
    }

    /// Schedule best-effort physical rollback for a dropped managed
    /// transaction.
    ///
    /// `SqliteTransaction::drop` cannot block the dropping thread, but merely
    /// publishing `NeedsRollback` leaves SQLite's real transaction (and any
    /// write lock it owns) open until another connection operation happens to
    /// arrive. Queue cleanup on the connection's blocking pool instead. The
    /// worker validates the transaction generation while holding `inner`, so
    /// a delayed cleanup from an older handle cannot roll back a newer
    /// transaction.
    ///
    /// Rollback remains best-effort here: a closed pool or SQLite rollback
    /// failure leaves `NeedsRollback` intact for `drain_orphaned_transaction`
    /// to retry on the next connection operation.
    fn schedule_dropped_transaction_rollback(&self, expected_generation: u64) {
        let inner = Arc::clone(&self.inner);
        let transaction_state = Arc::clone(&self.transaction_state);
        let transaction_generation = Arc::clone(&self.transaction_generation);

        let _cleanup = self.pool.spawn(move || {
            let guard = inner.lock();
            let Some(conn) = guard.conn.as_ref() else {
                // Closing rusqlite::Connection physically rolls back any open
                // transaction. A handle dropped after close may have
                // republished NeedsRollback, so retire that stale generation
                // while the closed connection state is stable under `inner`.
                if transaction_generation.load(Ordering::Acquire) == expected_generation {
                    let _ = advance_transaction_generation(transaction_generation.as_ref());
                    *transaction_state.lock() = TransactionState::Autocommit;
                }
                return;
            };

            // Every generation-changing worker also owns `inner`, so this
            // check stays stable through the rollback attempt below.
            if transaction_generation.load(Ordering::Acquire) != expected_generation {
                return;
            }

            let _ = rollback_orphaned_transaction_generation_guarded(
                conn,
                transaction_state.as_ref(),
                transaction_generation.as_ref(),
            );
        });
    }

    async fn open_with<E, F>(cx: &Cx, operation: SqliteOperation, open: F) -> Outcome<Self, E>
    where
        E: SqliteConnectionOpError,
        F: FnOnce() -> Result<rusqlite::Connection, E> + Send + 'static,
    {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }

        let pool = get_sqlite_pool();
        let pool_clone = pool.clone();
        let (tx, mut rx) = crate::channel::oneshot::channel();
        let permit = tx.reserve(cx);
        let handle = pool.spawn(move || {
            let result = open();
            if let Ok(permit) = permit {
                let _ = permit.send(result);
            }
        });

        match rx.recv(cx).await {
            Ok(Ok(conn)) => {
                let interrupt = Arc::new(conn.get_interrupt_handle());
                Outcome::Ok(Self {
                    inner: Arc::new(Mutex::new(SqliteConnectionInner::new(conn))),
                    pool: pool_clone,
                    transaction_state: Arc::new(Mutex::new(TransactionState::Autocommit)),
                    transaction_generation: Arc::new(AtomicU64::new(0)),
                    interrupt,
                    statement_timeout_override: None,
                })
            }
            Ok(Err(error)) => Outcome::Err(error),
            Err(crate::channel::oneshot::RecvError::Cancelled) => {
                handle.cancel();
                Outcome::Cancelled(sqlite_cancelled_reason(cx))
            }
            Err(crate::channel::oneshot::RecvError::Closed) => Outcome::Err(E::from_legacy(
                operation,
                SqliteError::Sqlite("failed to receive result".to_string()),
            )),
            Err(crate::channel::oneshot::RecvError::PolledAfterCompletion) => {
                unreachable!("SQLite blocking-pool open awaits a fresh oneshot recv future")
            }
        }
    }

    /// Opens a SQLite database at the given path.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    /// If cancelled during execution, the connection may or may not be opened.
    pub async fn open(cx: &Cx, path: impl AsRef<Path>) -> Outcome<Self, SqliteError> {
        let path = path.as_ref().to_path_buf();
        Self::open_with(cx, SqliteOperation::Open, move || {
            // SECURITY: lexical tilde/parent-traversal rejection must see the
            // raw input before canonicalization erases those components
            // (br-asupersync-uvqpga: open() previously skipped these checks).
            validate_sqlite_open_path_lexical(&path)?;
            // Resolve once and use the same path for validation and opening.
            let resolved_path = resolve_sqlite_open_path(&path)?;
            validate_resolved_sqlite_path(&resolved_path)?;
            let conn = rusqlite::Connection::open(&resolved_path)
                .map_err(|error| SqliteError::Sqlite(error.to_string()))?;
            configure_connection_defaults(&conn, true)?;
            Ok(conn)
        })
        .await
    }

    /// Opens a SQLite database and preserves structured engine diagnostics.
    ///
    /// This additive API has the same success and cancellation semantics as
    /// [`Self::open`]. It never parses SQLite's rendered error text: engine
    /// codes are captured before conversion, while validation failures retain
    /// their established [`SqliteError`] as the error source.
    pub async fn open_diagnosed(
        cx: &Cx,
        path: impl AsRef<Path>,
    ) -> Outcome<Self, SqliteOperationError> {
        let path = path.as_ref().to_path_buf();
        Self::open_with(cx, SqliteOperation::Open, move || {
            validate_sqlite_open_path_lexical(&path).map_err(|error| {
                SqliteOperationError::from_legacy(SqliteOperation::Validation, error)
            })?;
            let resolved_path = resolve_sqlite_open_path(&path).map_err(|error| {
                SqliteOperationError::from_legacy(SqliteOperation::Validation, error)
            })?;
            validate_resolved_sqlite_path(&resolved_path).map_err(|error| {
                SqliteOperationError::from_legacy(SqliteOperation::Validation, error)
            })?;
            let conn = rusqlite::Connection::open(&resolved_path).map_err(|error| {
                SqliteOperationError::from_rusqlite(SqliteOperation::Open, error)
            })?;
            configure_connection_defaults_with(&conn, true, |operation, error| {
                SqliteOperationError::from_rusqlite(operation, error)
            })?;
            Ok(conn)
        })
        .await
    }

    /// Opens an in-memory SQLite database.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn open_in_memory(cx: &Cx) -> Outcome<Self, SqliteError> {
        Self::open_with(cx, SqliteOperation::Open, move || {
            let conn = rusqlite::Connection::open_in_memory()
                .map_err(|error| SqliteError::Sqlite(error.to_string()))?;
            configure_connection_defaults(&conn, false)?;
            Ok(conn)
        })
        .await
    }

    /// Opens an in-memory SQLite database with structured diagnostics.
    pub async fn open_in_memory_diagnosed(cx: &Cx) -> Outcome<Self, SqliteOperationError> {
        Self::open_with(cx, SqliteOperation::Open, move || {
            let conn = rusqlite::Connection::open_in_memory().map_err(|error| {
                SqliteOperationError::from_rusqlite(SqliteOperation::Open, error)
            })?;
            configure_connection_defaults_with(&conn, false, |operation, error| {
                SqliteOperationError::from_rusqlite(operation, error)
            })?;
            Ok(conn)
        })
        .await
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
        if let Err(err) = validate_checked_sql_statement(sql) {
            return Outcome::Err(err);
        }
        self.execute_unchecked(cx, sql, params).await
    }

    /// Execute an unparameterized SQL command on the underlying connection.
    ///
    /// # Security
    ///
    /// This bypasses the checked surface and therefore permits engine-control
    /// statements such as `BEGIN`, `ROLLBACK`, and `PRAGMA`. `ATTACH`/`DETACH`
    /// remain disabled on this binding surface and should use separate
    /// validated connections instead. Use this only for static literals or
    /// version-controlled migration/control SQL.
    pub async fn execute_unchecked(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<u64, SqliteError> {
        self.execute_unchecked_with(cx, sql, params, |conn, sql, params| {
            let params_refs: Vec<&dyn rusqlite::ToSql> = params
                .iter()
                .map(|value| value as &dyn rusqlite::ToSql)
                .collect();
            conn.execute(sql, params_refs.as_slice())
                .map(|rows| rows as u64)
                .map_err(|error| SqliteError::Sqlite(error.to_string()))
        })
        .await
    }

    /// Executes a checked statement and preserves structured engine
    /// diagnostics without changing the legacy [`Self::execute`] contract.
    pub async fn execute_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<u64, SqliteOperationError> {
        if let Err(error) = validate_checked_sql_statement(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        self.execute_unchecked_diagnosed(cx, sql, params).await
    }

    /// Executes trusted SQL and captures prepare, bind, and step failures as
    /// structured diagnostics.
    ///
    /// This has the same security boundary as [`Self::execute_unchecked`].
    pub async fn execute_unchecked_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<u64, SqliteOperationError> {
        if let Err(error) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }
        match diagnose_legacy_outcome(
            SqliteOperation::TransactionRollback,
            self.drain_orphaned_transaction(cx).await,
        ) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }

        let sql = sql.to_string();
        let params = params.to_vec();
        self.run_connection_op_diagnosed(
            cx,
            "sqlite diagnosed execute",
            SqliteOperation::Step,
            move |conn| {
                let mut statement = conn.prepare_cached(&sql).map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Prepare, error)
                })?;
                let params_refs: Vec<&dyn rusqlite::ToSql> = params
                    .iter()
                    .map(|value| value as &dyn rusqlite::ToSql)
                    .collect();
                statement
                    .execute(params_refs.as_slice())
                    .map(|rows| rows as u64)
                    .map_err(|error| {
                        SqliteOperationError::from_rusqlite(SqliteOperation::Step, error)
                    })
            },
        )
        .await
    }

    async fn execute_transaction_control(
        &self,
        cx: &Cx,
        sql: &'static str,
        effect: TransactionWorkerEffect,
    ) -> Outcome<u64, SqliteError> {
        self.execute_unchecked_with(cx, sql, &[], move |conn, sql, _params| {
            effect.execute_worker(conn, sql)
        })
        .await
    }

    async fn execute_transaction_control_diagnosed(
        &self,
        cx: &Cx,
        sql: &'static str,
        operation: SqliteOperation,
        effect: TransactionWorkerEffect,
    ) -> Outcome<u64, SqliteOperationError> {
        if let Err(error) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }
        match diagnose_legacy_outcome(
            SqliteOperation::TransactionRollback,
            self.drain_orphaned_transaction(cx).await,
        ) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }

        self.run_connection_op_diagnosed(
            cx,
            "sqlite diagnosed transaction control",
            operation,
            move |conn| effect.execute_worker_diagnosed(conn, sql, operation),
        )
        .await
    }

    async fn execute_unchecked_with<F>(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
        execute: F,
    ) -> Outcome<u64, SqliteError>
    where
        F: FnOnce(&rusqlite::Connection, &str, &[SqliteValue]) -> Result<u64, SqliteError>
            + Send
            + 'static,
    {
        if let Err(err) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(err);
        }
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
            execute(conn, &sql, &params)
        })
        .await
    }

    /// Executes a batch of SQL statements.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn execute_batch(&self, cx: &Cx, sql: &str) -> Outcome<(), SqliteError> {
        if let Err(err) = validate_checked_sql_batch(sql) {
            return Outcome::Err(err);
        }
        self.execute_batch_unchecked(cx, sql).await
    }

    /// Execute a trusted batch of SQL statements without checked-surface
    /// validation.
    pub async fn execute_batch_unchecked(&self, cx: &Cx, sql: &str) -> Outcome<(), SqliteError> {
        if let Err(err) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(err);
        }
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

    /// Executes a checked SQL batch with structured engine diagnostics.
    pub async fn execute_batch_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
    ) -> Outcome<(), SqliteOperationError> {
        if let Err(error) = validate_checked_sql_batch(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        self.execute_batch_unchecked_diagnosed(cx, sql).await
    }

    /// Executes a trusted SQL batch with structured engine diagnostics.
    ///
    /// This has the same security boundary as
    /// [`Self::execute_batch_unchecked`].
    pub async fn execute_batch_unchecked_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
    ) -> Outcome<(), SqliteOperationError> {
        if let Err(error) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }
        match diagnose_legacy_outcome(
            SqliteOperation::TransactionRollback,
            self.drain_orphaned_transaction(cx).await,
        ) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }

        let sql = sql.to_string();
        self.run_connection_op_diagnosed(
            cx,
            "sqlite diagnosed execute_batch",
            SqliteOperation::ExecuteBatch,
            move |conn| {
                conn.execute_batch(&sql).map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::ExecuteBatch, error)
                })
            },
        )
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
        if let Err(err) = validate_checked_sql_statement(sql) {
            return Outcome::Err(err);
        }
        self.query_unchecked(cx, sql, params).await
    }

    /// Execute a trusted raw SQL query without checked-surface validation.
    pub async fn query_unchecked(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Vec<SqliteRow>, SqliteError> {
        if let Err(err) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(err);
        }
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

            let mut rows = stmt
                .query(params_refs.as_slice())
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

            let mut result = Vec::new();
            let mut metadata = None;
            while let Some(row) = rows
                .next()
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?
            {
                let (column_names, columns) =
                    metadata.get_or_insert_with(|| sqlite_row_metadata(row));
                result.push(sqlite_row_from_rusqlite_row(row, column_names, columns)?);
            }
            drop(rows);
            drop(stmt);
            Ok(result)
        })
        .await
    }

    /// Executes a checked query with structured prepare, bind, and step
    /// diagnostics.
    pub async fn query_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Vec<SqliteRow>, SqliteOperationError> {
        if let Err(error) = validate_checked_sql_statement(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        self.query_unchecked_diagnosed(cx, sql, params).await
    }

    /// Executes a trusted query with structured prepare, bind, and step
    /// diagnostics.
    ///
    /// This has the same security boundary as [`Self::query_unchecked`].
    pub async fn query_unchecked_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Vec<SqliteRow>, SqliteOperationError> {
        if let Err(error) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }
        match diagnose_legacy_outcome(
            SqliteOperation::TransactionRollback,
            self.drain_orphaned_transaction(cx).await,
        ) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }

        let sql = sql.to_string();
        let params = params.to_vec();
        self.run_connection_op_diagnosed(
            cx,
            "sqlite diagnosed query",
            SqliteOperation::Step,
            move |conn| {
                let params_refs: Vec<&dyn rusqlite::ToSql> = params
                    .iter()
                    .map(|value| value as &dyn rusqlite::ToSql)
                    .collect();
                let mut statement = conn.prepare_cached(&sql).map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Prepare, error)
                })?;
                let mut rows = statement.query(params_refs.as_slice()).map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Bind, error)
                })?;

                let mut result = Vec::new();
                let mut metadata = None;
                while let Some(row) = rows.next().map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Step, error)
                })? {
                    let (column_names, columns) =
                        metadata.get_or_insert_with(|| sqlite_row_metadata(row));
                    let converted = sqlite_row_from_rusqlite_row(row, column_names, columns)
                        .map_err(|error| {
                            SqliteOperationError::from_legacy(SqliteOperation::Step, error)
                        })?;
                    result.push(converted);
                }
                Ok(result)
            },
        )
        .await
    }

    /// Executes a query and streams rows through a bounded async receiver.
    ///
    /// This API preserves SQLite's native `sqlite3_step()` row-at-a-time
    /// behavior across the blocking-pool boundary. At most one converted row is
    /// buffered between the blocking worker and the async caller.
    ///
    /// The returned stream exclusively borrows this connection. Drop the
    /// stream before starting another operation on the same connection; this
    /// prevents a second operation from waiting behind a statement whose row
    /// delivery is itself waiting for the stream consumer.
    ///
    /// ```compile_fail
    /// use asupersync::database::SqliteConnection;
    /// use asupersync::{Cx, Outcome};
    ///
    /// async fn overlapping_operation(conn: &mut SqliteConnection, cx: &Cx) {
    ///     let Outcome::Ok(mut rows) = conn.query_stream(cx, "SELECT 1", &[]).await else {
    ///         return;
    ///     };
    ///     let _ = conn.is_open(); // connection remains exclusively borrowed
    ///     let _ = rows.next(cx).await;
    /// }
    /// ```
    pub async fn query_stream<'connection>(
        &'connection mut self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<SqliteRowStream<'connection>, SqliteError> {
        if let Err(err) = validate_checked_sql_statement(sql) {
            return Outcome::Err(err);
        }
        self.query_stream_unchecked(cx, sql, params).await
    }

    /// Execute a trusted raw SQL query and stream rows through a bounded
    /// async receiver.
    pub async fn query_stream_unchecked<'connection>(
        &'connection mut self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<SqliteRowStream<'connection>, SqliteError> {
        if let Err(err) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(err);
        }
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

        // br-asupersync-1cjrtx: streams get the same budget-derived
        // statement timeout as one-shot operations.
        let timeout =
            crate::database::effective_statement_timeout(cx, self.statement_timeout_override);
        if let Some(limit) = timeout {
            let remaining_ns = crate::database::remaining_budget(cx)
                .map_or_else(|| "none".to_string(), |d| d.as_nanos().to_string());
            let base_ms = self.statement_timeout_override.map_or_else(
                || "none".to_string(),
                |d| crate::database::statement_timeout_millis(d).to_string(),
            );
            cx.trace(&format!(
                "client.budget_forwarded proto=sqlite base_ms={base_ms} \
                 remaining_ns={remaining_ns} statement_timeout_ms={} op=row_stream",
                crate::database::statement_timeout_millis(limit)
            ));
        }

        let sql = sql.to_string();
        let params: Vec<SqliteValue> = params.to_vec();
        let inner = Arc::clone(&self.inner);
        let counters = Arc::new(SqliteRowStreamCounters::default());
        let worker_counters = Arc::clone(&counters);
        let (sender, receiver) = mpsc::channel(SQLITE_ROW_STREAM_CHANNEL_CAPACITY);
        let phase = Arc::new(Mutex::new(SqliteConnectionOpPhase::Queued));
        let worker_phase = Arc::clone(&phase);

        let handle = self.pool.spawn(move || {
            /// SQLite VM instructions between deadline checks — see
            /// `run_connection_op`.
            const TIMEOUT_PROGRESS_OPS: i32 = 1000;

            let result = (|| {
                let guard = inner.lock();
                {
                    let mut phase = worker_phase.lock();
                    match *phase {
                        SqliteConnectionOpPhase::Queued => {
                            *phase = SqliteConnectionOpPhase::Running;
                        }
                        SqliteConnectionOpPhase::CancelRequested => {
                            *phase = SqliteConnectionOpPhase::Completed;
                            drop(phase);
                            drop(guard);
                            return Ok(());
                        }
                        SqliteConnectionOpPhase::Running | SqliteConnectionOpPhase::Completed => {
                            unreachable!("a SQLite row-stream worker starts exactly once")
                        }
                    }
                }
                let body_result = (|| {
                    let conn = guard.get()?;
                    if let Some(limit) = timeout {
                        let deadline = std::time::Instant::now() + limit;
                        conn.progress_handler(
                            TIMEOUT_PROGRESS_OPS,
                            Some(move || std::time::Instant::now() >= deadline),
                        )
                        .map_err(|e| {
                            SqliteError::Sqlite(format!("failed to arm statement timeout: {e}"))
                        })?;
                    }

                    // Inner closure so the disarm below runs on EVERY exit path
                    // of the statement work — a `?` escaping with the handler
                    // still armed would impose a stale deadline on the next
                    // operation that borrows this connection.
                    let query_result = (|| {
                        let params_refs: Vec<&dyn rusqlite::ToSql> =
                            params.iter().map(|v| v as &dyn rusqlite::ToSql).collect();

                        let mut stmt = conn
                            .prepare_cached(&sql)
                            .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

                        let mut rows = stmt
                            .query(params_refs.as_slice())
                            .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

                        let mut metadata = None;
                        while let Some(row) = rows
                            .next()
                            .map_err(|e| SqliteError::Sqlite(e.to_string()))?
                        {
                            worker_counters.rows_stepped.fetch_add(1, Ordering::AcqRel);
                            let (column_names, columns) =
                                metadata.get_or_insert_with(|| sqlite_row_metadata(row));
                            let row = sqlite_row_from_rusqlite_row(row, column_names, columns)?;
                            if !send_sqlite_stream_message(&sender, &worker_counters, Ok(row)) {
                                break;
                            }
                        }
                        Ok(())
                    })();

                    if timeout.is_some() {
                        // Best-effort disarm — see `run_connection_op`.
                        let _ = conn.progress_handler(0, None::<fn() -> bool>);
                    }
                    query_result
                })();
                {
                    let mut phase = worker_phase.lock();
                    *phase = SqliteConnectionOpPhase::Completed;
                }
                drop(guard);
                body_result
            })();

            // br-asupersync-1cjrtx: relabel a deadline-progress-handler
            // abort as the dedicated timeout error (mirrors
            // `run_connection_op`); a consumer-driven interrupt discards
            // the message during the drain instead.
            let result = match (timeout, result) {
                (Some(limit), Err(err)) if sqlite_error_is_interrupt(&err) => {
                    Err(SqliteError::StatementTimeout { limit })
                }
                (_, result) => result,
            };

            if let Err(err) = result {
                let _ = send_sqlite_stream_message(&sender, &worker_counters, Err(err));
            }
        });

        Outcome::Ok(SqliteRowStream {
            receiver,
            handle,
            counters,
            phase,
            finished: false,
            interrupt: Arc::clone(&self.interrupt),
            _connection_lease: PhantomData,
        })
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
        if let Err(err) = validate_checked_sql_statement(sql) {
            return Outcome::Err(err);
        }
        self.query_row_unchecked(cx, sql, params).await
    }

    /// Execute a trusted raw SQL query_row without checked-surface validation.
    pub async fn query_row_unchecked(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Option<SqliteRow>, SqliteError> {
        if let Err(err) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(err);
        }
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

            let mut rows = stmt
                .query(params_refs.as_slice())
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

            let row_opt = rows
                .next()
                .map_err(|e| SqliteError::Sqlite(e.to_string()))?;

            let result = if let Some(row) = row_opt {
                let (column_names, columns) = sqlite_row_metadata(row);
                Some(sqlite_row_from_rusqlite_row(row, &column_names, &columns)?)
            } else {
                None
            };

            drop(rows);
            drop(stmt);
            Ok(result)
        })
        .await
    }

    /// Executes a checked query for its first row with structured diagnostics.
    pub async fn query_row_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Option<SqliteRow>, SqliteOperationError> {
        if let Err(error) = validate_checked_sql_statement(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        self.query_row_unchecked_diagnosed(cx, sql, params).await
    }

    /// Executes a trusted query for its first row with structured diagnostics.
    ///
    /// This has the same security boundary as [`Self::query_row_unchecked`].
    pub async fn query_row_unchecked_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Option<SqliteRow>, SqliteOperationError> {
        if let Err(error) = ensure_unchecked_sql_surface(sql) {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Validation,
                error,
            ));
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }
        match diagnose_legacy_outcome(
            SqliteOperation::TransactionRollback,
            self.drain_orphaned_transaction(cx).await,
        ) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }

        let sql = sql.to_string();
        let params = params.to_vec();
        self.run_connection_op_diagnosed(
            cx,
            "sqlite diagnosed query_row",
            SqliteOperation::Step,
            move |conn| {
                let params_refs: Vec<&dyn rusqlite::ToSql> = params
                    .iter()
                    .map(|value| value as &dyn rusqlite::ToSql)
                    .collect();
                let mut statement = conn.prepare_cached(&sql).map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Prepare, error)
                })?;
                let mut rows = statement.query(params_refs.as_slice()).map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Bind, error)
                })?;
                let row = rows.next().map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Step, error)
                })?;
                let result = match row {
                    Some(row) => {
                        let (column_names, columns) = sqlite_row_metadata(row);
                        Some(
                            sqlite_row_from_rusqlite_row(row, &column_names, &columns).map_err(
                                |error| {
                                    SqliteOperationError::from_legacy(SqliteOperation::Step, error)
                                },
                            )?,
                        )
                    }
                    None => None,
                };
                Ok(result)
            },
        )
        .await
    }

    async fn begin_with_sql<'conn>(
        &'conn self,
        cx: &Cx,
        sql: &'static str,
        operation: &'static str,
    ) -> Outcome<SqliteTransaction<'conn>, SqliteError> {
        trace_database_transaction(cx, "sqlite", operation, "start");
        let mut drop_guard = BeginDropGuard::new(
            Arc::clone(&self.transaction_state),
            Arc::clone(&self.transaction_generation),
        );
        let effect = TransactionWorkerEffect::Begin(drop_guard.attempt());

        match self.execute_transaction_control(cx, sql, effect).await {
            Outcome::Ok(_) => {
                let Some(generation) = drop_guard.opened_generation() else {
                    drop_guard.abandon();
                    trace_database_transaction(cx, "sqlite", operation, "err");
                    return Outcome::Err(SqliteError::Sqlite(
                        "managed BEGIN completed without a transaction generation".to_string(),
                    ));
                };
                let transaction = SqliteTransaction {
                    conn: self,
                    finished: false,
                    obligation: reserve_transaction_obligation(cx),
                    generation,
                };
                drop_guard.disarm();
                trace_database_transaction(cx, "sqlite", operation, "ok");
                Outcome::Ok(transaction)
            }
            Outcome::Err(e) => {
                drop_guard.disarm();
                trace_database_transaction(cx, "sqlite", operation, "err");
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                drop_guard.abandon();
                trace_database_transaction(cx, "sqlite", operation, "cancelled");
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                drop_guard.abandon();
                trace_database_transaction(cx, "sqlite", operation, "panicked");
                Outcome::Panicked(p)
            }
        }
    }

    async fn begin_with_sql_diagnosed<'conn>(
        &'conn self,
        cx: &Cx,
        sql: &'static str,
        trace_operation: &'static str,
    ) -> Outcome<SqliteTransaction<'conn>, SqliteOperationError> {
        trace_database_transaction(cx, "sqlite", trace_operation, "start");
        let mut drop_guard = BeginDropGuard::new(
            Arc::clone(&self.transaction_state),
            Arc::clone(&self.transaction_generation),
        );
        let effect = TransactionWorkerEffect::Begin(drop_guard.attempt());

        match self
            .execute_transaction_control_diagnosed(
                cx,
                sql,
                SqliteOperation::TransactionBegin,
                effect,
            )
            .await
        {
            Outcome::Ok(_) => {
                let Some(generation) = drop_guard.opened_generation() else {
                    drop_guard.abandon();
                    trace_database_transaction(cx, "sqlite", trace_operation, "err");
                    return Outcome::Err(SqliteOperationError::from_legacy(
                        SqliteOperation::TransactionBegin,
                        SqliteError::Sqlite(
                            "managed BEGIN completed without a transaction generation".to_string(),
                        ),
                    ));
                };
                let transaction = SqliteTransaction {
                    conn: self,
                    finished: false,
                    obligation: reserve_transaction_obligation(cx),
                    generation,
                };
                drop_guard.disarm();
                trace_database_transaction(cx, "sqlite", trace_operation, "ok");
                Outcome::Ok(transaction)
            }
            Outcome::Err(error) => {
                drop_guard.disarm();
                trace_database_transaction(cx, "sqlite", trace_operation, "err");
                Outcome::Err(error)
            }
            Outcome::Cancelled(reason) => {
                drop_guard.abandon();
                trace_database_transaction(cx, "sqlite", trace_operation, "cancelled");
                Outcome::Cancelled(reason)
            }
            Outcome::Panicked(payload) => {
                drop_guard.abandon();
                trace_database_transaction(cx, "sqlite", trace_operation, "panicked");
                Outcome::Panicked(payload)
            }
        }
    }

    /// Begins a new transaction.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn begin(&self, cx: &Cx) -> Outcome<SqliteTransaction<'_>, SqliteError> {
        self.begin_with_sql(cx, "BEGIN", "begin").await
    }

    /// Begins a deferred transaction with structured diagnostics.
    pub async fn begin_diagnosed(
        &self,
        cx: &Cx,
    ) -> Outcome<SqliteTransaction<'_>, SqliteOperationError> {
        self.begin_with_sql_diagnosed(cx, "BEGIN", "begin_diagnosed")
            .await
    }

    /// Begins an immediate transaction (acquires write lock immediately).
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn begin_immediate(&self, cx: &Cx) -> Outcome<SqliteTransaction<'_>, SqliteError> {
        self.begin_with_sql(cx, "BEGIN IMMEDIATE", "begin_immediate")
            .await
    }

    /// Begins an immediate transaction with structured diagnostics.
    pub async fn begin_immediate_diagnosed(
        &self,
        cx: &Cx,
    ) -> Outcome<SqliteTransaction<'_>, SqliteOperationError> {
        self.begin_with_sql_diagnosed(cx, "BEGIN IMMEDIATE", "begin_immediate_diagnosed")
            .await
    }

    /// Begins an exclusive transaction (acquires exclusive lock immediately).
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn begin_exclusive(&self, cx: &Cx) -> Outcome<SqliteTransaction<'_>, SqliteError> {
        self.begin_with_sql(cx, "BEGIN EXCLUSIVE", "begin_exclusive")
            .await
    }

    /// Begins an exclusive transaction with structured diagnostics.
    pub async fn begin_exclusive_diagnosed(
        &self,
        cx: &Cx,
    ) -> Outcome<SqliteTransaction<'_>, SqliteOperationError> {
        self.begin_with_sql_diagnosed(cx, "BEGIN EXCLUSIVE", "begin_exclusive_diagnosed")
            .await
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

    /// Updates SQLite's busy timeout with structured diagnostics.
    pub async fn set_busy_timeout_diagnosed(
        &self,
        cx: &Cx,
        timeout: Duration,
    ) -> Outcome<(), SqliteOperationError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(sqlite_cancelled_reason(cx));
        }
        match diagnose_legacy_outcome(
            SqliteOperation::TransactionRollback,
            self.drain_orphaned_transaction(cx).await,
        ) {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        self.run_connection_op_diagnosed(
            cx,
            "sqlite diagnosed set_busy_timeout",
            SqliteOperation::Configure,
            move |conn| {
                conn.busy_timeout(timeout).map_err(|error| {
                    SqliteOperationError::from_rusqlite(SqliteOperation::Configure, error)
                })
            },
        )
        .await
    }

    /// Closes the connection.
    ///
    /// Returns an error if WAL checkpoint fails to ensure no data loss.
    pub fn close(&self) -> Result<(), SqliteError> {
        let mut guard = self.inner.lock();
        if let Some(conn) = guard.conn.as_ref() {
            let _ =
                rollback_orphaned_transaction_mutex_guarded(conn, self.transaction_state.as_ref());

            // SECURITY FIX: Fail-closed WAL checkpoint to prevent data loss
            // WAL checkpoint failures now propagate as errors instead of being ignored
            match self.execute_wal_checkpoint_with_retry(conn) {
                Ok(()) => {
                    #[cfg(feature = "tracing-integration")]
                    crate::tracing_compat::debug!(
                        "WAL checkpoint completed successfully during close"
                    );
                }
                Err(e) => {
                    #[cfg(feature = "tracing-integration")]
                    crate::tracing_compat::error!(
                        error = %e,
                        "WAL checkpoint failed during connection close - failing close to prevent data loss"
                    );
                    return Err(e);
                }
            }

            conn.flush_prepared_statement_cache();
        }
        *self.transaction_state.lock() = TransactionState::Autocommit;
        guard.close();
        Ok(())
    }

    /// Closes the connection and classifies cleanup failures without changing
    /// [`Self::close`].
    pub fn close_diagnosed(&self) -> Result<(), SqliteOperationError> {
        self.close()
            .map_err(|error| SqliteOperationError::from_legacy(SqliteOperation::Close, error))
    }

    /// Closes the connection asynchronously with proper WAL checkpoint.
    ///
    /// This method ensures WAL frames are safely checkpointed before closing
    /// the connection, providing better crash recovery guarantees than the
    /// synchronous `close()` method. WAL checkpoint failures now cause close to fail.
    pub async fn close_async(&self, cx: &Cx) -> Outcome<(), SqliteError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        // Execute WAL checkpoint with verification asynchronously
        match self.execute_wal_checkpoint_async_with_retry(cx).await {
            Outcome::Ok(()) => {
                #[cfg(feature = "tracing-integration")]
                crate::tracing_compat::debug!("Async WAL checkpoint completed successfully");
            }
            Outcome::Err(e) => {
                #[cfg(feature = "tracing-integration")]
                crate::tracing_compat::error!(
                    error = %e,
                    "Async WAL checkpoint failed during connection close - failing close to prevent data loss"
                );
                return Outcome::Err(e);
            }
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        }

        // Close the connection (skip WAL checkpoint since already done)
        match self.close_without_checkpoint() {
            Ok(()) => Outcome::Ok(()),
            Err(e) => Outcome::Err(e),
        }
    }

    /// Closes the connection asynchronously with structured cleanup
    /// diagnostics.
    pub async fn close_async_diagnosed(&self, cx: &Cx) -> Outcome<(), SqliteOperationError> {
        diagnose_legacy_outcome(SqliteOperation::Close, self.close_async(cx).await)
    }

    /// Returns true if the connection is open.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.inner.lock().conn.is_some()
    }

    /// Execute WAL checkpoint with retry logic and verification
    fn execute_wal_checkpoint_with_retry(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<(), SqliteError> {
        const MAX_RETRY_ATTEMPTS: u32 = 3;
        const RETRY_DELAY_MS: u64 = 50;

        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            match self.execute_single_wal_checkpoint(conn) {
                Ok(()) => {
                    #[cfg(feature = "tracing-integration")]
                    if attempt > 1 {
                        crate::tracing_compat::info!(
                            attempt = attempt,
                            "WAL checkpoint succeeded after retry"
                        );
                    }
                    return Ok(());
                }
                Err(e) => {
                    #[cfg(feature = "tracing-integration")]
                    crate::tracing_compat::warn!(
                        error = %e,
                        attempt = attempt,
                        max_attempts = MAX_RETRY_ATTEMPTS,
                        "WAL checkpoint attempt failed"
                    );

                    if attempt == MAX_RETRY_ATTEMPTS {
                        return Err(SqliteError::WalCheckpointFailed(format!(
                            "WAL checkpoint failed after {} attempts: {}",
                            MAX_RETRY_ATTEMPTS, e
                        )));
                    }

                    // Brief delay before retry
                    std::thread::sleep(std::time::Duration::from_millis(
                        RETRY_DELAY_MS * attempt as u64,
                    ));
                }
            }
        }

        unreachable!("Loop should always return within max attempts")
    }

    /// Execute a single WAL checkpoint with verification
    fn execute_single_wal_checkpoint(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<(), rusqlite::Error> {
        // Use PRAGMA wal_checkpoint(RESTART) for stronger durability guarantees
        // This ensures WAL is checkpointed AND reset
        conn.execute_batch("PRAGMA wal_checkpoint(RESTART)")?;

        // Verify checkpoint completed by checking WAL size
        // After successful checkpoint, WAL should be minimal
        let mut stmt = conn.prepare_cached("PRAGMA wal_checkpoint")?;
        let result: (i32, i32, i32) =
            stmt.query_row([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;

        let (busy, log_pages, checkpointed_pages) = result;

        if busy != 0 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                Some("WAL checkpoint blocked by concurrent readers".to_string()),
            ));
        }

        if log_pages > 0 && checkpointed_pages == 0 {
            return Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_IOERR),
                Some(format!(
                    "WAL checkpoint failed - {} pages remain in WAL",
                    log_pages
                )),
            ));
        }

        Ok(())
    }

    /// Execute WAL checkpoint asynchronously with retry logic
    async fn execute_wal_checkpoint_async_with_retry(&self, cx: &Cx) -> Outcome<(), SqliteError> {
        const MAX_RETRY_ATTEMPTS: u32 = 3;

        for attempt in 1..=MAX_RETRY_ATTEMPTS {
            match self.execute_wal_checkpoint_async_single(cx).await {
                Outcome::Ok(()) => {
                    #[cfg(feature = "tracing-integration")]
                    if attempt > 1 {
                        crate::tracing_compat::info!(
                            attempt = attempt,
                            "Async WAL checkpoint succeeded after retry"
                        );
                    }
                    return Outcome::Ok(());
                }
                Outcome::Err(e) => {
                    #[cfg(feature = "tracing-integration")]
                    crate::tracing_compat::warn!(
                        error = %e,
                        attempt = attempt,
                        max_attempts = MAX_RETRY_ATTEMPTS,
                        "Async WAL checkpoint attempt failed"
                    );

                    if attempt == MAX_RETRY_ATTEMPTS {
                        return Outcome::Err(SqliteError::WalCheckpointFailed(format!(
                            "Async WAL checkpoint failed after {} attempts: {}",
                            MAX_RETRY_ATTEMPTS, e
                        )));
                    }

                    let retry_delay = Duration::from_millis(50 * u64::from(attempt));
                    if let Err(reason) = sqlite_wait_retry_delay(cx, retry_delay).await {
                        return Outcome::Cancelled(reason);
                    }
                }
                Outcome::Cancelled(r) => return Outcome::Cancelled(r),
                Outcome::Panicked(p) => return Outcome::Panicked(p),
            }
        }

        unreachable!("Loop should always return within max attempts")
    }

    /// Execute a single async WAL checkpoint with verification
    async fn execute_wal_checkpoint_async_single(&self, cx: &Cx) -> Outcome<(), SqliteError> {
        // Use RESTART for stronger durability guarantees
        match self
            .execute_batch_unchecked(cx, "PRAGMA wal_checkpoint(RESTART)")
            .await
        {
            Outcome::Ok(()) => {
                // Verify checkpoint by checking WAL status
                match self.query_unchecked(cx, "PRAGMA wal_checkpoint", &[]).await {
                    Outcome::Ok(rows) => {
                        if let Some(row) = rows.first() {
                            let busy = match wal_checkpoint_i64(row, "busy") {
                                Ok(value) => value,
                                Err(err) => return Outcome::Err(err),
                            };
                            let log_pages = match wal_checkpoint_i64(row, "log") {
                                Ok(value) => value,
                                Err(err) => return Outcome::Err(err),
                            };
                            let checkpointed_pages = match wal_checkpoint_i64(row, "checkpointed") {
                                Ok(value) => value,
                                Err(err) => return Outcome::Err(err),
                            };

                            if busy != 0 {
                                return Outcome::Err(SqliteError::WalCheckpointFailed(
                                    "WAL checkpoint blocked by concurrent readers".to_string(),
                                ));
                            }

                            if log_pages > 0 && checkpointed_pages == 0 {
                                return Outcome::Err(SqliteError::WalCheckpointFailed(format!(
                                    "WAL checkpoint failed - {} pages remain in WAL",
                                    log_pages
                                )));
                            }
                        }
                        Outcome::Ok(())
                    }
                    Outcome::Err(e) => Outcome::Err(e),
                    Outcome::Cancelled(r) => Outcome::Cancelled(r),
                    Outcome::Panicked(p) => Outcome::Panicked(p),
                }
            }
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Close connection without performing WAL checkpoint (for use after async checkpoint)
    fn close_without_checkpoint(&self) -> Result<(), SqliteError> {
        let mut guard = self.inner.lock();
        if let Some(conn) = guard.conn.as_ref() {
            let _ =
                rollback_orphaned_transaction_mutex_guarded(conn, self.transaction_state.as_ref());
            conn.flush_prepared_statement_cache();
        }
        *self.transaction_state.lock() = TransactionState::Autocommit;
        guard.close();
        Ok(())
    }
}

/// A SQLite transaction.
///
/// The transaction will be rolled back on drop if not committed.
pub struct SqliteTransaction<'a> {
    conn: &'a SqliteConnection,
    finished: bool,
    /// br-asupersync-server-stack-hardening-eeexl1.5 — the open transaction's
    /// obligation. Reserved at `begin` when running inside a non-root region;
    /// `commit` consumes it via `commit()`, while rollback (explicit or on
    /// drop/cancel) consumes it via `abort()`. `None` at the root region
    /// (obligations must be non-root, ASUP-E103) — still rolled back via
    /// poison-on-drop, just not obligation-tracked.
    obligation: Option<ObligationToken<TransactionKind>>,
    /// Physical transaction generation assigned by the BEGIN worker.
    generation: u64,
}

/// Reserve a transaction obligation scoped to the caller's current region.
///
/// Returns `None` at the root region: obligations must be scoped to a
/// non-root structured-concurrency region (ASUP-E103), so a transaction begun
/// outside any child region is intentionally not obligation-tracked. It still
/// rolls back on drop via the connection transaction-state poison.
fn reserve_transaction_obligation(cx: &Cx) -> Option<ObligationToken<TransactionKind>> {
    let region = cx.region_id();
    if region.as_u64() == 0 {
        None
    } else {
        Some(ObligationToken::reserve("db-transaction:sqlite", region))
    }
}

impl SqliteTransaction<'_> {
    #[must_use]
    pub(crate) fn requires_rollback_before_commit(&self) -> bool {
        let state = self.conn.transaction_state.lock();
        self.conn.transaction_generation.load(Ordering::Acquire) == self.generation
            && *state == TransactionState::NeedsRollback
    }

    pub(crate) fn poison_for_rollback(&self) {
        let mut state = self.conn.transaction_state.lock();
        if self.conn.transaction_generation.load(Ordering::Acquire) == self.generation {
            *state = TransactionState::NeedsRollback;
        }
    }

    /// Commits the transaction.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn commit(mut self, cx: &Cx) -> Outcome<(), SqliteError> {
        if self.finished {
            trace_database_transaction(cx, "sqlite", "commit", "already_finished");
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        trace_database_transaction(cx, "sqlite", "commit", "start");
        let finish_effect = TransactionFinishEffect::new(
            Arc::clone(&self.conn.transaction_state),
            Arc::clone(&self.conn.transaction_generation),
            self.generation,
            TransactionFinishKind::Commit,
            self.obligation.take(),
        );
        let effect = TransactionWorkerEffect::Finish(finish_effect);
        match self
            .conn
            .execute_transaction_control(cx, "COMMIT", effect)
            .await
        {
            Outcome::Ok(_) => {
                self.finished = true;
                trace_database_transaction(cx, "sqlite", "commit", "ok");
                Outcome::Ok(())
            }
            Outcome::Err(e) => {
                trace_database_transaction(cx, "sqlite", "commit", "err");
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                trace_database_transaction(cx, "sqlite", "commit", "cancelled");
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                trace_database_transaction(cx, "sqlite", "commit", "panicked");
                Outcome::Panicked(p)
            }
        }
    }

    /// Commits the transaction with structured engine diagnostics.
    pub async fn commit_diagnosed(mut self, cx: &Cx) -> Outcome<(), SqliteOperationError> {
        if self.finished {
            trace_database_transaction(cx, "sqlite", "commit_diagnosed", "already_finished");
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::TransactionCommit,
                SqliteError::TransactionFinished,
            ));
        }
        trace_database_transaction(cx, "sqlite", "commit_diagnosed", "start");
        let finish_effect = TransactionFinishEffect::new(
            Arc::clone(&self.conn.transaction_state),
            Arc::clone(&self.conn.transaction_generation),
            self.generation,
            TransactionFinishKind::Commit,
            self.obligation.take(),
        );
        let effect = TransactionWorkerEffect::Finish(finish_effect);
        match self
            .conn
            .execute_transaction_control_diagnosed(
                cx,
                "COMMIT",
                SqliteOperation::TransactionCommit,
                effect,
            )
            .await
        {
            Outcome::Ok(_) => {
                self.finished = true;
                trace_database_transaction(cx, "sqlite", "commit_diagnosed", "ok");
                Outcome::Ok(())
            }
            Outcome::Err(error) => {
                trace_database_transaction(cx, "sqlite", "commit_diagnosed", "err");
                Outcome::Err(error)
            }
            Outcome::Cancelled(reason) => {
                trace_database_transaction(cx, "sqlite", "commit_diagnosed", "cancelled");
                Outcome::Cancelled(reason)
            }
            Outcome::Panicked(payload) => {
                trace_database_transaction(cx, "sqlite", "commit_diagnosed", "panicked");
                Outcome::Panicked(payload)
            }
        }
    }

    /// Rolls back the transaction.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), SqliteError> {
        if self.finished {
            trace_database_transaction(cx, "sqlite", "rollback", "already_finished");
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        trace_database_transaction(cx, "sqlite", "rollback", "start");
        let finish_effect = TransactionFinishEffect::new(
            Arc::clone(&self.conn.transaction_state),
            Arc::clone(&self.conn.transaction_generation),
            self.generation,
            TransactionFinishKind::Rollback,
            self.obligation.take(),
        );
        let effect = TransactionWorkerEffect::Finish(finish_effect);
        match self
            .conn
            .execute_transaction_control(cx, "ROLLBACK", effect)
            .await
        {
            Outcome::Ok(_) => {
                self.finished = true;
                trace_database_transaction(cx, "sqlite", "rollback", "ok");
                Outcome::Ok(())
            }
            Outcome::Err(e) => {
                trace_database_transaction(cx, "sqlite", "rollback", "err");
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                trace_database_transaction(cx, "sqlite", "rollback", "cancelled");
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                trace_database_transaction(cx, "sqlite", "rollback", "panicked");
                Outcome::Panicked(p)
            }
        }
    }

    /// Rolls back the transaction with structured engine diagnostics.
    pub async fn rollback_diagnosed(mut self, cx: &Cx) -> Outcome<(), SqliteOperationError> {
        if self.finished {
            trace_database_transaction(cx, "sqlite", "rollback_diagnosed", "already_finished");
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::TransactionRollback,
                SqliteError::TransactionFinished,
            ));
        }
        trace_database_transaction(cx, "sqlite", "rollback_diagnosed", "start");
        let finish_effect = TransactionFinishEffect::new(
            Arc::clone(&self.conn.transaction_state),
            Arc::clone(&self.conn.transaction_generation),
            self.generation,
            TransactionFinishKind::Rollback,
            self.obligation.take(),
        );
        let effect = TransactionWorkerEffect::Finish(finish_effect);
        match self
            .conn
            .execute_transaction_control_diagnosed(
                cx,
                "ROLLBACK",
                SqliteOperation::TransactionRollback,
                effect,
            )
            .await
        {
            Outcome::Ok(_) => {
                self.finished = true;
                trace_database_transaction(cx, "sqlite", "rollback_diagnosed", "ok");
                Outcome::Ok(())
            }
            Outcome::Err(error) => {
                trace_database_transaction(cx, "sqlite", "rollback_diagnosed", "err");
                Outcome::Err(error)
            }
            Outcome::Cancelled(reason) => {
                trace_database_transaction(cx, "sqlite", "rollback_diagnosed", "cancelled");
                Outcome::Cancelled(reason)
            }
            Outcome::Panicked(payload) => {
                trace_database_transaction(cx, "sqlite", "rollback_diagnosed", "panicked");
                Outcome::Panicked(payload)
            }
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

    /// Executes a statement inside this transaction with structured
    /// diagnostics.
    pub async fn execute_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<u64, SqliteOperationError> {
        if self.finished {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Step,
                SqliteError::TransactionFinished,
            ));
        }
        self.conn.execute_diagnosed(cx, sql, params).await
    }

    /// Executes trusted transaction-control SQL within this transaction.
    pub(crate) async fn execute_unchecked(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<u64, SqliteError> {
        if self.finished {
            return Outcome::Err(SqliteError::TransactionFinished);
        }
        self.conn.execute_unchecked(cx, sql, params).await
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

    /// Executes a query inside this transaction with structured diagnostics.
    pub async fn query_diagnosed(
        &self,
        cx: &Cx,
        sql: &str,
        params: &[SqliteValue],
    ) -> Outcome<Vec<SqliteRow>, SqliteOperationError> {
        if self.finished {
            return Outcome::Err(SqliteOperationError::from_legacy(
                SqliteOperation::Step,
                SqliteError::TransactionFinished,
            ));
        }
        self.conn.query_diagnosed(cx, sql, params).await
    }
}

impl Drop for SqliteTransaction<'_> {
    fn drop(&mut self) {
        // Resolve the obligation first: a transaction dropped without an
        // explicit commit rolls back, so abort() is the correct discharge and
        // it disarms the token's own leak panic.
        if let Some(token) = self.obligation.take() {
            let _ = token.abort();
        }
        if !self.finished {
            self.poison_for_rollback();
            self.conn
                .schedule_dropped_transaction_rollback(self.generation);
        }
    }
}

/// Converts a rusqlite value reference to our SqliteValue.
fn column_name_or_index(column_names: &[String], idx: usize) -> String {
    column_names
        .get(idx)
        .cloned()
        .unwrap_or_else(|| format!("index {idx}"))
}

fn convert_value(
    value: rusqlite::types::ValueRef<'_>,
    column: &str,
) -> Result<SqliteValue, SqliteError> {
    match value {
        rusqlite::types::ValueRef::Null => Ok(SqliteValue::Null),
        rusqlite::types::ValueRef::Integer(v) => Ok(SqliteValue::Integer(v)),
        rusqlite::types::ValueRef::Real(v) => Ok(SqliteValue::Real(v)),
        rusqlite::types::ValueRef::Text(v) => {
            let text =
                std::str::from_utf8(v).map_err(|source| SqliteError::InvalidTextEncoding {
                    column: column.to_string(),
                    source,
                })?;
            Ok(SqliteValue::Text(text.to_string()))
        }
        rusqlite::types::ValueRef::Blob(v) => Ok(SqliteValue::Blob(v.to_vec())),
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
include!("sqlite_tests.rs");
