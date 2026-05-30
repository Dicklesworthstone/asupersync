//! Transaction management helpers.
//!
//! Provides high-level ergonomic wrappers for database transactions that
//! handle commit/rollback lifecycle automatically, plus savepoint support.
//!
//! # Design
//!
//! The low-level transaction types ([`PgTransaction`], [`SqliteTransaction`],
//! [`MySqlTransaction`]) require manual `commit()`/`rollback()` calls.
//! This module provides:
//!
//! - [`with_pg_transaction`]: Run a closure inside a PostgreSQL transaction
//! - [`with_sqlite_transaction`]: Run a closure inside a SQLite transaction
//! - [`with_mysql_transaction`]: Run a closure inside a MySQL transaction
//! - [`with_pg_transaction_retry`]: PostgreSQL retry on serialization failure (40001)
//! - [`with_mysql_transaction_retry`]: MySQL retry on deadlock (1213/1205)
//! - [`with_sqlite_transaction_retry`]: SQLite retry on SQLITE_BUSY/SQLITE_LOCKED
//! - [`PgSavepoint`] / [`SqliteSavepoint`] / [`MySqlSavepoint`]: Nested savepoints
//! - [`RetryPolicy`]: Configurable retry with exponential backoff
//! - [`TransactionReplaySafety`]: Explicit opt-in for replaying user closures
//!
//! All helpers integrate with [`Cx`] for cancellation. On `Outcome::Err` or
//! `Outcome::Cancelled`, the transaction is rolled back. On `Outcome::Ok`,
//! it is committed.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::database::transaction::{with_pg_transaction, RetryPolicy};
//!
//! async fn transfer(conn: &mut PgConnection, cx: &Cx) -> Outcome<(), PgError> {
//!     with_pg_transaction(conn, cx, |tx, cx| async move {
//!         tx.execute(cx, "UPDATE accounts SET balance = balance - 100 WHERE id = 1").await?;
//!         tx.execute(cx, "UPDATE accounts SET balance = balance + 100 WHERE id = 2").await?;
//!         Outcome::Ok(())
//!     }).await
//! }
//! ```
//!
//! [`Cx`]: crate::cx::Cx
//! [`PgTransaction`]: super::PgTransaction
//! [`SqliteTransaction`]: super::SqliteTransaction
//! [`MySqlTransaction`]: super::MySqlTransaction

use crate::cx::Cx;
use crate::time::{sleep, wall_now};
use crate::types::{CancelReason, Outcome};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

// ─── RetryPolicy ─────────────────────────────────────────────────────────────

/// Policy for retrying transactions on serialization failure.
///
/// When a transaction fails due to a serialization conflict (e.g. PostgreSQL
/// `40001`, SQLite `SQLITE_BUSY`), the retry policy controls whether and how
/// many times to retry the entire transaction.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (0 = no retries).
    pub max_retries: u32,
    /// Base delay between retries. Actual delay is `base_delay * 2^attempt`.
    pub base_delay: Duration,
    /// Maximum delay cap.
    pub max_delay: Duration,
}

impl RetryPolicy {
    /// No retries — fail on the first error.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            max_retries: 0,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
        }
    }

    /// Default retry policy: 3 retries with exponential backoff.
    #[must_use]
    pub const fn default_retry() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
        }
    }

    /// Compute delay for the given attempt (0-indexed), capped at `max_delay`.
    #[must_use]
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        let delay_ms = self
            .base_delay
            .as_millis()
            .saturating_mul(u128::from(factor));
        let capped = delay_ms.min(self.max_delay.as_millis());
        // Safe: max_delay.as_millis() fits in u64 for any reasonable duration
        Duration::from_millis(capped.min(u128::from(u64::MAX)) as u64)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::none()
    }
}

/// Whether replaying a transaction closure is safe after the closure has started.
///
/// Retry helpers may need to rerun the entire closure after a commit-time
/// serialization conflict or deadlock. That replay is only safe when the
/// closure performs no externally visible side effects beyond the database
/// transaction itself, or when those effects are otherwise idempotent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransactionReplaySafety {
    /// Fail closed once the user closure has started.
    ///
    /// This still permits retries for transient begin-time failures, because
    /// the closure body has not executed yet.
    #[default]
    ReplayUnsafe,
    /// Caller has verified the closure is safe to replay after it starts.
    ReplaySafe,
}

/// Validate that a savepoint name is safe for SQL identifier interpolation.
/// Rejects anything that is not `[a-zA-Z0-9_]` to prevent SQL injection.
fn validate_savepoint_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn cancelled_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason().unwrap_or_default()
}

async fn wait_retry_delay(cx: &Cx, delay: Duration) -> Result<(), CancelReason> {
    if delay.is_zero() {
        cx.checkpoint().map_err(|_| cancelled_reason(cx))?;
        crate::runtime::yield_now().await;
        return cx.checkpoint().map_err(|_| cancelled_reason(cx));
    }

    let now = cx
        .timer_driver()
        .map_or_else(wall_now, |driver| driver.now());
    let mut sleeper = sleep(now, delay);
    poll_fn(|task_cx| {
        if cx.checkpoint().is_err() {
            return Poll::Ready(Err(cancelled_reason(cx)));
        }
        Pin::new(&mut sleeper).poll(task_cx).map(|()| Ok(()))
    })
    .await
}

#[cfg(test)]
async fn retry_with_policy<T, E, Op, OpFut, Pred>(
    cx: &Cx,
    policy: &RetryPolicy,
    mut op: Op,
    is_retryable: Pred,
) -> Outcome<T, E>
where
    Op: FnMut() -> OpFut,
    OpFut: Future<Output = Outcome<T, E>>,
    Pred: Fn(&E) -> bool,
{
    let mut attempt = 0u32;
    loop {
        let result = op().await;
        match &result {
            Outcome::Err(err) if is_retryable(err) && attempt < policy.max_retries => {
                let delay = policy.delay_for(attempt);
                attempt += 1;
                if let Err(reason) = wait_retry_delay(cx, delay).await {
                    return Outcome::Cancelled(reason);
                }
            }
            _ => return result,
        }
    }
}

// ─── PostgreSQL helpers ──────────────────────────────────────────────────────

#[cfg(feature = "postgres")]
mod pg {
    use super::{
        Cx, Future, Outcome, RetryPolicy, TransactionReplaySafety, validate_savepoint_name,
        wait_retry_delay,
    };
    use crate::database::postgres::{PgConnection, PgError, PgTransaction};
    use std::{
        fmt,
        sync::atomic::{AtomicBool, Ordering},
    };

    fn rollback_required_error() -> PgError {
        PgError::Protocol("transaction must roll back before commit".to_string())
    }

    /// Run a closure inside a PostgreSQL transaction.
    ///
    /// The closure receives a mutable reference to the active transaction and
    /// a `&Cx`. If the closure returns `Outcome::Ok(value)`, the transaction
    /// is committed and the value is returned. On `Outcome::Err` or
    /// `Outcome::Cancelled`, the transaction is rolled back.
    ///
    /// # Panics
    ///
    /// If the closure panics (via `Outcome::Panicked`), the transaction is
    /// rolled back before propagating the panic payload.
    pub async fn with_pg_transaction<T, F, Fut>(
        conn: &mut PgConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, PgError>
    where
        F: FnOnce(&mut PgTransaction<'_>, &Cx) -> Fut,
        Fut: Future<Output = Outcome<T, PgError>>,
    {
        let mut tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&mut tx, cx).await;

        match result {
            Outcome::Ok(value) => {
                if tx.requires_rollback_before_commit() {
                    return Outcome::Err(rollback_required_error());
                }
                match tx.commit(cx).await {
                    Outcome::Ok(()) => Outcome::Ok(value),
                    Outcome::Err(e) => Outcome::Err(e),
                    Outcome::Cancelled(r) => Outcome::Cancelled(r),
                    Outcome::Panicked(p) => Outcome::Panicked(p),
                }
            }
            Outcome::Err(e) => {
                // Best-effort rollback; drop will handle it if this fails.
                let _ = tx.rollback(cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                let _ = tx.rollback(cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                let _ = tx.rollback(cx).await;
                Outcome::Panicked(p)
            }
        }
    }

    /// Run a closure inside a PostgreSQL transaction with retry on
    /// serialization failure.
    ///
    /// Serialization failures (SQLSTATE `40001`) are retried according to the
    /// given [`RetryPolicy`]. Pass [`TransactionReplaySafety::ReplaySafe`] only
    /// when rerunning the closure cannot duplicate externally visible side
    /// effects. Other errors are returned immediately.
    pub async fn with_pg_transaction_retry<T, F, MkFut>(
        conn: &mut PgConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        mut f: F,
    ) -> Outcome<T, PgError>
    where
        T: Send,
        F: FnMut(&mut PgTransaction<'_>, &Cx) -> MkFut + Send,
        MkFut: Future<Output = Outcome<T, PgError>> + Send,
    {
        let body_started = AtomicBool::new(false);
        let mut attempt = 0u32;

        loop {
            body_started.store(false, Ordering::Relaxed);
            let result = with_pg_transaction(conn, cx, |tx, tx_cx| {
                body_started.store(true, Ordering::Relaxed);
                f(tx, tx_cx)
            })
            .await;

            match &result {
                Outcome::Err(err)
                    if err.is_serialization_failure()
                        && (replay_safety == TransactionReplaySafety::ReplaySafe
                            || !body_started.load(Ordering::Relaxed))
                        && attempt < policy.max_retries =>
                {
                    let delay = policy.delay_for(attempt);
                    attempt += 1;
                    if let Err(reason) = wait_retry_delay(cx, delay).await {
                        return Outcome::Cancelled(reason);
                    }
                }
                _ => return result,
            }
        }
    }

    /// A PostgreSQL savepoint within an active transaction.
    ///
    /// Savepoints enable nested transaction semantics: you can roll back to
    /// a savepoint without rolling back the entire transaction.
    ///
    /// Created via [`PgSavepoint::new`].
    pub struct PgSavepoint<'a, 'tx> {
        tx: &'a mut PgTransaction<'tx>,
        name: String,
        released: bool,
    }

    impl fmt::Debug for PgSavepoint<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("PgSavepoint")
                .field("name", &self.name)
                .field("released", &self.released)
                .finish()
        }
    }

    impl<'a, 'tx> PgSavepoint<'a, 'tx> {
        /// Create a new savepoint with the given name.
        ///
        /// Name must be `[a-zA-Z0-9_]+` to prevent SQL injection.
        pub async fn new(
            tx: &'a mut PgTransaction<'tx>,
            cx: &Cx,
            name: &str,
        ) -> Outcome<PgSavepoint<'a, 'tx>, PgError> {
            if !validate_savepoint_name(name) {
                return Outcome::Err(PgError::Protocol(format!(
                    "invalid savepoint name: {name:?}"
                )));
            }
            let sql = format!("SAVEPOINT {name}");
            match tx.execute_unchecked(cx, &sql).await {
                Outcome::Ok(_) => Outcome::Ok(PgSavepoint {
                    tx,
                    name: name.to_owned(),
                    released: false,
                }),
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            }
        }

        /// Release (commit) the savepoint.
        pub async fn release(mut self, cx: &Cx) -> Outcome<(), PgError> {
            if self.released {
                return Outcome::Err(PgError::TransactionFinished);
            }
            let sql = format!("RELEASE SAVEPOINT {}", self.name);
            match self.tx.execute_unchecked(cx, &sql).await {
                Outcome::Ok(_) => {
                    self.released = true;
                    Outcome::Ok(())
                }
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            }
        }

        /// Roll back to the savepoint.
        pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), PgError> {
            if self.released {
                return Outcome::Err(PgError::TransactionFinished);
            }
            let rollback_sql = format!("ROLLBACK TO SAVEPOINT {}", self.name);
            match self.tx.execute_unchecked(cx, &rollback_sql).await {
                Outcome::Ok(_) => {
                    let release_sql = format!("RELEASE SAVEPOINT {}", self.name);
                    match self.tx.execute_unchecked(cx, &release_sql).await {
                        Outcome::Ok(_) => {
                            self.released = true;
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

        /// Access the underlying transaction.
        pub fn transaction(&mut self) -> &mut PgTransaction<'tx> {
            self.tx
        }
    }

    impl Drop for PgSavepoint<'_, '_> {
        fn drop(&mut self) {
            if !self.released {
                self.tx.poison_for_rollback();
            }
        }
    }
}

#[cfg(feature = "postgres")]
pub use pg::{PgSavepoint, with_pg_transaction, with_pg_transaction_retry};

// ─── SQLite helpers ──────────────────────────────────────────────────────────

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::{
        Cx, Future, Outcome, RetryPolicy, TransactionReplaySafety, validate_savepoint_name,
        wait_retry_delay,
    };
    use crate::database::sqlite::{SqliteConnection, SqliteError, SqliteTransaction};
    use std::{
        fmt,
        pin::Pin,
        sync::atomic::{AtomicBool, Ordering},
    };

    type SqliteTxFuture<'a, T> = Pin<Box<dyn Future<Output = Outcome<T, SqliteError>> + Send + 'a>>;

    fn rollback_required_error() -> SqliteError {
        SqliteError::Sqlite("transaction must roll back before commit".to_string())
    }

    /// Run a closure inside a SQLite transaction.
    ///
    /// See [`with_pg_transaction`](super::with_pg_transaction) for semantics.
    pub async fn with_sqlite_transaction<T, F>(
        conn: &SqliteConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, SqliteError>
    where
        F: for<'a> FnOnce(&'a SqliteTransaction<'_>, &'a Cx) -> SqliteTxFuture<'a, T>,
    {
        let tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&tx, cx).await;

        match result {
            Outcome::Ok(value) => {
                if tx.requires_rollback_before_commit() {
                    return Outcome::Err(rollback_required_error());
                }
                match tx.commit(cx).await {
                    Outcome::Ok(()) => Outcome::Ok(value),
                    Outcome::Err(e) => Outcome::Err(e),
                    Outcome::Cancelled(r) => Outcome::Cancelled(r),
                    Outcome::Panicked(p) => Outcome::Panicked(p),
                }
            }
            Outcome::Err(e) => {
                let _ = tx.rollback(cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                let _ = tx.rollback(cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                let _ = tx.rollback(cx).await;
                Outcome::Panicked(p)
            }
        }
    }

    /// Run a closure inside a SQLite IMMEDIATE transaction.
    ///
    /// Acquires the write lock immediately, avoiding SQLITE_BUSY in the
    /// middle of a transaction.
    pub async fn with_sqlite_transaction_immediate<T, F>(
        conn: &SqliteConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, SqliteError>
    where
        F: for<'a> FnOnce(&'a SqliteTransaction<'_>, &'a Cx) -> SqliteTxFuture<'a, T>,
    {
        let tx = match conn.begin_immediate(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&tx, cx).await;

        match result {
            Outcome::Ok(value) => {
                if tx.requires_rollback_before_commit() {
                    return Outcome::Err(rollback_required_error());
                }
                match tx.commit(cx).await {
                    Outcome::Ok(()) => Outcome::Ok(value),
                    Outcome::Err(e) => Outcome::Err(e),
                    Outcome::Cancelled(r) => Outcome::Cancelled(r),
                    Outcome::Panicked(p) => Outcome::Panicked(p),
                }
            }
            Outcome::Err(e) => {
                let _ = tx.rollback(cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                let _ = tx.rollback(cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                let _ = tx.rollback(cx).await;
                Outcome::Panicked(p)
            }
        }
    }

    /// Run a closure inside a SQLite transaction with retry on busy/locked.
    ///
    /// `SQLITE_BUSY` and `SQLITE_LOCKED` errors are retried according to the
    /// given [`RetryPolicy`]. Pass [`TransactionReplaySafety::ReplaySafe`] only
    /// when rerunning the closure cannot duplicate externally visible side
    /// effects. Other errors are returned immediately.
    ///
    /// For write-heavy workloads, prefer [`with_sqlite_transaction_immediate`]
    /// which acquires the write lock upfront to reduce contention.
    pub async fn with_sqlite_transaction_retry<T, F>(
        conn: &SqliteConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        mut f: F,
    ) -> Outcome<T, SqliteError>
    where
        T: Send,
        F: for<'a> FnMut(&'a SqliteTransaction<'_>, &'a Cx) -> SqliteTxFuture<'a, T> + Send,
    {
        let body_started = AtomicBool::new(false);
        let mut attempt = 0u32;

        loop {
            body_started.store(false, Ordering::Relaxed);
            let result = with_sqlite_transaction(conn, cx, |tx, tx_cx| {
                body_started.store(true, Ordering::Relaxed);
                f(tx, tx_cx)
            })
            .await;

            match &result {
                Outcome::Err(err)
                    if (err.is_busy() || err.is_locked())
                        && (replay_safety == TransactionReplaySafety::ReplaySafe
                            || !body_started.load(Ordering::Relaxed))
                        && attempt < policy.max_retries =>
                {
                    let delay = policy.delay_for(attempt);
                    attempt += 1;
                    if let Err(reason) = wait_retry_delay(cx, delay).await {
                        return Outcome::Cancelled(reason);
                    }
                }
                _ => return result,
            }
        }
    }

    /// A SQLite savepoint within an active transaction.
    ///
    /// Created via [`SqliteSavepoint::new`].
    pub struct SqliteSavepoint<'a, 'tx> {
        tx: &'a SqliteTransaction<'tx>,
        name: String,
        released: bool,
    }

    impl fmt::Debug for SqliteSavepoint<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("SqliteSavepoint")
                .field("name", &self.name)
                .field("released", &self.released)
                .finish()
        }
    }

    impl<'a, 'tx> SqliteSavepoint<'a, 'tx> {
        /// Create a new savepoint with the given name.
        ///
        /// Name must be `[a-zA-Z0-9_]+` to prevent SQL injection.
        pub async fn new(
            tx: &'a SqliteTransaction<'tx>,
            cx: &Cx,
            name: &str,
        ) -> Outcome<SqliteSavepoint<'a, 'tx>, SqliteError> {
            if !validate_savepoint_name(name) {
                return Outcome::Err(SqliteError::Sqlite(format!(
                    "invalid savepoint name: {name:?}"
                )));
            }
            let sql = format!("SAVEPOINT {name}");
            match tx.execute_unchecked(cx, &sql, &[]).await {
                Outcome::Ok(_) => Outcome::Ok(SqliteSavepoint {
                    tx,
                    name: name.to_owned(),
                    released: false,
                }),
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            }
        }

        /// Release (commit) the savepoint.
        pub async fn release(mut self, cx: &Cx) -> Outcome<(), SqliteError> {
            if self.released {
                return Outcome::Err(SqliteError::TransactionFinished);
            }
            let sql = format!("RELEASE SAVEPOINT {}", self.name);
            match self.tx.execute_unchecked(cx, &sql, &[]).await {
                Outcome::Ok(_) => {
                    self.released = true;
                    Outcome::Ok(())
                }
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            }
        }

        /// Roll back to the savepoint.
        pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), SqliteError> {
            if self.released {
                return Outcome::Err(SqliteError::TransactionFinished);
            }
            let rollback_sql = format!("ROLLBACK TO SAVEPOINT {}", self.name);
            match self.tx.execute_unchecked(cx, &rollback_sql, &[]).await {
                Outcome::Ok(_) => {
                    let release_sql = format!("RELEASE SAVEPOINT {}", self.name);
                    match self.tx.execute_unchecked(cx, &release_sql, &[]).await {
                        Outcome::Ok(_) => {
                            self.released = true;
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

        /// Access the underlying transaction.
        #[must_use]
        pub fn transaction(&self) -> &SqliteTransaction<'tx> {
            self.tx
        }
    }

    impl Drop for SqliteSavepoint<'_, '_> {
        fn drop(&mut self) {
            if !self.released {
                self.tx.poison_for_rollback();
            }
        }
    }
}

#[cfg(feature = "sqlite")]
pub use sqlite::{
    SqliteSavepoint, with_sqlite_transaction, with_sqlite_transaction_immediate,
    with_sqlite_transaction_retry,
};

// ─── MySQL helpers ───────────────────────────────────────────────────────────

#[cfg(feature = "mysql")]
mod mysql {
    use super::{
        Cx, Future, Outcome, RetryPolicy, TransactionReplaySafety, validate_savepoint_name,
        wait_retry_delay,
    };
    use crate::database::mysql::{MySqlConnection, MySqlError, MySqlTransaction};
    use std::{
        fmt,
        sync::atomic::{AtomicBool, Ordering},
    };

    fn rollback_required_error() -> MySqlError {
        MySqlError::Protocol("transaction must roll back before commit".to_string())
    }

    /// Run a closure inside a MySQL transaction.
    ///
    /// See [`with_pg_transaction`](super::with_pg_transaction) for semantics.
    pub async fn with_mysql_transaction<T, F, Fut>(
        conn: &mut MySqlConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, MySqlError>
    where
        F: FnOnce(&mut MySqlTransaction<'_>, &Cx) -> Fut,
        Fut: Future<Output = Outcome<T, MySqlError>>,
    {
        let mut tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&mut tx, cx).await;

        match result {
            Outcome::Ok(value) => {
                if tx.requires_rollback_before_commit() {
                    return Outcome::Err(rollback_required_error());
                }
                match tx.commit(cx).await {
                    Outcome::Ok(()) => Outcome::Ok(value),
                    Outcome::Err(e) => Outcome::Err(e),
                    Outcome::Cancelled(r) => Outcome::Cancelled(r),
                    Outcome::Panicked(p) => Outcome::Panicked(p),
                }
            }
            Outcome::Err(e) => {
                let _ = tx.rollback(cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                let _ = tx.rollback(cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                let _ = tx.rollback(cx).await;
                Outcome::Panicked(p)
            }
        }
    }

    /// Run a closure inside a MySQL transaction with retry on deadlock.
    ///
    /// Deadlocks (error 1213) and lock wait timeouts (error 1205) are retried
    /// according to the given [`RetryPolicy`]. Pass
    /// [`TransactionReplaySafety::ReplaySafe`] only when rerunning the closure
    /// cannot duplicate externally visible side effects. Other errors are
    /// returned immediately.
    pub async fn with_mysql_transaction_retry<T, F, MkFut>(
        conn: &mut MySqlConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        mut f: F,
    ) -> Outcome<T, MySqlError>
    where
        T: Send,
        F: FnMut(&mut MySqlTransaction<'_>, &Cx) -> MkFut + Send,
        MkFut: Future<Output = Outcome<T, MySqlError>> + Send,
    {
        let body_started = AtomicBool::new(false);
        let mut attempt = 0u32;

        loop {
            body_started.store(false, Ordering::Relaxed);
            let result = with_mysql_transaction(conn, cx, |tx, tx_cx| {
                body_started.store(true, Ordering::Relaxed);
                f(tx, tx_cx)
            })
            .await;

            match &result {
                Outcome::Err(err)
                    if err.is_deadlock()
                        && (replay_safety == TransactionReplaySafety::ReplaySafe
                            || !body_started.load(Ordering::Relaxed))
                        && attempt < policy.max_retries =>
                {
                    let delay = policy.delay_for(attempt);
                    attempt += 1;
                    if let Err(reason) = wait_retry_delay(cx, delay).await {
                        return Outcome::Cancelled(reason);
                    }
                }
                _ => return result,
            }
        }
    }

    /// A MySQL savepoint within an active transaction.
    ///
    /// Created via [`MySqlSavepoint::new`].
    pub struct MySqlSavepoint<'a, 'tx> {
        tx: &'a mut MySqlTransaction<'tx>,
        name: String,
        released: bool,
    }

    impl fmt::Debug for MySqlSavepoint<'_, '_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MySqlSavepoint")
                .field("name", &self.name)
                .field("released", &self.released)
                .finish()
        }
    }

    impl<'a, 'tx> MySqlSavepoint<'a, 'tx> {
        /// Create a new savepoint with the given name.
        ///
        /// Name must be `[a-zA-Z0-9_]+` to prevent SQL injection.
        pub async fn new(
            tx: &'a mut MySqlTransaction<'tx>,
            cx: &Cx,
            name: &str,
        ) -> Outcome<MySqlSavepoint<'a, 'tx>, MySqlError> {
            if !validate_savepoint_name(name) {
                return Outcome::Err(MySqlError::Protocol(format!(
                    "invalid savepoint name: {name:?}"
                )));
            }
            let sql = format!("SAVEPOINT {name}");
            match tx.execute_static_sql(cx, &sql).await {
                Outcome::Ok(_) => Outcome::Ok(MySqlSavepoint {
                    tx,
                    name: name.to_owned(),
                    released: false,
                }),
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            }
        }

        /// Release (commit) the savepoint.
        pub async fn release(mut self, cx: &Cx) -> Outcome<(), MySqlError> {
            if self.released {
                return Outcome::Err(MySqlError::TransactionFinished);
            }
            let sql = format!("RELEASE SAVEPOINT {}", self.name);
            match self.tx.execute_static_sql(cx, &sql).await {
                Outcome::Ok(_) => {
                    self.released = true;
                    Outcome::Ok(())
                }
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            }
        }

        /// Roll back to the savepoint.
        pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), MySqlError> {
            if self.released {
                return Outcome::Err(MySqlError::TransactionFinished);
            }
            let rollback_sql = format!("ROLLBACK TO SAVEPOINT {}", self.name);
            match self.tx.execute_static_sql(cx, &rollback_sql).await {
                Outcome::Ok(_) => {
                    let release_sql = format!("RELEASE SAVEPOINT {}", self.name);
                    match self.tx.execute_static_sql(cx, &release_sql).await {
                        Outcome::Ok(_) => {
                            self.released = true;
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

        /// Access the underlying transaction.
        pub fn transaction(&mut self) -> &mut MySqlTransaction<'tx> {
            self.tx
        }
    }

    impl Drop for MySqlSavepoint<'_, '_> {
        fn drop(&mut self) {
            if !self.released {
                self.tx.poison_for_rollback();
            }
        }
    }
}

#[cfg(feature = "mysql")]
pub use mysql::{MySqlSavepoint, with_mysql_transaction, with_mysql_transaction_retry};

// ─── Tests ───────────────────────────────────────────────────────────────────

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
    #[cfg(feature = "sqlite")]
    use crate::conformance::{ConformanceTarget, LabRuntimeTarget, TestConfig};
    #[cfg(feature = "sqlite")]
    use crate::cx::Cx;
    #[cfg(feature = "sqlite")]
    use crate::database::sqlite::{SqliteConnection, SqliteError, SqliteValue};
    use std::task::{Context, Poll, Waker};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct RetryProbeError(&'static str);

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        crate::test_phase!(name);
    }

    #[test]
    fn retry_policy_none() {
        init_test("retry_policy_none");
        let policy = RetryPolicy::none();
        assert_eq!(policy.max_retries, 0);
        assert_eq!(policy.base_delay, Duration::ZERO);
        crate::test_complete!("retry_policy_none");
    }

    #[test]
    fn retry_policy_default() {
        init_test("retry_policy_default");
        let policy = RetryPolicy::default_retry();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay, Duration::from_millis(50));
        assert_eq!(policy.max_delay, Duration::from_secs(2));
        crate::test_complete!("retry_policy_default");
    }

    #[test]
    fn retry_policy_exponential_backoff() {
        init_test("retry_policy_exponential_backoff");
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        };

        // attempt 0: 100ms * 2^0 = 100ms
        assert_eq!(policy.delay_for(0), Duration::from_millis(100));
        // attempt 1: 100ms * 2^1 = 200ms
        assert_eq!(policy.delay_for(1), Duration::from_millis(200));
        // attempt 2: 100ms * 2^2 = 400ms
        assert_eq!(policy.delay_for(2), Duration::from_millis(400));
        // attempt 3: 100ms * 2^3 = 800ms
        assert_eq!(policy.delay_for(3), Duration::from_millis(800));
        crate::test_complete!("retry_policy_exponential_backoff");
    }

    #[test]
    fn retry_policy_capped_at_max() {
        init_test("retry_policy_capped_at_max");
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(2),
        };

        // attempt 3: 500ms * 8 = 4000ms → capped to 2000ms
        assert_eq!(policy.delay_for(3), Duration::from_secs(2));
        // attempt 10: still capped
        assert_eq!(policy.delay_for(10), Duration::from_secs(2));
        crate::test_complete!("retry_policy_capped_at_max");
    }

    #[test]
    fn retry_policy_delay_is_monotonic_and_cap_stable() {
        init_test("retry_policy_delay_is_monotonic_and_cap_stable");
        let policy = RetryPolicy {
            max_retries: 12,
            base_delay: Duration::from_millis(125),
            max_delay: Duration::from_secs(2),
        };

        let mut previous = Duration::ZERO;
        let mut capped_attempts = 0usize;
        for attempt in 0..12 {
            let delay = policy.delay_for(attempt);
            assert!(
                delay >= previous,
                "retry delay decreased at attempt {attempt}: {delay:?} < {previous:?}"
            );
            assert!(
                delay <= policy.max_delay,
                "retry delay exceeded max at attempt {attempt}: {delay:?}"
            );
            if delay == policy.max_delay {
                capped_attempts += 1;
            }
            previous = delay;
        }

        assert_eq!(
            policy.delay_for(4),
            policy.max_delay,
            "125ms * 2^4 should reach the configured 2s cap"
        );
        assert!(
            capped_attempts >= 8,
            "once capped, all later attempts should remain at max_delay"
        );
        crate::test_complete!("retry_policy_delay_is_monotonic_and_cap_stable");
    }

    #[test]
    fn retry_policy_overflow_safe() {
        init_test("retry_policy_overflow_safe");
        let policy = RetryPolicy {
            max_retries: 100,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
        };

        // Very large attempt numbers should not panic.
        let delay = policy.delay_for(63);
        assert!(delay <= Duration::from_secs(60));
        let delay = policy.delay_for(100);
        assert!(delay <= Duration::from_secs(60));
        crate::test_complete!("retry_policy_overflow_safe");
    }

    #[test]
    fn retry_policy_default_trait() {
        init_test("retry_policy_default_trait");
        let policy = RetryPolicy::default();
        // Default trait impl is `none()`
        assert_eq!(policy.max_retries, 0);
        crate::test_complete!("retry_policy_default_trait");
    }

    #[test]
    fn retry_policy_debug() {
        let policy = RetryPolicy::default_retry();
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("RetryPolicy"));
        assert!(dbg.contains("max_retries"));
    }

    #[test]
    fn retry_policy_clone() {
        let policy = RetryPolicy::default_retry();
        let cloned = policy.clone();
        assert_eq!(cloned.max_retries, policy.max_retries);
        assert_eq!(cloned.base_delay, policy.base_delay);
        assert_eq!(cloned.max_delay, policy.max_delay);
    }

    #[test]
    fn wait_retry_delay_returns_cancelled_while_sleeping() {
        init_test("wait_retry_delay_returns_cancelled_while_sleeping");
        let cx = Cx::for_testing();
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let expected = CancelReason::user("stop");
        let mut fut = Box::pin(wait_retry_delay(&cx, Duration::from_secs(60)));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));
        cx.set_cancel_reason(expected.clone());

        match fut.as_mut().poll(&mut task_cx) {
            Poll::Ready(Err(reason)) => assert_eq!(reason, expected),
            other => panic!("expected cancelled retry wait, got {other:?}"),
        }
        crate::test_complete!("wait_retry_delay_returns_cancelled_while_sleeping");
    }

    #[test]
    fn wait_retry_delay_zero_delay_returns_cancelled_after_yield() {
        init_test("wait_retry_delay_zero_delay_returns_cancelled_after_yield");
        let cx = Cx::for_testing();
        let waker = noop_waker();
        let mut task_cx = Context::from_waker(&waker);
        let expected = CancelReason::user("stop");
        let mut fut = Box::pin(wait_retry_delay(&cx, Duration::ZERO));

        assert!(matches!(fut.as_mut().poll(&mut task_cx), Poll::Pending));
        cx.set_cancel_reason(expected.clone());

        match fut.as_mut().poll(&mut task_cx) {
            Poll::Ready(Err(reason)) => assert_eq!(reason, expected),
            other => panic!("expected cancelled zero-delay retry wait, got {other:?}"),
        }
        crate::test_complete!("wait_retry_delay_zero_delay_returns_cancelled_after_yield");
    }

    #[test]
    fn retry_with_policy_stops_after_max_retries_on_persistent_error() {
        init_test("retry_with_policy_stops_after_max_retries_on_persistent_error");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                attempts += 1;
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "retryable",
                )))
            },
            |_| true,
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("retryable")),
            other => panic!("expected persistent retryable error, got {other:?}"),
        }
        assert_eq!(
            attempts, 4,
            "max_retries=3 must stop after 4 total attempts"
        );
        crate::test_complete!("retry_with_policy_stops_after_max_retries_on_persistent_error");
    }

    #[test]
    fn retry_with_policy_replay_unsafe_still_retries_before_body_starts() {
        init_test("retry_with_policy_replay_unsafe_still_retries_before_body_starts");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let replay_safety = TransactionReplaySafety::ReplayUnsafe;
        let body_started = std::cell::Cell::new(false);
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                body_started.set(false);
                attempts += 1;
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "retryable",
                )))
            },
            |_| replay_safety == TransactionReplaySafety::ReplaySafe || !body_started.get(),
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("retryable")),
            other => panic!("expected persistent retryable error, got {other:?}"),
        }
        assert_eq!(attempts, 4, "begin-time retryables should remain retryable");
        crate::test_complete!("retry_with_policy_replay_unsafe_still_retries_before_body_starts");
    }

    #[test]
    fn retry_with_policy_replay_unsafe_fails_closed_after_body_starts() {
        init_test("retry_with_policy_replay_unsafe_fails_closed_after_body_starts");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let replay_safety = TransactionReplaySafety::ReplayUnsafe;
        let body_started = std::cell::Cell::new(false);
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                body_started.set(false);
                attempts += 1;
                body_started.set(true);
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "retryable",
                )))
            },
            |_| replay_safety == TransactionReplaySafety::ReplaySafe || !body_started.get(),
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("retryable")),
            other => panic!("expected persistent retryable error, got {other:?}"),
        }
        assert_eq!(attempts, 1, "replay-unsafe closures must not be rerun");
        crate::test_complete!("retry_with_policy_replay_unsafe_fails_closed_after_body_starts");
    }

    #[test]
    fn retry_with_policy_returns_non_retryable_error_immediately() {
        init_test("retry_with_policy_returns_non_retryable_error_immediately");
        let cx = Cx::for_testing();
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        };
        let mut attempts = 0u32;

        let outcome = futures_lite::future::block_on(retry_with_policy(
            &cx,
            &policy,
            || {
                attempts += 1;
                std::future::ready(Outcome::<(), RetryProbeError>::Err(RetryProbeError(
                    "fatal",
                )))
            },
            |_| false,
        ));

        match outcome {
            Outcome::Err(err) => assert_eq!(err, RetryProbeError("fatal")),
            other => panic!("expected non-retryable error, got {other:?}"),
        }
        assert_eq!(attempts, 1, "non-retryable errors must not loop");
        crate::test_complete!("retry_with_policy_returns_non_retryable_error_immediately");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_commit_persists_under_lab_runtime() {
        init_test("with_sqlite_transaction_commit_persists_under_lab_runtime");
        let config = TestConfig::new()
            .with_seed(0x7A11_7E01)
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

                let count_inside_tx = match with_sqlite_transaction(&conn, &cx, |tx, cx| {
                    Box::pin(async move {
                        match tx
                            .execute(
                                cx,
                                "INSERT INTO tx_items(name) VALUES (?1)",
                                &[SqliteValue::Text("helper_committed".to_string())],
                            )
                            .await
                        {
                            Outcome::Ok(1) => {}
                            other => panic!("insert in helper transaction failed: {other:?}"),
                        }

                        let rows_inside = match tx
                            .query(cx, "SELECT COUNT(*) AS count FROM tx_items", &[])
                            .await
                        {
                            Outcome::Ok(rows) => rows,
                            other => {
                                panic!("count query inside helper transaction failed: {other:?}")
                            }
                        };
                        let count_inside_tx = rows_inside[0]
                            .get_i64("count")
                            .expect("count column should be present");
                        tracing::info!(
                            event = %serde_json::json!({
                                "phase": "helper_inserted",
                                "count_inside_tx": count_inside_tx,
                            }),
                            "sqlite_transaction_lab_checkpoint"
                        );

                        Outcome::Ok(count_inside_tx)
                    })
                })
                .await
                {
                    Outcome::Ok(count) => count,
                    other => panic!("with_sqlite_transaction failed: {other:?}"),
                };

                let rows_after = match conn
                    .query(
                        &cx,
                        "SELECT COUNT(*) AS count, MIN(name) AS name FROM tx_items",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(rows) => rows,
                    other => panic!("query after helper commit failed: {other:?}"),
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
                        "phase": "helper_committed",
                        "count_after_commit": count_after_commit,
                        "name": committed_name,
                    }),
                    "sqlite_transaction_lab_checkpoint"
                );
                conn.close().unwrap();

                (count_inside_tx, count_after_commit, committed_name)
            });

        assert_eq!(count_inside_tx, 1);
        assert_eq!(count_after_commit, 1);
        assert_eq!(committed_name, "helper_committed");
        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "transaction helper lab-runtime test should leave runtime invariants clean: {violations:?}"
        );
    }

    #[cfg(feature = "sqlite")]
    fn run_sqlite_commit_abort_isolation_permutation(abort_first: bool) -> Vec<String> {
        let config = TestConfig::new()
            .with_seed(0x7A11_7E02)
            .with_tracing(true)
            .with_max_steps(20_000);
        let mut runtime = LabRuntimeTarget::create_runtime(config);

        let rows = LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");

            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };
            match conn
                .execute_batch(
                    &cx,
                    "CREATE TABLE tx_isolation_items (id INTEGER PRIMARY KEY, name TEXT);",
                )
                .await
            {
                Outcome::Ok(()) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let run_commit = || {
                with_sqlite_transaction(&conn, &cx, |tx, cx| {
                    Box::pin(async move {
                        match tx
                            .execute(
                                cx,
                                "INSERT INTO tx_isolation_items(name) VALUES (?1)",
                                &[SqliteValue::Text("committed".to_string())],
                            )
                            .await
                        {
                            Outcome::Ok(1) => Outcome::Ok(()),
                            other => {
                                panic!("commit branch insert failed: {other:?}")
                            }
                        }
                    })
                })
            };

            let run_abort = || {
                with_sqlite_transaction(&conn, &cx, |tx, cx| {
                    Box::pin(async move {
                        match tx
                            .execute(
                                cx,
                                "INSERT INTO tx_isolation_items(name) VALUES (?1)",
                                &[SqliteValue::Text("rolled_back".to_string())],
                            )
                            .await
                        {
                            Outcome::Ok(1) => {}
                            other => panic!("abort branch insert failed: {other:?}"),
                        }
                        Outcome::<(), SqliteError>::Err(SqliteError::Sqlite(
                            "metamorphic rollback branch".to_string(),
                        ))
                    })
                })
            };

            if abort_first {
                match run_abort().await {
                    Outcome::Err(SqliteError::Sqlite(message))
                        if message == "metamorphic rollback branch" => {}
                    other => panic!("abort-first branch should roll back: {other:?}"),
                }
                match run_commit().await {
                    Outcome::Ok(()) => {}
                    other => panic!("commit-after-abort branch failed: {other:?}"),
                }
            } else {
                match run_commit().await {
                    Outcome::Ok(()) => {}
                    other => panic!("commit-first branch failed: {other:?}"),
                }
                match run_abort().await {
                    Outcome::Err(SqliteError::Sqlite(message))
                        if message == "metamorphic rollback branch" => {}
                    other => panic!("abort-after-commit branch should roll back: {other:?}"),
                }
            }

            let rows = match conn
                .query(&cx, "SELECT name FROM tx_isolation_items ORDER BY id", &[])
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("final query failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| {
                    row.get_str("name")
                        .expect("name column should be present")
                        .to_string()
                })
                .collect::<Vec<_>>();
            conn.close().unwrap();
            names
        });

        let violations = runtime.oracles.check_all(runtime.now());
        assert!(
            violations.is_empty(),
            "sqlite transaction permutation should leave runtime invariants clean: {violations:?}"
        );

        rows
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn metamorphic_sqlite_commit_abort_isolation() {
        init_test("metamorphic_sqlite_commit_abort_isolation");

        let abort_then_commit = run_sqlite_commit_abort_isolation_permutation(true);
        let commit_then_abort = run_sqlite_commit_abort_isolation_permutation(false);

        assert_eq!(abort_then_commit, vec!["committed".to_string()]);
        assert_eq!(commit_then_abort, vec!["committed".to_string()]);
        assert_eq!(abort_then_commit, commit_then_abort);

        crate::test_complete!("metamorphic_sqlite_commit_abort_isolation");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_dropped_savepoint_refuses_commit() {
        init_test("with_sqlite_transaction_dropped_savepoint_refuses_commit");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_guard_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_guard_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer insert failed: {other:?}"),
                    }

                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    match savepoint
                        .transaction()
                        .execute(
                            cx,
                            "INSERT INTO savepoint_guard_items(name) VALUES (?1)",
                            &[SqliteValue::Text("inner".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("inner insert failed: {other:?}"),
                    }

                    drop(savepoint);
                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Err(SqliteError::Sqlite(msg)) => {
                    assert!(msg.contains("must roll back before commit"), "got: {msg}");
                }
                other => panic!("expected rollback-required error, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT COUNT(*) AS count FROM savepoint_guard_items",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("count query after dropped savepoint failed: {other:?}"),
            };

            let count = rows[0].get_i64("count").expect("count column");
            assert_eq!(count, 0, "dropped savepoint must prevent commit");
        });

        crate::test_complete!("with_sqlite_transaction_dropped_savepoint_refuses_commit");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_savepoint_rollback_discards_inner_changes() {
        init_test("with_sqlite_transaction_savepoint_rollback_discards_inner_changes");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_rollback_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_rollback_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer_before".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer_before insert failed: {other:?}"),
                    }

                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    match savepoint
                        .transaction()
                        .execute(
                            cx,
                            "INSERT INTO savepoint_rollback_items(name) VALUES (?1)",
                            &[SqliteValue::Text("inner".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("inner insert failed: {other:?}"),
                    }

                    match savepoint.rollback(cx).await {
                        Outcome::Ok(()) => {}
                        other => panic!("savepoint rollback failed: {other:?}"),
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_rollback_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer_after".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer_after insert failed: {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Ok(()) => {}
                other => panic!("expected outer transaction commit, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT name FROM savepoint_rollback_items ORDER BY id",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("query after rollback failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| row.get_str("name").expect("name column").to_string())
                .collect::<Vec<_>>();
            assert_eq!(
                names,
                vec!["outer_before".to_string(), "outer_after".to_string()]
            );
        });

        crate::test_complete!("with_sqlite_transaction_savepoint_rollback_discards_inner_changes");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_savepoint_rollback_removes_marker() {
        init_test("with_sqlite_transaction_savepoint_rollback_removes_marker");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_marker_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    match savepoint
                        .transaction()
                        .execute(
                            cx,
                            "INSERT INTO savepoint_marker_items(name) VALUES (?1)",
                            &[SqliteValue::Text("inner".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("inner insert failed: {other:?}"),
                    }

                    match savepoint.rollback(cx).await {
                        Outcome::Ok(()) => {}
                        other => panic!("savepoint rollback failed: {other:?}"),
                    }

                    match tx.execute_unchecked(cx, "RELEASE SAVEPOINT sp1", &[]).await {
                        Outcome::Err(SqliteError::Sqlite(msg)) => {
                            assert!(
                                msg.contains("no such savepoint")
                                    || msg.contains("no such savepoint: sp1"),
                                "expected missing-savepoint error, got: {msg}"
                            );
                        }
                        other => {
                            panic!("helper rollback must remove savepoint marker, got {other:?}")
                        }
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_marker_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer insert failed: {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Ok(()) => {}
                other => panic!("expected outer transaction commit, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT name FROM savepoint_marker_items ORDER BY id",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("query after rollback-marker check failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| row.get_str("name").expect("name column").to_string())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["outer".to_string()]);
        });

        crate::test_complete!("with_sqlite_transaction_savepoint_rollback_removes_marker");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_raw_outer_release_cascades_inner_savepoint() {
        init_test("with_sqlite_transaction_raw_outer_release_cascades_inner_savepoint");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                .execute(
                    &cx,
                    "CREATE TABLE savepoint_cascade_items (id INTEGER PRIMARY KEY, name TEXT)",
                    &[],
                )
                .await
            {
                Outcome::Ok(_) => {}
                other => panic!("schema setup failed: {other:?}"),
            }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx.execute_unchecked(cx, "SAVEPOINT outer_sp", &[]).await {
                        Outcome::Ok(_) => {}
                        other => panic!("outer savepoint create failed: {other:?}"),
                    }
                    match tx.execute_unchecked(cx, "SAVEPOINT inner_sp", &[]).await {
                        Outcome::Ok(_) => {}
                        other => panic!("inner savepoint create failed: {other:?}"),
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_cascade_items(name) VALUES (?1)",
                            &[SqliteValue::Text("nested".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("nested insert failed: {other:?}"),
                    }

                    match tx
                        .execute_unchecked(cx, "RELEASE SAVEPOINT outer_sp", &[])
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer release failed: {other:?}"),
                    }

                    match tx
                        .execute_unchecked(cx, "ROLLBACK TO SAVEPOINT inner_sp", &[])
                        .await
                    {
                        Outcome::Err(SqliteError::Sqlite(msg)) => {
                            assert!(
                                msg.contains("no such savepoint")
                                    || msg.contains("no such savepoint: inner_sp"),
                                "expected cascaded inner savepoint removal, got: {msg}"
                            );
                        }
                        other => panic!(
                            "releasing outer savepoint must cascade inner savepoint, got {other:?}"
                        ),
                    }

                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_cascade_items(name) VALUES (?1)",
                            &[SqliteValue::Text("after".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("post-cascade insert failed: {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Ok(()) => {}
                other => panic!("expected outer transaction commit, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT name FROM savepoint_cascade_items ORDER BY id",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("query after cascade failed: {other:?}"),
            };

            let names = rows
                .iter()
                .map(|row| row.get_str("name").expect("name column").to_string())
                .collect::<Vec<_>>();
            assert_eq!(names, vec!["nested".to_string(), "after".to_string()]);
        });

        crate::test_complete!("with_sqlite_transaction_raw_outer_release_cascades_inner_savepoint");
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn with_sqlite_transaction_cancelled_savepoint_release_poison_commit() {
        init_test("with_sqlite_transaction_cancelled_savepoint_release_poison_commit");

        let mut runtime = LabRuntimeTarget::create_runtime(TestConfig::default());
        LabRuntimeTarget::block_on(&mut runtime, async move {
            let cx = Cx::current().expect("lab runtime should install a current Cx");
            let conn = match SqliteConnection::open_in_memory(&cx).await {
                Outcome::Ok(conn) => conn,
                other => panic!("open_in_memory failed: {other:?}"),
            };

            match conn
                    .execute(
                        &cx,
                        "CREATE TABLE savepoint_release_cancel_items (id INTEGER PRIMARY KEY, name TEXT)",
                        &[],
                    )
                    .await
                {
                    Outcome::Ok(_) => {}
                    other => panic!("schema setup failed: {other:?}"),
                }

            let tx_outcome = with_sqlite_transaction(&conn, &cx, |tx, cx| {
                Box::pin(async move {
                    match tx
                        .execute(
                            cx,
                            "INSERT INTO savepoint_release_cancel_items(name) VALUES (?1)",
                            &[SqliteValue::Text("outer".to_string())],
                        )
                        .await
                    {
                        Outcome::Ok(_) => {}
                        other => panic!("outer insert failed: {other:?}"),
                    }

                    let savepoint = match SqliteSavepoint::new(tx, cx, "sp1").await {
                        Outcome::Ok(savepoint) => savepoint,
                        other => panic!("savepoint create failed: {other:?}"),
                    };

                    let cancelled = Cx::for_testing();
                    let expected = CancelReason::user("cancel savepoint release");
                    cancelled.set_cancel_reason(expected.clone());
                    match savepoint.release(&cancelled).await {
                        Outcome::Cancelled(reason) => assert_eq!(reason, expected),
                        other => panic!("expected cancelled savepoint release, got {other:?}"),
                    }

                    Outcome::Ok(())
                })
            })
            .await;

            match tx_outcome {
                Outcome::Err(SqliteError::Sqlite(msg)) => {
                    assert!(msg.contains("must roll back before commit"), "got: {msg}");
                }
                other => panic!("expected rollback-required error, got {other:?}"),
            }

            let rows = match conn
                .query(
                    &cx,
                    "SELECT COUNT(*) AS count FROM savepoint_release_cancel_items",
                    &[],
                )
                .await
            {
                Outcome::Ok(rows) => rows,
                other => panic!("count query after cancelled release failed: {other:?}"),
            };

            let count = rows[0].get_i64("count").expect("count column");
            assert_eq!(count, 0, "cancelled savepoint release must prevent commit");
        });

        crate::test_complete!("with_sqlite_transaction_cancelled_savepoint_release_poison_commit");
    }
}
