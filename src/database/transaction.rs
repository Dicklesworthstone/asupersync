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

#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql", test))]
pub(crate) fn trace_database_transaction(
    cx: &Cx,
    backend: &'static str,
    operation: &'static str,
    outcome: &'static str,
) {
    cx.trace_with_fields(
        "database.transaction.lifecycle",
        &[
            ("component", "database"),
            ("resource", "transaction"),
            ("backend", backend),
            ("operation", operation),
            ("outcome", outcome),
        ],
    );
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

// Test-only helper: every caller drives this to completion with
// `futures_lite::future::block_on` on a single thread, so the future is never
// sent anywhere. Adding `Send` bounds to `Op`/`OpFut`/`Pred` would constrain
// test closures (which may capture non-`Send` counters) to buy a property no
// caller needs, so the bound is deliberately absent and the nursery lint is
// scoped off here rather than satisfied.
#[cfg(test)]
#[allow(clippy::future_not_send)]
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

    const HELPER_ROLLBACK_MASKED_POLLS: u32 = 1024;

    fn rollback_required_error() -> PgError {
        PgError::Protocol("transaction must roll back before commit".to_string())
    }

    /// Roll back before propagating the body's outcome, with cancellation
    /// masked for a bounded number of polls as in the SQLite helper. The body
    /// may have cancelled `cx`; `rollback` then stopped at its first
    /// checkpoint and sent nothing, so the transaction and its locks stayed
    /// open until the connection's next operation.
    async fn rollback_before_propagating(tx: PgTransaction<'_>, cx: &Cx) {
        let _ =
            crate::combinator::commit_section(cx, HELPER_ROLLBACK_MASKED_POLLS, tx.rollback(cx))
                .await;
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
                let rollback_required = tx.requires_rollback_before_commit();
                if rollback_required || cx.checkpoint().is_err() {
                    rollback_before_propagating(tx, cx).await;
                    return if rollback_required {
                        Outcome::Err(rollback_required_error())
                    } else {
                        Outcome::Cancelled(cancelled_before_commit(cx))
                    };
                }
                tx.commit(cx).await.map(|()| value)
            }
            Outcome::Err(e) => {
                // Best-effort rollback; drop will handle it if this fails.
                rollback_before_propagating(tx, cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                rollback_before_propagating(tx, cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                rollback_before_propagating(tx, cx).await;
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

    /// A Cx cancelled while the body finished refuses the commit, and
    /// dropping the transaction would only schedule its rollback for the
    /// connection's next operation, so `with_pg_transaction` finishes that
    /// rollback first and reports this reason
    /// (br-asupersync-sqlite-pool-audit-r10-dj4uhx L4).
    fn cancelled_before_commit(cx: &Cx) -> crate::types::CancelReason {
        cx.cancel_reason()
            .unwrap_or_else(|| crate::types::CancelReason::user("cancelled"))
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

    const HELPER_ROLLBACK_MASKED_POLLS: u32 = 1024;

    fn rollback_required_error() -> SqliteError {
        SqliteError::Sqlite("transaction must roll back before commit".to_string())
    }

    /// Finish helper-owned rollback before propagating the body outcome.
    ///
    /// The body may have cancelled `cx`, so polling `rollback` normally would
    /// reject the operation at its first checkpoint and leave physical cleanup
    /// to `SqliteTransaction::drop`. A transaction helper must not return while
    /// that best-effort cleanup can still own SQLite's write transaction. Mask
    /// cancellation only for a bounded number of polls; `rollback` retains its
    /// ordinary error/cancellation tracing, while the caller preserves the
    /// body's original outcome.
    async fn rollback_before_propagating(tx: SqliteTransaction<'_>, cx: &Cx) {
        let _ =
            crate::combinator::commit_section(cx, HELPER_ROLLBACK_MASKED_POLLS, tx.rollback(cx))
                .await;
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
                    rollback_before_propagating(tx, cx).await;
                    return Outcome::Err(rollback_required_error());
                }
                // A Cx cancelled while the body finished refuses the commit,
                // and dropping the transaction would only schedule its
                // rollback: finish that rollback before returning.
                if cx.checkpoint().is_err() {
                    rollback_before_propagating(tx, cx).await;
                    return Outcome::Cancelled(
                        cx.cancel_reason()
                            .unwrap_or_else(|| crate::types::CancelReason::user("cancelled")),
                    );
                }
                match tx.commit(cx).await {
                    Outcome::Ok(()) => Outcome::Ok(value),
                    Outcome::Err(e) => Outcome::Err(e),
                    Outcome::Cancelled(r) => Outcome::Cancelled(r),
                    Outcome::Panicked(p) => Outcome::Panicked(p),
                }
            }
            Outcome::Err(e) => {
                rollback_before_propagating(tx, cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                rollback_before_propagating(tx, cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                rollback_before_propagating(tx, cx).await;
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
                    rollback_before_propagating(tx, cx).await;
                    return Outcome::Err(rollback_required_error());
                }
                // A Cx cancelled while the body finished refuses the commit,
                // and dropping the transaction would only schedule its
                // rollback: finish that rollback before returning.
                if cx.checkpoint().is_err() {
                    rollback_before_propagating(tx, cx).await;
                    return Outcome::Cancelled(
                        cx.cancel_reason()
                            .unwrap_or_else(|| crate::types::CancelReason::user("cancelled")),
                    );
                }
                match tx.commit(cx).await {
                    Outcome::Ok(()) => Outcome::Ok(value),
                    Outcome::Err(e) => Outcome::Err(e),
                    Outcome::Cancelled(r) => Outcome::Cancelled(r),
                    Outcome::Panicked(p) => Outcome::Panicked(p),
                }
            }
            Outcome::Err(e) => {
                rollback_before_propagating(tx, cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                rollback_before_propagating(tx, cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                rollback_before_propagating(tx, cx).await;
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

    const HELPER_ROLLBACK_MASKED_POLLS: u32 = 1024;

    fn rollback_required_error() -> MySqlError {
        MySqlError::Protocol("transaction must roll back before commit".to_string())
    }

    /// Roll back with cancellation masked for a bounded number of polls; see
    /// the PostgreSQL helper.
    async fn rollback_before_propagating(tx: MySqlTransaction<'_>, cx: &Cx) {
        let _ =
            crate::combinator::commit_section(cx, HELPER_ROLLBACK_MASKED_POLLS, tx.rollback(cx))
                .await;
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
                let rollback_required = tx.requires_rollback_before_commit();
                if rollback_required || cx.checkpoint().is_err() {
                    rollback_before_propagating(tx, cx).await;
                    return if rollback_required {
                        Outcome::Err(rollback_required_error())
                    } else {
                        Outcome::Cancelled(cancelled_before_commit(cx))
                    };
                }
                tx.commit(cx).await.map(|()| value)
            }
            Outcome::Err(e) => {
                rollback_before_propagating(tx, cx).await;
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                rollback_before_propagating(tx, cx).await;
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                rollback_before_propagating(tx, cx).await;
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

    /// A Cx cancelled while the body finished refuses the commit, and
    /// dropping the transaction would only schedule its rollback, so
    /// `with_mysql_transaction` finishes that rollback first and reports this
    /// reason (br-asupersync-sqlite-pool-audit-r10-dj4uhx L4).
    fn cancelled_before_commit(cx: &Cx) -> crate::types::CancelReason {
        cx.cancel_reason()
            .unwrap_or_else(|| crate::types::CancelReason::user("cancelled"))
    }
}

#[cfg(feature = "mysql")]
pub use mysql::{MySqlSavepoint, with_mysql_transaction, with_mysql_transaction_retry};

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "transaction_inline_tests.rs"]
mod tests;
