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

// ─── PostgreSQL helpers ──────────────────────────────────────────────────────

#[cfg(feature = "postgres")]
mod pg {
    use super::*;
    use crate::database::postgres::{PgConnection, PgError, PgTransaction};
    use std::fmt;

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
            Outcome::Ok(value) => match tx.commit(cx).await {
                Outcome::Ok(()) => Outcome::Ok(value),
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            },
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
    /// given [`RetryPolicy`]. Other errors are returned immediately.
    pub async fn with_pg_transaction_retry<T, F, MkFut>(
        conn: &mut PgConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        mut f: F,
    ) -> Outcome<T, PgError>
    where
        F: FnMut(&mut PgTransaction<'_>, &Cx) -> MkFut,
        MkFut: Future<Output = Outcome<T, PgError>>,
    {
        let mut attempt = 0u32;
        loop {
            let result = with_pg_transaction(conn, cx, &mut f).await;
            match &result {
                Outcome::Err(e) if e.is_serialization_failure() && attempt < policy.max_retries => {
                    attempt += 1;
                    let delay = policy.delay_for(attempt.saturating_sub(1));
                    if let Err(reason) = wait_retry_delay(cx, delay).await {
                        return Outcome::Cancelled(reason);
                    }
                    continue;
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
            match tx.execute(cx, &sql).await {
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
            self.released = true;
            let sql = format!("RELEASE SAVEPOINT {}", self.name);
            match self.tx.execute(cx, &sql).await {
                Outcome::Ok(_) => Outcome::Ok(()),
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
            self.released = true;
            let sql = format!("ROLLBACK TO SAVEPOINT {}", self.name);
            match self.tx.execute(cx, &sql).await {
                Outcome::Ok(_) => Outcome::Ok(()),
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
}

#[cfg(feature = "postgres")]
pub use pg::{PgSavepoint, with_pg_transaction, with_pg_transaction_retry};

// ─── SQLite helpers ──────────────────────────────────────────────────────────

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::{Cx, Future, Outcome, RetryPolicy, validate_savepoint_name, wait_retry_delay};
    use crate::database::sqlite::{SqliteConnection, SqliteError, SqliteTransaction};
    use std::fmt;

    /// Run a closure inside a SQLite transaction.
    ///
    /// See [`with_pg_transaction`](super::with_pg_transaction) for semantics.
    pub async fn with_sqlite_transaction<T, F, Fut>(
        conn: &SqliteConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, SqliteError>
    where
        F: FnOnce(&SqliteTransaction<'_>, &Cx) -> Fut,
        Fut: Future<Output = Outcome<T, SqliteError>>,
    {
        let tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&tx, cx).await;

        match result {
            Outcome::Ok(value) => match tx.commit(cx).await {
                Outcome::Ok(()) => Outcome::Ok(value),
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            },
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
    pub async fn with_sqlite_transaction_immediate<T, F, Fut>(
        conn: &SqliteConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, SqliteError>
    where
        F: FnOnce(&SqliteTransaction<'_>, &Cx) -> Fut,
        Fut: Future<Output = Outcome<T, SqliteError>>,
    {
        let tx = match conn.begin_immediate(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&tx, cx).await;

        match result {
            Outcome::Ok(value) => match tx.commit(cx).await {
                Outcome::Ok(()) => Outcome::Ok(value),
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            },
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
    /// given [`RetryPolicy`]. Other errors are returned immediately.
    ///
    /// For write-heavy workloads, prefer [`with_sqlite_transaction_immediate`]
    /// which acquires the write lock upfront to reduce contention.
    pub async fn with_sqlite_transaction_retry<T, F, MkFut>(
        conn: &SqliteConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        mut f: F,
    ) -> Outcome<T, SqliteError>
    where
        F: FnMut(&SqliteTransaction<'_>, &Cx) -> MkFut,
        MkFut: Future<Output = Outcome<T, SqliteError>>,
    {
        let mut attempt = 0u32;
        loop {
            let result = with_sqlite_transaction(conn, cx, &mut f).await;
            match &result {
                Outcome::Err(e)
                    if (e.is_busy() || e.is_locked()) && attempt < policy.max_retries =>
                {
                    attempt += 1;
                    let delay = policy.delay_for(attempt.saturating_sub(1));
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
            match tx.execute(cx, &sql, &[]).await {
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
            self.released = true;
            let sql = format!("RELEASE SAVEPOINT {}", self.name);
            match self.tx.execute(cx, &sql, &[]).await {
                Outcome::Ok(_) => Outcome::Ok(()),
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
            self.released = true;
            let sql = format!("ROLLBACK TO SAVEPOINT {}", self.name);
            match self.tx.execute(cx, &sql, &[]).await {
                Outcome::Ok(_) => Outcome::Ok(()),
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
}

#[cfg(feature = "sqlite")]
pub use sqlite::{
    SqliteSavepoint, with_sqlite_transaction, with_sqlite_transaction_immediate,
    with_sqlite_transaction_retry,
};

// ─── MySQL helpers ───────────────────────────────────────────────────────────

#[cfg(feature = "mysql")]
mod mysql {
    use super::*;
    use crate::database::mysql::{MySqlConnection, MySqlError, MySqlTransaction};
    use std::fmt;

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
            Outcome::Ok(value) => match tx.commit(cx).await {
                Outcome::Ok(()) => Outcome::Ok(value),
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            },
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
    /// according to the given [`RetryPolicy`]. Other errors are returned
    /// immediately.
    pub async fn with_mysql_transaction_retry<T, F, MkFut>(
        conn: &mut MySqlConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        mut f: F,
    ) -> Outcome<T, MySqlError>
    where
        F: FnMut(&mut MySqlTransaction<'_>, &Cx) -> MkFut,
        MkFut: Future<Output = Outcome<T, MySqlError>>,
    {
        let mut attempt = 0u32;
        loop {
            let result = with_mysql_transaction(conn, cx, &mut f).await;
            match &result {
                Outcome::Err(e) if e.is_deadlock() && attempt < policy.max_retries => {
                    attempt += 1;
                    let delay = policy.delay_for(attempt.saturating_sub(1));
                    if let Err(reason) = wait_retry_delay(cx, delay).await {
                        return Outcome::Cancelled(reason);
                    }
                    continue;
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
            match tx.execute(cx, &sql).await {
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
            self.released = true;
            let sql = format!("RELEASE SAVEPOINT {}", self.name);
            match self.tx.execute(cx, &sql).await {
                Outcome::Ok(_) => Outcome::Ok(()),
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
            self.released = true;
            let sql = format!("ROLLBACK TO SAVEPOINT {}", self.name);
            match self.tx.execute(cx, &sql).await {
                Outcome::Ok(_) => Outcome::Ok(()),
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
}

#[cfg(feature = "mysql")]
pub use mysql::{MySqlSavepoint, with_mysql_transaction, with_mysql_transaction_retry};

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct NoopWaker;

    impl Wake for NoopWaker {
        fn wake(self: Arc<Self>) {}
    }

    fn noop_waker() -> Waker {
        Waker::from(Arc::new(NoopWaker))
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
}
