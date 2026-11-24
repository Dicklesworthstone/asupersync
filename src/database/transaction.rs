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
//! - [`with_pg_transaction_borrowed`] / [`with_mysql_transaction_borrowed`]:
//!   Borrow the transaction and context across awaits
//! - [`with_pg_transaction_with_state`] / [`with_mysql_transaction_with_state`]:
//!   Lend caller-owned SQL, parameters, and mutable state across awaits
//! - [`with_sqlite_transaction_with_state`] / [`with_sqlite_transaction_immediate_with_state`]:
//!   Lend caller-owned state to a deferred or immediate SQLite transaction
//! - [`with_pg_transaction_retry`]: PostgreSQL retry on serialization failure (40001)
//! - [`with_mysql_transaction_retry`]: MySQL retry on deadlock (1213/1205)
//! - [`with_pg_transaction_retry_borrowed`] / [`with_mysql_transaction_retry_borrowed`]:
//!   Retry borrowing callbacks with explicit replay safety
//! - [`with_pg_transaction_retry_with_state`] / [`with_mysql_transaction_retry_with_state`]:
//!   Retry callbacks while lending caller-owned state to each attempt
//! - [`with_sqlite_transaction_retry`]: SQLite retry on SQLITE_BUSY/SQLITE_LOCKED
//! - [`with_sqlite_transaction_retry_with_state`]: Retry while lending SQLite caller state
//! - [`PgSavepoint`] / [`SqliteSavepoint`] / [`MySqlSavepoint`]: Nested savepoints
//! - [`RetryPolicy`]: Configurable retry with exponential backoff
//! - [`TransactionReplaySafety`]: Explicit opt-in for replaying user closures
//! - [`ScopedTransactionFuture`]: A `Send` callback future with one borrow lifetime
//!
//! All helpers integrate with [`Cx`] for cancellation. On `Outcome::Err` or
//! `Outcome::Cancelled`, the transaction is rolled back. On `Outcome::Ok`,
//! it is committed.
//!
//! # Borrowing and cleanup
//!
//! Prefer the `with_state` helpers when an async body needs caller-owned
//! references. Pass a struct, tuple, slice, or the value itself as `&mut S`;
//! each invocation borrows the state, transaction, and context together.
//! Neither the state nor its contents need to be cloned or `'static`.
//! Mutable state only needs `Send`, not `Sync`. A result may contain an
//! existing reference stored in the state, but cannot retain the callback's
//! temporary borrow of the state or transaction.
//!
//! Retrying reborrows the same state. Database rollback does not undo changes
//! to caller memory or external effects, including changes from a failed
//! commit. Replay therefore requires [`TransactionReplaySafety::ReplaySafe`]
//! after the body starts; begin-time failures may retry without that opt-in.
//!
//! Await the helper to completion to let it finalize the transaction. An
//! `Outcome::Panicked` value follows the rollback path, while an unwinding
//! Rust panic or a dropped helper runs the backend's transaction `Drop`
//! recovery instead. Drop cannot await rollback. Explicit rollback is also
//! best effort under bounded cancellation masking: a failed rollback or
//! commit leaves recovery/discard to the backend's connection lifecycle.
//! These helpers do not promise successful physical rollback after transport
//! failure, or resolve an uncertain server commit after a lost response.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "postgres")]
//! # async fn example(
//! #     conn: &mut asupersync::database::PgConnection,
//! #     cx: &asupersync::Cx,
//! # ) -> asupersync::Outcome<u64, asupersync::database::PgError> {
//! use asupersync::database::transaction::{ScopedTransactionFuture, with_pg_transaction_with_state};
//!
//! let sql = String::from("UPDATE accounts SET balance = balance + 100 WHERE id = 2");
//! let mut state = sql.as_str();
//! with_pg_transaction_with_state(conn, cx, &mut state, |tx, cx, sql| {
//!     ScopedTransactionFuture::new(async move {
//!         // The transaction and caller-owned SQL are borrowed across await.
//!         tx.execute_unchecked(cx, *sql).await
//!     })
//! }).await
//! # }
//! ```
//!
//! [`Cx`]: crate::cx::Cx
//! [`PgTransaction`]: super::PgTransaction
//! [`SqliteTransaction`]: super::SqliteTransaction
//! [`MySqlTransaction`]: super::MySqlTransaction

use crate::channel::OwnedCancelRegistration;
use crate::cx::Cx;
use crate::time::{Sleep, SleepError, raw_wall_now, sleep_cx};
use crate::types::{CancelReason, Outcome};
use std::future::{Future, poll_fn};
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;

/// A boxed transaction callback future, retaining its original lifetime parameters.
///
/// Construct this with [`TransactionFuture::new`] around an `async move`
/// block. `'borrow` is the current transaction borrow; `'env` records an
/// environment that outlives that borrow. The boxed future is always `Send`.
///
/// At a higher-ranked callback boundary, an independently captured reference
/// is not tied to the callback's transaction borrow. Use the `with_state`
/// helpers to lend non-`'static` SQL, parameters, or mutable state explicitly.
/// Prefer [`ScopedTransactionFuture`] for those helpers: it names the same
/// type with a single invocation lifetime. This two-lifetime spelling remains
/// available for existing callbacks and type annotations; the environment
/// marker does not make independently captured references work under a
/// higher-ranked callback bound.
#[must_use = "transaction callback futures do nothing unless polled"]
pub struct TransactionFuture<'env, 'borrow, T, E> {
    future: Pin<Box<dyn Future<Output = Outcome<T, E>> + Send + 'borrow>>,
    // Preserve the existing environment marker. State-taking helpers use
    // the same lifetime for both parameters; their explicit state argument
    // establishes which caller data outlives the current transaction borrow.
    _capture_lifetime: PhantomData<&'borrow &'env ()>,
}

impl<T, E> std::fmt::Debug for TransactionFuture<'_, '_, T, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionFuture").finish_non_exhaustive()
    }
}

impl<'borrow, T, E> TransactionFuture<'_, 'borrow, T, E> {
    /// Box a callback future without requiring its captures to be `'static`.
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = Outcome<T, E>> + Send + 'borrow,
    {
        Self {
            future: Box::pin(future),
            _capture_lifetime: PhantomData,
        }
    }
}

impl<T, E> Future for TransactionFuture<'_, '_, T, E> {
    type Output = Outcome<T, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        self.get_mut().future.as_mut().poll(cx)
    }
}

/// A `Send` transaction callback future borrowing one invocation's inputs.
///
/// Use `ScopedTransactionFuture::new(async move { ... })` with any
/// `with_state` helper. The transaction, context, and caller state all share
/// `'borrow`, so borrowed SQL, parameters, and mutable state can cross awaits
/// without cloning. `T` may contain references with a lifetime independent of
/// this temporary borrow, such as an existing `&str` stored in the state.
///
/// This alias is exactly [`TransactionFuture`] with both lifetime parameters
/// equal. Existing `TransactionFuture::new` callbacks remain interchangeable;
/// there is no extra allocation, conversion, or new runtime dependency.
///
/// A future that retains non-`Send` data across an await is rejected, even
/// if the closure constructing it is itself `Send`:
///
/// ```compile_fail
/// use asupersync::Outcome;
/// use asupersync::database::transaction::ScopedTransactionFuture;
/// let _ = ScopedTransactionFuture::new(async {
///     let local = std::rc::Rc::new(1);
///     std::future::pending::<()>().await;
///     Outcome::<_, ()>::Ok(*local)
/// });
/// ```
pub type ScopedTransactionFuture<'borrow, T, E> = TransactionFuture<'borrow, 'borrow, T, E>;

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

fn retry_checkpoint(cx: &Cx) -> Result<(), CancelReason> {
    // A driverless Cx's checkpoint falls back through wall_now(), which can
    // otherwise adopt the polling task's unrelated virtual clock. The guard
    // covers only this synchronous check, never an await or a future poll.
    let _owner_clock = (!cx.has_timer()).then(|| Cx::set_current(Some(cx.clone())));
    cx.checkpoint().map_err(|_| cancelled_reason(cx))
}

pub(super) async fn wait_retry_delay(cx: &Cx, delay: Duration) -> Result<(), CancelReason> {
    if delay.is_zero() {
        retry_checkpoint(cx)?;
        crate::runtime::yield_now().await;
        return retry_checkpoint(cx);
    }

    // The explicit owner may differ from the task polling this helper. Use
    // its timer and cancellation subscription, including masked requests and
    // owner deadlines, instead of adopting the ambient task's clock or wakes.
    if cx.has_timer() {
        match sleep_cx(cx, delay).await {
            Ok(()) => return Ok(()),
            // Preserve this helper's default reason when legacy callers publish
            // cancellation without an attribution payload.
            Err(SleepError::Cancelled(_)) => return Err(cancelled_reason(cx)),
            Err(SleepError::TimerUnavailable) => {}
        }
    }

    // Driverless callers have historically been allowed to retry. Preserve
    // that wall-clock fallback, but bind it before polling under another Cx.
    // Keep the registration through a masked request so unmasking can wake
    // this wait; a fused Cx::cancelled() observer would unregister too soon.
    retry_checkpoint(cx)?;
    let mut sleeper = Sleep::with_wall_clock(raw_wall_now() + delay);
    let mut cancellation = OwnedCancelRegistration::new(cx.clone());
    let mut owner_deadline = cx.budget_deadline_sleep();
    poll_fn(|task_cx| {
        cancellation.refresh(task_cx.waker());
        if owner_deadline
            .as_mut()
            .is_some_and(|deadline| Pin::new(deadline).poll_deadline(task_cx).is_ready())
        {
            // Keep the cancel subscription after an expired masked deadline,
            // but never poll the completed timer again or spin on its expiry.
            owner_deadline = None;
        }
        if let Err(reason) = retry_checkpoint(cx) {
            return Poll::Ready(Err(reason));
        }
        if Pin::new(&mut sleeper).poll_deadline(task_cx).is_pending() {
            return Poll::Pending;
        }
        Poll::Ready(retry_checkpoint(cx))
    })
    .await
}

/// Apply the same replay gate and backoff to both callback forms. Taking the
/// error classification rather than an outcome avoids retaining a shared
/// reference to the caller's result across the delay.
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
async fn retry_after_error(
    cx: &Cx,
    policy: &RetryPolicy,
    replay_safety: TransactionReplaySafety,
    body_started: bool,
    is_retryable: bool,
    attempt: &mut u32,
) -> Result<bool, CancelReason> {
    if !is_retryable
        || (body_started && replay_safety == TransactionReplaySafety::ReplayUnsafe)
        || *attempt >= policy.max_retries
    {
        return Ok(false);
    }

    let delay = policy.delay_for(*attempt);
    *attempt += 1;
    wait_retry_delay(cx, delay).await?;
    Ok(true)
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
        Cx, Future, Outcome, RetryPolicy, ScopedTransactionFuture, TransactionFuture,
        TransactionReplaySafety, retry_after_error, validate_savepoint_name,
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

    /// All callback forms use this finalizer so cancellation, poisoned
    /// savepoints, and rollback preserve exactly the same outcome semantics.
    async fn finish_transaction<T>(
        tx: PgTransaction<'_>,
        cx: &Cx,
        result: Outcome<T, PgError>,
    ) -> Outcome<T, PgError> {
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

    /// Run a closure inside a PostgreSQL transaction.
    ///
    /// The closure receives a mutable reference to the active transaction and
    /// a `&Cx`. If the closure returns `Outcome::Ok(value)`, the transaction
    /// is committed and the value is returned. On `Outcome::Err` or
    /// `Outcome::Cancelled`, the transaction is rolled back.
    ///
    /// Use [`with_pg_transaction_borrowed`] when the callback awaits operations
    /// that borrow the transaction or its context.
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
        finish_transaction(tx, cx, result).await
    }

    /// Run a borrowing callback inside a PostgreSQL transaction.
    ///
    /// Return [`TransactionFuture::new`] around an `async move` block to await
    /// queries using the supplied transaction and context. To borrow caller-
    /// owned SQL, parameters, or other non-`'static` data across those awaits,
    /// use [`with_pg_transaction_with_state`]. Its explicit state argument
    /// ties those borrows to each callback invocation.
    ///
    /// Commit, cancellation, rollback, and `Outcome::Panicked` propagation
    /// have the same semantics as [`with_pg_transaction`]. The callback runs
    /// only after `BEGIN` succeeds. A successful body is committed only if
    /// the context is still active and the transaction does not require
    /// rollback.
    ///
    /// Both callback and future are `Send`, so the helper can be awaited by
    /// tasks running on native worker threads.
    pub async fn with_pg_transaction_borrowed<'env, T, F>(
        conn: &mut PgConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, PgError>
    where
        T: Send + 'env,
        F: for<'a, 'tx> FnOnce(
                &'a mut PgTransaction<'tx>,
                &'a Cx,
            ) -> TransactionFuture<'env, 'a, T, PgError>
            + Send
            + 'env,
    {
        let mut tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&mut tx, cx).await;
        finish_transaction(tx, cx, result).await
    }

    /// Run a PostgreSQL transaction while lending caller-owned state.
    ///
    /// `state` may contain non-`'static` references to SQL, parameters, or
    /// mutable caller data. The callback receives the state, transaction,
    /// and context under one borrow and can use all three across awaits.
    /// Return [`ScopedTransactionFuture::new`] around the callback's async
    /// block. `S` needs neither `Clone`, `Sync`, nor `'static` and may be
    /// unsized, for example a borrowed parameter slice.
    ///
    /// Commit, cancellation, rollback, and `Outcome::Panicked` handling are
    /// identical to [`with_pg_transaction`]. The callback runs only after
    /// `BEGIN` succeeds. Both callback and future are `Send`.
    ///
    /// An existing reference stored in the state can be returned without a copy:
    ///
    /// ```no_run
    /// use asupersync::{Cx, Outcome};
    /// use asupersync::database::{PgConnection, PgError};
    /// use asupersync::database::transaction::{ScopedTransactionFuture, with_pg_transaction_with_state};
    /// async fn update<'env>(conn: &mut PgConnection, cx: &Cx, sql: &'env str)
    ///     -> Outcome<&'env str, PgError>
    /// {
    ///     let mut state = (sql, 0usize);
    ///     with_pg_transaction_with_state(conn, cx, &mut state, |tx, cx, state| {
    ///         ScopedTransactionFuture::new(async move {
    ///             let result = tx.execute_unchecked(cx, state.0).await;
    ///             state.1 += 1;
    ///             result.map(|_| state.0)
    ///         })
    ///     }).await
    /// }
    /// ```
    ///
    /// The temporary transaction borrow cannot escape finalization:
    ///
    /// ```compile_fail
    /// use asupersync::{Cx, Outcome};
    /// use asupersync::database::PgConnection;
    /// use asupersync::database::transaction::{ScopedTransactionFuture, with_pg_transaction_with_state};
    /// async fn escape(conn: &mut PgConnection, cx: &Cx) {
    ///     let mut state = ();
    ///     let _ = with_pg_transaction_with_state(conn, cx, &mut state, |tx, _, _| {
    ///         ScopedTransactionFuture::new(async move { Outcome::Ok(tx) })
    ///     }).await;
    /// }
    /// ```
    ///
    /// Nor can the invocation's mutable state borrow be returned:
    ///
    /// ```compile_fail
    /// use asupersync::{Cx, Outcome};
    /// use asupersync::database::PgConnection;
    /// use asupersync::database::transaction::{ScopedTransactionFuture, with_pg_transaction_with_state};
    /// async fn escape(conn: &mut PgConnection, cx: &Cx) {
    ///     let mut state = String::from("caller-owned");
    ///     let _ = with_pg_transaction_with_state(conn, cx, &mut state, |_, _, state| {
    ///         ScopedTransactionFuture::new(async move { Outcome::Ok(state.as_str()) })
    ///     }).await;
    /// }
    /// ```
    pub async fn with_pg_transaction_with_state<T, S, F>(
        conn: &mut PgConnection,
        cx: &Cx,
        state: &mut S,
        f: F,
    ) -> Outcome<T, PgError>
    where
        T: Send,
        S: Send + ?Sized,
        F: for<'a, 'tx> FnOnce(
                &'a mut PgTransaction<'tx>,
                &'a Cx,
                &'a mut S,
            ) -> ScopedTransactionFuture<'a, T, PgError>
            + Send,
    {
        let mut tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&mut tx, cx, state).await;
        finish_transaction(tx, cx, result).await
    }

    /// Run a closure inside a PostgreSQL transaction with retry on
    /// serialization failure.
    ///
    /// Serialization failures (SQLSTATE `40001`) are retried according to the
    /// given [`RetryPolicy`]. Pass [`TransactionReplaySafety::ReplaySafe`] only
    /// when rerunning the closure cannot duplicate externally visible side
    /// effects. Other errors are returned immediately.
    ///
    /// Use [`with_pg_transaction_retry_borrowed`] for a borrowing callback.
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

            let is_retryable =
                matches!(&result, Outcome::Err(err) if err.is_serialization_failure());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started.load(Ordering::Relaxed),
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
            }
        }
    }

    /// Run a borrowing callback with retry on PostgreSQL serialization
    /// failures (SQLSTATE `40001`).
    ///
    /// Return [`TransactionFuture::new`] around each attempt's `async move`
    /// block. Each attempt receives a fresh transaction. Failed attempts
    /// complete the helper's rollback handling before the next `BEGIN`.
    ///
    /// The callback is `FnMut`: it may update a captured attempt counter
    /// before returning its future. To borrow caller-owned SQL, parameters,
    /// or mutable state across awaits, use
    /// [`with_pg_transaction_retry_with_state`].
    ///
    /// [`TransactionReplaySafety::ReplayUnsafe`] permits retry only when
    /// `BEGIN` failed before the callback started. Opt into
    /// [`TransactionReplaySafety::ReplaySafe`] only if repeating the body,
    /// including its captured-state changes, cannot duplicate externally
    /// visible effects. Commit-time serialization failures can also replay
    /// the body. Other outcomes return immediately, and backoff observes
    /// cancellation through the supplied context.
    pub async fn with_pg_transaction_retry_borrowed<'env, T, F>(
        conn: &mut PgConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        mut f: F,
    ) -> Outcome<T, PgError>
    where
        T: Send + 'env,
        F: for<'a, 'tx> FnMut(
                &'a mut PgTransaction<'tx>,
                &'a Cx,
            ) -> TransactionFuture<'env, 'a, T, PgError>
            + Send
            + 'env,
    {
        let mut attempt = 0u32;
        loop {
            let mut body_started = false;
            let result = match conn.begin(cx).await {
                Outcome::Ok(mut tx) => {
                    body_started = true;
                    let result = f(&mut tx, cx).await;
                    finish_transaction(tx, cx, result).await
                }
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            };

            let is_retryable =
                matches!(&result, Outcome::Err(err) if err.is_serialization_failure());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started,
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
            }
        }
    }

    /// Retry PostgreSQL transactions while lending state to each attempt.
    ///
    /// The callback can borrow and mutate `state` across awaits, including
    /// references stored inside it. Each attempt reborrows the same state
    /// after the previous transaction has completed its rollback handling.
    /// Changes to caller state are not rolled back with the database.
    ///
    /// Retry classification, backoff cancellation, and replay safety follow
    /// [`with_pg_transaction_retry_borrowed`]. `ReplayUnsafe` retries only
    /// before the body starts; `ReplaySafe` also permits replay after body
    /// execution or a retryable commit error.
    pub async fn with_pg_transaction_retry_with_state<T, S, F>(
        conn: &mut PgConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        state: &mut S,
        mut f: F,
    ) -> Outcome<T, PgError>
    where
        T: Send,
        S: Send + ?Sized,
        F: for<'a, 'tx> FnMut(
                &'a mut PgTransaction<'tx>,
                &'a Cx,
                &'a mut S,
            ) -> ScopedTransactionFuture<'a, T, PgError>
            + Send,
    {
        let mut attempt = 0u32;
        loop {
            let mut body_started = false;
            let result = with_pg_transaction_with_state(conn, cx, state, |tx, tx_cx, state| {
                body_started = true;
                f(tx, tx_cx, state)
            })
            .await;
            let is_retryable =
                matches!(&result, Outcome::Err(err) if err.is_serialization_failure());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started,
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
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
pub use pg::{
    PgSavepoint, with_pg_transaction, with_pg_transaction_borrowed, with_pg_transaction_retry,
    with_pg_transaction_retry_borrowed, with_pg_transaction_retry_with_state,
    with_pg_transaction_with_state,
};

// ─── SQLite helpers ──────────────────────────────────────────────────────────

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::{
        Cx, Future, Outcome, RetryPolicy, ScopedTransactionFuture, TransactionReplaySafety,
        retry_after_error, validate_savepoint_name,
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

    /// Every callback and BEGIN mode shares the same finalization path.
    async fn finish_transaction<T>(
        tx: SqliteTransaction<'_>,
        cx: &Cx,
        result: Outcome<T, SqliteError>,
    ) -> Outcome<T, SqliteError> {
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

    /// Run a closure inside a SQLite transaction.
    ///
    /// See [`with_pg_transaction`](super::with_pg_transaction) for semantics.
    /// Use [`with_sqlite_transaction_with_state`] to borrow caller-owned
    /// SQL, parameters, or mutable state across awaits.
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
        finish_transaction(tx, cx, result).await
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
        finish_transaction(tx, cx, result).await
    }

    /// Run a deferred SQLite transaction while lending caller-owned state.
    ///
    /// The callback borrows the transaction, context, and `state` for the
    /// same invocation lifetime. SQL and parameters may refer to local data;
    /// neither `S` nor its contents need `Clone`, `Sync`, or `'static`.
    /// `S` can also be unsized, such as a parameter slice.
    ///
    /// The callback runs only after `BEGIN` succeeds. Commit, precommit
    /// cancellation checks, and rollback are identical to
    /// [`with_sqlite_transaction`]. SQLite transactions use shared references
    /// because their operations serialize access through the connection.
    ///
    /// ```no_run
    /// use asupersync::{Cx, Outcome};
    /// use asupersync::database::{SqliteConnection, SqliteError, SqliteValue};
    /// use asupersync::database::transaction::{ScopedTransactionFuture, with_sqlite_transaction_with_state};
    /// async fn update(conn: &SqliteConnection, cx: &Cx) -> Outcome<u64, SqliteError> {
    ///     let sql = String::from("UPDATE accounts SET balance = balance + ?1");
    ///     let parameters = [SqliteValue::Integer(100)];
    ///     let mut calls = 0;
    ///     let mut state = (sql.as_str(), parameters.as_slice(), &mut calls);
    ///     with_sqlite_transaction_with_state(conn, cx, &mut state, |tx, cx, state| {
    ///         ScopedTransactionFuture::new(async move {
    ///             let result = tx.execute(cx, state.0, state.1).await;
    ///             *state.2 += 1;
    ///             result
    ///         })
    ///     }).await
    /// }
    /// ```
    pub async fn with_sqlite_transaction_with_state<T, S, F>(
        conn: &SqliteConnection,
        cx: &Cx,
        state: &mut S,
        f: F,
    ) -> Outcome<T, SqliteError>
    where
        T: Send,
        S: Send + ?Sized,
        F: for<'a, 'tx> FnOnce(
                &'a SqliteTransaction<'tx>,
                &'a Cx,
                &'a mut S,
            ) -> ScopedTransactionFuture<'a, T, SqliteError>
            + Send,
    {
        let tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&tx, cx, state).await;
        finish_transaction(tx, cx, result).await
    }

    /// Lend caller-owned state to a SQLite IMMEDIATE transaction.
    ///
    /// This has the borrowing and cleanup semantics of
    /// [`with_sqlite_transaction_with_state`], but acquires the write lock
    /// before invoking the callback, as [`with_sqlite_transaction_immediate`]
    /// does. A refused `BEGIN IMMEDIATE` leaves caller state untouched.
    pub async fn with_sqlite_transaction_immediate_with_state<T, S, F>(
        conn: &SqliteConnection,
        cx: &Cx,
        state: &mut S,
        f: F,
    ) -> Outcome<T, SqliteError>
    where
        T: Send,
        S: Send + ?Sized,
        F: for<'a, 'tx> FnOnce(
                &'a SqliteTransaction<'tx>,
                &'a Cx,
                &'a mut S,
            ) -> ScopedTransactionFuture<'a, T, SqliteError>
            + Send,
    {
        let tx = match conn.begin_immediate(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&tx, cx, state).await;
        finish_transaction(tx, cx, result).await
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

            let is_retryable =
                matches!(&result, Outcome::Err(err) if err.is_busy() || err.is_locked());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started.load(Ordering::Relaxed),
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
            }
        }
    }

    /// Retry deferred SQLite transactions while lending state to each attempt.
    ///
    /// Retries `SQLITE_BUSY` / `SQLITE_LOCKED` under the same policy as
    /// [`with_sqlite_transaction_retry`]. Each attempt reborrows the same
    /// state after the previous attempt's finalization; the callback never
    /// runs when `BEGIN` fails. Caller-memory changes are not rolled back.
    /// `ReplayUnsafe` permits begin-time retries only. `ReplaySafe` also
    /// permits replay after the body starts, including a retryable commit
    /// error. Backoff observes cancellation through the supplied context.
    pub async fn with_sqlite_transaction_retry_with_state<T, S, F>(
        conn: &SqliteConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        state: &mut S,
        mut f: F,
    ) -> Outcome<T, SqliteError>
    where
        T: Send,
        S: Send + ?Sized,
        F: for<'a, 'tx> FnMut(
                &'a SqliteTransaction<'tx>,
                &'a Cx,
                &'a mut S,
            ) -> ScopedTransactionFuture<'a, T, SqliteError>
            + Send,
    {
        let mut attempt = 0u32;
        loop {
            let mut body_started = false;
            let result = with_sqlite_transaction_with_state(conn, cx, state, |tx, tx_cx, state| {
                body_started = true;
                f(tx, tx_cx, state)
            })
            .await;
            let is_retryable =
                matches!(&result, Outcome::Err(err) if err.is_busy() || err.is_locked());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started,
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
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
    with_sqlite_transaction_immediate_with_state, with_sqlite_transaction_retry,
    with_sqlite_transaction_retry_with_state, with_sqlite_transaction_with_state,
};

// ─── MySQL helpers ───────────────────────────────────────────────────────────

#[cfg(feature = "mysql")]
mod mysql {
    use super::{
        Cx, Future, Outcome, RetryPolicy, ScopedTransactionFuture, TransactionFuture,
        TransactionReplaySafety, retry_after_error, validate_savepoint_name,
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

    /// Keep both callback forms on the same commit and rollback path.
    async fn finish_transaction<T>(
        tx: MySqlTransaction<'_>,
        cx: &Cx,
        result: Outcome<T, MySqlError>,
    ) -> Outcome<T, MySqlError> {
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

    /// Run a closure inside a MySQL transaction.
    ///
    /// See [`with_pg_transaction`](super::with_pg_transaction) for semantics.
    /// Use [`with_mysql_transaction_borrowed`] to await operations that borrow
    /// the transaction or its context.
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
        finish_transaction(tx, cx, result).await
    }

    /// Run a borrowing callback inside a MySQL transaction.
    ///
    /// Return [`TransactionFuture::new`] around an `async move` block to await
    /// queries while borrowing the transaction and its context. To borrow
    /// caller-owned SQL, parameters, or other non-`'static` data across awaits,
    /// use [`with_mysql_transaction_with_state`].
    ///
    /// This uses the same commit, cancellation, and rollback semantics as
    /// [`with_mysql_transaction`], including rollback before propagating an
    /// error, cancellation, or `Outcome::Panicked` value. A successful body
    /// commits only while the context is active and rollback is not required.
    /// The callback and its future are `Send`, so the helper can be awaited
    /// by tasks running on native worker threads.
    pub async fn with_mysql_transaction_borrowed<'env, T, F>(
        conn: &mut MySqlConnection,
        cx: &Cx,
        f: F,
    ) -> Outcome<T, MySqlError>
    where
        T: Send + 'env,
        F: for<'a, 'tx> FnOnce(
                &'a mut MySqlTransaction<'tx>,
                &'a Cx,
            ) -> TransactionFuture<'env, 'a, T, MySqlError>
            + Send
            + 'env,
    {
        let mut tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&mut tx, cx).await;
        finish_transaction(tx, cx, result).await
    }

    /// Run a MySQL transaction while lending caller-owned state.
    ///
    /// `state` may contain non-`'static` references to SQL, parameters, or
    /// mutable caller data. The callback borrows it for the same invocation
    /// as the transaction and context, and may use all three across awaits.
    /// Return [`ScopedTransactionFuture::new`] around the callback's async
    /// block. `S` needs neither `Clone`, `Sync`, nor `'static` and may be
    /// unsized. Results may contain existing references stored in the state,
    /// but cannot retain the invocation's temporary state or transaction borrow.
    ///
    /// This uses the commit, cancellation, rollback, and panic-outcome
    /// handling of [`with_mysql_transaction`]. The callback runs only after
    /// `START TRANSACTION` succeeds. Both callback and future are `Send`.
    pub async fn with_mysql_transaction_with_state<T, S, F>(
        conn: &mut MySqlConnection,
        cx: &Cx,
        state: &mut S,
        f: F,
    ) -> Outcome<T, MySqlError>
    where
        T: Send,
        S: Send + ?Sized,
        F: for<'a, 'tx> FnOnce(
                &'a mut MySqlTransaction<'tx>,
                &'a Cx,
                &'a mut S,
            ) -> ScopedTransactionFuture<'a, T, MySqlError>
            + Send,
    {
        let mut tx = match conn.begin(cx).await {
            Outcome::Ok(tx) => tx,
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        };

        let result = f(&mut tx, cx, state).await;
        finish_transaction(tx, cx, result).await
    }

    /// Run a closure inside a MySQL transaction with retry on deadlock.
    ///
    /// Deadlocks (error 1213) and lock wait timeouts (error 1205) are retried
    /// according to the given [`RetryPolicy`]. Pass
    /// [`TransactionReplaySafety::ReplaySafe`] only when rerunning the closure
    /// cannot duplicate externally visible side effects. Other errors are
    /// returned immediately.
    ///
    /// Use [`with_mysql_transaction_retry_borrowed`] for a borrowing callback.
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

            let is_retryable = matches!(&result, Outcome::Err(err) if err.is_deadlock());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started.load(Ordering::Relaxed),
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
            }
        }
    }

    /// Run a borrowing callback with retry on MySQL deadlock (1213) or
    /// lock wait timeout (1205).
    ///
    /// Return [`TransactionFuture::new`] around each attempt's `async move`
    /// block. Each attempt starts a fresh transaction after the preceding
    /// attempt has completed the helper's rollback handling.
    ///
    /// The `FnMut` callback may change captured state before returning the
    /// future. To borrow caller-owned SQL, parameters, or mutable state
    /// across awaits, use [`with_mysql_transaction_retry_with_state`].
    ///
    /// [`TransactionReplaySafety::ReplayUnsafe`] permits retries only before
    /// the body starts. Choose [`TransactionReplaySafety::ReplaySafe`] only
    /// when repeating the complete callback, including its captured-state
    /// changes, cannot duplicate externally visible effects. A retryable
    /// commit error may also replay the body. Other outcomes return
    /// immediately, and the context can cancel the retry backoff.
    pub async fn with_mysql_transaction_retry_borrowed<'env, T, F>(
        conn: &mut MySqlConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        mut f: F,
    ) -> Outcome<T, MySqlError>
    where
        T: Send + 'env,
        F: for<'a, 'tx> FnMut(
                &'a mut MySqlTransaction<'tx>,
                &'a Cx,
            ) -> TransactionFuture<'env, 'a, T, MySqlError>
            + Send
            + 'env,
    {
        let mut attempt = 0u32;
        loop {
            let mut body_started = false;
            let result = match conn.begin(cx).await {
                Outcome::Ok(mut tx) => {
                    body_started = true;
                    let result = f(&mut tx, cx).await;
                    finish_transaction(tx, cx, result).await
                }
                Outcome::Err(e) => Outcome::Err(e),
                Outcome::Cancelled(r) => Outcome::Cancelled(r),
                Outcome::Panicked(p) => Outcome::Panicked(p),
            };

            let is_retryable = matches!(&result, Outcome::Err(err) if err.is_deadlock());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started,
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
            }
        }
    }

    /// Retry MySQL transactions while lending state to each attempt.
    ///
    /// The callback can borrow and mutate `state` across awaits. Each attempt
    /// reborrows the same state after the previous transaction has completed
    /// its rollback handling. Caller-state changes survive database rollback.
    ///
    /// Deadlock classification, backoff cancellation, and replay safety
    /// follow [`with_mysql_transaction_retry_borrowed`]. `ReplayUnsafe`
    /// retries only before the body starts; `ReplaySafe` also permits replay
    /// after body execution or a retryable commit error.
    pub async fn with_mysql_transaction_retry_with_state<T, S, F>(
        conn: &mut MySqlConnection,
        cx: &Cx,
        policy: &RetryPolicy,
        replay_safety: TransactionReplaySafety,
        state: &mut S,
        mut f: F,
    ) -> Outcome<T, MySqlError>
    where
        T: Send,
        S: Send + ?Sized,
        F: for<'a, 'tx> FnMut(
                &'a mut MySqlTransaction<'tx>,
                &'a Cx,
                &'a mut S,
            ) -> ScopedTransactionFuture<'a, T, MySqlError>
            + Send,
    {
        let mut attempt = 0u32;
        loop {
            let mut body_started = false;
            let result = with_mysql_transaction_with_state(conn, cx, state, |tx, tx_cx, state| {
                body_started = true;
                f(tx, tx_cx, state)
            })
            .await;
            let is_retryable = matches!(&result, Outcome::Err(err) if err.is_deadlock());
            match retry_after_error(
                cx,
                policy,
                replay_safety,
                body_started,
                is_retryable,
                &mut attempt,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return result,
                Err(reason) => return Outcome::Cancelled(reason),
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
pub use mysql::{
    MySqlSavepoint, with_mysql_transaction, with_mysql_transaction_borrowed,
    with_mysql_transaction_retry, with_mysql_transaction_retry_borrowed,
    with_mysql_transaction_retry_with_state, with_mysql_transaction_with_state,
};

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[path = "transaction_inline_tests.rs"]
mod tests;
