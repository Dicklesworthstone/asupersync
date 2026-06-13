//! Database clients with async wrappers and Cx integration.
//!
//! This module provides async wrappers for database clients, integrating with
//! asupersync's cancel-correct semantics and blocking pool.
//!
//! # Available Clients
//!
//! - [`sqlite`]: SQLite async wrapper using blocking pool (requires `sqlite` feature)
//! - [`postgres`]: PostgreSQL async client with wire protocol (requires `postgres` feature)
//! - [`mysql`]: MySQL async client with wire protocol (requires `mysql` feature)
//!
//! # Design Philosophy
//!
//! Database clients integrate with [`Cx`] for checkpointing and cancellation.
//! SQLite uses the blocking pool for synchronous operations, while PostgreSQL
//! and MySQL implement their respective wire protocols over async TCP.
//!
//! [`Cx`]: crate::cx::Cx
//!
//! # Deadline propagation (min-plus composition)
//!
//! Query timeouts compose with the ambient [`Cx`] budget through meet
//! semantics, mirroring the outbound HTTP/gRPC clients
//! (br-asupersync-server-stack-hardening-eeexl1.1.2): the effective
//! statement timeout for each query is `min(remaining Cx budget,
//! per-connection override)`. A database call therefore can never outlive
//! its caller's deadline, and each hop only ever tightens the bound. The
//! per-backend delivery mechanism is `SET statement_timeout` (PostgreSQL),
//! `SET SESSION max_execution_time` (MySQL, `SELECT`-only by server
//! semantics), and a deadline-checking progress handler (SQLite).
//!
//! On cancellation observed mid-query, each client performs a wire-level
//! cancel inside the drain phase — PostgreSQL `CancelRequest` on a fresh
//! socket, MySQL `KILL QUERY` on a fresh connection, SQLite
//! `sqlite3_interrupt` — and only resolves the operation as `Cancelled`
//! after the wire cancel has completed (or its connection-close fallback
//! has been taken and logged).

pub mod pool;
pub mod transaction;

pub use pool::{
    AsyncConnectionManager, AsyncDbPool, AsyncPooledConnection, ConnectionManager, DbPool,
    DbPoolConfig, DbPoolError, DbPoolStats, PooledConnection,
};

#[cfg(feature = "sqlite")]
pub mod sqlite;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "mysql")]
pub mod mysql;

#[cfg(feature = "sqlite")]
pub use sqlite::{SqliteConnection, SqliteError, SqliteRow, SqliteTransaction, SqliteValue};

#[cfg(feature = "postgres")]
pub use postgres::{
    Format as PgFormat, FromSql as PgFromSql, IsNull as PgIsNull, PgColumn, PgConnectOptions,
    PgConnection, PgError, PgRow, PgStatement, PgTransaction, PgValue, PreparedCacheStats, SslMode,
    ToSql as PgToSql, oid as pg_oid,
};

#[cfg(feature = "mysql")]
pub use mysql::{
    MySqlColumn, MySqlConnectOptions, MySqlConnection, MySqlConnectionManager, MySqlError,
    MySqlRow, MySqlTransaction, MySqlValue, SslMode as MySqlSslMode,
    column_type as mysql_column_type,
};

/// Remaining wall/virtual time before the ambient [`Cx`] budget deadline.
///
/// Returns `None` when the budget carries no deadline; returns
/// `Some(Duration::ZERO)` when the deadline has already passed (the caller's
/// own checkpoint will normally have observed that first). Uses the Cx's
/// timer driver when available so lab runs stay on virtual time, falling
/// back to the wall clock otherwise — the same convention as the outbound
/// HTTP/gRPC clients (br-asupersync-server-stack-hardening-eeexl1.1.3).
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) fn remaining_budget(cx: &crate::cx::Cx) -> Option<std::time::Duration> {
    let deadline = cx.budget().deadline?;
    let now = cx
        .timer_driver()
        .map_or_else(crate::time::wall_now, |timer| timer.now());
    Some(std::time::Duration::from_nanos(
        deadline.duration_since(now),
    ))
}

/// Effective statement timeout: `min(remaining Cx budget, per-query override)`.
///
/// Meet semantics (br-asupersync-server-stack-hardening-eeexl1.1.2): the
/// budget can only tighten the override and vice versa. Returns `None` when
/// neither bound exists, in which case no timeout is forwarded to the server.
#[cfg(feature = "sqlite")]
pub(crate) fn effective_statement_timeout(
    cx: &crate::cx::Cx,
    override_timeout: Option<std::time::Duration>,
) -> Option<std::time::Duration> {
    [remaining_budget(cx), override_timeout]
        .into_iter()
        .flatten()
        .min()
}

/// Converts an effective statement timeout to whole milliseconds for wire
/// delivery, rounding up and clamping to at least 1ms. Most servers treat a
/// `0` timeout as "disabled", which would invert the meaning of an
/// already-exhausted budget — the 1ms floor keeps an exhausted budget
/// expiring promptly instead of never.
#[cfg(any(feature = "sqlite", feature = "postgres", feature = "mysql"))]
pub(crate) fn statement_timeout_millis(timeout: std::time::Duration) -> u64 {
    let millis = timeout.as_millis();
    let rounded = if timeout.subsec_nanos() % 1_000_000 == 0 {
        millis
    } else {
        millis + 1
    };
    u64::try_from(rounded).unwrap_or(u64::MAX).max(1)
}

/// Effective wire statement timeout in milliseconds for the SQL backends
/// that deliver timeouts via a session variable (`SET statement_timeout`
/// for PostgreSQL, `SET SESSION max_execution_time` for MySQL).
///
/// The budget-derived component shrinks continuously, so forwarding it
/// exactly would force a session-variable round-trip before every query.
/// Instead the remaining budget is rounded **up** to a 50ms bucket once it
/// exceeds 100ms (exact below that), so back-to-back queries under the same
/// deadline reuse the session value. The slack is bounded by the bucket
/// size and only affects the server-side backstop: the client-side budget
/// checkpoints still enforce the exact deadline. The per-connection
/// override is forwarded exactly; meet semantics pick the tighter of the
/// two.
#[cfg(any(feature = "postgres", feature = "mysql"))]
pub(crate) fn wire_statement_timeout_ms(
    cx: &crate::cx::Cx,
    override_timeout: Option<std::time::Duration>,
) -> Option<u64> {
    let remaining_ms = remaining_budget(cx).map(|remaining| {
        let ms = statement_timeout_millis(remaining);
        if ms <= 100 {
            ms
        } else {
            ms.div_ceil(50).saturating_mul(50)
        }
    });
    let override_ms = override_timeout.map(statement_timeout_millis);
    [remaining_ms, override_ms].into_iter().flatten().min()
}
