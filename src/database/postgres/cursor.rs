//! Consumer-paced PostgreSQL portals over the existing owned connection.

use super::{
    Cx, Outcome, PgColumn, PgConnection, PgError, PgRow, PgStatement, PgTransaction,
    ToSql, MAX_BACKEND_MESSAGE_LEN, build_close_msg, build_describe_msg,
    build_execute_msg, build_sync_msg, cancelled_reason, unexpected_backend_message,
};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// Explicit bounds for a consumer-paced PostgreSQL result cursor.
///
/// `batch_rows` limits the rows requested in each Execute message. The byte
/// limit applies to each backend message body in cursor preparation, fetching,
/// and close, including metadata and asynchronous notices, before allocation.
/// Authentication and shared session maintenance retain their existing limits.
/// The client retains one
/// decoded row at a time; rows retained by the caller are outside these bounds.
/// PostgreSQL may perform arbitrary work to produce a batch (for example a
/// sort), so these are result-delivery bounds, not SQL execution-work limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PgCursorConfig {
    batch_rows: i32,
    max_message_bytes: usize,
}

impl PgCursorConfig {
    /// Require a positive row count that fits the wire protocol, and a positive
    /// message-body cap no larger than the existing PostgreSQL frame limit.
    pub fn new(batch_rows: u32, max_message_bytes: usize) -> Result<Self, PgError> {
        let batch_rows = i32::try_from(batch_rows).map_err(|_| {
            PgError::Protocol("cursor batch size exceeds i32::MAX".to_string())
        })?;
        if batch_rows == 0 || max_message_bytes == 0
            || max_message_bytes > MAX_BACKEND_MESSAGE_LEN as usize - 4
        {
            return Err(PgError::Protocol("invalid cursor row or message-body bound".to_string()));
        }
        Ok(Self { batch_rows, max_message_bytes })
    }

    /// Maximum rows requested from the server in one Execute message.
    #[must_use]
    pub const fn batch_rows(self) -> u32 { self.batch_rows as u32 }

    /// Maximum individual backend message body, checked before allocation.
    #[must_use]
    pub const fn max_message_bytes(self) -> usize { self.max_message_bytes }
}

/// Observed cursor completion after the backend acknowledged Close and Sync.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgCursorComplete {
    rows_received: u64,
    rows_yielded: u64,
    exhausted: bool,
    command_tag: Option<String>,
}

impl PgCursorComplete {
    /// Rows decoded, including any bounded remainder discarded by `close`.
    #[must_use]
    pub const fn rows_received(&self) -> u64 { self.rows_received }

    /// Rows returned to the caller by `next`.
    #[must_use]
    pub const fn rows_yielded(&self) -> u64 { self.rows_yielded }

    /// Whether CommandComplete or EmptyQueryResponse was observed. Early close
    /// at PortalSuspended is not reported as execution of the entire result.
    #[must_use]
    pub const fn exhausted(&self) -> bool { self.exhausted }

    /// The server's command tag, absent after early close or an empty query.
    #[must_use]
    pub fn command_tag(&self) -> Option<&str> { self.command_tag.as_deref() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase { Bind, Description, Rows, Suspended, Close, Ready, Completed, Failed }

/// A prepared PostgreSQL portal fetched in bounded, consumer-paced batches.
///
/// The connection is exclusively borrowed until this cursor is dropped. The
/// backend's implicit transaction remains open between batches: no Sync is
/// sent at PortalSuspended, because Sync would end that transaction and destroy
/// the portal. Exhaustion or [`Self::close`] closes the portal, sends Sync, and
/// awaits ReadyForQuery before allowing connection reuse. Sync preserves an
/// explicit transaction opened by `BEGIN`; its normal commit/rollback remains
/// the transaction owner's responsibility.
///
/// A cancelled operation uses the existing bounded wire CancelRequest path.
/// Dropping this cursor, or abandoning an already-polled `next` future, closes
/// an unsynchronized socket. Drop cannot await a server-side cancellation
/// acknowledgement. Use `close` for graceful early termination. No background
/// reader or task is started, and no next batch is requested between calls to
/// `next`.
#[must_use = "read or close the cursor to synchronize its connection"]
pub struct PgCursor<'a> {
    connection: &'a mut PgConnection,
    config: PgCursorConfig,
    statement_name: String,
    columns: Option<Arc<Vec<PgColumn>>>,
    column_indices: Option<Arc<BTreeMap<String, usize>>>,
    phase: Phase,
    batch_received: i32,
    rows_received: u64,
    rows_yielded: u64,
    exhausted: bool,
    command_tag: Option<String>,
    sync_sent: bool,
    synchronized: bool,
}

impl fmt::Debug for PgCursor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgCursor").field("config", &self.config)
            .field("phase", &self.phase).field("rows_received", &self.rows_received)
            .field("rows_yielded", &self.rows_yielded).finish_non_exhaustive()
    }
}

impl PgConnection {
    /// Open a bounded portal for a prepared statement.
    ///
    /// Resolve the statement's retained SQL through this connection's prepared
    /// cache. A foreign or stale handle never aliases an unrelated server-side
    /// name: it is prepared on the current backend if needed. Parameter arity
    /// and binary type checks use that backend's resulting statement metadata.
    /// This retains the ordinary reconnect, orphan rollback, statement timeout,
    /// cache invalidation and parameter encoding behavior.
    pub async fn query_cursor_prepared<'a>(
        &'a mut self, cx: &Cx, statement: &PgStatement, params: &[&dyn ToSql],
        config: PgCursorConfig,
    ) -> Outcome<PgCursor<'a>, PgError> {
        self.start_cursor(cx, &statement.sql, params, config).await
    }

    /// Prepare a parameterized query and open its consumer-paced result cursor.
    /// SQL structure is caller-controlled; external values belong in `params`.
    pub async fn query_cursor_params<'a>(
        &'a mut self, cx: &Cx, sql: &str, params: &[&dyn ToSql], config: PgCursorConfig,
    ) -> Outcome<PgCursor<'a>, PgError> {
        self.start_cursor(cx, sql, params, config).await
    }

    async fn start_cursor<'a>(
        &'a mut self, cx: &Cx, sql: &str, params: &[&dyn ToSql], config: PgCursorConfig,
    ) -> Outcome<PgCursor<'a>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(cancelled_reason(cx));
        }
        let mut opening = Opening { connection: Some(self) };
        let connection = opening.connection.as_deref_mut().expect("owned opening connection");
        match connection.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        match connection.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            other => return other.map(|()| unreachable!()),
        }
        match connection.apply_statement_timeout(cx).await {
            Outcome::Ok(()) => {}
            other => return other.map(|()| unreachable!()),
        }
        let statement = match connection.prepare_with_body_limit(cx, sql, config.max_message_bytes).await {
            Outcome::Ok(statement) => statement,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        if let Err(error) = Self::validate_prepared_bind_arity(&statement, params)
            .and_then(|()| Self::validate_prepared_bind_types(&statement, params))
        {
            return Outcome::Err(error);
        }
        let request = (|| {
            let mut request = Self::bind_prepared(&statement, params)?;
            request.extend_from_slice(&build_describe_msg(b'P', "")?);
            request.extend_from_slice(&build_execute_msg("", config.batch_rows)?);
            request.extend_from_slice(&[b'H', 0, 0, 0, 4]); // Flush, deliberately not Sync.
            Ok::<_, PgError>(request)
        })();
        let request = match request {
            Ok(request) => request,
            Err(error) => return Outcome::Err(error),
        };
        connection.inner.closed = true;
        // Construct the ownership guard before the first write. Abandoning the
        // startup future then closes even a partially written Bind/Execute.
        let mut cursor = PgCursor {
            connection: opening.connection.take().expect("transfer opening ownership"),
            config, statement_name: statement.name,
            columns: None, column_indices: None, phase: Phase::Bind,
            batch_received: 0, rows_received: 0, rows_yielded: 0,
            exhausted: false, command_tag: None, sync_sent: false, synchronized: false,
        };
        if let Err(error) = cursor.connection.write_all(cx, &request).await {
            return cursor.fail(error);
        }
        Outcome::Ok(cursor)
    }
}

impl PgTransaction<'_> {
    /// Open a bounded prepared cursor within this explicit transaction. Close
    /// or exhaust the cursor before committing or rolling back the transaction.
    pub async fn query_cursor_prepared<'a>(
        &'a mut self, cx: &Cx, statement: &PgStatement, params: &[&dyn ToSql],
        config: PgCursorConfig,
    ) -> Outcome<PgCursor<'a>, PgError> {
        if self.finished { return Outcome::Err(PgError::TransactionFinished); }
        self.conn.query_cursor_prepared(cx, statement, params, config).await
    }

    /// Prepare a parameterized bounded cursor inside this explicit transaction.
    pub async fn query_cursor_params<'a>(
        &'a mut self, cx: &Cx, sql: &str, params: &[&dyn ToSql], config: PgCursorConfig,
    ) -> Outcome<PgCursor<'a>, PgError> {
        if self.finished { return Outcome::Err(PgError::TransactionFinished); }
        self.conn.query_cursor_params(cx, sql, params, config).await
    }
}

// Preparation and session maintenance precede the cursor object. If an opening
// future is abandoned in their protocol exchange, fence that socket too.
struct Opening<'a> { connection: Option<&'a mut PgConnection> }
impl Drop for Opening<'_> {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.as_deref_mut()
            && connection.inner.closed
        {
            connection.abort_in_flight_exchange();
        }
    }
}

struct Operation<'a, 'conn> { cursor: &'a mut PgCursor<'conn>, completed: bool }
impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        if !self.completed {
            self.cursor.phase = Phase::Failed;
            self.cursor.connection.abort_in_flight_exchange();
        }
    }
}

impl PgCursor<'_> {
    /// Return one row, requesting another bounded batch only when needed.
    /// `Ok(None)` is returned only after portal close and ReadyForQuery.
    pub async fn next(&mut self, cx: &Cx) -> Outcome<Option<PgRow>, PgError> {
        if self.phase == Phase::Completed { return Outcome::Ok(None); }
        if self.phase == Phase::Failed { return Outcome::Err(PgError::ConnectionClosed); }
        let mut operation = Operation { cursor: self, completed: false };
        let result = operation.cursor.drive(cx, true).await;
        operation.completed = true;
        result
    }

    /// Rows yielded so far; this does not include the remainder discarded by
    /// an early `close`.
    #[must_use]
    pub const fn row_count(&self) -> u64 { self.rows_yielded }

    /// Successful synchronization receipt, including whether the full result
    /// was exhausted. A failed or interrupted exchange has no completion.
    #[must_use]
    pub fn completion(&self) -> Option<PgCursorComplete> {
        (self.phase == Phase::Completed).then(|| PgCursorComplete {
            rows_received: self.rows_received, rows_yielded: self.rows_yielded,
            exhausted: self.exhausted, command_tag: self.command_tag.clone(),
        })
    }

    /// Gracefully close without requesting another batch. Discard at most the
    /// remainder of the already requested batch, then Close + Sync and wait for
    /// ReadyForQuery. Cancellation follows the usual wire-cancel/close path.
    pub async fn close(mut self, cx: &Cx) -> Outcome<PgCursorComplete, PgError> {
        if self.phase == Phase::Completed {
            return Outcome::Ok(self.completion().expect("completed cursor"));
        }
        if self.phase == Phase::Failed { return Outcome::Err(PgError::ConnectionClosed); }
        match self.drive(cx, false).await {
            Outcome::Ok(None) => Outcome::Ok(self.completion().expect("synchronized cursor")),
            Outcome::Ok(Some(_)) => unreachable!("closing never yields rows"),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    fn fail<T>(&mut self, error: PgError) -> Outcome<T, PgError> {
        self.phase = Phase::Failed;
        self.connection.fail_in_flight(error)
    }

    async fn read(&mut self, cx: &Cx) -> Result<(u8, Vec<u8>), PgError> {
        self.connection.read_message_with_body_limit(cx, self.config.max_message_bytes, "cursor").await
    }

    async fn drive(&mut self, cx: &Cx, yield_rows: bool) -> Outcome<Option<PgRow>, PgError> {
        loop {
            if cx.checkpoint().is_err() {
                self.phase = Phase::Failed;
                return self.connection.cancel_in_flight(cx).await;
            }
            if self.phase == Phase::Suspended {
                if !yield_rows { return self.finish_portal(cx, false).await.map(|()| None); }
                let mut request = match build_execute_msg("", self.config.batch_rows) {
                    Ok(request) => request,
                    Err(error) => return self.fail(error),
                };
                request.extend_from_slice(&[b'H', 0, 0, 0, 4]);
                if let Err(error) = self.connection.write_all(cx, &request).await {
                    return self.fail(error);
                }
                self.batch_received = 0;
                self.phase = Phase::Rows;
            }
            let (kind, data) = match self.read(cx).await {
                Ok(message) => message,
                Err(error) => return self.fail(error),
            };
            if kind == b'E' { return self.server_error(cx, &data).await; }
            match self.connection.handle_async_backend_message(kind, &data) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return self.fail(error),
            }
            match (self.phase, kind) {
                (Phase::Bind, b'2') if data.is_empty() => self.phase = Phase::Description,
                (Phase::Description, b'T') => {
                    let (columns, indices) = match self.connection.parse_row_description(&data) {
                        Ok(metadata) => metadata,
                        Err(error) => return self.fail(error),
                    };
                    self.columns = Some(Arc::new(columns));
                    self.column_indices = Some(Arc::new(indices));
                    self.phase = Phase::Rows;
                }
                (Phase::Description, b'n') if data.is_empty() => self.phase = Phase::Rows,
                (Phase::Rows, b'D') => {
                    if self.batch_received >= self.config.batch_rows {
                        return self.fail(PgError::Protocol("cursor exceeded requested batch row count".to_string()));
                    }
                    let (Some(columns), Some(indices)) = (&self.columns, &self.column_indices) else {
                        return self.fail(PgError::Protocol("cursor DataRow has no RowDescription".to_string()));
                    };
                    let values = match self.connection.parse_data_row(&data, columns) {
                        Ok(values) => values,
                        Err(error) => return self.fail(error),
                    };
                    let row = PgRow { columns: Arc::clone(columns), column_indices: Arc::clone(indices), values };
                    let Some(count) = self.rows_received.checked_add(1) else {
                        return self.fail(PgError::Protocol("cursor row count overflow".to_string()));
                    };
                    self.rows_received = count;
                    self.batch_received += 1;
                    if yield_rows {
                        self.rows_yielded += 1; // Never greater than checked rows_received.
                        return Outcome::Ok(Some(row));
                    }
                }
                (Phase::Rows, b's') if data.is_empty()
                    && self.columns.is_some() && self.batch_received == self.config.batch_rows => {
                    self.phase = Phase::Suspended;
                }
                (Phase::Rows, b'C') => {
                    let mut reader = super::MessageReader::new(&data);
                    let tag = match reader.read_cstring() {
                        Ok(tag) if !tag.is_empty() => tag,
                        _ => return self.fail(PgError::Protocol("malformed cursor CommandComplete".to_string())),
                    };
                    if let Err(error) = reader.ensure_consumed("cursor CommandComplete") {
                        return self.fail(error);
                    }
                    if PgConnection::command_tag_requires_prepared_cache_invalidation(tag) {
                        self.connection.invalidate_prepared_cache_after_schema_or_session_change();
                    }
                    if PgConnection::command_tag_requires_session_discard(tag) {
                        self.connection.inner.needs_discard = true;
                    }
                    self.command_tag = Some(tag.to_string());
                    return self.finish_portal(cx, true).await.map(|()| None);
                }
                (Phase::Rows, b'I') if data.is_empty() && self.columns.is_none()
                    && self.batch_received == 0 => {
                    return self.finish_portal(cx, true).await.map(|()| None);
                }
                _ => return self.fail(unexpected_backend_message("bounded cursor response", kind)),
            }
        }
    }

    async fn finish_portal(&mut self, cx: &Cx, exhausted: bool) -> Outcome<(), PgError> {
        let request = (|| {
            let mut request = build_close_msg(b'P', "")?;
            request.extend_from_slice(&build_sync_msg()?);
            Ok::<_, PgError>(request)
        })();
        let request = match request { Ok(request) => request, Err(error) => return self.fail(error) };
        self.phase = Phase::Close;
        self.sync_sent = true;
        if let Err(error) = self.connection.write_all(cx, &request).await { return self.fail(error); }
        loop {
            let (kind, data) = match self.read(cx).await {
                Ok(message) => message,
                Err(error) => return self.fail(error),
            };
            if kind == b'E' { return self.server_error(cx, &data).await; }
            match self.connection.handle_async_backend_message(kind, &data) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => return self.fail(error),
            }
            match (self.phase, kind) {
                (Phase::Close, b'3') if data.is_empty() => self.phase = Phase::Ready,
                (Phase::Ready, b'Z') => {
                    if let Err(error) = self.connection.handle_ready_for_query(&data) { return self.fail(error); }
                    self.connection.inner.closed = false;
                    self.phase = Phase::Completed;
                    self.synchronized = true;
                    self.exhausted = exhausted;
                    return Outcome::Ok(());
                }
                _ => return self.fail(unexpected_backend_message("cursor close response", kind)),
            }
        }
    }

    async fn server_error<T>(&mut self, cx: &Cx, data: &[u8]) -> Outcome<T, PgError> {
        let error = match self.connection.parse_error_response(data) {
            Ok(error) => error,
            Err(error) => return self.fail(error),
        };
        let result = Outcome::<(), _>::Err(error);
        self.connection.forget_unusable_prepared_statement(&result, &self.statement_name);
        self.phase = Phase::Failed;
        // After an extended-query error the backend ignores everything up to
        // Sync. A bounded cursor has not sent one while fetching batches.
        if !self.sync_sent {
            let sync = match build_sync_msg() { Ok(sync) => sync, Err(error) => return self.fail(error) };
            self.sync_sent = true;
            if let Err(error) = self.connection.write_all(cx, &sync).await { return self.fail(error); }
        }
        loop {
            let (kind, data) = match self.read(cx).await {
                Ok(message) => message,
                Err(error) => return self.fail(error),
            };
            if kind == b'Z' {
                if let Err(error) = self.connection.handle_ready_for_query(&data) { return self.fail(error); }
                self.connection.inner.closed = false;
                self.synchronized = true;
                return result.map(|()| unreachable!());
            }
            match self.connection.handle_async_backend_message(kind, &data) {
                Ok(true) => {}
                Ok(false) => return self.fail(unexpected_backend_message("cursor error recovery", kind)),
                Err(error) => return self.fail(error),
            }
        }
    }
}

impl Drop for PgCursor<'_> {
    fn drop(&mut self) {
        if !self.synchronized { self.connection.abort_in_flight_exchange(); }
    }
}

#[cfg(test)]
#[path = "cursor_tests.rs"]
mod tests;
