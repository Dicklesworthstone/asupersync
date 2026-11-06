//! Isolated, bounded stored-procedure results (asupersync-1dl7, asupersync-1dl7s).

use super::*;

const MULTI_RESULT_CAPABILITIES: u32 =
    capability::CLIENT_MULTI_RESULTS | capability::CLIENT_PS_MULTI_RESULTS;
const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;
const SERVER_PS_OUT_PARAMS: u16 = 0x1000;

/// Aggregate limits for one multi-result query, including its closing status.
/// The ordinary connection's per-result row ceiling also remains in effect.
///
/// The byte limit applies independently to wire bytes (including packet
/// headers) and a decoded-storage accounting budget: retained value capacities
/// plus conservative row/column bookkeeping. Packet lengths are checked before
/// allocation. One wire-bounded row may be decoded before its retained storage
/// is charged; the byte limit is not an exact peak allocator limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MySqlMultiResultLimits {
    max_result_sets: usize,
    max_rows: usize,
    max_bytes: usize,
}

impl MySqlMultiResultLimits {
    /// Set positive aggregate result, row, and byte limits.
    pub fn new(
        max_result_sets: usize,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Self, MySqlError> {
        if max_result_sets == 0 || max_rows == 0 || max_bytes == 0 {
            return Err(MySqlError::InvalidParameter(
                "multi-result limits must all be positive".to_string(),
            ));
        }
        Ok(Self { max_result_sets, max_rows, max_bytes })
    }

    /// Maximum number of row sets and command statuses combined.
    #[must_use]
    pub const fn max_result_sets(self) -> usize { self.max_result_sets }

    /// Maximum number of rows across all result sets.
    #[must_use]
    pub const fn max_rows(self) -> usize { self.max_rows }

    /// Maximum wire bytes and decoded-storage charge, independently.
    #[must_use]
    pub const fn max_bytes(self) -> usize { self.max_bytes }
}

impl Default for MySqlMultiResultLimits {
    fn default() -> Self {
        Self { max_result_sets: 64, max_rows: 100_000, max_bytes: 16 * 1024 * 1024 }
    }
}

/// Additional working-set limits for an incremental multi-result response.
///
/// The connection's aggregate limits still apply even when rows are released
/// immediately. These independent limits bound one reassembled wire packet
/// (including all fragment headers), the current result's metadata accounting,
/// and one decoded row's accounting. A packet is admitted before allocating its
/// payload; a row is decoded before checking its retained capacities. Accounting
/// includes conservative bookkeeping and is not an exact peak allocator limit.
/// Rows and metadata retained by the caller are outside the stream's working set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MySqlMultiResultStreamConfig {
    max_packet_bytes: usize,
    max_metadata_bytes: usize,
    max_row_bytes: usize,
}

impl MySqlMultiResultStreamConfig {
    /// Set positive packet, current-result metadata, and decoded-row limits.
    pub fn new(
        max_packet_bytes: usize,
        max_metadata_bytes: usize,
        max_row_bytes: usize,
    ) -> Result<Self, MySqlError> {
        if max_packet_bytes < 4 || max_metadata_bytes == 0 || max_row_bytes == 0 {
            return Err(MySqlError::InvalidParameter(
                "stream limits require at least four packet bytes and positive metadata/row bytes"
                    .to_string(),
            ));
        }
        Ok(Self { max_packet_bytes, max_metadata_bytes, max_row_bytes })
    }

    /// Maximum bytes in one packet, including its fragment headers.
    #[must_use]
    pub const fn max_packet_bytes(self) -> usize { self.max_packet_bytes }

    /// Maximum metadata accounting charge for the current result set.
    #[must_use]
    pub const fn max_metadata_bytes(self) -> usize { self.max_metadata_bytes }

    /// Maximum decoded-storage accounting charge for one row.
    #[must_use]
    pub const fn max_row_bytes(self) -> usize { self.max_row_bytes }
}

impl Default for MySqlMultiResultStreamConfig {
    fn default() -> Self {
        Self {
            max_packet_bytes: 1024 * 1024,
            max_metadata_bytes: 1024 * 1024,
            max_row_bytes: 1024 * 1024,
        }
    }
}

/// Column metadata announcing a row set, including an empty row set.
#[derive(Debug, Clone)]
pub struct MySqlResultSetMetadata {
    index: usize,
    columns: Arc<Vec<MySqlColumn>>,
    status_flags: u16,
}

impl MySqlResultSetMetadata {
    /// Zero-based position among row sets and command statuses combined.
    #[must_use]
    pub const fn index(&self) -> usize { self.index }

    /// Columns shared with subsequent rows until this result completes.
    #[must_use]
    pub fn columns(&self) -> &[MySqlColumn] { &self.columns }

    /// Whether the metadata marks prepared CALL OUT/INOUT parameters.
    #[must_use]
    pub const fn is_output_parameters(&self) -> bool {
        self.status_flags & SERVER_PS_OUT_PARAMS != 0
    }
}

/// A row-set terminator or a command-only result, in server order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MySqlResultSetCompletion {
    index: usize,
    row_count: usize,
    command_result: Option<MySqlExecResult>,
    metadata_status_flags: u16,
    status_flags: u16,
}

impl MySqlResultSetCompletion {
    /// Zero-based position among row sets and command statuses combined.
    #[must_use]
    pub const fn index(self) -> usize { self.index }

    /// Number of rows emitted for this result set.
    #[must_use]
    pub const fn row_count(self) -> usize { self.row_count }

    /// Affected rows and generated key for an OK-only result.
    #[must_use]
    pub const fn command_result(self) -> Option<MySqlExecResult> { self.command_result }

    /// Flags from the row terminator or command OK, without metadata merging.
    #[must_use]
    pub const fn status_flags(self) -> u16 { self.status_flags }

    /// Whether this result contains prepared CALL OUT/INOUT parameters.
    #[must_use]
    pub const fn is_output_parameters(self) -> bool {
        (self.metadata_status_flags | self.status_flags) & SERVER_PS_OUT_PARAMS != 0
    }

    /// Whether the same exchange still requires another result or closing OK.
    ///
    /// Prepared OUT metadata can require a closing CALL status even when the
    /// row terminator itself clears the MORE and OUT flags.
    #[must_use]
    pub const fn has_more_results(self) -> bool {
        self.status_flags & SERVER_MORE_RESULTS_EXISTS != 0
            || (self.is_output_parameters()
                && self.metadata_status_flags & SERVER_MORE_RESULTS_EXISTS != 0)
    }
}

/// One incremental event from a multi-result response.
///
/// Each row set emits `Columns`, zero or more `Row` events, and `Complete`.
/// Command-only results emit only `Complete`. Earlier events remain visible
/// if a later result fails; they do not establish that the statement succeeded
/// or that its effects committed. Only the final completion restores reuse.
#[derive(Debug)]
#[non_exhaustive]
pub enum MySqlMultiResultEvent {
    /// Metadata for the next row set, also emitted when it has no rows.
    Columns(MySqlResultSetMetadata),
    /// A row belonging to the most recently announced columns.
    Row(MySqlRow),
    /// End of a row set, or a standalone command status.
    Complete(MySqlResultSetCompletion),
}

/// An exclusive, bounded incremental borrow of a multi-result connection.
///
/// There is no background reader or queue: each [`Self::next`] reads only far
/// enough to return one event. Drop poisons an unfinished session and retains
/// its KILL-on-connection-drop ownership. Dropping an individual `next` future
/// after polling also poisons the stream: a later read cannot resume a lost
/// partial packet. Use [`Self::finish`] to drain with a deadline and preserve
/// reuse, or [`Self::abort`] for bounded KILL/transport cleanup now.
#[must_use]
pub struct MySqlMultiResultStream<'a> {
    connection: &'a mut MySqlMultiResultConnection,
    reader: ResponseReader,
    read_in_progress: bool,
    finished: bool,
}

impl fmt::Debug for MySqlMultiResultStream<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MySqlMultiResultStream")
            .field("finished", &self.finished)
            .field("read_in_progress", &self.read_in_progress)
            .finish_non_exhaustive()
    }
}

impl MySqlMultiResultStream<'_> {
    /// Read one event. `Ok(None)` follows the final completion or an error.
    ///
    /// Cancellation preserves its reason and finishes bounded KILL/close
    /// cleanup before returning. Malformed input and limit failures also close
    /// the transport. A well-formed terminal server ERR leaves framing reusable.
    pub async fn next(&mut self, cx: &Cx) -> Outcome<Option<MySqlMultiResultEvent>, MySqlError> {
        if self.finished {
            return Outcome::Ok(None);
        }
        if self.read_in_progress {
            // Packet buffers belong to the abandoned future. Never interpret
            // the remaining payload as a new packet header on a later call.
            self.connection.connection.inner.closed = true;
            let result = self.connection.finish_exchange(
                cx, Outcome::Err(MySqlError::ConnectionClosed),
            ).await;
            self.finished = true;
            self.read_in_progress = false;
            return result;
        }
        self.read_in_progress = true;
        let result = self.connection.read_result_event(cx, &mut self.reader).await;
        let terminal = result.is_err() || self.reader.is_finished();
        let result = if terminal {
            self.connection.finish_exchange(cx, result_outcome(result)).await
        } else {
            result_outcome(result)
        };
        // Keep the in-progress fence set throughout cancellation cleanup too:
        // abandoning that await must retain the connection's KILL ownership.
        self.finished = terminal;
        self.read_in_progress = false;
        result
    }

    /// Discard remaining events and wait at most `max_wait` for a terminal packet.
    ///
    /// A deadline or malformed/incomplete response retires the session through
    /// the existing separately bounded KILL/close cleanup. Total latency may
    /// include that cleanup after `max_wait`. A well-formed terminal server ERR
    /// preserves framing but is returned as an error. An already terminated
    /// stream is a no-op; errors already reported by `next` are not repeated.
    pub async fn finish(mut self, cx: &Cx, max_wait: Duration) -> Outcome<(), MySqlError> {
        if self.finished {
            return Outcome::Ok(());
        }
        let deadline = cx.now() + max_wait;
        let drained = crate::time::timeout_at(deadline, async {
            let mut events_since_yield = 0;
            loop {
                if self.finished {
                    return Some(Outcome::Ok(()));
                }
                // A peer can keep every socket read immediately ready. Check
                // between events too, so draining cannot monopolize one poll
                // beyond the deadline without re-polling the outer timer.
                if cx.now() > deadline {
                    return None;
                }
                match self.next(cx).await {
                    Outcome::Ok(Some(_)) => {
                        events_since_yield += 1;
                        if events_since_yield == 32 && !self.finished {
                            events_since_yield = 0;
                            crate::runtime::yield_now().await;
                        }
                    }
                    Outcome::Ok(None) => return Some(Outcome::Ok(())),
                    Outcome::Err(error) => return Some(Outcome::Err(error)),
                    Outcome::Cancelled(reason) => return Some(Outcome::Cancelled(reason)),
                    Outcome::Panicked(payload) => return Some(Outcome::Panicked(payload)),
                }
            }
        }).await;
        match drained {
            Ok(Some(result)) => result,
            Ok(None) | Err(_) => {
                self.abort_inner(cx).await;
                Outcome::Err(MySqlError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "multi-result stream drain deadline elapsed",
                )))
            }
        }
    }

    /// Stop an unfinished response and complete bounded KILL/transport cleanup.
    ///
    /// This always retires an unfinished session. Transport closure is the
    /// fallback if KILL cannot be sent; neither outcome guarantees rollback.
    pub async fn abort(mut self, cx: &Cx) {
        self.abort_inner(cx).await;
    }

    async fn abort_inner(&mut self, cx: &Cx) {
        if self.finished && !self.read_in_progress {
            return;
        }
        self.read_in_progress = true;
        self.connection.connection.inner.closed = true;
        self.connection.connection.wire_cancel_in_drain(cx).await;
        self.connection.connection.inner.query_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
        self.finished = true;
        self.read_in_progress = false;
    }
}

impl Drop for MySqlMultiResultStream<'_> {
    fn drop(&mut self) {
        if !self.finished || self.read_in_progress {
            self.connection.connection.inner.closed = true;
        }
    }
}

/// One row set or command status from a stored-procedure response.
///
/// Empty row sets retain their column metadata. A command status, including
/// the closing CALL status, has no columns and has a [`Self::command_result`].
#[derive(Debug)]
pub struct MySqlResultSet {
    columns: Arc<Vec<MySqlColumn>>,
    rows: Vec<MySqlRow>,
    command_result: Option<MySqlExecResult>,
    metadata_status_flags: u16,
    status_flags: u16,
}

impl MySqlResultSet {
    /// Column metadata, also present when a SELECT returned no rows.
    #[must_use]
    pub fn columns(&self) -> &[MySqlColumn] { &self.columns }

    /// Rows in this result set, in server order.
    #[must_use]
    pub fn rows(&self) -> &[MySqlRow] { &self.rows }

    /// Take ownership of this result set's rows.
    #[must_use]
    pub fn into_rows(self) -> Vec<MySqlRow> { self.rows }

    /// Affected rows and generated key for an OK-only result.
    #[must_use]
    pub const fn command_result(&self) -> Option<MySqlExecResult> { self.command_result }

    /// Status flags from the final row terminator or command OK packet.
    #[must_use]
    pub const fn status_flags(&self) -> u16 { self.status_flags }

    /// Whether this set contains prepared CALL OUT/INOUT parameters.
    #[must_use]
    pub const fn is_output_parameters(&self) -> bool {
        (self.metadata_status_flags | self.status_flags) & SERVER_PS_OUT_PARAMS != 0
    }
}

/// A dedicated connection that consumes complete MySQL multi-result responses.
///
/// This opt-in enables result-returning stored procedures, including prepared
/// CALL parameters, while ordinary [`MySqlConnection`] negotiation is unchanged.
/// `CLIENT_MULTI_STATEMENTS` and local-file requests remain disabled. There is
/// no conversion or mutable access to the inner single-result connection.
///
/// Collected queries return only after every result and the final status have
/// been consumed. Streaming queries expose rows incrementally under additional
/// working-set limits. Both share the same parser and aggregate limits. A terminal
/// server ERR leaves framing synchronized; collected queries discard partial
/// results, while already emitted stream events remain visible to the caller.
/// Cancellation, malformed input, or a limit failure closes the session through
/// the existing bounded KILL/close cleanup.
/// Dropping an unfinished query leaves it poisoned and retains KILL-on-drop
/// ownership. A query error does not imply its server-side effects rolled back.
pub struct MySqlMultiResultConnection {
    connection: MySqlConnection,
    limits: MySqlMultiResultLimits,
}

impl fmt::Debug for MySqlMultiResultConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MySqlMultiResultConnection")
            .field("connection_id", &self.connection.inner.connection_id)
            .field("closed", &self.connection.inner.closed)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// Pool manager for isolated, bounded multi-result MySQL sessions.
///
/// Use this manager with [`crate::database::pool::AsyncDbPool`]. It negotiates
/// the dedicated text/prepared multi-result profile while retaining the ordinary
/// manager's release checks, prepared-statement checkout epochs, and optional
/// session reset. An unfinished stream, poisoned exchange, open transaction, or
/// changed autocommit mode is discarded instead of reset or recycled.
///
/// Session reset is opt-in, as on [`MySqlConnectionManager`]. Enable
/// [`Self::reset_session_on_return`] when borrowers must not inherit session
/// variables, temporary tables, advisory locks, or the selected database.
/// Collected and streamed queries keep the same limits on every checkout.
pub struct MySqlMultiResultConnectionManager {
    manager: MySqlConnectionManager,
    limits: MySqlMultiResultLimits,
    #[cfg(feature = "tls")]
    connector: Option<TlsConnector>,
}

impl fmt::Debug for MySqlMultiResultConnectionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("MySqlMultiResultConnectionManager");
        debug
            .field("manager", &self.manager)
            .field("limits", &self.limits);
        #[cfg(feature = "tls")]
        debug.field("explicit_tls_connector", &self.connector.is_some());
        debug.finish_non_exhaustive()
    }
}

impl MySqlMultiResultConnectionManager {
    /// Create a manager with default aggregate limits and session reset disabled.
    #[must_use]
    pub fn new(options: MySqlConnectOptions) -> Self {
        Self {
            manager: MySqlConnectionManager::new(options),
            limits: MySqlMultiResultLimits::default(),
            #[cfg(feature = "tls")]
            connector: None,
        }
    }

    /// Set the aggregate query limits for every connection minted by this pool.
    #[must_use]
    pub fn with_limits(mut self, limits: MySqlMultiResultLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Isolate session state between borrowers using the ordinary MySQL reset.
    ///
    /// This captures the initial charset/collation and autocommit baseline,
    /// then runs `COM_RESET_CONNECTION` and restores that baseline plus the
    /// configured database before reuse. A nonempty initial database is needed
    /// for reuse; otherwise returned sessions are discarded. Reset failures,
    /// cancellation, and the connection's finite reset timeout also discard.
    ///
    /// Guard drop schedules the reset for checkout validation or the next
    /// operation, including when validation is disabled. Use
    /// [`crate::database::pool::AsyncPooledConnection::reset_and_return`] to
    /// release server resources before the connection goes idle. An unfinished
    /// result stream is never repaired by a reset: its session is discarded.
    #[must_use]
    pub fn reset_session_on_return(mut self, enabled: bool) -> Self {
        self.manager = self.manager.reset_session_on_return(enabled);
        self
    }

    /// Retain explicit TLS trust roots, pins, or client identity for new sessions.
    ///
    /// The connection's existing TLS transport also retains this connector for
    /// separate KILL connections. As on the standalone multi-result constructor,
    /// `ssl-mode=preferred` or `required` is necessary; `disabled` is rejected
    /// before opening a socket. The server must offer TLS in either enabled mode.
    #[cfg(feature = "tls")]
    #[must_use]
    pub fn with_tls_connector(mut self, connector: TlsConnector) -> Self {
        self.connector = Some(connector);
        self
    }

    /// The authentication, database, timeout, and transport options in use.
    #[must_use]
    pub fn options(&self) -> &MySqlConnectOptions {
        self.manager.options()
    }

    /// The aggregate limits applied independently to each query.
    #[must_use]
    pub const fn limits(&self) -> MySqlMultiResultLimits {
        self.limits
    }
}

impl crate::database::pool::AsyncConnectionManager for MySqlMultiResultConnectionManager {
    type Connection = MySqlMultiResultConnection;
    type Error = MySqlError;

    async fn connect(&self, cx: &Cx) -> Outcome<Self::Connection, Self::Error> {
        MySqlMultiResultConnection::connect_managed(
            cx,
            self.manager.options.clone(),
            self.limits,
            self.manager.reset_session_on_return,
            #[cfg(feature = "tls")]
            self.connector.clone(),
        )
        .await
    }

    async fn is_valid(&self, cx: &Cx, conn: &mut Self::Connection) -> bool {
        crate::database::pool::AsyncConnectionManager::is_valid(
            &self.manager,
            cx,
            &mut conn.connection,
        )
        .await
    }

    async fn reset_on_return(&self, cx: &Cx, conn: &mut Self::Connection) -> bool {
        crate::database::pool::AsyncConnectionManager::reset_on_return(
            &self.manager,
            cx,
            &mut conn.connection,
        )
        .await
    }

    fn release_check(&self, conn: &mut Self::Connection) -> bool {
        crate::database::pool::AsyncConnectionManager::release_check(
            &self.manager,
            &mut conn.connection,
        )
    }
}

impl MySqlMultiResultConnection {
    /// Connect with default aggregate limits and the URL's authentication/TLS policy.
    pub async fn connect(cx: &Cx, url: &str) -> Outcome<Self, MySqlError> {
        if let Err(error) = check_context(cx) {
            return outcome_from_error(error);
        }
        let options = match MySqlConnectOptions::parse(url) {
            Ok(options) => options,
            Err(error) => return outcome_from_error(error),
        };
        Self::connect_with_options(cx, options, MySqlMultiResultLimits::default()).await
    }

    /// Connect with explicit options and per-query aggregate limits.
    pub async fn connect_with_options(
        cx: &Cx,
        options: MySqlConnectOptions,
        limits: MySqlMultiResultLimits,
    ) -> Outcome<Self, MySqlError> {
        Self::connect_managed(
            cx,
            options,
            limits,
            false,
            #[cfg(feature = "tls")]
            None,
        )
        .await
    }

    /// Connect with explicit TLS trust roots, pins, or client identity.
    #[cfg(feature = "tls")]
    pub async fn connect_with_tls_connector(
        cx: &Cx,
        options: MySqlConnectOptions,
        limits: MySqlMultiResultLimits,
        connector: TlsConnector,
    ) -> Outcome<Self, MySqlError> {
        Self::connect_managed(cx, options, limits, false, Some(connector)).await
    }

    async fn connect_managed(
        cx: &Cx,
        options: MySqlConnectOptions,
        limits: MySqlMultiResultLimits,
        capture_pool_session: bool,
        #[cfg(feature = "tls")] connector: Option<TlsConnector>,
    ) -> Outcome<Self, MySqlError> {
        #[cfg(feature = "tls")]
        if connector.is_some() && options.ssl_mode == SslMode::Disabled {
            return Outcome::Err(MySqlError::InvalidParameter(
                "an explicit TLS connector requires ssl-mode=preferred or required".to_string(),
            ));
        }
        let connected = MySqlConnection::connect_bounded_with_capabilities(
            cx,
            options,
            capture_pool_session,
            MULTI_RESULT_CAPABILITIES,
            #[cfg(feature = "tls")]
            connector,
        )
        .await;
        Self::from_connected(connected, limits)
    }

    fn from_connected(
        connected: Outcome<MySqlConnection, MySqlError>,
        limits: MySqlMultiResultLimits,
    ) -> Outcome<Self, MySqlError> {
        match connected {
            Outcome::Ok(connection) => {
                if connection.inner.capabilities & MULTI_RESULT_CAPABILITIES
                    != MULTI_RESULT_CAPABILITIES
                {
                    return Outcome::Err(MySqlError::Protocol(
                        "server did not negotiate text and prepared multi-result support".to_string(),
                    ));
                }
                Outcome::Ok(Self { connection, limits })
            }
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    #[cfg(test)]
    pub(super) fn from_connection_for_test(
        connection: MySqlConnection,
        limits: MySqlMultiResultLimits,
    ) -> Self {
        Self { connection, limits }
    }

    /// Whether this session has closed or become unusable after an abandoned exchange.
    #[must_use]
    pub fn is_closed(&self) -> bool { self.connection.inner.closed }

    /// The limits applied independently to each query.
    #[must_use]
    pub const fn limits(&self) -> MySqlMultiResultLimits { self.limits }

    /// Prepare a statement using this session's existing bounded statement cache.
    pub async fn prepare(&mut self, cx: &Cx, sql: &str) -> Outcome<MySqlStatement, MySqlError> {
        self.connection.prepare(cx, sql).await
    }

    /// Run static SQL through the ordinary static-SQL validation policy.
    pub async fn query_static_sql(
        &mut self,
        cx: &Cx,
        sql: &str,
    ) -> Outcome<Vec<MySqlResultSet>, MySqlError> {
        if let Err(error) = self.connection.validate_sql_security(sql) {
            return outcome_from_error(error);
        }
        self.query_trusted_sql(cx, sql).await
    }

    /// Read all results of one statement supplied entirely by the application.
    ///
    /// No parameterization or SQL heuristic is applied. Bind untrusted values
    /// through [`Self::query_params`] or [`Self::query_prepared`]. Multiple SQL
    /// statements separated by semicolons are not enabled by this connection.
    pub async fn query_trusted_sql(
        &mut self,
        cx: &Cx,
        sql: &str,
    ) -> Outcome<Vec<MySqlResultSet>, MySqlError> {
        let mut reader = match self.begin_text(cx, sql, None).await {
            Outcome::Ok(reader) => reader,
            other => return other.map(|_| Vec::new()),
        };
        let result = self.collect(cx, &mut reader).await;
        self.finish_exchange(cx, result_outcome(result)).await
    }

    /// Stream validated static SQL, exposing each result's metadata and rows.
    pub async fn query_stream_static_sql<'a>(
        &'a mut self,
        cx: &Cx,
        sql: &str,
        config: MySqlMultiResultStreamConfig,
    ) -> Outcome<MySqlMultiResultStream<'a>, MySqlError> {
        if let Err(error) = self.connection.validate_sql_security(sql) {
            return outcome_from_error(error);
        }
        self.query_stream_trusted_sql(cx, sql, config).await
    }

    /// Stream one application-supplied statement without SQL heuristics.
    ///
    /// Bind untrusted values through [`Self::query_stream_params`] or
    /// [`Self::query_stream_prepared`]. The borrow lasts until the stream is
    /// finished, aborted, or dropped; no other command can interleave.
    pub async fn query_stream_trusted_sql<'a>(
        &'a mut self,
        cx: &Cx,
        sql: &str,
        config: MySqlMultiResultStreamConfig,
    ) -> Outcome<MySqlMultiResultStream<'a>, MySqlError> {
        match self.begin_text(cx, sql, Some(config)).await {
            Outcome::Ok(reader) => Outcome::Ok(MySqlMultiResultStream {
                connection: self,
                reader,
                read_in_progress: false,
                finished: false,
            }),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    async fn begin_text(
        &mut self,
        cx: &Cx,
        sql: &str,
        config: Option<MySqlMultiResultStreamConfig>,
    ) -> Outcome<ResponseReader, MySqlError> {
        if self.connection.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }
        // A pool can disable checkout validation. Finish any deferred reset
        // before flushing cached statements or claiming user-query ownership:
        // failed or abandoned reset I/O must close without issuing KILL QUERY.
        if let Err(error) = self.connection.reset_pooled_session(cx).await {
            return outcome_from_error(error);
        }
        if let Err(error) = self.connection.forget_prepared_statements_before(cx, sql).await {
            return outcome_from_error(error);
        }
        self.connection.inner.query_in_flight.store(true, std::sync::atomic::Ordering::Release);
        let setup = if MySqlConnection::is_session_control_statement(sql) {
            Outcome::Ok(())
        } else {
            self.connection.apply_statement_timeout(cx).await
        };
        match setup {
            Outcome::Ok(()) => {}
            Outcome::Err(error) => return self.finish_exchange(cx, Outcome::Err(error)).await,
            Outcome::Cancelled(reason) => return self.finish_exchange(cx, Outcome::Cancelled(reason)).await,
            Outcome::Panicked(payload) => return self.finish_exchange(cx, Outcome::Panicked(payload)).await,
        }
        let mut budget = ResultBudget::new(self.limits);
        match self.start_text(cx, sql, &mut budget, config).await {
            Ok(first) => Outcome::Ok(ResponseReader {
                budget,
                config,
                binary: false,
                statement_id: None,
                results_started: 0,
                state: ResponseState::Header(Some(first)),
            }),
            Err(error) => self.finish_exchange(cx, outcome_from_error(error)).await,
        }
    }

    async fn start_text(
        &mut self,
        cx: &Cx,
        sql: &str,
        budget: &mut ResultBudget,
        config: Option<MySqlMultiResultStreamConfig>,
    ) -> Result<Vec<u8>, MySqlError> {
        check_context(cx)?;
        self.connection.drain_abandoned_transaction(cx).await?;
        let mut packet = PacketBuffer::new();
        packet.set_sequence(0);
        packet.write_byte(command::COM_QUERY);
        packet.write_bytes(sql.as_bytes());
        let packet = packet.build_packet();
        self.connection.inner.closed = true;
        self.connection.write_all(Some(cx), &packet.bytes).await?;
        self.connection.inner.sequence = packet.next_sequence;
        self.read_response_packet(cx, budget, config).await
    }

    /// Execute a statement prepared on this connection and consume all results.
    /// Statement connection/checkout ownership and parameter counts are checked
    /// by the same admission path as ordinary prepared queries.
    pub async fn query_prepared(
        &mut self,
        cx: &Cx,
        statement: &MySqlStatement,
        params: &[&dyn ToSql],
    ) -> Outcome<Vec<MySqlResultSet>, MySqlError> {
        let mut reader = match self.begin_prepared(cx, statement, params, None).await {
            Outcome::Ok(reader) => reader,
            other => return other.map(|_| Vec::new()),
        };
        let result = self.collect(cx, &mut reader).await;
        self.finish_exchange(cx, result_outcome(result)).await
    }

    /// Stream binary rows from a prepared statement owned by this session.
    ///
    /// Parameter values and the statement are consumed during admission; the
    /// returned stream borrows only the connection. OUT/INOUT result metadata
    /// and the closing CALL status are exposed in their wire order.
    pub async fn query_stream_prepared<'a>(
        &'a mut self,
        cx: &Cx,
        statement: &MySqlStatement,
        params: &[&dyn ToSql],
        config: MySqlMultiResultStreamConfig,
    ) -> Outcome<MySqlMultiResultStream<'a>, MySqlError> {
        match self.begin_prepared(cx, statement, params, Some(config)).await {
            Outcome::Ok(reader) => Outcome::Ok(MySqlMultiResultStream {
                connection: self,
                reader,
                read_in_progress: false,
                finished: false,
            }),
            Outcome::Err(error) => Outcome::Err(error),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    async fn begin_prepared(
        &mut self,
        cx: &Cx,
        statement: &MySqlStatement,
        params: &[&dyn ToSql],
        config: Option<MySqlMultiResultStreamConfig>,
    ) -> Outcome<ResponseReader, MySqlError> {
        if self.connection.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }
        // Match ordinary prepared-query admission: session reset precedes
        // checkout-epoch checks, parameter handling, and in-flight ownership.
        if let Err(error) = self.connection.reset_pooled_session(cx).await {
            return outcome_from_error(error);
        }
        self.connection.inner.query_in_flight.store(true, std::sync::atomic::Ordering::Release);
        let mut budget = ResultBudget::new(self.limits);
        let allowance = budget.packet_allowance(config);
        let mut remaining = allowance;
        let started = self.connection.start_prepared_query_with_budget(
            cx, statement, params, 0, Some(&mut remaining),
        ).await;
        budget.wire_bytes -= allowance - remaining;
        match started {
            Outcome::Ok(first) => match self.check_response_packet(first) {
                Ok(first) => Outcome::Ok(ResponseReader {
                    budget,
                    config,
                    binary: true,
                    statement_id: Some(statement.statement_id),
                    results_started: 0,
                    state: ResponseState::Header(Some(first)),
                }),
                Err(error) => self.finish_exchange(cx, outcome_from_error(error)).await,
            },
            other => {
                let result = other.map(|first| ResponseReader {
                    budget,
                    config,
                    binary: true,
                    statement_id: Some(statement.statement_id),
                    results_started: 0,
                    state: ResponseState::Header(Some(first)),
                });
                self.finish_exchange(cx, result).await
            }
        }
    }

    /// Prepare and stream a parameterized statement, including `CALL proc(?)`.
    pub async fn query_stream_params<'a>(
        &'a mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
        config: MySqlMultiResultStreamConfig,
    ) -> Outcome<MySqlMultiResultStream<'a>, MySqlError> {
        let statement = match self.prepare(cx, sql).await {
            Outcome::Ok(statement) => statement,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        self.query_stream_prepared(cx, &statement, params, config).await
    }

    /// Prepare and execute a parameterized statement, including `CALL proc(?)`.
    pub async fn query_params(
        &mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Outcome<Vec<MySqlResultSet>, MySqlError> {
        let statement = match self.prepare(cx, sql).await {
            Outcome::Ok(statement) => statement,
            Outcome::Err(error) => return Outcome::Err(error),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        self.query_prepared(cx, &statement, params).await
    }

    /// Close and consume the session, including a previously poisoned transport.
    pub async fn close(mut self) -> Result<(), MySqlError> {
        self.connection.close().await
    }

    async fn finish_exchange<T>(
        &mut self,
        cx: &Cx,
        result: Outcome<T, MySqlError>,
    ) -> Outcome<T, MySqlError> {
        if !matches!(&result, Outcome::Ok(_)) && self.connection.inner.closed {
            // Bounds and malformed input are also unfinished exchanges. Keep
            // KILL ownership until bounded cleanup closes the transport.
            self.connection.wire_cancel_in_drain(cx).await;
        }
        self.connection.inner.query_in_flight.store(false, std::sync::atomic::Ordering::Release);
        result
    }

    async fn read_response_packet(
        &mut self,
        cx: &Cx,
        budget: &mut ResultBudget,
        config: Option<MySqlMultiResultStreamConfig>,
    ) -> Result<Vec<u8>, MySqlError> {
        // The existing packet reader checks every fragment's declared length
        // before allocation. A local allowance enforces both a per-packet and
        // an aggregate cap without changing ordinary connection behavior.
        let allowance = budget.packet_allowance(config);
        let mut remaining = allowance;
        let packet = self.connection
            .read_packet_with_budget(Some(cx), Some(&mut remaining)).await;
        budget.wire_bytes -= allowance - remaining;
        let (data, sequence) = packet?;
        self.connection.inner.sequence = sequence.wrapping_add(1);
        self.check_response_packet(data)
    }

    fn check_response_packet(&mut self, data: Vec<u8>) -> Result<Vec<u8>, MySqlError> {
        if data.is_empty() {
            return Err(MySqlError::InvalidPacket("empty multi-result packet".to_string()));
        }
        if data[0] == 0xff {
            let error = MySqlConnection::parse_error(&data);
            if matches!(&error, MySqlError::Server { .. }) {
                self.connection.inner.closed = false;
            }
            return Err(error);
        }
        Ok(data)
    }

    async fn collect(
        &mut self,
        cx: &Cx,
        reader: &mut ResponseReader,
    ) -> Result<Vec<MySqlResultSet>, MySqlError> {
        let mut results = Vec::new();
        let mut current: Option<MySqlResultSet> = None;
        while let Some(event) = self.read_result_event(cx, reader).await? {
            match event {
                MySqlMultiResultEvent::Columns(metadata) => {
                    current = Some(MySqlResultSet {
                        columns: metadata.columns,
                        rows: Vec::new(),
                        command_result: None,
                        metadata_status_flags: metadata.status_flags,
                        status_flags: 0,
                    });
                }
                MySqlMultiResultEvent::Row(row) => {
                    let result = current.as_mut().ok_or_else(|| MySqlError::Protocol(
                        "multi-result row without metadata".to_string(),
                    ))?;
                    result.rows.push(row);
                }
                MySqlMultiResultEvent::Complete(completion) => {
                    let mut result = current.take().unwrap_or_else(|| MySqlResultSet {
                        columns: Arc::new(Vec::new()),
                        rows: Vec::new(),
                        command_result: completion.command_result,
                        metadata_status_flags: completion.metadata_status_flags,
                        status_flags: completion.status_flags,
                    });
                    result.status_flags = completion.status_flags;
                    results.push(result);
                }
            }
        }
        Ok(results)
    }

    async fn read_result_event(
        &mut self,
        cx: &Cx,
        reader: &mut ResponseReader,
    ) -> Result<Option<MySqlMultiResultEvent>, MySqlError> {
        // Once a terminal packet has been consumed, cancellation must not
        // replace its result during the collector's final iteration.
        if reader.is_finished() {
            return Ok(None);
        }
        check_context(cx)?;
        let state = std::mem::replace(&mut reader.state, ResponseState::Finished);
        match state {
            ResponseState::Header(first) => {
                if reader.results_started >= self.limits.max_result_sets {
                    return Err(MySqlError::Protocol("multi-result result-set limit exceeded".to_string()));
                }
                let first = match first {
                    Some(first) => first,
                    None => self.read_response_packet(cx, &mut reader.budget, reader.config).await?,
                };
                // Preserve the collector's aggregate bookkeeping charge even
                // when a stream immediately releases each completed result.
                reader.budget.charge_storage(4 * std::mem::size_of::<MySqlResultSet>() + 64)?;
                let index = reader.results_started;
                reader.results_started += 1;
                if first.first() == Some(&0x00) {
                    let ok = MySqlConnection::parse_ok_packet(&first)?;
                    return self.complete_result(cx, reader, MySqlResultSetCompletion {
                        index,
                        row_count: 0,
                        command_result: Some(MySqlExecResult {
                            affected_rows: ok.affected_rows,
                            last_insert_id: ok.last_insert_id,
                        }),
                        metadata_status_flags: 0,
                        status_flags: ok.status_flags,
                    }).await.map(Some);
                }
                if first.first() == Some(&0xfb) {
                    return Err(MySqlError::Protocol("LOAD DATA LOCAL INFILE remains disabled".to_string()));
                }
                let mut packet = PacketReader::new(&first);
                let count = packet.read_lenenc_int()?;
                if count == 0 || count > MAX_COLUMN_COUNT || packet.remaining() != 0 {
                    return Err(MySqlError::InvalidPacket("invalid multi-result column count".to_string()));
                }
                let count = count as usize;
                let mut metadata_bytes = 0;
                reader.charge_metadata(
                    &mut metadata_bytes,
                    count.saturating_mul(std::mem::size_of::<MySqlColumn>() + 64),
                )?;
                let mut columns = Vec::with_capacity(count);
                let mut indices = BTreeMap::new();
                for column_index in 0..count {
                    let data = self.read_response_packet(cx, &mut reader.budget, reader.config).await?;
                    reader.charge_metadata(&mut metadata_bytes, data.len().saturating_mul(2))?;
                    let column = MySqlConnection::parse_column_definition(&data)?;
                    indices.entry(column.name.clone()).or_insert(column_index);
                    columns.push(column);
                }
                let columns = Arc::new(columns);
                let metadata_status_flags = if self.deprecate_eof() {
                    0
                } else {
                    let eof = self.read_response_packet(cx, &mut reader.budget, reader.config).await?;
                    MySqlConnection::parse_eof_packet_status_flags(&eof)?
                };
                reader.state = ResponseState::Rows(ActiveRows {
                    index,
                    columns: Arc::clone(&columns),
                    indices: Arc::new(indices),
                    metadata_status_flags,
                    rows: 0,
                });
                Ok(Some(MySqlMultiResultEvent::Columns(MySqlResultSetMetadata {
                    index,
                    columns,
                    status_flags: metadata_status_flags,
                })))
            }
            ResponseState::Rows(mut rows) => {
                let data = self.read_response_packet(cx, &mut reader.budget, reader.config).await?;
                let deprecate_eof = self.deprecate_eof();
                let max_rows_per_result = self.connection.inner.max_result_rows.min(self.limits.max_rows);
                let values = if MySqlConnection::is_eof_packet(&data) {
                    None
                } else {
                    // Legacy EOF distinguishes a row before decoding. Keep
                    // the existing ambiguous OK/row parser for future profiles.
                    if !deprecate_eof {
                        reader.check_row_count(rows.rows, max_rows_per_result)?;
                    }
                    if reader.binary {
                        MySqlConnection::parse_binary_row_or_terminator(&data, &rows.columns, deprecate_eof)?
                    } else {
                        MySqlConnection::parse_data_row_or_terminator(&data, &rows.columns, deprecate_eof)?
                    }
                };
                if let Some(values) = values {
                    reader.check_row_count(rows.rows, max_rows_per_result)?;
                    let storage_bytes = ResultBudget::row_storage_bytes(&values);
                    if reader.config.is_some_and(|config| storage_bytes > config.max_row_bytes) {
                        return Err(MySqlError::Protocol("multi-result stream row byte limit exceeded".to_string()));
                    }
                    reader.budget.charge_storage(storage_bytes)?;
                    reader.budget.rows -= 1;
                    rows.rows += 1;
                    let row = MySqlRow {
                        columns: Arc::clone(&rows.columns),
                        column_indices: Arc::clone(&rows.indices),
                        values,
                    };
                    reader.state = ResponseState::Rows(rows);
                    Ok(Some(MySqlMultiResultEvent::Row(row)))
                } else {
                    let status_flags = MySqlConnection::parse_result_set_terminator_status_flags(&data)?;
                    self.complete_result(cx, reader, MySqlResultSetCompletion {
                        index: rows.index,
                        row_count: rows.rows,
                        command_result: None,
                        metadata_status_flags: rows.metadata_status_flags,
                        status_flags,
                    }).await.map(Some)
                }
            }
            ResponseState::Finished => Ok(None),
        }
    }

    async fn complete_result(
        &mut self,
        cx: &Cx,
        reader: &mut ResponseReader,
        completion: MySqlResultSetCompletion,
    ) -> Result<MySqlMultiResultEvent, MySqlError> {
        self.connection.inner.status_flags = completion.status_flags;
        if completion.has_more_results() {
            if reader.results_started >= self.limits.max_result_sets {
                return Err(MySqlError::Protocol("multi-result result-set limit exceeded".to_string()));
            }
            reader.state = ResponseState::Header(None);
        } else {
            reader.state = ResponseState::Finished;
            self.connection.inner.closed = false;
            if let Some(statement_id) = reader.statement_id {
                self.connection.forget_prepared_statements_after(cx, statement_id).await?;
            }
        }
        Ok(MySqlMultiResultEvent::Complete(completion))
    }

    fn deprecate_eof(&self) -> bool {
        self.connection.inner.capabilities & capability::CLIENT_DEPRECATE_EOF != 0
    }
}

struct ResponseReader {
    budget: ResultBudget,
    config: Option<MySqlMultiResultStreamConfig>,
    binary: bool,
    statement_id: Option<u32>,
    results_started: usize,
    state: ResponseState,
}

enum ResponseState {
    Header(Option<Vec<u8>>),
    Rows(ActiveRows),
    Finished,
}

struct ActiveRows {
    index: usize,
    columns: Arc<Vec<MySqlColumn>>,
    indices: Arc<BTreeMap<String, usize>>,
    metadata_status_flags: u16,
    rows: usize,
}

impl ResponseReader {
    fn is_finished(&self) -> bool {
        matches!(&self.state, ResponseState::Finished)
    }

    fn charge_metadata(&mut self, current: &mut usize, bytes: usize) -> Result<(), MySqlError> {
        let total = current.saturating_add(bytes);
        if self.config.is_some_and(|config| total > config.max_metadata_bytes) {
            return Err(MySqlError::Protocol("multi-result stream metadata byte limit exceeded".to_string()));
        }
        self.budget.charge_storage(bytes)?;
        *current = total;
        Ok(())
    }

    fn check_row_count(&self, rows: usize, per_result_limit: usize) -> Result<(), MySqlError> {
        if self.budget.rows == 0 {
            return Err(MySqlError::Protocol("multi-result aggregate row limit exceeded".to_string()));
        }
        if rows >= per_result_limit {
            return Err(MySqlError::Protocol("multi-result per-result row limit exceeded".to_string()));
        }
        Ok(())
    }
}

struct ResultBudget {
    wire_bytes: usize,
    storage_bytes: usize,
    rows: usize,
}

impl ResultBudget {
    fn new(limits: MySqlMultiResultLimits) -> Self {
        Self { wire_bytes: limits.max_bytes, storage_bytes: limits.max_bytes, rows: limits.max_rows }
    }

    fn packet_allowance(&self, config: Option<MySqlMultiResultStreamConfig>) -> usize {
        config.map_or(self.wire_bytes, |config| self.wire_bytes.min(config.max_packet_bytes))
    }

    fn charge_storage(&mut self, bytes: usize) -> Result<(), MySqlError> {
        self.storage_bytes = self.storage_bytes.checked_sub(bytes).ok_or_else(|| {
            MySqlError::Protocol("multi-result decoded byte limit exceeded".to_string())
        })?;
        Ok(())
    }

    fn row_storage_bytes(values: &Vec<MySqlValue>) -> usize {
        // Binary temporal values and unsigned BIGINTs can expand into text
        // longer than their wire representation. Charge retained capacities,
        // including the value Vec, rather than assuming payload size bounds it.
        let values_bytes = values.capacity().saturating_mul(std::mem::size_of::<MySqlValue>());
        let heap_bytes = values.iter().fold(0_usize, |bytes, value| {
            bytes.saturating_add(match value {
                MySqlValue::Text(text) => text.capacity(),
                MySqlValue::Bytes(bytes) => bytes.capacity(),
                _ => 0,
            })
        });
        values_bytes.saturating_add(heap_bytes)
            .saturating_add(4 * std::mem::size_of::<MySqlRow>())
    }
}

fn check_context(cx: &Cx) -> Result<(), MySqlError> {
    cx.checkpoint().map_err(|_| MySqlError::Cancelled(
        cx.cancel_reason().unwrap_or_else(|| CancelReason::user("multi-result query cancelled")),
    ))
}

fn result_outcome<T>(result: Result<T, MySqlError>) -> Outcome<T, MySqlError> {
    match result {
        Ok(value) => Outcome::Ok(value),
        Err(error) => outcome_from_error(error),
    }
}
