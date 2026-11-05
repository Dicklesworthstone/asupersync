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

    fn has_more_results(&self) -> bool {
        self.status_flags & SERVER_MORE_RESULTS_EXISTS != 0
            || (self.is_output_parameters()
                && self.metadata_status_flags & SERVER_MORE_RESULTS_EXISTS != 0)
    }
}

/// A dedicated connection that consumes complete MySQL multi-result responses.
///
/// This opt-in enables result-returning stored procedures, including prepared
/// CALL parameters, while ordinary [`MySqlConnection`] negotiation is unchanged.
/// `CLIENT_MULTI_STATEMENTS` and local-file requests remain disabled. There is
/// no conversion or mutable access to the inner single-result connection.
///
/// Results are returned only after every result and the final status have been
/// consumed. A terminal server ERR returns an error without partial results and
/// leaves framing synchronized. Cancellation, malformed input, or a limit
/// failure closes the session through the existing bounded KILL/close cleanup.
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
        let connected = MySqlConnection::connect_bounded_with_capabilities(
            cx,
            options,
            false,
            MULTI_RESULT_CAPABILITIES,
            #[cfg(feature = "tls")]
            None,
        ).await;
        Self::from_connected(connected, limits)
    }

    /// Connect with explicit TLS trust roots, pins, or client identity.
    #[cfg(feature = "tls")]
    pub async fn connect_with_tls_connector(
        cx: &Cx,
        options: MySqlConnectOptions,
        limits: MySqlMultiResultLimits,
        connector: TlsConnector,
    ) -> Outcome<Self, MySqlError> {
        if options.ssl_mode == SslMode::Disabled {
            return Outcome::Err(MySqlError::InvalidParameter(
                "an explicit TLS connector requires ssl-mode=preferred or required".to_string(),
            ));
        }
        let connected = MySqlConnection::connect_bounded_with_capabilities(
            cx, options, false, MULTI_RESULT_CAPABILITIES, Some(connector),
        ).await;
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
        if self.connection.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
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
        if !matches!(&setup, Outcome::Ok(())) {
            return self.finish_exchange(cx, setup.map(|()| Vec::new())).await;
        }
        let mut budget = ResultBudget::new(self.limits);
        let result = self.start_text(cx, sql, &mut budget).await;
        let result = match result {
            Ok(first) => self.collect(cx, first, false, &mut budget).await,
            Err(error) => Err(error),
        };
        self.finish_exchange(cx, result_outcome(result)).await
    }

    async fn start_text(
        &mut self,
        cx: &Cx,
        sql: &str,
        budget: &mut ResultBudget,
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
        self.read_response_packet(cx, budget).await
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
        if self.connection.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }
        self.connection.inner.query_in_flight.store(true, std::sync::atomic::Ordering::Release);
        let mut budget = ResultBudget::new(self.limits);
        let started = self.connection.start_prepared_query_with_budget(
            cx, statement, params, 0, Some(&mut budget.wire_bytes),
        ).await;
        let result = match started {
            Outcome::Ok(first) => {
                match self.collect(cx, first, true, &mut budget).await {
                    Ok(results) => self.connection
                        .forget_prepared_statements_after(cx, statement.statement_id)
                        .await.map(|()| results),
                    Err(error) => Err(error),
                }
            }
            other => return self.finish_exchange(cx, other.map(|_| Vec::new())).await,
        };
        self.finish_exchange(cx, result_outcome(result)).await
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
    ) -> Result<Vec<u8>, MySqlError> {
        let (data, sequence) = self.connection
            .read_packet_with_budget(Some(cx), Some(&mut budget.wire_bytes)).await?;
        self.connection.inner.sequence = sequence.wrapping_add(1);
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
        mut first: Vec<u8>,
        binary: bool,
        budget: &mut ResultBudget,
    ) -> Result<Vec<MySqlResultSet>, MySqlError> {
        let mut results = Vec::new();
        loop {
            check_context(cx)?;
            if first.first() == Some(&0xff) {
                let error = MySqlConnection::parse_error(&first);
                if matches!(&error, MySqlError::Server { .. }) {
                    self.connection.inner.closed = false;
                }
                return Err(error);
            }
            // Cover the result Vec's initial allocation and geometric growth,
            // plus the Arc/Vec header used even by an OK-only result.
            budget.charge_storage(4 * std::mem::size_of::<MySqlResultSet>() + 64)?;
            if results.len() >= self.limits.max_result_sets {
                return Err(MySqlError::Protocol("multi-result result-set limit exceeded".to_string()));
            }
            let result = if first.first() == Some(&0x00) {
                let ok = MySqlConnection::parse_ok_packet(&first)?;
                MySqlResultSet {
                    columns: Arc::new(Vec::new()),
                    rows: Vec::new(),
                    command_result: Some(MySqlExecResult {
                        affected_rows: ok.affected_rows,
                        last_insert_id: ok.last_insert_id,
                    }),
                    metadata_status_flags: 0,
                    status_flags: ok.status_flags,
                }
            } else {
                self.read_row_set(cx, &first, binary, budget).await?
            };
            self.connection.inner.status_flags = result.status_flags;
            let more = result.has_more_results();
            results.push(result);
            if !more {
                self.connection.inner.closed = false;
                return Ok(results);
            }
            if results.len() >= self.limits.max_result_sets {
                return Err(MySqlError::Protocol("multi-result result-set limit exceeded".to_string()));
            }
            first = self.read_response_packet(cx, budget).await?;
        }
    }

    async fn read_row_set(
        &mut self,
        cx: &Cx,
        first: &[u8],
        binary: bool,
        budget: &mut ResultBudget,
    ) -> Result<MySqlResultSet, MySqlError> {
        if first.first() == Some(&0xfb) {
            return Err(MySqlError::Protocol("LOAD DATA LOCAL INFILE remains disabled".to_string()));
        }
        let mut reader = PacketReader::new(first);
        let count = reader.read_lenenc_int()?;
        if count == 0 || count > MAX_COLUMN_COUNT || reader.remaining() != 0 {
            return Err(MySqlError::InvalidPacket("invalid multi-result column count".to_string()));
        }
        let count = count as usize;
        budget.charge_storage(count.saturating_mul(std::mem::size_of::<MySqlColumn>() + 64))?;
        let mut columns = Vec::with_capacity(count);
        let mut indices = BTreeMap::new();
        for index in 0..count {
            let data = self.read_response_packet(cx, budget).await?;
            budget.charge_storage(data.len().saturating_mul(2))?;
            let column = MySqlConnection::parse_column_definition(&data)?;
            indices.entry(column.name.clone()).or_insert(index);
            columns.push(column);
        }
        let columns = Arc::new(columns);
        let indices = Arc::new(indices);
        let deprecate_eof = self.connection.inner.capabilities & capability::CLIENT_DEPRECATE_EOF != 0;
        let metadata_status_flags = if deprecate_eof {
            0
        } else {
            let eof = self.read_response_packet(cx, budget).await?;
            MySqlConnection::parse_eof_packet_status_flags(&eof)?
        };
        let mut rows = Vec::new();
        let max_rows_per_result = self.connection.inner.max_result_rows.min(self.limits.max_rows);
        let status_flags = loop {
            let data = self.read_response_packet(cx, budget).await?;
            if MySqlConnection::is_eof_packet(&data) {
                break MySqlConnection::parse_eof_packet_status_flags(&data)?;
            }
            // The negotiated legacy-EOF profile distinguishes a row before
            // decoding it. Preserve the inherited ambiguous OK/row parser if
            // a future profile negotiates deprecated EOF instead.
            if !deprecate_eof && budget.rows == 0 {
                return Err(MySqlError::Protocol("multi-result aggregate row limit exceeded".to_string()));
            }
            if !deprecate_eof && rows.len() >= max_rows_per_result {
                return Err(MySqlError::Protocol("multi-result per-result row limit exceeded".to_string()));
            }
            let values = if binary {
                MySqlConnection::parse_binary_row_or_terminator(&data, &columns, deprecate_eof)?
            } else {
                MySqlConnection::parse_data_row_or_terminator(&data, &columns, deprecate_eof)?
            };
            let Some(values) = values else {
                break MySqlConnection::parse_result_set_terminator_status_flags(&data)?;
            };
            if budget.rows == 0 {
                return Err(MySqlError::Protocol("multi-result aggregate row limit exceeded".to_string()));
            }
            budget.rows -= 1;
            budget.charge_row(&values)?;
            self.connection.push_result_row(
                &mut rows, &columns, &indices, values, max_rows_per_result,
            )?;
        };
        Ok(MySqlResultSet {
            columns,
            rows,
            command_result: None,
            metadata_status_flags,
            status_flags,
        })
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

    fn charge_storage(&mut self, bytes: usize) -> Result<(), MySqlError> {
        self.storage_bytes = self.storage_bytes.checked_sub(bytes).ok_or_else(|| {
            MySqlError::Protocol("multi-result decoded byte limit exceeded".to_string())
        })?;
        Ok(())
    }

    fn charge_row(&mut self, values: &Vec<MySqlValue>) -> Result<(), MySqlError> {
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
        self.charge_storage(values_bytes.saturating_add(heap_bytes)
            .saturating_add(4 * std::mem::size_of::<MySqlRow>()))
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
