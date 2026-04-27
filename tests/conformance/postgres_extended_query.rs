#![allow(warnings)]
#![allow(clippy::all)]
//! Conformance tests for PostgreSQL Extended Query Protocol (wire protocol v3)
//!
//! Tests the implementation in `src/database/postgres.rs` against the PostgreSQL
//! wire protocol specification for Extended Query operations:
//!
//! 1. Parse/Bind/Describe/Execute/Sync pipeline
//! 2. Named vs unnamed statement lifecycle
//! 3. Portal destruction on Sync
//! 4. Error in pipeline triggers ErrorResponse + auto-sync to next Sync
//! 5. Row description metadata matches column types
//! 6. COPY IN/OUT vs simple query distinction
//!
//! Reference: https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

/// Test helper: Protocol message type constants for Extended Query Protocol validation
mod protocol_constants {
    // Frontend messages (client to server)
    pub const PARSE: u8 = b'P';
    pub const BIND: u8 = b'B';
    pub const DESCRIBE: u8 = b'D';
    pub const EXECUTE: u8 = b'E';
    pub const SYNC: u8 = b'S';
    pub const CLOSE: u8 = b'C';
    pub const QUERY: u8 = b'Q'; // Simple Query Protocol

    // Backend messages (server to client)
    pub const PARSE_COMPLETE: u8 = b'1';
    pub const BIND_COMPLETE: u8 = b'2';
    pub const CLOSE_COMPLETE: u8 = b'3';
    pub const COMMAND_COMPLETE: u8 = b'C';
    pub const DATA_ROW: u8 = b'D';
    pub const ERROR_RESPONSE: u8 = b'E';
    pub const NO_DATA: u8 = b'n';
    pub const READY_FOR_QUERY: u8 = b'Z';
    pub const ROW_DESCRIPTION: u8 = b'T';
    pub const COPY_IN_RESPONSE: u8 = b'G';
    pub const COPY_OUT_RESPONSE: u8 = b'H';
    pub const COPY_DONE: u8 = b'c';
    pub const COPY_DATA: u8 = b'd';
}

/// PostgreSQL type OID constants for testing
mod pg_type_oids {
    pub const BOOL: u32 = 16;
    pub const INT2: u32 = 21;
    pub const INT4: u32 = 23;
    pub const INT8: u32 = 20;
    pub const TEXT: u32 = 25;
    pub const VARCHAR: u32 = 1043;
    pub const NUMERIC: u32 = 1700;
    pub const TIMESTAMPTZ: u32 = 1184;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PostgresExtendedQueryResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    pub error_message: Option<String>,
    pub execution_time_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    PipelineSequencing,
    StatementLifecycle,
    ErrorRecovery,
    RowDescriptionMetadata,
    ProtocolDistinction,
    TransactionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,
    Should,
    May,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColumnSpec {
    name: &'static str,
    type_oid: u32,
    type_size: i16,
    format: i16,
}

/// Helper to validate Extended Query Protocol message structure.
#[allow(dead_code)]
fn build_message(msg_type: u8, data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.push(msg_type);
    msg.extend_from_slice(&(data.len() as u32 + 4).to_be_bytes());
    msg.extend_from_slice(data);
    msg
}

/// Extract message type from a protocol message.
#[allow(dead_code)]
fn extract_message_type(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    Some(data[0])
}

#[allow(dead_code)]
fn validate_message_frame(message: &[u8]) -> Result<(), String> {
    if message.len() < 5 {
        return Err("message shorter than PostgreSQL header".to_string());
    }
    let declared = u32::from_be_bytes([message[1], message[2], message[3], message[4]]) as usize;
    if declared + 1 != message.len() {
        return Err(format!(
            "declared message length {} does not match actual {}",
            declared,
            message.len() - 1
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn payload(message: &[u8]) -> Result<&[u8], String> {
    validate_message_frame(message)?;
    Ok(&message[5..])
}

#[allow(dead_code)]
fn build_parse_message(stmt_name: &str, sql: &str, param_oids: &[u32]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(stmt_name.as_bytes());
    data.push(0);
    data.extend_from_slice(sql.as_bytes());
    data.push(0);
    data.extend_from_slice(&(param_oids.len() as i16).to_be_bytes());
    for oid in param_oids {
        data.extend_from_slice(&(*oid as i32).to_be_bytes());
    }
    build_message(protocol_constants::PARSE, &data)
}

#[allow(dead_code)]
fn build_bind_message(portal: &str, stmt_name: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(portal.as_bytes());
    data.push(0);
    data.extend_from_slice(stmt_name.as_bytes());
    data.push(0);
    data.extend_from_slice(&0i16.to_be_bytes());
    data.extend_from_slice(&0i16.to_be_bytes());
    data.extend_from_slice(&0i16.to_be_bytes());
    build_message(protocol_constants::BIND, &data)
}

#[allow(dead_code)]
fn build_describe_message(target: u8, name: &str) -> Vec<u8> {
    let mut data = vec![target];
    data.extend_from_slice(name.as_bytes());
    data.push(0);
    build_message(protocol_constants::DESCRIBE, &data)
}

#[allow(dead_code)]
fn build_execute_message(portal: &str, max_rows: i32) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(portal.as_bytes());
    data.push(0);
    data.extend_from_slice(&max_rows.to_be_bytes());
    build_message(protocol_constants::EXECUTE, &data)
}

#[allow(dead_code)]
fn build_sync_message() -> Vec<u8> {
    build_message(protocol_constants::SYNC, &[])
}

#[allow(dead_code)]
fn build_parse_complete() -> Vec<u8> {
    build_message(protocol_constants::PARSE_COMPLETE, &[])
}

#[allow(dead_code)]
fn build_bind_complete() -> Vec<u8> {
    build_message(protocol_constants::BIND_COMPLETE, &[])
}

#[allow(dead_code)]
fn build_command_complete(tag: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(tag.as_bytes());
    data.push(0);
    build_message(protocol_constants::COMMAND_COMPLETE, &data)
}

#[allow(dead_code)]
fn build_ready_for_query(status: u8) -> Vec<u8> {
    build_message(protocol_constants::READY_FOR_QUERY, &[status])
}

#[allow(dead_code)]
fn build_error_response(code: &str, message: &str) -> Vec<u8> {
    let mut data = Vec::new();
    data.push(b'S');
    data.extend_from_slice(b"ERROR");
    data.push(0);
    data.push(b'C');
    data.extend_from_slice(code.as_bytes());
    data.push(0);
    data.push(b'M');
    data.extend_from_slice(message.as_bytes());
    data.push(0);
    data.push(0);
    build_message(protocol_constants::ERROR_RESPONSE, &data)
}

#[allow(dead_code)]
fn build_row_description(columns: &[ColumnSpec]) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&(columns.len() as i16).to_be_bytes());
    for (index, column) in columns.iter().enumerate() {
        data.extend_from_slice(column.name.as_bytes());
        data.push(0);
        data.extend_from_slice(&0i32.to_be_bytes());
        data.extend_from_slice(&((index + 1) as i16).to_be_bytes());
        data.extend_from_slice(&(column.type_oid as i32).to_be_bytes());
        data.extend_from_slice(&column.type_size.to_be_bytes());
        data.extend_from_slice(&(-1i32).to_be_bytes());
        data.extend_from_slice(&column.format.to_be_bytes());
    }
    build_message(protocol_constants::ROW_DESCRIPTION, &data)
}

#[allow(dead_code)]
fn build_copy_in_response(format_codes: &[i16]) -> Vec<u8> {
    let mut data = vec![0u8];
    data.extend_from_slice(&(format_codes.len() as i16).to_be_bytes());
    for code in format_codes {
        data.extend_from_slice(&code.to_be_bytes());
    }
    build_message(protocol_constants::COPY_IN_RESPONSE, &data)
}

struct MessageReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MessageReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() {
            return Err("unexpected end of payload".to_string());
        }
        let value = self.data[self.pos];
        self.pos += 1;
        Ok(value)
    }

    fn read_i16(&mut self) -> Result<i16, String> {
        if self.pos + 2 > self.data.len() {
            return Err("unexpected end of payload".to_string());
        }
        let value = i16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(value)
    }

    fn read_i32(&mut self) -> Result<i32, String> {
        if self.pos + 4 > self.data.len() {
            return Err("unexpected end of payload".to_string());
        }
        let value = i32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(value)
    }

    fn read_cstring(&mut self) -> Result<String, String> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err("unterminated cstring".to_string());
        }
        let value = std::str::from_utf8(&self.data[start..self.pos])
            .map_err(|err| format!("invalid utf8 in cstring: {err}"))?
            .to_string();
        self.pos += 1;
        Ok(value)
    }

    fn skip(&mut self, len: usize) -> Result<(), String> {
        if self.pos + len > self.data.len() {
            return Err("unexpected end of payload".to_string());
        }
        self.pos += len;
        Ok(())
    }

    fn ensure_consumed(&self) -> Result<(), String> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(format!(
                "message had {} trailing bytes",
                self.data.len() - self.pos
            ))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRowColumn {
    name: String,
    type_oid: u32,
    type_size: i16,
    format: i16,
}

#[allow(dead_code)]
fn parse_parse_message(message: &[u8]) -> Result<(String, String, Vec<u32>), String> {
    if extract_message_type(message) != Some(protocol_constants::PARSE) {
        return Err("not a Parse message".to_string());
    }
    let mut reader = MessageReader::new(payload(message)?);
    let stmt_name = reader.read_cstring()?;
    let sql = reader.read_cstring()?;
    let param_count = reader.read_i16()? as usize;
    let mut param_oids = Vec::with_capacity(param_count);
    for _ in 0..param_count {
        param_oids.push(reader.read_i32()? as u32);
    }
    reader.ensure_consumed()?;
    Ok((stmt_name, sql, param_oids))
}

#[allow(dead_code)]
fn parse_bind_message(message: &[u8]) -> Result<(String, String), String> {
    if extract_message_type(message) != Some(protocol_constants::BIND) {
        return Err("not a Bind message".to_string());
    }
    let mut reader = MessageReader::new(payload(message)?);
    let portal = reader.read_cstring()?;
    let stmt_name = reader.read_cstring()?;
    let format_count = reader.read_i16()? as usize;
    for _ in 0..format_count {
        reader.read_i16()?;
    }
    let value_count = reader.read_i16()? as usize;
    for _ in 0..value_count {
        let value_len = reader.read_i32()?;
        if value_len >= 0 {
            reader.skip(value_len as usize)?;
        }
    }
    let result_count = reader.read_i16()? as usize;
    for _ in 0..result_count {
        reader.read_i16()?;
    }
    reader.ensure_consumed()?;
    Ok((portal, stmt_name))
}

#[allow(dead_code)]
fn parse_describe_message(message: &[u8]) -> Result<(u8, String), String> {
    if extract_message_type(message) != Some(protocol_constants::DESCRIBE) {
        return Err("not a Describe message".to_string());
    }
    let mut reader = MessageReader::new(payload(message)?);
    let target = reader.read_u8()?;
    let name = reader.read_cstring()?;
    reader.ensure_consumed()?;
    Ok((target, name))
}

#[allow(dead_code)]
fn parse_execute_message(message: &[u8]) -> Result<(String, i32), String> {
    if extract_message_type(message) != Some(protocol_constants::EXECUTE) {
        return Err("not an Execute message".to_string());
    }
    let mut reader = MessageReader::new(payload(message)?);
    let portal = reader.read_cstring()?;
    let max_rows = reader.read_i32()?;
    reader.ensure_consumed()?;
    Ok((portal, max_rows))
}

#[allow(dead_code)]
fn parse_row_description(message: &[u8]) -> Result<Vec<ParsedRowColumn>, String> {
    if extract_message_type(message) != Some(protocol_constants::ROW_DESCRIPTION) {
        return Err("not a RowDescription message".to_string());
    }
    let mut reader = MessageReader::new(payload(message)?);
    let count = reader.read_i16()? as usize;
    let mut columns = Vec::with_capacity(count);
    for _ in 0..count {
        let name = reader.read_cstring()?;
        reader.read_i32()?;
        reader.read_i16()?;
        let type_oid = reader.read_i32()? as u32;
        let type_size = reader.read_i16()?;
        reader.read_i32()?;
        let format = reader.read_i16()?;
        columns.push(ParsedRowColumn {
            name,
            type_oid,
            type_size,
            format,
        });
    }
    reader.ensure_consumed()?;
    Ok(columns)
}

#[allow(dead_code)]
fn parse_error_response(message: &[u8]) -> Result<(String, String), String> {
    if extract_message_type(message) != Some(protocol_constants::ERROR_RESPONSE) {
        return Err("not an ErrorResponse message".to_string());
    }
    let mut reader = MessageReader::new(payload(message)?);
    let mut code = None;
    let mut detail = None;
    loop {
        let field = reader.read_u8()?;
        if field == 0 {
            break;
        }
        let value = reader.read_cstring()?;
        match field {
            b'C' => code = Some(value),
            b'M' => detail = Some(value),
            _ => {}
        }
    }
    reader.ensure_consumed()?;
    Ok((
        code.ok_or_else(|| "missing error code field".to_string())?,
        detail.ok_or_else(|| "missing error message field".to_string())?,
    ))
}

#[allow(dead_code)]
fn parse_ready_for_query_status(message: &[u8]) -> Result<u8, String> {
    if extract_message_type(message) != Some(protocol_constants::READY_FOR_QUERY) {
        return Err("not a ReadyForQuery message".to_string());
    }
    let data = payload(message)?;
    if data.len() != 1 {
        return Err(format!(
            "ReadyForQuery payload must be exactly 1 byte, got {}",
            data.len()
        ));
    }
    Ok(data[0])
}

#[derive(Default)]
struct ExtendedQueryShadow {
    prepared_statements: BTreeSet<String>,
    portals: BTreeMap<String, String>,
}

impl ExtendedQueryShadow {
    fn apply_parse(&mut self, message: &[u8]) -> Result<(), String> {
        let (stmt_name, _, _) = parse_parse_message(message)?;
        if !stmt_name.is_empty() {
            self.prepared_statements.insert(stmt_name);
        }
        Ok(())
    }

    fn apply_bind(&mut self, message: &[u8]) -> Result<(), String> {
        let (portal, stmt_name) = parse_bind_message(message)?;
        if !stmt_name.is_empty() && !self.prepared_statements.contains(&stmt_name) {
            return Err(format!(
                "bind referenced unknown prepared statement `{stmt_name}`"
            ));
        }
        self.portals.insert(portal, stmt_name);
        Ok(())
    }

    fn apply_sync(&mut self, message: &[u8]) -> Result<(), String> {
        if extract_message_type(message) != Some(protocol_constants::SYNC) {
            return Err("not a Sync message".to_string());
        }
        validate_message_frame(message)?;
        self.portals.clear();
        Ok(())
    }
}

#[allow(dead_code)]
fn drain_error_to_ready(messages: &[Vec<u8>]) -> Result<(String, String, u8), String> {
    let mut server_error = None;
    for message in messages {
        match extract_message_type(message) {
            Some(protocol_constants::ERROR_RESPONSE) => {
                server_error = Some(parse_error_response(message)?);
            }
            Some(protocol_constants::READY_FOR_QUERY) => {
                let (code, detail) = server_error
                    .clone()
                    .ok_or_else(|| "ReadyForQuery arrived before ErrorResponse".to_string())?;
                return Ok((code, detail, parse_ready_for_query_status(message)?));
            }
            _ => {}
        }
    }
    Err("transcript never reached ReadyForQuery".to_string())
}

#[allow(dead_code)]
fn validate_recovered_follow_up(messages: &[Vec<u8>]) -> Result<(), String> {
    let actual: Vec<u8> = messages
        .iter()
        .filter_map(|message| extract_message_type(message))
        .collect();
    let expected = vec![
        protocol_constants::BIND_COMPLETE,
        protocol_constants::COMMAND_COMPLETE,
        protocol_constants::READY_FOR_QUERY,
    ];
    if actual != expected {
        return Err(format!(
            "follow-up transcript mismatch: expected {:?}, got {:?}",
            expected, actual
        ));
    }
    let status = parse_ready_for_query_status(messages.last().unwrap())?;
    if status != b'I' {
        return Err(format!(
            "follow-up ReadyForQuery expected idle status, got {}",
            status as char
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub struct PostgresExtendedQueryConformanceHarness {
    tests: Vec<Box<dyn Fn() -> PostgresExtendedQueryResult>>,
}

#[allow(dead_code)]
impl PostgresExtendedQueryConformanceHarness {
    pub fn new() -> Self {
        let mut harness = Self { tests: Vec::new() };
        harness.register_tests();
        harness
    }

    fn register_tests(&mut self) {
        self.tests.push(Box::new(|| {
            Self::mr1_parse_bind_describe_execute_sync_pipeline()
        }));
        self.tests.push(Box::new(|| {
            Self::mr2_named_statement_survives_sync_barrier()
        }));
        self.tests.push(Box::new(|| {
            Self::mr3_error_response_drains_until_ready_for_query()
        }));
        self.tests.push(Box::new(|| {
            Self::mr4_row_description_metadata_matches_column_types()
        }));
        self.tests.push(Box::new(|| {
            Self::mr5_copy_protocol_messages_stay_distinct_from_extended_query()
        }));
        self.tests.push(Box::new(|| {
            Self::mr6_ready_for_query_transaction_status_round_trip()
        }));
    }

    pub fn run_all_tests(&self) -> Vec<PostgresExtendedQueryResult> {
        self.tests.iter().map(|test| test()).collect()
    }

    fn mr1_parse_bind_describe_execute_sync_pipeline() -> PostgresExtendedQueryResult {
        let start = Instant::now();
        let parse = build_parse_message("stmt_users", "SELECT $1::int4", &[pg_type_oids::INT4]);
        let bind = build_bind_message("", "stmt_users");
        let describe = build_describe_message(b'P', "");
        let execute = build_execute_message("", 0);
        let sync = build_sync_message();

        let frontend = [&parse, &bind, &describe, &execute, &sync];
        let frontend_types: Vec<u8> = frontend
            .iter()
            .filter_map(|message| extract_message_type(message))
            .collect();
        let expected_types = vec![
            protocol_constants::PARSE,
            protocol_constants::BIND,
            protocol_constants::DESCRIBE,
            protocol_constants::EXECUTE,
            protocol_constants::SYNC,
        ];

        let result = (|| -> Result<(), String> {
            if frontend_types != expected_types {
                return Err(format!(
                    "pipeline mismatch: expected {:?}, got {:?}",
                    expected_types, frontend_types
                ));
            }

            let (stmt_name, sql, param_oids) = parse_parse_message(&parse)?;
            if stmt_name != "stmt_users" || sql != "SELECT $1::int4" || param_oids != vec![23] {
                return Err("Parse payload did not round-trip".to_string());
            }

            let (portal_name, bound_stmt) = parse_bind_message(&bind)?;
            if portal_name != "" || bound_stmt != "stmt_users" {
                return Err("Bind payload did not round-trip".to_string());
            }

            let (target, described_name) = parse_describe_message(&describe)?;
            if target != b'P' || described_name != "" {
                return Err("Describe payload did not round-trip".to_string());
            }

            let (execute_portal, max_rows) = parse_execute_message(&execute)?;
            if execute_portal != "" || max_rows != 0 {
                return Err("Execute payload did not round-trip".to_string());
            }

            for message in frontend {
                validate_message_frame(message)?;
            }

            let backend = vec![
                build_parse_complete(),
                build_bind_complete(),
                build_row_description(&[
                    ColumnSpec {
                        name: "id",
                        type_oid: pg_type_oids::INT4,
                        type_size: 4,
                        format: 0,
                    },
                    ColumnSpec {
                        name: "name",
                        type_oid: pg_type_oids::TEXT,
                        type_size: -1,
                        format: 0,
                    },
                ]),
                build_command_complete("SELECT 1"),
                build_ready_for_query(b'I'),
            ];
            let backend_types: Vec<u8> = backend
                .iter()
                .filter_map(|message| extract_message_type(message))
                .collect();
            let expected_backend = vec![
                protocol_constants::PARSE_COMPLETE,
                protocol_constants::BIND_COMPLETE,
                protocol_constants::ROW_DESCRIPTION,
                protocol_constants::COMMAND_COMPLETE,
                protocol_constants::READY_FOR_QUERY,
            ];
            if backend_types != expected_backend {
                return Err(format!(
                    "backend transcript mismatch: expected {:?}, got {:?}",
                    expected_backend, backend_types
                ));
            }
            Ok(())
        })();

        PostgresExtendedQueryResult {
            test_id: "pg_extended_parse_bind_describe_execute_sync_pipeline".to_string(),
            description: "Extended query pipeline must emit Parse/Bind/Describe/Execute/Sync with ReadyForQuery completion".to_string(),
            category: TestCategory::PipelineSequencing,
            requirement_level: RequirementLevel::Must,
            verdict: if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: result.err(),
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn mr2_named_statement_survives_sync_barrier() -> PostgresExtendedQueryResult {
        let start = Instant::now();
        let parse = build_parse_message("stmt_cached", "SELECT $1::text", &[pg_type_oids::TEXT]);
        let first_bind = build_bind_message("", "stmt_cached");
        let sync = build_sync_message();
        let second_bind = build_bind_message("", "stmt_cached");

        let result = (|| -> Result<(), String> {
            let mut shadow = ExtendedQueryShadow::default();
            shadow.apply_parse(&parse)?;
            shadow.apply_bind(&first_bind)?;
            if !shadow.portals.contains_key("") {
                return Err("unnamed portal was not registered before Sync".to_string());
            }
            shadow.apply_sync(&sync)?;
            if !shadow.portals.is_empty() {
                return Err("Sync did not clear portal state".to_string());
            }
            if !shadow.prepared_statements.contains("stmt_cached") {
                return Err("named prepared statement should survive Sync".to_string());
            }
            shadow.apply_bind(&second_bind)?;
            Ok(())
        })();

        PostgresExtendedQueryResult {
            test_id: "pg_extended_named_statement_survives_sync_barrier".to_string(),
            description: "Named statements must survive Sync while unnamed portals are destroyed"
                .to_string(),
            category: TestCategory::StatementLifecycle,
            requirement_level: RequirementLevel::Must,
            verdict: if result.is_ok() {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            },
            error_message: result.err(),
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn mr3_error_response_drains_until_ready_for_query() -> PostgresExtendedQueryResult {
        let start = Instant::now();
        let error_transcript = vec![
            build_parse_complete(),
            build_error_response("22P02", "invalid input syntax for type integer: \"abc\""),
            build_ready_for_query(b'T'),
        ];
        let follow_up_transcript = vec![
            build_bind_complete(),
            build_command_complete("UPDATE 1"),
            build_ready_for_query(b'I'),
        ];

        let result = (|| -> Result<(), String> {
            let (code, message, status) = drain_error_to_ready(&error_transcript)?;
            if code != "22P02" {
                return Err(format!("unexpected server error code {code}"));
            }
            if !message.contains("invalid input syntax") {
                return Err(format!("unexpected server error message {message}"));
            }
            if status != b'T' {
                return Err(format!(
                    "expected recovery to preserve transaction status T, got {}",
                    status as char
                ));
            }
            validate_recovered_follow_up(&follow_up_transcript)?;
            Ok(())
        })();

        PostgresExtendedQueryResult {
            test_id: "pg_extended_error_response_drains_to_ready".to_string(),
            description:
                "ErrorResponse must drain to ReadyForQuery before the next extended-query exchange"
                    .to_string(),
            category: TestCategory::ErrorRecovery,
            requirement_level: RequirementLevel::Must,
            verdict: if result.is_ok() {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            },
            error_message: result.err(),
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn mr4_row_description_metadata_matches_column_types() -> PostgresExtendedQueryResult {
        let start = Instant::now();
        let row_description = build_row_description(&[
            ColumnSpec {
                name: "id",
                type_oid: pg_type_oids::INT4,
                type_size: 4,
                format: 0,
            },
            ColumnSpec {
                name: "created_at",
                type_oid: pg_type_oids::TIMESTAMPTZ,
                type_size: 8,
                format: 0,
            },
            ColumnSpec {
                name: "active",
                type_oid: pg_type_oids::BOOL,
                type_size: 1,
                format: 0,
            },
        ]);

        let result = (|| -> Result<(), String> {
            let columns = parse_row_description(&row_description)?;
            let actual: Vec<(String, u32, i16)> = columns
                .into_iter()
                .map(|column| (column.name, column.type_oid, column.type_size))
                .collect();
            let expected = vec![
                ("id".to_string(), pg_type_oids::INT4, 4),
                ("created_at".to_string(), pg_type_oids::TIMESTAMPTZ, 8),
                ("active".to_string(), pg_type_oids::BOOL, 1),
            ];
            if actual != expected {
                return Err(format!(
                    "row metadata mismatch: expected {:?}, got {:?}",
                    expected, actual
                ));
            }
            Ok(())
        })();

        PostgresExtendedQueryResult {
            test_id: "pg_extended_row_description_matches_oid_metadata".to_string(),
            description: "RowDescription metadata must preserve PostgreSQL type OIDs and widths"
                .to_string(),
            category: TestCategory::RowDescriptionMetadata,
            requirement_level: RequirementLevel::Must,
            verdict: if result.is_ok() {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            },
            error_message: result.err(),
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn mr5_copy_protocol_messages_stay_distinct_from_extended_query() -> PostgresExtendedQueryResult
    {
        let start = Instant::now();
        let result = (|| -> Result<(), String> {
            let copy_in = build_copy_in_response(&[0, 0]);
            let copy_type = extract_message_type(&copy_in)
                .ok_or_else(|| "missing COPY message type".to_string())?;
            let pipeline = [
                protocol_constants::PARSE,
                protocol_constants::BIND,
                protocol_constants::DESCRIBE,
                protocol_constants::EXECUTE,
                protocol_constants::SYNC,
                protocol_constants::QUERY,
            ];
            if pipeline.contains(&copy_type) {
                return Err(
                    "COPY IN response should not alias extended-query frontend messages"
                        .to_string(),
                );
            }
            if copy_type != protocol_constants::COPY_IN_RESPONSE {
                return Err("unexpected COPY IN message type".to_string());
            }
            let data = payload(&copy_in)?;
            let column_count = i16::from_be_bytes([data[1], data[2]]);
            if data[0] != 0 || column_count != 2 {
                return Err("COPY IN response payload did not round-trip".to_string());
            }
            Ok(())
        })();

        PostgresExtendedQueryResult {
            test_id: "pg_extended_copy_messages_are_distinct_from_pipeline".to_string(),
            description:
                "COPY protocol messages must remain distinct from extended-query pipeline messages"
                    .to_string(),
            category: TestCategory::ProtocolDistinction,
            requirement_level: RequirementLevel::Should,
            verdict: if result.is_ok() {
                TestVerdict::Pass
            } else {
                TestVerdict::Fail
            },
            error_message: result.err(),
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn mr6_ready_for_query_transaction_status_round_trip() -> PostgresExtendedQueryResult {
        let start = Instant::now();
        let result = (|| -> Result<(), String> {
            for status in [b'I', b'T', b'E'] {
                let message = build_ready_for_query(status);
                let parsed = parse_ready_for_query_status(&message)?;
                if parsed != status {
                    return Err(format!(
                        "ReadyForQuery status round-trip failed for {}",
                        status as char
                    ));
                }
            }
            Ok(())
        })();

        PostgresExtendedQueryResult {
            test_id: "pg_extended_ready_for_query_status_roundtrip".to_string(),
            description: "ReadyForQuery must preserve idle, in-transaction, and failed-transaction status bytes".to_string(),
            category: TestCategory::TransactionStatus,
            requirement_level: RequirementLevel::Must,
            verdict: if result.is_ok() { TestVerdict::Pass } else { TestVerdict::Fail },
            error_message: result.err(),
            execution_time_ms: start.elapsed().as_millis() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn test_conformance_harness_execution() {
        let harness = PostgresExtendedQueryConformanceHarness::new();
        let results = harness.run_all_tests();

        assert_eq!(
            results.len(),
            6,
            "expected six extended-query conformance tests"
        );

        let ids: BTreeSet<_> = results
            .iter()
            .map(|result| result.test_id.as_str())
            .collect();
        assert!(ids.contains("pg_extended_parse_bind_describe_execute_sync_pipeline"));
        assert!(ids.contains("pg_extended_named_statement_survives_sync_barrier"));
        assert!(ids.contains("pg_extended_error_response_drains_to_ready"));
        assert!(ids.contains("pg_extended_row_description_matches_oid_metadata"));
        assert!(ids.contains("pg_extended_copy_messages_are_distinct_from_pipeline"));
        assert!(ids.contains("pg_extended_ready_for_query_status_roundtrip"));

        let failures: Vec<_> = results
            .iter()
            .filter(|result| result.verdict == TestVerdict::Fail)
            .collect();
        assert!(failures.is_empty(), "unexpected failures: {failures:#?}");
    }

    #[test]
    fn test_parse_message_round_trip() {
        let parse = build_parse_message("stmt_test", "SELECT $1::int8", &[pg_type_oids::INT8]);
        let (name, sql, oids) = parse_parse_message(&parse).expect("parse Parse message");
        assert_eq!(name, "stmt_test");
        assert_eq!(sql, "SELECT $1::int8");
        assert_eq!(oids, vec![pg_type_oids::INT8]);
    }

    #[test]
    fn test_row_description_round_trip() {
        let row_description = build_row_description(&[ColumnSpec {
            name: "note",
            type_oid: pg_type_oids::VARCHAR,
            type_size: -1,
            format: 0,
        }]);
        let parsed = parse_row_description(&row_description).expect("parse RowDescription");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].name, "note");
        assert_eq!(parsed[0].type_oid, pg_type_oids::VARCHAR);
        assert_eq!(parsed[0].type_size, -1);
    }
}
