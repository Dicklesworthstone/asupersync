#![allow(warnings)]
#![allow(clippy::all)]
//! Conformance tests for the PostgreSQL Extended Query protocol (wire protocol v3),
//! run against the implementation in `src/database/postgres.rs`.
//!
//! Each requirement is either decided by production code or reported as
//! `TestVerdict::Skipped` with the reason. No verdict comes from a model in
//! this file:
//!
//! * Frontend messages are built by production (`build_bind_msg`,
//!   `build_execute_msg`, `build_sync_msg`, and `fuzz_build_parse_msg`, which
//!   wraps the private `build_parse_msg`). The bytes are compared one for one
//!   with the spec encoding produced by this file's `build_*_message` oracle
//!   builders, which are themselves pinned to hand-encoded bytes in the tests
//!   at the bottom.
//! * Backend messages are encoded here from the spec. Production frames them
//!   (`test_backend_message_body_len`) and decodes them
//!   (`fuzz_parse_row_description`, `fuzz_parse_data_row`,
//!   `fuzz_parse_error_response`, `fuzz_parse_copy_out_response`,
//!   `fuzz_apply_ready_for_query`). Spec-valid and malformed bodies are both
//!   fed in.
//! * Production exposes no observable for pipeline ordering, the Describe
//!   encoding, the statement and portal lifecycle, the drain to ReadyForQuery
//!   after an ErrorResponse, or the COPY-versus-query dispatch. They run
//!   inside async `PgConnection` methods talking to a live server, or in
//!   private builders, so they are reported as Skipped.
//! * Without `--features postgres`, and `test-internals` for the hooks, the
//!   production-decided requirements report Skipped ("needs --features ...").
//!
//! References:
//! https://www.postgresql.org/docs/current/protocol-flow.html#PROTOCOL-FLOW-EXT-QUERY
//! https://www.postgresql.org/docs/current/protocol-message-formats.html

use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Message type bytes from the protocol's message-format table.
mod protocol_constants {
    // Frontend messages (client to server)
    pub const PARSE: u8 = b'P';
    pub const BIND: u8 = b'B';
    pub const EXECUTE: u8 = b'E';
    pub const SYNC: u8 = b'S';

    // Backend messages (server to client)
    pub const DATA_ROW: u8 = b'D';
    pub const ERROR_RESPONSE: u8 = b'E';
    pub const READY_FOR_QUERY: u8 = b'Z';
    pub const ROW_DESCRIPTION: u8 = b'T';
    pub const COPY_IN_RESPONSE: u8 = b'G';
    pub const COPY_OUT_RESPONSE: u8 = b'H';
}

/// PostgreSQL type OIDs used by the fixtures.
mod pg_type_oids {
    pub const BOOL: u32 = 16;
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

/// Start of every Skipped note for a requirement production cannot show.
const NO_OBSERVABLE: &str = "production exposes no observable for this";

/// How a requirement was decided.
#[derive(Debug)]
enum Decision {
    /// Production code ran and the spec assertions were evaluated on its output.
    Decided(Result<(), String>),
    /// Production could not be reached; the note says why.
    Skipped(String),
}

/// What decides a requirement, so the self-test can predict its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// Public builders, compiled with `--features postgres`.
    PublicBuilder,
    /// `#[cfg(feature = "test-internals")]` hooks, which also need `postgres`.
    TestInternalsHook,
    /// No production observable; always Skipped.
    Unobservable,
}

#[derive(Clone)]
struct Requirement {
    id: &'static str,
    description: &'static str,
    category: TestCategory,
    level: RequirementLevel,
    evidence: Evidence,
    check: fn() -> Decision,
}

// ============================================================================
// Spec oracle: message encodings written from the message-format table
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColumnSpec {
    name: &'static str,
    table_oid: u32,
    column_id: i16,
    type_oid: u32,
    type_size: i16,
    type_modifier: i32,
    format: i16,
}

/// Frames a message: Byte1 type, then an Int32 length that counts itself but
/// not the type byte, then the body.
fn build_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(5 + body.len());
    msg.push(msg_type);
    msg.extend_from_slice(&(body.len() as u32 + 4).to_be_bytes());
    msg.extend_from_slice(body);
    msg
}

/// String: the bytes followed by a NUL terminator.
fn push_cstring(buf: &mut Vec<u8>, value: &str) {
    buf.extend_from_slice(value.as_bytes());
    buf.push(0);
}

/// Parse: String statement, String query, Int16 n, Int32[n] parameter type OIDs.
fn build_parse_message(stmt_name: &str, sql: &str, param_oids: &[u32]) -> Vec<u8> {
    let mut body = Vec::new();
    push_cstring(&mut body, stmt_name);
    push_cstring(&mut body, sql);
    body.extend_from_slice(&(param_oids.len() as i16).to_be_bytes());
    for oid in param_oids {
        body.extend_from_slice(&oid.to_be_bytes());
    }
    build_message(protocol_constants::PARSE, &body)
}

/// Bind: String portal, String statement, Int16 c + Int16[c] parameter format
/// codes, Int16 n + n x (Int32 length, or -1 for NULL with no bytes, then the
/// value bytes), Int16 r + Int16[r] result format codes.
fn build_bind_message(
    portal: &str,
    stmt_name: &str,
    param_formats: &[i16],
    values: &[Option<&[u8]>],
    result_formats: &[i16],
) -> Vec<u8> {
    let mut body = Vec::new();
    push_cstring(&mut body, portal);
    push_cstring(&mut body, stmt_name);
    body.extend_from_slice(&(param_formats.len() as i16).to_be_bytes());
    for code in param_formats {
        body.extend_from_slice(&code.to_be_bytes());
    }
    body.extend_from_slice(&(values.len() as i16).to_be_bytes());
    for value in values {
        match value {
            Some(bytes) => {
                body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                body.extend_from_slice(bytes);
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    body.extend_from_slice(&(result_formats.len() as i16).to_be_bytes());
    for code in result_formats {
        body.extend_from_slice(&code.to_be_bytes());
    }
    build_message(protocol_constants::BIND, &body)
}

/// Execute: String portal, Int32 maximum rows (0 = no limit).
fn build_execute_message(portal: &str, max_rows: i32) -> Vec<u8> {
    let mut body = Vec::new();
    push_cstring(&mut body, portal);
    body.extend_from_slice(&max_rows.to_be_bytes());
    build_message(protocol_constants::EXECUTE, &body)
}

/// Sync: no body.
fn build_sync_message() -> Vec<u8> {
    build_message(protocol_constants::SYNC, &[])
}

/// ReadyForQuery: Byte1 transaction status ('I', 'T' or 'E').
fn build_ready_for_query(status: u8) -> Vec<u8> {
    build_message(protocol_constants::READY_FOR_QUERY, &[status])
}

/// ErrorResponse body: (Byte1 field type, String value)*, then a zero byte.
fn error_response_body(fields: &[(u8, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (field_type, value) in fields {
        body.push(*field_type);
        push_cstring(&mut body, value);
    }
    body.push(0);
    body
}

/// RowDescription body: Int16 n, then per field String name, Int32 table OID,
/// Int16 attribute number, Int32 type OID, Int16 type size, Int32 type
/// modifier, Int16 format code.
fn row_description_body(columns: &[ColumnSpec]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(columns.len() as i16).to_be_bytes());
    for column in columns {
        push_cstring(&mut body, column.name);
        body.extend_from_slice(&column.table_oid.to_be_bytes());
        body.extend_from_slice(&column.column_id.to_be_bytes());
        body.extend_from_slice(&column.type_oid.to_be_bytes());
        body.extend_from_slice(&column.type_size.to_be_bytes());
        body.extend_from_slice(&column.type_modifier.to_be_bytes());
        body.extend_from_slice(&column.format.to_be_bytes());
    }
    body
}

/// DataRow body: Int16 declared value count, then per value an Int32 length
/// (-1 = NULL with no bytes) and the value bytes.
fn data_row_body(declared_count: i16, values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut body = declared_count.to_be_bytes().to_vec();
    for value in values {
        match value {
            Some(bytes) => {
                body.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
                body.extend_from_slice(bytes);
            }
            None => body.extend_from_slice(&(-1i32).to_be_bytes()),
        }
    }
    body
}

/// CopyInResponse and CopyOutResponse body: Int8 overall format, Int16
/// declared column count, Int16[] column format codes.
fn copy_response_body(overall_format: u8, declared_count: i16, column_formats: &[i16]) -> Vec<u8> {
    let mut body = vec![overall_format];
    body.extend_from_slice(&declared_count.to_be_bytes());
    for code in column_formats {
        body.extend_from_slice(&code.to_be_bytes());
    }
    body
}

/// Checks the header every frontend frame must carry: the type byte and an
/// Int32 length equal to the frame size minus the type byte.
fn check_frame_header(what: &str, frame: &[u8], expected_type: u8) -> Result<(), String> {
    if frame.len() < 5 {
        return Err(format!(
            "{what}: {} bytes is shorter than the Byte1 type + Int32 length header",
            frame.len()
        ));
    }
    if frame[0] != expected_type {
        return Err(format!(
            "{what}: type byte {:?}, the spec requires {:?}",
            frame[0] as char, expected_type as char
        ));
    }
    let declared = i32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
    if usize::try_from(declared).ok() != Some(frame.len() - 1) {
        return Err(format!(
            "{what}: Int32 length {declared}, but it must count itself plus the {} body bytes, i.e. {}",
            frame.len() - 5,
            frame.len() - 1
        ));
    }
    Ok(())
}

/// Compares a production-built frontend frame with the spec encoding.
fn expect_frame(what: &str, produced: &[u8], expected_type: u8, spec: &[u8]) -> Result<(), String> {
    check_frame_header(what, produced, expected_type)?;
    if produced != spec {
        return Err(format!(
            "{what}: production emitted {produced:02x?}, the spec encoding is {spec:02x?}"
        ));
    }
    Ok(())
}

// ============================================================================
// Requirements production exposes no observable for
// ============================================================================

fn pipeline_order_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: PgConnection::query_params, prepare and query_prepared build the \
         Parse/Bind/Describe/Execute/Sync sequence and write it in one write_all inside async fns, \
         then consume ParseComplete..ReadyForQuery from the socket. No test-internals hook returns \
         that buffer or feeds a backend transcript to those fns, so checking the order needs a live \
         server. Production decides each message's layout in the \
         pg_extended_*_message_wire_format requirements"
    ))
}

fn describe_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: build_describe_msg in src/database/postgres.rs is private and has no \
         test-internals re-export (Parse has fuzz_build_parse_msg; Describe has nothing)"
    ))
}

fn statement_lifecycle_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: named statements live in the private PgConnectionInner::prepared_cache \
         and portals exist only on the server. prepare, query_prepared and close_statement reach \
         them only over a live connection, and no hook exposes the cache or a Sync boundary"
    ))
}

fn error_drain_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: skipping to Sync after an error is server behaviour. The client side, \
         PgConnection::drain_to_ready (reached through parse_error_and_drain), is an async fn \
         reading the socket. fuzz_apply_sync_recovery re-implements that loop inside the hook with \
         its own message filter, so it would test the hook, not production. Production's part of \
         this exchange is decided in pg_extended_error_response_fields_decoded and \
         pg_extended_ready_for_query_status_roundtrip"
    ))
}

fn copy_distinction_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: PgConnection::copy_in and copy_out dispatch on CopyInResponse ('G') and \
         CopyOutResponse ('H'), and the query paths dispatch on their own backend types, all inside \
         async fns over a live connection. No hook replays a backend stream through that dispatch. \
         The COPY response header decoder is decided in pg_extended_copy_response_header_decoded"
    ))
}

// ============================================================================
// Frontend messages built by production's public builders
// ============================================================================

#[cfg(feature = "postgres")]
mod frontend {
    use super::*;
    use asupersync::database::postgres::{
        Format, ToSql, build_bind_msg, build_execute_msg, build_sync_msg,
    };

    struct BindCase<'a> {
        what: &'static str,
        portal: &'static str,
        statement: &'static str,
        params: Vec<&'a dyn ToSql>,
        result_format: Format,
        spec_param_formats: Vec<i16>,
        spec_values: Vec<Option<&'a [u8]>>,
        spec_result_formats: Vec<i16>,
    }

    pub(super) fn bind_message_wire_format() -> Decision {
        Decision::Decided(check_bind())
    }

    pub(super) fn execute_message_wire_format() -> Decision {
        Decision::Decided(check_execute())
    }

    pub(super) fn sync_message_wire_format() -> Decision {
        Decision::Decided(check_sync())
    }

    fn check_bind() -> Result<(), String> {
        // Encoded by hand: unnamed portal and statement, no parameter format
        // codes, no values, one result format code (text) for all columns.
        let what = "Bind(\"\", \"\", [], Text)";
        let produced = build_bind_msg("", "", &[], Format::Text)
            .map_err(|err| format!("{what}: production refused it: {err:?}"))?;
        expect_frame(
            what,
            &produced,
            protocol_constants::BIND,
            &[b'B', 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
        )?;

        let forty_two: i32 = 42;
        let seven: i32 = 7;
        let abc: &str = "abc";
        let x: &str = "x";
        let null: Option<i32> = None;
        let forty_two_be = 42i32.to_be_bytes();
        let seven_be = 7i32.to_be_bytes();

        // The format-code section has several spec-valid shapes (count 0 =
        // all text, count 1 = one code for every parameter, or one code per
        // parameter). The oracle encodes the shape libpq sends, which is also
        // the shape build_bind_msg documents.
        let cases = vec![
            BindCase {
                what: "one binary int4 parameter: a single format code 1",
                portal: "",
                statement: "stmt_users",
                params: vec![&forty_two as &dyn ToSql],
                result_format: Format::Text,
                spec_param_formats: vec![1],
                spec_values: vec![Some(&forty_two_be[..])],
                spec_result_formats: vec![0],
            },
            BindCase {
                what: "one text parameter: all text needs no format codes",
                portal: "",
                statement: "stmt_users",
                params: vec![&abc as &dyn ToSql],
                result_format: Format::Text,
                spec_param_formats: vec![],
                spec_values: vec![Some(&b"abc"[..])],
                spec_result_formats: vec![0],
            },
            BindCase {
                what: "binary and text parameters: one format code per parameter",
                portal: "",
                statement: "stmt_pair",
                params: vec![&seven as &dyn ToSql, &x as &dyn ToSql],
                result_format: Format::Text,
                spec_param_formats: vec![1, 0],
                spec_values: vec![Some(&seven_be[..]), Some(&b"x"[..])],
                spec_result_formats: vec![0],
            },
            BindCase {
                what: "NULL parameter: length -1 and no value bytes",
                portal: "",
                statement: "stmt_users",
                params: vec![&null as &dyn ToSql],
                result_format: Format::Text,
                spec_param_formats: vec![1],
                spec_values: vec![None],
                spec_result_formats: vec![0],
            },
            BindCase {
                what: "named portal and statement, binary results",
                portal: "p1",
                statement: "stmt_1",
                params: vec![],
                result_format: Format::Binary,
                spec_param_formats: vec![],
                spec_values: vec![],
                spec_result_formats: vec![1],
            },
        ];
        for case in &cases {
            let what = format!(
                "Bind({:?}, {:?}), {}",
                case.portal, case.statement, case.what
            );
            let produced = build_bind_msg(
                case.portal,
                case.statement,
                &case.params,
                case.result_format,
            )
            .map_err(|err| format!("{what}: production refused it: {err:?}"))?;
            let spec = build_bind_message(
                case.portal,
                case.statement,
                &case.spec_param_formats,
                &case.spec_values,
                &case.spec_result_formats,
            );
            expect_frame(&what, &produced, protocol_constants::BIND, &spec)?;
        }

        // A String is NUL-terminated, so a name containing NUL cannot be framed.
        for (portal, statement) in [("portal\0x", ""), ("", "stmt\0x")] {
            if let Ok(frame) = build_bind_msg(portal, statement, &[], Format::Text) {
                return Err(format!(
                    "Bind({portal:?}, {statement:?}): a String field with an embedded NUL was framed as {frame:02x?}"
                ));
            }
        }
        Ok(())
    }

    fn check_execute() -> Result<(), String> {
        // Encoded by hand: 'E', length 9, "" (unnamed portal), Int32 0 = no row limit.
        let produced = build_execute_msg("", 0)
            .map_err(|err| format!("Execute(\"\", 0): production refused it: {err:?}"))?;
        expect_frame(
            "Execute(\"\", 0)",
            &produced,
            protocol_constants::EXECUTE,
            &[b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0],
        )?;
        for (portal, max_rows) in [("p1", 100), ("cursor_7", 1)] {
            let what = format!("Execute({portal:?}, {max_rows})");
            let produced = build_execute_msg(portal, max_rows)
                .map_err(|err| format!("{what}: production refused it: {err:?}"))?;
            expect_frame(
                &what,
                &produced,
                protocol_constants::EXECUTE,
                &build_execute_message(portal, max_rows),
            )?;
        }
        if let Ok(frame) = build_execute_msg("portal\0x", 0) {
            return Err(format!(
                "Execute(\"portal\\0x\", 0): a String field with an embedded NUL was framed as {frame:02x?}"
            ));
        }
        Ok(())
    }

    fn check_sync() -> Result<(), String> {
        let produced =
            build_sync_msg().map_err(|err| format!("Sync: production refused it: {err:?}"))?;
        // Encoded by hand: 'S' and an Int32 length of 4 (the length itself).
        expect_frame(
            "Sync",
            &produced,
            protocol_constants::SYNC,
            &[b'S', 0, 0, 0, 4],
        )?;
        expect_frame(
            "Sync",
            &produced,
            protocol_constants::SYNC,
            &build_sync_message(),
        )
    }
}

#[cfg(not(feature = "postgres"))]
mod frontend {
    use super::*;

    fn needs_postgres(builder: &str) -> Decision {
        Decision::Skipped(format!(
            "needs --features postgres: {builder} lives in asupersync::database::postgres, which \
             is compiled only with the postgres feature (src/database/mod.rs)"
        ))
    }

    pub(super) fn bind_message_wire_format() -> Decision {
        needs_postgres("build_bind_msg")
    }

    pub(super) fn execute_message_wire_format() -> Decision {
        needs_postgres("build_execute_msg")
    }

    pub(super) fn sync_message_wire_format() -> Decision {
        needs_postgres("build_sync_msg")
    }
}

// ============================================================================
// Parse builder and backend parsers reached through test-internals hooks
// ============================================================================

#[cfg(all(feature = "postgres", feature = "test-internals"))]
mod hooks {
    use super::*;
    use asupersync::database::postgres::{
        Format, PgError, PgErrorDiagnostic, PgValue, fuzz_apply_ready_for_query,
        fuzz_build_parse_msg, fuzz_parse_copy_out_response, fuzz_parse_data_row,
        fuzz_parse_error_response, fuzz_parse_row_description, test_backend_message_body_len,
    };

    pub(super) fn parse_message_wire_format() -> Decision {
        Decision::Decided(check_parse())
    }

    pub(super) fn backend_length_prefix() -> Decision {
        Decision::Decided(check_length_prefix())
    }

    pub(super) fn error_response_fields() -> Decision {
        Decision::Decided(check_error_response())
    }

    pub(super) fn row_description_metadata() -> Decision {
        Decision::Decided(check_row_description())
    }

    pub(super) fn row_description_malformed() -> Decision {
        Decision::Decided(check_row_description_malformed())
    }

    pub(super) fn data_row_decoding() -> Decision {
        Decision::Decided(check_data_row())
    }

    pub(super) fn copy_response_header() -> Decision {
        Decision::Decided(check_copy_response())
    }

    pub(super) fn ready_for_query_status() -> Decision {
        Decision::Decided(check_ready_for_query())
    }

    /// Splits a spec-encoded backend frame the way production's reader does:
    /// production's length-prefix check decides how long the body is.
    fn production_body<'a>(
        what: &str,
        frame: &'a [u8],
        expected_type: u8,
    ) -> Result<&'a [u8], String> {
        if frame.len() < 5 || frame[0] != expected_type {
            return Err(format!(
                "{what}: test fixture is not a {:?} frame: {frame:02x?}",
                expected_type as char
            ));
        }
        let declared = i32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        let body_len = test_backend_message_body_len(declared).map_err(|err| {
            format!("{what}: production rejected the spec-valid length prefix {declared}: {err:?}")
        })?;
        match frame.get(5..) {
            Some(body) if body.len() == body_len => Ok(body),
            _ => Err(format!(
                "{what}: production derived a {body_len}-byte body from length {declared}, the frame carries {} bytes",
                frame.len() - 5
            )),
        }
    }

    fn check_parse() -> Result<(), String> {
        // Encoded by hand: 'P', length 16, "" (unnamed statement), "SELECT 1",
        // Int16 0 parameter types.
        let what = "Parse(\"\", \"SELECT 1\", [])";
        let produced = fuzz_build_parse_msg("", "SELECT 1", &[])
            .map_err(|err| format!("{what}: production refused it: {err:?}"))?;
        let mut spec = vec![b'P', 0, 0, 0, 16, 0];
        spec.extend_from_slice(b"SELECT 1");
        spec.extend_from_slice(&[0, 0, 0]);
        expect_frame(what, &produced, protocol_constants::PARSE, &spec)?;

        let cases: [(&str, &str, &[u32]); 2] = [
            ("stmt_users", "SELECT $1::int4", &[pg_type_oids::INT4]),
            // OID 0 leaves the parameter type to the server.
            ("stmt_pair", "SELECT $1, $2", &[0, pg_type_oids::TEXT]),
        ];
        for (statement, sql, oids) in cases {
            let what = format!("Parse({statement:?}, {sql:?}, {oids:?})");
            let produced = fuzz_build_parse_msg(statement, sql, oids)
                .map_err(|err| format!("{what}: production refused it: {err:?}"))?;
            expect_frame(
                &what,
                &produced,
                protocol_constants::PARSE,
                &build_parse_message(statement, sql, oids),
            )?;
        }

        // A String is NUL-terminated, so a NUL inside one cannot be framed;
        // framing it would make the server read a different statement.
        for (statement, sql) in [("stmt\0x", "SELECT 1"), ("stmt", "SELECT 1\0; SELECT 2")] {
            if let Ok(frame) = fuzz_build_parse_msg(statement, sql, &[]) {
                return Err(format!(
                    "Parse({statement:?}, {sql:?}): a String field with an embedded NUL was framed as {frame:02x?}"
                ));
            }
        }
        Ok(())
    }

    fn check_length_prefix() -> Result<(), String> {
        // The Int32 length counts itself, so the body is length - 4 bytes.
        for (declared, body_len) in [(4, 0usize), (5, 1), (4 + 8192, 8192)] {
            match test_backend_message_body_len(declared) {
                Ok(n) if n == body_len => {}
                other => {
                    return Err(format!(
                        "length prefix {declared}: the spec body length is {body_len}, production returned {other:?}"
                    ));
                }
            }
        }
        // Below 4 the length cannot even cover itself; framing on it would
        // desynchronise the stream.
        for declared in [3, 1, 0, -1, i32::MIN] {
            if let Ok(n) = test_backend_message_body_len(declared) {
                return Err(format!(
                    "length prefix {declared} is below the 4-byte minimum, yet production framed a {n}-byte body"
                ));
            }
        }
        Ok(())
    }

    fn check_error_response() -> Result<(), String> {
        let message = "invalid input syntax for type integer: \"abc\"";
        let fields: [(u8, &str); 11] = [
            (b'S', "ERROR"),
            (b'V', "ERROR"),
            (b'C', "22P02"),
            (b'M', message),
            (b'D', "Token \"abc\" is invalid."),
            (b'H', "Pass a numeric literal."),
            (b'P', "8"),
            (b'F', "numutils.c"),
            (b'L', "232"),
            (b'R', "pg_strtoint32_safe"),
            // Not a field type the spec defines; frontends should silently ignore it.
            (b'Y', "field type from the future"),
        ];
        let frame = build_message(
            protocol_constants::ERROR_RESPONSE,
            &error_response_body(&fields),
        );
        let body = production_body("ErrorResponse", &frame, protocol_constants::ERROR_RESPONSE)?;
        match fuzz_parse_error_response(body) {
            Ok(PgError::Server {
                code,
                message: decoded,
                detail,
                hint,
                diagnostic,
                ..
            }) => {
                let expected_diagnostic = PgErrorDiagnostic {
                    severity: Some("ERROR".to_string()),
                    position: Some("8".to_string()),
                    file_name: Some("numutils.c".to_string()),
                    line_number: Some("232".to_string()),
                    routine_name: Some("pg_strtoint32_safe".to_string()),
                    ..PgErrorDiagnostic::default()
                };
                if code != "22P02"
                    || decoded != message
                    || detail.as_deref() != Some("Token \"abc\" is invalid.")
                    || hint.as_deref() != Some("Pass a numeric literal.")
                    || diagnostic != expected_diagnostic
                {
                    return Err(format!(
                        "ErrorResponse: production decoded code={code:?} message={decoded:?} detail={detail:?} hint={hint:?} diagnostic={diagnostic:?}; the spec fields are {fields:?}"
                    ));
                }
            }
            other => {
                return Err(format!(
                    "ErrorResponse: expected a server error carrying the spec fields, production returned {other:?}"
                ));
            }
        }

        let mut no_terminator = error_response_body(&fields[..4]);
        no_terminator.pop();
        let mut trailing = error_response_body(&fields[..4]);
        trailing.push(b'x');
        let malformed: [(&str, Vec<u8>); 4] = [
            ("an empty body (no fields, no terminator)", Vec::new()),
            ("fields but no terminating zero byte", no_terminator),
            (
                "a field value without its NUL terminator",
                vec![b'C', b'2', b'2', b'P'],
            ),
            ("bytes after the terminating zero byte", trailing),
        ];
        for (label, bad) in malformed {
            let frame = build_message(protocol_constants::ERROR_RESPONSE, &bad);
            let body =
                production_body("ErrorResponse", &frame, protocol_constants::ERROR_RESPONSE)?;
            if let Ok(decoded) = fuzz_parse_error_response(body) {
                return Err(format!(
                    "ErrorResponse with {label}: production accepted {bad:02x?} as {decoded:?}"
                ));
            }
        }
        Ok(())
    }

    fn metadata_columns() -> [ColumnSpec; 5] {
        [
            ColumnSpec {
                name: "id",
                table_oid: 16_384,
                column_id: 1,
                type_oid: pg_type_oids::INT4,
                type_size: 4,
                type_modifier: -1,
                format: 0,
            },
            ColumnSpec {
                name: "created_at",
                table_oid: 16_384,
                column_id: 2,
                type_oid: pg_type_oids::TIMESTAMPTZ,
                type_size: 8,
                type_modifier: -1,
                format: 0,
            },
            ColumnSpec {
                name: "active",
                table_oid: 16_384,
                column_id: 3,
                type_oid: pg_type_oids::BOOL,
                type_size: 1,
                type_modifier: -1,
                format: 0,
            },
            // varchar(20): the type modifier is the declared length plus the
            // 4-byte header. The table OID is above i32::MAX, so it must be
            // read as unsigned.
            ColumnSpec {
                name: "note",
                table_oid: 4_000_000_000,
                column_id: 4,
                type_oid: pg_type_oids::VARCHAR,
                type_size: -1,
                type_modifier: 24,
                format: 0,
            },
            // A computed numeric(10,2) column in binary: no table (OID 0,
            // attribute 0), type modifier ((10 << 16) | 2) + 4.
            ColumnSpec {
                name: "?column?",
                table_oid: 0,
                column_id: 0,
                type_oid: pg_type_oids::NUMERIC,
                type_size: -1,
                type_modifier: ((10 << 16) | 2) + 4,
                format: 1,
            },
        ]
    }

    fn check_row_description() -> Result<(), String> {
        let columns = metadata_columns();
        let frame = build_message(
            protocol_constants::ROW_DESCRIPTION,
            &row_description_body(&columns),
        );
        let body = production_body(
            "RowDescription",
            &frame,
            protocol_constants::ROW_DESCRIPTION,
        )?;
        let (decoded, index) = fuzz_parse_row_description(body).map_err(|err| {
            format!("RowDescription: production rejected a spec-valid message: {err:?}")
        })?;
        if decoded.len() != columns.len() {
            return Err(format!(
                "RowDescription: the spec bytes declare {} fields, production decoded {}",
                columns.len(),
                decoded.len()
            ));
        }
        for (position, (got, want)) in decoded.iter().zip(columns.iter()).enumerate() {
            let got_fields = (
                got.name.as_str(),
                got.table_oid,
                got.column_id,
                got.type_oid,
                got.type_size,
                got.type_modifier,
                got.format_code,
            );
            let want_fields = (
                want.name,
                want.table_oid,
                want.column_id,
                want.type_oid,
                want.type_size,
                want.type_modifier,
                want.format,
            );
            if got_fields != want_fields {
                return Err(format!(
                    "RowDescription field {position}: production decoded (name, table OID, attnum, type OID, typlen, typmod, format) = {got_fields:?}, the spec bytes carry {want_fields:?}"
                ));
            }
            if index.get(want.name) != Some(&position) {
                return Err(format!(
                    "RowDescription: production's name index maps {:?} to {:?}, expected Some({position})",
                    want.name,
                    index.get(want.name)
                ));
            }
        }
        if index.len() != columns.len() {
            return Err(format!(
                "RowDescription: production's name index has {} entries for {} uniquely named fields",
                index.len(),
                columns.len()
            ));
        }

        // The field count "can be zero".
        let frame = build_message(
            protocol_constants::ROW_DESCRIPTION,
            &row_description_body(&[]),
        );
        let body = production_body(
            "RowDescription",
            &frame,
            protocol_constants::ROW_DESCRIPTION,
        )?;
        match fuzz_parse_row_description(body) {
            Ok((fields, names)) if fields.is_empty() && names.is_empty() => Ok(()),
            other => Err(format!(
                "RowDescription with zero fields: production returned {other:?}"
            )),
        }
    }

    fn check_row_description_malformed() -> Result<(), String> {
        let one_column = [metadata_columns()[0].clone()];
        let valid = row_description_body(&one_column);
        let mut negative_count = valid.clone();
        negative_count[..2].copy_from_slice(&(-1i16).to_be_bytes());
        let mut count_too_high = valid.clone();
        count_too_high[..2].copy_from_slice(&2i16.to_be_bytes());
        let mut missing_format = valid.clone();
        missing_format.truncate(valid.len() - 2);
        let mut unterminated_name = 1i16.to_be_bytes().to_vec();
        unterminated_name.extend_from_slice(b"id");
        let mut trailing = valid.clone();
        trailing.push(0);
        let malformed: [(&str, Vec<u8>); 5] = [
            ("a negative field count", negative_count),
            (
                "a field count larger than the fields present",
                count_too_high,
            ),
            ("a field cut off before its format code", missing_format),
            ("a field name without its NUL terminator", unterminated_name),
            ("bytes after the last field", trailing),
        ];
        for (label, bad) in malformed {
            let frame = build_message(protocol_constants::ROW_DESCRIPTION, &bad);
            let body = production_body(
                "RowDescription",
                &frame,
                protocol_constants::ROW_DESCRIPTION,
            )?;
            if let Ok((columns, _)) = fuzz_parse_row_description(body) {
                return Err(format!(
                    "RowDescription with {label}: production accepted {bad:02x?} and decoded {columns:?}"
                ));
            }
        }
        Ok(())
    }

    fn data_row_columns() -> [ColumnSpec; 5] {
        let column =
            |name: &'static str, column_id: i16, type_oid: u32, type_size: i16, format: i16| {
                ColumnSpec {
                    name,
                    table_oid: 16_384,
                    column_id,
                    type_oid,
                    type_size,
                    type_modifier: -1,
                    format,
                }
            };
        [
            column("id", 1, pg_type_oids::INT4, 4, 0),
            column("name", 2, pg_type_oids::TEXT, -1, 0),
            column("active", 3, pg_type_oids::BOOL, 1, 0),
            column("score", 4, pg_type_oids::INT8, 8, 1),
            column("note", 5, pg_type_oids::TEXT, -1, 0),
        ]
    }

    fn check_data_row() -> Result<(), String> {
        // The column types and formats come from production's RowDescription decoder.
        let frame = build_message(
            protocol_constants::ROW_DESCRIPTION,
            &row_description_body(&data_row_columns()),
        );
        let body = production_body(
            "RowDescription",
            &frame,
            protocol_constants::ROW_DESCRIPTION,
        )?;
        let (columns, _) = fuzz_parse_row_description(body).map_err(|err| {
            format!("RowDescription for the DataRow fixtures: production rejected it: {err:?}")
        })?;

        let big_be = 9_000_000_000i64.to_be_bytes();
        let zero_be = 0i64.to_be_bytes();
        let rows: [(&str, Vec<Option<&[u8]>>, Vec<PgValue>); 2] = [
            (
                "text, binary and NULL values",
                vec![
                    Some(&b"42"[..]),
                    Some(&b"alice"[..]),
                    Some(&b"t"[..]),
                    Some(&big_be[..]),
                    None,
                ],
                vec![
                    PgValue::Int4(42),
                    PgValue::Text("alice".to_string()),
                    PgValue::Bool(true),
                    PgValue::Int8(9_000_000_000),
                    PgValue::Null,
                ],
            ),
            (
                "zero-length values, which are not NULL",
                vec![
                    Some(&b"-7"[..]),
                    Some(&b""[..]),
                    Some(&b"f"[..]),
                    Some(&zero_be[..]),
                    Some(&b""[..]),
                ],
                vec![
                    PgValue::Int4(-7),
                    PgValue::Text(String::new()),
                    PgValue::Bool(false),
                    PgValue::Int8(0),
                    PgValue::Text(String::new()),
                ],
            ),
        ];
        for (label, values, expected) in rows {
            let frame = build_message(
                protocol_constants::DATA_ROW,
                &data_row_body(values.len() as i16, &values),
            );
            let body = production_body("DataRow", &frame, protocol_constants::DATA_ROW)?;
            match fuzz_parse_data_row(body, &columns) {
                Ok(decoded) if decoded == expected => {}
                other => {
                    return Err(format!(
                        "DataRow with {label}: the spec values are {expected:?}, production returned {other:?}"
                    ));
                }
            }
        }

        let good: [Option<&[u8]>; 5] = [
            Some(&b"1"[..]),
            Some(&b"bob"[..]),
            Some(&b"t"[..]),
            Some(&zero_be[..]),
            None,
        ];
        let mut extra_value = data_row_body(6, &good);
        extra_value.extend_from_slice(&(-1i32).to_be_bytes());
        let mut length_below_null = data_row_body(5, &good[..4]);
        length_below_null.extend_from_slice(&(-2i32).to_be_bytes());
        let mut overlong = data_row_body(5, &good[..4]);
        overlong.extend_from_slice(&10i32.to_be_bytes());
        overlong.extend_from_slice(b"ab");
        let mut trailing = data_row_body(5, &good);
        trailing.push(0);
        let malformed: [(&str, Vec<u8>); 6] = [
            (
                "fewer values than RowDescription fields",
                data_row_body(4, &good[..4]),
            ),
            ("more values than RowDescription fields", extra_value),
            ("a negative value count", data_row_body(-1, &[])),
            ("a value length below -1", length_below_null),
            ("a value length longer than the bytes present", overlong),
            ("bytes after the last value", trailing),
        ];
        for (label, bad) in malformed {
            let frame = build_message(protocol_constants::DATA_ROW, &bad);
            let body = production_body("DataRow", &frame, protocol_constants::DATA_ROW)?;
            if let Ok(decoded) = fuzz_parse_data_row(body, &columns) {
                return Err(format!(
                    "DataRow with {label}: production accepted {bad:02x?} as {decoded:?}"
                ));
            }
        }
        Ok(())
    }

    /// fuzz_parse_copy_out_response calls the same `parse_copy_response` that
    /// production uses for CopyInResponse ('G') and CopyOutResponse ('H');
    /// only the context label differs. The spec gives both the same layout.
    fn check_copy_response() -> Result<(), String> {
        let valid: [(&str, u8, u8, Vec<i16>, (Format, Vec<Format>)); 3] = [
            (
                "CopyInResponse, text, two columns",
                protocol_constants::COPY_IN_RESPONSE,
                0,
                vec![0, 0],
                (Format::Text, vec![Format::Text, Format::Text]),
            ),
            (
                "CopyOutResponse, binary, three columns",
                protocol_constants::COPY_OUT_RESPONSE,
                1,
                vec![1, 1, 1],
                (Format::Binary, vec![Format::Binary; 3]),
            ),
            (
                "CopyInResponse, text, no columns",
                protocol_constants::COPY_IN_RESPONSE,
                0,
                vec![],
                (Format::Text, vec![]),
            ),
        ];
        for (label, msg_type, overall, codes, expected) in valid {
            let frame = build_message(
                msg_type,
                &copy_response_body(overall, codes.len() as i16, &codes),
            );
            let body = production_body(label, &frame, msg_type)?;
            match fuzz_parse_copy_out_response(body) {
                Ok(decoded) if decoded == expected => {}
                other => {
                    return Err(format!(
                        "{label}: the spec formats are {expected:?}, production returned {other:?}"
                    ));
                }
            }
        }

        // The decoder returns Format, which can only say text or binary, so
        // for an undefined code the only correct outcome is a rejection.
        let mut trailing = copy_response_body(0, 1, &[0]);
        trailing.push(0);
        let malformed: [(&str, Vec<u8>); 5] = [
            (
                "an overall format other than 0 or 1",
                copy_response_body(2, 1, &[0]),
            ),
            (
                "a column format other than 0 or 1",
                copy_response_body(1, 1, &[2]),
            ),
            ("a negative column count", copy_response_body(0, -1, &[])),
            (
                "fewer column formats than the declared count",
                copy_response_body(0, 2, &[0]),
            ),
            ("bytes after the column formats", trailing),
        ];
        for (label, bad) in malformed {
            let frame = build_message(protocol_constants::COPY_IN_RESPONSE, &bad);
            let body = production_body(
                "CopyInResponse",
                &frame,
                protocol_constants::COPY_IN_RESPONSE,
            )?;
            if let Ok(decoded) = fuzz_parse_copy_out_response(body) {
                return Err(format!(
                    "COPY response with {label}: production accepted {bad:02x?} as {decoded:?}"
                ));
            }
        }
        Ok(())
    }

    fn check_ready_for_query() -> Result<(), String> {
        // Idle, then in a transaction, then a failed transaction, then idle
        // again; the connection must record each status it is handed.
        let mut status = b'I';
        for next in [b'T', b'E', b'I', b'I'] {
            let frame = build_ready_for_query(next);
            let body =
                production_body("ReadyForQuery", &frame, protocol_constants::READY_FOR_QUERY)?;
            let (result, recorded) = fuzz_apply_ready_for_query(body, status);
            match result {
                Ok(parsed) if parsed == next && recorded == next => {}
                other => {
                    return Err(format!(
                        "ReadyForQuery {:?} after {:?}: production returned {other:?} and recorded {:?}",
                        next as char, status as char, recorded as char
                    ));
                }
            }
            status = recorded;
        }

        // The body is exactly one byte; anything else is malformed and must
        // leave the recorded status alone.
        let malformed: [(&str, Vec<u8>); 2] = [
            ("an empty body", Vec::new()),
            ("a two-byte body", vec![b'I', b'T']),
        ];
        for (label, bad) in malformed {
            let frame = build_message(protocol_constants::READY_FOR_QUERY, &bad);
            let body =
                production_body("ReadyForQuery", &frame, protocol_constants::READY_FOR_QUERY)?;
            let (result, recorded) = fuzz_apply_ready_for_query(body, b'T');
            if result.is_ok() || recorded != b'T' {
                return Err(format!(
                    "ReadyForQuery with {label}: production returned {result:?} and left the recorded status at {:?} (it was 'T')",
                    recorded as char
                ));
            }
        }

        // 'X' is none of the spec's I/T/E. It must not be reported as one of
        // them, and must not flip the recorded status to another known state.
        let frame = build_ready_for_query(b'X');
        let body = production_body("ReadyForQuery", &frame, protocol_constants::READY_FOR_QUERY)?;
        let (result, recorded) = fuzz_apply_ready_for_query(body, b'T');
        if matches!(result, Ok(b'I' | b'T' | b'E')) || matches!(recorded, b'I' | b'E') {
            return Err(format!(
                "ReadyForQuery with status byte 'X': production returned {result:?} and recorded {:?}",
                recorded as char
            ));
        }
        Ok(())
    }
}

#[cfg(not(all(feature = "postgres", feature = "test-internals")))]
mod hooks {
    use super::*;

    fn unavailable(hook: &str) -> Decision {
        if cfg!(feature = "postgres") {
            Decision::Skipped(format!(
                "needs --features test-internals: {hook} is #[cfg(feature = \"test-internals\")] \
                 in src/database/postgres.rs"
            ))
        } else {
            Decision::Skipped(format!(
                "needs --features postgres: {hook} lives in asupersync::database::postgres, which \
                 is compiled only with the postgres feature (and the hook also needs test-internals)"
            ))
        }
    }

    pub(super) fn parse_message_wire_format() -> Decision {
        unavailable("fuzz_build_parse_msg")
    }

    pub(super) fn backend_length_prefix() -> Decision {
        unavailable("test_backend_message_body_len")
    }

    pub(super) fn error_response_fields() -> Decision {
        unavailable("fuzz_parse_error_response")
    }

    pub(super) fn row_description_metadata() -> Decision {
        unavailable("fuzz_parse_row_description")
    }

    pub(super) fn row_description_malformed() -> Decision {
        unavailable("fuzz_parse_row_description")
    }

    pub(super) fn data_row_decoding() -> Decision {
        unavailable("fuzz_parse_data_row")
    }

    pub(super) fn copy_response_header() -> Decision {
        unavailable("fuzz_parse_copy_out_response")
    }

    pub(super) fn ready_for_query_status() -> Decision {
        unavailable("fuzz_apply_ready_for_query")
    }
}

// ============================================================================
// Requirement table and harness
// ============================================================================

fn requirements() -> Vec<Requirement> {
    use Evidence::{PublicBuilder, TestInternalsHook, Unobservable};
    vec![
        Requirement {
            id: "pg_extended_parse_bind_describe_execute_sync_pipeline",
            description: "Extended query pipeline must emit Parse/Bind/Describe/Execute/Sync with ReadyForQuery completion",
            category: TestCategory::PipelineSequencing,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: pipeline_order_unobservable,
        },
        Requirement {
            id: "pg_extended_parse_message_wire_format",
            description: "Parse must be framed as 'P', Int32 length, String statement, String query, Int16 count and Int32 parameter type OIDs, and a NUL inside a String must be refused",
            category: TestCategory::PipelineSequencing,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::parse_message_wire_format,
        },
        Requirement {
            id: "pg_extended_bind_message_wire_format",
            description: "Bind must be framed as 'B', Int32 length, String portal, String statement, parameter format codes, length-prefixed values (-1 for NULL) and result format codes, and a NUL inside a String must be refused",
            category: TestCategory::PipelineSequencing,
            level: RequirementLevel::Must,
            evidence: PublicBuilder,
            check: frontend::bind_message_wire_format,
        },
        Requirement {
            id: "pg_extended_describe_message_wire_format",
            description: "Describe must be framed as 'D', Int32 length, Byte1 'S' or 'P' and the String name",
            category: TestCategory::PipelineSequencing,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: describe_unobservable,
        },
        Requirement {
            id: "pg_extended_execute_message_wire_format",
            description: "Execute must be framed as 'E', Int32 length, String portal and Int32 row limit (0 = no limit)",
            category: TestCategory::PipelineSequencing,
            level: RequirementLevel::Must,
            evidence: PublicBuilder,
            check: frontend::execute_message_wire_format,
        },
        Requirement {
            id: "pg_extended_sync_message_wire_format",
            description: "Sync must be the 5-byte frame 'S' with Int32 length 4",
            category: TestCategory::PipelineSequencing,
            level: RequirementLevel::Must,
            evidence: PublicBuilder,
            check: frontend::sync_message_wire_format,
        },
        Requirement {
            id: "pg_extended_named_statement_survives_sync_barrier",
            description: "Named statements must survive Sync while unnamed portals are destroyed",
            category: TestCategory::StatementLifecycle,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: statement_lifecycle_unobservable,
        },
        Requirement {
            id: "pg_extended_error_response_drains_to_ready",
            description: "ErrorResponse must drain to ReadyForQuery before the next extended-query exchange",
            category: TestCategory::ErrorRecovery,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: error_drain_unobservable,
        },
        Requirement {
            id: "pg_extended_error_response_fields_decoded",
            description: "ErrorResponse fields (severity, SQLSTATE, message, detail, hint, position, file, line, routine) must be decoded, unknown field types ignored, and malformed bodies rejected",
            category: TestCategory::ErrorRecovery,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::error_response_fields,
        },
        Requirement {
            id: "pg_extended_backend_length_prefix_validated",
            description: "A backend Int32 length counts itself, so the body is length - 4 bytes, and a length below 4 must be rejected",
            category: TestCategory::ErrorRecovery,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::backend_length_prefix,
        },
        Requirement {
            id: "pg_extended_row_description_matches_oid_metadata",
            description: "RowDescription metadata must preserve PostgreSQL type OIDs and widths",
            category: TestCategory::RowDescriptionMetadata,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::row_description_metadata,
        },
        Requirement {
            id: "pg_extended_row_description_malformed_rejected",
            description: "A RowDescription whose field count, field layout or length disagree must be rejected",
            category: TestCategory::RowDescriptionMetadata,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::row_description_malformed,
        },
        Requirement {
            id: "pg_extended_data_row_decoded_per_row_description",
            description: "DataRow values must be decoded with their RowDescription type and format, -1 as NULL and length 0 as an empty value, and malformed rows rejected",
            category: TestCategory::RowDescriptionMetadata,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::data_row_decoding,
        },
        Requirement {
            id: "pg_extended_copy_messages_are_distinct_from_pipeline",
            description: "COPY protocol messages must remain distinct from extended-query pipeline messages",
            category: TestCategory::ProtocolDistinction,
            level: RequirementLevel::Should,
            evidence: Unobservable,
            check: copy_distinction_unobservable,
        },
        Requirement {
            id: "pg_extended_copy_response_header_decoded",
            description: "CopyInResponse/CopyOutResponse must decode as Int8 overall format, Int16 count and Int16 column formats, and malformed headers must be rejected",
            category: TestCategory::ProtocolDistinction,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::copy_response_header,
        },
        Requirement {
            id: "pg_extended_ready_for_query_status_roundtrip",
            description: "ReadyForQuery must preserve idle, in-transaction, and failed-transaction status bytes",
            category: TestCategory::TransactionStatus,
            level: RequirementLevel::Must,
            evidence: TestInternalsHook,
            check: hooks::ready_for_query_status,
        },
    ]
}

fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

fn run_requirement(requirement: &Requirement) -> PostgresExtendedQueryResult {
    let start = Instant::now();
    // A panic in production code is a failure of that requirement, not of the
    // whole harness.
    let decision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(requirement.check))
        .unwrap_or_else(|payload| {
            Decision::Decided(Err(format!(
                "production code panicked: {}",
                panic_text(&*payload)
            )))
        });
    let (verdict, error_message) = match decision {
        Decision::Decided(Ok(())) => (TestVerdict::Pass, None),
        Decision::Decided(Err(reason)) => (TestVerdict::Fail, Some(reason)),
        Decision::Skipped(note) => (TestVerdict::Skipped, Some(note)),
    };
    PostgresExtendedQueryResult {
        test_id: requirement.id.to_string(),
        description: requirement.description.to_string(),
        category: requirement.category.clone(),
        requirement_level: requirement.level.clone(),
        verdict,
        error_message,
        execution_time_ms: start.elapsed().as_millis() as u64,
    }
}

#[allow(dead_code)]
pub struct PostgresExtendedQueryConformanceHarness {
    tests: Vec<Requirement>,
}

#[allow(dead_code)]
impl PostgresExtendedQueryConformanceHarness {
    pub fn new() -> Self {
        Self {
            tests: requirements(),
        }
    }

    pub fn run_all_tests(&self) -> Vec<PostgresExtendedQueryResult> {
        self.tests.iter().map(run_requirement).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The requirements no production hook can decide. Moving one out of
    /// this set needs a production observable for it.
    const UNOBSERVABLE: [&str; 5] = [
        "pg_extended_parse_bind_describe_execute_sync_pipeline",
        "pg_extended_describe_message_wire_format",
        "pg_extended_named_statement_survives_sync_barrier",
        "pg_extended_error_response_drains_to_ready",
        "pg_extended_copy_messages_are_distinct_from_pipeline",
    ];

    fn expected_verdict(evidence: Evidence) -> TestVerdict {
        let reachable = match evidence {
            Evidence::Unobservable => false,
            Evidence::PublicBuilder => cfg!(feature = "postgres"),
            Evidence::TestInternalsHook => {
                cfg!(all(feature = "postgres", feature = "test-internals"))
            }
        };
        if reachable {
            TestVerdict::Pass
        } else {
            TestVerdict::Skipped
        }
    }

    #[test]
    fn test_conformance_harness_execution() {
        let requirements = requirements();
        let results = PostgresExtendedQueryConformanceHarness::new().run_all_tests();

        assert_eq!(
            results.len(),
            16,
            "expected sixteen extended-query requirements"
        );
        let ids: BTreeSet<&str> = results.iter().map(|r| r.test_id.as_str()).collect();
        assert_eq!(ids.len(), results.len(), "requirement ids must be unique");
        for id in [
            "pg_extended_parse_bind_describe_execute_sync_pipeline",
            "pg_extended_named_statement_survives_sync_barrier",
            "pg_extended_error_response_drains_to_ready",
            "pg_extended_row_description_matches_oid_metadata",
            "pg_extended_copy_messages_are_distinct_from_pipeline",
            "pg_extended_ready_for_query_status_roundtrip",
        ] {
            assert!(ids.contains(id), "missing requirement {id}");
        }

        let failures: Vec<_> = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Fail)
            .collect();
        assert!(failures.is_empty(), "spec violations: {failures:#?}");

        let unobservable: BTreeSet<&str> = requirements
            .iter()
            .filter(|r| r.evidence == Evidence::Unobservable)
            .map(|r| r.id)
            .collect();
        assert_eq!(
            unobservable,
            UNOBSERVABLE.into_iter().collect::<BTreeSet<_>>()
        );

        for (requirement, result) in requirements.iter().zip(&results) {
            assert_eq!(result.test_id, requirement.id);
            assert_eq!(
                result.verdict,
                expected_verdict(requirement.evidence),
                "{}: {:?}",
                result.test_id,
                result.error_message
            );
            if result.verdict == TestVerdict::Skipped {
                let note = result.error_message.as_deref().unwrap_or("");
                let reason = if requirement.evidence == Evidence::Unobservable {
                    NO_OBSERVABLE
                } else {
                    "needs --features "
                };
                assert!(
                    note.starts_with(reason),
                    "{}: skip note {note:?} must start with {reason:?}",
                    result.test_id
                );
            }
        }
    }

    /// Pins the oracle builders to bytes encoded by hand from the
    /// message-format table, so the oracle cannot drift along with production.
    #[test]
    fn oracle_builders_match_hand_encoded_spec_bytes() {
        let mut parse = vec![b'P', 0, 0, 0, 16, 0];
        parse.extend_from_slice(b"SELECT 1");
        parse.extend_from_slice(&[0, 0, 0]);
        assert_eq!(build_parse_message("", "SELECT 1", &[]), parse);

        assert_eq!(
            build_bind_message("", "", &[], &[], &[0]),
            vec![b'B', 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(
            build_bind_message("", "s", &[1], &[Some(&[0, 0, 0, 42][..])], &[0]),
            vec![
                b'B', 0, 0, 0, 25, 0, b's', 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 4, 0, 0, 0, 42, 0, 1, 0,
                0
            ]
        );
        assert_eq!(
            build_execute_message("", 0),
            vec![b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0]
        );
        assert_eq!(build_sync_message(), vec![b'S', 0, 0, 0, 4]);
        assert_eq!(build_ready_for_query(b'I'), vec![b'Z', 0, 0, 0, 5, b'I']);

        assert_eq!(error_response_body(&[(b'C', "X")]), vec![b'C', b'X', 0, 0]);
        assert_eq!(
            row_description_body(&[ColumnSpec {
                name: "a",
                table_oid: 1,
                column_id: 1,
                type_oid: pg_type_oids::INT4,
                type_size: 4,
                type_modifier: -1,
                format: 0,
            }]),
            vec![
                0, 1, b'a', 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 23, 0, 4, 0xff, 0xff, 0xff, 0xff, 0, 0
            ]
        );
        assert_eq!(
            data_row_body(2, &[None, Some(&b"ab"[..])]),
            vec![0, 2, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 2, b'a', b'b']
        );
        assert_eq!(copy_response_body(1, 2, &[0, 1]), vec![1, 0, 2, 0, 0, 0, 1]);
    }
}
