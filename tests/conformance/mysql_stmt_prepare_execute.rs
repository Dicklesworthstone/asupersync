#![allow(warnings)]
#![allow(clippy::all)]
//! MySQL prepared-statement (COM_STMT_PREPARE / COM_STMT_EXECUTE) conformance,
//! run against the binary-protocol client in `src/database/mysql.rs`.
//!
//! Each requirement is either decided by production code or reported as
//! `TestVerdict::Skipped` with the reason. No verdict comes from a model in
//! this file:
//!
//! * COM_STMT_EXECUTE is built by production with
//!   `fuzz_build_stmt_execute_packet`. The parameter block (NULL bitmap,
//!   new_params_bound_flag, parameter types and values) comes from the
//!   production `write_stmt_execute_params` and `ToSql` impls, and the packet
//!   header from the production `PacketBuffer::build_packet`. The 10-byte
//!   command prefix is written by the hook itself
//!   (src/database/mysql.rs:7016-7021); it restates the same lines of
//!   `query_prepared_inner_impl` and `execute_prepared_inner_impl`
//!   (src/database/mysql.rs:5337-5342 and 5479-5484) instead of sharing a
//!   function with them. The bytes are compared one for one with this file's
//!   spec encoding, whose builders are pinned to hand-encoded bytes in the
//!   tests at the bottom.
//! * Server packets are encoded here from the spec and decoded by production:
//!   `fuzz_parse_column_definition`, `fuzz_parse_binary_row`,
//!   `fuzz_parse_text_row`, `fuzz_parse_data_row_or_terminator`,
//!   `fuzz_parse_ok_packet_fields`, `fuzz_parse_error_packet` and
//!   `fuzz_decode_packet_header`. Spec-valid and malformed bytes are both fed
//!   in. Production's public `column_type` constants are checked against the
//!   protocol's field-type table.
//! * Production exposes no observable for the COM_STMT_PREPARE exchange,
//!   COM_STMT_CLOSE, long data, cursors other than "no cursor", the
//!   client-side parameter-count check, or the binary result-set terminator.
//!   Those run inside async `MySqlConnection` methods against a live server,
//!   or are never sent, so they are reported as Skipped with the source lines
//!   that show why.
//! * Without `--features mysql` every production-decided requirement reports
//!   Skipped ("needs --features mysql"). The hooks need no other feature.
//!
//! Where the spec lets the client choose, the exact-byte fixtures encode one
//! valid choice: text parameters are declared MYSQL_TYPE_VAR_STRING and byte
//! parameters MYSQL_TYPE_BLOB (any string-class type is valid, and
//! MYSQL-STMT-005 accepts the whole class), and a NULL parameter keeps its
//! declared type, as libmysqlclient's `store_param_type` sends it.
//!
//! References, MySQL Client/Server Protocol
//! (https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html):
//! "MySQL Packets", "Integer Types" (length-encoded integers),
//! "COM_STMT_EXECUTE", "Binary Protocol Resultset", "Binary Protocol Value",
//! "Text Resultset", "Column Definition", "OK_Packet", "EOF_Packet",
//! "ERR_Packet" and the MYSQL_TYPE field-type table.

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Test result for a single conformance requirement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct MySqlStmtConformanceResult {
    pub test_id: String,
    pub description: String,
    pub category: TestCategory,
    pub requirement_level: RequirementLevel,
    pub verdict: TestVerdict,
    /// Why the requirement failed or was skipped; `None` on a pass.
    pub notes: Option<String>,
    pub elapsed_ms: u64,
}

/// Conformance test categories for MySQL prepared statements.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestCategory {
    PacketFormat,
    ParameterTypes,
    NullBitmap,
    LongData,
    CursorFlags,
    BinaryResultSet,
    TextResultSet,
    ErrorHandling,
}

/// Protocol requirement level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum RequirementLevel {
    Must,   // Protocol requirement
    Should, // Recommended behavior
    May,    // Optional feature
}

/// Test execution result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum TestVerdict {
    Pass,
    Fail,
    Skipped,
    ExpectedFailure,
}

/// MySQL field types (MYSQL_TYPE_*) from the protocol's field-type table.
/// This is the spec side of every type-code comparison.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum MySqlType {
    Decimal = 0x00,
    Tiny = 0x01,
    Short = 0x02,
    Long = 0x03,
    Float = 0x04,
    Double = 0x05,
    Null = 0x06,
    Timestamp = 0x07,
    LongLong = 0x08,
    Int24 = 0x09,
    Date = 0x0A,
    Time = 0x0B,
    DateTime = 0x0C,
    Year = 0x0D,
    NewDate = 0x0E,
    VarChar = 0x0F,
    Bit = 0x10,
    Json = 0xF5,
    NewDecimal = 0xF6,
    Enum = 0xF7,
    Set = 0xF8,
    TinyBlob = 0xF9,
    MediumBlob = 0xFA,
    LongBlob = 0xFB,
    Blob = 0xFC,
    VarString = 0xFD,
    String = 0xFE,
    Geometry = 0xFF,
}

/// COM_STMT_EXECUTE cursor type flags.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CursorType {
    NoCursor = 0x00,
    ReadOnly = 0x01,
    ForUpdate = 0x02,
    Scrollable = 0x04,
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
    /// `#[doc(hidden)]` hooks and public items of `asupersync::database::mysql`,
    /// compiled only with `--features mysql`.
    MysqlHook,
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
// Spec oracle: packet encodings written from the protocol documentation
// ============================================================================

mod protocol_constants {
    /// COM_STMT_EXECUTE command byte.
    pub const COM_STMT_EXECUTE: u8 = 0x17;
    /// new_params_bound_flag value saying the parameter types follow.
    pub const NEW_PARAMS_BOUND: u8 = 0x01;
    /// High byte of a parameter type field for an UNSIGNED integer.
    pub const PARAM_UNSIGNED: u8 = 0x80;
    pub const OK_HEADER: u8 = 0x00;
    pub const EOF_HEADER: u8 = 0xFE;
    pub const ERR_HEADER: u8 = 0xFF;
    /// A NULL value in a text resultset row.
    pub const TEXT_NULL: u8 = 0xFB;
    /// The most payload one packet carries: 2^24 - 1 bytes.
    pub const MAX_PAYLOAD: usize = 0xFF_FFFF;

    // Column definition flags.
    pub const NOT_NULL_FLAG: u16 = 0x0001;
    pub const PRI_KEY_FLAG: u16 = 0x0002;
    pub const BLOB_FLAG: u16 = 0x0010;
    pub const UNSIGNED_FLAG: u16 = 0x0020;
    pub const ZEROFILL_FLAG: u16 = 0x0040;
    pub const BINARY_FLAG: u16 = 0x0080;
    pub const AUTO_INCREMENT_FLAG: u16 = 0x0200;

    // Server status flags.
    pub const SERVER_STATUS_IN_TRANS: u16 = 0x0001;
    pub const SERVER_STATUS_AUTOCOMMIT: u16 = 0x0002;

    // Character set (collation) ids.
    pub const CHARSET_BINARY: u16 = 63;
    pub const CHARSET_UTF8MB4: u16 = 255;
}

/// Length-encoded integer: below 251 in one byte, then 0xFC + int<2>,
/// 0xFD + int<3> and 0xFE + int<8>.
fn encode_length_encoded_integer(value: u64) -> Vec<u8> {
    if value < 251 {
        vec![value as u8]
    } else if value < 65536 {
        let mut result = vec![0xFC];
        result.extend_from_slice(&(value as u16).to_le_bytes());
        result
    } else if value < 16_777_216 {
        let mut result = vec![0xFD];
        result.extend_from_slice(&(value as u32).to_le_bytes()[0..3]);
        result
    } else {
        let mut result = vec![0xFE];
        result.extend_from_slice(&value.to_le_bytes());
        result
    }
}

/// Length-encoded string: a length-encoded integer, then that many bytes.
fn encode_length_encoded_string(data: &[u8]) -> Vec<u8> {
    let mut result = encode_length_encoded_integer(data.len() as u64);
    result.extend_from_slice(data);
    result
}

/// Frames a payload as MySQL packets: int<3> payload length, int<1> sequence
/// id, then the payload. A payload of 2^24 - 1 bytes or more goes out in
/// packets of 2^24 - 1 bytes with consecutive sequence ids, and one that is an
/// exact multiple of that size ends with an empty packet.
fn frame_packets(first_sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(payload.len() + 8);
    let mut sequence = first_sequence;
    let mut rest = payload;
    loop {
        let chunk = rest.len().min(protocol_constants::MAX_PAYLOAD);
        framed.extend_from_slice(&[
            (chunk & 0xFF) as u8,
            ((chunk >> 8) & 0xFF) as u8,
            ((chunk >> 16) & 0xFF) as u8,
            sequence,
        ]);
        framed.extend_from_slice(&rest[..chunk]);
        rest = &rest[chunk..];
        sequence = sequence.wrapping_add(1);
        if chunk < protocol_constants::MAX_PAYLOAD {
            return framed;
        }
    }
}

/// One COM_STMT_EXECUTE parameter as the spec lays it out.
#[derive(Debug, Clone)]
struct SpecParam {
    type_code: u8,
    unsigned: bool,
    /// The binary-protocol value bytes, or `None` for SQL NULL.
    value: Option<Vec<u8>>,
}

impl SpecParam {
    fn bound(type_code: MySqlType, unsigned: bool, value: Vec<u8>) -> Self {
        Self {
            type_code: type_code as u8,
            unsigned,
            value: Some(value),
        }
    }

    /// A NULL parameter. The spec leaves its type field to the client; the
    /// oracle keeps the declared type and unsigned flag, as libmysqlclient's
    /// `store_param_type` does for a NULL bind.
    fn null(type_code: MySqlType, unsigned: bool) -> Self {
        Self {
            type_code: type_code as u8,
            unsigned,
            value: None,
        }
    }
}

/// COM_STMT_EXECUTE payload: int<1> 0x17, int<4> statement_id, int<1> flags,
/// int<4> iteration_count (always 1), then, only when there are parameters:
/// the NULL bitmap of (n + 7) / 8 bytes (parameter i is bit i % 8 of byte
/// i / 8), int<1> new_params_bound_flag, n x int<2> parameter type (type code,
/// then 0x80 for UNSIGNED), and the values of the non-NULL parameters in order.
fn stmt_execute_payload(statement_id: u32, flags: u8, params: &[SpecParam]) -> Vec<u8> {
    let mut payload = vec![protocol_constants::COM_STMT_EXECUTE];
    payload.extend_from_slice(&statement_id.to_le_bytes());
    payload.push(flags);
    payload.extend_from_slice(&1u32.to_le_bytes());
    if params.is_empty() {
        return payload;
    }
    let mut bitmap = vec![0u8; (params.len() + 7) / 8];
    for (index, param) in params.iter().enumerate() {
        if param.value.is_none() {
            bitmap[index / 8] |= 1 << (index % 8);
        }
    }
    payload.extend_from_slice(&bitmap);
    payload.push(protocol_constants::NEW_PARAMS_BOUND);
    for param in params {
        payload.push(param.type_code);
        payload.push(if param.unsigned {
            protocol_constants::PARAM_UNSIGNED
        } else {
            0x00
        });
    }
    for value in params.iter().filter_map(|param| param.value.as_ref()) {
        payload.extend_from_slice(value);
    }
    payload
}

/// A framed COM_STMT_EXECUTE: sequence id 0, CURSOR_TYPE_NO_CURSOR.
fn stmt_execute_packet(statement_id: u32, params: &[SpecParam]) -> Vec<u8> {
    frame_packets(
        0,
        &stmt_execute_payload(statement_id, CursorType::NoCursor as u8, params),
    )
}

/// The fields of a Column Definition 41 packet. The catalog is always "def".
#[derive(Debug, Clone)]
struct ColumnSpec {
    schema: &'static str,
    table: &'static str,
    org_table: &'static str,
    name: String,
    org_name: String,
    charset: u16,
    length: u32,
    column_type: u8,
    flags: u16,
    decimals: u8,
}

/// A column of table `test.t` whose name and original name are `name`.
fn column_spec(
    name: &str,
    column_type: MySqlType,
    charset: u16,
    length: u32,
    flags: u16,
    decimals: u8,
) -> ColumnSpec {
    ColumnSpec {
        schema: "test",
        table: "t",
        org_table: "t",
        name: name.to_string(),
        org_name: name.to_string(),
        charset,
        length,
        column_type: column_type as u8,
        flags,
        decimals,
    }
}

/// `count` signed INT columns named c0, c1, ...
fn int_columns(count: usize) -> Vec<ColumnSpec> {
    (0..count)
        .map(|index| {
            column_spec(
                &format!("c{index}"),
                MySqlType::Long,
                protocol_constants::CHARSET_BINARY,
                11,
                0,
                0,
            )
        })
        .collect()
}

/// Column Definition 41: six length-encoded strings (catalog, schema, table,
/// org_table, name, org_name), the length of the fixed fields (0x0C), int<2>
/// character set, int<4> column length, int<1> type, int<2> flags, int<1>
/// decimals and a 2-byte zero filler.
fn column_definition_bytes(column: &ColumnSpec) -> Vec<u8> {
    let mut packet = Vec::new();
    for text in [
        "def",
        column.schema,
        column.table,
        column.org_table,
        column.name.as_str(),
        column.org_name.as_str(),
    ] {
        packet.extend_from_slice(&encode_length_encoded_string(text.as_bytes()));
    }
    packet.push(0x0C);
    packet.extend_from_slice(&column.charset.to_le_bytes());
    packet.extend_from_slice(&column.length.to_le_bytes());
    packet.push(column.column_type);
    packet.extend_from_slice(&column.flags.to_le_bytes());
    packet.push(column.decimals);
    packet.extend_from_slice(&[0x00, 0x00]);
    packet
}

/// Binary Protocol Resultset Row: header 0x00, a NULL bitmap of
/// (n + 7 + 2) / 8 bytes with column i at bit i + 2, then the values of the
/// non-NULL columns.
fn binary_row_bytes(values: &[Option<Vec<u8>>]) -> Vec<u8> {
    let mut row = vec![0x00];
    let mut bitmap = vec![0u8; (values.len() + 7 + 2) / 8];
    for (index, value) in values.iter().enumerate() {
        if value.is_none() {
            let bit = index + 2;
            bitmap[bit / 8] |= 1 << (bit % 8);
        }
    }
    row.extend_from_slice(&bitmap);
    for value in values.iter().flatten() {
        row.extend_from_slice(value);
    }
    row
}

/// Text Resultset Row: each value a length-encoded string, or 0xFB for NULL.
fn text_row_bytes(values: &[Option<&[u8]>]) -> Vec<u8> {
    let mut row = Vec::new();
    for value in values {
        match value {
            Some(bytes) => row.extend_from_slice(&encode_length_encoded_string(bytes)),
            None => row.push(protocol_constants::TEXT_NULL),
        }
    }
    row
}

/// OK_Packet with CLIENT_PROTOCOL_41: header, length-encoded affected_rows and
/// last_insert_id, int<2> status flags, int<2> warnings, then the info text.
fn ok_packet_bytes(
    header: u8,
    affected_rows: u64,
    last_insert_id: u64,
    status_flags: u16,
    warnings: u16,
    info: &[u8],
) -> Vec<u8> {
    let mut packet = vec![header];
    packet.extend_from_slice(&encode_length_encoded_integer(affected_rows));
    packet.extend_from_slice(&encode_length_encoded_integer(last_insert_id));
    packet.extend_from_slice(&status_flags.to_le_bytes());
    packet.extend_from_slice(&warnings.to_le_bytes());
    packet.extend_from_slice(info);
    packet
}

/// EOF_Packet with CLIENT_PROTOCOL_41: 0xFE, int<2> warnings, int<2> status flags.
fn eof_packet_bytes(warnings: u16, status_flags: u16) -> Vec<u8> {
    let mut packet = vec![protocol_constants::EOF_HEADER];
    packet.extend_from_slice(&warnings.to_le_bytes());
    packet.extend_from_slice(&status_flags.to_le_bytes());
    packet
}

/// ERR_Packet: 0xFF, int<2> error code, with CLIENT_PROTOCOL_41 the '#' marker
/// and the 5-character SQLSTATE, then the message.
fn err_packet_bytes(code: u16, sql_state: Option<&str>, message: &str) -> Vec<u8> {
    let mut packet = vec![protocol_constants::ERR_HEADER];
    packet.extend_from_slice(&code.to_le_bytes());
    if let Some(state) = sql_state {
        packet.push(b'#');
        packet.extend_from_slice(state.as_bytes());
    }
    packet.extend_from_slice(message.as_bytes());
    packet
}

/// Checks that `frame` is exactly one packet with sequence id 0, as a command
/// packet must be, and returns its payload.
fn single_packet_payload<'a>(what: &str, frame: &'a [u8]) -> Result<&'a [u8], String> {
    if frame.len() < 4 {
        return Err(format!(
            "{what}: {} bytes cannot hold the 4-byte packet header",
            frame.len()
        ));
    }
    let declared =
        usize::from(frame[0]) | (usize::from(frame[1]) << 8) | (usize::from(frame[2]) << 16);
    if declared != frame.len() - 4 || declared >= protocol_constants::MAX_PAYLOAD {
        return Err(format!(
            "{what}: the int<3> payload length is {declared}, but the frame carries {} payload bytes in one packet",
            frame.len() - 4
        ));
    }
    if frame[3] != 0 {
        return Err(format!(
            "{what}: sequence id {}, a command packet starts at 0",
            frame[3]
        ));
    }
    Ok(&frame[4..])
}

/// The parts of a one-parameter COM_STMT_EXECUTE payload.
struct OneParam<'a> {
    null_bit: bool,
    type_code: u8,
    type_flags: u8,
    value: &'a [u8],
}

/// Splits a one-parameter COM_STMT_EXECUTE packet at the offsets the spec
/// fixes: 10-byte prefix, 1-byte NULL bitmap, new_params_bound_flag, int<2>
/// type, then the value.
fn one_param<'a>(what: &str, frame: &'a [u8]) -> Result<OneParam<'a>, String> {
    let payload = single_packet_payload(what, frame)?;
    if payload.len() < 14 || payload[0] != protocol_constants::COM_STMT_EXECUTE {
        return Err(format!(
            "{what}: {payload:02x?} is not a one-parameter COM_STMT_EXECUTE payload"
        ));
    }
    if payload[10] & 0xFE != 0 {
        return Err(format!(
            "{what}: NULL bitmap {:#04x} sets bits beyond the single parameter",
            payload[10]
        ));
    }
    if payload[11] != protocol_constants::NEW_PARAMS_BOUND {
        return Err(format!(
            "{what}: new_params_bound_flag is {:#04x}, but the parameter types follow it, which needs 0x01",
            payload[11]
        ));
    }
    Ok(OneParam {
        null_bit: payload[10] & 0x01 != 0,
        type_code: payload[12],
        type_flags: payload[13],
        value: &payload[14..],
    })
}

/// Describes where two byte strings differ, without printing megabytes.
fn describe_mismatch(produced: &[u8], spec: &[u8]) -> String {
    const SHOWN: usize = 96;
    if produced.len() <= SHOWN && spec.len() <= SHOWN {
        return format!("production emitted {produced:02x?}, the spec encoding is {spec:02x?}");
    }
    let first = produced
        .iter()
        .zip(spec)
        .position(|(left, right)| left != right)
        .unwrap_or(produced.len().min(spec.len()));
    let window = |bytes: &[u8]| {
        let end = (first + 16).min(bytes.len());
        let start = first.saturating_sub(8).min(end);
        format!("{:02x?}", &bytes[start..end])
    };
    format!(
        "production emitted {} bytes, the spec encoding is {} bytes; they first differ at byte {first}: production {} vs spec {}",
        produced.len(),
        spec.len(),
        window(produced),
        window(spec)
    )
}

/// Compares production's bytes with the spec encoding.
fn expect_bytes(what: &str, produced: &[u8], spec: &[u8]) -> Result<(), String> {
    if produced == spec {
        Ok(())
    } else {
        Err(format!("{what}: {}", describe_mismatch(produced, spec)))
    }
}

/// `{:?}` cut to a readable length.
fn short_debug<T: std::fmt::Debug>(value: &T) -> String {
    const LIMIT: usize = 240;
    let text = format!("{value:?}");
    let chars = text.chars().count();
    if chars <= LIMIT {
        text
    } else {
        let head: String = text.chars().take(LIMIT).collect();
        format!("{head}... ({chars} chars)")
    }
}

// ============================================================================
// Requirements production exposes no observable for
// ============================================================================

fn prepare_packet_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: MySqlConnection::prepare_inner builds COM_STMT_PREPARE inline \
         (src/database/mysql.rs:5092-5097) and writes it to the socket inside an async fn; no \
         hook returns those bytes"
    ))
}

fn prepare_ok_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: the COM_STMT_PREPARE_OK header (status, statement_id, num_columns, \
         num_params, reserved byte, warning_count) is decoded by a closure inside the async \
         prepare_inner (src/database/mysql.rs:5127-5152), which reads it, and the parameter and \
         column definitions after it (src/database/mysql.rs:5155-5201), from a live socket. The \
         definitions themselves go through parse_column_definition, decided in MYSQL-STMT-026"
    ))
}

fn close_packet_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: COM_STMT_CLOSE is built only in the async close_prepared_statement_id \
         (src/database/mysql.rs:5228-5251), reached when prepare_inner evicts a cached statement \
         (src/database/mysql.rs:5215-5223); no hook returns the bytes"
    ))
}

fn long_data_packet_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: production never sends COM_STMT_SEND_LONG_DATA. \
         command::COM_STMT_SEND_LONG_DATA (src/database/mysql.rs:336) has no use, and \
         write_stmt_execute_params (src/database/mysql.rs:6213-6255) puts every value inline in \
         COM_STMT_EXECUTE"
    ))
}

fn long_data_chunking_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: production never sends COM_STMT_SEND_LONG_DATA \
         (src/database/mysql.rs:336 is its only mention), so there are no long-data chunks. A \
         large value goes inline in COM_STMT_EXECUTE and PacketBuffer::build_packet splits the \
         packet at 2^24 - 1 bytes, which MYSQL-STMT-008 and MYSQL-STMT-031 decide"
    ))
}

fn long_data_reset_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: production keeps no long-data state to reset. COM_STMT_SEND_LONG_DATA \
         and COM_STMT_RESET (src/database/mysql.rs:336 and 338) are declared and never sent"
    ))
}

fn read_only_cursor_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: production never requests CURSOR_TYPE_READ_ONLY. The COM_STMT_EXECUTE \
         flags byte is the constant 0x00 in query_prepared_inner_impl and \
         execute_prepared_inner_impl (src/database/mysql.rs:5341 and 5483), no API takes a cursor \
         type, and COM_STMT_FETCH is not implemented. MYSQL-STMT-016 decides the 0x00 byte"
    ))
}

fn scrollable_cursor_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: production never requests CURSOR_TYPE_SCROLLABLE. The flags byte is the \
         constant 0x00 (src/database/mysql.rs:5341 and 5483), no API takes a cursor type, and \
         COM_STMT_FETCH is not implemented"
    ))
}

fn parameter_count_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: the check params.len() != stmt.param_count runs inside the async \
         query_prepared_inner_impl and execute_prepared_inner_impl \
         (src/database/mysql.rs:5317-5323 and 5459-5465) on a live connection. MySqlStatement's \
         fields are private (src/database/mysql.rs:6292-6307), and fuzz_build_stmt_execute_packet \
         takes no expected parameter count"
    ))
}

fn invalid_cursor_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: no API accepts a cursor type, so production cannot send an invalid one \
         or be seen handling it. The flags byte is the constant 0x00 \
         (src/database/mysql.rs:5341 and 5483)"
    ))
}

fn binary_terminator_unobservable() -> Decision {
    Decision::Skipped(format!(
        "{NO_OBSERVABLE}: binary result-set rows are told apart from their EOF/OK terminator by \
         the private parse_binary_row_or_terminator (src/database/mysql.rs:3997-4017), called \
         from the async read_binary_result_set (src/database/mysql.rs:3815-3871), which also \
         routes an ERR packet to parse_error (src/database/mysql.rs:3855). fuzz_parse_binary_row \
         calls parse_binary_row directly. The text-protocol terminator logic is decided in \
         MYSQL-STMT-028"
    ))
}

// ============================================================================
// Requirements decided by production code
// ============================================================================

#[cfg(feature = "mysql")]
mod production {
    use super::protocol_constants::*;
    use super::*;
    use asupersync::database::mysql::{
        MySqlColumn, MySqlError, MySqlValue, ToSql, column_type, fuzz_build_stmt_execute_packet,
        fuzz_decode_packet_header, fuzz_parse_binary_row, fuzz_parse_column_definition,
        fuzz_parse_data_row_or_terminator, fuzz_parse_error_packet, fuzz_parse_ok_packet_fields,
        fuzz_parse_text_row,
    };

    pub(super) fn stmt_execute_packet_format() -> Decision {
        Decision::Decided(check_stmt_execute_packet())
    }

    pub(super) fn parameter_type_codes() -> Decision {
        Decision::Decided(check_parameter_type_codes())
    }

    pub(super) fn type_code_table() -> Decision {
        Decision::Decided(check_type_code_table())
    }

    pub(super) fn unsigned_flag() -> Decision {
        Decision::Decided(check_unsigned_flag())
    }

    pub(super) fn parameter_length_encoding() -> Decision {
        Decision::Decided(check_parameter_length_encoding())
    }

    pub(super) fn null_bitmap_encoding() -> Decision {
        Decision::Decided(check_null_bitmap_encoding())
    }

    pub(super) fn null_bitmap_length() -> Decision {
        Decision::Decided(check_null_bitmap_length())
    }

    pub(super) fn null_bitmap_bit_order() -> Decision {
        Decision::Decided(check_null_bitmap_bit_order())
    }

    pub(super) fn mixed_null_parameters() -> Decision {
        Decision::Decided(check_mixed_null_parameters())
    }

    pub(super) fn cursor_flags_byte() -> Decision {
        Decision::Decided(check_cursor_flags_byte())
    }

    pub(super) fn binary_result_row() -> Decision {
        Decision::Decided(check_binary_result_row())
    }

    pub(super) fn binary_row_null_bitmap_offset() -> Decision {
        Decision::Decided(check_binary_row_null_bitmap_offset())
    }

    pub(super) fn binary_value_encoding() -> Decision {
        Decision::Decided(check_binary_value_encoding())
    }

    pub(super) fn length_encoded_values() -> Decision {
        Decision::Decided(check_length_encoded_values())
    }

    pub(super) fn invalid_statement_id() -> Decision {
        Decision::Decided(check_invalid_statement_id())
    }

    pub(super) fn column_definition() -> Decision {
        Decision::Decided(check_column_definition())
    }

    pub(super) fn text_result_row() -> Decision {
        Decision::Decided(check_text_result_row())
    }

    pub(super) fn text_result_terminators() -> Decision {
        Decision::Decided(check_text_result_terminators())
    }

    pub(super) fn ok_packet() -> Decision {
        Decision::Decided(check_ok_packet())
    }

    pub(super) fn err_packet() -> Decision {
        Decision::Decided(check_err_packet())
    }

    pub(super) fn packet_framing() -> Decision {
        Decision::Decided(check_packet_framing())
    }

    // ---- helpers ----------------------------------------------------------

    /// Production's COM_STMT_EXECUTE packet, header included.
    fn build(what: &str, statement_id: u32, params: &[&dyn ToSql]) -> Result<Vec<u8>, String> {
        fuzz_build_stmt_execute_packet(statement_id, params)
            .map_err(|err| format!("{what}: production refused to build it: {err:?}"))
    }

    fn expect_execute(
        what: &str,
        statement_id: u32,
        params: &[&dyn ToSql],
        spec: &[u8],
    ) -> Result<Vec<u8>, String> {
        let produced = build(what, statement_id, params)?;
        expect_bytes(what, &produced, spec)?;
        Ok(produced)
    }

    /// Decodes spec-encoded column definitions with production's decoder and
    /// checks every field, so the rows below are parsed with metadata that
    /// production itself produced.
    fn decode_columns(what: &str, specs: &[ColumnSpec]) -> Result<Vec<MySqlColumn>, String> {
        let mut columns = Vec::with_capacity(specs.len());
        for spec in specs {
            let bytes = column_definition_bytes(spec);
            let column = fuzz_parse_column_definition(&bytes).map_err(|err| {
                format!(
                    "{what}: production rejected the spec-valid definition of column {:?} ({}): {err:?}",
                    spec.name,
                    short_debug(&bytes)
                )
            })?;
            check_column(what, &column, spec)?;
            columns.push(column);
        }
        Ok(columns)
    }

    fn check_column(what: &str, got: &MySqlColumn, want: &ColumnSpec) -> Result<(), String> {
        let got_fields = (
            got.catalog.as_str(),
            got.schema.as_str(),
            got.table.as_str(),
            got.org_table.as_str(),
            got.name.as_str(),
            got.org_name.as_str(),
            got.charset,
            got.length,
            got.column_type,
            got.flags,
            got.decimals,
        );
        let want_fields = (
            "def",
            want.schema,
            want.table,
            want.org_table,
            want.name.as_str(),
            want.org_name.as_str(),
            want.charset,
            want.length,
            want.column_type,
            want.flags,
            want.decimals,
        );
        if got_fields == want_fields {
            Ok(())
        } else {
            Err(format!(
                "{what}: production decoded (catalog, schema, table, org_table, name, org_name, charset, length, type, flags, decimals) = {}, the spec bytes carry {}",
                short_debug(&got_fields),
                short_debug(&want_fields)
            ))
        }
    }

    fn expect_binary_row(
        what: &str,
        row: &[u8],
        columns: &[MySqlColumn],
        expected: &[MySqlValue],
    ) -> Result<(), String> {
        match fuzz_parse_binary_row(row, columns) {
            Ok(values) if values.as_slice() == expected => Ok(()),
            other => Err(format!(
                "{what}: binary row {} carries {}, production returned {}",
                short_debug(&row),
                short_debug(&expected),
                short_debug(&other)
            )),
        }
    }

    /// The decimal value of an integer, whatever lossless variant holds it.
    fn integer_text(value: &MySqlValue) -> Option<String> {
        match value {
            MySqlValue::Tiny(v) => Some(v.to_string()),
            MySqlValue::Short(v) => Some(v.to_string()),
            MySqlValue::Long(v) => Some(v.to_string()),
            MySqlValue::LongLong(v) => Some(v.to_string()),
            MySqlValue::Text(text)
                if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                Some(text.clone())
            }
            _ => None,
        }
    }

    // ---- MYSQL-STMT-003 ---------------------------------------------------

    fn check_stmt_execute_packet() -> Result<(), String> {
        // Encoded by hand: statement 1234, a NULL INT and the string "test_value".
        let null_int: Option<i32> = None;
        let text: &str = "test_value";
        let params: [&dyn ToSql; 2] = [&null_int, &text];
        let mut spec = vec![
            27, 0, 0, 0,    // payload length 27, sequence id 0
            0x17, // COM_STMT_EXECUTE
            0xD2, 0x04, 0x00, 0x00, // statement_id 1234
            0x00, // flags: CURSOR_TYPE_NO_CURSOR
            0x01, 0x00, 0x00, 0x00, // iteration_count 1
            0x01, // NULL bitmap: parameter 0 is NULL
            0x01, // new_params_bound_flag
            0x03, 0x00, // parameter 0: MYSQL_TYPE_LONG, signed
            0xFD, 0x00, // parameter 1: MYSQL_TYPE_VAR_STRING
            0x0A, // parameter 1 value: length 10, then the bytes
        ];
        spec.extend_from_slice(b"test_value");
        expect_execute(
            "COM_STMT_EXECUTE(1234, [NULL INT, \"test_value\"])",
            1234,
            &params,
            &spec,
        )?;

        // Encoded by hand: no parameters, so nothing follows the iteration count.
        let none: [&dyn ToSql; 0] = [];
        expect_execute(
            "COM_STMT_EXECUTE(42, [])",
            42,
            &none,
            &[10, 0, 0, 0, 0x17, 42, 0, 0, 0, 0x00, 0x01, 0x00, 0x00, 0x00],
        )?;

        let id: i64 = -1;
        let port: u16 = 3306;
        let blob: &[u8] = &[0x00, 0xFF, 0x7F];
        let params: [&dyn ToSql; 3] = [&id, &port, &blob];
        let spec = stmt_execute_packet(
            0x0102_0304,
            &[
                SpecParam::bound(MySqlType::LongLong, false, (-1i64).to_le_bytes().to_vec()),
                SpecParam::bound(MySqlType::Short, true, 3306u16.to_le_bytes().to_vec()),
                SpecParam::bound(
                    MySqlType::Blob,
                    false,
                    encode_length_encoded_string(&[0x00, 0xFF, 0x7F]),
                ),
            ],
        );
        expect_execute(
            "COM_STMT_EXECUTE(0x01020304, [-1i64, 3306u16, 3-byte blob])",
            0x0102_0304,
            &params,
            &spec,
        )?;
        Ok(())
    }

    // ---- MYSQL-STMT-005 ---------------------------------------------------

    fn check_parameter_type_codes() -> Result<(), String> {
        let tiny: i8 = -5;
        let short: i16 = -2;
        let long: i32 = 1_000_000;
        let longlong: i64 = -9_000_000_000;
        let float: f32 = 1.5;
        let double: f64 = -2.25;
        let flag: bool = true;
        // A fixed-width value fixes its type code: the server reads as many
        // bytes as the declared type has.
        let fixed: [(&str, &dyn ToSql, MySqlType, Vec<u8>); 7] = [
            (
                "i8 -5",
                &tiny,
                MySqlType::Tiny,
                (-5i8).to_le_bytes().to_vec(),
            ),
            (
                "i16 -2",
                &short,
                MySqlType::Short,
                (-2i16).to_le_bytes().to_vec(),
            ),
            (
                "i32 1000000",
                &long,
                MySqlType::Long,
                1_000_000i32.to_le_bytes().to_vec(),
            ),
            (
                "i64 -9000000000",
                &longlong,
                MySqlType::LongLong,
                (-9_000_000_000i64).to_le_bytes().to_vec(),
            ),
            (
                "f32 1.5",
                &float,
                MySqlType::Float,
                1.5f32.to_le_bytes().to_vec(),
            ),
            (
                "f64 -2.25",
                &double,
                MySqlType::Double,
                (-2.25f64).to_le_bytes().to_vec(),
            ),
            ("bool true", &flag, MySqlType::Tiny, vec![0x01]),
        ];
        for (label, param, code, value) in fixed {
            let what = format!("COM_STMT_EXECUTE with one {label} parameter");
            let produced = build(&what, 5, &[param])?;
            let layout = one_param(&what, &produced)?;
            if layout.null_bit || layout.type_code != code as u8 || layout.value != value.as_slice()
            {
                return Err(format!(
                    "{what}: production sent type {:#04x} (NULL bit {}) with value {:02x?}; a {label} value is sent as {code:?} ({:#04x}) with value {value:02x?}",
                    layout.type_code, layout.null_bit, layout.value, code as u8
                ));
            }
        }

        // A length-encoded value may be declared as any string-class type.
        const STRING_CLASS: [MySqlType; 7] = [
            MySqlType::VarChar,
            MySqlType::TinyBlob,
            MySqlType::MediumBlob,
            MySqlType::LongBlob,
            MySqlType::Blob,
            MySqlType::VarString,
            MySqlType::String,
        ];
        let text: &str = "h\u{e9}llo";
        let owned = String::from("abc");
        let bytes: &[u8] = &[0x00, 0x01, 0xFE];
        let vec_bytes: Vec<u8> = vec![0xFF; 3];
        let lenenc: [(&str, &dyn ToSql, Vec<u8>); 4] = [
            (
                "&str \"h\u{e9}llo\"",
                &text,
                encode_length_encoded_string("h\u{e9}llo".as_bytes()),
            ),
            (
                "String \"abc\"",
                &owned,
                encode_length_encoded_string(b"abc"),
            ),
            (
                "&[u8]",
                &bytes,
                encode_length_encoded_string(&[0x00, 0x01, 0xFE]),
            ),
            (
                "Vec<u8>",
                &vec_bytes,
                encode_length_encoded_string(&[0xFF; 3]),
            ),
        ];
        for (label, param, value) in lenenc {
            let what = format!("COM_STMT_EXECUTE with one {label} parameter");
            let produced = build(&what, 5, &[param])?;
            let layout = one_param(&what, &produced)?;
            let string_class = STRING_CLASS
                .iter()
                .any(|class| *class as u8 == layout.type_code);
            if layout.null_bit || !string_class || layout.value != value.as_slice() {
                return Err(format!(
                    "{what}: production sent type {:#04x} (NULL bit {}) with value {:02x?}; a length-encoded value needs a string-class type ({STRING_CLASS:?}) and the value {value:02x?}",
                    layout.type_code, layout.null_bit, layout.value
                ));
            }
        }

        // A NULL parameter is marked in the bitmap and has no value bytes; its
        // 2-byte type field is still present.
        let null_int: Option<u32> = None;
        let what = "COM_STMT_EXECUTE with one NULL parameter";
        let produced = build(what, 5, &[&null_int])?;
        let layout = one_param(what, &produced)?;
        if !layout.null_bit || !layout.value.is_empty() {
            return Err(format!(
                "{what}: production set the NULL bit to {} and sent value bytes {:02x?}; a NULL parameter has its bit set and no value",
                layout.null_bit, layout.value
            ));
        }
        Ok(())
    }

    // ---- MYSQL-STMT-006 ---------------------------------------------------

    fn check_type_code_table() -> Result<(), String> {
        // MYSQL_TYPE_NEWDATE is server-internal and never sent, and production
        // has no constant for it.
        let table: [(&str, u8, MySqlType); 27] = [
            (
                "MYSQL_TYPE_DECIMAL",
                column_type::MYSQL_TYPE_DECIMAL,
                MySqlType::Decimal,
            ),
            (
                "MYSQL_TYPE_TINY",
                column_type::MYSQL_TYPE_TINY,
                MySqlType::Tiny,
            ),
            (
                "MYSQL_TYPE_SHORT",
                column_type::MYSQL_TYPE_SHORT,
                MySqlType::Short,
            ),
            (
                "MYSQL_TYPE_LONG",
                column_type::MYSQL_TYPE_LONG,
                MySqlType::Long,
            ),
            (
                "MYSQL_TYPE_FLOAT",
                column_type::MYSQL_TYPE_FLOAT,
                MySqlType::Float,
            ),
            (
                "MYSQL_TYPE_DOUBLE",
                column_type::MYSQL_TYPE_DOUBLE,
                MySqlType::Double,
            ),
            (
                "MYSQL_TYPE_NULL",
                column_type::MYSQL_TYPE_NULL,
                MySqlType::Null,
            ),
            (
                "MYSQL_TYPE_TIMESTAMP",
                column_type::MYSQL_TYPE_TIMESTAMP,
                MySqlType::Timestamp,
            ),
            (
                "MYSQL_TYPE_LONGLONG",
                column_type::MYSQL_TYPE_LONGLONG,
                MySqlType::LongLong,
            ),
            (
                "MYSQL_TYPE_INT24",
                column_type::MYSQL_TYPE_INT24,
                MySqlType::Int24,
            ),
            (
                "MYSQL_TYPE_DATE",
                column_type::MYSQL_TYPE_DATE,
                MySqlType::Date,
            ),
            (
                "MYSQL_TYPE_TIME",
                column_type::MYSQL_TYPE_TIME,
                MySqlType::Time,
            ),
            (
                "MYSQL_TYPE_DATETIME",
                column_type::MYSQL_TYPE_DATETIME,
                MySqlType::DateTime,
            ),
            (
                "MYSQL_TYPE_YEAR",
                column_type::MYSQL_TYPE_YEAR,
                MySqlType::Year,
            ),
            (
                "MYSQL_TYPE_VARCHAR",
                column_type::MYSQL_TYPE_VARCHAR,
                MySqlType::VarChar,
            ),
            (
                "MYSQL_TYPE_BIT",
                column_type::MYSQL_TYPE_BIT,
                MySqlType::Bit,
            ),
            (
                "MYSQL_TYPE_JSON",
                column_type::MYSQL_TYPE_JSON,
                MySqlType::Json,
            ),
            (
                "MYSQL_TYPE_NEWDECIMAL",
                column_type::MYSQL_TYPE_NEWDECIMAL,
                MySqlType::NewDecimal,
            ),
            (
                "MYSQL_TYPE_ENUM",
                column_type::MYSQL_TYPE_ENUM,
                MySqlType::Enum,
            ),
            (
                "MYSQL_TYPE_SET",
                column_type::MYSQL_TYPE_SET,
                MySqlType::Set,
            ),
            (
                "MYSQL_TYPE_TINY_BLOB",
                column_type::MYSQL_TYPE_TINY_BLOB,
                MySqlType::TinyBlob,
            ),
            (
                "MYSQL_TYPE_MEDIUM_BLOB",
                column_type::MYSQL_TYPE_MEDIUM_BLOB,
                MySqlType::MediumBlob,
            ),
            (
                "MYSQL_TYPE_LONG_BLOB",
                column_type::MYSQL_TYPE_LONG_BLOB,
                MySqlType::LongBlob,
            ),
            (
                "MYSQL_TYPE_BLOB",
                column_type::MYSQL_TYPE_BLOB,
                MySqlType::Blob,
            ),
            (
                "MYSQL_TYPE_VAR_STRING",
                column_type::MYSQL_TYPE_VAR_STRING,
                MySqlType::VarString,
            ),
            (
                "MYSQL_TYPE_STRING",
                column_type::MYSQL_TYPE_STRING,
                MySqlType::String,
            ),
            (
                "MYSQL_TYPE_GEOMETRY",
                column_type::MYSQL_TYPE_GEOMETRY,
                MySqlType::Geometry,
            ),
        ];
        let mismatches: Vec<String> = table
            .iter()
            .filter(|entry| entry.1 != entry.2 as u8)
            .map(|entry| {
                format!(
                    "{} is {:#04x}, the spec value is {:#04x}",
                    entry.0, entry.1, entry.2 as u8
                )
            })
            .collect();
        if mismatches.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "asupersync::database::mysql::column_type disagrees with the field-type table: {}",
                mismatches.join("; ")
            ))
        }
    }

    // ---- MYSQL-STMT-007 ---------------------------------------------------

    fn check_unsigned_flag() -> Result<(), String> {
        // Execute: an unsigned integer carries 0x80 in the high byte of its
        // type field; a signed one must not, or -1 would arrive as 2^n - 1.
        let u8_value: u8 = 200;
        let u16_value: u16 = 65_000;
        let u32_value: u32 = u32::MAX;
        let u64_value: u64 = u64::MAX;
        let i8_value: i8 = -1;
        let i16_value: i16 = -1;
        let i32_value: i32 = -1;
        let i64_value: i64 = -1;
        let cases: [(&str, &dyn ToSql, MySqlType, bool, Vec<u8>); 8] = [
            ("u8 200", &u8_value, MySqlType::Tiny, true, vec![200]),
            (
                "u16 65000",
                &u16_value,
                MySqlType::Short,
                true,
                65_000u16.to_le_bytes().to_vec(),
            ),
            ("u32::MAX", &u32_value, MySqlType::Long, true, vec![0xFF; 4]),
            (
                "u64::MAX",
                &u64_value,
                MySqlType::LongLong,
                true,
                vec![0xFF; 8],
            ),
            ("i8 -1", &i8_value, MySqlType::Tiny, false, vec![0xFF]),
            ("i16 -1", &i16_value, MySqlType::Short, false, vec![0xFF; 2]),
            ("i32 -1", &i32_value, MySqlType::Long, false, vec![0xFF; 4]),
            (
                "i64 -1",
                &i64_value,
                MySqlType::LongLong,
                false,
                vec![0xFF; 8],
            ),
        ];
        for (label, param, code, unsigned, value) in cases {
            let what = format!("COM_STMT_EXECUTE with one {label} parameter");
            let spec = stmt_execute_packet(11, &[SpecParam::bound(code, unsigned, value)]);
            expect_execute(&what, 11, &[param], &spec)?;
        }

        // Result rows: a column with UNSIGNED_FLAG holds the unsigned value of
        // its bytes, in both protocols.
        let columns = decode_columns(
            "UNSIGNED and signed integer columns",
            &[
                column_spec(
                    "tiny_u",
                    MySqlType::Tiny,
                    CHARSET_BINARY,
                    3,
                    UNSIGNED_FLAG,
                    0,
                ),
                column_spec(
                    "short_u",
                    MySqlType::Short,
                    CHARSET_BINARY,
                    5,
                    UNSIGNED_FLAG,
                    0,
                ),
                column_spec(
                    "long_u",
                    MySqlType::Long,
                    CHARSET_BINARY,
                    10,
                    UNSIGNED_FLAG,
                    0,
                ),
                column_spec(
                    "longlong_u_max",
                    MySqlType::LongLong,
                    CHARSET_BINARY,
                    20,
                    UNSIGNED_FLAG,
                    0,
                ),
                column_spec(
                    "longlong_u_small",
                    MySqlType::LongLong,
                    CHARSET_BINARY,
                    20,
                    UNSIGNED_FLAG,
                    0,
                ),
                column_spec("tiny_signed", MySqlType::Tiny, CHARSET_BINARY, 4, 0, 0),
            ],
        )?;
        let binary = binary_row_bytes(&[
            Some(vec![0xFF]),
            Some(vec![0xFF; 2]),
            Some(vec![0xFF; 4]),
            Some(vec![0xFF; 8]),
            Some(5u64.to_le_bytes().to_vec()),
            Some(vec![0xFF]),
        ]);
        let text = text_row_bytes(&[
            Some(&b"255"[..]),
            Some(&b"65535"[..]),
            Some(&b"4294967295"[..]),
            Some(&b"18446744073709551615"[..]),
            Some(&b"5"[..]),
            Some(&b"-1"[..]),
        ]);
        let want = [
            "255",
            "65535",
            "4294967295",
            "18446744073709551615",
            "5",
            "-1",
        ];
        let decoded = [
            (
                "binary",
                binary.clone(),
                fuzz_parse_binary_row(&binary, &columns),
            ),
            ("text", text.clone(), fuzz_parse_text_row(&text, &columns)),
        ];
        for (protocol, row, result) in decoded {
            let values = result.map_err(|err| {
                format!(
                    "{protocol} row {row:02x?} of integer values: production rejected it: {err:?}"
                )
            })?;
            let got: Vec<Option<String>> = values.iter().map(integer_text).collect();
            let expected: Vec<Option<String>> =
                want.iter().map(|value| Some(value.to_string())).collect();
            if got != expected {
                return Err(format!(
                    "{protocol} row {row:02x?}: the columns hold {want:?}, production decoded {values:?}"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-008 ---------------------------------------------------

    fn check_parameter_length_encoding() -> Result<(), String> {
        // Encoded by hand from the length-encoded integer table.
        let cases: [(usize, &[u8]); 9] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (250, &[0xFA]),
            (251, &[0xFC, 0xFB, 0x00]),
            (252, &[0xFC, 0xFC, 0x00]),
            (65_535, &[0xFC, 0xFF, 0xFF]),
            (65_536, &[0xFD, 0x00, 0x00, 0x01]),
            (70_000, &[0xFD, 0x70, 0x11, 0x01]),
            // 0xFE + int<8> needs a 2^24-byte value, which also makes the
            // packet longer than one packet can carry.
            (
                16_777_216,
                &[0xFE, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            ),
        ];
        for (len, prefix) in cases {
            let value = vec![b'x'; len];
            let param: &[u8] = &value;
            let what = format!("COM_STMT_EXECUTE with a {len}-byte value");
            let produced = build(&what, 9, &[&param])?;
            // The value starts at payload offset 14, inside the first packet.
            let at = 4 + 14;
            match produced.get(at..at + prefix.len()) {
                Some(got) if got == prefix => {}
                got => {
                    return Err(format!(
                        "{what}: production's length prefix is {got:02x?}, the length-encoded integer for {len} is {prefix:02x?}"
                    ));
                }
            }
            let spec = stmt_execute_packet(
                9,
                &[SpecParam::bound(
                    MySqlType::Blob,
                    false,
                    encode_length_encoded_string(&value),
                )],
            );
            expect_bytes(&what, &produced, &spec)?;
        }
        Ok(())
    }

    // ---- MYSQL-STMT-009..012 ----------------------------------------------

    /// Production's packet for INT parameters, NULL where `nulls` says so,
    /// compared whole with the spec encoding.
    fn null_pattern_packet(what: &str, nulls: &[bool]) -> Result<Vec<u8>, String> {
        let values: Vec<Option<i32>> = nulls
            .iter()
            .enumerate()
            .map(|(index, null)| {
                if *null {
                    None
                } else {
                    Some(index as i32 * 3 + 1)
                }
            })
            .collect();
        let params: Vec<&dyn ToSql> = values.iter().map(|value| value as &dyn ToSql).collect();
        let spec_params: Vec<SpecParam> = values
            .iter()
            .map(|value| match value {
                Some(number) => {
                    SpecParam::bound(MySqlType::Long, false, number.to_le_bytes().to_vec())
                }
                None => SpecParam::null(MySqlType::Long, false),
            })
            .collect();
        expect_execute(what, 77, &params, &stmt_execute_packet(77, &spec_params))
    }

    fn check_bitmap(what: &str, frame: &[u8], expected: &[u8]) -> Result<(), String> {
        let payload = single_packet_payload(what, frame)?;
        match payload.get(10..10 + expected.len()) {
            Some(got) if got == expected => Ok(()),
            got => Err(format!(
                "{what}: production's NULL bitmap is {got:02x?}, the spec bitmap is {expected:02x?}"
            )),
        }
    }

    fn check_null_bitmap_encoding() -> Result<(), String> {
        let alternating: Vec<bool> = (0..16)
            .map(|index| matches!(index, 1 | 3 | 5 | 7 | 8 | 10 | 12 | 14))
            .collect();
        let cases: [(&str, Vec<bool>, &[u8]); 5] = [
            ("1 parameter, NULL", vec![true], &[0b0000_0001]),
            ("1 parameter, not NULL", vec![false], &[0b0000_0000]),
            ("8 parameters, all NULL", vec![true; 8], &[0b1111_1111]),
            (
                "9 parameters, all NULL",
                vec![true; 9],
                &[0b1111_1111, 0b0000_0001],
            ),
            (
                "16 parameters, 1 3 5 7 8 10 12 14 NULL",
                alternating,
                &[0b1010_1010, 0b0101_0101],
            ),
        ];
        for (label, nulls, bitmap) in cases {
            let what = format!("COM_STMT_EXECUTE with {label}");
            let produced = null_pattern_packet(&what, &nulls)?;
            check_bitmap(&what, &produced, bitmap)?;
        }
        Ok(())
    }

    fn check_null_bitmap_length() -> Result<(), String> {
        let cases: [(usize, usize); 8] = [
            (0, 0),
            (1, 1),
            (7, 1),
            (8, 1),
            (9, 2),
            (15, 2),
            (16, 2),
            (17, 3),
        ];
        for (count, bitmap_len) in cases {
            let what = format!("COM_STMT_EXECUTE with {count} non-NULL INT parameters");
            let produced = null_pattern_packet(&what, &vec![false; count])?;
            let payload = single_packet_payload(&what, &produced)?;
            // 10-byte prefix; then the bitmap, new_params_bound_flag and, per
            // INT parameter, 2 type bytes and 4 value bytes.
            let spec_len = if count == 0 {
                10
            } else {
                10 + bitmap_len + 1 + 6 * count
            };
            if payload.len() != spec_len {
                return Err(format!(
                    "{what}: payload is {} bytes, the spec layout with a {bitmap_len}-byte bitmap is {spec_len}",
                    payload.len()
                ));
            }
            if count > 0 {
                check_bitmap(&what, &produced, &vec![0u8; bitmap_len])?;
                if payload[10 + bitmap_len] != NEW_PARAMS_BOUND {
                    return Err(format!(
                        "{what}: the byte after a {bitmap_len}-byte bitmap is {:#04x}, not new_params_bound_flag 0x01",
                        payload[10 + bitmap_len]
                    ));
                }
            }
        }
        Ok(())
    }

    fn check_null_bitmap_bit_order() -> Result<(), String> {
        // Parameter i is bit i % 8, least significant first, of byte i / 8.
        let nulls: Vec<bool> = (0..16)
            .map(|index| matches!(index, 0 | 3 | 8 | 15))
            .collect();
        let what = "COM_STMT_EXECUTE with parameters 0, 3, 8 and 15 of 16 NULL";
        let produced = null_pattern_packet(what, &nulls)?;
        check_bitmap(what, &produced, &[0x09, 0x81])
    }

    fn check_mixed_null_parameters() -> Result<(), String> {
        let p0: Option<i32> = None;
        let p1: i64 = 7;
        let p2: Option<&str> = None;
        let p3: &str = "x";
        let p4: f64 = 1.0;
        let params: [&dyn ToSql; 5] = [&p0, &p1, &p2, &p3, &p4];
        // Encoded by hand: every parameter has a type, only 1, 3 and 4 a value.
        let mut payload = vec![
            0x17, 0x05, 0x00, 0x00, 0x00, // COM_STMT_EXECUTE, statement_id 5
            0x00, 0x01, 0x00, 0x00, 0x00, // no cursor, iteration_count 1
            0x05, // NULL bitmap: parameters 0 and 2
            0x01, // new_params_bound_flag
            0x03, 0x00, // MYSQL_TYPE_LONG
            0x08, 0x00, // MYSQL_TYPE_LONGLONG
            0xFD, 0x00, // MYSQL_TYPE_VAR_STRING
            0xFD, 0x00, // MYSQL_TYPE_VAR_STRING
            0x05, 0x00, // MYSQL_TYPE_DOUBLE
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // parameter 1
            0x01, b'x', // parameter 3
        ];
        payload.extend_from_slice(&1.0f64.to_le_bytes()); // parameter 4
        expect_execute(
            "COM_STMT_EXECUTE(5, [NULL INT, 7i64, NULL VARCHAR, \"x\", 1.0f64])",
            5,
            &params,
            &frame_packets(0, &payload),
        )?;
        Ok(())
    }

    // ---- MYSQL-STMT-016 ---------------------------------------------------

    fn check_cursor_flags_byte() -> Result<(), String> {
        let one: i32 = 1;
        let null: Option<i64> = None;
        let none: [&dyn ToSql; 0] = [];
        let single: [&dyn ToSql; 1] = [&one];
        let pair: [&dyn ToSql; 2] = [&null, &one];
        let cases: [(&str, &[&dyn ToSql]); 3] = [
            ("no parameters", &none),
            ("one parameter", &single),
            ("a NULL and an INT parameter", &pair),
        ];
        for (label, params) in cases {
            let what = format!("COM_STMT_EXECUTE with {label}");
            let produced = build(&what, 3, params)?;
            let payload = single_packet_payload(&what, &produced)?;
            if payload.get(5) != Some(&(CursorType::NoCursor as u8)) {
                return Err(format!(
                    "{what}: flags byte {:02x?}; production opens no cursor and sends no COM_STMT_FETCH, so it must send CURSOR_TYPE_NO_CURSOR (0x00)",
                    payload.get(5)
                ));
            }
            if payload.get(6..10) != Some(&[0x01, 0x00, 0x00, 0x00][..]) {
                return Err(format!(
                    "{what}: iteration_count bytes {:02x?}, the spec requires int<4> 1",
                    payload.get(6..10)
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-019 ---------------------------------------------------

    fn result_columns() -> [ColumnSpec; 3] {
        [
            column_spec(
                "id",
                MySqlType::Long,
                CHARSET_BINARY,
                11,
                NOT_NULL_FLAG | PRI_KEY_FLAG | AUTO_INCREMENT_FLAG,
                0,
            ),
            column_spec("nickname", MySqlType::VarString, CHARSET_UTF8MB4, 256, 0, 0),
            column_spec(
                "name",
                MySqlType::VarString,
                CHARSET_UTF8MB4,
                400,
                NOT_NULL_FLAG,
                0,
            ),
        ]
    }

    fn check_binary_result_row() -> Result<(), String> {
        let columns = decode_columns("binary result set", &result_columns())?;
        // Encoded by hand: header 0x00, NULL bitmap 0b0000_1000 (column 1 is
        // bit 1 + 2), INT 12345, then "test_string" with length 11.
        let mut row = vec![0x00, 0b0000_1000, 0x39, 0x30, 0x00, 0x00, 0x0B];
        row.extend_from_slice(b"test_string");
        expect_binary_row(
            "binary row [12345, NULL, \"test_string\"]",
            &row,
            &columns,
            &[
                MySqlValue::Long(12345),
                MySqlValue::Null,
                MySqlValue::Text("test_string".to_string()),
            ],
        )?;

        let mut wrong_header = row.clone();
        wrong_header[0] = 0x01;
        let mut overlong = vec![0x00, 0b0000_1000, 0x39, 0x30, 0x00, 0x00, 0x20];
        overlong.extend_from_slice(b"test_string");
        let mut trailing = row.clone();
        trailing.push(0x00);
        let malformed: [(&str, Vec<u8>); 7] = [
            ("a header byte other than 0x00", wrong_header),
            (
                "an EOF packet in place of a row",
                eof_packet_bytes(0, SERVER_STATUS_AUTOCOMMIT),
            ),
            ("no NULL bitmap", vec![0x00]),
            (
                "an INT value cut to 2 of its 4 bytes",
                vec![0x00, 0b0000_1000, 0x39, 0x30],
            ),
            (
                "fewer values than columns",
                vec![0x00, 0b0000_1000, 0x39, 0x30, 0x00, 0x00],
            ),
            ("a string longer than the bytes left", overlong),
            ("bytes after the last value", trailing),
        ];
        for (label, bad) in malformed {
            if let Ok(values) = fuzz_parse_binary_row(&bad, &columns) {
                return Err(format!(
                    "binary row with {label}: production accepted {bad:02x?} as {values:?}"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-020 ---------------------------------------------------

    fn check_binary_row_null_bitmap_offset() -> Result<(), String> {
        // 10 columns: (10 + 7 + 2) / 8 = 2 bytes, columns at bits 2..=11.
        let ten = decode_columns("ten INT columns", &int_columns(10))?;
        expect_binary_row(
            "10 INT columns, all NULL",
            &[0x00, 0xFC, 0x0F],
            &ten,
            &vec![MySqlValue::Null; 10],
        )?;
        let mut none_null = vec![0x00, 0x00, 0x00];
        for index in 0..10i32 {
            none_null.extend_from_slice(&(index * 100).to_le_bytes());
        }
        let values: Vec<MySqlValue> = (0..10).map(|index| MySqlValue::Long(index * 100)).collect();
        expect_binary_row("10 INT columns, none NULL", &none_null, &ten, &values)?;

        // Six columns fit bits 2..=7 of one byte; a seventh needs a second byte.
        let six = decode_columns("six INT columns", &int_columns(6))?;
        let mut last_of_six = vec![0x00, 0b1000_0000];
        for index in 0..5i32 {
            last_of_six.extend_from_slice(&index.to_le_bytes());
        }
        let mut want: Vec<MySqlValue> = (0..5).map(MySqlValue::Long).collect();
        want.push(MySqlValue::Null);
        expect_binary_row("6 INT columns, column 5 NULL", &last_of_six, &six, &want)?;

        let seven = decode_columns("seven INT columns", &int_columns(7))?;
        let mut last_of_seven = vec![0x00, 0x00, 0b0000_0001];
        for index in 0..6i32 {
            last_of_seven.extend_from_slice(&index.to_le_bytes());
        }
        let mut want: Vec<MySqlValue> = (0..6).map(MySqlValue::Long).collect();
        want.push(MySqlValue::Null);
        expect_binary_row(
            "7 INT columns, column 6 NULL",
            &last_of_seven,
            &seven,
            &want,
        )?;

        // Column 0 is bit 2, not bit 0.
        let two = decode_columns("two INT columns", &int_columns(2))?;
        let mut first_null = vec![0x00, 0b0000_0100];
        first_null.extend_from_slice(&5i32.to_le_bytes());
        expect_binary_row(
            "2 INT columns, column 0 NULL",
            &first_null,
            &two,
            &[MySqlValue::Null, MySqlValue::Long(5)],
        )?;

        // Bits 0 and 1 belong to no column. Rejecting a row that sets one is
        // fine; reading it as column 0 being NULL is not.
        let mut reserved = vec![0x00, 0b0000_0001];
        reserved.extend_from_slice(&5i32.to_le_bytes());
        reserved.extend_from_slice(&6i32.to_le_bytes());
        match fuzz_parse_binary_row(&reserved, &two) {
            Err(_) => {}
            Ok(values) if values == [MySqlValue::Long(5), MySqlValue::Long(6)] => {}
            Ok(values) => {
                return Err(format!(
                    "binary row {reserved:02x?} sets reserved bit 0, which is not a column; production decoded {values:?}"
                ));
            }
        }

        // Seven all-NULL columns need two bitmap bytes; one is a cut-off row.
        let truncated: [u8; 2] = [0x00, 0xFC];
        if let Ok(values) = fuzz_parse_binary_row(&truncated, &seven) {
            return Err(format!(
                "binary row {truncated:02x?} has a 1-byte NULL bitmap for 7 columns, which need 2; production accepted it as {values:?}"
            ));
        }
        Ok(())
    }

    // ---- MYSQL-STMT-021 ---------------------------------------------------

    fn check_binary_value_encoding() -> Result<(), String> {
        // Decode: each value alone in a one-column binary row. Temporal values
        // are rendered as text by production.
        let micros = 123_456u32.to_le_bytes();
        let mut datetime_micros = vec![11, 0xE8, 0x07, 1, 15, 10, 30, 45];
        datetime_micros.extend_from_slice(&micros);
        let column = |name: &str, kind: MySqlType| column_spec(name, kind, CHARSET_BINARY, 0, 0, 0);
        let cases: Vec<(&str, ColumnSpec, Vec<u8>, MySqlValue)> = vec![
            (
                "TINY 127",
                column("v", MySqlType::Tiny),
                vec![0x7F],
                MySqlValue::Tiny(127),
            ),
            (
                "TINY -128",
                column("v", MySqlType::Tiny),
                vec![0x80],
                MySqlValue::Tiny(-128),
            ),
            (
                "SHORT 32767",
                column("v", MySqlType::Short),
                i16::MAX.to_le_bytes().to_vec(),
                MySqlValue::Short(i16::MAX),
            ),
            (
                "YEAR 2024 (int<2>)",
                column_spec(
                    "v",
                    MySqlType::Year,
                    CHARSET_BINARY,
                    4,
                    UNSIGNED_FLAG | ZEROFILL_FLAG,
                    0,
                ),
                2024u16.to_le_bytes().to_vec(),
                MySqlValue::Short(2024),
            ),
            (
                "LONG 2147483647",
                column("v", MySqlType::Long),
                i32::MAX.to_le_bytes().to_vec(),
                MySqlValue::Long(i32::MAX),
            ),
            (
                "INT24 -8388608 (int<4>)",
                column("v", MySqlType::Int24),
                (-8_388_608i32).to_le_bytes().to_vec(),
                MySqlValue::Long(-8_388_608),
            ),
            (
                "LONGLONG i64::MIN",
                column("v", MySqlType::LongLong),
                i64::MIN.to_le_bytes().to_vec(),
                MySqlValue::LongLong(i64::MIN),
            ),
            (
                "FLOAT 3.14",
                column("v", MySqlType::Float),
                3.14f32.to_le_bytes().to_vec(),
                MySqlValue::Float(3.14),
            ),
            (
                "DOUBLE pi",
                column("v", MySqlType::Double),
                std::f64::consts::PI.to_le_bytes().to_vec(),
                MySqlValue::Double(std::f64::consts::PI),
            ),
            (
                "NEWDECIMAL -123.45 (a length-encoded string)",
                column("v", MySqlType::NewDecimal),
                encode_length_encoded_string(b"-123.45"),
                MySqlValue::Text("-123.45".to_string()),
            ),
            (
                "VAR_STRING in utf8mb4",
                column_spec("v", MySqlType::VarString, CHARSET_UTF8MB4, 80, 0, 0),
                encode_length_encoded_string("h\u{e9}llo".as_bytes()),
                MySqlValue::Text("h\u{e9}llo".to_string()),
            ),
            (
                "STRING in utf8mb4",
                column_spec("v", MySqlType::String, CHARSET_UTF8MB4, 8, 0, 0),
                encode_length_encoded_string(b"ab"),
                MySqlValue::Text("ab".to_string()),
            ),
            (
                "BLOB",
                column_spec(
                    "v",
                    MySqlType::Blob,
                    CHARSET_BINARY,
                    65_535,
                    BLOB_FLAG | BINARY_FLAG,
                    0,
                ),
                encode_length_encoded_string(&[0x00, 0xFF, 0x10]),
                MySqlValue::Bytes(vec![0x00, 0xFF, 0x10]),
            ),
            (
                "VARBINARY (VAR_STRING, binary charset)",
                column_spec(
                    "v",
                    MySqlType::VarString,
                    CHARSET_BINARY,
                    16,
                    BINARY_FLAG,
                    0,
                ),
                encode_length_encoded_string(&[0xC3, 0x28]),
                MySqlValue::Bytes(vec![0xC3, 0x28]),
            ),
            (
                "DATE 2024-01-15",
                column("v", MySqlType::Date),
                vec![4, 0xE8, 0x07, 1, 15],
                MySqlValue::Text("2024-01-15".to_string()),
            ),
            (
                "DATETIME 2024-01-15 10:30:45",
                column("v", MySqlType::DateTime),
                vec![7, 0xE8, 0x07, 1, 15, 10, 30, 45],
                MySqlValue::Text("2024-01-15 10:30:45".to_string()),
            ),
            (
                "DATETIME with microseconds",
                column("v", MySqlType::DateTime),
                datetime_micros,
                MySqlValue::Text("2024-01-15 10:30:45.123456".to_string()),
            ),
            (
                "TIMESTAMP of length 0 (all fields zero)",
                column("v", MySqlType::Timestamp),
                vec![0],
                MySqlValue::Text("0000-00-00 00:00:00".to_string()),
            ),
            (
                "TIME -1 day 02:03:04",
                column("v", MySqlType::Time),
                vec![8, 1, 1, 0, 0, 0, 2, 3, 4],
                MySqlValue::Text("-1 02:03:04".to_string()),
            ),
            (
                "TIME with microseconds",
                column("v", MySqlType::Time),
                vec![12, 0, 0, 0, 0, 0, 10, 20, 30, 5, 0, 0, 0],
                MySqlValue::Text("0 10:20:30.000005".to_string()),
            ),
            (
                "TIME of length 0 (all fields zero)",
                column("v", MySqlType::Time),
                vec![0],
                MySqlValue::Text("00:00:00".to_string()),
            ),
        ];
        for (label, spec, value, want) in cases {
            let columns = decode_columns(label, std::slice::from_ref(&spec))?;
            let row = binary_row_bytes(&[Some(value)]);
            expect_binary_row(
                &format!("binary {label}"),
                &row,
                &columns,
                std::slice::from_ref(&want),
            )?;
        }

        let malformed: Vec<(&str, ColumnSpec, Vec<u8>)> = vec![
            (
                "DATETIME with length 5 (only 0, 4, 7 and 11 exist)",
                column("v", MySqlType::DateTime),
                vec![5, 0xE8, 0x07, 1, 15, 10],
            ),
            (
                "TIME with length 9 (only 0, 8 and 12 exist)",
                column("v", MySqlType::Time),
                vec![9, 0, 0, 0, 0, 0, 1, 2, 3, 0],
            ),
            (
                "DATE whose length byte runs past the row",
                column("v", MySqlType::Date),
                vec![4, 0xE8, 0x07],
            ),
            (
                "FLOAT cut to 3 bytes",
                column("v", MySqlType::Float),
                vec![0, 0, 0],
            ),
            (
                "LONGLONG cut to 7 bytes",
                column("v", MySqlType::LongLong),
                vec![0; 7],
            ),
        ];
        for (label, spec, value) in malformed {
            let columns = decode_columns(label, std::slice::from_ref(&spec))?;
            let row = binary_row_bytes(&[Some(value)]);
            if let Ok(values) = fuzz_parse_binary_row(&row, &columns) {
                return Err(format!(
                    "binary row with {label}: production accepted {row:02x?} as {values:?}"
                ));
            }
        }

        // Encode: the same formats in a COM_STMT_EXECUTE.
        let tiny = i8::MAX;
        let short = i16::MAX;
        let long = i32::MAX;
        let longlong = i64::MAX;
        let float = 3.14f32;
        let double = std::f64::consts::PI;
        let text: &str = "hello world";
        let params: [&dyn ToSql; 7] = [&tiny, &short, &long, &longlong, &float, &double, &text];
        let spec = stmt_execute_packet(
            21,
            &[
                SpecParam::bound(MySqlType::Tiny, false, vec![0x7F]),
                SpecParam::bound(MySqlType::Short, false, vec![0xFF, 0x7F]),
                SpecParam::bound(MySqlType::Long, false, vec![0xFF, 0xFF, 0xFF, 0x7F]),
                SpecParam::bound(
                    MySqlType::LongLong,
                    false,
                    vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F],
                ),
                SpecParam::bound(MySqlType::Float, false, 3.14f32.to_le_bytes().to_vec()),
                SpecParam::bound(
                    MySqlType::Double,
                    false,
                    std::f64::consts::PI.to_le_bytes().to_vec(),
                ),
                SpecParam::bound(
                    MySqlType::VarString,
                    false,
                    encode_length_encoded_string(b"hello world"),
                ),
            ],
        );
        expect_execute(
            "COM_STMT_EXECUTE with the i8/i16/i32/i64 maxima, 3.14f32, pi and \"hello world\"",
            21,
            &params,
            &spec,
        )?;
        Ok(())
    }

    // ---- MYSQL-STMT-022 ---------------------------------------------------

    fn check_length_encoded_values() -> Result<(), String> {
        let columns = decode_columns(
            "one VARCHAR column",
            &[column_spec(
                "s",
                MySqlType::VarString,
                CHARSET_UTF8MB4,
                262_140,
                0,
                0,
            )],
        )?;
        // Encoded by hand: the length prefix for each value length.
        let cases: [(usize, &[u8]); 8] = [
            (0, &[0x00]),
            (1, &[0x01]),
            (250, &[0xFA]),
            (251, &[0xFC, 0xFB, 0x00]),
            (252, &[0xFC, 0xFC, 0x00]),
            (300, &[0xFC, 0x2C, 0x01]),
            (65_535, &[0xFC, 0xFF, 0xFF]),
            (65_536, &[0xFD, 0x00, 0x00, 0x01]),
        ];
        for (len, prefix) in cases {
            let text = "x".repeat(len);
            let mut row = prefix.to_vec();
            row.extend_from_slice(text.as_bytes());
            match fuzz_parse_text_row(&row, &columns) {
                Ok(values) if values == [MySqlValue::Text(text.clone())] => {}
                other => {
                    return Err(format!(
                        "text row with a {len}-byte value behind the prefix {prefix:02x?}: production returned {}",
                        short_debug(&other)
                    ));
                }
            }
        }

        // In a text row 0xFB is NULL.
        match fuzz_parse_text_row(&[TEXT_NULL], &columns) {
            Ok(values) if values == [MySqlValue::Null] => {}
            other => {
                return Err(format!(
                    "text row [0xfb]: 0xFB is a NULL value, production returned {other:?}"
                ));
            }
        }

        // 0xFE + int<8>, here in an OK packet's affected_rows.
        let big = 1u64 << 40;
        let ok = ok_packet_bytes(OK_HEADER, big, 0, SERVER_STATUS_AUTOCOMMIT, 0, b"");
        match fuzz_parse_ok_packet_fields(&ok) {
            Ok((rows, status)) if rows == big && status == SERVER_STATUS_AUTOCOMMIT => {}
            other => {
                return Err(format!(
                    "OK packet {ok:02x?} with affected_rows 2^40 (0xFE + int<8>): production returned {other:?}"
                ));
            }
        }

        let malformed_rows: [(&str, &[u8]); 4] = [
            ("the undefined prefix 0xFF", &[0xFF]),
            (
                "a 0xFC prefix with one of its two length bytes",
                &[0xFC, 0x05],
            ),
            (
                "a 0xFD prefix with two of its three length bytes",
                &[0xFD, 0x01, 0x00],
            ),
            ("a length of 5 with 2 bytes left", &[0x05, b'a', b'b']),
        ];
        for (label, bad) in malformed_rows {
            if let Ok(values) = fuzz_parse_text_row(bad, &columns) {
                return Err(format!(
                    "text row with {label}: production accepted {bad:02x?} as {values:?}"
                ));
            }
        }

        // NULL lives in a binary row's bitmap, so 0xFB cannot start a value there.
        let binary = [0x00, 0x00, TEXT_NULL];
        if let Ok(values) = fuzz_parse_binary_row(&binary, &columns) {
            return Err(format!(
                "binary row {binary:02x?}: 0xFB is not a length, production accepted it as {values:?}"
            ));
        }
        // In an integer field neither 0xFB nor 0xFF is a length-encoded integer.
        for prefix in [0xFBu8, 0xFF] {
            let bad = [OK_HEADER, prefix, 0x00, 0x02, 0x00, 0x00, 0x00];
            if let Ok(fields) = fuzz_parse_ok_packet_fields(&bad) {
                return Err(format!(
                    "OK packet {bad:02x?}: affected_rows starts with {prefix:#04x}, which is no length-encoded integer, yet production decoded {fields:?}"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-023 ---------------------------------------------------

    fn check_invalid_statement_id() -> Result<(), String> {
        // The client sends whatever id it holds; the server judges it.
        let none: [&dyn ToSql; 0] = [];
        expect_execute(
            "COM_STMT_EXECUTE(u32::MAX, [])",
            u32::MAX,
            &none,
            &[
                10, 0, 0, 0, 0x17, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00,
            ],
        )?;
        let one: i32 = 1;
        expect_execute(
            "COM_STMT_EXECUTE(u32::MAX, [1i32])",
            u32::MAX,
            &[&one],
            &stmt_execute_packet(
                u32::MAX,
                &[SpecParam::bound(
                    MySqlType::Long,
                    false,
                    1i32.to_le_bytes().to_vec(),
                )],
            ),
        )?;

        // An unknown id draws ER_UNKNOWN_STMT_HANDLER (1243, SQLSTATE HY000).
        let message =
            "Unknown prepared statement handler (4294967295) given to mysqld_stmt_execute";
        let err = err_packet_bytes(1243, Some("HY000"), message);
        match fuzz_parse_error_packet(&err) {
            MySqlError::Server {
                code,
                sql_state,
                message: decoded,
            } if code == 1243 && sql_state == "HY000" && decoded == message => Ok(()),
            other => Err(format!(
                "ERR packet {err:02x?}: the spec fields are code 1243, SQLSTATE HY000, message {message:?}; production decoded {other:?}"
            )),
        }
    }

    // ---- MYSQL-STMT-026 ---------------------------------------------------

    fn check_column_definition() -> Result<(), String> {
        let specs = vec![
            ColumnSpec {
                schema: "test",
                table: "u",
                org_table: "users",
                name: "id".to_string(),
                org_name: "id".to_string(),
                charset: CHARSET_BINARY,
                length: 11,
                column_type: MySqlType::Long as u8,
                flags: NOT_NULL_FLAG | PRI_KEY_FLAG | AUTO_INCREMENT_FLAG,
                decimals: 0,
            },
            // An alias differs from the original name.
            ColumnSpec {
                schema: "test",
                table: "u",
                org_table: "users",
                name: "full_name".to_string(),
                org_name: "name".to_string(),
                charset: CHARSET_UTF8MB4,
                length: 1020,
                column_type: MySqlType::VarString as u8,
                flags: 0,
                decimals: 0,
            },
            // A computed column has no schema, table or original name.
            ColumnSpec {
                schema: "",
                table: "",
                org_table: "",
                name: "price*2".to_string(),
                org_name: String::new(),
                charset: CHARSET_BINARY,
                length: 23,
                column_type: MySqlType::NewDecimal as u8,
                flags: BINARY_FLAG,
                decimals: 2,
            },
            // A 251-byte alias needs the 0xFC length prefix.
            ColumnSpec {
                schema: "test",
                table: "u",
                org_table: "users",
                name: "a".repeat(251),
                org_name: "id".to_string(),
                charset: CHARSET_BINARY,
                length: 20,
                column_type: MySqlType::LongLong as u8,
                flags: UNSIGNED_FLAG,
                decimals: 0,
            },
        ];
        decode_columns("Column Definition 41", &specs)?;

        // Offsets in the first definition: "def" (4 bytes), "test" (5), "u"
        // (2), "users" (6), "id" (3) and "id" (3), then 0x0C at byte 23.
        let valid = column_definition_bytes(&specs[0]);
        let strings_len = 23;
        let name_at = 4 + 5 + 2 + 6;
        let mut null_name = valid.clone();
        null_name[name_at] = 0xFB;
        let mut bad_prefix = valid.clone();
        bad_prefix[0] = 0xFF;
        let malformed: [(&str, Vec<u8>); 6] = [
            ("an empty packet", Vec::new()),
            (
                "a catalog cut off inside its string",
                vec![0x03, b'd', b'e'],
            ),
            (
                "the six strings and no fixed-length fields",
                valid[..strings_len].to_vec(),
            ),
            (
                "fixed-length fields cut before decimals",
                valid[..strings_len + 10].to_vec(),
            ),
            (
                "a name length of 0xFB, which no length-encoded string has",
                null_name,
            ),
            ("the undefined length prefix 0xFF", bad_prefix),
        ];
        for (label, bad) in malformed {
            if let Ok(column) = fuzz_parse_column_definition(&bad) {
                return Err(format!(
                    "column definition with {label}: production accepted {bad:02x?} as {column:?}"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-027 ---------------------------------------------------

    fn text_columns() -> [ColumnSpec; 5] {
        [
            column_spec("id", MySqlType::Long, CHARSET_BINARY, 11, NOT_NULL_FLAG, 0),
            column_spec("name", MySqlType::VarString, CHARSET_UTF8MB4, 400, 0, 0),
            column_spec("score", MySqlType::Double, CHARSET_BINARY, 22, 0, 31),
            column_spec("born", MySqlType::Date, CHARSET_BINARY, 10, BINARY_FLAG, 0),
            column_spec("note", MySqlType::VarString, CHARSET_UTF8MB4, 1020, 0, 0),
        ]
    }

    fn check_text_result_row() -> Result<(), String> {
        let columns = decode_columns("text result set", &text_columns())?;
        // Encoded by hand: "42", "alice", "3.5", "2024-01-15", then 0xFB (NULL).
        let mut first = vec![0x02, b'4', b'2', 0x05];
        first.extend_from_slice(b"alice");
        first.push(0x03);
        first.extend_from_slice(b"3.5");
        first.push(0x0A);
        first.extend_from_slice(b"2024-01-15");
        first.push(0xFB);
        let second = text_row_bytes(&[
            Some(&b"-7"[..]),
            Some(&b""[..]),
            Some(&b"0.25"[..]),
            Some(&b"0000-00-00"[..]),
            Some(&b""[..]),
        ]);
        let rows: [(&str, Vec<u8>, Vec<MySqlValue>); 2] = [
            (
                "values and a NULL",
                first,
                vec![
                    MySqlValue::Long(42),
                    MySqlValue::Text("alice".to_string()),
                    MySqlValue::Double(3.5),
                    MySqlValue::Text("2024-01-15".to_string()),
                    MySqlValue::Null,
                ],
            ),
            (
                "empty strings, which are not NULL",
                second,
                vec![
                    MySqlValue::Long(-7),
                    MySqlValue::Text(String::new()),
                    MySqlValue::Double(0.25),
                    MySqlValue::Text("0000-00-00".to_string()),
                    MySqlValue::Text(String::new()),
                ],
            ),
        ];
        for (label, row, expected) in rows {
            match fuzz_parse_text_row(&row, &columns) {
                Ok(values) if values == expected => {}
                other => {
                    return Err(format!(
                        "text row with {label} {row:02x?}: the spec values are {expected:?}, production returned {other:?}"
                    ));
                }
            }
        }

        let good: [Option<&[u8]>; 5] = [
            Some(&b"1"[..]),
            Some(&b"bob"[..]),
            Some(&b"2.5"[..]),
            Some(&b"2000-02-29"[..]),
            None,
        ];
        let mut extra = text_row_bytes(&good);
        extra.extend_from_slice(&[0x01, b'x']);
        let mut overlong = text_row_bytes(&good[..4]);
        overlong.extend_from_slice(&[0x09, b'a', b'b']);
        let malformed: [(&str, Vec<u8>); 4] = [
            ("fewer values than columns", text_row_bytes(&good[..4])),
            ("a value after the last column", extra),
            ("a value length past the end of the packet", overlong),
            ("the undefined length prefix 0xFF", vec![0xFF, 0x01, b'1']),
        ];
        for (label, bad) in malformed {
            if let Ok(values) = fuzz_parse_text_row(&bad, &columns) {
                return Err(format!(
                    "text row with {label}: production accepted {bad:02x?} as {values:?}"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-028 ---------------------------------------------------

    fn check_text_result_terminators() -> Result<(), String> {
        let columns = decode_columns(
            "terminator fixtures",
            &[
                column_spec("name", MySqlType::VarString, CHARSET_UTF8MB4, 400, 0, 0),
                column_spec("id", MySqlType::Long, CHARSET_BINARY, 11, 0, 0),
            ],
        )?;
        let row = text_row_bytes(&[Some(&b"bob"[..]), Some(&b"1"[..])]);
        let row_values = vec![MySqlValue::Text("bob".to_string()), MySqlValue::Long(1)];
        // A row whose first value is empty starts with 0x00, like an OK packet.
        let empty_first = text_row_bytes(&[Some(&b""[..]), Some(&b"5"[..])]);
        let empty_first_values = vec![MySqlValue::Text(String::new()), MySqlValue::Long(5)];
        let eof = eof_packet_bytes(0, SERVER_STATUS_AUTOCOMMIT);
        // Under CLIENT_DEPRECATE_EOF the set ends with an OK packet whose
        // header is 0xFE, with or without info text.
        let ok_fe = ok_packet_bytes(EOF_HEADER, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0, b"");
        let ok_fe_info = ok_packet_bytes(EOF_HEADER, 0, 0, SERVER_STATUS_AUTOCOMMIT, 0, b"done");
        let cases: [(&str, bool, &[u8], Option<Vec<MySqlValue>>); 7] = [
            ("an EOF packet", false, eof.as_slice(), None),
            (
                "a data row",
                false,
                row.as_slice(),
                Some(row_values.clone()),
            ),
            (
                "a row whose first value is empty",
                false,
                empty_first.as_slice(),
                Some(empty_first_values.clone()),
            ),
            (
                "a 7-byte OK packet with header 0xFE",
                true,
                ok_fe.as_slice(),
                None,
            ),
            (
                "an 11-byte OK packet with header 0xFE and info text",
                true,
                ok_fe_info.as_slice(),
                None,
            ),
            ("a data row", true, row.as_slice(), Some(row_values)),
            (
                "a row whose first value is empty",
                true,
                empty_first.as_slice(),
                Some(empty_first_values),
            ),
        ];
        for (label, deprecate_eof, packet, want) in cases {
            let mode = if deprecate_eof {
                "CLIENT_DEPRECATE_EOF"
            } else {
                "classic EOF"
            };
            match (
                fuzz_parse_data_row_or_terminator(packet, &columns, deprecate_eof),
                &want,
            ) {
                (Ok(None), None) => {}
                (Ok(Some(values)), Some(expected)) if &values == expected => {}
                (other, _) => {
                    let spec = match &want {
                        None => "a result-set terminator".to_string(),
                        Some(values) => format!("the row {values:?}"),
                    };
                    return Err(format!(
                        "{label} ({mode}) {packet:02x?} is {spec}, production returned {other:?}"
                    ));
                }
            }
        }

        // An ERR packet ends the set with an error: it is neither a row nor a
        // successful end.
        let err = err_packet_bytes(1064, Some("42000"), "You have an error in your SQL syntax");
        for deprecate_eof in [false, true] {
            if let Ok(outcome) = fuzz_parse_data_row_or_terminator(&err, &columns, deprecate_eof) {
                return Err(format!(
                    "ERR packet {err:02x?} (deprecate_eof = {deprecate_eof}): production returned Ok({outcome:?})"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-029 ---------------------------------------------------

    fn check_ok_packet() -> Result<(), String> {
        // Encoded by hand: header, affected_rows 3, last_insert_id 0, status
        // SERVER_STATUS_AUTOCOMMIT, no warnings.
        let simple: [u8; 7] = [0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00];
        let detailed = ok_packet_bytes(
            OK_HEADER,
            300,
            70_000,
            SERVER_STATUS_IN_TRANS | SERVER_STATUS_AUTOCOMMIT,
            1,
            b"Rows matched: 300  Changed: 300  Warnings: 1",
        );
        let huge = ok_packet_bytes(
            OK_HEADER,
            16_777_221,
            u64::MAX,
            SERVER_STATUS_AUTOCOMMIT,
            0,
            b"",
        );
        let valid: [(&str, &[u8], (u64, u16)); 3] = [
            (
                "affected_rows 3",
                &simple[..],
                (3, SERVER_STATUS_AUTOCOMMIT),
            ),
            (
                "affected_rows 300 (0xFC), last_insert_id 70000 (0xFD) and info text",
                detailed.as_slice(),
                (300, SERVER_STATUS_IN_TRANS | SERVER_STATUS_AUTOCOMMIT),
            ),
            (
                "affected_rows 16777221 and last_insert_id u64::MAX (0xFE)",
                huge.as_slice(),
                (16_777_221, SERVER_STATUS_AUTOCOMMIT),
            ),
        ];
        for (label, packet, expected) in valid {
            match fuzz_parse_ok_packet_fields(packet) {
                Ok(fields) if fields == expected => {}
                other => {
                    return Err(format!(
                        "OK packet with {label} {packet:02x?}: the spec (affected_rows, status_flags) is {expected:?}, production returned {other:?}"
                    ));
                }
            }
        }

        let mut bad_header = simple.to_vec();
        bad_header[0] = 0x01;
        let malformed: [(&str, Vec<u8>); 6] = [
            ("an empty packet", Vec::new()),
            ("a header byte of 0x01", bad_header),
            (
                "an ERR packet",
                err_packet_bytes(1146, Some("42S02"), "Table 'test.t' doesn't exist"),
            ),
            ("status flags cut short", simple[..4].to_vec()),
            ("no warning count", simple[..5].to_vec()),
            (
                "affected_rows cut inside its 0xFC length",
                vec![0x00, 0xFC, 0x01],
            ),
        ];
        for (label, bad) in malformed {
            if let Ok(fields) = fuzz_parse_ok_packet_fields(&bad) {
                return Err(format!(
                    "OK packet with {label}: production accepted {bad:02x?} as {fields:?}"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-030 ---------------------------------------------------

    fn check_err_packet() -> Result<(), String> {
        let cases: [(&str, u16, Option<&str>, &str); 4] = [
            (
                "ER_NO_SUCH_TABLE",
                1146,
                Some("42S02"),
                "Table 'test.t' doesn't exist",
            ),
            (
                "ER_PARSE_ERROR",
                1064,
                Some("42000"),
                "You have an error in your SQL syntax",
            ),
            ("an empty message", 1213, Some("40001"), ""),
            ("no SQLSTATE marker", 1040, None, "Too many connections"),
        ];
        for (label, code, sql_state, message) in cases {
            let packet = err_packet_bytes(code, sql_state, message);
            match fuzz_parse_error_packet(&packet) {
                MySqlError::Server {
                    code: got_code,
                    sql_state: got_state,
                    message: got_message,
                } if got_code == code
                    && got_message == message
                    && sql_state.map_or(true, |state| got_state == state) => {}
                other => {
                    return Err(format!(
                        "ERR packet with {label} {packet:02x?}: the spec fields are code {code}, SQLSTATE {sql_state:?}, message {message:?}; production decoded {other:?}"
                    ));
                }
            }
        }

        let malformed: [(&str, Vec<u8>); 4] = [
            ("an empty packet", Vec::new()),
            (
                "an OK packet",
                ok_packet_bytes(OK_HEADER, 1, 0, SERVER_STATUS_AUTOCOMMIT, 0, b""),
            ),
            ("a lone 0xFF header", vec![ERR_HEADER]),
            ("an error code cut to one byte", vec![ERR_HEADER, 0x7A]),
        ];
        for (label, packet) in malformed {
            if let MySqlError::Server {
                code,
                sql_state,
                message,
            } = fuzz_parse_error_packet(&packet)
            {
                return Err(format!(
                    "{label} {packet:02x?}: production reported a server error, code {code}, SQLSTATE {sql_state:?}, message {message:?}"
                ));
            }
        }
        Ok(())
    }

    // ---- MYSQL-STMT-031 ---------------------------------------------------

    fn check_packet_framing() -> Result<(), String> {
        let valid: [([u8; 4], u8, (u32, u8)); 5] = [
            ([0x05, 0x00, 0x00, 0x00], 0, (5, 0)),
            ([0x2C, 0x01, 0x00, 0x01], 1, (300, 1)),
            ([0x01, 0x02, 0x03, 0x07], 7, (0x03_0201, 7)),
            ([0xFF, 0xFF, 0xFF, 0x02], 2, (0xFF_FFFF, 2)),
            ([0x00, 0x00, 0x00, 0x03], 3, (0, 3)),
        ];
        for (header, expected_seq, want) in valid {
            match fuzz_decode_packet_header(header, expected_seq) {
                Ok(decoded) if decoded == want => {}
                other => {
                    return Err(format!(
                        "packet header {header:02x?} expecting sequence id {expected_seq}: the spec (payload length, sequence id) is {want:?}, production returned {other:?}"
                    ));
                }
            }
        }
        // Sequence ids count up by one per packet; any other id is out of order.
        let out_of_order: [([u8; 4], u8); 3] = [
            ([0x05, 0x00, 0x00, 0x02], 1),
            ([0x05, 0x00, 0x00, 0x00], 1),
            ([0x05, 0x00, 0x00, 0xFF], 0),
        ];
        for (header, expected_seq) in out_of_order {
            if let Ok(decoded) = fuzz_decode_packet_header(header, expected_seq) {
                return Err(format!(
                    "packet header {header:02x?} while expecting sequence id {expected_seq}: production accepted it as {decoded:?}"
                ));
            }
        }

        // Outbound: a payload of exactly 2^24 - 1 bytes is followed by an
        // empty packet. 18 bytes are prefix, bitmap, flag, type and the
        // 0xFD + int<3> length.
        let len = MAX_PAYLOAD - 18;
        let value = vec![b'y'; len];
        let param: &[u8] = &value;
        let what = "COM_STMT_EXECUTE whose payload is exactly 2^24 - 1 bytes";
        let produced = build(what, 31, &[&param])?;
        if produced.get(..4) != Some(&[0xFF, 0xFF, 0xFF, 0x00][..]) {
            return Err(format!(
                "{what}: first packet header {:02x?}, the spec header is [ff, ff, ff, 00]",
                produced.get(..4)
            ));
        }
        if produced.len() != 4 + MAX_PAYLOAD + 4
            || produced[4 + MAX_PAYLOAD..] != [0x00, 0x00, 0x00, 0x01]
        {
            return Err(format!(
                "{what}: {} bytes ending in {:02x?}; the spec ends with the empty packet [00, 00, 00, 01] after one full packet",
                produced.len(),
                &produced[produced.len().saturating_sub(4)..]
            ));
        }
        let spec = stmt_execute_packet(
            31,
            &[SpecParam::bound(
                MySqlType::Blob,
                false,
                encode_length_encoded_string(&value),
            )],
        );
        expect_bytes(what, &produced, &spec)
    }
}

#[cfg(not(feature = "mysql"))]
mod production {
    use super::*;

    fn needs_mysql(hook: &str) -> Decision {
        Decision::Skipped(format!(
            "needs --features mysql: {hook} lives in asupersync::database::mysql, which is \
             compiled only with the mysql feature (src/database/mod.rs:53-54)"
        ))
    }

    pub(super) fn stmt_execute_packet_format() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn parameter_type_codes() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn type_code_table() -> Decision {
        needs_mysql("column_type")
    }

    pub(super) fn unsigned_flag() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet, fuzz_parse_binary_row and fuzz_parse_text_row")
    }

    pub(super) fn parameter_length_encoding() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn null_bitmap_encoding() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn null_bitmap_length() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn null_bitmap_bit_order() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn mixed_null_parameters() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn cursor_flags_byte() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet")
    }

    pub(super) fn binary_result_row() -> Decision {
        needs_mysql("fuzz_parse_column_definition and fuzz_parse_binary_row")
    }

    pub(super) fn binary_row_null_bitmap_offset() -> Decision {
        needs_mysql("fuzz_parse_column_definition and fuzz_parse_binary_row")
    }

    pub(super) fn binary_value_encoding() -> Decision {
        needs_mysql("fuzz_parse_binary_row and fuzz_build_stmt_execute_packet")
    }

    pub(super) fn length_encoded_values() -> Decision {
        needs_mysql("fuzz_parse_text_row, fuzz_parse_binary_row and fuzz_parse_ok_packet_fields")
    }

    pub(super) fn invalid_statement_id() -> Decision {
        needs_mysql("fuzz_build_stmt_execute_packet and fuzz_parse_error_packet")
    }

    pub(super) fn column_definition() -> Decision {
        needs_mysql("fuzz_parse_column_definition")
    }

    pub(super) fn text_result_row() -> Decision {
        needs_mysql("fuzz_parse_text_row")
    }

    pub(super) fn text_result_terminators() -> Decision {
        needs_mysql("fuzz_parse_data_row_or_terminator")
    }

    pub(super) fn ok_packet() -> Decision {
        needs_mysql("fuzz_parse_ok_packet_fields")
    }

    pub(super) fn err_packet() -> Decision {
        needs_mysql("fuzz_parse_error_packet")
    }

    pub(super) fn packet_framing() -> Decision {
        needs_mysql("fuzz_decode_packet_header and fuzz_build_stmt_execute_packet")
    }
}

// ============================================================================
// Requirement table and harness
// ============================================================================

fn requirements() -> Vec<Requirement> {
    use Evidence::{MysqlHook, Unobservable};
    vec![
        Requirement {
            id: "MYSQL-STMT-001",
            description: "COM_STMT_PREPARE packet format MUST follow wire protocol",
            category: TestCategory::PacketFormat,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: prepare_packet_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-002",
            description: "COM_STMT_PREPARE_OK response MUST follow specification",
            category: TestCategory::PacketFormat,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: prepare_ok_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-003",
            description: "COM_STMT_EXECUTE packet format MUST be compliant: int<3> length and sequence id 0, then 0x17, int<4> statement_id, int<1> flags, int<4> iteration_count 1 and, with parameters, the NULL bitmap, new_params_bound_flag, int<2> types and binary values",
            category: TestCategory::PacketFormat,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::stmt_execute_packet_format,
        },
        Requirement {
            id: "MYSQL-STMT-004",
            description: "COM_STMT_CLOSE packet format MUST be correct",
            category: TestCategory::PacketFormat,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: close_packet_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-005",
            description: "Parameter type signaling MUST use correct MYSQL_TYPE codes: a fixed-width value is declared with the type of its width, a length-encoded value with a string-class type, and a NULL value is marked in the bitmap",
            category: TestCategory::ParameterTypes,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::parameter_type_codes,
        },
        Requirement {
            id: "MYSQL-STMT-006",
            description: "MYSQL_TYPE codes MUST match specification exactly: production's column_type constants equal the protocol's field-type table",
            category: TestCategory::ParameterTypes,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::type_code_table,
        },
        Requirement {
            id: "MYSQL-STMT-007",
            description: "Unsigned flag handling MUST be correct for integer types: unsigned parameters carry 0x80 in the type field's high byte, signed ones do not, and UNSIGNED columns decode without sign extension",
            category: TestCategory::ParameterTypes,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::unsigned_flag,
        },
        Requirement {
            id: "MYSQL-STMT-008",
            description: "Parameter length encoding MUST follow MySQL specification: a string or blob value is prefixed with its length-encoded length (1 byte, 0xFC + int<2>, 0xFD + int<3> or 0xFE + int<8>)",
            category: TestCategory::ParameterTypes,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::parameter_length_encoding,
        },
        Requirement {
            id: "MYSQL-STMT-009",
            description: "NULL bitmap encoding MUST follow Section 16.6.4.2: bit i of the bitmap marks parameter i as NULL",
            category: TestCategory::NullBitmap,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::null_bitmap_encoding,
        },
        Requirement {
            id: "MYSQL-STMT-010",
            description: "NULL bitmap length calculation MUST be correct: (n + 7) / 8 bytes, and no bitmap for zero parameters",
            category: TestCategory::NullBitmap,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::null_bitmap_length,
        },
        Requirement {
            id: "MYSQL-STMT-011",
            description: "NULL bitmap bit ordering MUST follow LSB-first convention",
            category: TestCategory::NullBitmap,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::null_bitmap_bit_order,
        },
        Requirement {
            id: "MYSQL-STMT-012",
            description: "Mixed NULL/non-NULL parameters MUST be handled correctly: every parameter has a type, only the non-NULL ones have a value",
            category: TestCategory::NullBitmap,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::mixed_null_parameters,
        },
        Requirement {
            id: "MYSQL-STMT-013",
            description: "COM_STMT_SEND_LONG_DATA packet format MUST be correct",
            category: TestCategory::LongData,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: long_data_packet_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-014",
            description: "Long data chunking MUST handle large data correctly",
            category: TestCategory::LongData,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: long_data_chunking_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-015",
            description: "Long data parameters MUST be reset between executions",
            category: TestCategory::LongData,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: long_data_reset_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-016",
            description: "Cursor type flags MUST be correctly encoded: production's flags byte is CURSOR_TYPE_NO_CURSOR (0x00), the only cursor type it sends",
            category: TestCategory::CursorFlags,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::cursor_flags_byte,
        },
        Requirement {
            id: "MYSQL-STMT-017",
            description: "CURSOR_TYPE_READ_ONLY MUST be handled correctly",
            category: TestCategory::CursorFlags,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: read_only_cursor_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-018",
            description: "Scrollable cursor behavior MUST be correct",
            category: TestCategory::CursorFlags,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: scrollable_cursor_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-019",
            description: "Binary result set format MUST follow specification: header 0x00, the NULL bitmap and the non-NULL values, decoded per column definition, with malformed rows rejected",
            category: TestCategory::BinaryResultSet,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::binary_result_row,
        },
        Requirement {
            id: "MYSQL-STMT-020",
            description: "Binary row NULL bitmap MUST handle +2 offset correctly: (n + 7 + 2) / 8 bytes, column i at bit i + 2",
            category: TestCategory::BinaryResultSet,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::binary_row_null_bitmap_offset,
        },
        Requirement {
            id: "MYSQL-STMT-021",
            description: "Binary value encoding MUST use correct formats: fixed-width integers and floats, length-encoded strings and DECIMAL, and length-prefixed DATE/DATETIME/TIME, in both directions",
            category: TestCategory::BinaryResultSet,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::binary_value_encoding,
        },
        Requirement {
            id: "MYSQL-STMT-022",
            description: "Length-encoded values MUST be handled correctly: every prefix form decoded, 0xFB read as NULL in text rows and refused where NULL cannot appear, malformed prefixes rejected",
            category: TestCategory::BinaryResultSet,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::length_encoded_values,
        },
        Requirement {
            id: "MYSQL-STMT-023",
            description: "Invalid statement ID handling MUST follow protocol: the id is sent verbatim and the server's ER_UNKNOWN_STMT_HANDLER ERR packet is decoded",
            category: TestCategory::ErrorHandling,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::invalid_statement_id,
        },
        Requirement {
            id: "MYSQL-STMT-024",
            description: "Parameter count mismatch MUST be detectable",
            category: TestCategory::ErrorHandling,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: parameter_count_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-025",
            description: "Invalid cursor type MUST be handled properly",
            category: TestCategory::ErrorHandling,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: invalid_cursor_unobservable,
        },
        Requirement {
            id: "MYSQL-STMT-026",
            description: "Column Definition 41 packets MUST decode catalog, schema, table, org_table, name, org_name, character set, length, type, flags and decimals, and truncated or ill-prefixed packets MUST be rejected",
            category: TestCategory::BinaryResultSet,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::column_definition,
        },
        Requirement {
            id: "MYSQL-STMT-027",
            description: "Text resultset rows MUST decode each value as a length-encoded string or 0xFB NULL per its column type, and rows whose value count or lengths disagree MUST be rejected",
            category: TestCategory::TextResultSet,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::text_result_row,
        },
        Requirement {
            id: "MYSQL-STMT-028",
            description: "Text result-set rows MUST be told apart from their terminator: an EOF packet (an 0xFE OK packet under CLIENT_DEPRECATE_EOF) ends the set, a row starting with an empty value stays a row, and an ERR packet is neither",
            category: TestCategory::TextResultSet,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::text_result_terminators,
        },
        Requirement {
            id: "MYSQL-STMT-029",
            description: "OK packets MUST decode the length-encoded affected_rows and last_insert_id and the status flags, and truncated or non-OK packets MUST be rejected",
            category: TestCategory::PacketFormat,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::ok_packet,
        },
        Requirement {
            id: "MYSQL-STMT-030",
            description: "ERR packets MUST decode the error code, the '#'-marked SQLSTATE and the message, and non-ERR or truncated packets MUST NOT be reported as server errors",
            category: TestCategory::ErrorHandling,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::err_packet,
        },
        Requirement {
            id: "MYSQL-STMT-031",
            description: "Packets MUST be framed as int<3> payload length and int<1> sequence id, out-of-order sequence ids MUST be rejected, and a payload of 2^24 - 1 bytes MUST be followed by an empty packet",
            category: TestCategory::PacketFormat,
            level: RequirementLevel::Must,
            evidence: MysqlHook,
            check: production::packet_framing,
        },
        Requirement {
            id: "MYSQL-STMT-032",
            description: "Binary result set rows MUST end at an EOF packet (an 0xFE OK packet under CLIENT_DEPRECATE_EOF), and an ERR packet MUST end the set with an error",
            category: TestCategory::BinaryResultSet,
            level: RequirementLevel::Must,
            evidence: Unobservable,
            check: binary_terminator_unobservable,
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

fn run_requirement(requirement: &Requirement) -> MySqlStmtConformanceResult {
    let start = Instant::now();
    // A panic in production code fails that requirement, not the harness.
    let decision = std::panic::catch_unwind(std::panic::AssertUnwindSafe(requirement.check))
        .unwrap_or_else(|payload| {
            Decision::Decided(Err(format!(
                "production code panicked: {}",
                panic_text(&*payload)
            )))
        });
    let (verdict, notes) = match decision {
        Decision::Decided(Ok(())) => (TestVerdict::Pass, None),
        Decision::Decided(Err(reason)) => (TestVerdict::Fail, Some(reason)),
        Decision::Skipped(note) => (TestVerdict::Skipped, Some(note)),
    };
    MySqlStmtConformanceResult {
        test_id: requirement.id.to_string(),
        description: requirement.description.to_string(),
        category: requirement.category.clone(),
        requirement_level: requirement.level.clone(),
        verdict,
        notes,
        elapsed_ms: elapsed_millis_for_report(start.elapsed()),
    }
}

fn elapsed_millis_for_report(elapsed: Duration) -> u64 {
    let rounded = elapsed.as_nanos().saturating_add(999_999) / 1_000_000;
    rounded.clamp(1, u128::from(u64::MAX)) as u64
}

/// MySQL COM_STMT_PREPARE/EXECUTE conformance harness.
#[allow(dead_code)]
pub struct MySqlStmtConformanceHarness {
    requirements: Vec<Requirement>,
}

#[allow(dead_code)]
impl MySqlStmtConformanceHarness {
    /// Create a new conformance test harness.
    pub fn new() -> Self {
        Self {
            requirements: requirements(),
        }
    }

    /// Execute all conformance tests.
    pub fn run_all_tests(&mut self) -> Vec<MySqlStmtConformanceResult> {
        self.requirements.iter().map(run_requirement).collect()
    }
}

impl Default for MySqlStmtConformanceHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashSet};

    /// The requirements no production hook can decide. Moving one out of
    /// this set needs a production observable for it.
    const UNOBSERVABLE: [&str; 11] = [
        "MYSQL-STMT-001",
        "MYSQL-STMT-002",
        "MYSQL-STMT-004",
        "MYSQL-STMT-013",
        "MYSQL-STMT-014",
        "MYSQL-STMT-015",
        "MYSQL-STMT-017",
        "MYSQL-STMT-018",
        "MYSQL-STMT-024",
        "MYSQL-STMT-025",
        "MYSQL-STMT-032",
    ];

    fn expected_verdict(evidence: Evidence) -> TestVerdict {
        match evidence {
            Evidence::Unobservable => TestVerdict::Skipped,
            Evidence::MysqlHook if cfg!(feature = "mysql") => TestVerdict::Pass,
            Evidence::MysqlHook => TestVerdict::Skipped,
        }
    }

    #[test]
    fn test_mysql_stmt_conformance_suite_completeness() {
        let requirements = requirements();
        let mut harness = MySqlStmtConformanceHarness::new();
        let results = harness.run_all_tests();

        for result in &results {
            println!(
                "mysql_stmt_conformance id={} verdict={:?} elapsed_ms={} notes={:?}",
                result.test_id, result.verdict, result.elapsed_ms, result.notes
            );
        }

        assert_eq!(
            results.len(),
            32,
            "expected 32 prepared-statement requirements"
        );
        let ids: BTreeSet<&str> = results.iter().map(|r| r.test_id.as_str()).collect();
        assert_eq!(ids.len(), results.len(), "requirement ids must be unique");

        let categories: HashSet<&TestCategory> = results.iter().map(|r| &r.category).collect();
        for category in [
            TestCategory::PacketFormat,
            TestCategory::ParameterTypes,
            TestCategory::NullBitmap,
            TestCategory::LongData,
            TestCategory::CursorFlags,
            TestCategory::BinaryResultSet,
            TestCategory::TextResultSet,
            TestCategory::ErrorHandling,
        ] {
            assert!(
                categories.contains(&category),
                "category {category:?} has no requirement"
            );
        }

        // Any spec violation fails the suite, whatever its requirement level.
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

        // The Skipped set is pinned exactly: the unobservable requirements
        // with --features mysql, every requirement without it.
        let skipped: BTreeSet<&str> = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Skipped)
            .map(|r| r.test_id.as_str())
            .collect();
        let expected_skipped: BTreeSet<&str> = if cfg!(feature = "mysql") {
            UNOBSERVABLE.into_iter().collect()
        } else {
            ids.clone()
        };
        assert_eq!(skipped, expected_skipped, "Skipped requirement ids");

        for (requirement, result) in requirements.iter().zip(&results) {
            assert_eq!(result.test_id, requirement.id);
            assert_eq!(
                result.verdict,
                expected_verdict(requirement.evidence),
                "{}: {:?}",
                result.test_id,
                result.notes
            );
            if result.verdict == TestVerdict::Skipped {
                let note = result.notes.as_deref().unwrap_or("");
                let reason = if requirement.evidence == Evidence::Unobservable {
                    NO_OBSERVABLE
                } else {
                    "needs --features mysql"
                };
                assert!(
                    note.starts_with(reason),
                    "{}: skip note {note:?} must start with {reason:?}",
                    result.test_id
                );
            }
        }

        assert!(
            results.iter().all(|r| r.elapsed_ms > 0),
            "all conformance results must record non-zero elapsed time"
        );

        let passed = results
            .iter()
            .filter(|r| r.verdict == TestVerdict::Pass)
            .count();
        println!(
            "mysql_stmt_conformance summary: {} requirements, {passed} passed, {} skipped, 0 failed",
            results.len(),
            skipped.len()
        );
    }

    /// Pins the spec type table this file compares production against.
    #[test]
    fn test_mysql_type_codes() {
        let table: [(MySqlType, u8); 28] = [
            (MySqlType::Decimal, 0x00),
            (MySqlType::Tiny, 0x01),
            (MySqlType::Short, 0x02),
            (MySqlType::Long, 0x03),
            (MySqlType::Float, 0x04),
            (MySqlType::Double, 0x05),
            (MySqlType::Null, 0x06),
            (MySqlType::Timestamp, 0x07),
            (MySqlType::LongLong, 0x08),
            (MySqlType::Int24, 0x09),
            (MySqlType::Date, 0x0A),
            (MySqlType::Time, 0x0B),
            (MySqlType::DateTime, 0x0C),
            (MySqlType::Year, 0x0D),
            (MySqlType::NewDate, 0x0E),
            (MySqlType::VarChar, 0x0F),
            (MySqlType::Bit, 0x10),
            (MySqlType::Json, 0xF5),
            (MySqlType::NewDecimal, 0xF6),
            (MySqlType::Enum, 0xF7),
            (MySqlType::Set, 0xF8),
            (MySqlType::TinyBlob, 0xF9),
            (MySqlType::MediumBlob, 0xFA),
            (MySqlType::LongBlob, 0xFB),
            (MySqlType::Blob, 0xFC),
            (MySqlType::VarString, 0xFD),
            (MySqlType::String, 0xFE),
            (MySqlType::Geometry, 0xFF),
        ];
        for (kind, code) in table {
            assert_eq!(kind as u8, code, "{kind:?}");
        }
    }

    #[test]
    fn test_cursor_type_values() {
        // Verify cursor type values match specification
        assert_eq!(CursorType::NoCursor as u8, 0x00);
        assert_eq!(CursorType::ReadOnly as u8, 0x01);
        assert_eq!(CursorType::ForUpdate as u8, 0x02);
        assert_eq!(CursorType::Scrollable as u8, 0x04);
    }

    /// Pins the oracle builders to bytes encoded by hand from the protocol
    /// documentation, so the oracle cannot drift along with production.
    #[test]
    fn oracle_builders_match_hand_encoded_spec_bytes() {
        // Length-encoded integers and strings.
        assert_eq!(encode_length_encoded_integer(0), vec![0x00]);
        assert_eq!(encode_length_encoded_integer(250), vec![0xFA]);
        assert_eq!(encode_length_encoded_integer(251), vec![0xFC, 0xFB, 0x00]);
        assert_eq!(
            encode_length_encoded_integer(65_535),
            vec![0xFC, 0xFF, 0xFF]
        );
        assert_eq!(
            encode_length_encoded_integer(65_536),
            vec![0xFD, 0x00, 0x00, 0x01]
        );
        assert_eq!(
            encode_length_encoded_integer(16_777_215),
            vec![0xFD, 0xFF, 0xFF, 0xFF]
        );
        assert_eq!(
            encode_length_encoded_integer(16_777_216),
            vec![0xFE, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode_length_encoded_string(b"hello"),
            vec![0x05, b'h', b'e', b'l', b'l', b'o']
        );

        // Packet framing, including the split at 2^24 - 1 bytes.
        assert_eq!(
            frame_packets(0, &[0x17]),
            vec![0x01, 0x00, 0x00, 0x00, 0x17]
        );
        assert_eq!(frame_packets(3, &[]), vec![0x00, 0x00, 0x00, 0x03]);
        let exact = vec![0xAB; 0xFF_FFFF];
        let framed = frame_packets(0, &exact);
        assert_eq!(framed.len(), 4 + 0xFF_FFFF + 4);
        assert_eq!(&framed[..4], &[0xFF, 0xFF, 0xFF, 0x00]);
        assert_eq!(&framed[4 + 0xFF_FFFF..], &[0x00, 0x00, 0x00, 0x01]);
        let over = vec![0xCD; 0xFF_FFFF + 2];
        let framed = frame_packets(0, &over);
        assert_eq!(framed.len(), 4 + 0xFF_FFFF + 4 + 2);
        assert_eq!(
            &framed[4 + 0xFF_FFFF..4 + 0xFF_FFFF + 4],
            &[0x02, 0x00, 0x00, 0x01]
        );

        // COM_STMT_EXECUTE.
        let mut execute = vec![
            27, 0, 0, 0, 0x17, 0xD2, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01,
            0x03, 0x00, 0xFD, 0x00, 0x0A,
        ];
        execute.extend_from_slice(b"test_value");
        assert_eq!(
            stmt_execute_packet(
                1234,
                &[
                    SpecParam::null(MySqlType::Long, false),
                    SpecParam::bound(
                        MySqlType::VarString,
                        false,
                        encode_length_encoded_string(b"test_value"),
                    ),
                ],
            ),
            execute
        );
        assert_eq!(
            stmt_execute_packet(42, &[]),
            vec![10, 0, 0, 0, 0x17, 42, 0, 0, 0, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
        let nine_nulls: Vec<SpecParam> = (0..9)
            .map(|_| SpecParam::null(MySqlType::Tiny, true))
            .collect();
        let payload = stmt_execute_payload(1, 0x00, &nine_nulls);
        assert_eq!(&payload[10..13], &[0xFF, 0x01, 0x01]);
        assert_eq!(&payload[13..15], &[0x01, 0x80]);
        assert_eq!(payload.len(), 10 + 2 + 1 + 18);

        // Column Definition 41.
        let column = column_spec("id", MySqlType::Long, 63, 11, 0x0003, 0);
        assert_eq!(
            column_definition_bytes(&column),
            vec![
                0x03, b'd', b'e', b'f', 0x04, b't', b'e', b's', b't', 0x01, b't', 0x01, b't', 0x02,
                b'i', b'd', 0x02, b'i', b'd', 0x0C, 63, 0x00, 11, 0x00, 0x00, 0x00, 0x03, 0x03,
                0x00, 0x00, 0x00, 0x00,
            ]
        );

        // Rows.
        let mut binary = vec![0x00, 0b0000_1000, 0x39, 0x30, 0x00, 0x00, 0x0B];
        binary.extend_from_slice(b"test_string");
        assert_eq!(
            binary_row_bytes(&[
                Some(12345i32.to_le_bytes().to_vec()),
                None,
                Some(encode_length_encoded_string(b"test_string")),
            ]),
            binary
        );
        let ten_nulls: Vec<Option<Vec<u8>>> = vec![None; 10];
        assert_eq!(binary_row_bytes(&ten_nulls), vec![0x00, 0xFC, 0x0F]);
        assert_eq!(
            text_row_bytes(&[Some(&b"42"[..]), None, Some(&b""[..])]),
            vec![0x02, b'4', b'2', 0xFB, 0x00]
        );

        // OK, EOF and ERR packets.
        assert_eq!(
            ok_packet_bytes(0x00, 3, 0, 0x0002, 0, b""),
            vec![0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            ok_packet_bytes(0xFE, 0, 0, 0x0002, 0, b"done"),
            vec![
                0xFE, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, b'd', b'o', b'n', b'e'
            ]
        );
        assert_eq!(
            eof_packet_bytes(0, 0x0002),
            vec![0xFE, 0x00, 0x00, 0x02, 0x00]
        );
        assert_eq!(
            err_packet_bytes(1146, Some("42S02"), "x"),
            vec![0xFF, 0x7A, 0x04, b'#', b'4', b'2', b'S', b'0', b'2', b'x']
        );
        assert_eq!(
            err_packet_bytes(1040, None, "y"),
            vec![0xFF, 0x10, 0x04, b'y']
        );
    }
}
