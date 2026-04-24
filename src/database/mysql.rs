//! MySQL async client with wire protocol implementation.
//!
//! This module provides a pure-Rust MySQL client implementing the wire protocol
//! with full Cx integration, multiple authentication plugins, and cancel-correct semantics.
//!
//! # Design
//!
//! MySQL uses a packet-based protocol with 4-byte headers (3 bytes length + 1 byte sequence).
//! All operations integrate with [`Cx`] for checkpointing and cancellation.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::database::MySqlConnection;
//!
//! async fn example(cx: &Cx) -> Result<(), MySqlError> {
//!     let conn = MySqlConnection::connect(cx, "mysql://user:pass@localhost/db").await?;
//!
//!     let rows = conn.query(cx, "SELECT id, name FROM users WHERE active = 1").await?;
//!     for row in rows {
//!         let id: i32 = row.get_i32("id")?;
//!         let name: &str = row.get_str("name")?;
//!         println!("User {id}: {name}");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! [`Cx`]: crate::cx::Cx

use crate::cx::Cx;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::TcpStream;
use crate::types::{CancelReason, Outcome};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

// ============================================================================
// Error Types
// ============================================================================

/// Error type for MySQL operations.
#[derive(Debug)]
pub enum MySqlError {
    /// I/O error during communication.
    Io(io::Error),
    /// Protocol error (malformed message).
    Protocol(String),
    /// Invalid packet for the current protocol state.
    InvalidPacket(String),
    /// Authentication failed.
    AuthenticationFailed(String),
    /// Server error response.
    Server {
        /// MySQL error code.
        code: u16,
        /// SQL state (5 characters).
        sql_state: String,
        /// Error message.
        message: String,
    },
    /// Operation was cancelled.
    Cancelled(CancelReason),
    /// Connection is closed.
    ConnectionClosed,
    /// Column not found in row.
    ColumnNotFound(String),
    /// Type conversion error.
    TypeConversion {
        /// Column name.
        column: String,
        /// Expected type.
        expected: &'static str,
        /// Actual type.
        actual: String,
    },
    /// Invalid connection URL.
    InvalidUrl(String),
    /// Invalid client-side parameter input.
    InvalidParameter(String),
    /// TLS required but not available.
    TlsRequired,
    /// Transaction already finished.
    TransactionFinished,
    /// Unsupported authentication plugin.
    UnsupportedAuthPlugin(String),
}

impl MySqlError {
    /// Returns the MySQL server error code, if this is a server error.
    #[must_use]
    pub fn server_code(&self) -> Option<u16> {
        match self {
            Self::Server { code, .. } => Some(*code),
            _ => None,
        }
    }

    /// Returns the SQL state string, if this is a server error.
    #[must_use]
    pub fn sql_state(&self) -> Option<&str> {
        match self {
            Self::Server { sql_state, .. } => Some(sql_state),
            _ => None,
        }
    }

    /// Returns the error code as a string (for cross-backend parity).
    #[must_use]
    pub fn error_code(&self) -> Option<String> {
        self.server_code().map(|c| c.to_string())
    }

    /// Returns `true` if this is a serialization failure.
    ///
    /// MySQL error 1213 (ER_LOCK_DEADLOCK) maps to this category.
    #[must_use]
    pub fn is_serialization_failure(&self) -> bool {
        self.server_code() == Some(1213)
    }

    /// Returns `true` if this is a deadlock detected error.
    ///
    /// MySQL error 1205 (ER_LOCK_WAIT_TIMEOUT) and 1213 (ER_LOCK_DEADLOCK).
    #[must_use]
    pub fn is_deadlock(&self) -> bool {
        matches!(self.server_code(), Some(1205 | 1213))
    }

    /// Returns `true` if this is a unique constraint violation.
    ///
    /// MySQL error 1062 (ER_DUP_ENTRY).
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        self.server_code() == Some(1062)
    }

    /// Returns `true` if this is any constraint violation.
    ///
    /// MySQL errors: 1062 (duplicate), 1451/1452 (foreign key).
    #[must_use]
    pub fn is_constraint_violation(&self) -> bool {
        matches!(self.server_code(), Some(1062 | 1451 | 1452))
    }

    /// Returns `true` if this is a connection-level error.
    ///
    /// Includes I/O errors, connection closed, and MySQL errors
    /// 2006 (server gone) and 2013 (lost connection during query).
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::ConnectionClosed | Self::TlsRequired
        ) || matches!(self.server_code(), Some(2006 | 2013))
    }

    /// Returns `true` if this error is transient and may succeed on retry.
    ///
    /// Transient errors: deadlock (1213), lock wait timeout (1205),
    /// server gone (2006), lost connection (2013), and I/O errors.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        if matches!(self, Self::Io(_) | Self::ConnectionClosed) {
            return true;
        }
        matches!(self.server_code(), Some(1205 | 1213 | 2006 | 2013))
    }

    /// Returns `true` if this error is safe to retry automatically.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.is_transient()
    }
}

impl fmt::Display for MySqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "MySQL I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "MySQL protocol error: {msg}"),
            Self::InvalidPacket(msg) => write!(f, "Invalid MySQL packet: {msg}"),
            Self::AuthenticationFailed(msg) => write!(f, "MySQL authentication failed: {msg}"),
            Self::Server {
                code,
                sql_state,
                message,
            } => write!(f, "MySQL error [{code}] ({sql_state}): {message}"),
            Self::Cancelled(reason) => write!(f, "MySQL operation cancelled: {reason:?}"),
            Self::ConnectionClosed => write!(f, "MySQL connection is closed"),
            Self::ColumnNotFound(name) => write!(f, "Column not found: {name}"),
            Self::TypeConversion {
                column,
                expected,
                actual,
            } => write!(
                f,
                "Type conversion error for column {column}: expected {expected}, got {actual}"
            ),
            Self::InvalidUrl(msg) => write!(f, "Invalid MySQL URL: {msg}"),
            Self::InvalidParameter(msg) => write!(f, "Invalid MySQL parameter: {msg}"),
            Self::TlsRequired => write!(f, "TLS required but not available"),
            Self::TransactionFinished => write!(f, "Transaction already finished"),
            Self::UnsupportedAuthPlugin(plugin) => {
                write!(f, "Unsupported authentication plugin: {plugin}")
            }
        }
    }
}

impl std::error::Error for MySqlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for MySqlError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

// ============================================================================
// MySQL Wire Protocol Constants
// ============================================================================

/// MySQL capability flags.
#[allow(dead_code)]
mod capability {
    pub const CLIENT_LONG_PASSWORD: u32 = 1;
    pub const CLIENT_FOUND_ROWS: u32 = 2;
    pub const CLIENT_LONG_FLAG: u32 = 4;
    pub const CLIENT_CONNECT_WITH_DB: u32 = 8;
    pub const CLIENT_NO_SCHEMA: u32 = 16;
    pub const CLIENT_COMPRESS: u32 = 32;
    pub const CLIENT_ODBC: u32 = 64;
    pub const CLIENT_LOCAL_FILES: u32 = 128;
    pub const CLIENT_IGNORE_SPACE: u32 = 256;
    pub const CLIENT_PROTOCOL_41: u32 = 512;
    pub const CLIENT_INTERACTIVE: u32 = 1024;
    pub const CLIENT_SSL: u32 = 2048;
    pub const CLIENT_IGNORE_SIGPIPE: u32 = 4096;
    pub const CLIENT_TRANSACTIONS: u32 = 8192;
    pub const CLIENT_RESERVED: u32 = 16384;
    pub const CLIENT_SECURE_CONNECTION: u32 = 32768;
    pub const CLIENT_MULTI_STATEMENTS: u32 = 1 << 16;
    pub const CLIENT_MULTI_RESULTS: u32 = 1 << 17;
    pub const CLIENT_PS_MULTI_RESULTS: u32 = 1 << 18;
    pub const CLIENT_PLUGIN_AUTH: u32 = 1 << 19;
    pub const CLIENT_CONNECT_ATTRS: u32 = 1 << 20;
    pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 1 << 21;
    pub const CLIENT_DEPRECATE_EOF: u32 = 1 << 24;
}

/// MySQL command codes.
#[allow(dead_code)]
mod command {
    pub const COM_QUIT: u8 = 0x01;
    pub const COM_INIT_DB: u8 = 0x02;
    pub const COM_QUERY: u8 = 0x03;
    pub const COM_FIELD_LIST: u8 = 0x04;
    pub const COM_PING: u8 = 0x0E;
    pub const COM_STMT_PREPARE: u8 = 0x16;
    pub const COM_STMT_EXECUTE: u8 = 0x17;
    pub const COM_STMT_SEND_LONG_DATA: u8 = 0x18;
    pub const COM_STMT_CLOSE: u8 = 0x19;
    pub const COM_STMT_RESET: u8 = 0x1A;
}

/// Maximum payload size for a single MySQL packet (16 MiB - 1 byte).
const MAX_PACKET_SIZE: u32 = 16 * 1024 * 1024 - 1; // 16_777_215

/// Default maximum number of rows returned from a single result set.
/// Prevents unbounded memory growth from runaway SELECTs.
const DEFAULT_MAX_RESULT_ROWS: usize = 1_000_000;
/// Guard against corrupted or malicious servers sending enormous column counts.
const MAX_COLUMN_COUNT: u64 = 16_384;
/// Practical limit for reassembled multi-packet payloads.
const MAX_REASSEMBLED_PACKET_SIZE: usize = 64 * 1024 * 1024;
/// MySQL's binary charset/collation ID in result-set metadata.
const MYSQL_BINARY_CHARSET_ID: u16 = 63;

/// MySQL column types for result set parsing.
#[allow(dead_code, missing_docs)]
pub mod column_type {
    /// Decimal type.
    pub const MYSQL_TYPE_DECIMAL: u8 = 0;
    /// Tiny integer (TINYINT).
    pub const MYSQL_TYPE_TINY: u8 = 1;
    /// Short integer (SMALLINT).
    pub const MYSQL_TYPE_SHORT: u8 = 2;
    /// Long integer (INT).
    pub const MYSQL_TYPE_LONG: u8 = 3;
    /// Single-precision float.
    pub const MYSQL_TYPE_FLOAT: u8 = 4;
    /// Double-precision float.
    pub const MYSQL_TYPE_DOUBLE: u8 = 5;
    /// NULL type.
    pub const MYSQL_TYPE_NULL: u8 = 6;
    /// Timestamp.
    pub const MYSQL_TYPE_TIMESTAMP: u8 = 7;
    /// Long long integer (BIGINT).
    pub const MYSQL_TYPE_LONGLONG: u8 = 8;
    /// Medium integer (MEDIUMINT).
    pub const MYSQL_TYPE_INT24: u8 = 9;
    /// Date.
    pub const MYSQL_TYPE_DATE: u8 = 10;
    /// Time.
    pub const MYSQL_TYPE_TIME: u8 = 11;
    /// Datetime.
    pub const MYSQL_TYPE_DATETIME: u8 = 12;
    /// Year.
    pub const MYSQL_TYPE_YEAR: u8 = 13;
    /// Variable-length string.
    pub const MYSQL_TYPE_VARCHAR: u8 = 15;
    /// Bit field.
    pub const MYSQL_TYPE_BIT: u8 = 16;
    /// JSON document.
    pub const MYSQL_TYPE_JSON: u8 = 245;
    /// New decimal (high precision).
    pub const MYSQL_TYPE_NEWDECIMAL: u8 = 246;
    /// Enumeration.
    pub const MYSQL_TYPE_ENUM: u8 = 247;
    /// Set.
    pub const MYSQL_TYPE_SET: u8 = 248;
    /// Tiny blob.
    pub const MYSQL_TYPE_TINY_BLOB: u8 = 249;
    /// Medium blob.
    pub const MYSQL_TYPE_MEDIUM_BLOB: u8 = 250;
    /// Long blob.
    pub const MYSQL_TYPE_LONG_BLOB: u8 = 251;
    /// Standard blob.
    pub const MYSQL_TYPE_BLOB: u8 = 252;
    /// Variable-length string (alias).
    pub const MYSQL_TYPE_VAR_STRING: u8 = 253;
    /// Fixed-length string.
    pub const MYSQL_TYPE_STRING: u8 = 254;
    /// Geometry type.
    pub const MYSQL_TYPE_GEOMETRY: u8 = 255;
}

// ============================================================================
// MySQL Wire Protocol Types
// ============================================================================

/// Column description from result set.
#[derive(Debug, Clone)]
pub struct MySqlColumn {
    /// Catalog (always "def").
    pub catalog: String,
    /// Schema (database name).
    pub schema: String,
    /// Table name.
    pub table: String,
    /// Original table name.
    pub org_table: String,
    /// Column name.
    pub name: String,
    /// Original column name.
    pub org_name: String,
    /// Character set.
    pub charset: u16,
    /// Column length.
    pub length: u32,
    /// Column type.
    pub column_type: u8,
    /// Column flags.
    pub flags: u16,
    /// Decimal places.
    pub decimals: u8,
}

impl MySqlColumn {
    /// Create a simple string column for prepared statement metadata.
    pub fn new_simple_string(name: &str) -> Self {
        Self {
            catalog: "def".to_string(),
            schema: String::new(),
            table: String::new(),
            org_table: String::new(),
            name: name.to_string(),
            org_name: name.to_string(),
            charset: 0,
            length: 0,
            column_type: 0,
            flags: 0,
            decimals: 0,
        }
    }
}

/// A value from a MySQL row.
#[derive(Debug, Clone, PartialEq)]
pub enum MySqlValue {
    /// NULL value.
    Null,
    /// Boolean value.
    Bool(bool),
    /// Tiny integer (8-bit).
    Tiny(i8),
    /// Short integer (16-bit).
    Short(i16),
    /// Long integer (32-bit).
    Long(i32),
    /// Long long integer (64-bit).
    LongLong(i64),
    /// Single-precision float.
    Float(f32),
    /// Double-precision float.
    Double(f64),
    /// Text value.
    Text(String),
    /// Binary data.
    Bytes(Vec<u8>),
}

impl MySqlValue {
    /// Returns true if this is NULL.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Try to get as bool.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            Self::Tiny(v) => Some(*v != 0),
            _ => None,
        }
    }

    /// Try to get as i32.
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::Long(v) => Some(*v),
            Self::Short(v) => Some(i32::from(*v)),
            Self::Tiny(v) => Some(i32::from(*v)),
            _ => None,
        }
    }

    /// Try to get as i64.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::LongLong(v) => Some(*v),
            Self::Long(v) => Some(i64::from(*v)),
            Self::Short(v) => Some(i64::from(*v)),
            Self::Tiny(v) => Some(i64::from(*v)),
            _ => None,
        }
    }

    /// Try to get as f64.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Double(v) => Some(*v),
            Self::Float(v) => Some(f64::from(*v)),
            _ => None,
        }
    }

    /// Try to get as string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Text(v) => Some(v),
            _ => None,
        }
    }

    /// Try to get as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(v) => Some(v),
            _ => None,
        }
    }
}

impl fmt::Display for MySqlValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "NULL"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::Tiny(v) => write!(f, "{v}"),
            Self::Short(v) => write!(f, "{v}"),
            Self::Long(v) => write!(f, "{v}"),
            Self::LongLong(v) => write!(f, "{v}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Double(v) => write!(f, "{v}"),
            Self::Text(v) => write!(f, "{v}"),
            Self::Bytes(v) => write!(f, "<bytes {} len>", v.len()),
        }
    }
}

/// A row from a MySQL query result.
#[derive(Debug, Clone)]
pub struct MySqlRow {
    /// Column metadata.
    columns: Arc<Vec<MySqlColumn>>,
    /// Column name to index mapping.
    column_indices: Arc<BTreeMap<String, usize>>,
    /// Row values.
    values: Vec<MySqlValue>,
}

impl MySqlRow {
    /// Get a value by column name.
    pub fn get(&self, column: &str) -> Result<&MySqlValue, MySqlError> {
        let idx = self
            .column_indices
            .get(column)
            .ok_or_else(|| MySqlError::ColumnNotFound(column.to_string()))?;
        self.values
            .get(*idx)
            .ok_or_else(|| MySqlError::ColumnNotFound(column.to_string()))
    }

    /// Get a value by column index.
    pub fn get_idx(&self, idx: usize) -> Result<&MySqlValue, MySqlError> {
        self.values
            .get(idx)
            .ok_or_else(|| MySqlError::ColumnNotFound(format!("index {idx}")))
    }

    /// Get an i32 value by column name.
    pub fn get_i32(&self, column: &str) -> Result<i32, MySqlError> {
        let val = self.get(column)?;
        val.as_i32().ok_or_else(|| MySqlError::TypeConversion {
            column: column.to_string(),
            expected: "i32",
            actual: format!("{val:?}"),
        })
    }

    /// Get an i64 value by column name.
    pub fn get_i64(&self, column: &str) -> Result<i64, MySqlError> {
        let val = self.get(column)?;
        val.as_i64().ok_or_else(|| MySqlError::TypeConversion {
            column: column.to_string(),
            expected: "i64",
            actual: format!("{val:?}"),
        })
    }

    /// Get a string value by column name.
    pub fn get_str(&self, column: &str) -> Result<&str, MySqlError> {
        let val = self.get(column)?;
        val.as_str().ok_or_else(|| MySqlError::TypeConversion {
            column: column.to_string(),
            expected: "string",
            actual: format!("{val:?}"),
        })
    }

    /// Get a bool value by column name.
    pub fn get_bool(&self, column: &str) -> Result<bool, MySqlError> {
        let val = self.get(column)?;
        val.as_bool().ok_or_else(|| MySqlError::TypeConversion {
            column: column.to_string(),
            expected: "bool",
            actual: format!("{val:?}"),
        })
    }

    /// Returns the number of columns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if the row has no columns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Returns column metadata.
    #[must_use]
    pub fn columns(&self) -> &[MySqlColumn] {
        &self.columns
    }
}

// ============================================================================
// Wire Protocol Encoding/Decoding
// ============================================================================

/// Buffer for building protocol messages.
struct PacketBuffer {
    buf: Vec<u8>,
    sequence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EncodedPacket {
    bytes: Vec<u8>,
    next_sequence: u8,
}

impl PacketBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
            sequence: 0,
        }
    }

    fn set_sequence(&mut self, seq: u8) {
        self.sequence = seq;
    }

    fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn write_u16_le(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u32_le(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_null_terminated(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }

    /// Write length-encoded integer.
    fn write_lenenc_int(&mut self, v: u64) {
        if v < 251 {
            self.buf.push(v as u8);
        } else if v < 65536 {
            self.buf.push(0xFC);
            self.buf.extend_from_slice(&(v as u16).to_le_bytes());
        } else if v < 16_777_216 {
            self.buf.push(0xFD);
            self.buf.push((v & 0xFF) as u8);
            self.buf.push(((v >> 8) & 0xFF) as u8);
            self.buf.push(((v >> 16) & 0xFF) as u8);
        } else {
            self.buf.push(0xFE);
            self.buf.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Build one logical packet message with 4-byte headers.
    ///
    /// MySQL splits payloads at `MAX_PACKET_SIZE` boundaries and continues
    /// with incrementing sequence IDs until the last chunk is shorter than
    /// `MAX_PACKET_SIZE`. An exact-boundary payload therefore needs a
    /// zero-length terminator packet.
    fn build_packet(&self) -> EncodedPacket {
        let mut sequence = self.sequence;
        let mut offset = 0usize;
        let max_payload = MAX_PACKET_SIZE as usize;
        let payload_len = self.buf.len();
        let packet_count = if payload_len == 0 {
            1
        } else {
            payload_len / max_payload + 1
        };
        let mut result = Vec::with_capacity(payload_len + packet_count * 4);

        loop {
            let remaining = payload_len.saturating_sub(offset);
            let chunk_len = remaining.min(max_payload);

            result.push((chunk_len & 0xFF) as u8);
            result.push(((chunk_len >> 8) & 0xFF) as u8);
            result.push(((chunk_len >> 16) & 0xFF) as u8);
            result.push(sequence);

            if chunk_len > 0 {
                result.extend_from_slice(&self.buf[offset..offset + chunk_len]);
                offset += chunk_len;
            }

            sequence = sequence.wrapping_add(1);

            if chunk_len < max_payload {
                break;
            }

            if offset == payload_len {
                // Exact 0xFF_FFFF boundary: emit the required empty terminator.
                result.extend_from_slice(&[0, 0, 0, sequence]);
                sequence = sequence.wrapping_add(1);
                break;
            }
        }

        EncodedPacket {
            bytes: result,
            next_sequence: sequence,
        }
    }
}

/// Packet reader for parsing MySQL packets.
struct PacketReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> PacketReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_byte(&mut self) -> Result<u8, MySqlError> {
        if self.pos >= self.data.len() {
            return Err(MySqlError::Protocol("unexpected end of packet".to_string()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], MySqlError> {
        if len > self.data.len().saturating_sub(self.pos) {
            return Err(MySqlError::Protocol("unexpected end of packet".to_string()));
        }
        let data = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(data)
    }

    fn read_rest(&mut self) -> &'a [u8] {
        let data = &self.data[self.pos..];
        self.pos = self.data.len();
        data
    }

    fn read_u16_le(&mut self) -> Result<u16, MySqlError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32_le(&mut self) -> Result<u32, MySqlError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64_le(&mut self) -> Result<u64, MySqlError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_null_terminated(&mut self) -> Result<&'a str, MySqlError> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err(MySqlError::Protocol("unterminated string".to_string()));
        }
        let s = std::str::from_utf8(&self.data[start..self.pos])
            .map_err(|e| MySqlError::Protocol(format!("invalid UTF-8: {e}")))?;
        self.pos += 1; // skip null
        Ok(s)
    }

    /// Read length-encoded integer.
    fn read_lenenc_int(&mut self) -> Result<u64, MySqlError> {
        let first = self.read_byte()?;
        match first {
            0..=250 => Ok(u64::from(first)),
            0xFC => Ok(u64::from(self.read_u16_le()?)),
            0xFD => {
                let bytes = self.read_bytes(3)?;
                Ok(u64::from(bytes[0]) | (u64::from(bytes[1]) << 8) | (u64::from(bytes[2]) << 16))
            }
            0xFE => self.read_u64_le(),
            0xFB => Err(MySqlError::Protocol(
                "NULL in length-encoded int".to_string(),
            )),
            _ => Err(MySqlError::Protocol(format!(
                "invalid length-encoded int prefix: {first}"
            ))),
        }
    }

    /// Read length-encoded string.
    fn read_lenenc_str(&mut self) -> Result<&'a str, MySqlError> {
        let len = usize::try_from(self.read_lenenc_int()?)
            .map_err(|_| MySqlError::Protocol("length too large".to_string()))?;
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes).map_err(|e| MySqlError::Protocol(format!("invalid UTF-8: {e}")))
    }

    /// Read length-encoded bytes.
    fn read_lenenc_bytes(&mut self) -> Result<&'a [u8], MySqlError> {
        let len = usize::try_from(self.read_lenenc_int()?)
            .map_err(|_| MySqlError::Protocol("length too large".to_string()))?;
        self.read_bytes(len)
    }
}

// ============================================================================
// Authentication
// ============================================================================

/// Compute SHA1 hash.
fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute SHA256 hash.
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// mysql_native_password authentication.
/// scramble = SHA1(password) XOR SHA1(nonce + SHA1(SHA1(password)))
fn mysql_native_auth(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    let password_hash = sha1(password.as_bytes());
    let double_hash = sha1(&password_hash);

    let mut combined = Vec::with_capacity(nonce.len() + 20);
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&double_hash);
    let scramble_hash = sha1(&combined);

    password_hash
        .iter()
        .zip(scramble_hash.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

/// caching_sha2_password authentication (fast auth).
/// scramble = SHA256(password) XOR SHA256(SHA256(SHA256(password)) + nonce)
fn caching_sha2_auth(password: &str, nonce: &[u8]) -> Vec<u8> {
    if password.is_empty() {
        return Vec::new();
    }

    let password_hash = sha256(password.as_bytes());
    let double_hash = sha256(&password_hash);

    let mut combined = Vec::with_capacity(32 + nonce.len());
    combined.extend_from_slice(&double_hash);
    combined.extend_from_slice(nonce);
    let scramble_hash = sha256(&combined);

    password_hash
        .iter()
        .zip(scramble_hash.iter())
        .map(|(a, b)| a ^ b)
        .collect()
}

// ============================================================================
// Connection URL Parsing
// ============================================================================

/// Parsed MySQL connection URL.
#[derive(Debug, Clone)]
pub struct MySqlConnectOptions {
    /// Host name or IP address.
    pub host: String,
    /// Port number (default 3306).
    pub port: u16,
    /// Database name.
    pub database: Option<String>,
    /// Username.
    pub user: String,
    /// Password.
    pub password: Option<String>,
    /// Connect timeout.
    pub connect_timeout: Option<std::time::Duration>,
    /// Require SSL.
    pub ssl_mode: SslMode,
}

/// SSL connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SslMode {
    /// Never use SSL.
    #[default]
    Disabled,
    /// Prefer SSL if available.
    Preferred,
    /// Require SSL.
    Required,
}

/// Percent-decode a URL component (e.g., user or password).
/// Handles `%XX` hex pairs; passes through malformed sequences unchanged.
fn percent_decode(input: &str) -> String {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl MySqlConnectOptions {
    /// Parse a connection URL.
    ///
    /// Format: `mysql://user:password@host:port/database?param=value`
    ///
    /// Supported query parameters:
    /// - `ssl-mode` or `sslmode`: `disabled`, `preferred`, `required`
    /// - `connect_timeout`: seconds (integer)
    pub fn parse(url: &str) -> Result<Self, MySqlError> {
        let url = url
            .strip_prefix("mysql://")
            .ok_or_else(|| MySqlError::InvalidUrl("URL must start with mysql://".to_string()))?;

        // Split into auth@hostport/database?params
        let (auth_host, params) = url.split_once('?').unwrap_or((url, ""));

        // Split database
        let (auth_host, database) = auth_host
            .rsplit_once('/')
            .map(|(ah, db)| (ah, Some(db.to_string())))
            .unwrap_or((auth_host, None));

        // Split auth@host
        let (user, password, host_port) = if let Some((auth, host)) = auth_host.rsplit_once('@') {
            let (user, password) = auth
                .split_once(':')
                .map_or((auth, None), |(u, p)| (u, Some(p)));
            (percent_decode(user), password.map(percent_decode), host)
        } else {
            ("root".to_string(), None, auth_host)
        };

        // Split host:port (with IPv6 bracket support: [::1]:3306)
        let (host, port) = if host_port.starts_with('[') {
            // IPv6 literal: [addr]:port or [addr]
            if let Some((bracketed, rest)) = host_port.split_once(']') {
                let addr = &bracketed[1..]; // strip leading '['
                let port = rest
                    .strip_prefix(':')
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(3306);
                (addr, port)
            } else {
                return Err(MySqlError::InvalidUrl(
                    "unclosed IPv6 bracket in host".to_string(),
                ));
            }
        } else if host_port.matches(':').count() > 1 {
            (host_port, 3306)
        } else {
            host_port
                .rsplit_once(':')
                .map_or((host_port, 3306), |(h, p)| (h, p.parse().unwrap_or(3306)))
        };

        let mut connect_timeout = None;
        let mut ssl_mode = SslMode::Disabled;

        // Parse query parameters
        if !params.is_empty() {
            for pair in params.split('&') {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                match key {
                    "ssl-mode" | "sslmode" => {
                        ssl_mode = match value {
                            "disabled" | "DISABLED" => SslMode::Disabled,
                            "preferred" | "PREFERRED" => SslMode::Preferred,
                            "required" | "REQUIRED" => SslMode::Required,
                            _ => {
                                return Err(MySqlError::InvalidUrl(format!(
                                    "unknown ssl-mode: {value}"
                                )));
                            }
                        };
                    }
                    "connect_timeout" => {
                        if let Ok(secs) = value.parse::<u64>() {
                            connect_timeout = Some(std::time::Duration::from_secs(secs));
                        }
                    }
                    _ => {
                        // Unknown parameters are silently ignored for forward-compat.
                    }
                }
            }
        }

        Ok(Self {
            host: host.to_string(),
            port,
            database,
            user,
            password,
            connect_timeout,
            ssl_mode,
        })
    }
}

// ============================================================================
// MySQL Connection
// ============================================================================

/// Initial handshake data from server.
struct Handshake {
    server_version: String,
    connection_id: u32,
    auth_plugin_data: Vec<u8>,
    capabilities: u32,
    charset: u8,
    status_flags: u16,
    auth_plugin_name: String,
}

struct OkPacket {
    affected_rows: u64,
    status_flags: u16,
}

/// Inner connection state.
struct MySqlConnectionInner {
    /// TCP stream to the server.
    stream: TcpStream,
    /// Connection ID.
    connection_id: u32,
    /// Server capabilities.
    capabilities: u32,
    /// Character set.
    charset: u8,
    /// Server status flags.
    status_flags: u16,
    /// Sequence number for next packet.
    sequence: u8,
    /// Whether the connection is closed.
    closed: bool,
    /// Server version string.
    server_version: String,
    /// True when a transaction was dropped without explicit commit/rollback.
    /// The next command will issue an implicit ROLLBACK first.
    needs_rollback: bool,
    /// Maximum number of rows to return from a result set.
    max_result_rows: usize,
}

impl Drop for MySqlConnectionInner {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            self.closed = true;
        }
    }
}

/// An async MySQL connection.
///
/// All operations integrate with [`Cx`] for cancellation and checkpointing.
///
/// [`Cx`]: crate::cx::Cx
pub struct MySqlConnection {
    /// Inner connection state.
    inner: MySqlConnectionInner,
}

impl fmt::Debug for MySqlConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MySqlConnection")
            .field("connection_id", &self.inner.connection_id)
            .field("server_version", &self.inner.server_version)
            .field("closed", &self.inner.closed)
            .finish()
    }
}

#[inline]
fn outcome_from_error<T>(err: MySqlError) -> Outcome<T, MySqlError> {
    if let MySqlError::Cancelled(reason) = err {
        Outcome::Cancelled(reason)
    } else {
        Outcome::Err(err)
    }
}

impl MySqlConnection {
    /// Connect to a MySQL database.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn connect(cx: &Cx, url: &str) -> Outcome<Self, MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let options = match MySqlConnectOptions::parse(url) {
            Ok(opts) => opts,
            Err(e) => return outcome_from_error(e),
        };

        Self::connect_with_options(cx, options).await
    }

    /// Connect with explicit options.
    pub async fn connect_with_options(
        cx: &Cx,
        options: MySqlConnectOptions,
    ) -> Outcome<Self, MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        // Connect to the server (applying connect_timeout if configured).
        let addr = format!("{}:{}", options.host, options.port);
        let stream = if let Some(timeout) = options.connect_timeout {
            match TcpStream::connect_timeout(addr, timeout).await {
                Ok(s) => s,
                Err(e) => return Outcome::Err(MySqlError::Io(e)),
            }
        } else {
            match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => return Outcome::Err(MySqlError::Io(e)),
            }
        };

        let mut conn = Self {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };

        // Read initial handshake
        let handshake = match conn.read_handshake().await {
            Ok(h) => h,
            Err(e) => return outcome_from_error(e),
        };

        conn.inner.connection_id = handshake.connection_id;
        conn.inner.charset = handshake.charset;
        conn.inner.status_flags = handshake.status_flags;
        conn.inner.server_version = handshake.server_version.clone();

        if options.ssl_mode == SslMode::Required {
            return Outcome::Err(MySqlError::TlsRequired);
        }

        // Send handshake response
        if let Err(e) = conn.send_handshake_response(&options, &handshake).await {
            return outcome_from_error(e);
        }

        // Handle authentication response
        if let Err(e) = conn.handle_auth_response(&options, &handshake).await {
            return outcome_from_error(e);
        }

        Outcome::Ok(conn)
    }

    /// Read the initial handshake packet.
    async fn read_handshake(&mut self) -> Result<Handshake, MySqlError> {
        let (data, seq) = self.read_packet().await?;
        self.inner.sequence = seq.wrapping_add(1);

        let mut reader = PacketReader::new(&data);

        let protocol_version = reader.read_byte()?;
        if protocol_version != 10 {
            return Err(MySqlError::Protocol(format!(
                "unsupported protocol version: {protocol_version}"
            )));
        }

        let server_version = reader.read_null_terminated()?.to_string();
        let connection_id = reader.read_u32_le()?;

        // Auth plugin data part 1 (8 bytes)
        let auth_data_1 = reader.read_bytes(8)?;

        // Filler (1 byte)
        let _ = reader.read_byte()?;

        // Capabilities (lower 2 bytes)
        let cap_lower = reader.read_u16_le()?;

        // Default charset, status flags, capabilities (upper 2 bytes)
        let charset = reader.read_byte()?;
        let status_flags = reader.read_u16_le()?;
        let cap_upper = reader.read_u16_le()?;
        let capabilities = u32::from(cap_lower) | (u32::from(cap_upper) << 16);

        // Auth plugin data length
        let auth_data_len = reader.read_byte()?;

        // Reserved (10 bytes)
        let _ = reader.read_bytes(10)?;

        // Auth plugin data part 2 (if capabilities include SECURE_CONNECTION)
        let mut auth_plugin_data = auth_data_1.to_vec();
        if capabilities & capability::CLIENT_SECURE_CONNECTION != 0 {
            let part2_len = std::cmp::max(13, auth_data_len.saturating_sub(8)) as usize;
            let auth_data_2 = reader.read_bytes(part2_len.min(reader.remaining()))?;
            // Strip only the trailing null byte (nonce may contain embedded 0x00)
            let end = if auth_data_2.last() == Some(&0) {
                auth_data_2.len() - 1
            } else {
                auth_data_2.len()
            };
            auth_plugin_data.extend_from_slice(&auth_data_2[..end]);
        }

        // Auth plugin name (if capabilities include PLUGIN_AUTH)
        let auth_plugin_name =
            if capabilities & capability::CLIENT_PLUGIN_AUTH != 0 && reader.remaining() > 0 {
                reader.read_null_terminated()?.to_string()
            } else {
                "mysql_native_password".to_string()
            };

        Ok(Handshake {
            server_version,
            connection_id,
            auth_plugin_data,
            capabilities,
            charset,
            status_flags,
            auth_plugin_name,
        })
    }

    /// Send the handshake response.
    async fn send_handshake_response(
        &mut self,
        options: &MySqlConnectOptions,
        handshake: &Handshake,
    ) -> Result<(), MySqlError> {
        let mut buf = PacketBuffer::new();
        buf.set_sequence(self.inner.sequence);

        // Client capabilities
        let mut client_caps = capability::CLIENT_PROTOCOL_41
            | capability::CLIENT_SECURE_CONNECTION
            | capability::CLIENT_PLUGIN_AUTH
            | capability::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            | capability::CLIENT_TRANSACTIONS
            | capability::CLIENT_MULTI_RESULTS;

        if options.database.is_some() {
            client_caps |= capability::CLIENT_CONNECT_WITH_DB;
        }

        // CLIENT_SSL is only valid in the separate MySQL SSL Request packet,
        // before TLS wraps the stream. Do not set it on the plaintext full
        // handshake response, which already carries authentication data.
        // Runtime packet parsing decisions must use negotiated capabilities,
        // not the server-advertised superset.
        self.inner.capabilities =
            Self::negotiated_capabilities(handshake.capabilities, client_caps);

        buf.write_u32_le(client_caps);
        buf.write_u32_le(16_777_215); // Max packet size
        buf.write_byte(handshake.charset); // Character set
        buf.write_bytes(&[0u8; 23]); // Reserved

        // Username
        buf.write_null_terminated(&options.user);

        // Auth response
        let password = options.password.as_deref().unwrap_or_default();
        let auth_response = match handshake.auth_plugin_name.as_str() {
            "mysql_native_password" => mysql_native_auth(password, &handshake.auth_plugin_data),
            "caching_sha2_password" => caching_sha2_auth(password, &handshake.auth_plugin_data),
            plugin => {
                return Err(MySqlError::UnsupportedAuthPlugin(plugin.to_string()));
            }
        };

        buf.write_lenenc_int(auth_response.len() as u64);
        buf.write_bytes(&auth_response);

        // Database
        if let Some(ref db) = options.database {
            buf.write_null_terminated(db);
        }

        // Auth plugin name
        buf.write_null_terminated(&handshake.auth_plugin_name);

        let packet = buf.build_packet();
        self.write_all(&packet.bytes).await?;
        self.inner.sequence = packet.next_sequence;

        Ok(())
    }

    #[inline]
    const fn negotiated_capabilities(server_caps: u32, client_caps: u32) -> u32 {
        server_caps & client_caps
    }

    /// Handle authentication response from server.
    async fn handle_auth_response(
        &mut self,
        options: &MySqlConnectOptions,
        handshake: &Handshake,
    ) -> Result<(), MySqlError> {
        let (data, seq) = self.read_packet().await?;
        self.inner.sequence = seq.wrapping_add(1);

        if data.is_empty() {
            return Err(MySqlError::Protocol("empty auth response".to_string()));
        }

        match data[0] {
            0x00 => {
                // OK packet - authentication successful
                Ok(())
            }
            0xFF => {
                // ERR packet
                Err(Self::parse_error(&data))
            }
            0xFE => {
                // Auth switch request
                self.handle_auth_switch(&data[1..], options, handshake)
                    .await
            }
            0x01 => {
                // More data needed (caching_sha2_password)
                self.handle_caching_sha2_more_data(&data[1..], options, handshake)
                    .await
            }
            _ => Err(MySqlError::Protocol(format!(
                "unexpected auth response: {:02x}",
                data[0]
            ))),
        }
    }

    /// Handle auth switch request.
    async fn handle_auth_switch(
        &mut self,
        data: &[u8],
        options: &MySqlConnectOptions,
        _handshake: &Handshake,
    ) -> Result<(), MySqlError> {
        let mut reader = PacketReader::new(data);

        let plugin_name = reader.read_null_terminated()?;
        // Strip trailing null byte from auth data — the initial handshake
        // does this (line ~1163) but this path was missing it, causing
        // the XOR scramble to include an extra 0x00 and auth to always fail.
        let auth_data_raw = reader.read_rest();
        let auth_data = if auth_data_raw.last() == Some(&0) {
            &auth_data_raw[..auth_data_raw.len() - 1]
        } else {
            auth_data_raw
        };

        let password = options.password.as_deref().unwrap_or_default();
        let auth_response = match plugin_name {
            "mysql_native_password" => mysql_native_auth(password, auth_data),
            "caching_sha2_password" => caching_sha2_auth(password, auth_data),
            plugin => {
                return Err(MySqlError::UnsupportedAuthPlugin(plugin.to_string()));
            }
        };

        // Send auth response
        let mut buf = PacketBuffer::new();
        buf.set_sequence(self.inner.sequence);
        buf.write_bytes(&auth_response);
        let packet = buf.build_packet();
        self.write_all(&packet.bytes).await?;
        self.inner.sequence = packet.next_sequence;

        // Read final response
        let (data, seq) = self.read_packet().await?;
        self.inner.sequence = seq.wrapping_add(1);

        match data.first() {
            Some(0x00) => Ok(()),
            Some(0xFF) => Err(Self::parse_error(&data)),
            Some(0x01) if plugin_name == "caching_sha2_password" => {
                // Need to handle more data for caching_sha2_password
                self.handle_caching_sha2_final(&data[1..], options).await
            }
            _ => Err(MySqlError::Protocol(
                "unexpected auth switch response".to_string(),
            )),
        }
    }

    /// Handle caching_sha2_password more data request.
    async fn handle_caching_sha2_more_data(
        &mut self,
        data: &[u8],
        _options: &MySqlConnectOptions,
        _handshake: &Handshake,
    ) -> Result<(), MySqlError> {
        if data.first() == Some(&0x03) {
            // Fast auth success - wait for OK packet
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);
            match data.first() {
                Some(0x00) => Ok(()),
                Some(0xFF) => Err(Self::parse_error(&data)),
                _ => Err(MySqlError::Protocol(
                    "unexpected response after fast auth".to_string(),
                )),
            }
        } else if data.first() == Some(&0x04) {
            // Full authentication required - would need RSA key exchange
            // For now, this requires a secure connection
            Err(MySqlError::AuthenticationFailed(
                "caching_sha2_password full auth requires secure connection".to_string(),
            ))
        } else {
            Err(MySqlError::Protocol(format!(
                "unexpected caching_sha2 status: {:?}",
                data.first()
            )))
        }
    }

    /// Handle final step of caching_sha2_password auth.
    async fn handle_caching_sha2_final(
        &mut self,
        data: &[u8],
        _options: &MySqlConnectOptions,
    ) -> Result<(), MySqlError> {
        if data.first() == Some(&0x03) {
            // Fast auth success - wait for OK packet
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);
            match data.first() {
                Some(0x00) => Ok(()),
                Some(0xFF) => Err(Self::parse_error(&data)),
                _ => Err(MySqlError::Protocol(
                    "unexpected response after fast auth".to_string(),
                )),
            }
        } else {
            Err(MySqlError::AuthenticationFailed(
                "caching_sha2_password requires cached credentials or secure connection"
                    .to_string(),
            ))
        }
    }

    /// Execute a query.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    /// If a previous transaction was dropped without commit/rollback,
    /// an implicit ROLLBACK is issued first.
    pub async fn query(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<MySqlRow>, MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        if let Err(e) = self.drain_abandoned_transaction().await {
            return outcome_from_error(e);
        }

        // Send COM_QUERY
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_QUERY);
        buf.write_bytes(sql.as_bytes());
        let packet = buf.build_packet();

        // Mark closed before the protocol exchange so that if this future is
        // dropped mid-write or mid-read (e.g. by task cancellation), the
        // connection stays closed and prevents protocol desynchronization.
        self.inner.closed = true;

        if let Err(e) = self.write_all(&packet.bytes).await {
            return outcome_from_error(e);
        }
        self.inner.sequence = packet.next_sequence;

        // Read response
        let (data, seq) = match self.read_packet().await {
            Ok(p) => p,
            Err(e) => return outcome_from_error(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        if data.is_empty() {
            return Outcome::Err(MySqlError::Protocol("empty query response".to_string()));
        }

        match data[0] {
            0x00 => {
                match Self::parse_ok_packet(&data) {
                    Ok(ok) => {
                        self.inner.status_flags = ok.status_flags;
                        self.inner.closed = false;
                        Outcome::Ok(Vec::new())
                    }
                    Err(e) => {
                        // The full packet was received, so protocol sync is
                        // preserved even if the OK payload is malformed.
                        self.inner.closed = false;
                        Outcome::Err(e)
                    }
                }
            }
            0xFF => {
                // ERR packet
                let err = Self::parse_error(&data);
                if matches!(&err, MySqlError::Server { .. }) {
                    self.inner.closed = false;
                }
                Outcome::Err(err)
            }
            _ => {
                // Result set
                match self.read_result_set(cx, &data).await {
                    Ok(rows) => {
                        self.inner.closed = false;
                        Outcome::Ok(rows)
                    }
                    Err(MySqlError::Cancelled(r)) => Outcome::Cancelled(r),
                    Err(e) => outcome_from_error(e),
                }
            }
        }
    }

    /// Read a complete result set.
    ///
    /// Enforces `max_result_rows` to prevent unbounded memory growth.
    async fn read_result_set(
        &mut self,
        cx: &Cx,
        first_packet: &[u8],
    ) -> Result<Vec<MySqlRow>, MySqlError> {
        let mut reader = PacketReader::new(first_packet);
        let column_count_raw = reader.read_lenenc_int()?;
        if column_count_raw > MAX_COLUMN_COUNT {
            return Err(MySqlError::Protocol(format!(
                "column count {column_count_raw} exceeds maximum {MAX_COLUMN_COUNT}"
            )));
        }
        let column_count = column_count_raw as usize;
        let deprecate_eof = self.inner.capabilities & capability::CLIENT_DEPRECATE_EOF != 0;
        let max_rows = self.inner.max_result_rows;

        if column_count == 0 {
            return Ok(Vec::new());
        }

        let (columns, indices) = self.read_result_set_columns(column_count).await?;

        // Read rows
        let mut rows = Vec::new();

        loop {
            if cx.checkpoint().is_err() {
                // The server is still streaming row packets. Mark the
                // connection as closed to prevent protocol desync on reuse
                // (same as the max-rows guard below).
                self.inner.closed = true;
                return Err(MySqlError::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| crate::types::CancelReason::user("cancelled")),
                ));
            }
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);

            if data.is_empty() {
                continue;
            }

            match data[0] {
                0xFF => {
                    // ERR packet
                    return Err(Self::parse_error(&data));
                }
                _ => {
                    if let Some(values) =
                        Self::parse_data_row_or_terminator(&data, &columns, deprecate_eof)?
                    {
                        self.push_result_row(&mut rows, &columns, &indices, values, max_rows)?;
                    } else {
                        self.inner.status_flags =
                            Self::parse_result_set_terminator_status_flags(&data)?;
                        break;
                    }
                }
            }
        }

        Ok(rows)
    }

    /// Read a complete binary-protocol result set from COM_STMT_EXECUTE.
    ///
    /// Enforces `max_result_rows` to prevent unbounded memory growth.
    async fn read_binary_result_set(
        &mut self,
        cx: &Cx,
        first_packet: &[u8],
    ) -> Result<Vec<MySqlRow>, MySqlError> {
        let mut reader = PacketReader::new(first_packet);
        let column_count_raw = reader.read_lenenc_int()?;
        if column_count_raw > MAX_COLUMN_COUNT {
            return Err(MySqlError::Protocol(format!(
                "column count {column_count_raw} exceeds maximum {MAX_COLUMN_COUNT}"
            )));
        }
        let column_count = column_count_raw as usize;
        let deprecate_eof = self.inner.capabilities & capability::CLIENT_DEPRECATE_EOF != 0;
        let max_rows = self.inner.max_result_rows;

        if column_count == 0 {
            return Ok(Vec::new());
        }

        let (columns, indices) = self.read_result_set_columns(column_count).await?;
        let mut rows = Vec::new();

        loop {
            if cx.checkpoint().is_err() {
                self.inner.closed = true;
                return Err(MySqlError::Cancelled(
                    cx.cancel_reason()
                        .unwrap_or_else(|| crate::types::CancelReason::user("cancelled")),
                ));
            }

            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);

            if data.is_empty() {
                continue;
            }

            match data[0] {
                0xFF => return Err(Self::parse_error(&data)),
                _ => {
                    if let Some(values) =
                        Self::parse_binary_row_or_terminator(&data, &columns, deprecate_eof)?
                    {
                        self.push_result_row(&mut rows, &columns, &indices, values, max_rows)?;
                    } else {
                        self.inner.status_flags =
                            Self::parse_result_set_terminator_status_flags(&data)?;
                        break;
                    }
                }
            }
        }

        Ok(rows)
    }

    async fn read_result_set_columns(
        &mut self,
        column_count: usize,
    ) -> Result<(Arc<Vec<MySqlColumn>>, Arc<BTreeMap<String, usize>>), MySqlError> {
        let mut columns = Vec::with_capacity(column_count);
        let mut indices = BTreeMap::new();

        for i in 0..column_count {
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);

            let column = Self::parse_column_definition(&data)?;
            indices.entry(column.name.clone()).or_insert(i);
            columns.push(column);
        }

        // In CLIENT_DEPRECATE_EOF mode, there is no metadata terminator after
        // column definitions; rows start immediately and the final terminator
        // is an OK packet. Without DEPRECATE_EOF we still expect EOF here.
        if Self::expects_metadata_eof(self.inner.capabilities) {
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);
            if !Self::is_eof_packet(&data) {
                return Err(MySqlError::Protocol(
                    "expected EOF after columns".to_string(),
                ));
            }
            self.inner.status_flags = Self::parse_eof_packet_status_flags(&data)?;
        }

        Ok((Arc::new(columns), Arc::new(indices)))
    }

    fn parse_column_definition(data: &[u8]) -> Result<MySqlColumn, MySqlError> {
        let mut reader = PacketReader::new(data);

        let catalog = reader.read_lenenc_str()?.to_string();
        let schema = reader.read_lenenc_str()?.to_string();
        let table = reader.read_lenenc_str()?.to_string();
        let org_table = reader.read_lenenc_str()?.to_string();
        let name = reader.read_lenenc_str()?.to_string();
        let org_name = reader.read_lenenc_str()?.to_string();

        // Fixed fields (0x0C length indicator)
        let _ = reader.read_lenenc_int()?;
        let charset = reader.read_u16_le()?;
        let length = reader.read_u32_le()?;
        let column_type = reader.read_byte()?;
        let flags = reader.read_u16_le()?;
        let decimals = reader.read_byte()?;

        Ok(MySqlColumn {
            catalog,
            schema,
            table,
            org_table,
            name,
            org_name,
            charset,
            length,
            column_type,
            flags,
            decimals,
        })
    }

    fn push_result_row(
        &mut self,
        rows: &mut Vec<MySqlRow>,
        columns: &Arc<Vec<MySqlColumn>>,
        indices: &Arc<BTreeMap<String, usize>>,
        values: Vec<MySqlValue>,
        max_rows: usize,
    ) -> Result<(), MySqlError> {
        if rows.len() >= max_rows {
            // The server is still sending row packets that we cannot drain
            // synchronously. Mark the connection as closed to prevent
            // protocol desync on reuse.
            self.inner.closed = true;
            return Err(MySqlError::Protocol(format!(
                "result set exceeds maximum row limit ({max_rows})"
            )));
        }

        rows.push(MySqlRow {
            columns: Arc::clone(columns),
            column_indices: Arc::clone(indices),
            values,
        });
        Ok(())
    }

    /// Parse a text protocol row.
    fn parse_text_row(data: &[u8], columns: &[MySqlColumn]) -> Result<Vec<MySqlValue>, MySqlError> {
        let mut reader = PacketReader::new(data);
        let mut values = Vec::with_capacity(columns.len());

        for col in columns {
            // Check for NULL (0xFB)
            if reader.remaining() > 0 && data[reader.pos] == 0xFB {
                reader.pos += 1;
                values.push(MySqlValue::Null);
                continue;
            }

            let raw = reader.read_lenenc_bytes()?;
            let value = Self::parse_text_value(raw, col)?;
            values.push(value);
        }

        if reader.remaining() != 0 {
            return Err(MySqlError::Protocol(format!(
                "row packet has {} trailing bytes",
                reader.remaining()
            )));
        }

        Ok(values)
    }

    fn parse_binary_row_or_terminator(
        data: &[u8],
        columns: &[MySqlColumn],
        deprecate_eof: bool,
    ) -> Result<Option<Vec<MySqlValue>>, MySqlError> {
        if Self::is_eof_packet(data) {
            return Ok(None);
        }

        if data.first() == Some(&0x00) {
            return Self::parse_binary_row(data, columns).map(Some);
        }

        if deprecate_eof && data.first() == Some(&0xFE) && Self::is_deprecate_eof_ok_packet(data) {
            return Ok(None);
        }

        Err(MySqlError::Protocol(
            "unexpected binary result-set row packet".to_string(),
        ))
    }

    fn parse_binary_row(
        data: &[u8],
        columns: &[MySqlColumn],
    ) -> Result<Vec<MySqlValue>, MySqlError> {
        let mut reader = PacketReader::new(data);
        let header = reader.read_byte()?;
        if header != 0x00 {
            return Err(MySqlError::Protocol(
                "binary row must start with 0x00".to_string(),
            ));
        }

        let null_bitmap_len = (columns.len() + 7 + 2) / 8;
        let null_bitmap = reader.read_bytes(null_bitmap_len)?;
        let mut values = Vec::with_capacity(columns.len());

        for (idx, col) in columns.iter().enumerate() {
            let bit_idx = idx + 2;
            if (null_bitmap[bit_idx / 8] & (1 << (bit_idx % 8))) != 0 {
                values.push(MySqlValue::Null);
                continue;
            }

            values.push(Self::parse_binary_value(&mut reader, col)?);
        }

        if reader.remaining() != 0 {
            return Err(MySqlError::Protocol(format!(
                "binary row packet has {} trailing bytes",
                reader.remaining()
            )));
        }

        Ok(values)
    }

    fn parse_binary_value(
        reader: &mut PacketReader<'_>,
        col: &MySqlColumn,
    ) -> Result<MySqlValue, MySqlError> {
        Ok(match col.column_type {
            column_type::MYSQL_TYPE_TINY => {
                MySqlValue::Tiny(i8::from_le_bytes([reader.read_byte()?]))
            }
            column_type::MYSQL_TYPE_SHORT | column_type::MYSQL_TYPE_YEAR => {
                MySqlValue::Short(i16::from_le_bytes(reader.read_u16_le()?.to_le_bytes()))
            }
            column_type::MYSQL_TYPE_LONG | column_type::MYSQL_TYPE_INT24 => {
                MySqlValue::Long(i32::from_le_bytes(reader.read_u32_le()?.to_le_bytes()))
            }
            column_type::MYSQL_TYPE_LONGLONG => {
                MySqlValue::LongLong(i64::from_le_bytes(reader.read_u64_le()?.to_le_bytes()))
            }
            column_type::MYSQL_TYPE_FLOAT => {
                MySqlValue::Float(f32::from_bits(reader.read_u32_le()?))
            }
            column_type::MYSQL_TYPE_DOUBLE => {
                MySqlValue::Double(f64::from_bits(reader.read_u64_le()?))
            }
            column_type::MYSQL_TYPE_DATE
            | column_type::MYSQL_TYPE_DATETIME
            | column_type::MYSQL_TYPE_TIMESTAMP => {
                Self::parse_binary_datetime_value(reader, col.column_type)?
            }
            column_type::MYSQL_TYPE_TIME => Self::parse_binary_time_value(reader)?,
            column_type::MYSQL_TYPE_NULL => MySqlValue::Null,
            column_type::MYSQL_TYPE_VARCHAR
            | column_type::MYSQL_TYPE_VAR_STRING
            | column_type::MYSQL_TYPE_STRING
            | column_type::MYSQL_TYPE_TINY_BLOB
            | column_type::MYSQL_TYPE_MEDIUM_BLOB
            | column_type::MYSQL_TYPE_LONG_BLOB
            | column_type::MYSQL_TYPE_BLOB => Self::parse_binary_string_value(reader, col)?,
            column_type::MYSQL_TYPE_GEOMETRY | column_type::MYSQL_TYPE_BIT => {
                MySqlValue::Bytes(reader.read_lenenc_bytes()?.to_vec())
            }
            _ => {
                let raw = reader.read_lenenc_bytes()?;
                match std::str::from_utf8(raw) {
                    Ok(s) => MySqlValue::Text(s.to_string()),
                    Err(_) => MySqlValue::Bytes(raw.to_vec()),
                }
            }
        })
    }

    fn parse_binary_string_value(
        reader: &mut PacketReader<'_>,
        col: &MySqlColumn,
    ) -> Result<MySqlValue, MySqlError> {
        let raw = reader.read_lenenc_bytes()?;
        Self::parse_string_or_bytes_value(raw, col)
    }

    fn parse_binary_datetime_value(
        reader: &mut PacketReader<'_>,
        column_type: u8,
    ) -> Result<MySqlValue, MySqlError> {
        let len = usize::from(reader.read_byte()?);
        let data = reader.read_bytes(len)?;
        let mut value_reader = PacketReader::new(data);

        if len == 0 {
            return Ok(if column_type == column_type::MYSQL_TYPE_DATE {
                MySqlValue::Text("0000-00-00".to_string())
            } else {
                MySqlValue::Text("0000-00-00 00:00:00".to_string())
            });
        }

        if len != 4 && len != 7 && len != 11 {
            return Err(MySqlError::Protocol(format!(
                "invalid binary datetime length {len}"
            )));
        }

        let year = value_reader.read_u16_le()?;
        let month = value_reader.read_byte()?;
        let day = value_reader.read_byte()?;
        if column_type == column_type::MYSQL_TYPE_DATE || len == 4 {
            return Ok(MySqlValue::Text(format!("{year:04}-{month:02}-{day:02}")));
        }

        let hour = value_reader.read_byte()?;
        let minute = value_reader.read_byte()?;
        let second = value_reader.read_byte()?;
        if len == 7 {
            return Ok(MySqlValue::Text(format!(
                "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
            )));
        }

        let micros = value_reader.read_u32_le()?;
        Ok(MySqlValue::Text(format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{micros:06}"
        )))
    }

    fn parse_binary_time_value(reader: &mut PacketReader<'_>) -> Result<MySqlValue, MySqlError> {
        let len = usize::from(reader.read_byte()?);
        let data = reader.read_bytes(len)?;
        let mut value_reader = PacketReader::new(data);

        if len == 0 {
            return Ok(MySqlValue::Text("00:00:00".to_string()));
        }

        if len != 8 && len != 12 {
            return Err(MySqlError::Protocol(format!(
                "invalid binary time length {len}"
            )));
        }

        let negative = value_reader.read_byte()? != 0;
        let days = value_reader.read_u32_le()?;
        let hour = value_reader.read_byte()?;
        let minute = value_reader.read_byte()?;
        let second = value_reader.read_byte()?;
        let sign = if negative { "-" } else { "" };
        if len == 8 {
            return Ok(MySqlValue::Text(format!(
                "{sign}{days} {hour:02}:{minute:02}:{second:02}"
            )));
        }

        let micros = value_reader.read_u32_le()?;
        Ok(MySqlValue::Text(format!(
            "{sign}{days} {hour:02}:{minute:02}:{second:02}.{micros:06}"
        )))
    }

    #[inline]
    fn is_eof_packet(data: &[u8]) -> bool {
        data.first() == Some(&0xFE) && data.len() < 9
    }

    fn parse_ok_packet(data: &[u8]) -> Result<OkPacket, MySqlError> {
        if data.first() != Some(&0x00) {
            return Err(MySqlError::Protocol("not an OK packet".to_string()));
        }

        let mut reader = PacketReader::new(&data[1..]);
        let affected_rows = reader.read_lenenc_int()?;
        let _last_insert_id = reader.read_lenenc_int()?;
        let status_flags = reader.read_u16_le()?;
        let _warning_count = reader.read_u16_le()?;

        Ok(OkPacket {
            affected_rows,
            status_flags,
        })
    }

    fn parse_eof_packet_status_flags(data: &[u8]) -> Result<u16, MySqlError> {
        if !Self::is_eof_packet(data) {
            return Err(MySqlError::Protocol("not an EOF packet".to_string()));
        }

        let mut reader = PacketReader::new(&data[1..]);
        let _warning_count = reader.read_u16_le()?;
        reader.read_u16_le()
    }

    fn parse_result_set_terminator_status_flags(data: &[u8]) -> Result<u16, MySqlError> {
        if Self::is_eof_packet(data) {
            return Self::parse_eof_packet_status_flags(data);
        }

        match data.first() {
            Some(0x00 | 0xFE) => Self::parse_ok_packet_like_status_flags(data),
            _ => Err(MySqlError::Protocol(
                "not a result-set terminator packet".to_string(),
            )),
        }
    }

    fn parse_ok_packet_like_status_flags(data: &[u8]) -> Result<u16, MySqlError> {
        match data.first() {
            Some(0x00 | 0xFE) => {}
            _ => return Err(MySqlError::Protocol("not an OK-like packet".to_string())),
        }

        let mut reader = PacketReader::new(&data[1..]);
        let _affected_rows = reader.read_lenenc_int()?;
        let _last_insert_id = reader.read_lenenc_int()?;
        reader.read_u16_le()
    }

    #[inline]
    const fn expects_metadata_eof(capabilities: u32) -> bool {
        capabilities & capability::CLIENT_DEPRECATE_EOF == 0
    }

    #[inline]
    fn is_result_set_ok_packet(data: &[u8]) -> bool {
        if data.first() != Some(&0x00) {
            return false;
        }

        let mut reader = PacketReader::new(&data[1..]);
        reader.read_lenenc_int().is_ok()
            && reader.read_lenenc_int().is_ok()
            && reader.read_u16_le().is_ok()
            && reader.read_u16_le().is_ok()
    }

    /// Recognises a 0xFE-header OK packet used as a result-set terminator
    /// in CLIENT_DEPRECATE_EOF mode.  Same structure as a regular OK
    /// packet but with the legacy EOF header byte.
    #[inline]
    fn is_deprecate_eof_ok_packet(data: &[u8]) -> bool {
        if data.first() != Some(&0xFE) {
            return false;
        }
        // Same structure check as is_result_set_ok_packet but for 0xFE header.
        let mut reader = PacketReader::new(&data[1..]);
        reader.read_lenenc_int().is_ok()
            && reader.read_lenenc_int().is_ok()
            && reader.read_u16_le().is_ok()
            && reader.read_u16_le().is_ok()
    }

    /// Parse an incoming row packet or classify it as a result-set terminator.
    ///
    /// In `CLIENT_DEPRECATE_EOF` mode, packets starting with `0x00` are
    /// ambiguous: they may be a valid data row (first column is empty string)
    /// or an OK terminator. We parse as a row first and only classify as
    /// terminator if row parsing fails and the packet has OK structure.
    fn parse_data_row_or_terminator(
        data: &[u8],
        columns: &[MySqlColumn],
        deprecate_eof: bool,
    ) -> Result<Option<Vec<MySqlValue>>, MySqlError> {
        if Self::is_eof_packet(data) {
            return Ok(None);
        }

        // In CLIENT_DEPRECATE_EOF mode the server sends an OK packet
        // instead of EOF to terminate the result set.  That OK may use
        // either a 0x00 or 0xFE header byte.  The 0xFE case with a
        // non-empty info string (len ≥ 9) passes through is_eof_packet,
        // so we must check for it explicitly here.
        if deprecate_eof && matches!(data.first(), Some(&0x00 | &0xFE)) {
            return match Self::parse_text_row(data, columns) {
                Ok(values) => Ok(Some(values)),
                Err(row_err) => {
                    if Self::is_result_set_ok_packet(data) || Self::is_deprecate_eof_ok_packet(data)
                    {
                        Ok(None)
                    } else {
                        Err(row_err)
                    }
                }
            };
        }

        Self::parse_text_row(data, columns).map(Some)
    }

    /// Parse a text format value.
    fn parse_text_value(data: &[u8], col: &MySqlColumn) -> Result<MySqlValue, MySqlError> {
        let text = match Self::parse_string_or_bytes_value(data, col)? {
            MySqlValue::Bytes(bytes) => return Ok(MySqlValue::Bytes(bytes)),
            MySqlValue::Text(text) => text,
            value => {
                return Err(MySqlError::Protocol(format!(
                    "unexpected string parser value: {value:?}"
                )));
            }
        };

        let parse_err = |typ: &str| {
            MySqlError::Protocol(format!("cannot parse {typ} from text value: {text:?}"))
        };
        Ok(match col.column_type {
            column_type::MYSQL_TYPE_TINY => {
                MySqlValue::Tiny(text.parse().map_err(|_| parse_err("TINY"))?)
            }
            column_type::MYSQL_TYPE_SHORT | column_type::MYSQL_TYPE_YEAR => {
                MySqlValue::Short(text.parse().map_err(|_| parse_err("SHORT"))?)
            }
            column_type::MYSQL_TYPE_LONG | column_type::MYSQL_TYPE_INT24 => {
                MySqlValue::Long(text.parse().map_err(|_| parse_err("LONG"))?)
            }
            column_type::MYSQL_TYPE_LONGLONG => {
                MySqlValue::LongLong(text.parse().map_err(|_| parse_err("LONGLONG"))?)
            }
            column_type::MYSQL_TYPE_FLOAT => {
                MySqlValue::Float(text.parse().map_err(|_| parse_err("FLOAT"))?)
            }
            column_type::MYSQL_TYPE_DOUBLE
            | column_type::MYSQL_TYPE_DECIMAL
            | column_type::MYSQL_TYPE_NEWDECIMAL => {
                MySqlValue::Double(text.parse().map_err(|_| parse_err("DOUBLE"))?)
            }
            _ => MySqlValue::Text(text),
        })
    }

    fn parse_string_or_bytes_value(
        data: &[u8],
        col: &MySqlColumn,
    ) -> Result<MySqlValue, MySqlError> {
        if Self::is_binary_payload_column(col) {
            return Ok(MySqlValue::Bytes(data.to_vec()));
        }

        let text = std::str::from_utf8(data)
            .map_err(|e| MySqlError::Protocol(format!("invalid UTF-8: {e}")))?;
        Ok(MySqlValue::Text(text.to_string()))
    }

    #[inline]
    fn is_binary_payload_column(col: &MySqlColumn) -> bool {
        matches!(
            col.column_type,
            column_type::MYSQL_TYPE_GEOMETRY | column_type::MYSQL_TYPE_BIT
        ) || (col.charset == MYSQL_BINARY_CHARSET_ID
            && Self::is_string_like_column_type(col.column_type))
    }

    #[inline]
    const fn is_string_like_column_type(column_type: u8) -> bool {
        matches!(
            column_type,
            column_type::MYSQL_TYPE_VARCHAR
                | column_type::MYSQL_TYPE_VAR_STRING
                | column_type::MYSQL_TYPE_STRING
                | column_type::MYSQL_TYPE_TINY_BLOB
                | column_type::MYSQL_TYPE_MEDIUM_BLOB
                | column_type::MYSQL_TYPE_LONG_BLOB
                | column_type::MYSQL_TYPE_BLOB
        )
    }

    /// Execute a command (INSERT, UPDATE, DELETE) and return affected rows.
    ///
    /// If a previous transaction was dropped without commit/rollback,
    /// an implicit ROLLBACK is issued first.
    pub async fn execute(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        if let Err(e) = self.drain_abandoned_transaction().await {
            return outcome_from_error(e);
        }

        // Send COM_QUERY
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_QUERY);
        buf.write_bytes(sql.as_bytes());
        let packet = buf.build_packet();

        // Mark closed before the protocol exchange so that if this future is
        // dropped mid-write or mid-read (e.g. by task cancellation), the
        // connection stays closed and prevents protocol desynchronization.
        self.inner.closed = true;

        if let Err(e) = self.write_all(&packet.bytes).await {
            return outcome_from_error(e);
        }
        self.inner.sequence = packet.next_sequence;

        // Read response
        let (data, seq) = match self.read_packet().await {
            Ok(p) => p,
            Err(e) => return outcome_from_error(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        if data.is_empty() {
            return Outcome::Err(MySqlError::Protocol("empty execute response".to_string()));
        }

        match data[0] {
            0x00 => {
                // OK packet
                match Self::parse_ok_packet(&data) {
                    Ok(ok) => {
                        self.inner.status_flags = ok.status_flags;
                        self.inner.closed = false;
                        Outcome::Ok(ok.affected_rows)
                    }
                    Err(e) => {
                        // OK packet was fully received; connection protocol
                        // state is clean even though the payload is malformed.
                        self.inner.closed = false;
                        Outcome::Err(e)
                    }
                }
            }
            0xFF => {
                // ERR packet
                let err = Self::parse_error(&data);
                if matches!(&err, MySqlError::Server { .. }) {
                    self.inner.closed = false;
                }
                Outcome::Err(err)
            }
            _ => {
                // Result set - consume it and return 0 affected rows
                match self.read_result_set(cx, &data).await {
                    Ok(_) => {
                        self.inner.closed = false;
                        Outcome::Ok(0)
                    }
                    Err(MySqlError::Cancelled(r)) => Outcome::Cancelled(r),
                    Err(e) => outcome_from_error(e),
                }
            }
        }
    }

    /// Begin a transaction.
    pub async fn begin(&mut self, cx: &Cx) -> Outcome<MySqlTransaction<'_>, MySqlError> {
        match self.execute(cx, "START TRANSACTION").await {
            Outcome::Ok(_) => Outcome::Ok(MySqlTransaction {
                conn: self,
                finished: false,
            }),
            Outcome::Err(e) => outcome_from_error(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Ping the server.
    pub async fn ping(&mut self, cx: &Cx) -> Outcome<(), MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_PING);
        let packet = buf.build_packet();

        self.inner.closed = true;

        if let Err(e) = self.write_all(&packet.bytes).await {
            return outcome_from_error(e);
        }
        self.inner.sequence = packet.next_sequence;

        let (data, seq) = match self.read_packet().await {
            Ok(p) => p,
            Err(e) => return outcome_from_error(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        match data.first() {
            Some(0x00) => match Self::parse_ok_packet(&data) {
                Ok(ok) => {
                    self.inner.status_flags = ok.status_flags;
                    self.inner.closed = false;
                    Outcome::Ok(())
                }
                Err(e) => {
                    self.inner.closed = false;
                    Outcome::Err(e)
                }
            },
            Some(0xFF) => {
                let err = Self::parse_error(&data);
                if matches!(&err, MySqlError::Server { .. }) {
                    self.inner.closed = false;
                }
                Outcome::Err(err)
            }
            _ => Outcome::Err(MySqlError::Protocol("unexpected ping response".to_string())),
        }
    }

    /// Get the server version string.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.inner.server_version
    }

    /// Get the connection ID.
    #[must_use]
    pub fn connection_id(&self) -> u32 {
        self.inner.connection_id
    }

    /// Check if the connection is in a transaction.
    #[must_use]
    pub fn in_transaction(&self) -> bool {
        self.inner.status_flags & 0x0001 != 0 // SERVER_STATUS_IN_TRANS
    }

    /// Close the connection.
    pub async fn close(&mut self) -> Result<(), MySqlError> {
        if self.inner.closed {
            return Ok(());
        }

        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_QUIT);
        let packet = buf.build_packet();
        let _ = self.write_all(&packet.bytes).await;

        let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
        self.inner.closed = true;
        Ok(())
    }

    /// Prepare a statement for later execution.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let stmt = conn.prepare(cx, "SELECT id FROM users WHERE active = ?").await?;
    /// let rows1 = conn.query_prepared(cx, &stmt, &[&true]).await?;
    /// let rows2 = conn.query_prepared(cx, &stmt, &[&false]).await?;
    /// ```
    pub async fn prepare(&mut self, cx: &Cx, sql: &str) -> Outcome<MySqlStatement, MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        if let Err(e) = self.drain_abandoned_transaction().await {
            return outcome_from_error(e);
        }

        // Build COM_STMT_PREPARE packet
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_STMT_PREPARE);
        buf.write_bytes(sql.as_bytes());
        let packet = buf.build_packet();

        // Mark closed before the protocol exchange to prevent desync on cancel
        self.inner.closed = true;

        if let Err(e) = self.write_all(&packet.bytes).await {
            return outcome_from_error(e);
        }
        self.inner.sequence = packet.next_sequence;

        // Read prepare response
        let (response_data, seq) = match self.read_packet().await {
            Ok((data, seq)) => (data, seq),
            Err(e) => return outcome_from_error(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        if response_data.is_empty() {
            return Outcome::Err(MySqlError::InvalidPacket("Empty prepare response".into()));
        }

        // Check for error response
        if response_data[0] == 0xff {
            let err = Self::parse_error(&response_data);
            if matches!(&err, MySqlError::Server { .. }) {
                self.inner.closed = false;
            }
            return Outcome::Err(err);
        }

        // Parse prepare OK response
        if response_data[0] != 0x00 {
            return Outcome::Err(MySqlError::InvalidPacket("Invalid prepare response".into()));
        }

        if response_data.len() < 12 {
            return Outcome::Err(MySqlError::InvalidPacket(
                "Prepare response too short".into(),
            ));
        }

        let parsed_header = (|| {
            let mut reader = PacketReader::new(&response_data[1..]);
            let statement_id = reader.read_u32_le()?;
            let column_count = reader.read_u16_le()?;
            let param_count = reader.read_u16_le()?;
            let _reserved = reader.read_byte()?; // Should be 0x00
            let _warning_count = reader.read_u16_le()?;
            Ok((statement_id, column_count, param_count))
        })();
        let (statement_id, column_count, param_count) = match parsed_header {
            Ok(header) => header,
            Err(e) => {
                return outcome_from_error(e);
            }
        };

        // Read parameter metadata if any
        let mut params = Vec::new();
        if param_count > 0 {
            for _ in 0..param_count {
                let (_param_data, seq) = match self.read_packet().await {
                    Ok((data, seq)) => (data, seq),
                    Err(e) => return outcome_from_error(e),
                };
                self.inner.sequence = seq.wrapping_add(1);

                // Parse column definition packet - simplified for now
                params.push(MySqlColumn::new_simple_string("param"));
            }

            // Read EOF packet after parameters
            let (_eof_data, seq) = match self.read_packet().await {
                Ok((data, seq)) => (data, seq),
                Err(e) => return outcome_from_error(e),
            };
            self.inner.sequence = seq.wrapping_add(1);
        }

        // Read column metadata if any
        let mut columns = Vec::new();
        if column_count > 0 {
            for _ in 0..column_count {
                let (_col_data, seq) = match self.read_packet().await {
                    Ok((data, seq)) => (data, seq),
                    Err(e) => return outcome_from_error(e),
                };
                self.inner.sequence = seq.wrapping_add(1);

                // Parse column definition packet - simplified for now
                columns.push(MySqlColumn::new_simple_string("column"));
            }

            // Read EOF packet after columns
            let (_eof_data, seq) = match self.read_packet().await {
                Ok((data, seq)) => (data, seq),
                Err(e) => return outcome_from_error(e),
            };
            self.inner.sequence = seq.wrapping_add(1);
        }

        self.inner.closed = false;

        let stmt = MySqlStatement {
            statement_id,
            param_count,
            column_count,
            params,
            columns,
        };

        Outcome::Ok(stmt)
    }

    /// Execute a prepared statement that returns rows.
    pub async fn query_prepared(
        &mut self,
        cx: &Cx,
        stmt: &MySqlStatement,
        params: &[&dyn ToSql],
    ) -> Outcome<Vec<MySqlRow>, MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        if params.len() != stmt.param_count as usize {
            return Outcome::Err(MySqlError::InvalidParameter(format!(
                "Expected {} parameters, got {}",
                stmt.param_count,
                params.len()
            )));
        }

        if let Err(e) = self.drain_abandoned_transaction().await {
            return outcome_from_error(e);
        }

        // Build COM_STMT_EXECUTE packet
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_STMT_EXECUTE);
        buf.write_u32_le(stmt.statement_id);
        buf.write_byte(0x00); // flags
        buf.write_u32_le(1); // iteration count

        if let Err(e) = write_stmt_execute_params(&mut buf, params) {
            return outcome_from_error(e);
        }

        let packet = buf.build_packet();

        // Mark closed before the protocol exchange
        self.inner.closed = true;

        if let Err(e) = self.write_all(&packet.bytes).await {
            return outcome_from_error(e);
        }
        self.inner.sequence = packet.next_sequence;

        // Read response
        let (response_data, seq) = match self.read_packet().await {
            Ok((data, seq)) => (data, seq),
            Err(e) => return outcome_from_error(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        if response_data.is_empty() {
            return Outcome::Err(MySqlError::InvalidPacket(
                "Empty prepared query response".into(),
            ));
        }

        match response_data[0] {
            0x00 => match Self::parse_ok_packet(&response_data) {
                Ok(ok_packet) => {
                    self.inner.status_flags = ok_packet.status_flags;
                    self.inner.closed = false;
                    Outcome::Ok(Vec::new())
                }
                Err(e) => {
                    self.inner.closed = false;
                    outcome_from_error(e)
                }
            },
            0xFF => {
                let err = Self::parse_error(&response_data);
                if matches!(&err, MySqlError::Server { .. }) {
                    self.inner.closed = false;
                }
                Outcome::Err(err)
            }
            _ => match self.read_binary_result_set(cx, &response_data).await {
                Ok(rows) => {
                    self.inner.closed = false;
                    Outcome::Ok(rows)
                }
                Err(MySqlError::Cancelled(reason)) => Outcome::Cancelled(reason),
                Err(e) => outcome_from_error(e),
            },
        }
    }

    /// Execute a prepared statement that does not return rows.
    pub async fn execute_prepared(
        &mut self,
        cx: &Cx,
        stmt: &MySqlStatement,
        params: &[&dyn ToSql],
    ) -> Outcome<u64, MySqlError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        if params.len() != stmt.param_count as usize {
            return Outcome::Err(MySqlError::InvalidParameter(format!(
                "Expected {} parameters, got {}",
                stmt.param_count,
                params.len()
            )));
        }

        if let Err(e) = self.drain_abandoned_transaction().await {
            return outcome_from_error(e);
        }

        // Build COM_STMT_EXECUTE packet (same as query_prepared)
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_STMT_EXECUTE);
        buf.write_u32_le(stmt.statement_id);
        buf.write_byte(0x00); // flags
        buf.write_u32_le(1); // iteration count

        if let Err(e) = write_stmt_execute_params(&mut buf, params) {
            return outcome_from_error(e);
        }

        let packet = buf.build_packet();

        // Mark closed before the protocol exchange
        self.inner.closed = true;

        if let Err(e) = self.write_all(&packet.bytes).await {
            return outcome_from_error(e);
        }
        self.inner.sequence = packet.next_sequence;

        // Read response
        let (response_data, seq) = match self.read_packet().await {
            Ok((data, seq)) => (data, seq),
            Err(e) => return outcome_from_error(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        if response_data.is_empty() {
            return Outcome::Err(MySqlError::InvalidPacket("Empty execute response".into()));
        }

        // Check for error response
        if response_data[0] == 0xff {
            let err = Self::parse_error(&response_data);
            if matches!(&err, MySqlError::Server { .. }) {
                self.inner.closed = false;
            }
            return Outcome::Err(err);
        }

        // Parse OK packet
        if response_data[0] == 0x00 {
            let ok_packet = match Self::parse_ok_packet(&response_data) {
                Ok(packet) => packet,
                Err(e) => {
                    self.inner.closed = false;
                    return outcome_from_error(e);
                }
            };
            self.inner.status_flags = ok_packet.status_flags;
            self.inner.closed = false;
            return Outcome::Ok(ok_packet.affected_rows);
        }

        Outcome::Err(MySqlError::InvalidPacket(
            "Unexpected execute response".into(),
        ))
    }

    /// Set the maximum number of rows returned from a single result set.
    ///
    /// Default is 1,000,000. Set to `usize::MAX` to disable.
    pub fn set_max_result_rows(&mut self, max: usize) {
        self.inner.max_result_rows = max;
    }

    /// Returns the current max result row limit.
    #[must_use]
    pub fn max_result_rows(&self) -> usize {
        self.inner.max_result_rows
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// If a prior transaction was dropped without commit/rollback, issue
    /// an implicit ROLLBACK to return the connection to a clean state.
    async fn drain_abandoned_transaction(&mut self) -> Result<(), MySqlError> {
        if !self.inner.needs_rollback {
            return Ok(());
        }

        // Mark the connection closed while we perform the rollback.
        // If this future is dropped mid-flight (e.g. by timeout), the connection
        // will remain closed, preventing protocol desynchronization.
        self.inner.closed = true;

        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_QUERY);
        buf.write_bytes(b"ROLLBACK");
        let packet = buf.build_packet();

        if let Err(e) = self.write_all(&packet.bytes).await {
            let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
            return Err(e);
        }
        self.inner.sequence = packet.next_sequence;

        let (data, seq) = match self.read_packet().await {
            Ok(res) => res,
            Err(e) => {
                let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
                return Err(e);
            }
        };
        self.inner.sequence = seq.wrapping_add(1);

        match data.first() {
            Some(0x00) => {
                self.inner.needs_rollback = false;
                self.inner.status_flags = Self::parse_ok_packet(&data)?.status_flags;
                self.inner.closed = false;
                Ok(())
            }
            Some(0xFF) => {
                let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
                Err(Self::parse_error(&data))
            }
            _ => {
                let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
                Err(MySqlError::Protocol(
                    "unexpected response to implicit ROLLBACK".to_string(),
                ))
            }
        }
    }

    /// Write data to the stream.
    async fn write_all(&mut self, data: &[u8]) -> Result<(), MySqlError> {
        let mut pos = 0;
        while pos < data.len() {
            let written = std::future::poll_fn(|cx| {
                if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled",
                    )));
                }
                Pin::new(&mut self.inner.stream).poll_write(cx, &data[pos..])
            })
            .await
            .map_err(MySqlError::Io)?;

            if written == 0 {
                return Err(MySqlError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write data",
                )));
            }
            pos += written;
        }
        Ok(())
    }

    /// Read exactly `len` bytes.
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), MySqlError> {
        let mut pos = 0;
        while pos < buf.len() {
            let mut read_buf = ReadBuf::new(&mut buf[pos..]);
            std::future::poll_fn(|cx| {
                if crate::cx::Cx::current().is_some_and(|c| c.checkpoint().is_err()) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "cancelled",
                    )));
                }
                Pin::new(&mut self.inner.stream).poll_read(cx, &mut read_buf)
            })
            .await
            .map_err(MySqlError::Io)?;

            let n = read_buf.filled().len();
            if n == 0 {
                return Err(MySqlError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }
            pos += n;
        }
        Ok(())
    }

    /// Read a complete packet.
    async fn read_packet(&mut self) -> Result<(Vec<u8>, u8), MySqlError> {
        let mut expected_seq = self.inner.sequence;
        let mut last_seq;
        let mut data = Vec::new();

        loop {
            let mut header = [0u8; 4];
            self.read_exact(&mut header).await?;

            let (len, seq) = Self::decode_packet_header(header, expected_seq)?;
            last_seq = seq;

            if len > 0 {
                let start = data.len();
                let new_len = start.saturating_add(len as usize);
                if new_len > MAX_REASSEMBLED_PACKET_SIZE {
                    return Err(MySqlError::Protocol(format!(
                        "packet payload {new_len} exceeds maximum allowed {MAX_REASSEMBLED_PACKET_SIZE}"
                    )));
                }
                data.resize(new_len, 0);
                self.read_exact(&mut data[start..]).await?;
            }

            expected_seq = expected_seq.wrapping_add(1);

            if len < MAX_PACKET_SIZE {
                return Ok((data, last_seq));
            }
        }
    }

    #[inline]
    fn decode_packet_header(header: [u8; 4], expected_seq: u8) -> Result<(u32, u8), MySqlError> {
        let len = u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16);
        let seq = header[3];

        if seq != expected_seq {
            return Err(MySqlError::Protocol(format!(
                "packet sequence mismatch: expected {expected_seq}, got {seq}"
            )));
        }

        // Guard against oversized packets (max MySQL packet is 16 MB minus 1 byte)
        if len > MAX_PACKET_SIZE {
            return Err(MySqlError::Protocol(format!(
                "packet length {len} exceeds maximum allowed {MAX_PACKET_SIZE}"
            )));
        }

        Ok((len, seq))
    }

    /// Parse an error packet and return the error.
    fn parse_error(data: &[u8]) -> MySqlError {
        if data.is_empty() || data[0] != 0xFF {
            return MySqlError::Protocol("not an error packet".to_string());
        }

        let mut reader = PacketReader::new(&data[1..]);
        let code = match reader.read_u16_le() {
            Ok(c) => c,
            Err(e) => return e,
        };

        // Check for SQL state marker
        let sql_state = if reader.remaining() > 0 && data.get(reader.pos + 1) == Some(&b'#') {
            reader.pos += 1; // skip #
            reader.read_bytes(5).map_or_else(
                |_| "HY000".to_string(),
                |state| std::str::from_utf8(state).unwrap_or("HY000").to_string(),
            )
        } else {
            "HY000".to_string()
        };

        let message = std::str::from_utf8(reader.read_rest())
            .unwrap_or("unknown error")
            .to_string();

        MySqlError::Server {
            code,
            sql_state,
            message,
        }
    }
}

// ============================================================================
// Prepared Statements
// ============================================================================

/// Trait for types that can be bound to MySQL prepared statement parameters.
pub trait ToSql: Sync {
    /// Encode this value for MySQL protocol.
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError>;

    /// The MySQL type code for this value.
    fn mysql_type_code(&self) -> u8;

    /// Whether this parameter is SQL NULL and must be represented in the
    /// COM_STMT_EXECUTE NULL bitmap instead of the value stream.
    fn is_null(&self) -> bool {
        false
    }
}

impl ToSql for bool {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        Ok(vec![u8::from(*self)])
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_TINY
    }
}

impl ToSql for i32 {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        Ok(self.to_le_bytes().to_vec())
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_LONG
    }
}

impl ToSql for i64 {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        Ok(self.to_le_bytes().to_vec())
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_LONGLONG
    }
}

impl ToSql for f32 {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        Ok(self.to_le_bytes().to_vec())
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_FLOAT
    }
}

impl ToSql for f64 {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        Ok(self.to_le_bytes().to_vec())
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_DOUBLE
    }
}

impl ToSql for str {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        Ok(encode_lenenc_bytes(self.as_bytes()))
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_VAR_STRING
    }
}

impl ToSql for String {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        self.as_str().to_sql()
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_VAR_STRING
    }
}

impl ToSql for [u8] {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        Ok(encode_lenenc_bytes(self))
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_BLOB
    }
}

impl ToSql for Vec<u8> {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        self.as_slice().to_sql()
    }

    fn mysql_type_code(&self) -> u8 {
        mysql_type::MYSQL_TYPE_BLOB
    }
}

impl<T: ToSql> ToSql for Option<T> {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        match self {
            Some(value) => value.to_sql(),
            None => Ok(vec![]),
        }
    }

    fn mysql_type_code(&self) -> u8 {
        match self {
            Some(value) => value.mysql_type_code(),
            None => mysql_type::MYSQL_TYPE_NULL,
        }
    }

    fn is_null(&self) -> bool {
        self.is_none()
    }
}

impl<T: ToSql + ?Sized> ToSql for &T {
    fn to_sql(&self) -> Result<Vec<u8>, MySqlError> {
        (*self).to_sql()
    }

    fn mysql_type_code(&self) -> u8 {
        (*self).mysql_type_code()
    }

    fn is_null(&self) -> bool {
        (*self).is_null()
    }
}

fn write_stmt_execute_params(
    buf: &mut PacketBuffer,
    params: &[&dyn ToSql],
) -> Result<(), MySqlError> {
    if params.is_empty() {
        return Ok(());
    }

    let mut null_bitmap = vec![0; params.len().div_ceil(8)];
    for (idx, param) in params.iter().enumerate() {
        if param.is_null() {
            null_bitmap[idx / 8] |= 1 << (idx % 8);
        }
    }
    buf.write_bytes(&null_bitmap);

    // Always send fresh parameter type metadata with the execute packet.
    buf.write_byte(0x01);
    for param in params {
        buf.write_u16_le(u16::from(param.mysql_type_code()));
    }

    for param in params {
        if param.is_null() {
            continue;
        }
        buf.write_bytes(&param.to_sql()?);
    }

    Ok(())
}

fn encode_lenenc_bytes(data: &[u8]) -> Vec<u8> {
    let mut buf = PacketBuffer::new();
    buf.write_lenenc_int(u64::try_from(data.len()).unwrap_or(u64::MAX));
    buf.write_bytes(data);
    buf.buf
}

/// MySQL type codes for protocol.
mod mysql_type {
    pub const MYSQL_TYPE_TINY: u8 = 1;
    pub const MYSQL_TYPE_LONG: u8 = 3;
    pub const MYSQL_TYPE_FLOAT: u8 = 4;
    pub const MYSQL_TYPE_DOUBLE: u8 = 5;
    pub const MYSQL_TYPE_NULL: u8 = 6;
    pub const MYSQL_TYPE_LONGLONG: u8 = 8;
    pub const MYSQL_TYPE_VAR_STRING: u8 = 253;
    pub const MYSQL_TYPE_BLOB: u8 = 252;
}

/// A MySQL prepared statement.
pub struct MySqlStatement {
    /// Server-side statement ID.
    statement_id: u32,
    /// Number of parameters.
    param_count: u16,
    /// Number of columns.
    column_count: u16,
    /// Parameter metadata.
    params: Vec<MySqlColumn>,
    /// Result column metadata.
    columns: Vec<MySqlColumn>,
}

impl MySqlStatement {
    /// Number of parameters in this statement.
    #[must_use]
    pub fn param_count(&self) -> u16 {
        self.param_count
    }

    /// Number of result columns.
    #[must_use]
    pub fn column_count(&self) -> u16 {
        self.column_count
    }

    /// Parameter metadata returned by the server.
    #[must_use]
    pub fn params(&self) -> &[MySqlColumn] {
        &self.params
    }

    /// Result column metadata returned by the server.
    #[must_use]
    pub fn columns(&self) -> &[MySqlColumn] {
        &self.columns
    }
}

// ============================================================================
// Transaction
// ============================================================================

/// A MySQL transaction.
///
/// The transaction will be rolled back on drop if not committed.
pub struct MySqlTransaction<'a> {
    conn: &'a mut MySqlConnection,
    finished: bool,
}

impl MySqlTransaction<'_> {
    /// Commit the transaction.
    pub async fn commit(mut self, cx: &Cx) -> Outcome<(), MySqlError> {
        if self.finished {
            return Outcome::Err(MySqlError::TransactionFinished);
        }
        match self.conn.execute(cx, "COMMIT").await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
            Outcome::Err(e) => outcome_from_error(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Rollback the transaction.
    pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), MySqlError> {
        if self.finished {
            return Outcome::Err(MySqlError::TransactionFinished);
        }
        match self.conn.execute(cx, "ROLLBACK").await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
            Outcome::Err(e) => outcome_from_error(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Execute a query within this transaction.
    pub async fn query(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<MySqlRow>, MySqlError> {
        if self.finished {
            return Outcome::Err(MySqlError::TransactionFinished);
        }
        self.conn.query(cx, sql).await
    }

    /// Execute a command within this transaction.
    pub async fn execute(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, MySqlError> {
        if self.finished {
            return Outcome::Err(MySqlError::TransactionFinished);
        }
        self.conn.execute(cx, sql).await
    }
}

impl Drop for MySqlTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Mark the connection so the next command will issue an implicit
            // ROLLBACK before proceeding. We cannot await inside Drop, so
            // the actual ROLLBACK is deferred to `drain_abandoned_transaction`.
            self.conn.inner.needs_rollback = true;
        }
    }
}

#[doc(hidden)]
pub fn fuzz_parse_ok_packet_fields(data: &[u8]) -> Result<(u64, u16), MySqlError> {
    MySqlConnection::parse_ok_packet(data).map(|packet| (packet.affected_rows, packet.status_flags))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::pedantic,
        clippy::nursery,
        clippy::expect_fun_call,
        clippy::map_unwrap_or,
        clippy::cast_possible_wrap,
        clippy::future_not_send
    )]
    use super::*;
    use crate::Cx;
    use crate::types::CancelKind;
    use std::io::{Read, Write};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::mpsc;
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    fn run<F: std::future::Future>(future: F) -> F::Output {
        futures_lite::future::block_on(future)
    }

    fn noop_waker() -> Waker {
        std::task::Waker::noop().clone()
    }

    fn poll_once<F: std::future::Future>(fut: &mut Pin<&mut F>) -> Poll<F::Output> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        fut.as_mut().poll(&mut cx)
    }

    fn cancelled_cx() -> Cx {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        cx
    }

    fn assert_user_cancelled<T>(outcome: Outcome<T, MySqlError>) {
        match outcome {
            Outcome::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
            Outcome::Err(err) => panic!("expected cancellation, got error: {err}"),
            Outcome::Ok(_) => panic!("expected cancellation, got success"),
            Outcome::Panicked(payload) => panic!("unexpected panic outcome: {payload:?}"),
        }
    }

    fn test_var_string_column(name: &str) -> MySqlColumn {
        MySqlColumn {
            catalog: "def".to_string(),
            schema: "test_db".to_string(),
            table: "users".to_string(),
            org_table: "users".to_string(),
            name: name.to_string(),
            org_name: name.to_string(),
            charset: 33,
            length: 255,
            column_type: column_type::MYSQL_TYPE_VAR_STRING,
            flags: 0,
            decimals: 0,
        }
    }

    fn test_column_with_type_and_charset(
        name: &str,
        column_type_code: u8,
        charset: u16,
    ) -> MySqlColumn {
        MySqlColumn {
            column_type: column_type_code,
            charset,
            ..test_var_string_column(name)
        }
    }

    fn ok_packet_payload(affected_rows: u64, status_flags: u16) -> Vec<u8> {
        let mut buf = PacketBuffer::new();
        buf.write_byte(0x00);
        buf.write_lenenc_int(affected_rows);
        buf.write_lenenc_int(0);
        buf.buf.extend_from_slice(&status_flags.to_le_bytes());
        buf.buf.extend_from_slice(&0u16.to_le_bytes());
        buf.buf
    }

    fn eof_packet_payload(status_flags: u16) -> Vec<u8> {
        let mut buf = PacketBuffer::new();
        buf.write_byte(0xFE);
        buf.buf.extend_from_slice(&0u16.to_le_bytes());
        buf.buf.extend_from_slice(&status_flags.to_le_bytes());
        buf.buf
    }

    fn deprecate_eof_ok_packet_payload(status_flags: u16, info: &[u8]) -> Vec<u8> {
        let mut buf = PacketBuffer::new();
        buf.write_byte(0xFE);
        buf.write_lenenc_int(0);
        buf.write_lenenc_int(0);
        buf.buf.extend_from_slice(&status_flags.to_le_bytes());
        buf.buf.extend_from_slice(&0u16.to_le_bytes());
        buf.write_lenenc_int(info.len() as u64);
        buf.write_bytes(info);
        buf.buf
    }

    fn column_definition_payload(name: &str) -> Vec<u8> {
        column_definition_payload_with_type(name, column_type::MYSQL_TYPE_VAR_STRING)
    }

    fn column_definition_payload_with_type(name: &str, column_type_code: u8) -> Vec<u8> {
        let mut buf = PacketBuffer::new();
        buf.write_lenenc_int(3);
        buf.write_bytes(b"def");
        buf.write_lenenc_int(0);
        buf.write_lenenc_int(0);
        buf.write_lenenc_int(0);
        buf.write_lenenc_int(name.len() as u64);
        buf.write_bytes(name.as_bytes());
        buf.write_lenenc_int(name.len() as u64);
        buf.write_bytes(name.as_bytes());
        buf.write_lenenc_int(0x0C);
        buf.buf.extend_from_slice(&33u16.to_le_bytes());
        buf.write_u32_le(255);
        buf.write_byte(column_type_code);
        buf.buf.extend_from_slice(&0u16.to_le_bytes());
        buf.write_byte(0);
        buf.buf
    }

    fn make_test_connection() -> MySqlConnection {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let std_stream = std::net::TcpStream::connect(addr).expect("connect");
        let _accepted = listener.accept().expect("accept");
        let stream = crate::net::TcpStream::from_std(std_stream).expect("from_std");
        MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        }
    }

    fn make_command_connection_with_single_response(
        response_payload: Vec<u8>,
    ) -> (MySqlConnection, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read command header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream
                .read_exact(&mut payload)
                .expect("read command payload");
            assert_eq!(payload[0], command::COM_QUERY);

            let mut packet = PacketBuffer::new();
            packet.set_sequence(1);
            packet.buf = response_payload;
            let packet = packet.build_packet();
            stream
                .write_all(&packet.bytes)
                .expect("write server response packet");
            stream.flush().expect("flush server response packet");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };

        (conn, server)
    }

    fn read_packet_payload_from_wire(payload: Vec<u8>) -> (Vec<u8>, u8) {
        use futures_lite::future;
        use std::io::Write as _;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let server_payload = payload;

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut buf = PacketBuffer::new();
            buf.set_sequence(0);
            buf.buf = server_payload;
            let packet = buf.build_packet();
            stream.write_all(&packet.bytes).expect("write packet");
            stream.flush().expect("flush packet");
        });

        let result = future::block_on(async move {
            let stream = crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client");
            let mut conn = MySqlConnection {
                inner: MySqlConnectionInner {
                    stream,
                    connection_id: 0,
                    capabilities: 0,
                    charset: 0,
                    status_flags: 0,
                    sequence: 0,
                    closed: false,
                    server_version: String::new(),
                    needs_rollback: false,
                    max_result_rows: DEFAULT_MAX_RESULT_ROWS,
                },
            };
            conn.read_packet().await.expect("read packet")
        });

        server.join().expect("join server");
        result
    }

    #[test]
    fn cancelled_commit_marks_connection_for_rollback() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        let outcome = run(async {
            let tx = MySqlTransaction {
                conn: &mut conn,
                finished: false,
            };
            tx.commit(&cx).await
        });

        assert_user_cancelled(outcome);
        assert!(conn.inner.needs_rollback);
    }

    #[test]
    fn cancelled_rollback_marks_connection_for_rollback() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        let outcome = run(async {
            let tx = MySqlTransaction {
                conn: &mut conn,
                finished: false,
            };
            tx.rollback(&cx).await
        });

        assert_user_cancelled(outcome);
        assert!(conn.inner.needs_rollback);
    }

    #[test]
    fn test_connect_options_parse() {
        let opts = MySqlConnectOptions::parse("mysql://user:pass@localhost:3306/mydb").unwrap();
        assert_eq!(opts.user, "user");
        assert_eq!(opts.password, Some("pass".to_string()));
        assert_eq!(opts.host, "localhost");
        assert_eq!(opts.port, 3306);
        assert_eq!(opts.database, Some("mydb".to_string()));
    }

    #[test]
    fn test_connect_options_parse_minimal() {
        let opts = MySqlConnectOptions::parse("mysql://localhost/mydb").unwrap();
        assert_eq!(opts.user, "root");
        assert_eq!(opts.password, None);
        assert_eq!(opts.host, "localhost");
        assert_eq!(opts.port, 3306);
        assert_eq!(opts.database, Some("mydb".to_string()));
    }

    #[test]
    fn test_connect_options_no_database() {
        let opts = MySqlConnectOptions::parse("mysql://user@localhost").unwrap();
        assert_eq!(opts.user, "user");
        assert_eq!(opts.database, None);
    }

    #[test]
    fn test_mysql_value_conversions() {
        assert!(MySqlValue::Null.is_null());
        assert_eq!(MySqlValue::Long(42).as_i32(), Some(42));
        assert_eq!(MySqlValue::Long(42).as_i64(), Some(42));
        assert_eq!(MySqlValue::Tiny(1).as_bool(), Some(true));
        assert_eq!(
            MySqlValue::Text("hello".to_string()).as_str(),
            Some("hello")
        );
    }

    #[test]
    fn test_mysql_native_auth() {
        // Test with known values
        let nonce = b"12345678901234567890";
        let result = mysql_native_auth("password", nonce);
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_caching_sha2_auth() {
        let nonce = b"12345678901234567890";
        let result = caching_sha2_auth("password", nonce);
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_lenenc_int() {
        // Test reading length-encoded integers
        let data = [0x00]; // 0
        let mut reader = PacketReader::new(&data);
        assert_eq!(reader.read_lenenc_int().unwrap(), 0);

        let data = [0xFA]; // 250
        let mut reader = PacketReader::new(&data);
        assert_eq!(reader.read_lenenc_int().unwrap(), 250);

        let data = [0xFC, 0x00, 0x01]; // 256
        let mut reader = PacketReader::new(&data);
        assert_eq!(reader.read_lenenc_int().unwrap(), 256);
    }

    #[test]
    fn test_packet_buffer() {
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_QUERY);
        buf.write_bytes(b"SELECT 1");

        let packet = buf.build_packet();
        assert_eq!(packet.bytes[0], 9); // length low byte
        assert_eq!(packet.bytes[1], 0); // length mid byte
        assert_eq!(packet.bytes[2], 0); // length high byte
        assert_eq!(packet.bytes[3], 0); // sequence
        assert_eq!(packet.bytes[4], command::COM_QUERY);
        assert_eq!(packet.next_sequence, 1);
    }

    #[test]
    fn test_lenenc_int_3byte() {
        // 3-byte encoding (0xFD prefix)
        let data = [0xFD, 0x01, 0x02, 0x03]; // 0x030201 = 197121
        let mut reader = PacketReader::new(&data);
        assert_eq!(reader.read_lenenc_int().unwrap(), 197_121);
    }

    #[test]
    fn test_lenenc_int_8byte() {
        // 8-byte encoding (0xFE prefix)
        let data = [0xFE, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut reader = PacketReader::new(&data);
        assert_eq!(reader.read_lenenc_int().unwrap(), 1);
    }

    #[test]
    fn test_lenenc_string() {
        // Length-encoded string: length=5, then "hello"
        let data = [0x05, b'h', b'e', b'l', b'l', b'o'];
        let mut reader = PacketReader::new(&data);
        let bytes = reader.read_lenenc_bytes().unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_null_terminated_string() {
        let data = [
            b'h', b'e', b'l', b'l', b'o', 0x00, b'e', b'x', b't', b'r', b'a',
        ];
        let mut reader = PacketReader::new(&data);
        let s = reader.read_null_terminated().unwrap();
        assert_eq!(s, "hello");
        assert_eq!(reader.pos, 6);
    }

    #[test]
    fn test_fixed_length_string() {
        let data = b"hello world";
        let mut reader = PacketReader::new(data);
        let bytes = reader.read_bytes(5).unwrap();
        assert_eq!(bytes, b"hello");
        assert_eq!(reader.pos, 5);
    }

    #[test]
    fn test_mysql_value_display() {
        assert_eq!(format!("{}", MySqlValue::Null), "NULL");
        assert_eq!(format!("{}", MySqlValue::Long(42)), "42");
        assert_eq!(format!("{}", MySqlValue::Text("test".to_string())), "test");
        assert_eq!(
            format!("{}", MySqlValue::Bytes(vec![1, 2, 3])),
            "<bytes 3 len>"
        );
    }

    #[test]
    fn test_mysql_value_type_conversions() {
        // Test Short to i32 conversion
        assert_eq!(MySqlValue::Short(100).as_i32(), Some(100));
        // Test Tiny to i32 conversion
        assert_eq!(MySqlValue::Tiny(42).as_i32(), Some(42));
        // Test LongLong to i64
        assert_eq!(
            MySqlValue::LongLong(123_456_789_012_345).as_i64(),
            Some(123_456_789_012_345)
        );
        // Test Float to f64
        assert!(MySqlValue::Float(3.5).as_f64().is_some());
        // Test Double to f64
        assert_eq!(MySqlValue::Double(2.5).as_f64(), Some(2.5));
        // Test invalid conversions return None
        assert_eq!(MySqlValue::Text("not a number".to_string()).as_i32(), None);
        assert_eq!(MySqlValue::Null.as_i64(), None);
    }

    #[test]
    fn test_mysql_value_bool_conversion() {
        assert_eq!(MySqlValue::Bool(true).as_bool(), Some(true));
        assert_eq!(MySqlValue::Bool(false).as_bool(), Some(false));
        assert_eq!(MySqlValue::Tiny(0).as_bool(), Some(false));
        assert_eq!(MySqlValue::Tiny(1).as_bool(), Some(true));
        assert_eq!(MySqlValue::Tiny(42).as_bool(), Some(true)); // Non-zero is true
    }

    #[test]
    fn test_mysql_value_bytes() {
        let bytes = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let val = MySqlValue::Bytes(bytes.clone());
        assert_eq!(val.as_bytes(), Some(bytes.as_slice()));
        assert_eq!(MySqlValue::Null.as_bytes(), None);
    }

    #[test]
    fn test_connect_options_with_port() {
        let opts = MySqlConnectOptions::parse("mysql://user@localhost:3307/db").unwrap();
        assert_eq!(opts.port, 3307);
    }

    #[test]
    fn test_connect_options_password_with_special() {
        // Password with special chars (non-encoded)
        let opts = MySqlConnectOptions::parse("mysql://user:pass123@localhost/db").unwrap();
        assert_eq!(opts.password, Some("pass123".to_string()));
    }

    #[test]
    fn test_connect_options_invalid_scheme() {
        let result = MySqlConnectOptions::parse("postgres://localhost/db");
        assert!(result.is_err());
    }

    #[test]
    fn test_mysql_error_display() {
        let err = MySqlError::Protocol("test error".to_string());
        assert!(format!("{err}").contains("test error"));

        let err = MySqlError::ColumnNotFound("missing_col".to_string());
        assert!(format!("{err}").contains("missing_col"));
    }

    #[test]
    fn test_packet_buffer_sequence() {
        let mut buf = PacketBuffer::new();
        buf.set_sequence(5);
        buf.write_byte(0x00);
        let packet = buf.build_packet();
        assert_eq!(packet.bytes[3], 5); // sequence byte
        assert_eq!(packet.next_sequence, 6);
    }

    #[test]
    fn stmt_execute_params_marks_nulls_and_omits_null_values() {
        let null_i32: Option<i32> = None;
        let some_i32 = Some(7_i32);
        let text = "ok".to_string();
        let mut buf = PacketBuffer::new();

        write_stmt_execute_params(&mut buf, &[&null_i32, &some_i32, &text])
            .expect("encode statement parameters");

        assert_eq!(buf.buf[0], 0b0000_0001, "first parameter is NULL");
        assert_eq!(buf.buf[1], 0x01, "new-params-bound flag must be set");
        assert_eq!(
            &buf.buf[2..8],
            &[
                mysql_type::MYSQL_TYPE_NULL,
                0,
                mysql_type::MYSQL_TYPE_LONG,
                0,
                mysql_type::MYSQL_TYPE_VAR_STRING,
                0
            ]
        );
        assert_eq!(&buf.buf[8..12], &7_i32.to_le_bytes());
        assert_eq!(&buf.buf[12..], &[2, b'o', b'k']);
    }

    #[test]
    fn stmt_execute_params_uses_lsb_first_null_bitmap_across_bytes() {
        let params = [
            None,
            Some(1_i32),
            None,
            Some(2_i32),
            Some(3_i32),
            Some(4_i32),
            Some(5_i32),
            Some(6_i32),
            None,
        ];
        let param_refs: Vec<&dyn ToSql> = params.iter().map(|param| param as &dyn ToSql).collect();
        let mut buf = PacketBuffer::new();

        write_stmt_execute_params(&mut buf, &param_refs).expect("encode statement parameters");

        assert_eq!(&buf.buf[..2], &[0b0000_0101, 0b0000_0001]);
    }

    #[test]
    fn stmt_execute_params_length_prefixes_variable_values() {
        let short = "abc".to_string();
        let long = vec![b'x'; 300];
        let mut buf = PacketBuffer::new();

        write_stmt_execute_params(&mut buf, &[&short, &long]).expect("encode statement parameters");

        assert_eq!(buf.buf[0], 0, "no NULL parameters");
        assert_eq!(buf.buf[1], 0x01, "new-params-bound flag must be set");
        assert_eq!(
            &buf.buf[2..6],
            &[
                mysql_type::MYSQL_TYPE_VAR_STRING,
                0,
                mysql_type::MYSQL_TYPE_BLOB,
                0
            ]
        );
        assert_eq!(&buf.buf[6..10], &[3, b'a', b'b', b'c']);
        assert_eq!(
            &buf.buf[10..13],
            &[0xFC, 0x2C, 0x01],
            "300-byte value must use 0xFC length encoding"
        );
        assert_eq!(&buf.buf[13..], long.as_slice());
    }

    #[test]
    fn binary_row_parser_uses_mysql_binary_row_format() {
        let columns = vec![
            MySqlColumn {
                column_type: column_type::MYSQL_TYPE_LONG,
                ..test_var_string_column("id")
            },
            test_var_string_column("name"),
            MySqlColumn {
                column_type: column_type::MYSQL_TYPE_LONG,
                ..test_var_string_column("missing")
            },
        ];
        let mut row = vec![0x00, 0b0001_0000];
        row.extend_from_slice(&123_i32.to_le_bytes());
        row.push(3);
        row.extend_from_slice(b"bob");

        let values = MySqlConnection::parse_binary_row(&row, &columns).expect("parse binary row");

        assert_eq!(
            values,
            vec![
                MySqlValue::Long(123),
                MySqlValue::Text("bob".to_string()),
                MySqlValue::Null
            ]
        );
    }

    #[test]
    fn binary_row_parser_decodes_nonbinary_blob_as_text() {
        let columns = vec![test_column_with_type_and_charset(
            "payload",
            column_type::MYSQL_TYPE_BLOB,
            33,
        )];
        let mut row = vec![0x00, 0x00, 5];
        row.extend_from_slice(b"hello");

        let values = MySqlConnection::parse_binary_row(&row, &columns).expect("parse binary row");

        assert_eq!(values, vec![MySqlValue::Text("hello".to_string())]);
    }

    #[test]
    fn binary_row_parser_preserves_binary_var_string_bytes() {
        let columns = vec![test_column_with_type_and_charset(
            "payload",
            column_type::MYSQL_TYPE_VAR_STRING,
            MYSQL_BINARY_CHARSET_ID,
        )];
        let row = [0x00, 0x00, 3, 0xFF, 0x00, 0xFE];

        let values = MySqlConnection::parse_binary_row(&row, &columns).expect("parse binary row");

        assert_eq!(values, vec![MySqlValue::Bytes(vec![0xFF, 0x00, 0xFE])]);
    }

    #[test]
    fn test_packet_buffer_large_payload() {
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        // Write 256 bytes
        for _ in 0..256 {
            buf.write_byte(0x41);
        }
        let packet = buf.build_packet();
        // Length should be 256 = 0x100
        assert_eq!(packet.bytes[0], 0x00); // low byte
        assert_eq!(packet.bytes[1], 0x01); // mid byte (256)
        assert_eq!(packet.bytes[2], 0x00); // high byte
        assert_eq!(packet.next_sequence, 1);
    }

    #[test]
    fn test_decode_packet_header_accepts_expected_sequence() {
        let header = [0x02, 0x00, 0x00, 0x07];
        let (len, seq) = MySqlConnection::decode_packet_header(header, 0x07).expect("valid header");
        assert_eq!(len, 2);
        assert_eq!(seq, 0x07);
    }

    #[test]
    fn test_decode_packet_header_rejects_sequence_mismatch() {
        let header = [0x01, 0x00, 0x00, 0x02];
        let err = MySqlConnection::decode_packet_header(header, 0x01).unwrap_err();
        assert!(matches!(err, MySqlError::Protocol(_)));
        assert!(format!("{err}").contains("sequence mismatch"));
    }

    #[test]
    fn test_decode_packet_header_accepts_max_packet_size() {
        // MAX_PACKET_SIZE = 0xFFFFFF is the largest value representable in
        // the 3-byte length field. The `> MAX_PACKET_SIZE` guard in
        // decode_packet_header is unreachable with valid 3-byte encoding
        // but is kept as defense-in-depth documentation.
        let header = [0xFF, 0xFF, 0xFF, 0x00];
        let (len, seq) =
            MySqlConnection::decode_packet_header(header, 0x00).expect("max size accepted");
        assert_eq!(len, MAX_PACKET_SIZE);
        assert_eq!(seq, 0x00);
    }

    #[test]
    fn test_mysql_column_fields() {
        let col = MySqlColumn {
            catalog: "def".to_string(),
            schema: "test_db".to_string(),
            table: "users".to_string(),
            org_table: "users".to_string(),
            name: "id".to_string(),
            org_name: "id".to_string(),
            charset: 33, // utf8
            length: 11,
            column_type: column_type::MYSQL_TYPE_LONG,
            flags: 0,
            decimals: 0,
        };
        assert_eq!(col.name, "id");
        assert_eq!(col.column_type, column_type::MYSQL_TYPE_LONG);
        assert_eq!(col.schema, "test_db");
    }

    #[test]
    fn test_ssl_mode_default() {
        assert_eq!(SslMode::default(), SslMode::Disabled);
    }

    #[test]
    fn test_negotiated_capabilities_require_client_and_server_support() {
        let server_caps = capability::CLIENT_PROTOCOL_41 | capability::CLIENT_DEPRECATE_EOF;
        let client_caps = capability::CLIENT_PROTOCOL_41;
        let negotiated = MySqlConnection::negotiated_capabilities(server_caps, client_caps);

        assert_eq!(
            negotiated & capability::CLIENT_PROTOCOL_41,
            capability::CLIENT_PROTOCOL_41
        );
        assert_eq!(negotiated & capability::CLIENT_DEPRECATE_EOF, 0);
    }

    #[test]
    fn test_parse_text_row_rejects_trailing_bytes() {
        let columns = vec![test_var_string_column("name")];

        let err = MySqlConnection::parse_text_row(&[0x00, 0x00], &columns).unwrap_err();
        assert!(matches!(err, MySqlError::Protocol(_)));
    }

    #[test]
    fn test_parse_text_row_preserves_invalid_utf8_blob_bytes() {
        let columns = vec![test_column_with_type_and_charset(
            "payload",
            column_type::MYSQL_TYPE_BLOB,
            MYSQL_BINARY_CHARSET_ID,
        )];
        let row = [3, 0xFF, 0x00, 0xFE];

        let values = MySqlConnection::parse_text_row(&row, &columns).expect("parse BLOB row");

        assert_eq!(values, vec![MySqlValue::Bytes(vec![0xFF, 0x00, 0xFE])]);
    }

    #[test]
    fn test_parse_text_row_decodes_nonbinary_blob_as_text() {
        let columns = vec![test_column_with_type_and_charset(
            "payload",
            column_type::MYSQL_TYPE_BLOB,
            33,
        )];
        let row = [5, b'h', b'e', b'l', b'l', b'o'];

        let values = MySqlConnection::parse_text_row(&row, &columns).expect("parse TEXT row");

        assert_eq!(values, vec![MySqlValue::Text("hello".to_string())]);
    }

    #[test]
    fn test_parse_text_row_preserves_binary_var_string_bytes() {
        let columns = vec![test_column_with_type_and_charset(
            "payload",
            column_type::MYSQL_TYPE_VAR_STRING,
            MYSQL_BINARY_CHARSET_ID,
        )];
        let row = [3, 0xFF, 0x00, 0xFE];

        let values =
            MySqlConnection::parse_text_row(&row, &columns).expect("parse binary VAR_STRING row");

        assert_eq!(values, vec![MySqlValue::Bytes(vec![0xFF, 0x00, 0xFE])]);
    }

    #[test]
    fn test_parse_text_row_rejects_invalid_utf8_text() {
        let columns = vec![test_var_string_column("payload")];
        let row = [3, 0xFF, 0x00, 0xFE];

        let err = MySqlConnection::parse_text_row(&row, &columns).unwrap_err();

        assert!(matches!(err, MySqlError::Protocol(msg) if msg.contains("invalid UTF-8")));
    }

    #[test]
    fn test_parse_data_row_or_terminator_prefers_valid_row_for_0x00_packets() {
        let columns: Vec<_> = (0..7)
            .map(|i| test_var_string_column(&format!("c{i}")))
            .collect();
        let data = vec![0x00; 7];

        assert!(MySqlConnection::is_result_set_ok_packet(&data));

        let values = MySqlConnection::parse_data_row_or_terminator(&data, &columns, true)
            .expect("parse should succeed")
            .expect("ambiguous packet should be treated as row when row parse succeeds");

        assert_eq!(values.len(), 7);
        for value in values {
            assert_eq!(value, MySqlValue::Text(String::new()));
        }
    }

    #[test]
    fn test_parse_data_row_or_terminator_accepts_ok_when_row_parse_fails() {
        let columns = vec![test_var_string_column("name")];
        let ok_packet = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];

        assert!(MySqlConnection::is_result_set_ok_packet(&ok_packet));

        let outcome = MySqlConnection::parse_data_row_or_terminator(&ok_packet, &columns, true)
            .expect("classification should succeed");
        assert!(outcome.is_none());
    }

    #[test]
    fn test_parse_data_row_or_terminator_non_deprecate_reports_row_error() {
        let columns = vec![test_var_string_column("name")];
        let ok_packet = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];

        let err =
            MySqlConnection::parse_data_row_or_terminator(&ok_packet, &columns, false).unwrap_err();
        assert!(matches!(err, MySqlError::Protocol(_)));
    }

    #[test]
    fn test_expects_metadata_eof_without_deprecate_eof() {
        assert!(MySqlConnection::expects_metadata_eof(
            capability::CLIENT_PROTOCOL_41
        ));
    }

    #[test]
    fn test_expects_metadata_eof_disabled_with_deprecate_eof() {
        assert!(!MySqlConnection::expects_metadata_eof(
            capability::CLIENT_PROTOCOL_41 | capability::CLIENT_DEPRECATE_EOF
        ));
    }

    // ====================================================================
    // T6.3 Hardening tests
    // ====================================================================

    #[test]
    fn test_percent_decode_basic() {
        assert_eq!(percent_decode("hello"), "hello");
        assert_eq!(percent_decode("hello%20world"), "hello world");
        assert_eq!(percent_decode("user%40host"), "user@host");
        assert_eq!(percent_decode("pass%2Fword"), "pass/word");
        assert_eq!(percent_decode("a%3Ab"), "a:b");
    }

    #[test]
    fn test_percent_decode_passthrough_malformed() {
        // Incomplete percent sequences pass through unchanged.
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%GG"), "%GG");
        assert_eq!(percent_decode("%2"), "%2");
    }

    #[test]
    fn test_percent_decode_mixed_case() {
        assert_eq!(percent_decode("%2f"), "/");
        assert_eq!(percent_decode("%2F"), "/");
    }

    #[test]
    fn test_connect_options_percent_encoded_password() {
        let opts = MySqlConnectOptions::parse("mysql://user:p%40ss%3Aword@localhost/db").unwrap();
        assert_eq!(opts.password, Some("p@ss:word".to_string()));
    }

    #[test]
    fn test_connect_options_percent_encoded_user() {
        let opts = MySqlConnectOptions::parse("mysql://user%40domain:pass@localhost/db").unwrap();
        assert_eq!(opts.user, "user@domain");
    }

    #[test]
    fn test_connect_options_ssl_mode_from_query() {
        let opts =
            MySqlConnectOptions::parse("mysql://user@localhost/db?ssl-mode=required").unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Required);

        let opts =
            MySqlConnectOptions::parse("mysql://user@localhost/db?sslmode=preferred").unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Preferred);
    }

    #[test]
    fn test_connect_options_connect_timeout_from_query() {
        let opts =
            MySqlConnectOptions::parse("mysql://user@localhost/db?connect_timeout=5").unwrap();
        assert_eq!(
            opts.connect_timeout,
            Some(std::time::Duration::from_secs(5))
        );
    }

    #[test]
    fn test_connect_options_invalid_ssl_mode_rejected() {
        let result = MySqlConnectOptions::parse("mysql://user@localhost/db?ssl-mode=bogus");
        assert!(result.is_err());
    }

    #[test]
    fn test_connect_options_multiple_query_params() {
        let opts = MySqlConnectOptions::parse(
            "mysql://user@localhost/db?ssl-mode=required&connect_timeout=10",
        )
        .unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Required);
        assert_eq!(
            opts.connect_timeout,
            Some(std::time::Duration::from_secs(10))
        );
    }

    #[test]
    fn test_connect_options_unknown_params_ignored() {
        let opts =
            MySqlConnectOptions::parse("mysql://user@localhost/db?charset=utf8mb4&unknown=value")
                .unwrap();
        // Should parse without error; unknown params silently dropped.
        assert_eq!(opts.host, "localhost");
    }

    #[test]
    fn test_build_packet_splits_oversized_payload() {
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.buf = vec![0x41; MAX_PACKET_SIZE as usize + 3];
        let packet = buf.build_packet();

        assert_eq!(&packet.bytes[..4], &[0xFF, 0xFF, 0xFF, 0x00]);
        let second_header_offset = 4 + MAX_PACKET_SIZE as usize;
        assert_eq!(
            &packet.bytes[second_header_offset..second_header_offset + 4],
            &[0x03, 0x00, 0x00, 0x01]
        );
        assert_eq!(packet.next_sequence, 2);
    }

    #[test]
    fn test_build_packet_accepts_max_payload() {
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.buf = vec![0x41; MAX_PACKET_SIZE as usize];
        let packet = buf.build_packet();
        assert_eq!(packet.bytes.len(), 8 + MAX_PACKET_SIZE as usize);
        let terminator_offset = 4 + MAX_PACKET_SIZE as usize;
        assert_eq!(
            &packet.bytes[terminator_offset..terminator_offset + 4],
            &[0x00, 0x00, 0x00, 0x01]
        );
        assert_eq!(packet.next_sequence, 2);
    }

    #[test]
    fn test_read_packet_reassembles_multi_packet_payload() {
        let payload = vec![0x5A; MAX_PACKET_SIZE as usize + 3];
        let (data, seq) = read_packet_payload_from_wire(payload.clone());

        assert_eq!(data, payload);
        assert_eq!(seq, 1);
    }

    #[test]
    fn test_read_packet_reassembles_exact_max_payload_with_terminator() {
        let payload = vec![0x4B; MAX_PACKET_SIZE as usize];
        let (data, seq) = read_packet_payload_from_wire(payload.clone());

        assert_eq!(data, payload);
        assert_eq!(seq, 1);
    }

    #[test]
    fn malformed_server_err_packet_keeps_query_connection_closed() {
        let (mut conn, server) = make_command_connection_with_single_response(vec![0xFF]);
        let cx = Cx::for_testing();

        let outcome = run(conn.query(&cx, "SELECT 1"));
        match outcome {
            Outcome::Err(MySqlError::Protocol(_)) => {}
            other => panic!(
                // ubs:ignore
                "expected malformed ERR packet protocol error, got {other:?}"
            ),
        }

        server.join().expect("join server");
        assert!(
            conn.inner.closed,
            "malformed ERR packets must keep query connections fail-closed"
        );
    }

    #[test]
    fn malformed_server_err_packet_keeps_execute_connection_closed() {
        let (mut conn, server) = make_command_connection_with_single_response(vec![0xFF]);
        let cx = Cx::for_testing();

        let outcome = run(conn.execute(&cx, "DELETE FROM widgets"));
        match outcome {
            Outcome::Err(MySqlError::Protocol(_)) => {}
            other => panic!(
                // ubs:ignore
                "expected malformed ERR packet protocol error, got {other:?}"
            ),
        }

        server.join().expect("join server");
        assert!(
            conn.inner.closed,
            "malformed ERR packets must keep execute connections fail-closed"
        );
    }

    #[test]
    fn execute_ok_packet_updates_in_transaction_status_flag() {
        const SERVER_STATUS_IN_TRANS: u16 = 0x0001;

        let (mut conn, server) = make_command_connection_with_single_response(ok_packet_payload(
            0,
            SERVER_STATUS_IN_TRANS,
        ));
        let cx = Cx::for_testing();

        let outcome = run(conn.execute(&cx, "START TRANSACTION"));
        match outcome {
            Outcome::Ok(0) => {}
            other => panic!("expected START TRANSACTION OK packet, got {other:?}"),
        }

        server.join().expect("join server");
        assert!(
            conn.in_transaction(),
            "OK packet status flags must refresh transaction state"
        );
    }

    #[test]
    fn execute_ok_packet_clears_in_transaction_status_flag() {
        const SERVER_STATUS_IN_TRANS: u16 = 0x0001;

        let (mut conn, server) =
            make_command_connection_with_single_response(ok_packet_payload(0, 0));
        conn.inner.status_flags = SERVER_STATUS_IN_TRANS;
        let cx = Cx::for_testing();

        let outcome = run(conn.execute(&cx, "COMMIT"));
        match outcome {
            Outcome::Ok(0) => {}
            other => panic!("expected COMMIT OK packet, got {other:?}"),
        }

        server.join().expect("join server");
        assert!(
            !conn.in_transaction(),
            "OK packet status flags must clear transaction state after COMMIT/ROLLBACK"
        );
    }

    #[test]
    fn query_result_set_terminator_updates_in_transaction_status_flag() {
        const SERVER_STATUS_IN_TRANS: u16 = 0x0001;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read query header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).expect("read query payload");
            assert_eq!(payload[0], command::COM_QUERY);

            let responses = [
                vec![0x01],
                column_definition_payload("value"),
                eof_packet_payload(0),
                eof_packet_payload(SERVER_STATUS_IN_TRANS),
            ];

            for (sequence, response) in responses.into_iter().enumerate() {
                let mut packet = PacketBuffer::new();
                packet.set_sequence((sequence + 1) as u8);
                packet.buf = response;
                let packet = packet.build_packet();
                stream
                    .write_all(&packet.bytes)
                    .expect("write result-set packet");
            }
            stream.flush().expect("flush result-set packets");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };
        let cx = Cx::for_testing();

        let outcome = run(conn.query(&cx, "SELECT value FROM test"));
        match outcome {
            Outcome::Ok(rows) => assert!(rows.is_empty(), "expected empty result set"),
            other => panic!("expected empty result set success, got {other:?}"),
        }

        server.join().expect("join server");
        assert!(
            conn.in_transaction(),
            "final result-set terminator must refresh transaction state"
        );
    }

    #[test]
    fn query_deprecate_eof_ok_terminator_updates_in_transaction_status_flag() {
        const SERVER_STATUS_IN_TRANS: u16 = 0x0001;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read query header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).expect("read query payload");
            assert_eq!(payload[0], command::COM_QUERY);

            let responses = [
                vec![0x01],
                column_definition_payload("value"),
                deprecate_eof_ok_packet_payload(SERVER_STATUS_IN_TRANS, b"done"),
            ];

            for (sequence, response) in responses.into_iter().enumerate() {
                let mut packet = PacketBuffer::new();
                packet.set_sequence((sequence + 1) as u8);
                packet.buf = response;
                let packet = packet.build_packet();
                stream
                    .write_all(&packet.bytes)
                    .expect("write result-set packet");
            }
            stream.flush().expect("flush result-set packets");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: capability::CLIENT_DEPRECATE_EOF,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };
        let cx = Cx::for_testing();

        let outcome = run(conn.query(&cx, "SELECT value FROM test"));
        match outcome {
            Outcome::Ok(rows) => assert!(rows.is_empty(), "expected empty result set"),
            other => panic!("expected empty result set success, got {other:?}"),
        }

        server.join().expect("join server");
        assert!(
            conn.in_transaction(),
            "deprecate-EOF OK terminator must refresh transaction state"
        );
    }

    #[test]
    fn dropped_result_set_query_keeps_connection_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let (query_seen_tx, query_seen_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read query header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream.read_exact(&mut payload).expect("read query payload");
            assert_eq!(payload[0], command::COM_QUERY);
            query_seen_tx.send(()).expect("signal query write");

            let mut packet = PacketBuffer::new();
            packet.set_sequence(1);
            packet.buf = vec![0x01]; // result set with one column follows
            let packet = packet.build_packet();
            stream
                .write_all(&packet.bytes)
                .expect("write first result-set packet");
            stream.flush().expect("flush first result-set packet");

            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("wait for client cancellation");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };
        let cx = Cx::for_testing();

        {
            let mut query = std::pin::pin!(conn.query(&cx, "SELECT 1"));
            let mut saw_query = false;
            for _ in 0..128 {
                if query_seen_rx.try_recv().is_ok() {
                    saw_query = true;
                }
                match poll_once(&mut query) {
                    Poll::Pending => std::thread::yield_now(),
                    Poll::Ready(outcome) => {
                        panic!(
                            "query unexpectedly completed before cancellation test point: {outcome:?}"
                        )
                    }
                }
                if saw_query {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            if !saw_query {
                query_seen_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("server should observe COM_QUERY");
                for _ in 0..32 {
                    let _ = poll_once(&mut query);
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        }

        release_tx.send(()).expect("release server");
        server.join().expect("join server");

        assert_eq!(
            conn.inner.sequence, 2,
            "test must consume the first result-set packet before cancellation"
        );
        assert!(
            conn.inner.closed,
            "dropping a query mid-result-set must keep the connection fail-closed"
        );
    }

    #[test]
    fn prepare_accepts_minimal_ok_packet() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read prepare header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream
                .read_exact(&mut payload)
                .expect("read prepare payload");
            assert_eq!(payload[0], command::COM_STMT_PREPARE);

            let mut response = PacketBuffer::new();
            response.write_byte(0x00);
            response.write_u32_le(99);
            response.write_u16_le(0);
            response.write_u16_le(0);
            response.write_byte(0x00);
            response.write_u16_le(0);

            let mut packet = PacketBuffer::new();
            packet.set_sequence(1);
            packet.buf = response.buf;
            let packet = packet.build_packet();
            stream
                .write_all(&packet.bytes)
                .expect("write prepare OK response");
            stream.flush().expect("flush prepare OK response");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };
        let cx = Cx::for_testing();

        let outcome = run(conn.prepare(&cx, "SELECT 1"));
        let stmt = match outcome {
            Outcome::Ok(stmt) => stmt,
            Outcome::Err(err) => panic!("expected prepare OK, got error: {err}"),
            Outcome::Cancelled(reason) => panic!("expected prepare OK, got cancellation: {reason}"),
            Outcome::Panicked(payload) => panic!("expected prepare OK, got panic: {payload:?}"),
        };

        server.join().expect("join server");
        assert_eq!(stmt.statement_id, 99);
        assert_eq!(stmt.param_count(), 0);
        assert_eq!(stmt.column_count(), 0);
        assert_eq!(conn.inner.sequence, 2);
        assert!(!conn.inner.closed);
    }

    #[test]
    fn empty_prepare_response_keeps_connection_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read prepare header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream
                .read_exact(&mut payload)
                .expect("read prepare payload");
            assert_eq!(payload[0], command::COM_STMT_PREPARE);

            let mut packet = PacketBuffer::new();
            packet.set_sequence(1);
            let packet = packet.build_packet();
            stream
                .write_all(&packet.bytes)
                .expect("write empty prepare response");
            stream.flush().expect("flush empty prepare response");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };
        let cx = Cx::for_testing();

        let outcome = run(conn.prepare(&cx, "SELECT 1"));
        match outcome {
            Outcome::Err(MySqlError::InvalidPacket(msg)) => {
                assert!(msg.contains("Empty prepare response"));
            }
            Outcome::Err(err) => panic!("expected invalid packet error, got error: {err}"),
            Outcome::Ok(_) => panic!("expected invalid packet error, got success"),
            Outcome::Cancelled(reason) => {
                panic!("expected invalid packet error, got cancellation: {reason}")
            }
            Outcome::Panicked(payload) => {
                panic!("expected invalid packet error, got panic: {payload:?}")
            }
        }

        server.join().expect("join server");
        assert!(
            conn.inner.closed,
            "empty COM_STMT_PREPARE response must keep connection fail-closed"
        );
    }

    #[test]
    fn query_prepared_decodes_binary_result_rows() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read execute header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream
                .read_exact(&mut payload)
                .expect("read execute payload");
            assert_eq!(payload[0], command::COM_STMT_EXECUTE);

            let mut row = vec![0x00, 0x00];
            row.extend_from_slice(&123_i32.to_le_bytes());

            let responses = [
                vec![0x01],
                column_definition_payload_with_type("value", column_type::MYSQL_TYPE_LONG),
                eof_packet_payload(0),
                row,
                eof_packet_payload(0),
            ];

            for (sequence, response) in responses.into_iter().enumerate() {
                let mut packet = PacketBuffer::new();
                packet.set_sequence((sequence + 1) as u8);
                packet.buf = response;
                let packet = packet.build_packet();
                stream
                    .write_all(&packet.bytes)
                    .expect("write prepared result-set packet");
            }
            stream.flush().expect("flush prepared result-set packets");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };
        let stmt = MySqlStatement {
            statement_id: 7,
            param_count: 0,
            column_count: 1,
            params: Vec::new(),
            columns: Vec::new(),
        };
        let cx = Cx::for_testing();

        let outcome = run(conn.query_prepared(&cx, &stmt, &[]));
        let rows = match outcome {
            Outcome::Ok(rows) => rows,
            Outcome::Err(err) => panic!("expected prepared rows, got error: {err}"),
            Outcome::Cancelled(reason) => {
                panic!("expected prepared rows, got cancellation: {reason}")
            }
            Outcome::Panicked(payload) => panic!("expected prepared rows, got panic: {payload:?}"),
        };

        server.join().expect("join server");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get_i32("value").expect("value column"), 123);
        assert_eq!(conn.inner.sequence, 6);
        assert!(!conn.inner.closed);
    }

    #[test]
    fn empty_execute_prepared_response_keeps_connection_closed() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set read timeout");

            let mut header = [0u8; 4];
            stream.read_exact(&mut header).expect("read execute header");
            let payload_len = usize::from(header[0])
                | (usize::from(header[1]) << 8)
                | (usize::from(header[2]) << 16);
            let mut payload = vec![0u8; payload_len];
            stream
                .read_exact(&mut payload)
                .expect("read execute payload");
            assert_eq!(payload[0], command::COM_STMT_EXECUTE);

            let mut packet = PacketBuffer::new();
            packet.set_sequence(1);
            let packet = packet.build_packet();
            stream
                .write_all(&packet.bytes)
                .expect("write empty execute response");
            stream.flush().expect("flush empty execute response");
        });

        let stream = run(async {
            crate::net::TcpStream::connect_socket_addr(addr)
                .await
                .expect("connect client")
        });

        let mut conn = MySqlConnection {
            inner: MySqlConnectionInner {
                stream,
                connection_id: 0,
                capabilities: 0,
                charset: 0,
                status_flags: 0,
                sequence: 0,
                closed: false,
                server_version: String::new(),
                needs_rollback: false,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };
        let stmt = MySqlStatement {
            statement_id: 7,
            param_count: 0,
            column_count: 0,
            params: Vec::new(),
            columns: Vec::new(),
        };
        let cx = Cx::for_testing();

        let outcome = run(conn.execute_prepared(&cx, &stmt, &[]));
        match outcome {
            Outcome::Err(MySqlError::InvalidPacket(msg)) => {
                assert!(msg.contains("Empty execute response"));
            }
            other => panic!("expected invalid packet error, got {other:?}"),
        }

        server.join().expect("join server");
        assert!(
            conn.inner.closed,
            "empty COM_STMT_EXECUTE response must keep connection fail-closed"
        );
    }

    #[test]
    fn test_default_max_result_rows() {
        assert_eq!(DEFAULT_MAX_RESULT_ROWS, 1_000_000);
    }

    #[test]
    fn test_lenenc_int_null_marker_rejected() {
        let data = [0xFB];
        let mut reader = PacketReader::new(&data);
        let err = reader.read_lenenc_int().unwrap_err();
        assert!(matches!(err, MySqlError::Protocol(_)));
    }

    #[test]
    fn test_lenenc_int_reserved_0xff_rejected() {
        let data = [0xFF];
        let mut reader = PacketReader::new(&data);
        let err = reader.read_lenenc_int().unwrap_err();
        assert!(matches!(err, MySqlError::Protocol(_)));
    }

    #[test]
    fn test_packet_reader_read_byte_eof() {
        let data: [u8; 0] = [];
        let mut reader = PacketReader::new(&data);
        assert!(reader.read_byte().is_err());
    }

    #[test]
    fn test_packet_reader_read_bytes_eof() {
        let data = [0x01, 0x02];
        let mut reader = PacketReader::new(&data);
        assert!(reader.read_bytes(3).is_err());
    }

    #[test]
    fn test_null_terminated_string_missing_null() {
        let data = [b'a', b'b', b'c']; // No null terminator
        let mut reader = PacketReader::new(&data);
        let err = reader.read_null_terminated().unwrap_err();
        assert!(matches!(err, MySqlError::Protocol(_)));
    }

    #[test]
    fn test_auth_empty_password_returns_empty() {
        assert!(mysql_native_auth("", b"nonce").is_empty());
        assert!(caching_sha2_auth("", b"nonce").is_empty());
    }

    #[test]
    fn test_mysql_native_auth_deterministic() {
        let nonce = b"12345678901234567890";
        let a = mysql_native_auth("secret", nonce);
        let b = mysql_native_auth("secret", nonce);
        assert_eq!(a, b);
        assert_eq!(a.len(), 20);
    }

    #[test]
    fn test_caching_sha2_auth_deterministic() {
        let nonce = b"12345678901234567890";
        let a = caching_sha2_auth("secret", nonce);
        let b = caching_sha2_auth("secret", nonce);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn test_mysql_native_auth_different_passwords_differ() {
        let nonce = b"12345678901234567890";
        let a = mysql_native_auth("password1", nonce);
        let b = mysql_native_auth("password2", nonce);
        assert_ne!(a, b);
    }

    #[test]
    fn test_is_eof_packet() {
        // Classic EOF: 0xFE + up to 4 bytes warning/status
        assert!(MySqlConnection::is_eof_packet(&[
            0xFE, 0x00, 0x00, 0x00, 0x00
        ]));
        assert!(MySqlConnection::is_eof_packet(&[0xFE]));
        // Too long to be EOF (would be a legitimate data row)
        assert!(!MySqlConnection::is_eof_packet(&[0xFE; 9]));
        // Wrong marker
        assert!(!MySqlConnection::is_eof_packet(&[0x00]));
    }

    #[test]
    fn test_parse_error_non_error_packet() {
        let data = [0x00, 0x01]; // Not an error packet (0xFF)
        let err = MySqlConnection::parse_error(&data);
        assert!(matches!(err, MySqlError::Protocol(_)));
    }

    #[test]
    fn test_parse_error_with_sql_state() {
        // Error packet: 0xFF, error_code (2 bytes), '#', sql_state (5 bytes), message
        let mut data = vec![0xFF];
        data.extend_from_slice(&1045_u16.to_le_bytes()); // Access denied
        data.push(b'#');
        data.extend_from_slice(b"28000");
        data.extend_from_slice(b"Access denied for user");
        let err = MySqlConnection::parse_error(&data);
        match err {
            MySqlError::Server {
                code,
                sql_state,
                message,
            } => {
                assert_eq!(code, 1045);
                assert_eq!(sql_state, "28000");
                assert!(message.contains("Access denied"));
            }
            other => panic!("expected Server error, got: {other:?}"),
        }
    }

    #[test]
    fn test_mysql_row_get_missing_column() {
        let columns = Arc::new(vec![test_var_string_column("name")]);
        let indices = Arc::new(BTreeMap::from([("name".to_string(), 0)]));
        let row = MySqlRow {
            columns,
            column_indices: indices,
            values: vec![MySqlValue::Text("alice".to_string())],
        };
        assert!(row.get("name").is_ok());
        assert!(row.get("missing").is_err());
    }

    #[test]
    fn test_mysql_row_len_and_is_empty() {
        let columns = Arc::new(vec![test_var_string_column("a")]);
        let indices = Arc::new(BTreeMap::new());
        let row = MySqlRow {
            columns: columns.clone(),
            column_indices: indices.clone(),
            values: vec![MySqlValue::Null],
        };
        assert_eq!(row.len(), 1);
        assert!(!row.is_empty());

        let empty_row = MySqlRow {
            columns,
            column_indices: indices,
            values: vec![],
        };
        assert!(empty_row.is_empty());
    }

    #[test]
    fn test_mysql_row_type_conversion_error() {
        let columns = Arc::new(vec![test_var_string_column("name")]);
        let indices = Arc::new(BTreeMap::from([("name".to_string(), 0)]));
        let row = MySqlRow {
            columns,
            column_indices: indices,
            values: vec![MySqlValue::Text("not_a_number".to_string())],
        };
        let err = row.get_i32("name").unwrap_err();
        assert!(matches!(err, MySqlError::TypeConversion { .. }));
    }

    #[test]
    fn test_hex_nibble() {
        assert_eq!(hex_nibble(b'0'), Some(0));
        assert_eq!(hex_nibble(b'9'), Some(9));
        assert_eq!(hex_nibble(b'a'), Some(10));
        assert_eq!(hex_nibble(b'f'), Some(15));
        assert_eq!(hex_nibble(b'A'), Some(10));
        assert_eq!(hex_nibble(b'F'), Some(15));
        assert_eq!(hex_nibble(b'g'), None);
        assert_eq!(hex_nibble(b' '), None);
    }

    #[test]
    fn test_packet_buffer_write_lenenc_int_boundaries() {
        // 1-byte encoding: 0..250
        let mut buf = PacketBuffer::new();
        buf.write_lenenc_int(0);
        assert_eq!(buf.buf, vec![0]);

        buf.buf.clear();
        buf.write_lenenc_int(250);
        assert_eq!(buf.buf, vec![250]);

        // 2-byte encoding: 251..65535
        buf.buf.clear();
        buf.write_lenenc_int(256);
        assert_eq!(buf.buf[0], 0xFC);

        // 3-byte encoding: 65536..16777215
        buf.buf.clear();
        buf.write_lenenc_int(70_000);
        assert_eq!(buf.buf[0], 0xFD);

        // 8-byte encoding: >= 16777216
        buf.buf.clear();
        buf.write_lenenc_int(20_000_000);
        assert_eq!(buf.buf[0], 0xFE);
    }

    #[test]
    fn test_connect_options_no_query_params_keeps_defaults() {
        let opts = MySqlConnectOptions::parse("mysql://user@localhost/db").unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Disabled);
        assert_eq!(opts.connect_timeout, None);
    }

    #[test]
    fn test_connect_options_ipv6_bracketed_host() {
        let opts = MySqlConnectOptions::parse("mysql://user:pass@[::1]:3307/testdb").unwrap();
        assert_eq!(opts.host, "::1");
        assert_eq!(opts.port, 3307);
        assert_eq!(opts.database.as_deref(), Some("testdb"));
        assert_eq!(opts.user, "user");
    }

    #[test]
    fn test_connect_options_ipv6_bracketed_host_no_port() {
        let opts = MySqlConnectOptions::parse("mysql://user@[::1]/testdb").unwrap();
        assert_eq!(opts.host, "::1");
        assert_eq!(opts.port, 3306);
        assert_eq!(opts.database.as_deref(), Some("testdb"));
    }

    #[test]
    fn test_connect_options_ipv6_unclosed_bracket_error() {
        let err = MySqlConnectOptions::parse("mysql://user@[::1:3306/db").unwrap_err();
        match err {
            MySqlError::InvalidUrl(msg) => assert!(msg.contains("bracket"), "{msg}"),
            other => panic!("expected InvalidUrl, got {other:?}"), // ubs:ignore - test logic
        }
    }
}
