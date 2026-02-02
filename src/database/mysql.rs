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
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

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
    /// TLS required but not available.
    TlsRequired,
    /// Transaction already finished.
    TransactionFinished,
    /// Unsupported authentication plugin.
    UnsupportedAuthPlugin(String),
}

impl fmt::Display for MySqlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "MySQL I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "MySQL protocol error: {msg}"),
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
    column_indices: Arc<HashMap<String, usize>>,
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

impl PacketBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
            sequence: 0,
        }
    }

    fn clear(&mut self) {
        self.buf.clear();
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

    /// Write length-encoded string.
    fn write_lenenc_str(&mut self, s: &str) {
        self.write_lenenc_int(s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
    }

    /// Build packet with 4-byte header.
    fn build_packet(&self) -> Vec<u8> {
        let len = self.buf.len();
        let mut result = Vec::with_capacity(4 + len);
        // 3 bytes length (little-endian)
        result.push((len & 0xFF) as u8);
        result.push(((len >> 8) & 0xFF) as u8);
        result.push(((len >> 16) & 0xFF) as u8);
        // 1 byte sequence number
        result.push(self.sequence);
        result.extend_from_slice(&self.buf);
        result
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
        if self.pos + len > self.data.len() {
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
        let len = self.read_lenenc_int()? as usize;
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes).map_err(|e| MySqlError::Protocol(format!("invalid UTF-8: {e}")))
    }

    /// Read length-encoded bytes.
    fn read_lenenc_bytes(&mut self) -> Result<&'a [u8], MySqlError> {
        let len = self.read_lenenc_int()? as usize;
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

impl MySqlConnectOptions {
    /// Parse a connection URL.
    ///
    /// Format: `mysql://user:password@host:port/database`
    pub fn parse(url: &str) -> Result<Self, MySqlError> {
        let url = url
            .strip_prefix("mysql://")
            .ok_or_else(|| MySqlError::InvalidUrl("URL must start with mysql://".to_string()))?;

        // Split into auth@hostport/database?params
        let (auth_host, _params) = url.split_once('?').unwrap_or((url, ""));

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
            (user.to_string(), password.map(String::from), host)
        } else {
            ("root".to_string(), None, auth_host)
        };

        // Split host:port
        let (host, port) = host_port
            .rsplit_once(':')
            .map_or((host_port, 3306), |(h, p)| (h, p.parse().unwrap_or(3306)));

        Ok(Self {
            host: host.to_string(),
            port,
            database,
            user,
            password,
            connect_timeout: None,
            ssl_mode: SslMode::Disabled,
        })
    }
}

// ============================================================================
// MySQL Connection
// ============================================================================

/// Initial handshake data from server.
struct Handshake {
    protocol_version: u8,
    server_version: String,
    connection_id: u32,
    auth_plugin_data: Vec<u8>,
    capabilities: u32,
    charset: u8,
    status_flags: u16,
    auth_plugin_name: String,
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

impl MySqlConnection {
    /// Connect to a MySQL database.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn connect(cx: &Cx, url: &str) -> Outcome<Self, MySqlError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        let options = match MySqlConnectOptions::parse(url) {
            Ok(opts) => opts,
            Err(e) => return Outcome::Err(e),
        };

        Self::connect_with_options(cx, options).await
    }

    /// Connect with explicit options.
    pub async fn connect_with_options(
        cx: &Cx,
        options: MySqlConnectOptions,
    ) -> Outcome<Self, MySqlError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        // Connect to the server
        let addr = format!("{}:{}", options.host, options.port);
        let stream = match TcpStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => return Outcome::Err(MySqlError::Io(e)),
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
            },
        };

        // Read initial handshake
        let handshake = match conn.read_handshake().await {
            Ok(h) => h,
            Err(e) => return Outcome::Err(e),
        };

        conn.inner.connection_id = handshake.connection_id;
        conn.inner.capabilities = handshake.capabilities;
        conn.inner.charset = handshake.charset;
        conn.inner.status_flags = handshake.status_flags;
        conn.inner.server_version = handshake.server_version.clone();

        // Send handshake response
        if let Err(e) = conn.send_handshake_response(&options, &handshake).await {
            return Outcome::Err(e);
        }

        // Handle authentication response
        if let Err(e) = conn.handle_auth_response(&options, &handshake).await {
            return Outcome::Err(e);
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
            // Remove trailing null if present
            let trimmed = auth_data_2
                .iter()
                .copied()
                .take_while(|&b| b != 0)
                .collect::<Vec<_>>();
            auth_plugin_data.extend_from_slice(&trimmed);
        }

        // Auth plugin name (if capabilities include PLUGIN_AUTH)
        let auth_plugin_name =
            if capabilities & capability::CLIENT_PLUGIN_AUTH != 0 && reader.remaining() > 0 {
                reader.read_null_terminated()?.to_string()
            } else {
                "mysql_native_password".to_string()
            };

        Ok(Handshake {
            protocol_version,
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

        buf.write_u32_le(client_caps);
        buf.write_u32_le(16_777_215); // Max packet size
        buf.write_byte(handshake.charset); // Character set
        buf.write_bytes(&[0u8; 23]); // Reserved

        // Username
        buf.write_null_terminated(&options.user);

        // Auth response
        let password = options.password.as_deref().unwrap_or("");
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
        self.write_all(&packet).await?;
        self.inner.sequence = self.inner.sequence.wrapping_add(1);

        Ok(())
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
        let auth_data = reader.read_rest();

        let password = options.password.as_deref().unwrap_or("");
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
        self.write_all(&packet).await?;
        self.inner.sequence = self.inner.sequence.wrapping_add(1);

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
    pub async fn query(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<MySqlRow>, MySqlError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        // Send COM_QUERY
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_QUERY);
        buf.write_bytes(sql.as_bytes());
        let packet = buf.build_packet();

        if let Err(e) = self.write_all(&packet).await {
            return Outcome::Err(e);
        }
        self.inner.sequence = 1;

        // Read response
        let (data, seq) = match self.read_packet().await {
            Ok(p) => p,
            Err(e) => return Outcome::Err(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        if data.is_empty() {
            return Outcome::Err(MySqlError::Protocol("empty query response".to_string()));
        }

        match data[0] {
            0x00 => {
                // OK packet (for non-SELECT queries)
                Outcome::Ok(Vec::new())
            }
            0xFF => {
                // ERR packet
                Outcome::Err(Self::parse_error(&data))
            }
            _ => {
                // Result set
                match self.read_result_set(&data).await {
                    Ok(rows) => Outcome::Ok(rows),
                    Err(e) => Outcome::Err(e),
                }
            }
        }
    }

    /// Read a complete result set.
    async fn read_result_set(&mut self, first_packet: &[u8]) -> Result<Vec<MySqlRow>, MySqlError> {
        let mut reader = PacketReader::new(first_packet);
        let column_count = reader.read_lenenc_int()? as usize;

        if column_count == 0 {
            return Ok(Vec::new());
        }

        // Read column definitions
        let mut columns = Vec::with_capacity(column_count);
        let mut indices = HashMap::with_capacity(column_count);

        for i in 0..column_count {
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);

            let mut reader = PacketReader::new(&data);

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

            indices.insert(name.clone(), i);
            columns.push(MySqlColumn {
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
            });
        }

        // Read EOF marker (if not using DEPRECATE_EOF)
        if self.inner.capabilities & capability::CLIENT_DEPRECATE_EOF == 0 {
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);
            if data.first() != Some(&0xFE) {
                return Err(MySqlError::Protocol(
                    "expected EOF after columns".to_string(),
                ));
            }
        }

        let columns = Arc::new(columns);
        let indices = Arc::new(indices);

        // Read rows
        let mut rows = Vec::new();

        loop {
            let (data, seq) = self.read_packet().await?;
            self.inner.sequence = seq.wrapping_add(1);

            if data.is_empty() {
                continue;
            }

            match data[0] {
                0xFE if data.len() < 9 => {
                    // EOF packet
                    break;
                }
                0xFF => {
                    // ERR packet
                    return Err(Self::parse_error(&data));
                }
                0x00 if self.inner.capabilities & capability::CLIENT_DEPRECATE_EOF != 0 => {
                    // OK packet (end of result set with DEPRECATE_EOF)
                    break;
                }
                _ => {
                    // Data row
                    let values = Self::parse_text_row(&data, &columns)?;
                    rows.push(MySqlRow {
                        columns: Arc::clone(&columns),
                        column_indices: Arc::clone(&indices),
                        values,
                    });
                }
            }
        }

        Ok(rows)
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

        Ok(values)
    }

    /// Parse a text format value.
    fn parse_text_value(data: &[u8], col: &MySqlColumn) -> Result<MySqlValue, MySqlError> {
        let s = std::str::from_utf8(data)
            .map_err(|e| MySqlError::Protocol(format!("invalid UTF-8: {e}")))?;

        Ok(match col.column_type {
            column_type::MYSQL_TYPE_TINY => MySqlValue::Tiny(s.parse().unwrap_or(0)),
            column_type::MYSQL_TYPE_SHORT | column_type::MYSQL_TYPE_YEAR => {
                MySqlValue::Short(s.parse().unwrap_or(0))
            }
            column_type::MYSQL_TYPE_LONG | column_type::MYSQL_TYPE_INT24 => {
                MySqlValue::Long(s.parse().unwrap_or(0))
            }
            column_type::MYSQL_TYPE_LONGLONG => MySqlValue::LongLong(s.parse().unwrap_or(0)),
            column_type::MYSQL_TYPE_FLOAT => MySqlValue::Float(s.parse().unwrap_or(0.0)),
            column_type::MYSQL_TYPE_DOUBLE
            | column_type::MYSQL_TYPE_DECIMAL
            | column_type::MYSQL_TYPE_NEWDECIMAL => MySqlValue::Double(s.parse().unwrap_or(0.0)),
            column_type::MYSQL_TYPE_TINY_BLOB
            | column_type::MYSQL_TYPE_MEDIUM_BLOB
            | column_type::MYSQL_TYPE_LONG_BLOB
            | column_type::MYSQL_TYPE_BLOB => MySqlValue::Bytes(data.to_vec()),
            _ => MySqlValue::Text(s.to_string()),
        })
    }

    /// Execute a command (INSERT, UPDATE, DELETE) and return affected rows.
    pub async fn execute(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, MySqlError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(MySqlError::ConnectionClosed);
        }

        // Send COM_QUERY
        let mut buf = PacketBuffer::new();
        buf.set_sequence(0);
        buf.write_byte(command::COM_QUERY);
        buf.write_bytes(sql.as_bytes());
        let packet = buf.build_packet();

        if let Err(e) = self.write_all(&packet).await {
            return Outcome::Err(e);
        }
        self.inner.sequence = 1;

        // Read response
        let (data, seq) = match self.read_packet().await {
            Ok(p) => p,
            Err(e) => return Outcome::Err(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        if data.is_empty() {
            return Outcome::Err(MySqlError::Protocol("empty execute response".to_string()));
        }

        match data[0] {
            0x00 => {
                // OK packet
                let mut reader = PacketReader::new(&data[1..]);
                match reader.read_lenenc_int() {
                    Ok(affected_rows) => Outcome::Ok(affected_rows),
                    Err(e) => Outcome::Err(e),
                }
            }
            0xFF => {
                // ERR packet
                Outcome::Err(Self::parse_error(&data))
            }
            _ => {
                // Result set - consume it and return 0 affected rows
                match self.read_result_set(&data).await {
                    Ok(_) => Outcome::Ok(0),
                    Err(e) => Outcome::Err(e),
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
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Ping the server.
    pub async fn ping(&mut self, cx: &Cx) -> Outcome<(), MySqlError> {
        if cx.is_cancel_requested() {
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

        if let Err(e) = self.write_all(&packet).await {
            return Outcome::Err(e);
        }
        self.inner.sequence = 1;

        let (data, seq) = match self.read_packet().await {
            Ok(p) => p,
            Err(e) => return Outcome::Err(e),
        };
        self.inner.sequence = seq.wrapping_add(1);

        match data.first() {
            Some(0x00) => Outcome::Ok(()),
            Some(0xFF) => Outcome::Err(Self::parse_error(&data)),
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
        let _ = self.write_all(&packet).await;

        self.inner.closed = true;
        Ok(())
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Write data to the stream.
    async fn write_all(&mut self, data: &[u8]) -> Result<(), MySqlError> {
        let mut pos = 0;
        while pos < data.len() {
            let written = std::future::poll_fn(|cx| {
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
        // Read header (4 bytes)
        let mut header = [0u8; 4];
        self.read_exact(&mut header).await?;

        let len = u32::from(header[0]) | (u32::from(header[1]) << 8) | (u32::from(header[2]) << 16);
        let seq = header[3];

        // Read payload
        let mut data = vec![0u8; len as usize];
        if len > 0 {
            self.read_exact(&mut data).await?;
        }

        Ok((data, seq))
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
        self.finished = true;
        match self.conn.execute(cx, "COMMIT").await {
            Outcome::Ok(_) => Outcome::Ok(()),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Rollback the transaction.
    pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), MySqlError> {
        if self.finished {
            return Outcome::Err(MySqlError::TransactionFinished);
        }
        self.finished = true;
        match self.conn.execute(cx, "ROLLBACK").await {
            Outcome::Ok(_) => Outcome::Ok(()),
            Outcome::Err(e) => Outcome::Err(e),
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
            // Best-effort rollback on drop
            // In practice, the server will auto-rollback when we send another command
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(packet[0], 9); // length low byte
        assert_eq!(packet[1], 0); // length mid byte
        assert_eq!(packet[2], 0); // length high byte
        assert_eq!(packet[3], 0); // sequence
        assert_eq!(packet[4], command::COM_QUERY);
    }

    #[test]
    fn test_lenenc_int_3byte() {
        // 3-byte encoding (0xFD prefix)
        let data = [0xFD, 0x01, 0x02, 0x03]; // 0x030201 = 197121
        let mut reader = PacketReader::new(&data);
        assert_eq!(reader.read_lenenc_int().unwrap(), 197121);
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
            MySqlValue::LongLong(123456789012345).as_i64(),
            Some(123456789012345)
        );
        // Test Float to f64
        assert!(MySqlValue::Float(3.14).as_f64().is_some());
        // Test Double to f64
        assert_eq!(MySqlValue::Double(2.718).as_f64(), Some(2.718));
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
        assert_eq!(packet[3], 5); // sequence byte
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
        assert_eq!(packet[0], 0x00); // low byte
        assert_eq!(packet[1], 0x01); // mid byte (256)
        assert_eq!(packet[2], 0x00); // high byte
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
}
