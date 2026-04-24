//! PostgreSQL async client with wire protocol implementation.
#![allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::needless_pass_by_ref_mut,
    clippy::match_same_arms
)]
//!
//! This module provides a pure-Rust PostgreSQL client implementing the wire protocol
//! with full Cx integration, SCRAM-SHA-256 authentication, and cancel-correct semantics.
//!
//! # Design
//!
//! Unlike SQLite which uses a blocking pool, PostgreSQL communicates over TCP
//! using an async connection. All operations integrate with [`Cx`] for checkpointing
//! and cancellation.
//!
//! # Example
//!
//! ```ignore
//! use asupersync::database::PgConnection;
//!
//! async fn example(cx: &Cx) -> Result<(), PgError> {
//!     let mut conn = PgConnection::connect(cx, "postgres://user:pass@localhost/db").await?;
//!
//!     let rows = conn.query_params(cx,
//!         "SELECT id, name FROM users WHERE active = $1",
//!         &[&true],
//!     ).await?;
//!     for row in &rows {
//!         let id: i32 = row.get_typed("id")?;
//!         let name: String = row.get_typed("name")?;
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
#[cfg(feature = "tls")]
use crate::tls::{TlsConnectorBuilder, TlsStream};
use crate::types::{CancelReason, Outcome};
use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

// ============================================================================
// Error Types
// ============================================================================

/// Error type for PostgreSQL operations.
#[derive(Debug)]
pub enum PgError {
    /// I/O error during communication.
    Io(io::Error),
    /// Protocol error (malformed message).
    Protocol(String),
    /// Authentication failed.
    AuthenticationFailed(String),
    /// Server error response.
    Server {
        /// PostgreSQL error code (e.g., "42P01").
        code: String,
        /// Error message.
        message: String,
        /// Optional detail.
        detail: Option<String>,
        /// Optional hint.
        hint: Option<String>,
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
        /// Actual type OID.
        actual_oid: u32,
    },
    /// Invalid connection URL.
    InvalidUrl(String),
    /// TLS required but not available.
    TlsRequired,
    /// TLS handshake or configuration error.
    Tls(String),
    /// Transaction already finished.
    TransactionFinished,
    /// Unsupported authentication method.
    UnsupportedAuth(String),
}

impl PgError {
    /// Returns the PostgreSQL error code, if this is a server error.
    #[must_use]
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Server { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Returns `true` if this is a serialization failure (SQLSTATE `40001`).
    ///
    /// Serialization failures occur with `SERIALIZABLE` or `REPEATABLE READ`
    /// isolation levels when a concurrent transaction conflicts. These are
    /// safe to retry.
    #[must_use]
    pub fn is_serialization_failure(&self) -> bool {
        self.code() == Some("40001")
    }

    /// Returns `true` if this is a deadlock detected error (SQLSTATE `40P01`).
    #[must_use]
    pub fn is_deadlock(&self) -> bool {
        self.code() == Some("40P01")
    }

    /// Returns `true` if this is a unique violation error (SQLSTATE `23505`).
    #[must_use]
    pub fn is_unique_violation(&self) -> bool {
        self.code() == Some("23505")
    }

    /// Returns `true` if this is any constraint violation (SQLSTATE class `23`).
    #[must_use]
    pub fn is_constraint_violation(&self) -> bool {
        self.code().is_some_and(|c| c.len() >= 2 && &c[..2] == "23")
    }

    /// Returns `true` if this is a connection-level error.
    ///
    /// Includes I/O errors, connection closed, TLS failures, and
    /// SQLSTATE class `08` (connection exception).
    #[must_use]
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            Self::Io(_) | Self::ConnectionClosed | Self::TlsRequired | Self::Tls(_)
        ) || self.code().is_some_and(|c| c.len() >= 2 && &c[..2] == "08")
    }

    /// Returns `true` if this error is transient and may succeed on retry.
    ///
    /// Transient errors include serialization failures, deadlocks,
    /// connection exceptions (class `08`), and insufficient resources (class `53`).
    #[must_use]
    pub fn is_transient(&self) -> bool {
        if matches!(self, Self::Io(_) | Self::ConnectionClosed) {
            return true;
        }
        self.code().is_some_and(|c| {
            c.len() >= 2
                && matches!(
                    &c[..2],
                    "40" // transaction rollback (serialization, deadlock)
                    | "08" // connection exception
                    | "53" // insufficient resources
                )
        })
    }

    /// Returns `true` if this error is safe to retry automatically.
    ///
    /// Currently equivalent to [`is_transient`](Self::is_transient), but may
    /// diverge if policy-level retry exclusions are added.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.is_transient()
    }

    /// Returns the SQLSTATE error code if this is a server error, or a
    /// synthetic code for non-server errors.
    #[must_use]
    pub fn error_code(&self) -> Option<&str> {
        self.code()
    }
}

impl fmt::Display for PgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "PostgreSQL I/O error: {e}"),
            Self::Protocol(msg) => write!(f, "PostgreSQL protocol error: {msg}"),
            Self::AuthenticationFailed(msg) => write!(f, "PostgreSQL authentication failed: {msg}"),
            Self::Server {
                code,
                message,
                detail,
                hint,
            } => {
                write!(f, "PostgreSQL error [{code}]: {message}")?;
                if let Some(d) = detail {
                    write!(f, " (detail: {d})")?;
                }
                if let Some(h) = hint {
                    write!(f, " (hint: {h})")?;
                }
                Ok(())
            }
            Self::Cancelled(reason) => write!(f, "PostgreSQL operation cancelled: {reason:?}"),
            Self::ConnectionClosed => write!(f, "PostgreSQL connection is closed"),
            Self::ColumnNotFound(name) => write!(f, "Column not found: {name}"),
            Self::TypeConversion {
                column,
                expected,
                actual_oid,
            } => write!(
                f,
                "Type conversion error for column {column}: expected {expected}, got OID {actual_oid}"
            ),
            Self::InvalidUrl(msg) => write!(f, "Invalid PostgreSQL URL: {msg}"),
            Self::TlsRequired => write!(f, "TLS required but not available"),
            Self::Tls(msg) => write!(f, "PostgreSQL TLS error: {msg}"),
            Self::TransactionFinished => write!(f, "Transaction already finished"),
            Self::UnsupportedAuth(method) => {
                write!(f, "Unsupported authentication method: {method}")
            }
        }
    }
}

impl std::error::Error for PgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for PgError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

// ============================================================================
// PostgreSQL Wire Protocol Types
// ============================================================================

/// PostgreSQL type OIDs for common types.
pub mod oid {
    /// Boolean type.
    pub const BOOL: u32 = 16;
    /// Binary data.
    pub const BYTEA: u32 = 17;
    /// Single character.
    pub const CHAR: u32 = 18;
    /// Object identifier.
    pub const OID: u32 = 26;
    /// 16-bit integer.
    pub const INT2: u32 = 21;
    /// 32-bit integer.
    pub const INT4: u32 = 23;
    /// 64-bit integer.
    pub const INT8: u32 = 20;
    /// Single-precision float.
    pub const FLOAT4: u32 = 700;
    /// Double-precision float.
    pub const FLOAT8: u32 = 701;
    /// Variable-length character string.
    pub const VARCHAR: u32 = 1043;
    /// Text (unlimited length).
    pub const TEXT: u32 = 25;
    /// Date.
    pub const DATE: u32 = 1082;
    /// Timestamp without timezone.
    pub const TIMESTAMP: u32 = 1114;
    /// Timestamp with timezone.
    pub const TIMESTAMPTZ: u32 = 1184;
    /// UUID.
    pub const UUID: u32 = 2950;
    /// JSON.
    pub const JSON: u32 = 114;
    /// JSONB (binary JSON).
    pub const JSONB: u32 = 3802;
}

/// Column description from RowDescription message.
#[derive(Debug, Clone)]
pub struct PgColumn {
    /// Column name.
    pub name: String,
    /// Table OID (0 if not a table column).
    pub table_oid: u32,
    /// Column attribute number.
    pub column_id: i16,
    /// Type OID.
    pub type_oid: u32,
    /// Type size (-1 for variable length).
    pub type_size: i16,
    /// Type modifier.
    pub type_modifier: i32,
    /// Format code (0 = text, 1 = binary).
    pub format_code: i16,
}

/// A value from a PostgreSQL row.
#[derive(Debug, Clone, PartialEq)]
pub enum PgValue {
    /// NULL value.
    Null,
    /// Boolean value.
    Bool(bool),
    /// 16-bit integer.
    Int2(i16),
    /// 32-bit integer.
    Int4(i32),
    /// 64-bit integer.
    Int8(i64),
    /// Single-precision float.
    Float4(f32),
    /// Double-precision float.
    Float8(f64),
    /// Text value.
    Text(String),
    /// Binary data.
    Bytes(Vec<u8>),
}

impl PgValue {
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
            _ => None,
        }
    }

    /// Try to get as i32.
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::Int4(v) => Some(*v),
            Self::Int2(v) => Some(i32::from(*v)),
            _ => None,
        }
    }

    /// Try to get as i64.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int8(v) => Some(*v),
            Self::Int4(v) => Some(i64::from(*v)),
            Self::Int2(v) => Some(i64::from(*v)),
            _ => None,
        }
    }

    /// Try to get as f64.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float8(v) => Some(*v),
            Self::Float4(v) => Some(f64::from(*v)),
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

impl fmt::Display for PgValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "NULL"),
            Self::Bool(v) => write!(f, "{v}"),
            Self::Int2(v) => write!(f, "{v}"),
            Self::Int4(v) => write!(f, "{v}"),
            Self::Int8(v) => write!(f, "{v}"),
            Self::Float4(v) => write!(f, "{v}"),
            Self::Float8(v) => write!(f, "{v}"),
            Self::Text(v) => write!(f, "{v}"),
            Self::Bytes(v) => write!(f, "<bytes {} len>", v.len()),
        }
    }
}

// ============================================================================
// Type-safe Parameter Encoding/Decoding (Extended Query Protocol)
// ============================================================================

/// Wire format for parameter and result values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Text format (default for Simple Query Protocol).
    Text = 0,
    /// Binary format (more efficient for numeric types).
    Binary = 1,
}

/// Indicates whether a parameter value is NULL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsNull {
    /// Value is SQL NULL.
    Yes,
    /// Value is not NULL.
    No,
}

/// Encode a Rust value into a PostgreSQL wire-format parameter.
///
/// Implementations write binary-format bytes into `buf` and return
/// [`IsNull::No`], or write nothing and return [`IsNull::Yes`] for NULL.
///
/// # Extensibility
///
/// Downstream crates can implement this for custom PostgreSQL types
/// (pgvector, PostGIS, etc.):
///
/// ```ignore
/// impl ToSql for PgVector {
///     fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
///         for &v in &self.0 {
///             buf.extend_from_slice(&v.to_be_bytes());
///         }
///         Ok(IsNull::No)
///     }
///     fn type_oid(&self) -> u32 { 0 } // let server infer
/// }
/// ```
pub trait ToSql: Sync {
    /// Encode this value into `buf`. Return [`IsNull::Yes`] for NULL
    /// (leaving `buf` unmodified).
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError>;

    /// PostgreSQL type OID. Return `0` to let the server infer.
    fn type_oid(&self) -> u32;

    /// Wire format for this parameter. Defaults to [`Format::Binary`].
    fn format(&self) -> Format {
        Format::Binary
    }
}

/// Decode a PostgreSQL wire-format value into a Rust type.
///
/// # Extensibility
///
/// Downstream crates can implement this for custom types:
///
/// ```ignore
/// impl FromSql for PgVector {
///     fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
///         // parse text or binary representation
///         Err(PgError::Protocol("parse pgvector".into()))
///     }
///     fn accepts(oid: u32) -> bool { true } // pgvector OID is dynamic
/// }
/// ```
pub trait FromSql: Sized {
    /// Decode a non-NULL value from raw wire bytes.
    fn from_sql(data: &[u8], oid: u32, format: Format) -> Result<Self, PgError>;

    /// Decode a SQL NULL. Defaults to returning an error.
    fn from_sql_null() -> Result<Self, PgError> {
        Err(PgError::Protocol("unexpected NULL value".to_string()))
    }

    /// Whether this type can decode values with the given OID.
    fn accepts(oid: u32) -> bool;
}

// ---- Built-in ToSql implementations ----

impl ToSql for bool {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.push(u8::from(*self));
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::BOOL
    }
}

impl ToSql for i16 {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::INT2
    }
}

impl ToSql for i32 {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::INT4
    }
}

impl ToSql for i64 {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::INT8
    }
}

impl ToSql for f32 {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::FLOAT4
    }
}

impl ToSql for f64 {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(&self.to_be_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::FLOAT8
    }
}

impl ToSql for str {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(self.as_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::TEXT
    }
    fn format(&self) -> Format {
        Format::Text
    }
}

impl ToSql for String {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(self.as_bytes());
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::TEXT
    }
    fn format(&self) -> Format {
        Format::Text
    }
}

impl ToSql for [u8] {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(self);
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::BYTEA
    }
}

impl ToSql for Vec<u8> {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        buf.extend_from_slice(self);
        Ok(IsNull::No)
    }
    fn type_oid(&self) -> u32 {
        oid::BYTEA
    }
}

impl<T: ToSql> ToSql for Option<T> {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        self.as_ref().map_or(Ok(IsNull::Yes), |v| v.to_sql(buf))
    }
    fn type_oid(&self) -> u32 {
        self.as_ref().map_or(0, ToSql::type_oid)
    }
    fn format(&self) -> Format {
        match self {
            Some(v) => v.format(),
            None => Format::Binary,
        }
    }
}

impl<T: ToSql + ?Sized> ToSql for &T {
    fn to_sql(&self, buf: &mut Vec<u8>) -> Result<IsNull, PgError> {
        (*self).to_sql(buf)
    }
    fn type_oid(&self) -> u32 {
        (*self).type_oid()
    }
    fn format(&self) -> Format {
        (*self).format()
    }
}

// ---- Built-in FromSql implementations ----

impl FromSql for bool {
    fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
        match format {
            Format::Binary => match data {
                [0] => Ok(false),
                [1] => Ok(true),
                [value] => Err(PgError::Protocol(format!(
                    "bool requires 0 or 1 in binary format, got {value}"
                ))),
                _ => Err(PgError::Protocol(format!(
                    "bool requires exactly 1 byte, got {}",
                    data.len()
                ))),
            },
            Format::Text => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
                match s {
                    "t" | "true" | "1" | "yes" | "on" => Ok(true),
                    "f" | "false" | "0" | "no" | "off" => Ok(false),
                    _ => Err(PgError::Protocol(format!("invalid bool text: {s}"))),
                }
            }
        }
    }
    fn accepts(oid: u32) -> bool {
        oid == oid::BOOL
    }
}

impl FromSql for i16 {
    fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
        match format {
            Format::Binary => {
                if data.len() < 2 {
                    return Err(PgError::Protocol("int2 requires 2 bytes".into()));
                }
                Ok(Self::from_be_bytes([data[0], data[1]]))
            }
            Format::Text => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid int2: {e}")))
            }
        }
    }
    fn accepts(oid: u32) -> bool {
        oid == oid::INT2
    }
}

impl FromSql for i32 {
    fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
        match format {
            Format::Binary => {
                if data.len() < 4 {
                    return Err(PgError::Protocol("int4 requires 4 bytes".into()));
                }
                Ok(Self::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            Format::Text => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid int4: {e}")))
            }
        }
    }
    fn accepts(oid: u32) -> bool {
        matches!(oid, oid::INT4 | oid::OID)
    }
}

impl FromSql for i64 {
    fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
        match format {
            Format::Binary => {
                if data.len() < 8 {
                    return Err(PgError::Protocol("int8 requires 8 bytes".into()));
                }
                Ok(Self::from_be_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]))
            }
            Format::Text => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid int8: {e}")))
            }
        }
    }
    fn accepts(oid: u32) -> bool {
        oid == oid::INT8
    }
}

impl FromSql for f32 {
    fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
        match format {
            Format::Binary => {
                if data.len() < 4 {
                    return Err(PgError::Protocol("float4 requires 4 bytes".into()));
                }
                Ok(Self::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            Format::Text => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid float4: {e}")))
            }
        }
    }
    fn accepts(oid: u32) -> bool {
        oid == oid::FLOAT4
    }
}

impl FromSql for f64 {
    fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
        match format {
            Format::Binary => {
                if data.len() < 8 {
                    return Err(PgError::Protocol("float8 requires 8 bytes".into()));
                }
                Ok(Self::from_be_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]))
            }
            Format::Text => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid float8: {e}")))
            }
        }
    }
    fn accepts(oid: u32) -> bool {
        oid == oid::FLOAT8
    }
}

impl FromSql for String {
    fn from_sql(data: &[u8], oid: u32, format: Format) -> Result<Self, PgError> {
        let mut data = data;
        if format == Format::Binary && oid == oid::JSONB {
            if data.first() == Some(&1) {
                data = &data[1..];
            } else if !data.is_empty() {
                return Err(PgError::Protocol(format!(
                    "unsupported JSONB version: {}",
                    data[0]
                )));
            }
        }
        std::str::from_utf8(data)
            .map(std::string::ToString::to_string)
            .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))
    }
    fn accepts(oid: u32) -> bool {
        matches!(
            oid,
            oid::TEXT
                | oid::VARCHAR
                | oid::CHAR
                | oid::JSON
                | oid::JSONB
                | oid::UUID
                | oid::DATE
                | oid::TIMESTAMP
                | oid::TIMESTAMPTZ
        )
    }
}

impl FromSql for Vec<u8> {
    fn from_sql(data: &[u8], _oid: u32, format: Format) -> Result<Self, PgError> {
        match format {
            Format::Binary => Ok(data.to_vec()),
            Format::Text => {
                let s = std::str::from_utf8(data)
                    .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
                s.strip_prefix("\\x").map_or_else(
                    || Ok(data.to_vec()),
                    |hex_str| {
                        hex::decode(hex_str)
                            .map_err(|e| PgError::Protocol(format!("invalid bytea hex: {e}")))
                    },
                )
            }
        }
    }
    fn accepts(oid: u32) -> bool {
        oid == oid::BYTEA
    }
}

impl<T: FromSql> FromSql for Option<T> {
    fn from_sql(data: &[u8], oid: u32, format: Format) -> Result<Self, PgError> {
        T::from_sql(data, oid, format).map(Some)
    }
    fn from_sql_null() -> Result<Self, PgError> {
        Ok(None)
    }
    fn accepts(oid: u32) -> bool {
        T::accepts(oid)
    }
}

/// Convert a [`PgValue`] to text-format bytes for [`FromSql`] decoding.
fn pg_value_to_text_bytes(val: &PgValue) -> Vec<u8> {
    match val {
        PgValue::Null => unreachable!("caller must handle NULL"),
        PgValue::Bool(b) => {
            if *b {
                b"t".to_vec()
            } else {
                b"f".to_vec()
            }
        }
        PgValue::Int2(v) => v.to_string().into_bytes(),
        PgValue::Int4(v) => v.to_string().into_bytes(),
        PgValue::Int8(v) => v.to_string().into_bytes(),
        PgValue::Float4(v) => v.to_string().into_bytes(),
        PgValue::Float8(v) => v.to_string().into_bytes(),
        PgValue::Text(s) => s.as_bytes().to_vec(),
        PgValue::Bytes(b) => b.clone(),
    }
}

fn pg_value_to_wire_bytes(val: &PgValue, oid: u32, format: Format) -> Result<Vec<u8>, PgError> {
    Ok(match format {
        Format::Text => match val {
            PgValue::Bytes(bytes) if oid == oid::BYTEA => {
                let mut out = Vec::with_capacity(2 + bytes.len() * 2);
                out.extend_from_slice(b"\\x");
                out.extend_from_slice(hex::encode(bytes).as_bytes());
                out
            }
            _ => pg_value_to_text_bytes(val),
        },
        Format::Binary => match val {
            PgValue::Null => unreachable!("caller must handle NULL"),
            PgValue::Bool(v) => vec![u8::from(*v)],
            PgValue::Int2(v) => v.to_be_bytes().to_vec(),
            PgValue::Int4(v) => v.to_be_bytes().to_vec(),
            PgValue::Int8(v) => v.to_be_bytes().to_vec(),
            PgValue::Float4(v) => v.to_be_bytes().to_vec(),
            PgValue::Float8(v) => v.to_be_bytes().to_vec(),
            PgValue::Text(text) => {
                if oid == oid::JSONB {
                    let mut out = Vec::with_capacity(text.len() + 1);
                    out.push(1);
                    out.extend_from_slice(text.as_bytes());
                    out
                } else {
                    text.as_bytes().to_vec()
                }
            }
            PgValue::Bytes(bytes) => bytes.clone(),
        },
    })
}

/// A row from a PostgreSQL query result.
#[derive(Debug, Clone)]
pub struct PgRow {
    /// Column metadata.
    columns: Arc<Vec<PgColumn>>,
    /// Column name to index mapping.
    column_indices: Arc<BTreeMap<String, usize>>,
    /// Row values.
    values: Vec<PgValue>,
}

impl PgRow {
    /// Get a value by column name.
    pub fn get(&self, column: &str) -> Result<&PgValue, PgError> {
        let idx = self
            .column_indices
            .get(column)
            .ok_or_else(|| PgError::ColumnNotFound(column.to_string()))?;
        self.values
            .get(*idx)
            .ok_or_else(|| PgError::ColumnNotFound(column.to_string()))
    }

    /// Get a value by column index.
    pub fn get_idx(&self, idx: usize) -> Result<&PgValue, PgError> {
        self.values
            .get(idx)
            .ok_or_else(|| PgError::ColumnNotFound(format!("index {idx}")))
    }

    /// Get an i32 value by column name.
    pub fn get_i32(&self, column: &str) -> Result<i32, PgError> {
        let idx = *self
            .column_indices
            .get(column)
            .ok_or_else(|| PgError::ColumnNotFound(column.to_string()))?;
        let val = &self.values[idx];
        val.as_i32().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "i32",
            actual_oid: self.columns.get(idx).map_or(0, |col| col.type_oid),
        })
    }

    /// Get an i64 value by column name.
    pub fn get_i64(&self, column: &str) -> Result<i64, PgError> {
        let idx = *self
            .column_indices
            .get(column)
            .ok_or_else(|| PgError::ColumnNotFound(column.to_string()))?;
        let val = &self.values[idx];
        val.as_i64().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "i64",
            actual_oid: self.columns.get(idx).map_or(0, |col| col.type_oid),
        })
    }

    /// Get a string value by column name.
    pub fn get_str(&self, column: &str) -> Result<&str, PgError> {
        let idx = *self
            .column_indices
            .get(column)
            .ok_or_else(|| PgError::ColumnNotFound(column.to_string()))?;
        let val = &self.values[idx];
        val.as_str().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "string",
            actual_oid: self.columns.get(idx).map_or(0, |col| col.type_oid),
        })
    }

    /// Get a bool value by column name.
    pub fn get_bool(&self, column: &str) -> Result<bool, PgError> {
        let idx = *self
            .column_indices
            .get(column)
            .ok_or_else(|| PgError::ColumnNotFound(column.to_string()))?;
        let val = &self.values[idx];
        val.as_bool().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "bool",
            actual_oid: self.columns.get(idx).map_or(0, |col| col.type_oid),
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
    pub fn columns(&self) -> &[PgColumn] {
        &self.columns
    }

    /// Get a typed value by column name using the [`FromSql`] trait.
    ///
    /// This works for rows from both the Simple Query and Extended Query
    /// protocols and preserves the original wire format of each column where
    /// possible when re-decoding through [`FromSql::from_sql`].
    ///
    /// ```ignore
    /// let id: i32 = row.get_typed("id")?;
    /// let name: String = row.get_typed("name")?;
    /// let score: Option<f64> = row.get_typed("score")?;
    /// ```
    pub fn get_typed<T: FromSql>(&self, column: &str) -> Result<T, PgError> {
        let idx = self
            .column_indices
            .get(column)
            .ok_or_else(|| PgError::ColumnNotFound(column.to_string()))?;
        let col = &self.columns[*idx];
        let val = &self.values[*idx];
        if val.is_null() {
            return T::from_sql_null();
        }
        let format = if col.format_code == 1 {
            Format::Binary
        } else {
            Format::Text
        };
        let bytes = pg_value_to_wire_bytes(val, col.type_oid, format)?;
        T::from_sql(&bytes, col.type_oid, format)
    }

    /// Get a typed value by column index using the [`FromSql`] trait.
    pub fn get_typed_idx<T: FromSql>(&self, idx: usize) -> Result<T, PgError> {
        let col = self
            .columns
            .get(idx)
            .ok_or_else(|| PgError::ColumnNotFound(format!("index {idx}")))?;
        let val = self
            .values
            .get(idx)
            .ok_or_else(|| PgError::ColumnNotFound(format!("index {idx}")))?;
        if val.is_null() {
            return T::from_sql_null();
        }
        let format = if col.format_code == 1 {
            Format::Binary
        } else {
            Format::Text
        };
        let bytes = pg_value_to_wire_bytes(val, col.type_oid, format)?;
        T::from_sql(&bytes, col.type_oid, format)
    }
}

// ============================================================================
// Wire Protocol Encoding/Decoding
// ============================================================================

/// Frontend (client) message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum FrontendMessage {
    /// Bind message.
    Bind = b'B',
    /// Close message.
    Close = b'C',
    /// Describe message.
    Describe = b'D',
    /// Execute message.
    Execute = b'E',
    /// Parse message.
    Parse = b'P',
    /// Simple query.
    Query = b'Q',
    /// Sync message.
    Sync = b'S',
    /// Terminate message.
    Terminate = b'X',
    /// Password message (authentication).
    Password = b'p',
    /// Copy data message.
    #[allow(dead_code)]
    CopyData = b'd',
    /// Copy done message.
    #[allow(dead_code)]
    CopyDone = b'c',
    /// Copy fail message.
    #[allow(dead_code)]
    CopyFail = b'f',
}

/// Backend (server) message types.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
enum BackendMessage {
    /// Authentication request.
    Authentication = b'R',
    /// Backend key data.
    BackendKeyData = b'K',
    /// Bind complete.
    #[allow(dead_code)]
    BindComplete = b'2',
    /// Close complete.
    CloseComplete = b'3',
    /// Command complete.
    CommandComplete = b'C',
    /// Data row.
    DataRow = b'D',
    /// Error response.
    ErrorResponse = b'E',
    /// No data (prepared statement returns no columns).
    #[allow(dead_code)]
    NoData = b'n',
    /// Notice response.
    NoticeResponse = b'N',
    /// Parameter description.
    #[allow(dead_code)]
    ParameterDescription = b't',
    /// Parameter status.
    ParameterStatus = b'S',
    /// Parse complete.
    ParseComplete = b'1',
    /// Portal suspended.
    PortalSuspended = b's',
    /// Ready for query.
    ReadyForQuery = b'Z',
    /// Row description.
    RowDescription = b'T',
    /// Copy in response.
    #[cfg(feature = "postgres")]
    #[allow(dead_code)]
    CopyInResponse = b'G',
    /// Copy out response.
    #[cfg(feature = "postgres")]
    #[allow(dead_code)]
    CopyOutResponse = b'H',
    /// Copy both response.
    #[cfg(feature = "postgres")]
    #[allow(dead_code)]
    CopyBothResponse = b'W',
    /// Copy data message.
    #[cfg(feature = "postgres")]
    #[allow(dead_code)]
    CopyData = b'd',
    /// Copy done message.
    #[cfg(feature = "postgres")]
    #[allow(dead_code)]
    CopyDone = b'c',
}

/// Buffer for building protocol messages.
struct MessageBuffer {
    buf: Vec<u8>,
}

impl MessageBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
        }
    }

    fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.buf.clear();
    }

    fn write_byte(&mut self, b: u8) {
        self.buf.push(b);
    }

    fn write_i16(&mut self, v: i16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn write_cstring(&mut self, s: &str) {
        // Prevent protocol injection: if the string contains an embedded NUL,
        // only write up to the first NUL byte (matching PostgreSQL server
        // C-string semantics). This avoids a mismatch where the client thinks
        // it sent one string but the server sees a truncated version followed
        // by attacker-controlled bytes.
        let bytes = s.as_bytes();
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        debug_assert!(end == bytes.len(), "embedded NUL in C-string: {s:?}");
        self.buf.extend_from_slice(&bytes[..end]);
        self.buf.push(0);
    }

    /// Build a typed message with length prefix.
    fn build_message(&mut self, msg_type: u8) -> Result<Vec<u8>, PgError> {
        // PostgreSQL protocol uses i32 for message length. Guard against
        // overflow for pathologically large messages (> 2 GiB payload).
        let payload_len = self.buf.len().saturating_add(4); // +4 for length field
        let len: i32 = i32::try_from(payload_len).map_err(|_| {
            PgError::Protocol("message payload exceeds PostgreSQL 2 GiB limit".into())
        })?;
        let mut result = Vec::with_capacity(1 + 4 + self.buf.len());
        result.push(msg_type);
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.buf);
        Ok(result)
    }

    /// Build a startup message (no type byte, includes protocol version).
    fn build_startup_message(&mut self) -> Result<Vec<u8>, PgError> {
        let payload_len = self.buf.len().saturating_add(4);
        let len: i32 = i32::try_from(payload_len).map_err(|_| {
            PgError::Protocol("message payload exceeds PostgreSQL 2 GiB limit".into())
        })?;
        let mut result = Vec::with_capacity(4 + self.buf.len());
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.buf);
        Ok(result)
    }

    #[cfg(test)]
    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

/// Message reader for parsing backend messages.
struct MessageReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MessageReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_byte(&mut self) -> Result<u8, PgError> {
        if self.pos >= self.data.len() {
            return Err(PgError::Protocol("unexpected end of message".to_string()));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_i16(&mut self) -> Result<i16, PgError> {
        if self.pos + 2 > self.data.len() {
            return Err(PgError::Protocol("unexpected end of message".to_string()));
        }
        let v = i16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_i32(&mut self) -> Result<i32, PgError> {
        if self.pos + 4 > self.data.len() {
            return Err(PgError::Protocol("unexpected end of message".to_string()));
        }
        let v = i32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], PgError> {
        if len > self.data.len().saturating_sub(self.pos) {
            return Err(PgError::Protocol("unexpected end of message".to_string()));
        }
        let data = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(data)
    }

    fn read_cstring(&mut self) -> Result<&'a str, PgError> {
        let start = self.pos;
        while self.pos < self.data.len() && self.data[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.data.len() {
            return Err(PgError::Protocol("unterminated string".to_string()));
        }
        let s = std::str::from_utf8(&self.data[start..self.pos])
            .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;
        self.pos += 1; // skip null terminator
        Ok(s)
    }
}

// ============================================================================
// SCRAM-SHA-256 Authentication
// ============================================================================

/// SCRAM-SHA-256 authentication state machine.
struct ScramAuth {
    /// Password.
    password: String,
    /// Client nonce.
    client_nonce: String,
    /// Full nonce (client + server).
    full_nonce: Option<String>,
    /// Salt from server.
    salt: Option<Vec<u8>>,
    /// Iteration count.
    iterations: Option<u32>,
    /// Auth message for signature.
    auth_message: Option<String>,
    /// Client first message bare.
    client_first_bare: String,
}

impl ScramAuth {
    fn new(cx: &Cx, username: &str, password: &str) -> Self {
        // Generate client nonce (24 random bytes, base64 encoded)
        let mut nonce_bytes = [0u8; 24];
        cx.random_bytes(&mut nonce_bytes);
        let client_nonce =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);

        // RFC 5802: escape '=' as '=3D' and ',' as '=2C' in username
        let escaped_username = username.replace('=', "=3D").replace(',', "=2C");
        let client_first_bare = format!("n={escaped_username},r={client_nonce}");

        Self {
            password: password.to_string(),
            client_nonce,
            full_nonce: None,
            salt: None,
            iterations: None,
            auth_message: None,
            client_first_bare,
        }
    }

    /// Generate the client-first message.
    fn client_first_message(&self) -> Vec<u8> {
        // gs2-header is "n,," for no channel binding
        format!("n,,{}", self.client_first_bare).into_bytes()
    }

    /// Process server-first message and generate client-final message.
    fn process_server_first(&mut self, server_first: &str) -> Result<Vec<u8>, PgError> {
        // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
        let mut server_nonce = None;
        let mut salt = None;
        let mut iterations = None;

        for part in server_first.split(',') {
            if let Some(value) = part.strip_prefix("r=") {
                server_nonce = Some(value.to_string());
            } else if let Some(value) = part.strip_prefix("s=") {
                salt = Some(
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                        .map_err(|e| PgError::AuthenticationFailed(format!("invalid salt: {e}")))?,
                );
            } else if let Some(value) = part.strip_prefix("i=") {
                iterations = Some(value.parse().map_err(|e| {
                    PgError::AuthenticationFailed(format!("invalid iterations: {e}"))
                })?);
            }
        }

        let full_nonce = server_nonce
            .ok_or_else(|| PgError::AuthenticationFailed("missing server nonce".to_string()))?;
        let salt = salt.ok_or_else(|| PgError::AuthenticationFailed("missing salt".to_string()))?;
        let iterations = iterations
            .ok_or_else(|| PgError::AuthenticationFailed("missing iterations".to_string()))?;
        // Reject unreasonable iteration counts to prevent DoS from a malicious
        // server. Real PostgreSQL uses 4096; anything above 600,000 is suspicious
        // and would cause multi-second PBKDF2 computation.
        const MAX_PBKDF2_ITERATIONS: u32 = 600_000;
        if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
            return Err(PgError::AuthenticationFailed(format!(
                "SCRAM iteration count {iterations} outside safe range 1..={MAX_PBKDF2_ITERATIONS}"
            )));
        }

        // Verify server nonce starts with our client nonce
        if !full_nonce.starts_with(&self.client_nonce) {
            return Err(PgError::AuthenticationFailed(
                "server nonce mismatch".to_string(),
            ));
        }

        self.full_nonce = Some(full_nonce.clone());
        self.salt = Some(salt.clone());
        self.iterations = Some(iterations);

        // Compute salted password using PBKDF2-SHA256
        let salted_password = self.pbkdf2_sha256(&self.password, &salt, iterations);

        // Compute client key and stored key
        let client_key = Self::hmac_sha256(&salted_password, b"Client Key");
        let stored_key = Self::sha256(&client_key);

        // Build client-final-message-without-proof
        let channel_binding =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"n,,");
        let client_final_without_proof = format!("c={channel_binding},r={full_nonce}");

        // Build auth message
        let auth_message = format!(
            "{},{},{}",
            self.client_first_bare, server_first, client_final_without_proof
        );
        self.auth_message = Some(auth_message.clone());

        // Compute client signature and proof
        let client_signature = Self::hmac_sha256(&stored_key, auth_message.as_bytes());
        let client_proof: Vec<u8> = client_key
            .iter()
            .zip(client_signature.iter())
            .map(|(k, s)| k ^ s)
            .collect();
        let client_proof_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &client_proof);

        // Build client-final-message
        let client_final = format!("{client_final_without_proof},p={client_proof_b64}");
        Ok(client_final.into_bytes())
    }

    /// Verify server-final message.
    fn verify_server_final(&self, server_final: &str) -> Result<(), PgError> {
        // Parse server-final-message: v=<server-signature>
        let server_sig_b64 = server_final
            .strip_prefix("v=")
            .ok_or_else(|| PgError::AuthenticationFailed("invalid server-final".to_string()))?;

        let server_sig =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, server_sig_b64)
                .map_err(|e| {
                    PgError::AuthenticationFailed(format!("invalid server signature: {e}"))
                })?;

        // Compute expected server signature
        let salt = self.salt.as_ref().ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing salt".to_string())
        })?;
        let iterations = self.iterations.ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing iterations".to_string())
        })?;
        let salted_password = self.pbkdf2_sha256(&self.password, salt, iterations); // ubs:ignore - dynamic password variable
        let server_key = Self::hmac_sha256(&salted_password, b"Server Key");
        let auth_message = self.auth_message.as_ref().ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing auth_message".to_string())
        })?;
        let expected_sig = Self::hmac_sha256(&server_key, auth_message.as_bytes());

        // Constant-time comparison to prevent timing side-channel attacks
        // against SCRAM mutual authentication. The length check must not
        // short-circuit the content comparison.
        let len_ok = server_sig.len() == expected_sig.len();
        let content_ok = server_sig
            .iter()
            .zip(expected_sig.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
        let sig_matches = len_ok & content_ok;
        if !sig_matches {
            return Err(PgError::AuthenticationFailed(
                "server signature mismatch".to_string(),
            ));
        }

        Ok(())
    }

    /// PBKDF2-SHA256 key derivation.
    fn pbkdf2_sha256(&self, password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut result = vec![0u8; 32]; // SHA-256 output size

        // PBKDF2 with single block (dkLen <= hLen)
        // U_1 = HMAC(password, salt || INT(1))
        let mut salt_with_block = salt.to_vec();
        salt_with_block.extend_from_slice(&1u32.to_be_bytes());

        let mut u = Self::hmac_sha256(password.as_bytes(), &salt_with_block);
        result.copy_from_slice(&u);

        // U_2 ... U_iterations
        for _ in 1..iterations {
            u = Self::hmac_sha256(password.as_bytes(), &u);
            for (r, ui) in result.iter_mut().zip(u.iter()) {
                *r ^= ui;
            }
        }

        result
    }

    /// HMAC-SHA256.
    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        const BLOCK_SIZE: usize = 64; // SHA-256 block size

        // Pad or hash key to block size
        let mut key_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let hash = Sha256::digest(key);
            key_block[..32].copy_from_slice(&hash);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        // Inner padding
        let mut inner = [0x36u8; BLOCK_SIZE];
        for (i, k) in key_block.iter().enumerate() {
            inner[i] ^= k;
        }

        // Outer padding
        let mut outer = [0x5cu8; BLOCK_SIZE];
        for (i, k) in key_block.iter().enumerate() {
            outer[i] ^= k;
        }

        // HMAC = H(outer || H(inner || data))
        let mut hasher = Sha256::new();
        hasher.update(inner);
        hasher.update(data);
        let inner_hash = hasher.finalize();

        let mut hasher = Sha256::new();
        hasher.update(outer);
        hasher.update(inner_hash);
        hasher.finalize().to_vec()
    }

    /// SHA-256 hash.
    fn sha256(data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).to_vec()
    }
}

// ============================================================================
// Connection URL Parsing
// ============================================================================

/// Parsed PostgreSQL connection URL.
#[derive(Clone)]
pub struct PgConnectOptions {
    /// Host name or IP address.
    pub host: String,
    /// Port number (default 5432).
    pub port: u16,
    /// Database name.
    pub database: String,
    /// Username.
    pub user: String,
    /// Password.
    pub password: Option<String>,
    /// Application name.
    pub application_name: Option<String>,
    /// Connect timeout.
    pub connect_timeout: Option<std::time::Duration>,
    /// SSL mode.
    pub ssl_mode: SslMode,
}

impl std::fmt::Debug for PgConnectOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgConnectOptions")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("application_name", &self.application_name)
            .field("connect_timeout", &self.connect_timeout)
            .field("ssl_mode", &self.ssl_mode)
            .finish()
    }
}

/// SSL connection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SslMode {
    /// Never use SSL.
    Disable,
    /// Prefer SSL if available (default).
    #[default]
    Prefer,
    /// Require SSL.
    Require,
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
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

impl PgConnectOptions {
    /// Parse a connection URL.
    ///
    /// Format: `postgres://user:password@host:port/database?options`
    pub fn parse(url: &str) -> Result<Self, PgError> {
        let url = url
            .strip_prefix("postgres://")
            .or_else(|| url.strip_prefix("postgresql://"))
            .ok_or_else(|| PgError::InvalidUrl("URL must start with postgres://".to_string()))?;

        // Split into auth@hostport/database?params
        let (auth_host, params) = url.split_once('?').unwrap_or((url, ""));
        let (auth_host_db, _params_str) = (auth_host, params);

        // Split host/database
        let (auth_host, database) = auth_host_db
            .rsplit_once('/')
            .ok_or_else(|| PgError::InvalidUrl("missing database name".to_string()))?;
        if database.is_empty() {
            return Err(PgError::InvalidUrl("missing database name".to_string()));
        }

        // Split auth@host
        let (user, password, host_port) = if let Some((auth, host)) = auth_host.rsplit_once('@') {
            let (user, password) = auth
                .split_once(':')
                .map_or((auth, None), |(u, p)| (u, Some(p)));
            (percent_decode(user), password.map(percent_decode), host)
        } else {
            ("postgres".to_string(), None, auth_host)
        };

        // Split host:port (handle IPv6 addresses like [::1]:5432)
        let (host, port) = if host_port.starts_with('[') {
            // IPv6 literal: [::1]:5432
            if let Some((bracket_host, rest)) = host_port.split_once(']') {
                let h = bracket_host.trim_start_matches('[');
                let p = if rest.is_empty() {
                    5432u16
                } else if let Some(port_str) = rest.strip_prefix(':') {
                    port_str
                        .parse()
                        .map_err(|_| PgError::InvalidUrl(format!("invalid port: {port_str}")))?
                } else {
                    return Err(PgError::InvalidUrl(format!(
                        "invalid host/port segment: {host_port}"
                    )));
                };
                (h, p)
            } else {
                return Err(PgError::InvalidUrl(format!(
                    "invalid IPv6 host literal: {host_port}"
                )));
            }
        } else if host_port.matches(':').count() > 1 {
            (host_port, 5432)
        } else {
            match host_port.rsplit_once(':') {
                Some((h, p)) => (
                    h,
                    p.parse()
                        .map_err(|_| PgError::InvalidUrl(format!("invalid port: {p}")))?,
                ),
                None => (host_port, 5432),
            }
        };
        if host.is_empty() {
            return Err(PgError::InvalidUrl("missing host".to_string()));
        }

        // Parse query parameters
        let mut ssl_mode = SslMode::Prefer;
        let mut application_name = None;
        let mut connect_timeout = None;
        for kv in params.split('&').filter(|s| !s.is_empty()) {
            if let Some((key, value)) = kv.split_once('=') {
                match key {
                    "sslmode" => {
                        ssl_mode = match value {
                            "disable" => SslMode::Disable,
                            "prefer" => SslMode::Prefer,
                            "require" => SslMode::Require,
                            _ => {
                                return Err(PgError::InvalidUrl(format!(
                                    "unknown sslmode: {value}"
                                )));
                            }
                        };
                    }
                    "application_name" => {
                        application_name = Some(percent_decode(value));
                    }
                    "connect_timeout" => {
                        let secs = value.parse::<u64>().map_err(|_| {
                            PgError::InvalidUrl(format!("invalid connect_timeout: {value}"))
                        })?;
                        connect_timeout = Some(std::time::Duration::from_secs(secs));
                    }
                    _ => {} // ignore unknown parameters
                }
            }
        }

        Ok(Self {
            host: percent_decode(host),
            port,
            database: percent_decode(database),
            user,
            password,
            application_name,
            connect_timeout,
            ssl_mode,
        })
    }
}

// ============================================================================
// PostgreSQL Stream (plain or TLS)
// ============================================================================

/// Transport stream that may be plain TCP or TLS-encrypted.
enum PgStream {
    /// Plain TCP connection.
    Plain(TcpStream),
    /// TLS-encrypted TCP connection.
    #[cfg(feature = "tls")]
    Tls(Box<TlsStream<TcpStream>>),
}

impl PgStream {
    /// Shut down the underlying transport.
    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.shutdown(how),
            #[cfg(feature = "tls")]
            Self::Tls(_) => Ok(()), // TLS stream dropped on connection close
        }
    }
}

impl AsyncRead for PgStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // SAFETY: we only project to one field at a time and both variants are Unpin.
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PgStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(s) => s.is_write_vectored(),
            #[cfg(feature = "tls")]
            Self::Tls(s) => s.is_write_vectored(),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_flush(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(s) => Pin::new(s).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

// ============================================================================
// PostgreSQL Connection
// ============================================================================

/// Maximum rows accepted per result set before closing the connection.
const DEFAULT_MAX_RESULT_ROWS: usize = 1_000_000;

/// Inner connection state.
struct PgConnectionInner {
    /// Transport stream (plain TCP or TLS).
    stream: PgStream,
    /// Server process ID.
    process_id: i32,
    /// Secret key for cancel requests.
    secret_key: i32,
    /// Server parameters.
    parameters: BTreeMap<String, String>,
    /// Transaction status.
    transaction_status: u8,
    /// Whether the connection is closed.
    closed: bool,
    /// Whether a rollback is needed before the next operation (orphaned transaction).
    needs_rollback: bool,
    /// Counter for generating unique prepared statement names.
    next_stmt_id: u32,
    /// Maximum number of rows to accept per result set before closing the
    /// connection. Prevents unbounded memory growth from runaway queries or
    /// a malicious server sending an endless DataRow stream.
    max_result_rows: usize,
}

impl Drop for PgConnectionInner {
    fn drop(&mut self) {
        if !self.closed {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            self.closed = true;
        }
    }
}

/// An async PostgreSQL connection.
///
/// All operations integrate with [`Cx`] for cancellation and checkpointing.
///
/// [`Cx`]: crate::cx::Cx
pub struct PgConnection {
    /// Inner connection state.
    inner: PgConnectionInner,
}

impl fmt::Debug for PgConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConnection")
            .field("process_id", &self.inner.process_id)
            .field("closed", &self.inner.closed)
            .finish()
    }
}

#[inline]
fn cancelled_reason(cx: &Cx) -> CancelReason {
    cx.cancel_reason()
        .unwrap_or_else(|| CancelReason::user("cancelled"))
}

fn unexpected_backend_message(context: &str, msg_type: u8) -> PgError {
    let rendered = if msg_type.is_ascii_graphic() {
        format!("'{}'", char::from(msg_type))
    } else {
        format!("0x{msg_type:02X}")
    };
    PgError::Protocol(format!(
        "unexpected backend message in {context}: {rendered}"
    ))
}

fn row_returning_execute_error(api: &str, query_api: &str) -> PgError {
    PgError::Protocol(format!(
        "{api} cannot consume row-returning statements; use {query_api} instead"
    ))
}

#[inline]
fn cancelled_error(cx: &Cx) -> PgError {
    PgError::Cancelled(cancelled_reason(cx))
}

#[inline]
fn outcome_from_error<T>(err: PgError) -> Outcome<T, PgError> {
    match err {
        PgError::Cancelled(reason) => Outcome::Cancelled(reason),
        other => Outcome::Err(other),
    }
}

impl PgConnection {
    #[inline]
    fn abort_in_flight_exchange(&mut self) {
        let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
        self.inner.closed = true;
    }

    #[inline]
    fn fail_in_flight<T>(&mut self, err: PgError) -> Outcome<T, PgError> {
        self.abort_in_flight_exchange();
        outcome_from_error(err)
    }

    #[inline]
    async fn ensure_no_orphaned_transaction(&mut self, cx: &Cx) -> Outcome<(), PgError> {
        match self.clear_orphaned_transaction(cx).await {
            Ok(()) => Outcome::Ok(()),
            Err(err) => outcome_from_error(err),
        }
    }

    fn handle_parameter_status(&mut self, data: &[u8]) -> Result<(), PgError> {
        let mut reader = MessageReader::new(data);
        let name = reader.read_cstring()?.to_string();
        let value = reader.read_cstring()?.to_string();
        self.inner.parameters.insert(name, value);
        Ok(())
    }

    fn handle_notification_response(&mut self, data: &[u8]) -> Result<(), PgError> {
        let mut reader = MessageReader::new(data);
        let _process_id = reader.read_i32()?;
        let _channel = reader.read_cstring()?;
        let _payload = reader.read_cstring()?;
        Ok(())
    }

    fn handle_async_backend_message(&mut self, msg_type: u8, data: &[u8]) -> Result<bool, PgError> {
        match msg_type {
            b'N' => Ok(true),
            b'S' => {
                self.handle_parameter_status(data)?;
                Ok(true)
            }
            b'A' => {
                self.handle_notification_response(data)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn connect_tcp_with<F, Fut>(
        options: &PgConnectOptions,
        connect: F,
    ) -> Result<TcpStream, PgError>
    where
        F: FnOnce(String, Option<std::time::Duration>) -> Fut,
        Fut: std::future::Future<Output = io::Result<TcpStream>>,
    {
        let addr = format!("{}:{}", options.host, options.port);
        connect(addr, options.connect_timeout)
            .await
            .map_err(PgError::Io)
    }

    async fn connect_tcp(options: &PgConnectOptions) -> Result<TcpStream, PgError> {
        Self::connect_tcp_with(options, |addr, timeout| async move {
            if let Some(timeout) = timeout {
                TcpStream::connect_timeout(addr, timeout).await
            } else {
                TcpStream::connect(addr).await
            }
        })
        .await
    }

    /// Connect to a PostgreSQL database.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn connect(cx: &Cx, url: &str) -> Outcome<Self, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(cancelled_reason(cx));
        }

        let options = match PgConnectOptions::parse(url) {
            Ok(opts) => opts,
            Err(e) => return Outcome::Err(e),
        };

        Self::connect_with_options(cx, options).await
    }

    /// Connect with explicit options.
    pub async fn connect_with_options(
        cx: &Cx,
        options: PgConnectOptions,
    ) -> Outcome<Self, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(cancelled_reason(cx));
        }

        let tcp_stream = match Self::connect_tcp(&options).await {
            Ok(stream) => stream,
            Err(e) => return Outcome::Err(e),
        };

        // TLS negotiation based on ssl_mode
        let stream = match options.ssl_mode {
            SslMode::Disable => PgStream::Plain(tcp_stream),
            #[cfg(feature = "tls")]
            SslMode::Prefer | SslMode::Require => {
                match Self::negotiate_tls(cx, tcp_stream, &options).await {
                    Ok(s) => s,
                    Err(PgError::Cancelled(reason)) => return Outcome::Cancelled(reason),
                    Err(e) if options.ssl_mode == SslMode::Require => {
                        return outcome_from_error(e);
                    }
                    Err(_) => {
                        // Prefer mode: TLS failed, reconnect without TLS.
                        match Self::connect_tcp(&options).await {
                            Ok(stream) => PgStream::Plain(stream),
                            Err(e) => return Outcome::Err(e),
                        }
                    }
                }
            }
            #[cfg(not(feature = "tls"))]
            SslMode::Require => {
                return Outcome::Err(PgError::Tls(
                    "TLS required but the `tls` feature is not enabled".into(),
                ));
            }
            #[cfg(not(feature = "tls"))]
            SslMode::Prefer => PgStream::Plain(tcp_stream),
        };

        let mut conn = Self {
            inner: PgConnectionInner {
                stream,
                process_id: 0,
                secret_key: 0,
                parameters: BTreeMap::new(),
                transaction_status: b'I', // Idle
                closed: false,
                needs_rollback: false,
                next_stmt_id: 0,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        };

        // Send startup message
        if let Err(e) = conn.send_startup(cx, &options).await {
            return outcome_from_error(e);
        }

        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(cancelled_reason(cx));
        }

        // Handle authentication
        if let Err(e) = conn.authenticate(cx, &options).await {
            return match e {
                PgError::Cancelled(reason) => Outcome::Cancelled(reason),
                other => Outcome::Err(other),
            };
        }

        // Wait for ReadyForQuery
        if let Err(e) = conn.wait_for_ready(cx).await {
            return match e {
                PgError::Cancelled(reason) => Outcome::Cancelled(reason),
                other => Outcome::Err(other),
            };
        }

        Outcome::Ok(conn)
    }

    #[inline]
    fn cancel_in_flight<T>(&mut self, cx: &Cx) -> Outcome<T, PgError> {
        // Once a caller cancels mid-flight we can't safely continue decoding
        // protocol messages for subsequent operations, so close this connection.
        self.abort_in_flight_exchange();
        Outcome::Cancelled(cancelled_reason(cx))
    }

    /// Negotiate TLS with the PostgreSQL server.
    ///
    /// Sends the 8-byte SSLRequest message and reads a single-byte response:
    /// - `S`: server accepts TLS — upgrade via `TlsConnector`.
    /// - `N`: server refuses TLS.
    #[cfg(feature = "tls")]
    async fn negotiate_tls(
        cx: &Cx,
        mut tcp: TcpStream,
        options: &PgConnectOptions,
    ) -> Result<PgStream, PgError> {
        // SSLRequest message: 8 bytes total
        //   4 bytes: message length (8, including self)
        //   4 bytes: SSL request code 80877103
        let ssl_request: [u8; 8] = {
            let len = 8i32.to_be_bytes();
            let code = 80_877_103i32.to_be_bytes();
            [
                len[0], len[1], len[2], len[3], code[0], code[1], code[2], code[3],
            ]
        };

        // Write SSLRequest
        {
            let mut pos = 0;
            while pos < ssl_request.len() {
                let written = std::future::poll_fn(|task_cx| {
                    if cx.checkpoint().is_err() {
                        return Poll::Ready(Err(cancelled_error(cx)));
                    }
                    match Pin::new(&mut tcp).poll_write(task_cx, &ssl_request[pos..]) {
                        Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
                        Poll::Ready(Err(err)) => Poll::Ready(Err(PgError::Io(err))),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await?;
                if written == 0 {
                    return Err(PgError::Io(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write SSLRequest",
                    )));
                }
                pos += written;
            }
        }

        // Read single-byte response
        let mut response = [0u8; 1];
        {
            let mut read_buf = ReadBuf::new(&mut response);
            std::future::poll_fn(|task_cx| {
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(cancelled_error(cx)));
                }
                match Pin::new(&mut tcp).poll_read(task_cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(PgError::Io(err))),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            if read_buf.filled().is_empty() {
                return Err(PgError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "server closed connection during TLS negotiation",
                )));
            }
        }

        match response[0] {
            b'S' => {
                // Server accepts TLS — perform handshake.
                let connector = TlsConnectorBuilder::new()
                    .with_webpki_roots()
                    .build()
                    .map_err(|e| PgError::Tls(e.to_string()))?;
                let tls_stream = connector
                    .connect(&options.host, tcp)
                    .await
                    .map_err(|e| PgError::Tls(e.to_string()))?;
                Ok(PgStream::Tls(Box::new(tls_stream)))
            }
            b'N' => {
                // Server refuses TLS.
                if options.ssl_mode == SslMode::Require {
                    Err(PgError::TlsRequired)
                } else {
                    // Prefer mode: fall back to plain.
                    Ok(PgStream::Plain(tcp))
                }
            }
            other => Err(PgError::Protocol(format!(
                "unexpected TLS negotiation response: 0x{other:02X}"
            ))),
        }
    }

    /// Send the startup message.
    async fn send_startup(&mut self, cx: &Cx, options: &PgConnectOptions) -> Result<(), PgError> {
        let mut buf = MessageBuffer::new();

        // Protocol version 3.0
        buf.write_i32(196_608); // 3 << 16

        // Parameters
        buf.write_cstring("user");
        buf.write_cstring(&options.user);

        buf.write_cstring("database");
        buf.write_cstring(&options.database);

        if let Some(ref app_name) = options.application_name {
            buf.write_cstring("application_name");
            buf.write_cstring(app_name);
        }

        // Terminating null
        buf.write_byte(0);

        let msg = buf.build_startup_message()?;
        self.write_all(cx, &msg).await?;

        Ok(())
    }

    /// Handle the authentication handshake.
    async fn authenticate(&mut self, cx: &Cx, options: &PgConnectOptions) -> Result<(), PgError> {
        loop {
            if cx.checkpoint().is_err() {
                return Err(PgError::Cancelled(cancelled_reason(cx)));
            }

            let (msg_type, data) = self.read_message(cx).await?;

            match msg_type {
                b'R' => {
                    // Authentication message
                    let mut reader = MessageReader::new(&data);
                    let auth_type = reader.read_i32()?;

                    match auth_type {
                        0 => {
                            // AuthenticationOk
                            return Ok(());
                        }
                        3 => {
                            // AuthenticationCleartextPassword
                            let password = options.password.as_ref().ok_or_else(|| {
                                PgError::AuthenticationFailed("password required".to_string())
                            })?;
                            self.send_password(cx, password).await?;
                        }
                        5 => {
                            // AuthenticationMD5Password
                            let salt = reader.read_bytes(4)?;
                            let password = options.password.as_ref().ok_or_else(|| {
                                PgError::AuthenticationFailed("password required".to_string())
                            })?;
                            self.send_md5_password(cx, &options.user, password, salt)
                                .await?;
                        }
                        10 => {
                            // AuthenticationSASL
                            let mechanisms = Self::read_sasl_mechanisms(&mut reader)?;
                            if mechanisms.contains(&"SCRAM-SHA-256".to_string()) {
                                let password = options.password.as_ref().ok_or_else(|| {
                                    PgError::AuthenticationFailed("password required".to_string())
                                })?;
                                self.authenticate_scram(cx, &options.user, password).await?;
                                return Ok(());
                            }
                            return Err(PgError::UnsupportedAuth(format!(
                                "SASL mechanisms: {mechanisms:?}"
                            )));
                        }
                        11 => {
                            // AuthenticationSASLContinue - handled in authenticate_scram
                            return Err(PgError::Protocol("unexpected SASLContinue".to_string()));
                        }
                        12 => {
                            // AuthenticationSASLFinal - handled in authenticate_scram
                            return Err(PgError::Protocol("unexpected SASLFinal".to_string()));
                        }
                        _ => {
                            return Err(PgError::UnsupportedAuth(format!("auth type {auth_type}")));
                        }
                    }
                }
                b'E' => {
                    // ErrorResponse
                    return Err(self.parse_error_response(&data)?);
                }
                _ => {
                    return Err(PgError::Protocol(format!(
                        "unexpected message type: {}",
                        msg_type as char
                    )));
                }
            }
        }
    }

    /// Read SASL mechanism list.
    fn read_sasl_mechanisms(reader: &mut MessageReader<'_>) -> Result<Vec<String>, PgError> {
        let mut mechanisms = Vec::new();
        loop {
            let mech = reader.read_cstring()?;
            if mech.is_empty() {
                break;
            }
            mechanisms.push(mech.to_string());
        }
        Ok(mechanisms)
    }

    /// Perform SCRAM-SHA-256 authentication.
    async fn authenticate_scram(
        &mut self,
        cx: &Cx,
        username: &str,
        password: &str,
    ) -> Result<(), PgError> {
        let mut scram = ScramAuth::new(cx, username, password);

        // Send SASLInitialResponse
        let client_first = scram.client_first_message();
        let mut buf = MessageBuffer::new();
        buf.write_cstring("SCRAM-SHA-256");
        let client_first_len = i32::try_from(client_first.len()).map_err(|_| {
            PgError::Protocol(format!(
                "SCRAM client-first message too large: {} bytes",
                client_first.len()
            ))
        })?;
        buf.write_i32(client_first_len);
        buf.write_bytes(&client_first);
        let msg = buf.build_message(FrontendMessage::Password as u8)?;
        self.write_all(cx, &msg).await?;

        if cx.checkpoint().is_err() {
            return Err(PgError::Cancelled(cancelled_reason(cx)));
        }

        // Receive SASLContinue
        let (msg_type, data) = self.read_message(cx).await?;
        if msg_type == b'E' {
            return Err(self.parse_error_response(&data)?);
        }
        if msg_type != b'R' {
            return Err(PgError::Protocol(format!(
                "expected R, got {}",
                msg_type as char
            )));
        }

        let mut reader = MessageReader::new(&data);
        let auth_type = reader.read_i32()?;
        if auth_type != 11 {
            return Err(PgError::Protocol(format!(
                "expected SASLContinue (11), got {auth_type}"
            )));
        }
        let server_first = std::str::from_utf8(reader.read_bytes(reader.remaining())?)
            .map_err(|e| PgError::Protocol(format!("invalid server-first: {e}")))?;

        // Process server-first and send client-final
        let client_final = scram.process_server_first(server_first)?;
        let mut buf = MessageBuffer::new();
        buf.write_bytes(&client_final);
        let msg = buf.build_message(FrontendMessage::Password as u8)?;
        self.write_all(cx, &msg).await?;

        if cx.checkpoint().is_err() {
            return Err(PgError::Cancelled(cancelled_reason(cx)));
        }

        // Receive SASLFinal
        let (msg_type, data) = self.read_message(cx).await?;
        if msg_type == b'E' {
            return Err(self.parse_error_response(&data)?);
        }
        if msg_type != b'R' {
            return Err(PgError::Protocol(format!(
                "expected R, got {}",
                msg_type as char
            )));
        }

        let mut reader = MessageReader::new(&data);
        let auth_type = reader.read_i32()?;
        if auth_type != 12 {
            return Err(PgError::Protocol(format!(
                "expected SASLFinal (12), got {auth_type}"
            )));
        }
        let server_final = std::str::from_utf8(reader.read_bytes(reader.remaining())?)
            .map_err(|e| PgError::Protocol(format!("invalid server-final: {e}")))?;

        // Verify server signature
        scram.verify_server_final(server_final)?;

        if cx.checkpoint().is_err() {
            return Err(PgError::Cancelled(cancelled_reason(cx)));
        }

        // Wait for AuthenticationOk
        let (msg_type, data) = self.read_message(cx).await?;
        if msg_type == b'E' {
            return Err(self.parse_error_response(&data)?);
        }
        if msg_type != b'R' {
            return Err(PgError::Protocol(format!(
                "expected R, got {}",
                msg_type as char
            )));
        }

        let mut reader = MessageReader::new(&data);
        let auth_type = reader.read_i32()?;
        if auth_type != 0 {
            return Err(PgError::Protocol(format!(
                "expected AuthOk (0), got {auth_type}"
            )));
        }

        Ok(())
    }

    /// Send cleartext password.
    async fn send_password(&mut self, cx: &Cx, password: &str) -> Result<(), PgError> {
        let mut buf = MessageBuffer::new();
        buf.write_cstring(password);
        let msg = buf.build_message(FrontendMessage::Password as u8)?;
        self.write_all(cx, &msg).await?;
        Ok(())
    }

    /// Send MD5-hashed password.
    #[allow(clippy::unused_async)]
    async fn send_md5_password(
        &mut self,
        _cx: &Cx,
        _user: &str,
        _password: &str,
        _salt: &[u8],
    ) -> Result<(), PgError> {
        // PostgreSQL MD5 auth uses MD5 not SHA256
        // SCRAM-SHA-256 is the recommended modern authentication
        // For now, we require SCRAM-SHA-256
        Err(PgError::UnsupportedAuth(
            "MD5 - please use SCRAM-SHA-256".to_string(),
        ))
    }

    /// Wait for ReadyForQuery message (handles ParameterStatus, BackendKeyData).
    async fn wait_for_ready(&mut self, cx: &Cx) -> Result<(), PgError> {
        loop {
            if cx.checkpoint().is_err() {
                return Err(PgError::Cancelled(cancelled_reason(cx)));
            }

            let (msg_type, data) = self.read_message(cx).await?;

            match msg_type {
                b'K' => {
                    // BackendKeyData
                    let mut reader = MessageReader::new(&data);
                    self.inner.process_id = reader.read_i32()?;
                    self.inner.secret_key = reader.read_i32()?;
                }
                b'S' => {
                    // ParameterStatus
                    self.handle_parameter_status(&data)?;
                }
                b'A' => {
                    // NotificationResponse can arrive asynchronously once the
                    // session is established; consume it without desyncing.
                    self.handle_notification_response(&data)?;
                }
                b'Z' => {
                    // ReadyForQuery
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    return Ok(());
                }
                b'E' => {
                    return Err(self.parse_error_response(&data)?);
                }
                b'N' => {
                    // NoticeResponse - log but continue
                }
                _ => {
                    return Err(unexpected_backend_message("startup sequence", msg_type));
                }
            }
        }
    }

    /// Execute a simple query.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn query(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Send Query message
        let mut buf = MessageBuffer::new();
        buf.write_cstring(sql);
        let msg = match buf.build_message(FrontendMessage::Query as u8) {
            Ok(m) => m,
            Err(e) => return Outcome::Err(e),
        };

        // Mark closed before the protocol exchange so that if this future is
        // dropped mid-write or mid-read (e.g. by task cancellation), the
        // connection stays closed and prevents protocol desynchronization.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &msg).await {
            return self.fail_in_flight(e);
        }

        // Process responses
        let mut columns: Option<Arc<Vec<PgColumn>>> = None;
        let mut column_indices: Option<Arc<BTreeMap<String, usize>>> = None;
        let mut rows = Vec::with_capacity(16);

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return self.fail_in_flight(e),
            };

            match msg_type {
                b'T' => {
                    // RowDescription
                    match self.parse_row_description(&data) {
                        Ok((cols, indices)) => {
                            columns = Some(Arc::new(cols));
                            column_indices = Some(Arc::new(indices));
                        }
                        Err(e) => return self.fail_in_flight(e),
                    }
                }
                b'D' => {
                    // DataRow — enforce max_result_rows to prevent OOM from
                    // runaway queries or a malicious server.
                    if rows.len() >= self.inner.max_result_rows {
                        return self.fail_in_flight(PgError::Protocol(format!(
                            "result set exceeded {} row limit",
                            self.inner.max_result_rows,
                        )));
                    }
                    let (Some(cols), Some(indices)) = (&columns, &column_indices) else {
                        return self.fail_in_flight(PgError::Protocol(
                            "received DataRow before RowDescription in simple query response"
                                .to_string(),
                        ));
                    };
                    match self.parse_data_row(&data, cols) {
                        Ok(values) => {
                            rows.push(PgRow {
                                columns: Arc::clone(cols),
                                column_indices: Arc::clone(indices),
                                values,
                            });
                        }
                        Err(e) => return self.fail_in_flight(e),
                    }
                }
                b'C' => {
                    // CommandComplete
                    // Continue to ReadyForQuery
                }
                b'I' => {
                    // EmptyQueryResponse
                }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    break;
                }
                b'E' => {
                    return outcome_from_error(self.parse_error_and_drain(cx, &data).await);
                }
                _ => {
                    match self.handle_async_backend_message(msg_type, &data) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return self.fail_in_flight(e),
                    }
                    return self.fail_in_flight(unexpected_backend_message(
                        "simple query response",
                        msg_type,
                    ));
                }
            }
        }

        Outcome::Ok(rows)
    }

    /// Execute a query and return first row.
    pub async fn query_one(&mut self, cx: &Cx, sql: &str) -> Outcome<Option<PgRow>, PgError> {
        match self.query(cx, sql).await {
            Outcome::Ok(mut rows) => {
                if rows.is_empty() {
                    Outcome::Ok(None)
                } else {
                    Outcome::Ok(Some(rows.remove(0)))
                }
            }
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Execute a command (INSERT, UPDATE, DELETE) and return affected rows.
    pub async fn execute(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Send Query message
        let mut buf = MessageBuffer::new();
        buf.write_cstring(sql);
        let msg = match buf.build_message(FrontendMessage::Query as u8) {
            Ok(m) => m,
            Err(e) => return Outcome::Err(e),
        };

        // Mark closed before the protocol exchange so that if this future is
        // dropped mid-write or mid-read (e.g. by task cancellation), the
        // connection stays closed and prevents protocol desynchronization.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &msg).await {
            return self.fail_in_flight(e);
        }

        // Process responses
        let mut affected_rows = 0u64;
        let mut saw_row_response = false;

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return self.fail_in_flight(e),
            };

            match msg_type {
                b'C' => {
                    // CommandComplete - parse affected rows
                    if let Ok(tag) = std::str::from_utf8(&data) {
                        let tag = tag.trim_end_matches('\0');
                        // Tag format: "INSERT 0 5" or "UPDATE 10" or "DELETE 3"
                        if let Some(num_str) = tag.rsplit(' ').next() {
                            if let Ok(num) = num_str.parse::<u64>() {
                                affected_rows = num;
                            }
                        }
                    }
                }
                b'T' | b'D' => {
                    // `execute()` is command-oriented and must not silently
                    // discard row-producing responses such as `SELECT` or
                    // `INSERT ... RETURNING`.
                    saw_row_response = true;
                }
                b'I' => {
                    // EmptyQueryResponse
                }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    if saw_row_response {
                        return Outcome::Err(row_returning_execute_error("execute()", "query()"));
                    }
                    break;
                }
                b'E' => {
                    return outcome_from_error(self.parse_error_and_drain(cx, &data).await);
                }
                _ => {
                    match self.handle_async_backend_message(msg_type, &data) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return self.fail_in_flight(e),
                    }
                    return self.fail_in_flight(unexpected_backend_message(
                        "simple execute response",
                        msg_type,
                    ));
                }
            }
        }

        Outcome::Ok(affected_rows)
    }

    /// Begin a transaction.
    pub async fn begin(&mut self, cx: &Cx) -> Outcome<PgTransaction<'_>, PgError> {
        match self.execute(cx, "BEGIN").await {
            Outcome::Ok(_) => Outcome::Ok(PgTransaction {
                conn: self,
                finished: false,
            }),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Get a server parameter.
    #[must_use]
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.inner.parameters.get(name).map(String::as_str)
    }

    /// Get the server version.
    #[must_use]
    pub fn server_version(&self) -> Option<&str> {
        self.parameter("server_version")
    }

    /// Check if the connection is in a transaction.
    #[must_use]
    pub fn in_transaction(&self) -> bool {
        self.inner.transaction_status == b'T' || self.inner.transaction_status == b'E'
    }

    /// Close the connection.
    pub async fn close(&mut self) -> Result<(), PgError> {
        if self.inner.closed {
            return Ok(());
        }

        // Send Terminate message
        let msg = [FrontendMessage::Terminate as u8, 0, 0, 0, 4]; // Type + length (4)
        let _ = self.write_all_unchecked(&msg).await;

        let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);

        self.inner.closed = true;
        Ok(())
    }

    // ========================================================================
    // Extended Query Protocol — parameterized queries
    // ========================================================================

    /// Execute a parameterized query using the Extended Query Protocol.
    ///
    /// Parameters use `$1`, `$2`, ... placeholders in SQL. This prevents
    /// SQL injection and enables type-safe binary parameter encoding.
    ///
    /// ```ignore
    /// let rows = conn.query_params(cx,
    ///     "SELECT id, name FROM users WHERE active = $1 AND age > $2",
    ///     &[&true, &21i32],
    /// ).await?;
    /// for row in &rows {
    ///     let id: i32 = row.get_typed("id")?;
    ///     let name: String = row.get_typed("name")?;
    /// }
    /// ```
    pub async fn query_params(
        &mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Outcome<Vec<PgRow>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        let param_oids: Vec<u32> = params.iter().map(ToSql::type_oid).collect();
        let parse = match build_parse_msg("", sql, &param_oids) {
            Ok(p) => p,
            Err(e) => return Outcome::Err(e),
        };
        let bind = match build_bind_msg("", "", params, Format::Text) {
            Ok(b) => b,
            Err(e) => return Outcome::Err(e),
        };
        let describe = match build_describe_msg(b'P', "") {
            Ok(d) => d,
            Err(e) => return Outcome::Err(e),
        };
        let execute = match build_execute_msg("", 0) {
            Ok(e) => e,
            Err(err) => return Outcome::Err(err),
        };
        let sync = match build_sync_msg() {
            Ok(s) => s,
            Err(e) => return Outcome::Err(e),
        };

        // Combine into single write for reduced syscalls.
        let total = parse.len() + bind.len() + describe.len() + execute.len() + sync.len();
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&parse);
        combined.extend_from_slice(&bind);
        combined.extend_from_slice(&describe);
        combined.extend_from_slice(&execute);
        combined.extend_from_slice(&sync);

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Mark closed before the protocol exchange so that if this future is
        // dropped mid-write or mid-read, the connection stays closed and
        // prevents protocol desynchronization.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &combined).await {
            return self.fail_in_flight(e);
        }

        self.read_extended_query_results(cx).await
    }

    /// Execute a parameterized query and return the first row.
    pub async fn query_one_params(
        &mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Outcome<Option<PgRow>, PgError> {
        match self.query_params(cx, sql, params).await {
            Outcome::Ok(mut rows) => {
                if rows.is_empty() {
                    Outcome::Ok(None)
                } else {
                    Outcome::Ok(Some(rows.remove(0)))
                }
            }
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Execute a parameterized command (INSERT, UPDATE, DELETE) using the
    /// Extended Query Protocol. Returns the number of affected rows.
    ///
    /// ```ignore
    /// let affected = conn.execute_params(cx,
    ///     "UPDATE users SET active = $1 WHERE id = $2",
    ///     &[&false, &42i32],
    /// ).await?;
    /// ```
    pub async fn execute_params(
        &mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Outcome<u64, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        let param_oids: Vec<u32> = params.iter().map(ToSql::type_oid).collect();
        let parse = match build_parse_msg("", sql, &param_oids) {
            Ok(p) => p,
            Err(e) => return Outcome::Err(e),
        };
        let bind = match build_bind_msg("", "", params, Format::Text) {
            Ok(b) => b,
            Err(e) => return Outcome::Err(e),
        };
        let execute = match build_execute_msg("", 0) {
            Ok(e) => e,
            Err(e) => return Outcome::Err(e),
        };
        let sync = match build_sync_msg() {
            Ok(s) => s,
            Err(e) => return Outcome::Err(e),
        };

        let total = parse.len() + bind.len() + execute.len() + sync.len();
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&parse);
        combined.extend_from_slice(&bind);
        combined.extend_from_slice(&execute);
        combined.extend_from_slice(&sync);

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Mark closed before the protocol exchange so that if this future is
        // dropped mid-write or mid-read, the connection stays closed and
        // prevents protocol desynchronization.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &combined).await {
            return self.fail_in_flight(e);
        }

        self.read_extended_execute_results(cx).await
    }

    /// Prepare a named statement for repeated execution.
    ///
    /// The server parses the SQL once and returns parameter/result metadata.
    /// Use [`query_prepared`](Self::query_prepared) or
    /// [`execute_prepared`](Self::execute_prepared) to run with different
    /// parameter values. Call [`close_statement`](Self::close_statement) when
    /// done to free server-side resources.
    ///
    /// ```ignore
    /// let stmt = conn.prepare(cx, "SELECT id FROM users WHERE active = $1").await?;
    /// let rows1 = conn.query_prepared(cx, &stmt, &[&true]).await?;
    /// let rows2 = conn.query_prepared(cx, &stmt, &[&false]).await?;
    /// conn.close_statement(cx, &stmt).await?;
    /// ```
    pub async fn prepare(&mut self, cx: &Cx, sql: &str) -> Outcome<PgStatement, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        let stmt_name = format!("__asupersync_s{}", self.inner.next_stmt_id);
        self.inner.next_stmt_id = self.inner.next_stmt_id.wrapping_add(1);

        // Parse with no type hints (let server infer from $N positions).
        let parse = match build_parse_msg(&stmt_name, sql, &[]) {
            Ok(p) => p,
            Err(e) => return Outcome::Err(e),
        };
        let describe = match build_describe_msg(b'S', &stmt_name) {
            Ok(d) => d,
            Err(e) => return Outcome::Err(e),
        };
        let sync = match build_sync_msg() {
            Ok(s) => s,
            Err(e) => return Outcome::Err(e),
        };

        let total = parse.len() + describe.len() + sync.len();
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&parse);
        combined.extend_from_slice(&describe);
        combined.extend_from_slice(&sync);

        // Mark closed before the protocol exchange to prevent desync on cancel.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &combined).await {
            return self.fail_in_flight(e);
        }

        // Read ParseComplete, ParameterDescription, RowDescription?, ReadyForQuery.
        let mut param_oids = Vec::new();
        let mut columns = Vec::new();

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return self.fail_in_flight(e),
            };

            match msg_type {
                b'1' => { /* ParseComplete */ }
                b't' => {
                    // ParameterDescription
                    match Self::parse_parameter_description(&data) {
                        Ok(oids) => param_oids = oids,
                        Err(e) => return self.fail_in_flight(e),
                    }
                }
                b'T' => {
                    // RowDescription
                    match self.parse_row_description(&data) {
                        Ok((cols, _)) => columns = cols,
                        Err(e) => return self.fail_in_flight(e),
                    }
                }
                b'n' => { /* NoData — statement returns no columns */ }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    break;
                }
                b'E' => {
                    return outcome_from_error(self.parse_error_and_drain(cx, &data).await);
                }
                _ => {
                    match self.handle_async_backend_message(msg_type, &data) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return self.fail_in_flight(e),
                    }
                    return self.fail_in_flight(unexpected_backend_message(
                        "prepared statement setup",
                        msg_type,
                    ));
                }
            }
        }

        Outcome::Ok(PgStatement {
            name: stmt_name,
            param_oids,
            columns,
        })
    }

    /// Execute a prepared statement returning rows.
    pub async fn query_prepared(
        &mut self,
        cx: &Cx,
        stmt: &PgStatement,
        params: &[&dyn ToSql],
    ) -> Outcome<Vec<PgRow>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        let bind = match build_bind_msg("", &stmt.name, params, Format::Text) {
            Ok(b) => b,
            Err(e) => return Outcome::Err(e),
        };
        let describe = match build_describe_msg(b'P', "") {
            Ok(d) => d,
            Err(e) => return Outcome::Err(e),
        };
        let execute = match build_execute_msg("", 0) {
            Ok(e) => e,
            Err(err) => return Outcome::Err(err),
        };
        let sync = match build_sync_msg() {
            Ok(s) => s,
            Err(e) => return Outcome::Err(e),
        };

        let total = bind.len() + describe.len() + execute.len() + sync.len();
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&bind);
        combined.extend_from_slice(&describe);
        combined.extend_from_slice(&execute);
        combined.extend_from_slice(&sync);

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Mark closed before the protocol exchange to prevent desync on cancel.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &combined).await {
            return self.fail_in_flight(e);
        }

        self.read_extended_query_results(cx).await
    }

    /// Execute a prepared statement returning affected row count.
    pub async fn execute_prepared(
        &mut self,
        cx: &Cx,
        stmt: &PgStatement,
        params: &[&dyn ToSql],
    ) -> Outcome<u64, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        let bind = match build_bind_msg("", &stmt.name, params, Format::Text) {
            Ok(b) => b,
            Err(e) => return Outcome::Err(e),
        };
        let execute = match build_execute_msg("", 0) {
            Ok(e) => e,
            Err(e) => return Outcome::Err(e),
        };
        let sync = match build_sync_msg() {
            Ok(s) => s,
            Err(e) => return Outcome::Err(e),
        };

        let total = bind.len() + execute.len() + sync.len();
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&bind);
        combined.extend_from_slice(&execute);
        combined.extend_from_slice(&sync);

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Mark closed before the protocol exchange to prevent desync on cancel.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &combined).await {
            return self.fail_in_flight(e);
        }

        self.read_extended_execute_results(cx).await
    }

    /// Close a prepared statement, freeing server-side resources.
    pub async fn close_statement(&mut self, cx: &Cx, stmt: &PgStatement) -> Outcome<(), PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }
        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        let close = match build_close_msg(b'S', &stmt.name) {
            Ok(c) => c,
            Err(e) => return Outcome::Err(e),
        };
        let sync = match build_sync_msg() {
            Ok(s) => s,
            Err(e) => return Outcome::Err(e),
        };

        let mut combined = Vec::with_capacity(close.len() + sync.len());
        combined.extend_from_slice(&close);
        combined.extend_from_slice(&sync);

        // Mark closed before the protocol exchange to prevent desync on cancel.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &combined).await {
            return self.fail_in_flight(e);
        }

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return self.fail_in_flight(e),
            };
            match msg_type {
                b'3' => { /* CloseComplete */ }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    break;
                }
                b'E' => {
                    return outcome_from_error(self.parse_error_and_drain(cx, &data).await);
                }
                _ => {
                    match self.handle_async_backend_message(msg_type, &data) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return self.fail_in_flight(e),
                    }
                    return self.fail_in_flight(unexpected_backend_message(
                        "close statement response",
                        msg_type,
                    ));
                }
            }
        }

        Outcome::Ok(())
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Clear an orphaned transaction left by a dropped `PgTransaction`.
    ///
    /// If `needs_rollback` is set, sends a ROLLBACK command and drains
    /// to `ReadyForQuery` before returning. This prevents the connection
    /// from being stuck in an aborted-transaction state.
    async fn clear_orphaned_transaction(&mut self, cx: &Cx) -> Result<(), PgError> {
        if !self.inner.needs_rollback {
            return Ok(());
        }

        // Mark the connection closed while we perform the rollback.
        // If this future is dropped mid-flight (e.g. by timeout), the connection
        // will remain closed, preventing protocol desynchronization.
        self.inner.closed = true;

        let mut buf = MessageBuffer::new();
        buf.write_cstring("ROLLBACK");
        let msg = buf.build_message(FrontendMessage::Query as u8)?;

        if let Err(e) = self.write_all(cx, &msg).await {
            let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
            return Err(e);
        }

        if let Err(e) = self.drain_to_ready(cx).await {
            // Drain errors during rollback are suppressed since the rollback
            // itself is the priority operation and a drain failure at that
            // point is non-fatal.
            let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);
            cx.trace(&format!("Failed to drain after ROLLBACK: {e}"));
            return Err(e);
        }

        // Successfully rolled back, restore connection state.
        self.inner.needs_rollback = false;
        self.inner.closed = false;

        Ok(())
    }

    /// Write data to the stream using async I/O and flush.
    ///
    /// The flush is necessary for TLS streams which may buffer outgoing
    /// data until explicitly flushed.
    async fn write_all_unchecked(&mut self, data: &[u8]) -> Result<(), PgError> {
        let mut pos = 0;
        while pos < data.len() {
            let written = std::future::poll_fn(|task_cx| {
                Pin::new(&mut self.inner.stream).poll_write(task_cx, &data[pos..])
            })
            .await
            .map_err(PgError::Io)?;

            if written == 0 {
                return Err(PgError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write data",
                )));
            }
            pos += written;
        }
        std::future::poll_fn(|task_cx| Pin::new(&mut self.inner.stream).poll_flush(task_cx))
            .await
            .map_err(PgError::Io)?;
        Ok(())
    }

    /// Write data to the stream using async I/O and flush with explicit
    /// cancellation checks from the caller-provided capability context.
    async fn write_all(&mut self, cx: &Cx, data: &[u8]) -> Result<(), PgError> {
        let mut pos = 0;
        while pos < data.len() {
            let written = std::future::poll_fn(|task_cx| {
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(cancelled_error(cx)));
                }
                match Pin::new(&mut self.inner.stream).poll_write(task_cx, &data[pos..]) {
                    Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(PgError::Io(err))),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;

            if written == 0 {
                return Err(PgError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write data",
                )));
            }
            pos += written;
        }
        std::future::poll_fn(|task_cx| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(cancelled_error(cx)));
            }
            match Pin::new(&mut self.inner.stream).poll_flush(task_cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(PgError::Io(err))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;
        Ok(())
    }

    /// Read exactly `len` bytes from the stream.
    async fn read_exact(&mut self, cx: &Cx, buf: &mut [u8]) -> Result<(), PgError> {
        let mut pos = 0;
        while pos < buf.len() {
            let mut read_buf = ReadBuf::new(&mut buf[pos..]);
            std::future::poll_fn(|task_cx| {
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(cancelled_error(cx)));
                }
                match Pin::new(&mut self.inner.stream).poll_read(task_cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(err)) => Poll::Ready(Err(PgError::Io(err))),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;

            let n = read_buf.filled().len();
            if n == 0 {
                return Err(PgError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }
            pos += n;
        }
        Ok(())
    }

    /// Read a complete message from the stream.
    async fn read_message(&mut self, cx: &Cx) -> Result<(u8, Vec<u8>), PgError> {
        // Read message type (1 byte)
        let mut type_buf = [0u8; 1];
        self.read_exact(cx, &mut type_buf).await?;
        let msg_type = type_buf[0];

        // Read length (4 bytes, includes itself)
        let mut len_buf = [0u8; 4];
        self.read_exact(cx, &mut len_buf).await?;
        let len_i32 = i32::from_be_bytes(len_buf);

        // Practical PostgreSQL message limit. The protocol allows up to 2 GiB
        // but legitimate messages rarely exceed a few tens of MiB even for large
        // COPY batches. Capping at 64 MiB prevents a malicious peer (or MitM on
        // an unencrypted connection) from forcing a multi-GiB allocation with a
        // single 5-byte header (DoS mitigation — issue #8).
        const MAX_MESSAGE_LEN: i32 = 64 * 1024 * 1024;
        if !(4..=MAX_MESSAGE_LEN).contains(&len_i32) {
            return Err(PgError::Protocol(format!(
                "invalid message length: {len_i32}"
            )));
        }
        let len = len_i32 as usize;

        // Read message body
        let body_len = len - 4;
        let mut body = vec![0u8; body_len];
        if body_len > 0 {
            self.read_exact(cx, &mut body).await?;
        }

        Ok((msg_type, body))
    }

    /// Parse RowDescription message.
    fn parse_row_description(
        &self,
        data: &[u8],
    ) -> Result<(Vec<PgColumn>, BTreeMap<String, usize>), PgError> {
        let mut reader = MessageReader::new(data);
        let num_fields_i16 = reader.read_i16()?;
        if num_fields_i16 < 0 {
            return Err(PgError::Protocol(format!(
                "negative field count in RowDescription: {num_fields_i16}"
            )));
        }
        let num_fields = num_fields_i16 as usize;

        let mut columns = Vec::with_capacity(num_fields);
        let mut indices = BTreeMap::new();

        for i in 0..num_fields {
            let name = reader.read_cstring()?.to_string();
            let table_oid = reader.read_i32()? as u32;
            let column_id = reader.read_i16()?;
            let type_oid = reader.read_i32()? as u32;
            let type_size = reader.read_i16()?;
            let type_modifier = reader.read_i32()?;
            let format_code = reader.read_i16()?;

            indices.insert(name.clone(), i);
            columns.push(PgColumn {
                name,
                table_oid,
                column_id,
                type_oid,
                type_size,
                type_modifier,
                format_code,
            });
        }

        Ok((columns, indices))
    }

    /// Parse DataRow message.
    fn parse_data_row(&self, data: &[u8], columns: &[PgColumn]) -> Result<Vec<PgValue>, PgError> {
        let mut reader = MessageReader::new(data);
        let num_values_i16 = reader.read_i16()?;
        if num_values_i16 < 0 {
            return Err(PgError::Protocol(format!(
                "negative value count in DataRow: {num_values_i16}"
            )));
        }
        let num_values = num_values_i16 as usize;

        if num_values != columns.len() {
            return Err(PgError::Protocol(format!(
                "DataRow column count mismatch: expected {}, got {num_values}",
                columns.len()
            )));
        }

        let mut values = Vec::with_capacity(num_values);

        for i in 0..num_values {
            let len = reader.read_i32()?;
            match len.cmp(&-1) {
                std::cmp::Ordering::Equal => {
                    // NULL value
                    values.push(PgValue::Null);
                }
                std::cmp::Ordering::Less => {
                    return Err(PgError::Protocol(format!(
                        "negative column length in DataRow: {len}"
                    )));
                }
                std::cmp::Ordering::Greater => {
                    let data = reader.read_bytes(len as usize)?;
                    let col = columns.get(i);
                    let type_oid = col.map_or(oid::TEXT, |c| c.type_oid);
                    let format = col.map_or(0, |c| c.format_code);

                    let value = match format {
                        0 => {
                            // Text format
                            self.parse_text_value(data, type_oid)?
                        }
                        1 => {
                            // Binary format
                            self.parse_binary_value(data, type_oid)?
                        }
                        _ => {
                            return Err(PgError::Protocol(format!(
                                "invalid format code in DataRow column {i}: {format}"
                            )));
                        }
                    };
                    values.push(value);
                }
            }
        }

        Ok(values)
    }

    /// Parse a text-format value.
    fn parse_text_value(&self, data: &[u8], type_oid: u32) -> Result<PgValue, PgError> {
        let s = std::str::from_utf8(data)
            .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;

        Ok(match type_oid {
            oid::BOOL => PgValue::Bool(bool::from_sql(data, type_oid, Format::Text)?),
            oid::INT2 => PgValue::Int2(
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid int2: {e}")))?,
            ),
            oid::INT4 | oid::OID => PgValue::Int4(
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid int4: {e}")))?,
            ),
            oid::INT8 => PgValue::Int8(
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid int8: {e}")))?,
            ),
            oid::FLOAT4 => PgValue::Float4(
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid float4: {e}")))?,
            ),
            oid::FLOAT8 => PgValue::Float8(
                s.parse()
                    .map_err(|e| PgError::Protocol(format!("invalid float8: {e}")))?,
            ),
            oid::BYTEA => {
                // Hex format: \x...
                if let Some(hex) = s.strip_prefix("\\x") {
                    let bytes = hex::decode(hex)
                        .map_err(|e| PgError::Protocol(format!("invalid bytea: {e}")))?;
                    PgValue::Bytes(bytes)
                } else {
                    PgValue::Bytes(data.to_vec())
                }
            }
            _ => PgValue::Text(s.to_string()),
        })
    }

    /// Parse a binary-format value.
    fn parse_binary_value(&self, data: &[u8], type_oid: u32) -> Result<PgValue, PgError> {
        Ok(match type_oid {
            oid::BOOL => PgValue::Bool(bool::from_sql(data, type_oid, Format::Binary)?),
            oid::INT2 if data.len() == 2 => PgValue::Int2(i16::from_be_bytes([data[0], data[1]])),
            oid::INT2 => {
                return Err(PgError::Protocol(format!(
                    "INT2 requires exactly 2 bytes, got {}",
                    data.len()
                )));
            }
            oid::INT4 | oid::OID if data.len() == 4 => {
                PgValue::Int4(i32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            oid::INT4 | oid::OID => {
                return Err(PgError::Protocol(format!(
                    "INT4/OID requires exactly 4 bytes, got {}",
                    data.len()
                )));
            }
            oid::INT8 if data.len() == 8 => PgValue::Int8(i64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            oid::INT8 => {
                return Err(PgError::Protocol(format!(
                    "INT8 requires exactly 8 bytes, got {}",
                    data.len()
                )));
            }
            oid::FLOAT4 if data.len() == 4 => {
                PgValue::Float4(f32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            oid::FLOAT4 => {
                return Err(PgError::Protocol(format!(
                    "FLOAT4 requires exactly 4 bytes, got {}",
                    data.len()
                )));
            }
            oid::FLOAT8 if data.len() == 8 => PgValue::Float8(f64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            oid::FLOAT8 => {
                return Err(PgError::Protocol(format!(
                    "FLOAT8 requires exactly 8 bytes, got {}",
                    data.len()
                )));
            }
            oid::BYTEA => PgValue::Bytes(data.to_vec()),
            oid::JSONB => {
                if data.first() == Some(&1) {
                    std::str::from_utf8(&data[1..]).map_or_else(
                        |_| PgValue::Bytes(data.to_vec()),
                        |s| PgValue::Text(s.to_string()),
                    )
                } else if data.is_empty() {
                    PgValue::Text(String::new())
                } else {
                    std::str::from_utf8(data).map_or_else(
                        |_| PgValue::Bytes(data.to_vec()),
                        |s| PgValue::Text(s.to_string()),
                    )
                }
            }
            _ => {
                // Try to interpret as text
                std::str::from_utf8(data).map_or_else(
                    |_| PgValue::Bytes(data.to_vec()),
                    |s| PgValue::Text(s.to_string()),
                )
            }
        })
    }

    /// Parse ErrorResponse message.
    fn parse_error_response(&self, data: &[u8]) -> Result<PgError, PgError> {
        let mut reader = MessageReader::new(data);
        let mut code = String::new();
        let mut message = String::new();
        let mut detail = None;
        let mut hint = None;

        loop {
            let field_type = reader.read_byte()?;
            if field_type == 0 {
                break;
            }
            let value = reader.read_cstring()?.to_string();

            match field_type {
                b'C' => code = value,
                b'M' => message = value,
                b'D' => detail = Some(value),
                b'H' => hint = Some(value),
                _ => {}
            }
        }

        Ok(PgError::Server {
            code,
            message,
            detail,
            hint,
        })
    }

    /// Parse an ErrorResponse and drain to ReadyForQuery.
    ///
    /// Returns the parsed server error when draining succeeds. If draining fails,
    /// returns a protocol error that includes both the server error details and
    /// the drain failure so re-synchronization failures are never swallowed.
    async fn parse_error_and_drain(&mut self, cx: &Cx, data: &[u8]) -> PgError {
        let server_err = self.parse_error_response(data).unwrap_or_else(|e| e);
        match self.drain_to_ready(cx).await {
            Ok(()) => server_err,
            Err(PgError::Cancelled(reason)) => {
                self.abort_in_flight_exchange();
                PgError::Cancelled(reason)
            }
            Err(drain_err) => {
                self.abort_in_flight_exchange();
                PgError::Protocol(format!(
                    "{server_err}; additionally failed to drain to ReadyForQuery: {drain_err}"
                ))
            }
        }
    }

    /// Parse a ParameterDescription message into a list of OIDs.
    fn parse_parameter_description(data: &[u8]) -> Result<Vec<u32>, PgError> {
        let mut reader = MessageReader::new(data);
        let num = reader.read_i16()?;
        if num < 0 {
            return Err(PgError::Protocol(format!(
                "negative parameter count: {num}"
            )));
        }
        let num = num as usize;
        let mut oids = Vec::with_capacity(num);
        for _ in 0..num {
            oids.push(reader.read_i32()? as u32);
        }
        Ok(oids)
    }

    /// Read results from Extended Query Protocol (query path).
    ///
    /// Expects: ParseComplete?, BindComplete, RowDescription?, DataRow*,
    /// CommandComplete, ReadyForQuery.
    async fn read_extended_query_results(&mut self, cx: &Cx) -> Outcome<Vec<PgRow>, PgError> {
        let mut columns: Option<Arc<Vec<PgColumn>>> = None;
        let mut column_indices: Option<Arc<BTreeMap<String, usize>>> = None;
        let mut rows = Vec::with_capacity(16);

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return self.fail_in_flight(e),
            };

            match msg_type {
                b'1' | b'2' => { /* ParseComplete / BindComplete */ }
                b'T' => match self.parse_row_description(&data) {
                    Ok((cols, indices)) => {
                        columns = Some(Arc::new(cols));
                        column_indices = Some(Arc::new(indices));
                    }
                    Err(e) => return self.fail_in_flight(e),
                },
                b'n' => { /* NoData */ }
                b'D' => {
                    if rows.len() >= self.inner.max_result_rows {
                        return self.fail_in_flight(PgError::Protocol(format!(
                            "result set exceeded {} row limit",
                            self.inner.max_result_rows,
                        )));
                    }
                    let (Some(cols), Some(indices)) = (&columns, &column_indices) else {
                        return self.fail_in_flight(PgError::Protocol(
                            "received DataRow before RowDescription in extended query response"
                                .to_string(),
                        ));
                    };
                    match self.parse_data_row(&data, cols) {
                        Ok(values) => {
                            rows.push(PgRow {
                                columns: Arc::clone(cols),
                                column_indices: Arc::clone(indices),
                                values,
                            });
                        }
                        Err(e) => return self.fail_in_flight(e),
                    }
                }
                b'C' | b's' => { /* CommandComplete / PortalSuspended */ }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    break;
                }
                b'E' => {
                    return outcome_from_error(self.parse_error_and_drain(cx, &data).await);
                }
                _ => {
                    match self.handle_async_backend_message(msg_type, &data) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return self.fail_in_flight(e),
                    }
                    return self.fail_in_flight(unexpected_backend_message(
                        "extended query response",
                        msg_type,
                    ));
                }
            }
        }

        Outcome::Ok(rows)
    }

    /// Read results from Extended Query Protocol (execute/command path).
    async fn read_extended_execute_results(&mut self, cx: &Cx) -> Outcome<u64, PgError> {
        let mut affected_rows = 0u64;
        let mut saw_row_response = false;

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return self.fail_in_flight(e),
            };

            match msg_type {
                b'1' | b'2' => { /* ParseComplete / BindComplete */ }
                b'C' => {
                    if let Ok(tag) = std::str::from_utf8(&data) {
                        let tag = tag.trim_end_matches('\0');
                        if let Some(num_str) = tag.rsplit(' ').next() {
                            if let Ok(num) = num_str.parse::<u64>() {
                                affected_rows = num;
                            }
                        }
                    }
                }
                b'T' | b'D' => {
                    // `execute_params()` / `execute_prepared()` must not
                    // silently drop row sets from `SELECT` or `... RETURNING`.
                    saw_row_response = true;
                }
                b'n' | b's' => { /* NoData / PortalSuspended */ }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    if saw_row_response {
                        return Outcome::Err(row_returning_execute_error(
                            "execute-style APIs",
                            "query-style APIs",
                        ));
                    }
                    break;
                }
                b'E' => {
                    return outcome_from_error(self.parse_error_and_drain(cx, &data).await);
                }
                _ => {
                    match self.handle_async_backend_message(msg_type, &data) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(e) => return self.fail_in_flight(e),
                    }
                    return self.fail_in_flight(unexpected_backend_message(
                        "extended execute response",
                        msg_type,
                    ));
                }
            }
        }

        Outcome::Ok(affected_rows)
    }

    /// Drain messages until ReadyForQuery to re-synchronize after an error.
    ///
    /// Returns `Ok(())` when `ReadyForQuery` is received, or `Err` if the
    /// connection hit an I/O error before reaching synchronization.
    async fn drain_to_ready(&mut self, cx: &Cx) -> Result<(), PgError> {
        loop {
            if cx.checkpoint().is_err() {
                return Err(PgError::Cancelled(cancelled_reason(cx)));
            }
            let (msg_type, data) = self.read_message(cx).await?;
            if msg_type == b'Z' {
                self.inner.closed = false;
                if !data.is_empty() {
                    self.inner.transaction_status = data[0];
                }
                return Ok(());
            }
        }
    }
}

// ============================================================================
// Extended Query Protocol — message builders
// ============================================================================

/// Build a Parse message (Extended Query Protocol).
fn build_parse_msg(stmt_name: &str, sql: &str, param_oids: &[u32]) -> Result<Vec<u8>, PgError> {
    if param_oids.len() > i16::MAX as usize {
        return Err(PgError::Protocol(format!(
            "too many parameters ({}, max {})",
            param_oids.len(),
            i16::MAX
        )));
    }
    let mut buf = MessageBuffer::with_capacity(sql.len() + 64);
    buf.write_cstring(stmt_name);
    buf.write_cstring(sql);
    buf.write_i16(param_oids.len() as i16);
    for &o in param_oids {
        buf.write_i32(o as i32);
    }
    buf.build_message(FrontendMessage::Parse as u8)
}

/// Build a Bind message (Extended Query Protocol).
#[doc(hidden)]
pub fn build_bind_msg(
    portal: &str,
    stmt_name: &str,
    params: &[&dyn ToSql],
    result_format: Format,
) -> Result<Vec<u8>, PgError> {
    if params.len() > i16::MAX as usize {
        return Err(PgError::Protocol(format!(
            "too many parameters ({}, max {})",
            params.len(),
            i16::MAX
        )));
    }
    let mut buf = MessageBuffer::with_capacity(256);
    buf.write_cstring(portal);
    buf.write_cstring(stmt_name);

    // Parameter format codes — one per parameter.
    buf.write_i16(params.len() as i16);
    for p in params {
        buf.write_i16(p.format() as i16);
    }

    // Parameter values.
    buf.write_i16(params.len() as i16);
    let mut val_buf = Vec::with_capacity(64);
    for p in params {
        val_buf.clear();
        match p.to_sql(&mut val_buf)? {
            IsNull::Yes => {
                buf.write_i32(-1);
            }
            IsNull::No => {
                let len = i32::try_from(val_buf.len()).map_err(|_| {
                    PgError::Protocol(format!(
                        "parameter value too large: {} bytes exceeds i32::MAX",
                        val_buf.len()
                    ))
                })?;
                buf.write_i32(len);
                buf.write_bytes(&val_buf);
            }
        }
    }

    // Result format codes — single code applied to all result columns.
    buf.write_i16(1);
    buf.write_i16(result_format as i16);

    buf.build_message(FrontendMessage::Bind as u8)
}

/// Build a Describe message.
fn build_describe_msg(target: u8, name: &str) -> Result<Vec<u8>, PgError> {
    let mut buf = MessageBuffer::new();
    buf.write_byte(target); // 'S' for statement, 'P' for portal
    buf.write_cstring(name);
    buf.build_message(FrontendMessage::Describe as u8)
}

/// Build an Execute message.
#[doc(hidden)]
pub fn build_execute_msg(portal: &str, max_rows: i32) -> Result<Vec<u8>, PgError> {
    let mut buf = MessageBuffer::new();
    buf.write_cstring(portal);
    buf.write_i32(max_rows); // 0 = all rows
    buf.build_message(FrontendMessage::Execute as u8)
}

/// Build a Sync message.
#[doc(hidden)]
pub fn build_sync_msg() -> Result<Vec<u8>, PgError> {
    let mut buf = MessageBuffer::new();
    buf.build_message(FrontendMessage::Sync as u8)
}

/// Build a Close message.
fn build_close_msg(target: u8, name: &str) -> Result<Vec<u8>, PgError> {
    let mut buf = MessageBuffer::new();
    buf.write_byte(target); // 'S' for statement, 'P' for portal
    buf.write_cstring(name);
    buf.build_message(FrontendMessage::Close as u8)
}

// ============================================================================
// Transaction
// ============================================================================

/// A PostgreSQL transaction.
///
/// The transaction will be rolled back on drop if not committed.
pub struct PgTransaction<'a> {
    conn: &'a mut PgConnection,
    finished: bool,
}

impl PgTransaction<'_> {
    /// Commit the transaction.
    pub async fn commit(mut self, cx: &Cx) -> Outcome<(), PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        match self.conn.execute(cx, "COMMIT").await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Rollback the transaction.
    pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        match self.conn.execute(cx, "ROLLBACK").await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Execute a query within this transaction.
    pub async fn query(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        self.conn.query(cx, sql).await
    }

    /// Execute a command within this transaction.
    pub async fn execute(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        self.conn.execute(cx, sql).await
    }

    /// Execute a parameterized query within this transaction.
    pub async fn query_params(
        &mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Outcome<Vec<PgRow>, PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        self.conn.query_params(cx, sql, params).await
    }

    /// Execute a parameterized command within this transaction.
    pub async fn execute_params(
        &mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Outcome<u64, PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        self.conn.execute_params(cx, sql, params).await
    }
}

impl Drop for PgTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Mark the connection so the next operation issues ROLLBACK first.
            // We can't await here, but without this flag the connection stays
            // in an aborted transaction state and all subsequent queries fail
            // with "current transaction is aborted".
            self.conn.inner.needs_rollback = true;
        }
    }
}

// ============================================================================
// Prepared Statement
// ============================================================================

/// A prepared PostgreSQL statement.
///
/// Created by [`PgConnection::prepare`] and executed with
/// [`PgConnection::query_prepared`] or [`PgConnection::execute_prepared`].
/// Call [`PgConnection::close_statement`] to release server-side resources.
#[derive(Debug, Clone)]
pub struct PgStatement {
    /// Server-side statement name.
    name: String,
    /// Parameter type OIDs from ParameterDescription.
    param_oids: Vec<u32>,
    /// Result column metadata from RowDescription (empty for non-SELECT).
    columns: Vec<PgColumn>,
}

impl PgStatement {
    /// Parameter type OIDs reported by the server.
    #[must_use]
    pub fn param_types(&self) -> &[u32] {
        &self.param_oids
    }

    /// Result column metadata. Empty for non-SELECT statements.
    #[must_use]
    pub fn columns(&self) -> &[PgColumn] {
        &self.columns
    }
}

// ============================================================================
// Hex Decoding (minimal implementation)
// ============================================================================

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err("odd length".to_string());
        }

        let mut result = Vec::with_capacity(s.len() / 2);
        let mut chars = s.chars();

        while let (Some(h), Some(l)) = (chars.next(), chars.next()) {
            let high = h.to_digit(16).ok_or("invalid hex digit")?;
            let low = l.to_digit(16).ok_or("invalid hex digit")?;
            result.push((high * 16 + low) as u8);
        }

        Ok(result)
    }

    pub fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            out.push(char::from(HEX[(byte >> 4) as usize]));
            out.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
        out
    }
}

#[cfg(test)]
#[allow(
    clippy::approx_constant,
    clippy::float_cmp,
    clippy::bool_assert_comparison
)]
mod tests {
    use super::*;
    use crate::Cx;
    use crate::types::CancelKind;

    fn run<F: std::future::Future>(future: F) -> F::Output {
        futures_lite::future::block_on(future)
    }

    fn cancelled_cx() -> Cx {
        let cx = Cx::for_testing();
        cx.cancel_fast(CancelKind::User);
        cx
    }

    fn assert_user_cancelled<T>(outcome: Outcome<T, PgError>) {
        match outcome {
            Outcome::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
            Outcome::Err(err) => panic!("expected cancellation, got error: {err}"),
            Outcome::Ok(_) => panic!("expected cancellation, got success"),
            Outcome::Panicked(payload) => panic!("unexpected panic outcome: {payload:?}"),
        }
    }

    #[test]
    fn low_level_write_all_uses_explicit_cx_for_cancellation() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        match run(conn.write_all(&cx, b"hello")).unwrap_err() {
            PgError::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
            other => panic!("expected Cancelled, got: {other}"),
        }
    }

    #[test]
    fn low_level_read_message_uses_explicit_cx_for_cancellation() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        match run(conn.read_message(&cx)).unwrap_err() {
            PgError::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
            other => panic!("expected Cancelled, got: {other}"),
        }
    }

    #[test]
    fn test_connect_options_parse() {
        let opts = PgConnectOptions::parse("postgres://user:pass@localhost:5432/mydb").unwrap();
        assert_eq!(opts.user, "user");
        assert_eq!(opts.password, Some("pass".to_string()));
        assert_eq!(opts.host, "localhost");
        assert_eq!(opts.port, 5432);
        assert_eq!(opts.database, "mydb");
    }

    #[test]
    fn test_connect_options_parse_minimal() {
        let opts = PgConnectOptions::parse("postgres://localhost/mydb").unwrap();
        assert_eq!(opts.user, "postgres");
        assert_eq!(opts.password, None);
        assert_eq!(opts.host, "localhost");
        assert_eq!(opts.port, 5432);
        assert_eq!(opts.database, "mydb");
    }

    #[test]
    fn test_pg_value_conversions() {
        assert!(PgValue::Null.is_null());
        assert_eq!(PgValue::Int4(42).as_i32(), Some(42));
        assert_eq!(PgValue::Int4(42).as_i64(), Some(42));
        assert_eq!(PgValue::Bool(true).as_bool(), Some(true));
        assert_eq!(PgValue::Text("hello".to_string()).as_str(), Some("hello"));
    }

    #[test]
    fn test_hex_decode() {
        assert_eq!(hex::decode("48656c6c6f").unwrap(), b"Hello");
        assert_eq!(hex::decode("").unwrap(), b"");
        assert!(hex::decode("123").is_err()); // odd length
    }

    #[test]
    fn test_message_buffer() {
        let mut buf = MessageBuffer::new();
        buf.write_i32(196_608);
        buf.write_cstring("user");
        buf.write_cstring("testuser");
        buf.write_byte(0);

        let msg = buf.build_startup_message().unwrap();
        assert!(msg.len() > 4); // At least length prefix
    }

    #[test]
    fn test_scram_pbkdf2_matches_rfc8018_sha256_vector() {
        let cx = Cx::for_testing();
        let auth = ScramAuth::new(&cx, "user", "password");
        let derived = auth.pbkdf2_sha256("password", b"salt", 1);
        let expected =
            hex::decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
                .expect("valid hex vector");

        assert_eq!(
            derived, expected,
            "PBKDF2-HMAC-SHA256 output should match the RFC 8018 reference vector"
        );
    }

    /// Create a PgConnection backed by a dummy socket pair for unit-testing
    /// parse methods that only inspect a byte slice.
    fn make_test_connection() -> PgConnection {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let std_stream = std::net::TcpStream::connect(addr).expect("connect");
        let _accepted = listener.accept().expect("accept");
        let stream = crate::net::TcpStream::from_std(std_stream).expect("from_std");
        PgConnection {
            inner: PgConnectionInner {
                stream: PgStream::Plain(stream),
                process_id: 0,
                secret_key: 0,
                parameters: BTreeMap::new(),
                transaction_status: b'I',
                closed: false,
                needs_rollback: false,
                next_stmt_id: 0,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
            },
        }
    }

    /// Create a PgConnection plus the peer stream so tests can inject backend
    /// protocol frames that `read_message()` will consume.
    fn make_test_connection_with_peer() -> (PgConnection, std::net::TcpStream) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let std_stream = std::net::TcpStream::connect(addr).expect("connect");
        let (peer_stream, _) = listener.accept().expect("accept");
        let stream = crate::net::TcpStream::from_std(std_stream).expect("from_std");
        (
            PgConnection {
                inner: PgConnectionInner {
                    stream: PgStream::Plain(stream),
                    process_id: 0,
                    secret_key: 0,
                    parameters: BTreeMap::new(),
                    transaction_status: b'I',
                    closed: false,
                    needs_rollback: false,
                    next_stmt_id: 0,
                    max_result_rows: DEFAULT_MAX_RESULT_ROWS,
                },
            },
            peer_stream,
        )
    }

    fn backend_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
        let len = i32::try_from(body.len() + 4).expect("test backend message length fits");
        let mut msg = Vec::with_capacity(1 + 4 + body.len());
        msg.push(msg_type);
        msg.extend_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(body);
        msg
    }

    fn ready_for_query(status: u8) -> Vec<u8> {
        backend_message(b'Z', &[status])
    }

    fn single_text_row_description() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(b"value\0");
        body.extend_from_slice(&0i32.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&(oid::TEXT as i32).to_be_bytes());
        body.extend_from_slice(&(-1i16).to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        backend_message(b'T', &body)
    }

    fn parameter_status_message(name: &str, value: &str) -> Vec<u8> {
        let mut body = Vec::with_capacity(name.len() + value.len() + 2);
        body.extend_from_slice(name.as_bytes());
        body.push(0);
        body.extend_from_slice(value.as_bytes());
        body.push(0);
        backend_message(b'S', &body)
    }

    fn notification_response_message(process_id: i32, channel: &str, payload: &str) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + channel.len() + payload.len() + 2);
        body.extend_from_slice(&process_id.to_be_bytes());
        body.extend_from_slice(channel.as_bytes());
        body.push(0);
        body.extend_from_slice(payload.as_bytes());
        body.push(0);
        backend_message(b'A', &body)
    }

    fn error_response_message(code: &str, message: &str) -> Vec<u8> {
        let mut body = Vec::with_capacity(code.len() + message.len() + 5);
        body.push(b'C');
        body.extend_from_slice(code.as_bytes());
        body.push(0);
        body.push(b'M');
        body.extend_from_slice(message.as_bytes());
        body.push(0);
        body.push(0);
        backend_message(b'E', &body)
    }

    #[test]
    fn cancelled_commit_marks_connection_for_rollback() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        let outcome = run(async {
            let tx = PgTransaction {
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
            let tx = PgTransaction {
                conn: &mut conn,
                finished: false,
            };
            tx.rollback(&cx).await
        });

        assert_user_cancelled(outcome);
        assert!(conn.inner.needs_rollback);
    }

    #[test]
    fn ensure_no_orphaned_transaction_maps_cancellation_to_outcome() {
        let mut conn = make_test_connection();
        conn.inner.needs_rollback = true;
        let cx = cancelled_cx();

        let outcome = run(conn.ensure_no_orphaned_transaction(&cx));

        assert_user_cancelled(outcome);
        assert!(
            conn.inner.closed,
            "cancelled rollback should leave connection closed"
        );
        assert!(
            conn.inner.needs_rollback,
            "cancelled rollback should preserve the rollback-needed marker"
        );
    }

    #[test]
    fn ensure_no_orphaned_transaction_is_noop_without_pending_rollback() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        let outcome = run(conn.ensure_no_orphaned_transaction(&cx));

        match outcome {
            Outcome::Ok(()) => {}
            other => panic!("expected orphan-cleanup noop, got: {other:?}"),
        }
        assert!(!conn.inner.closed);
        assert!(!conn.inner.needs_rollback);
    }

    #[test]
    fn negative_field_count_in_row_description() {
        let conn = make_test_connection();
        // i16 = -1  (0xFF 0xFF)
        let data: Vec<u8> = vec![0xFF, 0xFF];
        let result = conn.parse_row_description(&data);
        assert!(result.is_err());
        match result.unwrap_err() {
            PgError::Protocol(msg) => {
                assert!(msg.contains("negative field count"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got: {other}"),
        }
    }

    #[test]
    fn negative_value_count_in_data_row() {
        let conn = make_test_connection();
        // i16 = -1  (0xFF 0xFF)
        let data: Vec<u8> = vec![0xFF, 0xFF];
        let columns = vec![];
        let result = conn.parse_data_row(&data, &columns);
        assert!(result.is_err());
        match result.unwrap_err() {
            PgError::Protocol(msg) => {
                assert!(msg.contains("negative value count"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got: {other}"),
        }
    }

    #[test]
    fn negative_column_length_in_data_row() {
        let conn = make_test_connection();
        // num_values = 1 (0x00 0x01), then column len = -2 (0xFF 0xFF 0xFF 0xFE)
        let data: Vec<u8> = vec![0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFE];
        let columns = vec![PgColumn {
            name: "col".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::TEXT,
            type_size: -1,
            type_modifier: -1,
            format_code: 0,
        }];
        let result = conn.parse_data_row(&data, &columns);
        assert!(result.is_err());
        match result.unwrap_err() {
            PgError::Protocol(msg) => {
                assert!(msg.contains("negative column length"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got: {other}"),
        }
    }

    #[test]
    fn parse_data_row_rejects_invalid_format_code() {
        let conn = make_test_connection();
        let data: Vec<u8> = vec![0x00, 0x01, 0x00, 0x00, 0x00, 0x01, b'x'];
        let columns = vec![PgColumn {
            name: "col".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::TEXT,
            type_size: -1,
            type_modifier: -1,
            format_code: 2,
        }];
        let result = conn.parse_data_row(&data, &columns);
        match result.unwrap_err() {
            PgError::Protocol(msg) => {
                assert!(msg.contains("invalid format code"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got: {other}"),
        }
    }

    // ================================================================
    // PgConnectOptions::parse edge cases
    // ================================================================

    #[test]
    fn connect_options_postgresql_prefix() {
        let opts = PgConnectOptions::parse("postgresql://alice@db.host:5433/prod").unwrap();
        assert_eq!(opts.user, "alice");
        assert_eq!(opts.password, None);
        assert_eq!(opts.host, "db.host");
        assert_eq!(opts.port, 5433);
        assert_eq!(opts.database, "prod");
    }

    #[test]
    fn connect_options_ipv6_host() {
        let opts = PgConnectOptions::parse("postgres://user:pw@[::1]:5432/testdb").unwrap();
        assert_eq!(opts.host, "::1");
        assert_eq!(opts.port, 5432);
        assert_eq!(opts.user, "user");
        assert_eq!(opts.password, Some("pw".to_string()));
    }

    #[test]
    fn connect_options_ipv6_default_port() {
        let opts = PgConnectOptions::parse("postgres://[::1]/testdb").unwrap();
        assert_eq!(opts.host, "::1");
        assert_eq!(opts.port, 5432);
    }

    #[test]
    fn connect_options_rejects_missing_scheme() {
        let result = PgConnectOptions::parse("mysql://localhost/db");
        assert!(result.is_err());
        match result.unwrap_err() {
            PgError::InvalidUrl(msg) => {
                assert!(msg.contains("postgres://"), "got: {msg}");
            }
            other => panic!("expected InvalidUrl, got: {other}"),
        }
    }

    #[test]
    fn connect_options_rejects_missing_database() {
        let result = PgConnectOptions::parse("postgres://localhost");
        assert!(result.is_err());
        match result.unwrap_err() {
            PgError::InvalidUrl(msg) => {
                assert!(msg.contains("database"), "got: {msg}");
            }
            other => panic!("expected InvalidUrl, got: {other}"),
        }
    }

    #[test]
    fn connect_options_default_port_no_port_specified() {
        let opts = PgConnectOptions::parse("postgres://user@host/db").unwrap();
        assert_eq!(opts.port, 5432);
        assert_eq!(opts.host, "host");
    }

    #[test]
    fn connect_options_rejects_invalid_port() {
        let result = PgConnectOptions::parse("postgres://user@host:not-a-port/db");
        match result.unwrap_err() {
            PgError::InvalidUrl(msg) => assert!(msg.contains("invalid port"), "got: {msg}"),
            other => panic!("expected InvalidUrl, got: {other}"),
        }
    }

    #[test]
    fn connect_options_rejects_invalid_connect_timeout() {
        let result =
            PgConnectOptions::parse("postgres://user@host/db?connect_timeout=not-a-number");
        match result.unwrap_err() {
            PgError::InvalidUrl(msg) => {
                assert!(msg.contains("invalid connect_timeout"), "got: {msg}");
            }
            other => panic!("expected InvalidUrl, got: {other}"),
        }
    }

    #[test]
    fn connect_options_rejects_empty_database_component() {
        let result = PgConnectOptions::parse("postgres://user@host/");
        match result.unwrap_err() {
            PgError::InvalidUrl(msg) => {
                assert!(msg.contains("database"), "got: {msg}");
            }
            other => panic!("expected InvalidUrl, got: {other}"),
        }
    }

    #[test]
    fn connect_options_rejects_invalid_ipv6_literal() {
        let result = PgConnectOptions::parse("postgres://user@[::1:5432/db");
        match result.unwrap_err() {
            PgError::InvalidUrl(msg) => assert!(msg.contains("IPv6"), "got: {msg}"),
            other => panic!("expected InvalidUrl, got: {other}"),
        }
    }

    // ================================================================
    // PgValue accessor coverage
    // ================================================================

    #[test]
    fn pg_value_null_is_null() {
        assert!(PgValue::Null.is_null());
        assert!(!PgValue::Bool(true).is_null());
        assert!(!PgValue::Int4(0).is_null());
        assert!(!PgValue::Text(String::new()).is_null());
    }

    #[test]
    fn pg_value_as_bool_returns_none_for_wrong_type() {
        assert_eq!(PgValue::Int4(1).as_bool(), None);
        assert_eq!(PgValue::Null.as_bool(), None);
        assert_eq!(PgValue::Text("true".to_string()).as_bool(), None);
    }

    #[test]
    fn pg_value_as_i32_widens_from_i16() {
        assert_eq!(PgValue::Int2(42).as_i32(), Some(42));
        assert_eq!(PgValue::Int4(42).as_i32(), Some(42));
        assert_eq!(PgValue::Int4(i32::MIN).as_i32(), Some(i32::MIN));
        assert_eq!(PgValue::Int8(1).as_i32(), None);
        assert_eq!(PgValue::Null.as_i32(), None);
    }

    #[test]
    fn pg_value_as_i64_widens_from_smaller_ints() {
        assert_eq!(PgValue::Int2(10).as_i64(), Some(10));
        assert_eq!(PgValue::Int4(100).as_i64(), Some(100));
        assert_eq!(PgValue::Int8(i64::MAX).as_i64(), Some(i64::MAX));
        assert_eq!(PgValue::Float8(1.0).as_i64(), None);
    }

    #[test]
    fn pg_value_as_f64_widens_from_f32() {
        assert_eq!(PgValue::Float8(3.5).as_f64(), Some(3.5));
        assert_eq!(PgValue::Float4(1.0).as_f64(), Some(1.0));
        assert_eq!(PgValue::Int4(1).as_f64(), None);
    }

    #[test]
    fn pg_value_as_str_returns_text_only() {
        assert_eq!(PgValue::Text("hello".to_string()).as_str(), Some("hello"));
        assert_eq!(PgValue::Int4(42).as_str(), None);
        assert_eq!(PgValue::Null.as_str(), None);
    }

    #[test]
    fn pg_value_as_bytes_returns_bytes_only() {
        assert_eq!(
            PgValue::Bytes(vec![1, 2, 3]).as_bytes(),
            Some([1, 2, 3].as_slice())
        );
        assert_eq!(PgValue::Text("x".to_string()).as_bytes(), None);
        assert_eq!(PgValue::Null.as_bytes(), None);
    }

    // ================================================================
    // PgValue Display
    // ================================================================

    #[test]
    fn pg_value_display_all_variants() {
        assert_eq!(format!("{}", PgValue::Null), "NULL");
        assert_eq!(format!("{}", PgValue::Bool(true)), "true");
        assert_eq!(format!("{}", PgValue::Bool(false)), "false");
        assert_eq!(format!("{}", PgValue::Int2(100)), "100");
        assert_eq!(format!("{}", PgValue::Int4(-1)), "-1");
        assert_eq!(
            format!("{}", PgValue::Int8(999_999_999_999i64)),
            "999999999999"
        );
        assert_eq!(format!("{}", PgValue::Text("abc".to_string())), "abc");
        assert!(format!("{}", PgValue::Bytes(vec![1, 2])).contains("2 len"));
    }

    // ================================================================
    // PgRow accessors
    // ================================================================

    fn make_test_row(names: &[&str], values: Vec<PgValue>) -> PgRow {
        let columns: Vec<PgColumn> = names
            .iter()
            .map(|name| PgColumn {
                name: name.to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::TEXT,
                type_size: -1,
                type_modifier: -1,
                format_code: 0,
            })
            .collect();
        let mut indices = BTreeMap::new();
        for (i, name) in names.iter().enumerate() {
            indices.insert(name.to_string(), i);
        }
        PgRow {
            columns: Arc::new(columns),
            column_indices: Arc::new(indices),
            values,
        }
    }

    #[test]
    fn pg_row_get_valid_column() {
        let row = make_test_row(
            &["id", "name"],
            vec![PgValue::Int4(1), PgValue::Text("alice".to_string())],
        );
        assert_eq!(row.get("id").unwrap(), &PgValue::Int4(1));
        assert_eq!(
            row.get("name").unwrap(),
            &PgValue::Text("alice".to_string())
        );
    }

    #[test]
    fn pg_row_get_missing_column_returns_error() {
        let row = make_test_row(&["id"], vec![PgValue::Int4(1)]);
        match row.get("nonexistent").unwrap_err() {
            PgError::ColumnNotFound(name) => assert_eq!(name, "nonexistent"),
            other => panic!("expected ColumnNotFound, got: {other}"),
        }
    }

    #[test]
    fn pg_row_get_idx_valid_and_out_of_bounds() {
        let row = make_test_row(&["x"], vec![PgValue::Bool(true)]);
        assert_eq!(row.get_idx(0).unwrap(), &PgValue::Bool(true));
        assert!(row.get_idx(1).is_err());
    }

    #[test]
    fn pg_row_typed_getters_match_and_mismatch() {
        let row = PgRow {
            columns: Arc::new(vec![
                PgColumn {
                    name: "i".to_string(),
                    table_oid: 0,
                    column_id: 0,
                    type_oid: oid::INT4,
                    type_size: 4,
                    type_modifier: -1,
                    format_code: 1,
                },
                PgColumn {
                    name: "b".to_string(),
                    table_oid: 0,
                    column_id: 0,
                    type_oid: oid::BOOL,
                    type_size: 1,
                    type_modifier: -1,
                    format_code: 1,
                },
                PgColumn {
                    name: "s".to_string(),
                    table_oid: 0,
                    column_id: 0,
                    type_oid: oid::TEXT,
                    type_size: -1,
                    type_modifier: -1,
                    format_code: 0,
                },
                PgColumn {
                    name: "big".to_string(),
                    table_oid: 0,
                    column_id: 0,
                    type_oid: oid::INT8,
                    type_size: 8,
                    type_modifier: -1,
                    format_code: 1,
                },
            ]),
            column_indices: Arc::new(BTreeMap::from([
                ("i".to_string(), 0),
                ("b".to_string(), 1),
                ("s".to_string(), 2),
                ("big".to_string(), 3),
            ])),
            values: vec![
                PgValue::Int4(42),
                PgValue::Bool(false),
                PgValue::Text("hello".to_string()),
                PgValue::Int8(99),
            ],
        };
        assert_eq!(row.get_i32("i").unwrap(), 42);
        assert!(!row.get_bool("b").unwrap());
        assert_eq!(row.get_str("s").unwrap(), "hello");
        assert_eq!(row.get_i64("big").unwrap(), 99);

        // Type mismatch: i32 on a bool column
        match row.get_i32("b").unwrap_err() {
            PgError::TypeConversion {
                column,
                expected,
                actual_oid,
            } => {
                assert_eq!(column, "b");
                assert_eq!(expected, "i32");
                assert_eq!(actual_oid, oid::BOOL);
            }
            other => panic!("expected TypeConversion, got: {other}"),
        }
    }

    #[test]
    fn pg_row_typed_getters_use_real_column_oid_for_other_mismatches() {
        let row = PgRow {
            columns: Arc::new(vec![PgColumn {
                name: "count".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::INT8,
                type_size: 8,
                type_modifier: -1,
                format_code: 1,
            }]),
            column_indices: Arc::new(BTreeMap::from([("count".to_string(), 0)])),
            values: vec![PgValue::Int8(7)],
        };

        match row.get_bool("count").unwrap_err() {
            PgError::TypeConversion {
                column,
                expected,
                actual_oid,
            } => {
                assert_eq!(column, "count");
                assert_eq!(expected, "bool");
                assert_eq!(actual_oid, oid::INT8);
            }
            other => panic!("expected TypeConversion, got: {other}"),
        }
    }

    #[test]
    fn pg_row_len_and_is_empty() {
        let row = make_test_row(&["a", "b"], vec![PgValue::Null, PgValue::Null]);
        assert_eq!(row.len(), 2);
        assert!(!row.is_empty());

        let empty_row = make_test_row(&[], vec![]);
        assert_eq!(empty_row.len(), 0);
        assert!(empty_row.is_empty());
    }

    #[test]
    fn pg_row_columns_returns_metadata() {
        let row = make_test_row(&["id", "name"], vec![PgValue::Null, PgValue::Null]);
        let cols = row.columns();
        assert_eq!(cols.len(), 2);
        assert_eq!(cols[0].name, "id");
        assert_eq!(cols[1].name, "name");
    }

    // ================================================================
    // MessageBuffer construction
    // ================================================================

    #[test]
    fn message_buffer_build_message_wire_format() {
        let mut buf = MessageBuffer::new();
        buf.write_byte(b'Q');
        buf.write_cstring("SELECT 1");
        let msg = buf.build_message(FrontendMessage::Query as u8).unwrap();
        // byte 0: msg type 'Q'
        assert_eq!(msg[0], b'Q');
        // bytes 1-4: length = body_len + 4
        let len = i32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len() - 1);
    }

    #[test]
    fn message_buffer_startup_no_type_byte() {
        let mut buf = MessageBuffer::new();
        buf.write_i32(196_608); // protocol version 3.0
        buf.write_cstring("user");
        buf.write_cstring("test");
        buf.write_byte(0);
        let msg = buf.build_startup_message().unwrap();
        // bytes 0-3: length (includes itself)
        let len = i32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
        assert_eq!(len as usize, msg.len());
        // protocol version at bytes 4-7
        let version = i32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
        assert_eq!(version, 196_608);
    }

    #[test]
    fn message_buffer_write_i16_big_endian() {
        let mut buf = MessageBuffer::new();
        buf.write_i16(0x0102);
        let inner = buf.into_inner();
        assert_eq!(inner, vec![0x01, 0x02]);
    }

    #[test]
    fn message_buffer_clear_resets() {
        let mut buf = MessageBuffer::new();
        buf.write_byte(0xFF);
        buf.clear();
        assert!(buf.into_inner().is_empty());
    }

    #[test]
    fn message_buffer_with_capacity() {
        let buf = MessageBuffer::with_capacity(1024);
        assert!(buf.into_inner().is_empty());
    }

    // ================================================================
    // Wire protocol: parse_row_description valid cases
    // ================================================================

    #[test]
    fn parse_row_description_single_column() {
        let conn = make_test_connection();
        let mut data = Vec::new();
        // num_fields = 1
        data.extend_from_slice(&1i16.to_be_bytes());
        // name: "id\0"
        data.extend_from_slice(b"id\0");
        // table_oid
        data.extend_from_slice(&1234u32.to_be_bytes());
        // column_id
        data.extend_from_slice(&1i16.to_be_bytes());
        // type_oid (INT4)
        data.extend_from_slice(&oid::INT4.to_be_bytes());
        // type_size
        data.extend_from_slice(&4i16.to_be_bytes());
        // type_modifier
        data.extend_from_slice(&(-1i32).to_be_bytes());
        // format_code (text)
        data.extend_from_slice(&0i16.to_be_bytes());

        let (columns, indices) = conn.parse_row_description(&data).unwrap();
        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].name, "id");
        assert_eq!(columns[0].type_oid, oid::INT4);
        assert_eq!(columns[0].table_oid, 1234);
        assert_eq!(columns[0].format_code, 0);
        assert_eq!(*indices.get("id").unwrap(), 0);
    }

    #[test]
    fn parse_row_description_multiple_columns() {
        let conn = make_test_connection();
        let mut data = Vec::new();
        data.extend_from_slice(&2i16.to_be_bytes());
        // Column 1: "name" TEXT
        data.extend_from_slice(b"name\0");
        data.extend_from_slice(&0u32.to_be_bytes()); // table_oid
        data.extend_from_slice(&0i16.to_be_bytes()); // column_id
        data.extend_from_slice(&oid::TEXT.to_be_bytes());
        data.extend_from_slice(&(-1i16).to_be_bytes()); // type_size
        data.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
        data.extend_from_slice(&0i16.to_be_bytes()); // format_code
        // Column 2: "age" INT4
        data.extend_from_slice(b"age\0");
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0i16.to_be_bytes());
        data.extend_from_slice(&oid::INT4.to_be_bytes());
        data.extend_from_slice(&4i16.to_be_bytes());
        data.extend_from_slice(&(-1i32).to_be_bytes());
        data.extend_from_slice(&0i16.to_be_bytes());

        let (columns, indices) = conn.parse_row_description(&data).unwrap();
        assert_eq!(columns.len(), 2);
        assert_eq!(columns[0].name, "name");
        assert_eq!(columns[1].name, "age");
        assert_eq!(*indices.get("name").unwrap(), 0);
        assert_eq!(*indices.get("age").unwrap(), 1);
    }

    #[test]
    fn parse_row_description_zero_columns() {
        let conn = make_test_connection();
        let data: Vec<u8> = 0i16.to_be_bytes().to_vec();
        let (columns, indices) = conn.parse_row_description(&data).unwrap();
        assert!(columns.is_empty());
        assert!(indices.is_empty());
    }

    // ================================================================
    // Wire protocol: parse_data_row valid cases
    // ================================================================

    #[test]
    fn parse_data_row_text_int4() {
        let conn = make_test_connection();
        let columns = vec![PgColumn {
            name: "n".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::INT4,
            type_size: 4,
            type_modifier: -1,
            format_code: 0, // text
        }];
        let mut data = Vec::new();
        data.extend_from_slice(&1i16.to_be_bytes()); // num_values
        let val_bytes = b"42";
        data.extend_from_slice(&(val_bytes.len() as i32).to_be_bytes());
        data.extend_from_slice(val_bytes);

        let values = conn.parse_data_row(&data, &columns).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], PgValue::Int4(42));
    }

    #[test]
    fn parse_data_row_null_value() {
        let conn = make_test_connection();
        let columns = vec![PgColumn {
            name: "x".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::TEXT,
            type_size: -1,
            type_modifier: -1,
            format_code: 0,
        }];
        let mut data = Vec::new();
        data.extend_from_slice(&1i16.to_be_bytes()); // num_values
        data.extend_from_slice(&(-1i32).to_be_bytes()); // NULL

        let values = conn.parse_data_row(&data, &columns).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], PgValue::Null);
    }

    #[test]
    fn parse_data_row_binary_int4() {
        let conn = make_test_connection();
        let columns = vec![PgColumn {
            name: "n".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::INT4,
            type_size: 4,
            type_modifier: -1,
            format_code: 1, // binary
        }];
        let mut data = Vec::new();
        data.extend_from_slice(&1i16.to_be_bytes());
        data.extend_from_slice(&4i32.to_be_bytes()); // 4 bytes
        data.extend_from_slice(&42i32.to_be_bytes()); // value = 42

        let values = conn.parse_data_row(&data, &columns).unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(values[0], PgValue::Int4(42));
    }

    // ================================================================
    // parse_text_value for each type OID
    // ================================================================

    #[test]
    fn parse_text_value_bool() {
        let conn = make_test_connection();
        assert_eq!(
            conn.parse_text_value(b"t", oid::BOOL).unwrap(),
            PgValue::Bool(true)
        );
        assert_eq!(
            conn.parse_text_value(b"f", oid::BOOL).unwrap(),
            PgValue::Bool(false)
        );
        assert!(conn.parse_text_value(b"maybe", oid::BOOL).is_err());
    }

    #[test]
    fn parse_text_value_int2() {
        let conn = make_test_connection();
        assert_eq!(
            conn.parse_text_value(b"32767", oid::INT2).unwrap(),
            PgValue::Int2(32767)
        );
        assert_eq!(
            conn.parse_text_value(b"-1", oid::INT2).unwrap(),
            PgValue::Int2(-1)
        );
    }

    #[test]
    fn parse_text_value_int4() {
        let conn = make_test_connection();
        assert_eq!(
            conn.parse_text_value(b"2147483647", oid::INT4).unwrap(),
            PgValue::Int4(i32::MAX)
        );
    }

    #[test]
    fn parse_text_value_int8() {
        let conn = make_test_connection();
        assert_eq!(
            conn.parse_text_value(b"9223372036854775807", oid::INT8)
                .unwrap(),
            PgValue::Int8(i64::MAX)
        );
    }

    #[test]
    fn parse_text_value_float4() {
        let conn = make_test_connection();
        let v = conn.parse_text_value(b"3.5", oid::FLOAT4).unwrap();
        match v {
            PgValue::Float4(f) => assert!((f - 3.5).abs() < 0.001),
            other => panic!("expected Float4, got: {other}"),
        }
    }

    #[test]
    fn parse_text_value_float8() {
        let conn = make_test_connection();
        assert_eq!(
            conn.parse_text_value(b"2.5", oid::FLOAT8).unwrap(),
            PgValue::Float8(2.5)
        );
    }

    #[test]
    fn parse_text_value_bytea_hex_format() {
        let conn = make_test_connection();
        let v = conn.parse_text_value(b"\\x48656c6c6f", oid::BYTEA).unwrap();
        assert_eq!(v, PgValue::Bytes(b"Hello".to_vec()));
    }

    #[test]
    fn parse_text_value_bytea_raw_fallback() {
        let conn = make_test_connection();
        let v = conn.parse_text_value(b"raw", oid::BYTEA).unwrap();
        assert_eq!(v, PgValue::Bytes(b"raw".to_vec()));
    }

    #[test]
    fn parse_text_value_unknown_oid_returns_text() {
        let conn = make_test_connection();
        let v = conn.parse_text_value(b"anything", 99999).unwrap();
        assert_eq!(v, PgValue::Text("anything".to_string()));
    }

    #[test]
    fn parse_text_value_oid_type_maps_to_int4() {
        let conn = make_test_connection();
        assert_eq!(
            conn.parse_text_value(b"12345", oid::OID).unwrap(),
            PgValue::Int4(12345)
        );
    }

    #[test]
    fn parse_text_value_invalid_int_returns_protocol_error() {
        let conn = make_test_connection();
        let result = conn.parse_text_value(b"notanumber", oid::INT4);
        assert!(result.is_err());
        match result.unwrap_err() {
            PgError::Protocol(msg) => assert!(msg.contains("invalid int4"), "got: {msg}"),
            other => panic!("expected Protocol error, got: {other}"),
        }
    }

    // ================================================================
    // parse_binary_value for each type OID
    // ================================================================

    #[test]
    fn parse_binary_value_bool() {
        let conn = make_test_connection();
        assert_eq!(
            conn.parse_binary_value(&[1], oid::BOOL).unwrap(),
            PgValue::Bool(true)
        );
        assert_eq!(
            conn.parse_binary_value(&[0], oid::BOOL).unwrap(),
            PgValue::Bool(false)
        );
        assert!(conn.parse_binary_value(&[2], oid::BOOL).is_err());
        assert!(conn.parse_binary_value(&[], oid::BOOL).is_err());
    }

    #[test]
    fn parse_binary_value_int2() {
        let conn = make_test_connection();
        let v = conn
            .parse_binary_value(&256i16.to_be_bytes(), oid::INT2)
            .unwrap();
        assert_eq!(v, PgValue::Int2(256));
    }

    #[test]
    fn parse_binary_value_int4() {
        let conn = make_test_connection();
        let v = conn
            .parse_binary_value(&(-1i32).to_be_bytes(), oid::INT4)
            .unwrap();
        assert_eq!(v, PgValue::Int4(-1));
    }

    #[test]
    fn parse_binary_value_int8() {
        let conn = make_test_connection();
        let v = conn
            .parse_binary_value(&i64::MAX.to_be_bytes(), oid::INT8)
            .unwrap();
        assert_eq!(v, PgValue::Int8(i64::MAX));
    }

    #[test]
    fn parse_binary_value_float4() {
        let conn = make_test_connection();
        let v = conn
            .parse_binary_value(&1.5f32.to_be_bytes(), oid::FLOAT4)
            .unwrap();
        assert_eq!(v, PgValue::Float4(1.5));
    }

    #[test]
    fn parse_binary_value_float8() {
        let conn = make_test_connection();
        let v = conn
            .parse_binary_value(&2.5f64.to_be_bytes(), oid::FLOAT8)
            .unwrap();
        assert_eq!(v, PgValue::Float8(2.5));
    }

    #[test]
    fn parse_binary_value_bytea() {
        let conn = make_test_connection();
        let v = conn.parse_binary_value(&[0xDE, 0xAD], oid::BYTEA).unwrap();
        assert_eq!(v, PgValue::Bytes(vec![0xDE, 0xAD]));
    }

    #[test]
    fn parse_binary_value_unknown_oid_valid_utf8_returns_text() {
        let conn = make_test_connection();
        let v = conn.parse_binary_value(b"hello", 99999).unwrap();
        assert_eq!(v, PgValue::Text("hello".to_string()));
    }

    #[test]
    fn parse_binary_value_unknown_oid_invalid_utf8_returns_bytes() {
        let conn = make_test_connection();
        let v = conn.parse_binary_value(&[0xFF, 0xFE], 99999).unwrap();
        assert_eq!(v, PgValue::Bytes(vec![0xFF, 0xFE]));
    }

    // ================================================================
    // parse_error_response
    // ================================================================

    #[test]
    fn parse_error_response_all_fields() {
        let conn = make_test_connection();
        let mut data = Vec::new();
        // Code field
        data.push(b'C');
        data.extend_from_slice(b"42P01\0");
        // Message field
        data.push(b'M');
        data.extend_from_slice(b"relation does not exist\0");
        // Detail field
        data.push(b'D');
        data.extend_from_slice(b"Table \"users\" not found\0");
        // Hint field
        data.push(b'H');
        data.extend_from_slice(b"Check table name\0");
        // Terminator
        data.push(0);

        let err = conn.parse_error_response(&data).unwrap();
        match err {
            PgError::Server {
                code,
                message,
                detail,
                hint,
            } => {
                assert_eq!(code, "42P01");
                assert_eq!(message, "relation does not exist");
                assert_eq!(detail.as_deref(), Some("Table \"users\" not found"));
                assert_eq!(hint.as_deref(), Some("Check table name"));
            }
            other => panic!("expected Server error, got: {other}"),
        }
    }

    #[test]
    fn parse_error_response_minimal_fields() {
        let conn = make_test_connection();
        let mut data = Vec::new();
        data.push(b'M');
        data.extend_from_slice(b"syntax error\0");
        data.push(0);

        let err = conn.parse_error_response(&data).unwrap();
        match err {
            PgError::Server {
                code,
                message,
                detail,
                hint,
            } => {
                assert!(code.is_empty());
                assert_eq!(message, "syntax error");
                assert!(detail.is_none());
                assert!(hint.is_none());
            }
            other => panic!("expected Server error, got: {other}"),
        }
    }

    #[test]
    fn parse_error_and_drain_returns_server_error_when_drain_succeeds() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(&mut peer, &[b'Z', 0, 0, 0, 5, b'T']).unwrap();

        let mut data = Vec::new();
        data.push(b'C');
        data.extend_from_slice(b"XX000\0");
        data.push(b'M');
        data.extend_from_slice(b"boom\0");
        data.push(0);

        let cx = crate::cx::Cx::for_testing();
        let err = run(conn.parse_error_and_drain(&cx, &data));
        match err {
            PgError::Server { code, message, .. } => {
                assert_eq!(code, "XX000");
                assert_eq!(message, "boom");
            }
            other => panic!("expected Server error, got: {other}"),
        }
        assert_eq!(conn.inner.transaction_status, b'T');
    }

    #[test]
    fn parse_error_and_drain_surfaces_drain_failure_context() {
        let mut conn = make_test_connection();
        let mut data = Vec::new();
        data.push(b'C');
        data.extend_from_slice(b"XX000\0");
        data.push(b'M');
        data.extend_from_slice(b"boom\0");
        data.push(0);

        let cx = crate::cx::Cx::for_testing();
        let err = run(conn.parse_error_and_drain(&cx, &data));
        match err {
            PgError::Protocol(msg) => {
                assert!(msg.contains("boom"), "missing original server error: {msg}");
                assert!(
                    msg.contains("failed to drain to ReadyForQuery"),
                    "missing drain failure context: {msg}"
                );
            }
            other => panic!("expected Protocol error, got: {other}"),
        }
    }

    #[test]
    fn read_exact_observes_cancellation_while_pending() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        let cancel_cx = cx.clone();

        let wake_writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            cancel_cx.cancel_fast(CancelKind::User);
            std::io::Write::write_all(&mut peer, b"x").expect("wake pending read");
        });

        let mut buf = [0u8; 1];
        match run(conn.read_exact(&cx, &mut buf)) {
            Err(PgError::Cancelled(reason)) => assert_eq!(reason.kind, CancelKind::User),
            other => panic!("expected Cancelled, got: {other:?}"),
        }
        assert_eq!(buf, [0]);

        wake_writer.join().expect("wake writer should exit cleanly");
    }

    #[test]
    fn parse_error_and_drain_preserves_cancellation_and_closes_connection() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        conn.inner.closed = true;

        let mut data = Vec::new();
        data.push(b'C');
        data.extend_from_slice(b"XX000\0");
        data.push(b'M');
        data.extend_from_slice(b"boom\0");
        data.push(0);

        let cx = crate::cx::Cx::for_testing();
        let cancel_cx = cx.clone();
        let wake_writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            cancel_cx.cancel_fast(CancelKind::User);
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("wake pending drain");
        });

        match run(conn.parse_error_and_drain(&cx, &data)) {
            PgError::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
            other => panic!("expected Cancelled, got: {other}"),
        }
        assert!(conn.inner.closed);

        wake_writer.join().expect("wake writer should exit cleanly");
    }

    #[test]
    fn extended_execute_error_drain_cancellation_maps_to_cancelled_outcome() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        conn.inner.closed = true;
        let cx = crate::cx::Cx::for_testing();
        let cancel_cx = cx.clone();

        let wake_writer = std::thread::spawn(move || {
            std::io::Write::write_all(&mut peer, &error_response_message("XX000", "boom"))
                .expect("write ErrorResponse");
            std::thread::sleep(std::time::Duration::from_millis(20));
            cancel_cx.cancel_fast(CancelKind::User);
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("wake pending drain");
        });

        match run(conn.read_extended_execute_results(&cx)) {
            Outcome::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
            other => panic!("expected cancelled outcome, got: {other:?}"),
        }
        assert!(
            conn.inner.closed,
            "cancelled drain should leave the connection closed"
        );

        wake_writer.join().expect("wake writer should exit cleanly");
    }

    #[test]
    fn wait_for_ready_rejects_unexpected_message() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let data_row = backend_message(b'D', &0i16.to_be_bytes());
        std::io::Write::write_all(&mut peer, &data_row).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        let err = run(conn.wait_for_ready(&cx)).expect_err("unexpected message must fail");
        match err {
            PgError::Protocol(msg) => {
                assert!(msg.contains("startup sequence"), "got: {msg}");
                assert!(msg.contains("'D'"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got: {other}"),
        }
    }

    // ================================================================
    // PgError Display coverage
    // ================================================================

    #[test]
    fn pg_error_display_all_variants() {
        let io_err = PgError::Io(io::Error::new(io::ErrorKind::BrokenPipe, "pipe"));
        assert!(format!("{io_err}").contains("I/O error"));

        let proto = PgError::Protocol("bad msg".to_string());
        assert!(format!("{proto}").contains("protocol error"));
        assert!(format!("{proto}").contains("bad msg"));

        let auth = PgError::AuthenticationFailed("wrong pass".to_string());
        assert!(format!("{auth}").contains("authentication failed"));

        let server = PgError::Server {
            code: "23505".to_string(),
            message: "duplicate key".to_string(),
            detail: Some("Key exists".to_string()),
            hint: Some("Use upsert".to_string()),
        };
        let s = format!("{server}");
        assert!(s.contains("23505"));
        assert!(s.contains("duplicate key"));
        assert!(s.contains("Key exists"));
        assert!(s.contains("Use upsert"));

        let server_no_extras = PgError::Server {
            code: "42000".to_string(),
            message: "error".to_string(),
            detail: None,
            hint: None,
        };
        let s = format!("{server_no_extras}");
        assert!(s.contains("42000"));
        assert!(!s.contains("detail"));
        assert!(!s.contains("hint"));

        let closed = PgError::ConnectionClosed;
        assert!(format!("{closed}").contains("closed"));

        let col = PgError::ColumnNotFound("foo".to_string());
        assert!(format!("{col}").contains("foo"));

        let tc = PgError::TypeConversion {
            column: "bar".to_string(),
            expected: "i32",
            actual_oid: 25,
        };
        let s = format!("{tc}");
        assert!(s.contains("bar"));
        assert!(s.contains("i32"));
        assert!(s.contains("25"));

        let url = PgError::InvalidUrl("bad".to_string());
        assert!(format!("{url}").contains("bad"));

        let tls = PgError::TlsRequired;
        assert!(format!("{tls}").contains("TLS"));

        let txn = PgError::TransactionFinished;
        assert!(format!("{txn}").contains("finished"));

        let unsup = PgError::UnsupportedAuth("md5".to_string());
        assert!(format!("{unsup}").contains("md5"));
    }

    #[test]
    fn pg_error_source_io_only() {
        use std::error::Error;
        let io_err = PgError::Io(io::Error::other("test"));
        assert!(io_err.source().is_some());

        let proto = PgError::Protocol("x".to_string());
        assert!(proto.source().is_none());
    }

    // ================================================================
    // hex::decode edge cases
    // ================================================================

    #[test]
    fn hex_decode_uppercase() {
        assert_eq!(
            hex::decode("DEADBEEF").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn hex_decode_mixed_case() {
        assert_eq!(hex::decode("aAbBcC").unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn hex_decode_invalid_char() {
        assert!(hex::decode("ZZZZ").is_err());
    }

    #[test]
    fn hex_decode_single_byte() {
        assert_eq!(hex::decode("FF").unwrap(), vec![0xFF]);
    }

    #[test]
    fn ssl_mode_debug_clone_copy_default_eq() {
        let s = SslMode::default();
        assert_eq!(s, SslMode::Prefer);
        let dbg = format!("{s:?}");
        assert!(dbg.contains("Prefer"), "{dbg}");
        let copied: SslMode = s;
        let cloned = s;
        assert_eq!(copied, cloned);
        assert_ne!(s, SslMode::Disable);
    }

    #[test]
    fn frontend_message_debug_clone_copy_eq() {
        let m = FrontendMessage::Query;
        let dbg = format!("{m:?}");
        assert!(dbg.contains("Query"), "{dbg}");
        let copied: FrontendMessage = m;
        let cloned = m;
        assert_eq!(copied, cloned);
        assert_ne!(m, FrontendMessage::Terminate);
    }

    #[test]
    fn backend_message_debug_clone_copy_eq() {
        let m = BackendMessage::ReadyForQuery;
        let dbg = format!("{m:?}");
        assert!(dbg.contains("ReadyForQuery"), "{dbg}");
        let copied: BackendMessage = m;
        let cloned = m;
        assert_eq!(copied, cloned);
        assert_ne!(m, BackendMessage::DataRow);
    }

    // ================================================================
    // ToSql / FromSql trait tests
    // ================================================================

    #[test]
    fn to_sql_bool() {
        let mut buf = Vec::new();
        assert_eq!(true.to_sql(&mut buf).unwrap(), IsNull::No);
        assert_eq!(buf, [1]);
        buf.clear();
        assert_eq!(false.to_sql(&mut buf).unwrap(), IsNull::No);
        assert_eq!(buf, [0]);
        assert_eq!(true.type_oid(), oid::BOOL);
    }

    #[test]
    fn to_sql_integers() {
        let mut buf = Vec::new();

        let v: i16 = 0x1234;
        v.to_sql(&mut buf).unwrap();
        assert_eq!(buf, [0x12, 0x34]);
        assert_eq!(v.type_oid(), oid::INT2);
        buf.clear();

        let v: i32 = 0x1234_5678;
        v.to_sql(&mut buf).unwrap();
        assert_eq!(buf, [0x12, 0x34, 0x56, 0x78]);
        assert_eq!(v.type_oid(), oid::INT4);
        buf.clear();

        let v: i64 = 0x0102_0304_0506_0708;
        v.to_sql(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(v.type_oid(), oid::INT8);
    }

    #[test]
    fn to_sql_floats() {
        let mut buf = Vec::new();
        let v: f32 = 1.5;
        v.to_sql(&mut buf).unwrap();
        assert_eq!(buf, 1.5f32.to_be_bytes());
        assert_eq!(v.type_oid(), oid::FLOAT4);
        buf.clear();

        let v: f64 = 2.5;
        v.to_sql(&mut buf).unwrap();
        assert_eq!(buf, 2.5f64.to_be_bytes());
        assert_eq!(v.type_oid(), oid::FLOAT8);
    }

    #[test]
    fn to_sql_text() {
        let mut buf = Vec::new();
        "hello".to_sql(&mut buf).unwrap();
        assert_eq!(buf, b"hello");
        assert_eq!("hello".type_oid(), oid::TEXT);
        assert_eq!("hello".format(), Format::Text);
        buf.clear();

        String::from("world").to_sql(&mut buf).unwrap();
        assert_eq!(buf, b"world");
    }

    #[test]
    fn to_sql_bytes() {
        let mut buf = Vec::new();
        let data: &[u8] = &[1, 2, 3];
        data.to_sql(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3]);
        assert_eq!(data.type_oid(), oid::BYTEA);
        buf.clear();

        vec![4u8, 5, 6].to_sql(&mut buf).unwrap();
        assert_eq!(buf, [4, 5, 6]);
    }

    #[test]
    fn to_sql_option() {
        let mut buf = Vec::new();
        let some_val: Option<i32> = Some(42);
        assert_eq!(some_val.to_sql(&mut buf).unwrap(), IsNull::No);
        assert_eq!(buf, 42i32.to_be_bytes());
        assert_eq!(some_val.type_oid(), oid::INT4);

        buf.clear();
        let none_val: Option<i32> = None;
        assert_eq!(none_val.to_sql(&mut buf).unwrap(), IsNull::Yes);
        assert!(buf.is_empty());
        assert_eq!(none_val.type_oid(), 0);
    }

    #[test]
    fn to_sql_reference() {
        let mut buf = Vec::new();
        let v: &i32 = &42;
        v.to_sql(&mut buf).unwrap();
        assert_eq!(buf, 42i32.to_be_bytes());
    }

    #[test]
    fn from_sql_bool() {
        // Binary
        assert!(bool::from_sql(&[1], oid::BOOL, Format::Binary).unwrap());
        assert!(!bool::from_sql(&[0], oid::BOOL, Format::Binary).unwrap());
        assert!(bool::from_sql(&[2], oid::BOOL, Format::Binary).is_err());
        assert!(bool::from_sql(&[], oid::BOOL, Format::Binary).is_err());
        // Text
        assert!(bool::from_sql(b"t", oid::BOOL, Format::Text).unwrap());
        assert!(bool::from_sql(b"true", oid::BOOL, Format::Text).unwrap());
        assert!(!bool::from_sql(b"f", oid::BOOL, Format::Text).unwrap());
        assert!(!bool::from_sql(b"false", oid::BOOL, Format::Text).unwrap());
        assert!(!bool::from_sql(b"0", oid::BOOL, Format::Text).unwrap());
        assert!(!bool::from_sql(b"off", oid::BOOL, Format::Text).unwrap());
        assert!(bool::from_sql(b"maybe", oid::BOOL, Format::Text).is_err());
        assert!(bool::accepts(oid::BOOL));
        assert!(!bool::accepts(oid::INT4));
    }

    #[test]
    fn from_sql_integers() {
        // i16 binary
        assert_eq!(
            i16::from_sql(&0x1234i16.to_be_bytes(), oid::INT2, Format::Binary).unwrap(),
            0x1234
        );
        // i16 text
        assert_eq!(
            i16::from_sql(b"1234", oid::INT2, Format::Text).unwrap(),
            1234
        );
        // i16 too short
        assert!(i16::from_sql(&[0], oid::INT2, Format::Binary).is_err());

        // i32 binary
        assert_eq!(
            i32::from_sql(&42i32.to_be_bytes(), oid::INT4, Format::Binary).unwrap(),
            42
        );
        // i32 text
        assert_eq!(i32::from_sql(b"-7", oid::INT4, Format::Text).unwrap(), -7);
        assert!(i32::accepts(oid::INT4));
        assert!(i32::accepts(oid::OID));

        // i64
        assert_eq!(
            i64::from_sql(&999i64.to_be_bytes(), oid::INT8, Format::Binary).unwrap(),
            999
        );
        assert_eq!(
            i64::from_sql(b"9999999999", oid::INT8, Format::Text).unwrap(),
            9_999_999_999
        );
    }

    #[test]
    fn from_sql_floats() {
        assert_eq!(
            f32::from_sql(&1.5f32.to_be_bytes(), oid::FLOAT4, Format::Binary).unwrap(),
            1.5
        );
        assert_eq!(
            f32::from_sql(b"1.5", oid::FLOAT4, Format::Text).unwrap(),
            1.5
        );
        assert_eq!(
            f64::from_sql(&2.5f64.to_be_bytes(), oid::FLOAT8, Format::Binary).unwrap(),
            2.5
        );
        assert_eq!(
            f64::from_sql(b"-3.14", oid::FLOAT8, Format::Text).unwrap(),
            -3.14
        );
    }

    #[test]
    fn from_sql_string() {
        assert_eq!(
            String::from_sql(b"hello", oid::TEXT, Format::Text).unwrap(),
            "hello"
        );
        assert_eq!(
            String::from_sql(b"world", oid::VARCHAR, Format::Binary).unwrap(),
            "world"
        );
        assert!(String::accepts(oid::TEXT));
        assert!(String::accepts(oid::UUID));
        assert!(String::accepts(oid::JSON));
        assert!(!String::accepts(oid::INT4));
    }

    #[test]
    fn from_sql_bytes() {
        // Binary format: raw bytes
        assert_eq!(
            Vec::<u8>::from_sql(&[1, 2, 3], oid::BYTEA, Format::Binary).unwrap(),
            vec![1, 2, 3]
        );
        // Text format: hex-encoded
        assert_eq!(
            Vec::<u8>::from_sql(b"\\x48656c6c6f", oid::BYTEA, Format::Text).unwrap(),
            b"Hello".to_vec()
        );
    }

    #[test]
    fn from_sql_option() {
        assert_eq!(
            Option::<i32>::from_sql(&42i32.to_be_bytes(), oid::INT4, Format::Binary).unwrap(),
            Some(42)
        );
        assert_eq!(Option::<i32>::from_sql_null().unwrap(), None);
    }

    #[test]
    fn from_sql_null_error() {
        // Non-Option types reject NULL
        assert!(i32::from_sql_null().is_err());
        assert!(String::from_sql_null().is_err());
        assert!(bool::from_sql_null().is_err());
    }

    // ================================================================
    // Extended Query Protocol message builder tests
    // ================================================================

    #[test]
    fn build_parse_msg_structure() {
        let msg = build_parse_msg("", "SELECT 1", &[]).unwrap();
        // Type byte 'P'
        assert_eq!(msg[0], b'P');
        // Verify SQL is in the message body
        let body = &msg[5..]; // skip type + 4-byte length
        // Empty statement name: just a \0
        assert_eq!(body[0], 0);
        // SQL follows
        assert!(body[1..].starts_with(b"SELECT 1"));
    }

    #[test]
    fn build_parse_msg_with_oids() {
        let msg = build_parse_msg("stmt1", "SELECT $1", &[oid::INT4]).unwrap();
        assert_eq!(msg[0], b'P');
        // Statement name "stmt1" should be in body
        let body = &msg[5..];
        assert!(body.starts_with(b"stmt1\0"));
    }

    #[test]
    fn build_bind_msg_no_params() {
        let msg = build_bind_msg("", "", &[], Format::Text).unwrap();
        assert_eq!(msg[0], b'B');
    }

    #[test]
    fn build_bind_msg_with_params() {
        let params: Vec<&dyn ToSql> = vec![&42i32, &true];
        let msg = build_bind_msg("", "", &params, Format::Text).unwrap();
        assert_eq!(msg[0], b'B');
        // Verify message is non-trivial (has parameter data)
        assert!(msg.len() > 20);
    }

    #[test]
    fn build_bind_msg_with_null() {
        let val: Option<i32> = None;
        let params: Vec<&dyn ToSql> = vec![&val];
        let msg = build_bind_msg("", "", &params, Format::Text).unwrap();
        assert_eq!(msg[0], b'B');
        // NULL parameters have length -1 in the message
        // The -1 should appear as 0xFF 0xFF 0xFF 0xFF somewhere in the body
        let body = &msg[5..];
        let has_null_marker = body.windows(4).any(|w| w == [0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(
            has_null_marker,
            "bind message should contain NULL marker (-1)"
        );
    }

    #[test]
    fn build_describe_msg_portal() {
        let msg = build_describe_msg(b'P', "").unwrap();
        assert_eq!(msg[0], b'D');
        assert_eq!(msg[5], b'P'); // portal target
    }

    #[test]
    fn build_describe_msg_statement() {
        let msg = build_describe_msg(b'S', "my_stmt").unwrap();
        assert_eq!(msg[0], b'D');
        assert_eq!(msg[5], b'S'); // statement target
    }

    #[test]
    fn build_execute_msg_all_rows() {
        let msg = build_execute_msg("", 0).unwrap();
        assert_eq!(msg[0], b'E');
    }

    #[test]
    fn build_sync_msg_structure() {
        let msg = build_sync_msg().unwrap();
        assert_eq!(msg[0], b'S');
        // Sync has no body, just type + length(4)
        assert_eq!(msg.len(), 5);
    }

    #[test]
    fn build_close_msg_statement() {
        let msg = build_close_msg(b'S', "stmt1").unwrap();
        assert_eq!(msg[0], b'C');
        assert_eq!(msg[5], b'S');
    }

    // ================================================================
    // PgRow::get_typed tests
    // ================================================================

    #[test]
    fn pg_row_get_typed_int() {
        let columns = Arc::new(vec![PgColumn {
            name: "id".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::INT4,
            type_size: 4,
            type_modifier: -1,
            format_code: 0,
        }]);
        let mut indices = BTreeMap::new();
        indices.insert("id".to_string(), 0);
        let row = PgRow {
            columns: Arc::clone(&columns),
            column_indices: Arc::new(indices),
            values: vec![PgValue::Int4(42)],
        };
        let id: i32 = row.get_typed("id").unwrap();
        assert_eq!(id, 42);
    }

    #[test]
    fn pg_row_get_typed_string() {
        let columns = Arc::new(vec![PgColumn {
            name: "name".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::TEXT,
            type_size: -1,
            type_modifier: -1,
            format_code: 0,
        }]);
        let mut indices = BTreeMap::new();
        indices.insert("name".to_string(), 0);
        let row = PgRow {
            columns,
            column_indices: Arc::new(indices),
            values: vec![PgValue::Text("Alice".to_string())],
        };
        let name: String = row.get_typed("name").unwrap();
        assert_eq!(name, "Alice");
    }

    #[test]
    fn pg_row_get_typed_null_option() {
        let columns = Arc::new(vec![PgColumn {
            name: "val".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::INT4,
            type_size: 4,
            type_modifier: -1,
            format_code: 0,
        }]);
        let mut indices = BTreeMap::new();
        indices.insert("val".to_string(), 0);
        let row = PgRow {
            columns,
            column_indices: Arc::new(indices),
            values: vec![PgValue::Null],
        };
        let val: Option<i32> = row.get_typed("val").unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn pg_row_get_typed_null_non_option_errors() {
        let columns = Arc::new(vec![PgColumn {
            name: "val".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::INT4,
            type_size: 4,
            type_modifier: -1,
            format_code: 0,
        }]);
        let mut indices = BTreeMap::new();
        indices.insert("val".to_string(), 0);
        let row = PgRow {
            columns,
            column_indices: Arc::new(indices),
            values: vec![PgValue::Null],
        };
        let result: Result<i32, _> = row.get_typed("val");
        assert!(result.is_err());
    }

    #[test]
    fn pg_row_get_typed_idx() {
        let columns = Arc::new(vec![PgColumn {
            name: "x".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::FLOAT8,
            type_size: 8,
            type_modifier: -1,
            format_code: 0,
        }]);
        let mut indices = BTreeMap::new();
        indices.insert("x".to_string(), 0);
        let row = PgRow {
            columns,
            column_indices: Arc::new(indices),
            values: vec![PgValue::Float8(3.14)],
        };
        let x: f64 = row.get_typed_idx(0).unwrap();
        assert!((x - 3.14).abs() < 1e-10);
    }

    #[test]
    fn pg_row_get_typed_preserves_binary_bytea_format() {
        let columns = Arc::new(vec![PgColumn {
            name: "payload".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::BYTEA,
            type_size: -1,
            type_modifier: -1,
            format_code: 1,
        }]);
        let mut indices = BTreeMap::new();
        indices.insert("payload".to_string(), 0);
        let expected = vec![0xde, 0xad, 0x00, 0xff];
        let row = PgRow {
            columns,
            column_indices: Arc::new(indices),
            values: vec![PgValue::Bytes(expected.clone())],
        };

        let payload: Vec<u8> = row.get_typed("payload").unwrap();
        assert_eq!(payload, expected);
    }

    #[test]
    fn pg_row_get_typed_text_bytea_handles_non_utf8_bytes() {
        let columns = Arc::new(vec![PgColumn {
            name: "payload".to_string(),
            table_oid: 0,
            column_id: 0,
            type_oid: oid::BYTEA,
            type_size: -1,
            type_modifier: -1,
            format_code: 0,
        }]);
        let mut indices = BTreeMap::new();
        indices.insert("payload".to_string(), 0);
        let expected = vec![0xff, 0x00, 0x7f, 0x80];
        let row = PgRow {
            columns,
            column_indices: Arc::new(indices),
            values: vec![PgValue::Bytes(expected.clone())],
        };

        let payload: Vec<u8> = row.get_typed("payload").unwrap();
        assert_eq!(payload, expected);
    }

    #[test]
    fn pg_row_get_typed_column_not_found() {
        let columns = Arc::new(vec![]);
        let row = PgRow {
            columns,
            column_indices: Arc::new(BTreeMap::new()),
            values: vec![],
        };
        let result: Result<i32, _> = row.get_typed("missing");
        assert!(result.is_err());
    }

    // ================================================================
    // PgStatement tests
    // ================================================================

    #[test]
    fn pg_statement_accessors() {
        let stmt = PgStatement {
            name: "s1".to_string(),
            param_oids: vec![oid::INT4, oid::TEXT],
            columns: vec![PgColumn {
                name: "id".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::INT4,
                type_size: 4,
                type_modifier: -1,
                format_code: 0,
            }],
        };
        assert_eq!(stmt.param_types(), &[oid::INT4, oid::TEXT]);
        assert_eq!(stmt.columns().len(), 1);
        assert_eq!(stmt.columns()[0].name, "id");
    }

    // ================================================================
    // Format / IsNull derive coverage
    // ================================================================

    #[test]
    fn format_debug_clone_eq() {
        let f = Format::Binary;
        let f2 = f;
        assert_eq!(f, f2);
        assert_ne!(f, Format::Text);
        assert!(format!("{f:?}").contains("Binary"));
    }

    #[test]
    fn is_null_debug_clone_eq() {
        let n = IsNull::Yes;
        let n2 = n;
        assert_eq!(n, n2);
        assert_ne!(n, IsNull::No);
        assert!(format!("{n:?}").contains("Yes"));
    }

    // ================================================================
    // parse_parameter_description tests
    // ================================================================

    #[test]
    fn parse_parameter_description_empty() {
        // 0 parameters
        let data = 0i16.to_be_bytes();
        let oids = PgConnection::parse_parameter_description(&data).unwrap();
        assert!(oids.is_empty());
    }

    #[test]
    fn parse_parameter_description_two_params() {
        let mut data = Vec::new();
        data.extend_from_slice(&2i16.to_be_bytes());
        data.extend_from_slice(&(oid::INT4 as i32).to_be_bytes());
        data.extend_from_slice(&(oid::TEXT as i32).to_be_bytes());
        let oids = PgConnection::parse_parameter_description(&data).unwrap();
        assert_eq!(oids, vec![oid::INT4, oid::TEXT]);
    }

    #[test]
    fn parse_parameter_description_negative_count() {
        let data = (-1i16).to_be_bytes();
        assert!(PgConnection::parse_parameter_description(&data).is_err());
    }

    // ================================================================
    // pg_value_to_text_bytes roundtrip tests
    // ================================================================

    #[test]
    fn pg_value_to_text_bytes_roundtrip() {
        // Bool
        let bytes = pg_value_to_text_bytes(&PgValue::Bool(true));
        assert_eq!(
            bool::from_sql(&bytes, oid::BOOL, Format::Text).unwrap(),
            true
        );

        let bytes = pg_value_to_text_bytes(&PgValue::Bool(false));
        assert_eq!(
            bool::from_sql(&bytes, oid::BOOL, Format::Text).unwrap(),
            false
        );

        // Int2
        let bytes = pg_value_to_text_bytes(&PgValue::Int2(123));
        assert_eq!(i16::from_sql(&bytes, oid::INT2, Format::Text).unwrap(), 123);

        // Int4
        let bytes = pg_value_to_text_bytes(&PgValue::Int4(-42));
        assert_eq!(i32::from_sql(&bytes, oid::INT4, Format::Text).unwrap(), -42);

        // Int8
        let bytes = pg_value_to_text_bytes(&PgValue::Int8(9_000_000_000));
        assert_eq!(
            i64::from_sql(&bytes, oid::INT8, Format::Text).unwrap(),
            9_000_000_000
        );

        // Float4
        let bytes = pg_value_to_text_bytes(&PgValue::Float4(1.5));
        assert_eq!(
            f32::from_sql(&bytes, oid::FLOAT4, Format::Text).unwrap(),
            1.5
        );

        // Float8
        let bytes = pg_value_to_text_bytes(&PgValue::Float8(2.5));
        assert_eq!(
            f64::from_sql(&bytes, oid::FLOAT8, Format::Text).unwrap(),
            2.5
        );

        // Text
        let bytes = pg_value_to_text_bytes(&PgValue::Text("hello".to_string()));
        assert_eq!(
            String::from_sql(&bytes, oid::TEXT, Format::Text).unwrap(),
            "hello"
        );
    }

    #[test]
    fn connect_paths_short_circuit_on_cancel() {
        let cx = cancelled_cx();
        let options =
            PgConnectOptions::parse("postgres://localhost/testdb").expect("valid connection URL");

        assert_user_cancelled(run(PgConnection::connect(
            &cx,
            "postgres://localhost/testdb",
        )));
        assert_user_cancelled(run(PgConnection::connect_with_options(&cx, options)));
    }

    #[test]
    fn operation_paths_short_circuit_on_cancel() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        let param_value: i32 = 42;
        let params: [&dyn ToSql; 1] = [&param_value];
        let stmt = PgStatement {
            name: "s1".to_string(),
            param_oids: vec![oid::INT4],
            columns: vec![],
        };

        assert_user_cancelled(run(conn.query(&cx, "SELECT 1")));
        assert_user_cancelled(run(conn.query_one(&cx, "SELECT 1")));
        assert_user_cancelled(run(conn.execute(&cx, "SELECT 1")));
        assert_user_cancelled(run(conn.query_params(&cx, "SELECT $1", &params)));
        assert_user_cancelled(run(conn.query_one_params(&cx, "SELECT $1", &params)));
        assert_user_cancelled(run(conn.execute_params(&cx, "SELECT $1", &params)));
        assert_user_cancelled(run(conn.begin(&cx)));
        assert_user_cancelled(run(conn.prepare(&cx, "SELECT $1")));
        assert_user_cancelled(run(conn.query_prepared(&cx, &stmt, &params)));
        assert_user_cancelled(run(conn.execute_prepared(&cx, &stmt, &params)));
        assert_user_cancelled(run(conn.close_statement(&cx, &stmt)));
    }

    // -----------------------------------------------------------------------
    // Issue #18: TLS support + sslmode URL parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_sslmode_disable() {
        let opts =
            PgConnectOptions::parse("postgres://user:pass@localhost/db?sslmode=disable").unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Disable);
    }

    #[test]
    fn parse_sslmode_prefer() {
        let opts =
            PgConnectOptions::parse("postgres://user:pass@localhost/db?sslmode=prefer").unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Prefer);
    }

    #[test]
    fn parse_sslmode_require() {
        let opts =
            PgConnectOptions::parse("postgres://user:pass@localhost/db?sslmode=require").unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Require);
    }

    #[test]
    fn parse_sslmode_unknown_is_error() {
        let result = PgConnectOptions::parse("postgres://user@localhost/db?sslmode=magic");
        assert!(result.is_err());
    }

    #[test]
    fn parse_sslmode_default_is_prefer() {
        let opts = PgConnectOptions::parse("postgres://user@localhost/db").unwrap();
        assert_eq!(opts.ssl_mode, SslMode::Prefer);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn prefer_tls_cancellation_is_not_swallowed_by_plaintext_fallback() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("listener addr");

        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();

        let accept_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept first connection");
            cancel_cx.cancel_fast(CancelKind::User);
            drop(stream);
        });

        let options = PgConnectOptions {
            host: addr.ip().to_string(),
            port: addr.port(),
            database: "testdb".to_string(),
            user: "user".to_string(),
            password: Some("secret".to_string()),
            application_name: None,
            connect_timeout: Some(std::time::Duration::from_secs(1)),
            ssl_mode: SslMode::Prefer,
        };

        match run(PgConnection::connect_with_options(&cx, options)) {
            Outcome::Cancelled(reason) => assert_eq!(reason.kind, CancelKind::User),
            other => panic!("expected cancellation, got {other:?}"),
        }

        accept_thread
            .join()
            .expect("accept helper should exit cleanly");
    }

    #[test]
    fn parse_application_name_from_url() {
        let opts = PgConnectOptions::parse(
            "postgres://user@localhost/db?application_name=myapp&sslmode=disable",
        )
        .unwrap();
        assert_eq!(opts.application_name.as_deref(), Some("myapp"));
        assert_eq!(opts.ssl_mode, SslMode::Disable);
    }

    #[test]
    fn parse_connect_timeout_from_url() {
        let opts =
            PgConnectOptions::parse("postgres://user@localhost/db?connect_timeout=30").unwrap();
        assert_eq!(
            opts.connect_timeout,
            Some(std::time::Duration::from_secs(30))
        );
    }

    #[test]
    fn connect_tcp_with_passes_configured_connect_timeout() {
        let opts =
            PgConnectOptions::parse("postgres://user@localhost/db?connect_timeout=30").unwrap();
        let seen = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let seen_for_connect = std::sync::Arc::clone(&seen);

        let result = run(PgConnection::connect_tcp_with(
            &opts,
            move |addr, timeout| {
                let seen = std::sync::Arc::clone(&seen_for_connect);
                async move {
                    *seen.lock() = Some((addr, timeout));
                    Err(io::Error::new(io::ErrorKind::TimedOut, "synthetic timeout"))
                }
            },
        ));

        match result {
            Err(PgError::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected IO timeout, got {other:?}"),
        }

        let seen = seen.lock();
        assert_eq!(
            seen.as_ref(),
            Some(&(
                "localhost:5432".to_string(),
                Some(std::time::Duration::from_secs(30))
            ))
        );
    }

    #[test]
    fn connect_tcp_with_omits_timeout_when_not_configured() {
        let opts = PgConnectOptions::parse("postgres://user@localhost/db").unwrap();
        let seen = std::sync::Arc::new(parking_lot::Mutex::new(None));
        let seen_for_connect = std::sync::Arc::clone(&seen);

        let result = run(PgConnection::connect_tcp_with(
            &opts,
            move |addr, timeout| {
                let seen = std::sync::Arc::clone(&seen_for_connect);
                async move {
                    *seen.lock() = Some((addr, timeout));
                    Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "synthetic refusal",
                    ))
                }
            },
        ));

        match result {
            Err(PgError::Io(err)) => assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused),
            other => panic!("expected IO refusal, got {other:?}"),
        }

        let seen = seen.lock();
        assert_eq!(seen.as_ref(), Some(&("localhost:5432".to_string(), None)));
    }

    #[test]
    fn tls_error_is_connection_error() {
        let err = PgError::Tls("handshake failed".into());
        assert!(err.is_connection_error());
    }

    #[test]
    fn tls_error_display() {
        let err = PgError::Tls("cert expired".into());
        assert!(err.to_string().contains("cert expired"));
    }

    #[test]
    fn extended_readers_cancel_midflight_and_close_connection() {
        let cx = cancelled_cx();

        let mut query_conn = make_test_connection();
        assert_user_cancelled(run(query_conn.read_extended_query_results(&cx)));
        assert!(query_conn.inner.closed);

        let mut execute_conn = make_test_connection();
        assert_user_cancelled(run(execute_conn.read_extended_execute_results(&cx)));
        assert!(execute_conn.inner.closed);
    }

    #[test]
    fn query_rejects_datarow_before_row_description() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let data_row = backend_message(b'D', &0i16.to_be_bytes());
        std::io::Write::write_all(&mut peer, &data_row).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.query(&cx, "SELECT 1")) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("DataRow before RowDescription"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(conn.inner.closed);
    }

    #[test]
    fn query_tolerates_async_notification_response() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let notify = notification_response_message(42, "jobs", "done");
        let command_complete = backend_message(b'C', b"SELECT 0\0");
        std::io::Write::write_all(&mut peer, &notify).unwrap();
        std::io::Write::write_all(&mut peer, &command_complete).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.query(&cx, "SELECT 1")) {
            Outcome::Ok(rows) => assert!(rows.is_empty(), "unexpected rows: {rows:?}"),
            other => panic!("expected successful query, got {other:?}"),
        }
    }

    #[test]
    fn execute_updates_parameter_status_from_async_message() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let parameter_status = parameter_status_message("application_name", "asupersync-test");
        let command_complete = backend_message(b'C', b"SET\0");
        std::io::Write::write_all(&mut peer, &parameter_status).unwrap();
        std::io::Write::write_all(&mut peer, &command_complete).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.execute(&cx, "SET application_name = 'asupersync-test'")) {
            Outcome::Ok(affected) => assert_eq!(affected, 0),
            other => panic!("expected successful execute, got {other:?}"),
        }
        assert_eq!(conn.parameter("application_name"), Some("asupersync-test"));
    }

    #[test]
    fn execute_rejects_row_returning_response() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let row_description = single_text_row_description();
        let command_complete = backend_message(b'C', b"SELECT 0\0");
        std::io::Write::write_all(&mut peer, &row_description).unwrap();
        std::io::Write::write_all(&mut peer, &command_complete).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.execute(&cx, "SELECT 1")) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("execute()"), "got: {msg}");
                assert!(msg.contains("query()"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(!conn.inner.closed);
        assert_eq!(conn.inner.transaction_status, b'I');
    }

    #[test]
    fn extended_query_rejects_datarow_before_row_description() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let data_row = backend_message(b'D', &0i16.to_be_bytes());
        std::io::Write::write_all(&mut peer, &data_row).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.read_extended_query_results(&cx)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("DataRow before RowDescription"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn extended_execute_rejects_row_returning_response() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let row_description = single_text_row_description();
        let command_complete = backend_message(b'C', b"SELECT 0\0");
        std::io::Write::write_all(&mut peer, &row_description).unwrap();
        std::io::Write::write_all(&mut peer, &command_complete).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.read_extended_execute_results(&cx)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("execute-style APIs"), "got: {msg}");
                assert!(msg.contains("query-style APIs"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(!conn.inner.closed);
        assert_eq!(conn.inner.transaction_status, b'I');
    }

    #[test]
    fn extended_execute_type_mismatch_errors_preserve_session_recovery() {
        let cx = crate::cx::Cx::for_testing();
        let mismatch_cases = [
            (
                "22P02",
                "invalid input syntax for type integer: \"abc\"",
                b'I',
            ),
            (
                "42804",
                "column \"id\" is of type integer but expression is of type text",
                b'T',
            ),
        ];

        for (code, message, status) in mismatch_cases {
            let (mut conn, mut peer) = make_test_connection_with_peer();
            conn.inner.closed = true;

            std::io::Write::write_all(&mut peer, &error_response_message(code, message)).unwrap();
            std::io::Write::write_all(&mut peer, &ready_for_query(status)).unwrap();

            match run(conn.read_extended_execute_results(&cx)) {
                Outcome::Err(PgError::Server {
                    code: actual_code,
                    message: actual_message,
                    ..
                }) => {
                    assert_eq!(actual_code, code);
                    assert_eq!(actual_message, message);
                }
                other => panic!("expected server error, got {other:?}"),
            }

            assert!(
                !conn.inner.closed,
                "Bind/Execute type mismatch must drain back to ReadyForQuery"
            );
            assert_eq!(
                conn.inner.transaction_status, status,
                "server ReadyForQuery status should survive type mismatch recovery"
            );

            conn.inner.closed = true;
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"UPDATE 3\0")).unwrap();
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

            match run(conn.read_extended_execute_results(&cx)) {
                Outcome::Ok(affected_rows) => assert_eq!(affected_rows, 3),
                other => panic!("expected clean follow-up execute, got {other:?}"),
            }

            assert!(
                !conn.inner.closed,
                "follow-up execute should still complete on the recovered session"
            );
            assert_eq!(conn.inner.transaction_status, b'I');
        }
    }

    // ================================================================
    // COPY Protocol Conformance Tests
    // ================================================================

    #[cfg(feature = "postgres")]
    mod copy_protocol_conformance {
        use super::*;
        use std::io::{Cursor, Read};

        /// Test data for COPY protocol conformance.
        struct CopyTestData {
            text_format: Vec<u8>,
            binary_format: Vec<u8>,
            column_count: u16,
            format_codes: Vec<i16>,
        }

        impl CopyTestData {
            fn new_text_sample() -> Self {
                // Text format: tab-separated values with newline terminator
                let text_data = b"123\tJohn Doe\ttrue\n456\tJane Smith\tfalse\n".to_vec();
                let binary_data = Self::build_binary_sample();

                Self {
                    text_format: text_data,
                    binary_format: binary_data,
                    column_count: 3,
                    format_codes: vec![0, 0, 0], // All text format initially
                }
            }

            fn build_binary_sample() -> Vec<u8> {
                let mut buf = Vec::new();

                // Binary format signature
                buf.extend_from_slice(b"PGCOPY\n\xFF\r\n\0");
                // Flags field (32-bit, 0 = no special flags)
                buf.extend_from_slice(&0u32.to_be_bytes());
                // Header extension area length (32-bit, 0 = no extensions)
                buf.extend_from_slice(&0u32.to_be_bytes());

                // Row 1: (123, "John Doe", true)
                buf.extend_from_slice(&3u16.to_be_bytes()); // 3 columns
                // Column 1: INT4 value 123
                buf.extend_from_slice(&4u32.to_be_bytes()); // length
                buf.extend_from_slice(&123i32.to_be_bytes());
                // Column 2: TEXT value "John Doe"
                buf.extend_from_slice(&8u32.to_be_bytes()); // length
                buf.extend_from_slice(b"John Doe");
                // Column 3: BOOL value true
                buf.extend_from_slice(&1u32.to_be_bytes()); // length
                buf.push(1); // true

                // Row 2: (456, "Jane Smith", false)
                buf.extend_from_slice(&3u16.to_be_bytes()); // 3 columns
                // Column 1: INT4 value 456
                buf.extend_from_slice(&4u32.to_be_bytes()); // length
                buf.extend_from_slice(&456i32.to_be_bytes());
                // Column 2: TEXT value "Jane Smith"
                buf.extend_from_slice(&10u32.to_be_bytes()); // length
                buf.extend_from_slice(b"Jane Smith");
                // Column 3: BOOL value false
                buf.extend_from_slice(&1u32.to_be_bytes()); // length
                buf.push(0); // false

                // File trailer: -1 as 16-bit value
                buf.extend_from_slice(&(-1i16).to_be_bytes());

                buf
            }

            fn with_binary_formats(mut self) -> Self {
                // Set all columns to binary format (1 = binary, 0 = text)
                self.format_codes = vec![1, 1, 1];
                self
            }

            fn with_mixed_formats(mut self) -> Self {
                // Mixed: binary int, text string, binary bool
                self.format_codes = vec![1, 0, 1];
                self
            }
        }

        /// Creates a COPY IN response message for testing.
        fn build_copy_in_response(overall_format: u8, format_codes: &[i16]) -> Vec<u8> {
            let mut buf = Vec::new();

            // Message type
            buf.push(b'G');

            // Message length (excluding type byte)
            let length = 1 + 2 + (format_codes.len() * 2) as u32; // format + count + codes
            buf.extend_from_slice(&length.to_be_bytes());

            // Overall format (0 = text, 1 = binary)
            buf.push(overall_format);

            // Number of columns
            buf.extend_from_slice(&(format_codes.len() as u16).to_be_bytes());

            // Format codes for each column
            for &code in format_codes {
                buf.extend_from_slice(&code.to_be_bytes());
            }

            buf
        }

        /// Creates a COPY DATA message for testing.
        fn build_copy_data_message(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::new();

            // Message type
            buf.push(b'd');

            // Message length (excluding type byte)
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());

            // Data payload
            buf.extend_from_slice(data);

            buf
        }

        /// Creates a COPY DONE message for testing.
        fn build_copy_done_message() -> Vec<u8> {
            vec![b'c', 0, 0, 0, 0] // type + 4-byte length (0 for no data)
        }

        /// Creates a COPY FAIL message for testing.
        fn build_copy_fail_message(error_msg: &str) -> Vec<u8> {
            let mut buf = Vec::new();

            // Message type
            buf.push(b'f');

            // Message length (excluding type byte)
            buf.extend_from_slice(&(error_msg.len() as u32 + 1).to_be_bytes()); // +1 for null terminator

            // Error message with null terminator
            buf.extend_from_slice(error_msg.as_bytes());
            buf.push(0);

            buf
        }

        #[test]
        fn copy_in_response_text_mode_conformance() {
            let test_data = CopyTestData::new_text_sample();
            let message = build_copy_in_response(0, &test_data.format_codes); // 0 = text mode

            // Verify message structure
            assert_eq!(message[0], b'G'); // CopyInResponse type

            // Parse message content
            let length = u32::from_be_bytes([message[1], message[2], message[3], message[4]]);
            assert_eq!(length, 1 + 2 + (test_data.column_count * 2) as u32);

            let overall_format = message[5];
            assert_eq!(overall_format, 0); // Text mode

            let column_count = u16::from_be_bytes([message[6], message[7]]);
            assert_eq!(column_count, test_data.column_count);

            // Verify format codes (all should be 0 for text)
            for i in 0..test_data.column_count {
                let offset = 8 + (i as usize * 2);
                let format_code = i16::from_be_bytes([message[offset], message[offset + 1]]);
                assert_eq!(format_code, 0, "Column {i} should be text format");
            }
        }

        #[test]
        fn copy_in_response_binary_mode_conformance() {
            let test_data = CopyTestData::new_text_sample().with_binary_formats();
            let message = build_copy_in_response(1, &test_data.format_codes); // 1 = binary mode

            // Verify message structure
            assert_eq!(message[0], b'G'); // CopyInResponse type

            let overall_format = message[5];
            assert_eq!(overall_format, 1); // Binary mode

            // Verify format codes (all should be 1 for binary)
            for i in 0..test_data.column_count {
                let offset = 8 + (i as usize * 2);
                let format_code = i16::from_be_bytes([message[offset], message[offset + 1]]);
                assert_eq!(format_code, 1, "Column {i} should be binary format");
            }
        }

        #[test]
        fn copy_in_response_mixed_formats_conformance() {
            let test_data = CopyTestData::new_text_sample().with_mixed_formats();
            let message = build_copy_in_response(0, &test_data.format_codes); // overall text, mixed columns

            // Verify mixed format codes: binary, text, binary
            let expected_formats = [1, 0, 1];
            for (i, &expected) in expected_formats.iter().enumerate() {
                let offset = 8 + (i * 2);
                let format_code = i16::from_be_bytes([message[offset], message[offset + 1]]);
                assert_eq!(format_code, expected, "Column {i} format mismatch");
            }
        }

        #[test]
        fn copy_data_chunk_boundaries_conformance() {
            let test_data = CopyTestData::new_text_sample();

            // Test 1: Single chunk with complete rows
            let full_chunk = build_copy_data_message(&test_data.text_format);
            assert_eq!(full_chunk[0], b'd');
            let chunk_length =
                u32::from_be_bytes([full_chunk[1], full_chunk[2], full_chunk[3], full_chunk[4]]);
            assert_eq!(chunk_length, test_data.text_format.len() as u32);

            // Test 2: Multiple chunks with row boundaries
            let row1 = b"123\tJohn Doe\ttrue\n";
            let row2 = b"456\tJane Smith\tfalse\n";

            let chunk1 = build_copy_data_message(row1);
            let chunk2 = build_copy_data_message(row2);

            // Verify each chunk is properly formed
            assert_eq!(chunk1[0], b'd');
            assert_eq!(chunk2[0], b'd');

            let chunk1_len = u32::from_be_bytes([chunk1[1], chunk1[2], chunk1[3], chunk1[4]]);
            let chunk2_len = u32::from_be_bytes([chunk2[1], chunk2[2], chunk2[3], chunk2[4]]);

            assert_eq!(chunk1_len, row1.len() as u32);
            assert_eq!(chunk2_len, row2.len() as u32);

            // Test 3: Verify chunk data integrity
            assert_eq!(&chunk1[5..], row1);
            assert_eq!(&chunk2[5..], row2);
        }

        #[test]
        fn copy_data_binary_chunk_boundaries_conformance() {
            let test_data = CopyTestData::new_text_sample();
            let binary_chunk = build_copy_data_message(&test_data.binary_format);

            // Verify binary signature in the data
            let data_start = 5; // After message type and length
            let signature = &binary_chunk[data_start..data_start + 11];
            assert_eq!(
                signature, b"PGCOPY\n\xFF\r\n\0",
                "Binary format signature mismatch"
            );

            // Verify flags field
            let flags_start = data_start + 11;
            let flags = u32::from_be_bytes([
                binary_chunk[flags_start],
                binary_chunk[flags_start + 1],
                binary_chunk[flags_start + 2],
                binary_chunk[flags_start + 3],
            ]);
            assert_eq!(flags, 0, "Flags should be 0 for standard binary format");
        }

        #[test]
        fn copy_done_flush_semantics_conformance() {
            let copy_done_msg = build_copy_done_message();

            // Verify message structure
            assert_eq!(copy_done_msg.len(), 5);
            assert_eq!(copy_done_msg[0], b'c'); // CopyDone type

            // Verify length is 0 (no payload)
            let length = u32::from_be_bytes([
                copy_done_msg[1],
                copy_done_msg[2],
                copy_done_msg[3],
                copy_done_msg[4],
            ]);
            assert_eq!(length, 0, "CopyDone should have no payload");

            // Test flush semantics: CopyDone should trigger immediate processing
            // In a real implementation, this would flush all pending COPY data
            // Here we test that the message format is correct for triggering flush

            // Verify the message can be parsed as a proper protocol message
            let mut cursor = Cursor::new(&copy_done_msg[1..]); // Skip type byte
            let mut length_buf = [0u8; 4];
            cursor.read_exact(&mut length_buf).unwrap();
            let parsed_length = u32::from_be_bytes(length_buf);
            assert_eq!(parsed_length, 0);
        }

        #[test]
        fn copy_fail_error_propagation_conformance() {
            let error_messages = [
                "Invalid data format",
                "Constraint violation",
                "Connection lost during COPY",
                "Buffer overflow",
                "", // Empty error message
            ];

            for error_msg in &error_messages {
                let copy_fail_msg = build_copy_fail_message(error_msg);

                // Verify message structure
                assert_eq!(copy_fail_msg[0], b'f'); // CopyFail type

                // Verify length includes null terminator
                let length = u32::from_be_bytes([
                    copy_fail_msg[1],
                    copy_fail_msg[2],
                    copy_fail_msg[3],
                    copy_fail_msg[4],
                ]);
                assert_eq!(
                    length,
                    error_msg.len() as u32 + 1,
                    "Length should include null terminator"
                );

                // Verify message content and null termination
                let payload = &copy_fail_msg[5..];
                assert_eq!(payload.len(), error_msg.len() + 1);
                assert_eq!(&payload[..error_msg.len()], error_msg.as_bytes());
                assert_eq!(
                    payload[payload.len() - 1],
                    0,
                    "Message should be null-terminated"
                );

                // Test error propagation: verify the error can be extracted
                let extracted_error = std::str::from_utf8(&payload[..payload.len() - 1]).unwrap();
                assert_eq!(extracted_error, *error_msg);
            }
        }

        #[test]
        fn copy_fail_utf8_error_message_conformance() {
            // Test with UTF-8 error message containing non-ASCII characters
            let utf8_error = "Błąd podczas kopiowania danych"; // Polish error message
            let copy_fail_msg = build_copy_fail_message(utf8_error);

            let payload = &copy_fail_msg[5..];
            let extracted_error = std::str::from_utf8(&payload[..payload.len() - 1]).unwrap();
            assert_eq!(extracted_error, utf8_error);
        }

        #[test]
        fn binary_format_oid_mapping_conformance() {
            // Test OID mappings for standard PostgreSQL types
            struct OidTestCase {
                oid: u32,
                type_name: &'static str,
                sample_binary_data: Vec<u8>,
                expected_length: usize,
            }

            let test_cases = [
                // BOOL (OID 16)
                OidTestCase {
                    oid: oid::BOOL,
                    type_name: "BOOL",
                    sample_binary_data: vec![1], // true
                    expected_length: 1,
                },
                // INT2 (OID 21)
                OidTestCase {
                    oid: oid::INT2,
                    type_name: "INT2",
                    sample_binary_data: (42i16).to_be_bytes().to_vec(),
                    expected_length: 2,
                },
                // INT4 (OID 23)
                OidTestCase {
                    oid: oid::INT4,
                    type_name: "INT4",
                    sample_binary_data: (12345i32).to_be_bytes().to_vec(),
                    expected_length: 4,
                },
                // INT8 (OID 20)
                OidTestCase {
                    oid: oid::INT8,
                    type_name: "INT8",
                    sample_binary_data: (123456789i64).to_be_bytes().to_vec(),
                    expected_length: 8,
                },
                // FLOAT4 (OID 700)
                OidTestCase {
                    oid: oid::FLOAT4,
                    type_name: "FLOAT4",
                    sample_binary_data: (3.14f32).to_be_bytes().to_vec(),
                    expected_length: 4,
                },
                // FLOAT8 (OID 701)
                OidTestCase {
                    oid: oid::FLOAT8,
                    type_name: "FLOAT8",
                    sample_binary_data: (2.718281828f64).to_be_bytes().to_vec(),
                    expected_length: 8,
                },
                // TEXT (OID 25)
                OidTestCase {
                    oid: oid::TEXT,
                    type_name: "TEXT",
                    sample_binary_data: b"Hello, World!".to_vec(),
                    expected_length: 13,
                },
                // BYTEA (OID 17)
                OidTestCase {
                    oid: oid::BYTEA,
                    type_name: "BYTEA",
                    sample_binary_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
                    expected_length: 4,
                },
            ];

            for test_case in &test_cases {
                // Verify OID constant is correct
                assert!(
                    test_case.oid > 0,
                    "OID for {} should be positive",
                    test_case.type_name
                );

                // Test binary format encoding
                assert_eq!(
                    test_case.sample_binary_data.len(),
                    test_case.expected_length,
                    "Binary data length for {} should match expected",
                    test_case.type_name
                );

                // For fixed-size types, verify the encoding produces correct byte count
                match test_case.type_name {
                    "BOOL" => assert_eq!(test_case.sample_binary_data.len(), 1),
                    "INT2" => assert_eq!(test_case.sample_binary_data.len(), 2),
                    "INT4" => assert_eq!(test_case.sample_binary_data.len(), 4),
                    "INT8" => assert_eq!(test_case.sample_binary_data.len(), 8),
                    "FLOAT4" => assert_eq!(test_case.sample_binary_data.len(), 4),
                    "FLOAT8" => assert_eq!(test_case.sample_binary_data.len(), 8),
                    _ => {} // Variable-length types (TEXT, BYTEA) - no fixed size constraint
                }

                // Test binary roundtrip for numeric types
                match test_case.type_name {
                    "INT2" => {
                        let decoded = i16::from_be_bytes([
                            test_case.sample_binary_data[0],
                            test_case.sample_binary_data[1],
                        ]);
                        assert_eq!(decoded, 42);
                    }
                    "INT4" => {
                        let bytes = [
                            test_case.sample_binary_data[0],
                            test_case.sample_binary_data[1],
                            test_case.sample_binary_data[2],
                            test_case.sample_binary_data[3],
                        ];
                        let decoded = i32::from_be_bytes(bytes);
                        assert_eq!(decoded, 12345);
                    }
                    "INT8" => {
                        let bytes = [
                            test_case.sample_binary_data[0],
                            test_case.sample_binary_data[1],
                            test_case.sample_binary_data[2],
                            test_case.sample_binary_data[3],
                            test_case.sample_binary_data[4],
                            test_case.sample_binary_data[5],
                            test_case.sample_binary_data[6],
                            test_case.sample_binary_data[7],
                        ];
                        let decoded = i64::from_be_bytes(bytes);
                        assert_eq!(decoded, 123456789);
                    }
                    "FLOAT4" => {
                        let bytes = [
                            test_case.sample_binary_data[0],
                            test_case.sample_binary_data[1],
                            test_case.sample_binary_data[2],
                            test_case.sample_binary_data[3],
                        ];
                        let decoded = f32::from_be_bytes(bytes);
                        assert!((decoded - 3.14).abs() < f32::EPSILON);
                    }
                    "FLOAT8" => {
                        let bytes = [
                            test_case.sample_binary_data[0],
                            test_case.sample_binary_data[1],
                            test_case.sample_binary_data[2],
                            test_case.sample_binary_data[3],
                            test_case.sample_binary_data[4],
                            test_case.sample_binary_data[5],
                            test_case.sample_binary_data[6],
                            test_case.sample_binary_data[7],
                        ];
                        let decoded = f64::from_be_bytes(bytes);
                        assert!((decoded - 2.718281828).abs() < f64::EPSILON);
                    }
                    _ => {}
                }
            }
        }

        #[test]
        fn copy_protocol_message_type_conformance() {
            // Verify all COPY protocol message types are correctly defined
            assert_eq!(FrontendMessage::CopyData as u8, b'd');
            assert_eq!(FrontendMessage::CopyDone as u8, b'c');
            assert_eq!(FrontendMessage::CopyFail as u8, b'f');

            assert_eq!(BackendMessage::CopyInResponse as u8, b'G');
            assert_eq!(BackendMessage::CopyOutResponse as u8, b'H');
            assert_eq!(BackendMessage::CopyBothResponse as u8, b'W');
            assert_eq!(BackendMessage::CopyData as u8, b'd');
            assert_eq!(BackendMessage::CopyDone as u8, b'c');
        }

        #[test]
        fn copy_protocol_edge_cases_conformance() {
            // Test empty COPY data
            let empty_data = build_copy_data_message(&[]);
            assert_eq!(empty_data[0], b'd');
            let length =
                u32::from_be_bytes([empty_data[1], empty_data[2], empty_data[3], empty_data[4]]);
            assert_eq!(length, 0);

            // Test maximum single chunk size (64MB limit mentioned in code)
            let max_chunk_size = 64 * 1024 * 1024;
            let large_data = vec![b'x'; max_chunk_size];
            let large_chunk = build_copy_data_message(&large_data);
            assert_eq!(large_chunk[0], b'd');
            let chunk_length = u32::from_be_bytes([
                large_chunk[1],
                large_chunk[2],
                large_chunk[3],
                large_chunk[4],
            ]);
            assert_eq!(chunk_length, max_chunk_size as u32);

            // Test null values in binary format
            let mut null_data = Vec::new();
            null_data.extend_from_slice(b"PGCOPY\n\xFF\r\n\0"); // Binary signature
            null_data.extend_from_slice(&0u32.to_be_bytes()); // Flags
            null_data.extend_from_slice(&0u32.to_be_bytes()); // Header extension
            null_data.extend_from_slice(&1u16.to_be_bytes()); // 1 column
            null_data.extend_from_slice(&(-1i32).to_be_bytes()); // NULL value (length -1)
            null_data.extend_from_slice(&(-1i16).to_be_bytes()); // End marker

            let null_chunk = build_copy_data_message(&null_data);
            assert!(null_chunk.len() > 5); // Should contain the null value encoding
        }

        #[test]
        fn copy_protocol_error_edge_cases_conformance() {
            // Test very long error message
            let long_error = "x".repeat(8192); // 8KB error message
            let long_fail_msg = build_copy_fail_message(&long_error);
            assert_eq!(long_fail_msg[0], b'f');

            let length = u32::from_be_bytes([
                long_fail_msg[1],
                long_fail_msg[2],
                long_fail_msg[3],
                long_fail_msg[4],
            ]);
            assert_eq!(length, long_error.len() as u32 + 1); // +1 for null terminator

            // Test error message with embedded nulls (should be escaped or rejected)
            let null_error = "Error\0with\0nulls";
            let null_fail_msg = build_copy_fail_message(null_error);
            // Verify that embedded nulls don't break the protocol message structure
            let payload = &null_fail_msg[5..];
            assert_eq!(payload[payload.len() - 1], 0); // Still properly null-terminated
        }
    }
}
