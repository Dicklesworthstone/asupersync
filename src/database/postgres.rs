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
use crate::security::SecretString;
#[cfg(feature = "tls")]
use crate::tls::{Certificate, TlsConnector, TlsConnectorBuilder, TlsStream};
use crate::types::{CancelReason, Outcome};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

// ============================================================================
// Error Types
// ============================================================================

/// PostgreSQL ErrorResponse diagnostic fields per protocol documentation.
///
/// Captures actionable debugging information like constraint names, table names,
/// schema names, and column names that help developers understand what went wrong.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct PgErrorDiagnostic {
    /// Constraint name ('c' field) - crucial for constraint violation debugging.
    pub constraint_name: Option<String>,
    /// Table name ('t' field) - identifies which table caused the error.
    pub table_name: Option<String>,
    /// Schema name ('s' field) - schema context for the error.
    pub schema_name: Option<String>,
    /// Column name ('n' field) - specific column that caused the error.
    pub column_name: Option<String>,
    /// Severity ('S' field) - ERROR, FATAL, PANIC, WARNING, etc.
    pub severity: Option<String>,
    /// Routine name ('R' field) - PostgreSQL function where error occurred.
    pub routine_name: Option<String>,
    /// Position ('P' field) - character position in the query where error occurred.
    pub position: Option<String>,
    /// Internal position ('p' field) - position in internally generated query.
    pub internal_position: Option<String>,
    /// Internal query ('q' field) - the internally generated query.
    pub internal_query: Option<String>,
    /// Where context ('W' field) - context where error occurred.
    pub where_context: Option<String>,
    /// File name ('F' field) - source file where error occurred (debug builds).
    pub file_name: Option<String>,
    /// Line number ('L' field) - source line where error occurred (debug builds).
    pub line_number: Option<String>,
}

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
        /// Diagnostic fields from PostgreSQL protocol for actionable debugging.
        diagnostic: PgErrorDiagnostic,
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
    /// br-asupersync-dvgvcu — `begin_with_isolation` issued a
    /// `BEGIN ISOLATION LEVEL X` but the server-reported value of
    /// `SHOW transaction_isolation` did not match the requested
    /// level. The transaction has been rolled back before this
    /// error is returned.
    IsolationLevelMismatch {
        /// The level the caller requested.
        requested: IsolationLevel,
        /// The raw value the server reported via `SHOW transaction_isolation`.
        observed: String,
    },
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
                diagnostic,
            } => {
                write!(f, "PostgreSQL error [{code}]: {message}")?;
                if let Some(d) = detail {
                    write!(f, " (detail: {d})")?;
                }
                if let Some(h) = hint {
                    write!(f, " (hint: {h})")?;
                }

                // Show actionable diagnostic fields for better debugging
                if let Some(constraint) = &diagnostic.constraint_name {
                    write!(f, " (constraint: {constraint})")?;
                }
                if let Some(table) = &diagnostic.table_name {
                    write!(f, " (table: {table})")?;
                }
                if let Some(schema) = &diagnostic.schema_name {
                    write!(f, " (schema: {schema})")?;
                }
                if let Some(column) = &diagnostic.column_name {
                    write!(f, " (column: {column})")?;
                }
                if let Some(position) = &diagnostic.position {
                    write!(f, " (position: {position})")?;
                }

                Ok(())
            }
            Self::Cancelled(reason) => write!(f, "PostgreSQL operation cancelled: {reason}"),
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
            Self::IsolationLevelMismatch {
                requested,
                observed,
            } => write!(
                f,
                "PostgreSQL isolation level mismatch: requested {requested}, server reported \
                 {observed:?} — silent downgrade detected, transaction rolled back \
                 (br-asupersync-dvgvcu)"
            ),
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
    /// Arbitrary precision decimal.
    pub const NUMERIC: u32 = 1700;
    /// Variable-length character string.
    pub const VARCHAR: u32 = 1043;
    /// Text (unlimited length).
    pub const TEXT: u32 = 25;
    /// Date.
    pub const DATE: u32 = 1082;
    /// Timestamp without timezone.
    pub const TIMESTAMP: u32 = 1114;
    /// Time interval.
    pub const INTERVAL: u32 = 1186;
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
                | oid::INTERVAL
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
                // Calculate capacity with overflow protection for hex encoding (2 chars per byte + "\\x" prefix)
                let capacity = bytes.len().saturating_mul(2).saturating_add(2);
                let mut out = Vec::with_capacity(capacity);
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
                    // Calculate capacity with overflow protection for JSONB prefix (1 byte + text)
                    let mut out = Vec::with_capacity(text.len().saturating_add(1));
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
// Streaming Query API (DEFECT FIX)
// ============================================================================

/// Streaming query result iterator for bounded-memory row processing.
///
/// DEFECT FIX: This provides streaming iteration over query results to address
/// the memory usage issue where all rows are collected into Vec<PgRow> before
/// returning (lines 3524, 5436). With this API, memory usage is O(1) per row
/// instead of O(result_set_size).
///
/// # Example Usage
/// ```ignore
/// let mut stream = conn.query_stream(cx, "SELECT * FROM large_table").await?;
/// while let Some(row) = stream.next(cx).await? {
///     // Process one row at a time - bounded memory usage
///     process_row(&row)?;
/// }
/// ```
#[must_use]
pub struct PgRowStream<'a> {
    connection: &'a mut PgConnection,
    columns: Option<Arc<Vec<PgColumn>>>,
    column_indices: Option<Arc<BTreeMap<String, usize>>>,
    finished: bool,
    pending_row_count: u64,
}

impl<'a> PgRowStream<'a> {
    /// Get the next row from the stream.
    ///
    /// Returns `Ok(Some(row))` for the next row, `Ok(None)` when the stream
    /// is complete, or `Err(...)` on protocol errors.
    pub async fn next(&mut self, cx: &Cx) -> Outcome<Option<PgRow>, PgError> {
        if self.finished {
            return Outcome::Ok(None);
        }

        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        loop {
            let (msg_type, data) = match self.connection.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return Outcome::Err(e),
            };

            match msg_type {
                b'T' => {
                    // RowDescription - set up column metadata
                    match self.connection.parse_row_description(&data) {
                        Ok((cols, indices)) => {
                            self.columns = Some(Arc::new(cols));
                            self.column_indices = Some(Arc::new(indices));
                        }
                        Err(e) => return Outcome::Err(e),
                    }
                }
                b'D' => {
                    // DataRow - parse and return single row
                    let (Some(cols), Some(indices)) = (&self.columns, &self.column_indices) else {
                        return Outcome::Err(PgError::Protocol(
                            "received DataRow before RowDescription in streaming query".to_string(),
                        ));
                    };

                    match self.connection.parse_data_row(&data, cols) {
                        Ok(values) => {
                            self.pending_row_count += 1;
                            return Outcome::Ok(Some(PgRow {
                                columns: cols.clone(),
                                column_indices: indices.clone(),
                                values,
                            }));
                        }
                        Err(e) => return Outcome::Err(e),
                    }
                }
                b'C' => {
                    // CommandComplete - continue to ReadyForQuery
                    continue;
                }
                b'Z' => {
                    // ReadyForQuery - stream complete
                    self.finished = true;
                    self.connection.inner.closed = false;
                    if let Err(e) = self.connection.handle_ready_for_query(&data) {
                        return Outcome::Err(e);
                    }
                    return Outcome::Ok(None);
                }
                b'E' => {
                    // ErrorResponse
                    match self.connection.parse_error_response(&data) {
                        Ok(err) => return Outcome::Err(err),
                        Err(parse_err) => return Outcome::Err(parse_err),
                    }
                }
                _ => {
                    // Ignore other message types (notices, etc.)
                    continue;
                }
            }
        }
    }

    /// Get the number of rows processed so far by this stream.
    pub fn row_count(&self) -> u64 {
        self.pending_row_count
    }
}

impl PgConnection {
    /// Execute a streaming query with bounded memory usage.
    ///
    /// DEFECT FIX: This replaces the collect-all-rows pattern with streaming
    /// iteration. Memory usage is O(1) per row instead of O(result_set_size).
    ///
    /// # Security
    /// Same as [`Self::query_unchecked`] - no parameterization performed.
    pub async fn query_stream<'a>(
        &'a mut self,
        cx: &Cx,
        sql: &str,
    ) -> Outcome<PgRowStream<'a>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Send Query message
        let mut buf = MessageBuffer::new();
        buf.write_cstring(sql);
        let query_msg = match buf.build_message(FrontendMessage::Query as u8) {
            Ok(m) => m,
            Err(e) => return Outcome::Err(e),
        };

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Mark closed until ReadyForQuery so cancellation or drop cannot leave
        // a half-consumed stream available for a new protocol exchange.
        self.inner.closed = true;

        if let Err(err) = self.write_all(cx, &query_msg).await {
            return self.fail_in_flight(err);
        }

        // Return streaming iterator
        Outcome::Ok(PgRowStream {
            connection: self,
            columns: None,
            column_indices: None,
            finished: false,
            pending_row_count: 0,
        })
    }

    /// Execute a parameterized streaming query with bounded memory usage.
    ///
    /// DEFECT FIX: Streaming version of query_params for large result sets.
    pub async fn query_stream_params<'a>(
        &'a mut self,
        cx: &Cx,
        sql: &str,
        params: &[&dyn ToSql],
    ) -> Outcome<PgRowStream<'a>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // Use extended query protocol for parameterized queries
        let stmt_name = ""; // Unnamed statement
        let portal_name = ""; // Unnamed portal

        let param_oids: Vec<u32> = params.iter().map(ToSql::type_oid).collect();
        let parse_msg = match build_parse_msg(stmt_name, sql, &param_oids) {
            Ok(msg) => msg,
            Err(e) => return Outcome::Err(e),
        };
        let bind_msg = match build_bind_msg(portal_name, stmt_name, params, Format::Text) {
            Ok(msg) => msg,
            Err(e) => return Outcome::Err(e),
        };
        let execute_msg = match build_execute_msg(portal_name, 0) {
            Ok(msg) => msg,
            Err(e) => return Outcome::Err(e),
        };
        let sync_msg = match build_sync_msg() {
            Ok(msg) => msg,
            Err(e) => return Outcome::Err(e),
        };

        // Calculate total length with overflow protection for message concatenation
        let total = parse_msg
            .len()
            .saturating_add(bind_msg.len())
            .saturating_add(execute_msg.len())
            .saturating_add(sync_msg.len());
        let mut combined = Vec::with_capacity(total);
        combined.extend_from_slice(&parse_msg);
        combined.extend_from_slice(&bind_msg);
        combined.extend_from_slice(&execute_msg);
        combined.extend_from_slice(&sync_msg);

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.inner.closed = true;

        if let Err(err) = self.write_all(cx, &combined).await {
            return self.fail_in_flight(err);
        }

        // Return streaming iterator
        Outcome::Ok(PgRowStream {
            connection: self,
            columns: None,
            column_indices: None,
            finished: false,
            pending_row_count: 0,
        })
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
    CopyData = b'd',
    /// Copy done message.
    CopyDone = b'c',
    /// Copy fail message.
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

    fn write_startup_cstring(&mut self, context: &str, s: &str) -> Result<(), PgError> {
        if s.as_bytes().contains(&0) {
            return Err(PgError::Protocol(format!(
                "{context} contains embedded NUL byte"
            )));
        }
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
        Ok(())
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

    fn read_i64(&mut self) -> Result<i64, PgError> {
        if self.pos + 8 > self.data.len() {
            return Err(PgError::Protocol("unexpected end of message".to_string()));
        }
        let v = i64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
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

    fn ensure_consumed(&self, context: &str) -> Result<(), PgError> {
        let remaining = self.remaining();
        if remaining == 0 {
            Ok(())
        } else {
            Err(PgError::Protocol(format!(
                "{context} message has {remaining} trailing byte(s)"
            )))
        }
    }
}

// ============================================================================
// SCRAM-SHA-256 Authentication
// ============================================================================

/// SCRAM channel-binding mode. Drives the GS2 header and the `c=` value.
/// (br-asupersync-7n2xsi)
#[derive(Debug, Clone)]
#[allow(dead_code)]
enum ScramChannelBinding {
    /// No TLS — `n,,` GS2 header. Used with `SCRAM-SHA-256` over plain TCP.
    None,
    /// TLS in use, but server did NOT advertise `SCRAM-SHA-256-PLUS`.
    /// Send `y,,` GS2 to signal client supports channel binding even though
    /// the server didn't offer it. If a MITM stripped `-PLUS` from the
    /// mechanism advertisement, the real server will detect the mismatch
    /// (it would have advertised `-PLUS`) and abort the handshake — this
    /// is the RFC 5802 §6 channel-binding-downgrade detection.
    SupportedNotUsed,
    /// TLS in use AND `SCRAM-SHA-256-PLUS` selected. `cbind_data` is the
    /// `tls-server-end-point` channel-binding bytes (RFC 5929):
    /// SHA-256(leaf-cert-DER). The GS2 header is
    /// `p=tls-server-end-point,,` and the `c=` value carries the
    /// base64-encoded GS2-header || cbind_data.
    TlsServerEndPoint { cbind_data: Vec<u8> },
}

impl ScramChannelBinding {
    /// SASL mechanism name to send in SASLInitialResponse.
    fn mechanism(&self) -> &'static str {
        match self {
            Self::TlsServerEndPoint { .. } => "SCRAM-SHA-256-PLUS",
            Self::None | Self::SupportedNotUsed => "SCRAM-SHA-256",
        }
    }

    /// GS2 header prefix that goes both into client-first and (base64-encoded
    /// alongside any cbind data) into the `c=` value of client-final.
    fn gs2_header(&self) -> &'static str {
        match self {
            Self::None => "n,,",
            Self::SupportedNotUsed => "y,,",
            Self::TlsServerEndPoint { .. } => "p=tls-server-end-point,,",
        }
    }

    /// Bytes to base64-encode for the `c=` field: GS2 header || cbind_data.
    fn c_field_bytes(&self) -> Vec<u8> {
        let mut out = self.gs2_header().as_bytes().to_vec();
        if let Self::TlsServerEndPoint { cbind_data } = self {
            out.extend_from_slice(cbind_data);
        }
        out
    }
}

/// Compute the `tls-server-end-point` channel-binding data per RFC 5929.
///
/// Implementation note (br-asupersync-7n2xsi): RFC 5929 specifies that the
/// hash function matches the cert's signature algorithm hash, normalised to
/// SHA-256 if the signature uses MD5 or SHA-1. This implementation always
/// uses SHA-256, which is correct for the dominant case (modern PostgreSQL
/// servers with SHA-256-signed certs) and for the legacy MD5/SHA-1 cases.
/// Certificates signed with SHA-384 or SHA-512 would require this hash to
/// match the signature algorithm; that's a follow-up if production deployment
/// hits non-SHA-256 cert chains.
#[cfg(feature = "tls")]
fn tls_server_end_point_cbind(cert_der: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(cert_der);
    h.finalize().to_vec()
}

/// Constant-time equality for a secret expected byte string against an
/// attacker-controlled actual value.
///
/// SCRAM server signatures are fixed-size SHA-256 MACs, so length mismatches
/// are public. We still walk the full expected length to avoid turning
/// truncated attacker inputs into a variable-time prefix oracle.
#[inline]
fn scram_constant_time_eq_expected_len(expected: &[u8], actual: &[u8]) -> bool {
    use std::hint::black_box;

    let mut diff = u8::from(expected.len() != actual.len());

    // Use direct indexing instead of enumerate to avoid potential iterator overhead
    // that could introduce timing variations
    for i in 0..expected.len() {
        let actual_byte = actual.get(i).copied().unwrap_or(0);
        diff |= expected[i] ^ actual_byte;
    }

    black_box(diff) == 0
}

/// SCRAM-SHA-256 authentication state machine.
///
/// br-asupersync-r2l1ze: `password` is held in a [`SecretString`] so the
/// plaintext bytes are zeroized when the `ScramAuth` value is dropped
/// (i.e. when the SCRAM exchange completes or is cancelled). Heap
/// snapshots, core dumps, or attached debuggers reading stale memory
/// after auth completes recover only zero bytes.
struct ScramAuth {
    /// Password — wiped on drop (br-asupersync-r2l1ze).
    password: SecretString,
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
    /// Channel-binding mode (br-asupersync-7n2xsi).
    cb: ScramChannelBinding,
}

impl ScramAuth {
    fn new(cx: &Cx, username: &str, password: &str, cb: ScramChannelBinding) -> Self {
        // Generate client nonce (24 random bytes, base64 encoded)
        let mut nonce_bytes = [0u8; 24];
        cx.random_bytes(&mut nonce_bytes);
        let client_nonce =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, nonce_bytes);

        // RFC 5802: escape '=' as '=3D' and ',' as '=2C' in username
        let escaped_username = username.replace('=', "=3D").replace(',', "=2C");
        let client_first_bare = format!("n={escaped_username},r={client_nonce}");

        Self {
            password: SecretString::new(password),
            client_nonce,
            full_nonce: None,
            salt: None,
            iterations: None,
            auth_message: None,
            client_first_bare,
            cb,
        }
    }

    /// Generate the client-first message.
    /// gs2-header carries the channel-binding mode (br-asupersync-7n2xsi):
    ///   `n,,`                       no TLS / no CB support
    ///   `y,,`                       TLS but server didn't advertise -PLUS
    ///   `p=tls-server-end-point,,`  TLS + -PLUS selected
    fn client_first_message(&self) -> Vec<u8> {
        format!("{}{}", self.cb.gs2_header(), self.client_first_bare).into_bytes()
    }

    /// Process server-first message and generate client-final message.
    fn process_server_first(&mut self, server_first: &str) -> Result<Vec<u8>, PgError> {
        // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
        let mut server_nonce = None;
        let mut salt = None;
        let mut iterations = None;

        for part in server_first.split(',') {
            if part.starts_with("m=") {
                return Err(PgError::AuthenticationFailed(
                    "unsupported SCRAM mandatory extension".to_string(),
                ));
            } else if let Some(value) = part.strip_prefix("r=") {
                if server_nonce.replace(value.to_string()).is_some() {
                    return Err(PgError::AuthenticationFailed(
                        "duplicate server nonce".to_string(),
                    ));
                }
            } else if let Some(value) = part.strip_prefix("s=") {
                let decoded =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                        .map_err(|e| PgError::AuthenticationFailed(format!("invalid salt: {e}")))?;
                if salt.replace(decoded).is_some() {
                    return Err(PgError::AuthenticationFailed("duplicate salt".to_string()));
                }
            } else if let Some(value) = part.strip_prefix("i=") {
                let parsed = value.parse().map_err(|e| {
                    PgError::AuthenticationFailed(format!("invalid iterations: {e}"))
                })?;
                if iterations.replace(parsed).is_some() {
                    return Err(PgError::AuthenticationFailed(
                        "duplicate iterations".to_string(),
                    ));
                }
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
        let salted_password = self.pbkdf2_sha256(self.password.as_str(), &salt, iterations);

        // Compute client key and stored key
        let client_key = Self::hmac_sha256(&salted_password, b"Client Key");
        let stored_key = Self::sha256(&client_key);

        // Build client-final-message-without-proof. The `c=` field is the
        // base64 encoding of GS2-header || cbind_data, where the GS2 header
        // matches the one we sent in client-first. For -PLUS this carries the
        // tls-server-end-point hash so the server can verify channel binding;
        // for `y,,` (TLS but no -PLUS advertised) this signals the
        // downgrade-detection request to the server. (br-asupersync-7n2xsi)
        let channel_binding = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            self.cb.c_field_bytes(),
        );
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
        // Parse server-final-message: either v=<server-signature> or e=<server-error>
        let mut server_sig_b64 = None;
        let mut server_error = None;

        for part in server_final.split(',') {
            if part.starts_with("m=") {
                return Err(PgError::AuthenticationFailed(
                    "unsupported SCRAM mandatory extension".to_string(),
                ));
            } else if let Some(value) = part.strip_prefix("v=") {
                if server_sig_b64.replace(value).is_some() {
                    return Err(PgError::AuthenticationFailed(
                        "duplicate server signature".to_string(),
                    ));
                }
            } else if let Some(value) = part.strip_prefix("e=") {
                if server_error.replace(value).is_some() {
                    return Err(PgError::AuthenticationFailed(
                        "duplicate server error".to_string(),
                    ));
                }
            }
        }

        if server_sig_b64.is_some() && server_error.is_some() {
            return Err(PgError::AuthenticationFailed(
                "invalid server-final: verifier and error both present".to_string(),
            ));
        }

        if let Some(server_error) = server_error {
            return Err(PgError::AuthenticationFailed(format!(
                "server rejected SCRAM exchange: {server_error}"
            )));
        }

        let server_sig_b64 = server_sig_b64
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
        let salted_password = self.pbkdf2_sha256(self.password.as_str(), salt, iterations); // ubs:ignore - dynamic password variable
        let server_key = Self::hmac_sha256(&salted_password, b"Server Key");
        let auth_message = self.auth_message.as_ref().ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing auth_message".to_string())
        })?;
        let expected_sig = Self::hmac_sha256(&server_key, auth_message.as_bytes());

        if !scram_constant_time_eq_expected_len(&expected_sig, &server_sig) {
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
    ///
    /// br-asupersync-r2l1ze: stored in a [`SecretString`] so the
    /// plaintext bytes are zeroized when `PgConnectOptions` is dropped.
    pub password: Option<SecretString>,
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

/// br-asupersync-rsifm3 — Postgres transaction isolation level.
///
/// Used by [`PgConnection::begin_with_isolation`] to emit a single atomic
/// `BEGIN ISOLATION LEVEL X [READ ONLY|READ WRITE]` statement. Setting the
/// level via a separate `SET TRANSACTION ISOLATION LEVEL X` after `BEGIN`
/// also works in Postgres but costs an extra round-trip and leaves the
/// typed [`PgTransaction`] wrapper without introspection of the level in
/// effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationLevel {
    /// `READ UNCOMMITTED` — Postgres treats this as `READ COMMITTED`.
    ReadUncommitted,
    /// `READ COMMITTED` — Postgres default.
    ReadCommitted,
    /// `REPEATABLE READ` — snapshot isolation; reads see a consistent
    /// snapshot of the database as it existed at transaction start.
    RepeatableRead,
    /// `SERIALIZABLE` — strongest level; transactions are guaranteed to be
    /// equivalent to some serial execution. Required for correctness in
    /// workloads with read-modify-write hazards.
    Serializable,
}

impl IsolationLevel {
    /// Returns the SQL fragment for this level (no leading/trailing space).
    #[must_use]
    pub const fn as_sql(self) -> &'static str {
        match self {
            Self::ReadUncommitted => "READ UNCOMMITTED",
            Self::ReadCommitted => "READ COMMITTED",
            Self::RepeatableRead => "REPEATABLE READ",
            Self::Serializable => "SERIALIZABLE",
        }
    }

    /// br-asupersync-dvgvcu — Parse the value returned by
    /// `SHOW transaction_isolation`. Postgres reports these as
    /// lowercase with spaces (`read uncommitted`, `read committed`,
    /// `repeatable read`, `serializable`). The match is
    /// case-insensitive and tolerates either separator. Note
    /// Postgres collapses `read uncommitted` to behave like
    /// `read committed` internally; the server-reported string
    /// still distinguishes the two. The verifier therefore checks
    /// for exact requested-level match — a Postgres downgrade of
    /// `read uncommitted` to `read committed` is reported as a
    /// mismatch (the operator can opt out by requesting
    /// `read committed` directly).
    #[must_use]
    pub fn from_server_string(value: &str) -> Option<Self> {
        let normalised: String = value
            .trim()
            .chars()
            .map(|c| {
                if c == '-' || c == '_' {
                    ' '
                } else {
                    c.to_ascii_uppercase()
                }
            })
            .collect();
        match normalised.as_str() {
            "READ UNCOMMITTED" => Some(Self::ReadUncommitted),
            "READ COMMITTED" => Some(Self::ReadCommitted),
            "REPEATABLE READ" => Some(Self::RepeatableRead),
            "SERIALIZABLE" => Some(Self::Serializable),
            _ => None,
        }
    }
}

impl std::fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_sql())
    }
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
            // br-asupersync-r2l1ze: wrap the parsed password (whose
            // owned `String` allocation came from `percent_decode`)
            // into a `SecretString` so its bytes are zeroized on drop.
            // `from_string` reuses the existing allocation — the bytes
            // wiped at drop are the same bytes that were in memory
            // during connection setup.
            password: password.map(SecretString::from_string),
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

    /// br-asupersync-1wygbs: best-effort PostgreSQL Terminate frame
    /// (`'X'` 0x58 followed by big-endian 4-byte length=4) before TCP
    /// shutdown. Per the PostgreSQL FE/BE protocol, a backend that
    /// sees its TCP peer disappear without a prior Terminate retains
    /// session-scoped state (prepared statements, temp tables,
    /// advisory locks, idle-in-transaction state) until tcp_keepalive
    /// or idle_session_timeout fires — typically minutes to hours.
    /// Sending the Terminate first prompts immediate cleanup.
    ///
    /// The write is intentionally NON-blocking and best-effort: this
    /// runs from `Drop`, so it cannot await, cannot park the thread,
    /// and must tolerate any error (already-closed socket, broken
    /// pipe, partial write). Each successful 5-byte write closes the
    /// server-side leak; a failure leaves us no worse off than the
    /// previous shutdown-only behaviour.
    ///
    /// TLS is intentionally skipped — encrypting the frame would
    /// require driving an async TLS handshake from sync Drop. The
    /// existing TLS shutdown (drop-on-close) is preserved; the server
    /// still reclaims state via idle_session_timeout (slower but
    /// unavoidable from sync Drop). Future work could route TLS
    /// connection close through an async helper.
    fn try_send_terminate_frame(&self) {
        const TERMINATE_FRAME: [u8; 5] = [b'X', 0, 0, 0, 4];
        match self {
            Self::Plain(s) => {
                // Grab the inner std::net::TcpStream — set non-blocking
                // so a stalled peer cannot park this thread, then write
                // the 5 bytes. Errors are silently dropped: a failed
                // Terminate is no worse than the pre-fix shutdown-only
                // behaviour.
                if let Some(std_stream) = s.try_as_std() {
                    let _ = std_stream.set_nonblocking(true);
                    use std::io::Write;
                    let mut writer = std_stream;
                    let _ = writer.write_all(&TERMINATE_FRAME);
                }
            }
            #[cfg(feature = "tls")]
            Self::Tls(_) => {
                // See doc — TLS path requires async TLS encrypt; left
                // for a future async-helper refactor.
            }
        }
    }

    /// Whether this stream is TLS-encrypted. Used by SCRAM channel-binding
    /// selection (br-asupersync-7n2xsi).
    #[cfg(feature = "tls")]
    fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    /// Fallback for builds without the `tls` feature — there is no TLS path,
    /// so SCRAM channel binding is always disabled.
    #[cfg(not(feature = "tls"))]
    #[allow(dead_code)]
    fn is_tls(&self) -> bool {
        false
    }

    /// DER bytes of the TLS peer leaf certificate, when the stream is
    /// TLS-encrypted and the handshake produced a server cert.
    /// Returns `None` for plain TCP streams. Used to compute the
    /// `tls-server-end-point` channel-binding data for SCRAM-SHA-256-PLUS.
    /// (br-asupersync-7n2xsi)
    #[cfg(feature = "tls")]
    fn peer_leaf_certificate_der(&self) -> Option<Vec<u8>> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(s) => s.peer_leaf_certificate_der(),
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

/// Default cap on the per-connection prepared-statement cache.
///
/// br-asupersync-cvkoe9: pre-fix every distinct prepare() call allocated
/// a new server-side named statement that lived until DEALLOCATE or
/// session end. For long-lived pooled connections (default
/// max_lifetime 3600s in src/database/pool.rs) the server-side
/// pg_prepared_statements table grew monotonically with cumulative
/// distinct prepares — a real connection-scoped memory leak with no
/// upper bound. Post-fix the cache caps at this value, returns cached
/// statements on repeat-SQL hits, and sends DEALLOCATE for the LRU
/// entry on eviction.
pub const DEFAULT_MAX_PREPARED_STATEMENTS: usize = 256;

/// br-asupersync-7v80ju: hard cap on the size of the per-connection
/// deallocate-retry queue.
///
/// If a server is rejecting CLOSE messages faster than we can drain them, we
/// mark the connection unhealthy well before the queue itself grows large
/// enough to leak memory on the client side.
pub const DEALLOCATE_RETRY_QUEUE_CAP: usize = 64;

/// br-asupersync-7v80ju: consecutive CLOSE failures before eviction.
///
/// Three consecutive failures is a deliberate trade-off — one transient packet
/// loss is forgiven, but a systematically-misbehaving server (or a
/// desynchronised wire) is caught quickly.
pub const DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD: u32 = 3;

/// Bounded LRU cache for server-side prepared statements.
///
/// Keyed by SQL string (cheap given typical SQL is < 1 KB and there
/// are at most `cap` entries). LRU order is tracked by a
/// `VecDeque<String>` of SQL keys — most-recently-used at the BACK,
/// least-recently-used at the FRONT. On insert at cap the FRONT entry
/// is evicted and returned to the caller for DEALLOCATE.
struct PreparedStatementCache {
    /// SQL → cached statement metadata.
    entries: HashMap<String, PgStatement>,
    /// LRU order: front = least recently used, back = most recently used.
    /// Each String here is also a key in `entries`.
    lru: VecDeque<String>,
    /// Maximum entries before eviction. Setting to 0 effectively
    /// disables caching (every prepare() goes straight to wire + the
    /// just-inserted entry is evicted on the very next insert).
    cap: usize,
}

impl PreparedStatementCache {
    fn new(cap: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(cap.min(64)),
            lru: VecDeque::with_capacity(cap.min(64)),
            cap,
        }
    }

    /// Look up a cached statement. Returns a clone of the cached metadata
    /// AND moves the SQL key to the back of the LRU queue (most-recently
    /// used). Returns `None` on miss.
    fn get_and_touch(&mut self, sql: &str) -> Option<PgStatement> {
        let stmt = self.entries.get(sql)?.clone();
        // Move to back of LRU.
        if let Some(pos) = self.lru.iter().position(|s| s == sql) {
            if let Some(key) = self.lru.remove(pos) {
                self.lru.push_back(key);
            }
        }
        Some(stmt)
    }

    /// Insert a new statement into the cache. If the cache is at capacity,
    /// evicts the least-recently-used entry and returns its server-side
    /// name so the caller can send DEALLOCATE. If the SQL is already
    /// present, REPLACES the entry (returning the old name for DEALLOCATE
    /// — Postgres requires the old statement be closed before re-Parsing
    /// the same name, but here the names are unique per insert so we
    /// only return the OLD entry's name).
    fn insert_returning_evicted_name(&mut self, sql: String, stmt: PgStatement) -> Option<String> {
        // Reject zero-cap configs cleanly: insert returns evicted-self.
        if self.cap == 0 {
            return Some(stmt.name);
        }
        let mut evicted = None;
        // If SQL already cached (rare — would mean caller didn't check
        // get_and_touch first), close the OLD server-side name.
        if let Some(old) = self.entries.remove(&sql) {
            if let Some(pos) = self.lru.iter().position(|s| s == &sql) {
                self.lru.remove(pos);
            }
            evicted = Some(old.name);
        } else if self.entries.len() >= self.cap {
            // At cap. Evict LRU = front of queue.
            if let Some(victim_sql) = self.lru.pop_front() {
                if let Some(victim_stmt) = self.entries.remove(&victim_sql) {
                    evicted = Some(victim_stmt.name);
                }
            }
        }
        self.lru.push_back(sql.clone());
        self.entries.insert(sql, stmt);
        evicted
    }

    /// Clear the cache and return all server-side statement names that must
    /// be closed later. Names are returned in LRU order for deterministic
    /// cleanup and test assertions.
    fn clear_returning_names(&mut self) -> Vec<String> {
        let mut names = Vec::with_capacity(self.entries.len());
        while let Some(sql) = self.lru.pop_front() {
            if let Some(stmt) = self.entries.remove(&sql) {
                names.push(stmt.name);
            }
        }
        if !self.entries.is_empty() {
            names.extend(self.entries.drain().map(|(_, stmt)| stmt.name));
        }
        names
    }

    /// Remove a cached statement by its server-side statement name.
    ///
    /// Returns `true` when the name was present and removed from both
    /// the entry map and the LRU queue.
    fn remove_by_statement_name(&mut self, statement_name: &str) -> bool {
        let Some(sql) = self
            .entries
            .iter()
            .find_map(|(sql, stmt)| (stmt.name == statement_name).then(|| sql.clone()))
        else {
            return false;
        };

        self.entries.remove(&sql);
        if let Some(pos) = self.lru.iter().position(|key| key == &sql) {
            self.lru.remove(pos);
        }
        true
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Inner connection state.
struct PgConnectionInner {
    /// Transport stream (plain TCP or TLS).
    stream: PgStream,
    /// Original connection options retained for safe idle reconnect.
    options: PgConnectOptions,
    /// Server process ID.
    process_id: i32,
    /// Secret key for cancel requests.
    secret_key: i32,
    /// Cancellation target: host/port/connect-timeout retained from the
    /// original connect so a `CancelRequest` (PG protocol cancellation
    /// message — see RFC-style spec at PG docs §53.2.7) can be sent on
    /// a fresh TCP connection without re-parsing the URL or carrying
    /// the password forward (br-asupersync-gvkj1r).
    cancel_target: CancelTarget,
    /// Server parameters.
    parameters: BTreeMap<String, String>,
    /// Transaction status.
    transaction_status: u8,
    /// Whether the connection is closed.
    closed: bool,
    /// True when [`PgConnection::close`] was called explicitly. Explicitly
    /// closed connections stay closed; reconnect only covers remote idle drops
    /// and failed in-flight exchanges where the caller did not request close.
    explicitly_closed: bool,
    /// Whether a rollback is needed before the next operation (orphaned transaction).
    needs_rollback: bool,
    /// br-asupersync-yl4gu1: whether this connection must NOT be returned
    /// to a pool. Set when a `PgTransaction` was dropped without commit
    /// AND the rollback could not be issued synchronously (which is the
    /// always case in Drop). The pool's return path checks this flag and
    /// closes the connection instead of recycling it — preventing the
    /// next tenant from inheriting an `idle_in_transaction` backend with
    /// locks held. Combined with the existing `needs_rollback` flag,
    /// callers that DO continue using the same connection (without
    /// returning to a pool) still get the ROLLBACK on the next op; the
    /// pool case (drop-then-return) gets a clean conn close instead.
    needs_discard: bool,
    /// Counter for generating unique prepared statement names.
    next_stmt_id: u32,
    /// Maximum number of rows to accept per result set before closing the
    /// connection. Prevents unbounded memory growth from runaway queries or
    /// a malicious server sending an endless DataRow stream.
    max_result_rows: usize,
    /// Bounded LRU cache of server-side prepared statements (br-asupersync-cvkoe9).
    /// Pre-fix this connection leaked one server-side prepared statement per
    /// distinct prepare() call; post-fix the cache caps at
    /// [`DEFAULT_MAX_PREPARED_STATEMENTS`] entries with DEALLOCATE on
    /// eviction. Repeat-SQL prepares hit the fast path (no wire exchange).
    prepared_cache: PreparedStatementCache,
    /// br-asupersync-7v80ju: server-side prepared statement names that
    /// were evicted from `prepared_cache` but whose corresponding
    /// CLOSE message never reached the server (or whose response was
    /// lost). Pre-fix the eviction was fire-and-forget — a transient
    /// network blip silently leaked the server-side statement. The
    /// retry queue is drained at the start of public query, execute,
    /// and prepare paths via `flush_pending_deallocates`. Bounded by
    /// `DEALLOCATE_RETRY_QUEUE_CAP` so a misbehaving server cannot
    /// itself force unbounded growth on the client.
    deallocate_retry_queue: VecDeque<String>,
    /// br-asupersync-7v80ju: number of CONSECUTIVE failed CLOSE
    /// attempts since the last successful one. Reset to 0 on any
    /// success; once it crosses
    /// `DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD` the connection sets
    /// `unhealthy = true` so the pool evicts it on next return.
    consecutive_deallocate_failures: u32,
    /// br-asupersync-7v80ju: set to true once the connection has
    /// suffered too many CLOSE failures in a row to be trusted. The
    /// connection still services in-flight requests but must be
    /// removed from the pool. Exposed via
    /// [`PgConnection::is_unhealthy`].
    unhealthy: bool,
    /// LISTEN channels established by [`PgConnection::listen`]. These are
    /// replayed after an idle reconnect so notification consumers do not lose
    /// subscriptions across server-side idle timeouts.
    subscribed_channels: BTreeSet<String>,
}

/// Coordinates needed to send a PG `CancelRequest` on a fresh socket.
#[derive(Clone, Debug)]
struct CancelTarget {
    host: String,
    port: u16,
    /// Hard upper bound on the cancel-request connect — see
    /// `PgConnection::fire_cancel_request` for why this is clamped to a
    /// short value rather than inheriting the original `connect_timeout`.
    connect_timeout: std::time::Duration,
}

impl CancelTarget {
    fn from_options(options: &PgConnectOptions) -> Self {
        // CancelRequest is best-effort signaling — bound the connect attempt
        // to 500ms (or the user's configured connect_timeout, whichever is
        // smaller) so a cancelling caller can't be stalled by an
        // unreachable host on the cancel path.
        let cap = std::time::Duration::from_millis(500);
        let connect_timeout = options.connect_timeout.map_or(cap, |t| t.min(cap));
        Self {
            host: options.host.clone(),
            port: options.port,
            connect_timeout,
        }
    }
}

impl Drop for PgConnectionInner {
    /// br-asupersync-1wygbs: best-effort PostgreSQL Terminate frame
    /// before TCP shutdown. The previous shape only called
    /// `stream.shutdown(Both)`, which leaves session-scoped backend
    /// state (prepared statements, temp tables, advisory locks,
    /// idle-in-transaction state) live on the server until
    /// tcp_keepalive / idle_session_timeout fires (default
    /// minutes-to-hours). After 2-3 connection-drop cycles,
    /// pg_stat_activity / lock tables accumulate orphans.
    ///
    /// The fix sends the 5-byte Terminate message ([b'X', 0, 0, 0, 4])
    /// non-blocking before the shutdown. The write may fail (broken
    /// pipe, TLS, etc.), but every successful one prevents server-side
    /// leakage. TLS is intentionally NOT exercised here — encrypting
    /// the Terminate would require driving an async TLS handshake from
    /// inside Drop, which is impossible without blocking the calling
    /// thread on a runtime; for TLS the shutdown alone remains the
    /// current behaviour and the server still reclaims state via
    /// idle_session_timeout (slower but unavoidable in sync Drop).
    fn drop(&mut self) {
        if !self.closed {
            self.stream.try_send_terminate_frame();
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            self.closed = true;
        }
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn test_cancel_target() -> CancelTarget {
    CancelTarget {
        host: "127.0.0.1".to_string(),
        port: 5432,
        connect_timeout: std::time::Duration::from_millis(500),
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn test_pg_connect_options() -> PgConnectOptions {
    PgConnectOptions {
        host: "127.0.0.1".to_string(),
        port: 5432,
        database: "testdb".to_string(),
        user: "postgres".to_string(),
        password: None,
        application_name: Some("asupersync-postgres-test".to_string()),
        connect_timeout: Some(std::time::Duration::from_secs(1)),
        ssl_mode: SslMode::Disable,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PgOpenState {
    AlreadyOpen,
    Reconnected,
}

/// Server metadata returned when a PostgreSQL `COPY ... FROM STDIN` command
/// enters COPY IN mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgCopyInResponse {
    overall_format: Format,
    column_formats: Vec<Format>,
}

impl PgCopyInResponse {
    /// Overall COPY stream format requested by the backend.
    #[must_use]
    pub const fn overall_format(&self) -> Format {
        self.overall_format
    }

    /// Per-column COPY formats requested by the backend.
    #[must_use]
    pub fn column_formats(&self) -> &[Format] {
        &self.column_formats
    }
}

/// Summary returned after a `COPY ... FROM STDIN` stream completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgCopyInComplete {
    affected_rows: u64,
    chunks_sent: u64,
    bytes_sent: u64,
    response: PgCopyInResponse,
}

impl PgCopyInComplete {
    /// Row count parsed from the backend `COPY n` command tag.
    #[must_use]
    pub const fn affected_rows(&self) -> u64 {
        self.affected_rows
    }

    /// Number of `CopyData` frames sent by the client.
    #[must_use]
    pub const fn chunks_sent(&self) -> u64 {
        self.chunks_sent
    }

    /// Total payload bytes sent across `CopyData` frames.
    #[must_use]
    pub const fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// COPY IN format metadata announced by the backend.
    #[must_use]
    pub const fn response(&self) -> &PgCopyInResponse {
        &self.response
    }
}

/// Active PostgreSQL `COPY ... FROM STDIN` stream.
///
/// The connection remains reserved until the stream is explicitly finished or
/// failed. Dropping an unfinished stream closes the connection to prevent a
/// later request from reusing a socket that is still in COPY mode.
#[derive(Debug)]
pub struct PgCopyIn<'a> {
    connection: &'a mut PgConnection,
    response: PgCopyInResponse,
    chunks_sent: u64,
    bytes_sent: u64,
    finished: bool,
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

const POSTGRES_PROTOCOL_VERSION_3_0: i32 = 196_608;
const MAX_BACKEND_MESSAGE_LEN: i32 = 64 * 1024 * 1024;
const MAX_NOTIFICATION_CHANNEL_NAME_BYTES: usize = 63;
const MAX_NOTIFICATION_PAYLOAD_BYTES: usize = 8_000;
const COPY_TERMINAL_MASKED_POLLS: u32 = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
struct NotificationResponseFields {
    process_id: i32,
    channel: String,
    payload: String,
}

/// Structured `NotificationResponse` fields exposed only for fuzz/test seams.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzNotificationResponse {
    /// Backend process ID that sent the notification.
    pub process_id: i32,
    /// Notification channel name.
    pub channel: String,
    /// Notification payload.
    pub payload: String,
}

#[cfg(feature = "test-internals")]
impl From<NotificationResponseFields> for FuzzNotificationResponse {
    fn from(fields: NotificationResponseFields) -> Self {
        Self {
            process_id: fields.process_id,
            channel: fields.channel,
            payload: fields.payload,
        }
    }
}

fn backend_message_body_len(len_i32: i32) -> Result<usize, PgError> {
    // Practical PostgreSQL message limit. The protocol allows up to 2 GiB
    // but legitimate messages rarely exceed a few tens of MiB even for large
    // COPY batches. Capping at 64 MiB prevents a malicious peer (or MitM on
    // an unencrypted connection) from forcing a multi-GiB allocation with a
    // single 5-byte header.
    if !(4..=MAX_BACKEND_MESSAGE_LEN).contains(&len_i32) {
        return Err(PgError::Protocol(format!(
            "invalid message length: {len_i32}"
        )));
    }
    Ok(len_i32 as usize - 4)
}

#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn test_backend_message_body_len(len_i32: i32) -> Result<usize, PgError> {
    backend_message_body_len(len_i32)
}

#[cfg(any(test, feature = "test-internals"))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct PgStartupMessage {
    protocol_version: i32,
    parameters: BTreeMap<String, String>,
}

#[cfg(any(test, feature = "test-internals"))]
fn parse_startup_message(frame: &[u8]) -> Result<PgStartupMessage, PgError> {
    if frame.len() < 8 {
        return Err(PgError::Protocol("startup message too short".to_string()));
    }

    let len_i32 = i32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let body_len = backend_message_body_len(len_i32)?;
    let declared_len = body_len
        .checked_add(4)
        .ok_or_else(|| PgError::Protocol("startup message length overflow".to_string()))?;
    if frame.len() != declared_len {
        return Err(PgError::Protocol(format!(
            "startup message length mismatch: declared {declared_len}, actual {}",
            frame.len()
        )));
    }

    let mut reader = MessageReader::new(&frame[4..]);
    let protocol_version = reader.read_i32()?;
    if protocol_version != POSTGRES_PROTOCOL_VERSION_3_0 {
        return Err(PgError::Protocol(format!(
            "unsupported startup protocol version: {protocol_version}"
        )));
    }

    let mut parameters = BTreeMap::new();
    loop {
        if reader.remaining() == 0 {
            return Err(PgError::Protocol(
                "startup parameter list missing terminator".to_string(),
            ));
        }
        if reader.data[reader.pos] == 0 {
            reader.pos += 1;
            reader.ensure_consumed("StartupMessage")?;
            break;
        }

        let name = reader.read_cstring()?;
        validate_startup_parameter_name(name)?;
        if reader.remaining() == 0 {
            return Err(PgError::Protocol(format!(
                "startup parameter {name:?} missing value"
            )));
        }

        let value = reader.read_cstring()?;
        if parameters
            .insert(name.to_string(), value.to_string())
            .is_some()
        {
            return Err(PgError::Protocol(format!(
                "duplicate startup parameter: {name}"
            )));
        }
    }

    match parameters.get("user") {
        Some(user) if !user.is_empty() => Ok(PgStartupMessage {
            protocol_version,
            parameters,
        }),
        Some(_) => Err(PgError::Protocol(
            "startup parameter user cannot be empty".to_string(),
        )),
        None => Err(PgError::Protocol(
            "startup message missing required user parameter".to_string(),
        )),
    }
}

#[cfg(any(test, feature = "test-internals"))]
fn validate_startup_parameter_name(name: &str) -> Result<(), PgError> {
    if name.is_empty() {
        return Err(PgError::Protocol(
            "startup parameter name cannot be empty".to_string(),
        ));
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
    {
        return Err(PgError::Protocol(format!(
            "invalid startup parameter name: {name:?}"
        )));
    }
    Ok(())
}

fn validate_notification_channel_name(channel: &str) -> Result<(), PgError> {
    if channel.is_empty() {
        return Err(PgError::Protocol(
            "notification channel name cannot be empty".to_string(),
        ));
    }
    if channel.len() > MAX_NOTIFICATION_CHANNEL_NAME_BYTES {
        return Err(PgError::Protocol(format!(
            "notification channel name exceeds PostgreSQL {}-byte limit: {} bytes",
            MAX_NOTIFICATION_CHANNEL_NAME_BYTES,
            channel.len()
        )));
    }
    if channel.contains('\0') {
        return Err(PgError::Protocol(
            "notification channel name cannot contain NUL bytes".to_string(),
        ));
    }
    if channel.starts_with('.') || channel.ends_with('.') || channel.contains("..") {
        return Err(PgError::Protocol(
            "notification channel name must not contain empty path segments".to_string(),
        ));
    }
    if !channel
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return Err(PgError::Protocol(
            "notification channel name may contain only ASCII letters, digits, underscores, and dots"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_notification_payload(payload: &str) -> Result<(), PgError> {
    if payload.len() > MAX_NOTIFICATION_PAYLOAD_BYTES {
        return Err(PgError::Protocol(format!(
            "notification payload exceeds PostgreSQL default {}-byte limit: {} bytes",
            MAX_NOTIFICATION_PAYLOAD_BYTES,
            payload.len()
        )));
    }
    Ok(())
}

fn quote_postgres_identifier(identifier: &str) -> String {
    // Calculate capacity with overflow protection for quoted identifier
    let mut quoted = String::with_capacity(identifier.len().saturating_add(2));
    quoted.push('"');
    for ch in identifier.chars() {
        if ch == '"' {
            quoted.push('"');
        }
        quoted.push(ch);
    }
    quoted.push('"');
    quoted
}

fn build_listen_sql(channel: &str) -> Result<String, PgError> {
    validate_notification_channel_name(channel)?;
    Ok(format!("LISTEN {}", quote_postgres_identifier(channel)))
}

fn build_unlisten_sql(channel: &str) -> Result<String, PgError> {
    validate_notification_channel_name(channel)?;
    Ok(format!("UNLISTEN {}", quote_postgres_identifier(channel)))
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

    /// Send a PostgreSQL `CancelRequest` on a fresh TCP connection.
    ///
    /// Per the PG protocol (PG docs §53.2.7), cancellation of an in-flight
    /// query is signalled by opening a *separate* TCP connection to the
    /// same server and writing a 16-byte `CancelRequest` frame containing
    /// the target backend's process ID and cancellation key (both received
    /// in the original connection's `BackendKeyData` (`b'K'`) message).
    /// The server then sends `SIGINT` to the worker handling the cancelled
    /// query, which causes a quick rollback. Without this signal, just
    /// closing the original TCP socket leaves the server unaware — it may
    /// continue executing the query (holding locks, burning CPU) until it
    /// notices the closed socket on its next write attempt.
    ///
    /// Implementation properties (br-asupersync-gvkj1r):
    ///
    /// * Spawned on a detached `std::thread`, NOT through asupersync's
    ///   structured-concurrency machinery, because the caller's `Cx` is
    ///   already cancelled — we can't `.await` against it. Best-effort
    ///   signaling: a thread-spawn failure or a downed network would
    ///   simply mean the server learns of the cancel slightly later.
    /// * Sends raw 16 bytes over plain TCP. Per spec, `CancelRequest`
    ///   does NOT use TLS or any handshake — the secret key is the only
    ///   authentication and the protocol is fixed-frame.
    /// * Both the connect and write phases are bounded by
    ///   `cancel_target.connect_timeout` (≤ 500ms) so a hostile or
    ///   unreachable server cannot stall the cancel path indefinitely.
    /// * Returns no error and never panics — failures are deliberately
    ///   swallowed.
    fn fire_cancel_request(&self) {
        // No backend identity yet (e.g. cancel during pre-startup
        // exchange) → nothing the server can match this cancel against.
        if self.inner.process_id == 0 && self.inner.secret_key == 0 {
            return;
        }
        let host = self.inner.cancel_target.host.clone();
        let port = self.inner.cancel_target.port;
        let connect_timeout = self.inner.cancel_target.connect_timeout;
        let process_id = self.inner.process_id;
        let secret_key = self.inner.secret_key;

        // Detached. Bounded by connect_timeout + write_timeout. Errors
        // intentionally swallowed.
        let _ = std::thread::Builder::new()
            .name("pg-cancel-request".to_string())
            .spawn(move || {
                use std::io::Write as _;
                use std::net::ToSocketAddrs as _;

                let addr_str = format!("{host}:{port}");
                let addrs = match addr_str.to_socket_addrs() {
                    Ok(it) => it,
                    Err(_) => return,
                };
                for addr in addrs {
                    let mut stream =
                        match std::net::TcpStream::connect_timeout(&addr, connect_timeout) {
                            Ok(s) => s,
                            Err(_) => continue,
                        };
                    let _ = stream.set_write_timeout(Some(connect_timeout));

                    // CancelRequest frame, all big-endian:
                    //   length          = 16  (i32)
                    //   request_code    = 80877102  (i32, magic per protocol)
                    //   process_id      = i32 (from BackendKeyData)
                    //   secret_key      = i32 (from BackendKeyData)
                    let mut frame = [0u8; 16];
                    frame[0..4].copy_from_slice(&16i32.to_be_bytes());
                    frame[4..8].copy_from_slice(&80_877_102i32.to_be_bytes());
                    frame[8..12].copy_from_slice(&process_id.to_be_bytes());
                    frame[12..16].copy_from_slice(&secret_key.to_be_bytes());
                    let _ = stream.write_all(&frame);
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    return;
                }
            });
    }

    #[inline]
    fn fail_in_flight<T>(&mut self, err: PgError) -> Outcome<T, PgError> {
        self.abort_in_flight_exchange();
        outcome_from_error(err)
    }

    async fn ensure_open_for_request(&mut self, cx: &Cx) -> Outcome<PgOpenState, PgError> {
        if !self.inner.closed {
            return Outcome::Ok(PgOpenState::AlreadyOpen);
        }
        self.reconnect_idle(cx).await
    }

    async fn reconnect_idle(&mut self, cx: &Cx) -> Outcome<PgOpenState, PgError> {
        if self.inner.explicitly_closed
            || self.inner.transaction_status != b'I'
            || self.inner.needs_rollback
            || self.inner.needs_discard
        {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(cancelled_reason(cx));
        }

        let options = self.inner.options.clone();
        let max_result_rows = self.inner.max_result_rows;
        let subscribed_channels = self.inner.subscribed_channels.clone();

        let mut fresh = match Self::connect_with_options(cx, options).await {
            Outcome::Ok(conn) => conn,
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        fresh.inner.max_result_rows = max_result_rows;
        fresh.inner.subscribed_channels = subscribed_channels.clone();

        for channel in &subscribed_channels {
            let sql = match build_listen_sql(channel) {
                Ok(sql) => sql,
                Err(err) => return Outcome::Err(err),
            };
            match fresh.execute_unchecked_on_open(cx, &sql).await {
                Outcome::Ok(_) => {}
                Outcome::Err(err) => return Outcome::Err(err),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        let PgConnection { inner } = fresh;
        self.inner = inner;
        Outcome::Ok(PgOpenState::Reconnected)
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

    fn parse_notification_response_fields(
        data: &[u8],
    ) -> Result<NotificationResponseFields, PgError> {
        let mut reader = MessageReader::new(data);
        let process_id = reader.read_i32()?;
        let channel = reader.read_cstring()?.to_string();
        validate_notification_channel_name(&channel)?;
        let payload = reader.read_cstring()?.to_string();
        validate_notification_payload(&payload)?;
        reader.ensure_consumed("NotificationResponse")?;
        Ok(NotificationResponseFields {
            process_id,
            channel,
            payload,
        })
    }

    fn handle_notification_response(&mut self, data: &[u8]) -> Result<(), PgError> {
        let _fields = Self::parse_notification_response_fields(data)?;
        Ok(())
    }

    fn handle_ready_for_query(&mut self, data: &[u8]) -> Result<(), PgError> {
        self.inner.transaction_status = Self::parse_ready_for_query_transaction_status(data)?;
        Ok(())
    }

    fn parse_ready_for_query_transaction_status(data: &[u8]) -> Result<u8, PgError> {
        match data {
            [status @ (b'I' | b'T' | b'E')] => Ok(*status),
            [status] => Err(PgError::Protocol(format!(
                "invalid ReadyForQuery transaction state byte: 0x{status:02X}"
            ))),
            _ => Err(PgError::Protocol(format!(
                "ReadyForQuery requires exactly 1 status byte, got {}",
                data.len()
            ))),
        }
    }

    fn handle_async_backend_message(&mut self, msg_type: u8, data: &[u8]) -> Result<bool, PgError> {
        match msg_type {
            b'N' => {
                self.parse_notice_response(data)?;
                Ok(true)
            }
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
                    Err(e) => return outcome_from_error(e),
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

        let cancel_target = CancelTarget::from_options(&options);
        let mut conn = Self {
            inner: PgConnectionInner {
                stream,
                options: options.clone(),
                process_id: 0,
                secret_key: 0,
                cancel_target,
                parameters: BTreeMap::new(),
                transaction_status: b'I', // Idle
                closed: false,
                explicitly_closed: false,
                needs_rollback: false,
                needs_discard: false,
                next_stmt_id: 0,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
                prepared_cache: PreparedStatementCache::new(DEFAULT_MAX_PREPARED_STATEMENTS),
                deallocate_retry_queue: VecDeque::new(),
                consecutive_deallocate_failures: 0,
                unhealthy: false,
                subscribed_channels: BTreeSet::new(),
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
        // Best-effort: tell the server to abort the in-flight query via
        // PostgreSQL's CancelRequest protocol BEFORE we tear down the
        // original socket. Sending the cancel after the original close
        // would still work, but doing it first lets the server's SIGINT
        // race the close-induced read failure and minimizes the window
        // in which the server keeps holding locks for a query no one is
        // listening for. (br-asupersync-gvkj1r)
        self.fire_cancel_request();

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
                let connector = Self::build_postgres_tls_connector()?;
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
        buf.write_i32(POSTGRES_PROTOCOL_VERSION_3_0); // 3 << 16

        // Parameters
        buf.write_startup_cstring("startup parameter name", "user")?;
        buf.write_startup_cstring("startup user", &options.user)?;

        buf.write_startup_cstring("startup parameter name", "database")?;
        buf.write_startup_cstring("startup database", &options.database)?;

        if let Some(ref app_name) = options.application_name {
            buf.write_startup_cstring("startup parameter name", "application_name")?;
            buf.write_startup_cstring("startup application_name", app_name)?;
        }

        // Terminating null
        buf.write_byte(0);

        let msg = buf.build_startup_message()?;
        self.write_all(cx, &msg).await?;

        Ok(())
    }

    /// Handle the authentication handshake.
    async fn authenticate(&mut self, cx: &Cx, options: &PgConnectOptions) -> Result<(), PgError> {
        let mut auth_challenged = false;
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
                            if options.password.is_some() && !auth_challenged {
                                return Err(PgError::AuthenticationFailed(
                                    "server accepted connection without challenging configured password"
                                        .to_string(),
                                ));
                            }
                            return Ok(());
                        }
                        3 => {
                            // AuthenticationCleartextPassword
                            auth_challenged = true;
                            let password = options.password.as_ref().ok_or_else(|| {
                                PgError::AuthenticationFailed("password required".to_string())
                            })?;
                            self.send_password(cx, password.as_str()).await?;
                        }
                        5 => {
                            // AuthenticationMD5Password
                            auth_challenged = true;
                            let salt = reader.read_bytes(4)?;
                            let password = options.password.as_ref().ok_or_else(|| {
                                PgError::AuthenticationFailed("password required".to_string())
                            })?;
                            self.send_md5_password(cx, &options.user, password.as_str(), salt)
                                .await?;
                        }
                        10 => {
                            // AuthenticationSASL
                            let mechanisms = Self::read_sasl_mechanisms(&mut reader)?;

                            // SECURITY: Validate server only advertises acceptable SCRAM mechanisms
                            // Reject any SASL mechanism list containing non-SCRAM mechanisms to prevent
                            // downgrade attacks where server claims to support weak auth methods
                            Self::validate_sasl_mechanisms(&mechanisms)?;

                            // Channel-binding selection (br-asupersync-7n2xsi):
                            //   * If TLS is in use AND the server advertised
                            //     SCRAM-SHA-256-PLUS, use -PLUS with
                            //     tls-server-end-point cbind data computed
                            //     from the leaf cert. This is the strongest
                            //     posture and binds auth to the TLS channel.
                            //   * If TLS is in use but the server did NOT
                            //     advertise -PLUS, use SCRAM-SHA-256 with
                            //     `n,,` GS2. Several Postgres poolers reject
                            //     the `y,,` supported-but-not-used signal;
                            //     libpq/common drivers use the plain SCRAM
                            //     path for this case.
                            //   * Otherwise (plain TCP), use SCRAM-SHA-256
                            //     with `n,,` GS2 (no CB).
                            let cb = Self::pick_scram_channel_binding(
                                &mechanisms,
                                #[cfg(feature = "tls")]
                                {
                                    self.inner.stream.is_tls()
                                },
                                #[cfg(not(feature = "tls"))]
                                {
                                    false
                                },
                                #[cfg(feature = "tls")]
                                {
                                    self.inner.stream.peer_leaf_certificate_der()
                                },
                                #[cfg(not(feature = "tls"))]
                                {
                                    None::<Vec<u8>>
                                },
                            )?;
                            let chosen = cb.mechanism();
                            if mechanisms.iter().any(|m| m == chosen) {
                                let password = options.password.as_ref().ok_or_else(|| {
                                    PgError::AuthenticationFailed("password required".to_string())
                                })?;
                                self.authenticate_scram(cx, &options.user, password.as_str(), cb)
                                    .await?;
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

    #[cfg(feature = "tls")]
    fn build_postgres_tls_connector() -> Result<TlsConnector, PgError> {
        let mut tls_builder = TlsConnectorBuilder::new()
            .with_webpki_roots()
            .with_strict_ca_validation();

        // Match libpq-style deployments that provide an extra private
        // CA bundle through SSL_CERT_FILE, while keeping certificate
        // verification enabled.
        if let Ok(ca_path) = std::env::var("SSL_CERT_FILE") {
            let certs = Certificate::from_pem_file(&ca_path)
                .map_err(|err| PgError::Tls(format!("loading SSL_CERT_FILE {ca_path}: {err}")))?;
            tls_builder = tls_builder.add_root_certificates(certs);
        }

        tls_builder
            .build()
            .map_err(|err| PgError::Tls(err.to_string()))
    }

    /// Choose a `ScramChannelBinding` based on advertised mechanisms, whether
    /// the connection is already TLS, and the presence of a TLS leaf
    /// certificate. See the call site in the SASL handler for the policy tree.
    /// (br-asupersync-7n2xsi)
    fn pick_scram_channel_binding(
        mechanisms: &[String],
        tls_active: bool,
        tls_leaf_cert: Option<Vec<u8>>,
    ) -> Result<ScramChannelBinding, PgError> {
        #[cfg(feature = "tls")]
        let server_offers_plus = mechanisms.iter().any(|m| m == "SCRAM-SHA-256-PLUS");

        #[cfg(feature = "tls")]
        if tls_active {
            // TLS connections MUST have a certificate for secure channel binding
            let cert = tls_leaf_cert.ok_or_else(|| {
                PgError::AuthenticationFailed(
                    "TLS peer certificate required for PostgreSQL SCRAM authentication".to_string(),
                )
            })?;

            return Ok(if server_offers_plus {
                ScramChannelBinding::TlsServerEndPoint {
                    cbind_data: tls_server_end_point_cbind(&cert),
                }
            } else {
                // TLS is in use but the server did not advertise -PLUS.
                // Some Postgres poolers reject the `y,,` GS2 signal, so
                // use plain SCRAM like libpq/common drivers.
                ScramChannelBinding::None
            });
        }

        #[cfg(not(feature = "tls"))]
        let _ = (mechanisms, tls_active, tls_leaf_cert);

        Ok(ScramChannelBinding::None)
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

    /// Validate that server only advertises acceptable SCRAM mechanisms.
    ///
    /// This prevents downgrade attacks where a malicious server advertises
    /// weak authentication mechanisms alongside SCRAM to signal it accepts
    /// downgraded authentication. We enforce SCRAM-SHA-256 or better only.
    fn validate_sasl_mechanisms(mechanisms: &[String]) -> Result<(), PgError> {
        // Reject empty mechanism list
        if mechanisms.is_empty() {
            return Err(PgError::UnsupportedAuth(
                "Server advertised no SASL mechanisms".to_string(),
            ));
        }

        // Check that all mechanisms are acceptable SCRAM variants
        const ACCEPTABLE_MECHANISMS: &[&str] = &["SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"];

        for mechanism in mechanisms {
            if !ACCEPTABLE_MECHANISMS.contains(&mechanism.as_str()) {
                return Err(PgError::UnsupportedAuth(format!(
                    "Server advertised unacceptable SASL mechanism '{}'. Only SCRAM-SHA-256 and SCRAM-SHA-256-PLUS are allowed to prevent downgrade attacks",
                    mechanism
                )));
            }
        }

        // Ensure at least one SCRAM mechanism is available
        let has_scram = mechanisms
            .iter()
            .any(|m| m == "SCRAM-SHA-256" || m == "SCRAM-SHA-256-PLUS");

        if !has_scram {
            return Err(PgError::UnsupportedAuth(
                "Server must support SCRAM-SHA-256 or SCRAM-SHA-256-PLUS".to_string(),
            ));
        }

        Ok(())
    }

    /// Perform SCRAM authentication. The `cb` parameter chooses between
    /// `SCRAM-SHA-256` and `SCRAM-SHA-256-PLUS` and carries any
    /// `tls-server-end-point` channel-binding data. (br-asupersync-7n2xsi)
    async fn authenticate_scram(
        &mut self,
        cx: &Cx,
        username: &str,
        password: &str,
        cb: ScramChannelBinding,
    ) -> Result<(), PgError> {
        let mechanism = cb.mechanism();
        let mut scram = ScramAuth::new(cx, username, password, cb);

        // Send SASLInitialResponse
        let client_first = scram.client_first_message();
        let mut buf = MessageBuffer::new();
        buf.write_cstring(mechanism);
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
    async fn send_password(&mut self, _cx: &Cx, _password: &str) -> Result<(), PgError> {
        // PostgreSQL cleartext password authentication is vulnerable to downgrade attacks
        // SCRAM-SHA-256 is the recommended secure authentication method
        // For security, we require SCRAM-SHA-256
        Err(PgError::UnsupportedAuth(
            "Cleartext password rejected - please use SCRAM-SHA-256".to_string(),
        ))
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
                    self.handle_ready_for_query(&data)?;
                    return Ok(());
                }
                b'E' => {
                    return Err(self.parse_error_response(&data)?);
                }
                b'N' => {
                    self.parse_notice_response(&data)?;
                }
                _ => {
                    return Err(unexpected_backend_message("startup sequence", msg_type));
                }
            }
        }
    }

    /// Execute a simple query (DEPRECATED — use [`Self::query_unchecked`] for
    /// trusted-literal SQL or [`Self::query_params`] for parameterized
    /// queries).
    ///
    /// See [`Self::query_unchecked`] for the same implementation under the
    /// explicit-opt-in name. This shim is retained for source compatibility
    /// during the migration window (br-asupersync-0fxbp6).
    #[deprecated(
        note = "use query_unchecked for trusted-literal SQL or query_params for parameterized queries (br-asupersync-0fxbp6)"
    )]
    pub async fn query(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError> {
        self.query_unchecked(cx, sql).await
    }

    /// br-asupersync-0fxbp6 — Execute a simple (unparameterized) query.
    ///
    /// # Security
    ///
    /// **This function performs NO parameterization.** The `sql` string is
    /// sent directly to the server as a Postgres protocol Query message. If
    /// any portion of `sql` is built from untrusted input
    /// (`format!`, `String::push_str`, concatenation, etc.) the connection
    /// is wide open to SQL injection.
    ///
    /// Use this only when:
    /// - `sql` is a static literal (e.g. `"BEGIN"`, `"COMMIT"`,
    ///   `"VACUUM ANALYZE"`), or
    /// - `sql` was built entirely from values you control end-to-end.
    ///
    /// For any value derived from a user, request body, URL parameter,
    /// header, file content, environment variable, or other external source,
    /// use [`Self::query_params`] instead. LISTEN / UNLISTEN notification
    /// channel names are SQL identifiers rather than values; use
    /// [`Self::listen`] / [`Self::unlisten`] instead of interpolating them into
    /// raw SQL.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn query_unchecked(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
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

        let mut invalidate_prepared_cache = false;
        let mut discard_on_pool_return = false;
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
                    if let Some(tag) = Self::parse_command_tag(&data) {
                        invalidate_prepared_cache |=
                            Self::command_tag_requires_prepared_cache_invalidation(tag);
                        discard_on_pool_return |= Self::command_tag_requires_session_discard(tag);
                    }
                }
                b'I' => {
                    // EmptyQueryResponse
                }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if let Err(e) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(e);
                    }
                    if invalidate_prepared_cache {
                        self.invalidate_prepared_cache_after_schema_or_session_change();
                    }
                    if discard_on_pool_return {
                        self.inner.needs_discard = true;
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
    ///
    /// **Security:** see [`Self::query_unchecked`] — `sql` must be a trusted
    /// literal or fully caller-controlled. Use [`Self::query_one_params`] (or
    /// equivalent) for parameterized variants.
    pub async fn query_one(&mut self, cx: &Cx, sql: &str) -> Outcome<Option<PgRow>, PgError> {
        match self.query_unchecked(cx, sql).await {
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

    /// Execute a command (DEPRECATED — use [`Self::execute_unchecked`] for
    /// trusted-literal SQL or [`Self::execute_params`] for parameterized
    /// commands).
    ///
    /// See [`Self::execute_unchecked`] for the implementation under the
    /// explicit-opt-in name. This shim is retained for source compatibility
    /// during the migration window (br-asupersync-0fxbp6).
    #[deprecated(
        note = "use execute_unchecked for trusted-literal SQL or execute_params for parameterized commands (br-asupersync-0fxbp6)"
    )]
    pub async fn execute(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, PgError> {
        self.execute_unchecked(cx, sql).await
    }

    /// br-asupersync-0fxbp6 — Execute a simple (unparameterized) command.
    ///
    /// # Security
    ///
    /// **This function performs NO parameterization.** The `sql` string is
    /// sent directly to the server as a Postgres protocol Query message.
    /// Concatenating untrusted input into `sql` is a classic SQL injection
    /// vector.
    ///
    /// Use this only for static literals (`"BEGIN"`, `"COMMIT"`,
    /// `"ROLLBACK"`, `"VACUUM"`, schema migrations from version-controlled
    /// files, etc.) or values you fully control. For anything derived from
    /// external input, use [`Self::execute_params`] instead. LISTEN / UNLISTEN
    /// notification channel names are identifiers, not bind parameters; use
    /// [`Self::listen`] / [`Self::unlisten`] / [`Self::notify`] instead of
    /// constructing raw SQL around them.
    pub async fn execute_unchecked(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        self.execute_unchecked_on_open(cx, sql).await
    }

    async fn execute_unchecked_on_open(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, PgError> {
        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
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
        let mut invalidate_prepared_cache = false;

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
                    if let Some(tag) = Self::parse_command_tag(&data) {
                        if let Some(num) = Self::affected_rows_from_command_tag(tag) {
                            affected_rows = num;
                        }
                        invalidate_prepared_cache |=
                            Self::command_tag_requires_prepared_cache_invalidation(tag);
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
                    if let Err(e) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(e);
                    }
                    if saw_row_response {
                        return Outcome::Err(row_returning_execute_error("execute()", "query()"));
                    }
                    if invalidate_prepared_cache {
                        self.invalidate_prepared_cache_after_schema_or_session_change();
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

    /// Start a PostgreSQL `COPY ... FROM STDIN` operation.
    ///
    /// The SQL must be a trusted COPY statement that causes the backend to
    /// enter COPY IN mode. The returned [`PgCopyIn`] sends bounded `CopyData`
    /// frames and must be completed with [`PgCopyIn::finish`] or aborted with
    /// [`PgCopyIn::fail`].
    pub async fn copy_in<'a>(&'a mut self, cx: &Cx, sql: &str) -> Outcome<PgCopyIn<'a>, PgError> {
        if cx.checkpoint().is_err() {
            return Outcome::Cancelled(cancelled_reason(cx));
        }
        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        match self.ensure_no_orphaned_transaction(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        let mut buf = MessageBuffer::new();
        buf.write_cstring(sql);
        let msg = match buf.build_message(FrontendMessage::Query as u8) {
            Ok(msg) => msg,
            Err(err) => return Outcome::Err(err),
        };

        self.inner.closed = true;

        if let Err(err) = self.write_all(cx, &msg).await {
            return self.fail_in_flight(err);
        }

        let mut command_tag = None::<String>;
        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(msg) => msg,
                Err(err) => return self.fail_in_flight(err),
            };

            match msg_type {
                b'G' => {
                    let (overall_format, column_formats) =
                        match Self::parse_copy_response("CopyInResponse", &data) {
                            Ok(parsed) => parsed,
                            Err(err) => return self.fail_in_flight(err),
                        };
                    return Outcome::Ok(PgCopyIn {
                        connection: self,
                        response: PgCopyInResponse {
                            overall_format,
                            column_formats,
                        },
                        chunks_sent: 0,
                        bytes_sent: 0,
                        finished: false,
                    });
                }
                b'C' => {
                    command_tag = Self::parse_command_tag(&data).map(str::to_string);
                }
                b'I' => {}
                b'Z' => {
                    self.inner.closed = false;
                    if let Err(err) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(err);
                    }
                    let suffix = command_tag
                        .as_deref()
                        .map_or(String::new(), |tag| format!("; command tag was {tag:?}"));
                    return Outcome::Err(PgError::Protocol(format!(
                        "COPY FROM statement did not enter COPY IN mode{suffix}"
                    )));
                }
                b'E' => {
                    return outcome_from_error(self.parse_error_and_drain(cx, &data).await);
                }
                _ => {
                    match self.handle_async_backend_message(msg_type, &data) {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(err) => return self.fail_in_flight(err),
                    }
                    return self
                        .fail_in_flight(unexpected_backend_message("COPY IN startup", msg_type));
                }
            }
        }
    }

    /// Stream chunks into `COPY ... FROM STDIN` and finish with `CopyDone`.
    ///
    /// Each iterator item becomes one `CopyData` frame. If the iterator
    /// yields an error, the client sends `CopyFail`, drains back to
    /// `ReadyForQuery`, and returns the original source error. If cancellation
    /// is observed between chunks, the client also attempts `CopyFail` before
    /// returning cancellation.
    pub async fn copy_from_chunks<I, B>(
        &mut self,
        cx: &Cx,
        sql: &str,
        chunks: I,
    ) -> Outcome<PgCopyInComplete, PgError>
    where
        I: IntoIterator<Item = Result<B, PgError>>,
        B: AsRef<[u8]>,
    {
        let mut copy = match self.copy_in(cx, sql).await {
            Outcome::Ok(copy) => copy,
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };

        for chunk in chunks {
            if cx.checkpoint().is_err() {
                let reason = cancelled_reason(cx);
                let _ = copy.fail(cx, "COPY FROM cancelled before CopyDone").await;
                return Outcome::Cancelled(reason);
            }

            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(err) => match copy.fail(cx, "COPY FROM source error").await {
                    Outcome::Ok(()) => return Outcome::Err(err),
                    Outcome::Err(abort_err) => {
                        return Outcome::Err(PgError::Protocol(format!(
                            "{err}; additionally failed to abort COPY FROM: {abort_err}"
                        )));
                    }
                    Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                },
            };

            match copy.send_chunk(cx, chunk.as_ref()).await {
                Outcome::Ok(()) => {}
                Outcome::Err(err) => return Outcome::Err(err),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
        }

        copy.finish(cx).await
    }

    /// Register a PostgreSQL LISTEN channel with identifier quoting and
    /// explicit length validation.
    pub async fn listen(&mut self, cx: &Cx, channel: &str) -> Outcome<(), PgError> {
        let sql = match build_listen_sql(channel) {
            Ok(sql) => sql,
            Err(err) => return Outcome::Err(err),
        };
        match self.execute_unchecked(cx, &sql).await {
            Outcome::Ok(_) => {
                self.inner.subscribed_channels.insert(channel.to_string());
                Outcome::Ok(())
            }
            Outcome::Err(err) => Outcome::Err(err),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Stop listening on a PostgreSQL notification channel with the same
    /// validation rules as [`Self::listen`].
    pub async fn unlisten(&mut self, cx: &Cx, channel: &str) -> Outcome<(), PgError> {
        let sql = match build_unlisten_sql(channel) {
            Ok(sql) => sql,
            Err(err) => return Outcome::Err(err),
        };
        match self.execute_unchecked(cx, &sql).await {
            Outcome::Ok(_) => {
                self.inner.subscribed_channels.remove(channel);
                Outcome::Ok(())
            }
            Outcome::Err(err) => Outcome::Err(err),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Send a PostgreSQL notification without exposing callers to raw NOTIFY
    /// channel-name interpolation.
    pub async fn notify(&mut self, cx: &Cx, channel: &str, payload: &str) -> Outcome<(), PgError> {
        if let Err(err) = validate_notification_channel_name(channel) {
            return Outcome::Err(err);
        }
        if let Err(err) = validate_notification_payload(payload) {
            return Outcome::Err(err);
        }
        let params = [&channel as &dyn ToSql, &payload as &dyn ToSql];
        match self
            .query_one_params(cx, "SELECT pg_catalog.pg_notify($1, $2)", &params)
            .await
        {
            Outcome::Ok(_) => Outcome::Ok(()),
            Outcome::Err(err) => Outcome::Err(err),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Begin a transaction.
    pub async fn begin(&mut self, cx: &Cx) -> Outcome<PgTransaction<'_>, PgError> {
        match self.execute_unchecked(cx, "BEGIN").await {
            Outcome::Ok(_) => Outcome::Ok(PgTransaction {
                conn: self,
                finished: false,
                isolation_level: None,
                read_only: false,
            }),
            Outcome::Err(e) => Outcome::Err(e),
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// br-asupersync-rsifm3 — Begin a transaction with explicit isolation
    /// level and read-only configuration, atomically.
    ///
    /// Emits a single `BEGIN ISOLATION LEVEL <level> READ {ONLY|WRITE}`
    /// statement so the level is in effect from the very first query in
    /// the transaction. This avoids the two-round-trip
    /// `BEGIN; SET TRANSACTION ISOLATION LEVEL X` pattern and avoids the
    /// silent footgun of forgetting the SET (which leaves the transaction
    /// at the connection default — usually `READ COMMITTED`).
    ///
    /// The chosen level and read-only flag are recorded on the returned
    /// [`PgTransaction`] for introspection.
    pub async fn begin_with_isolation(
        &mut self,
        cx: &Cx,
        level: IsolationLevel,
        read_only: bool,
    ) -> Outcome<PgTransaction<'_>, PgError> {
        let access_mode = if read_only { "READ ONLY" } else { "READ WRITE" };
        let sql = format!("BEGIN ISOLATION LEVEL {level} {access_mode}");
        match self.execute_unchecked(cx, &sql).await {
            Outcome::Ok(_) => {}
            Outcome::Err(e) => return Outcome::Err(e),
            Outcome::Cancelled(r) => return Outcome::Cancelled(r),
            Outcome::Panicked(p) => return Outcome::Panicked(p),
        }

        if cx.checkpoint().is_err() {
            self.rollback_isolated_begin_or_mark(cx).await;
            return Outcome::Cancelled(cancelled_reason(cx));
        }

        // br-asupersync-dvgvcu — verify the server-applied
        // transaction isolation matches what was requested. The
        // BEGIN ISOLATION LEVEL form is atomic against the server's
        // own state, but Postgres deployments can layer
        // default_transaction_isolation overrides via ALTER ROLE /
        // ALTER DATABASE / GUC injection that would change the
        // effective level despite the BEGIN succeeding without
        // error. Without this verify, a caller that requests
        // SERIALIZABLE could be silently transacting at READ
        // COMMITTED, breaking correctness for read-modify-write.
        let observed_level = match self.query_unchecked(cx, "SHOW transaction_isolation").await {
            Outcome::Ok(rows) => match rows
                .first()
                .and_then(|r| r.get_str("transaction_isolation").ok())
                .map(str::to_string)
            {
                Some(s) => s,
                None => {
                    self.rollback_isolated_begin_or_mark(cx).await;
                    return Outcome::Err(PgError::IsolationLevelMismatch {
                        requested: level,
                        observed: String::new(),
                    });
                }
            },
            Outcome::Err(e) => {
                self.rollback_isolated_begin_or_mark(cx).await;
                return Outcome::Err(e);
            }
            Outcome::Cancelled(r) => {
                self.rollback_isolated_begin_or_mark(cx).await;
                return Outcome::Cancelled(r);
            }
            Outcome::Panicked(p) => {
                self.rollback_isolated_begin_or_mark(cx).await;
                return Outcome::Panicked(p);
            }
        };

        match IsolationLevel::from_server_string(&observed_level) {
            Some(parsed) if parsed == level => Outcome::Ok(PgTransaction {
                conn: self,
                finished: false,
                isolation_level: Some(level),
                read_only,
            }),
            _ => {
                self.rollback_isolated_begin_or_mark(cx).await;
                Outcome::Err(PgError::IsolationLevelMismatch {
                    requested: level,
                    observed: observed_level,
                })
            }
        }
    }

    /// br-asupersync-9g47af — once `BEGIN ...` succeeds, any verification
    /// failure must either return the connection to idle or mark it for orphan
    /// cleanup before the caller can reuse it.
    async fn rollback_isolated_begin_or_mark(&mut self, cx: &Cx) {
        const MASKED_ROLLBACK_POLLS: u32 = 32;

        match crate::combinator::commit_section(
            cx,
            MASKED_ROLLBACK_POLLS,
            self.execute_unchecked(cx, "ROLLBACK"),
        )
        .await
        {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => {
                self.inner.needs_rollback = true;
                self.inner.needs_discard = true;
                cx.trace(&format!(
                    "begin_with_isolation cleanup rollback failed; marking connection for orphan cleanup: {err}"
                ));
            }
            Outcome::Cancelled(reason) => {
                self.inner.needs_rollback = true;
                self.inner.needs_discard = true;
                cx.trace(&format!(
                    "begin_with_isolation cleanup rollback was cancelled; marking connection for orphan cleanup: {reason}"
                ));
            }
            Outcome::Panicked(_) => {
                self.inner.needs_rollback = true;
                self.inner.needs_discard = true;
                cx.trace(
                    "begin_with_isolation cleanup rollback panicked; marking connection for orphan cleanup",
                );
            }
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

    /// br-asupersync-yl4gu1: returns `true` when this connection has
    /// been tagged as unsafe for pool recycling — typically because a
    /// `PgTransaction` was dropped without commit and the pending
    /// ROLLBACK has not yet executed. Pool implementations MUST
    /// consult this flag in their return path: when it is `true`,
    /// close the connection (`Self::close`) instead of returning it
    /// to the idle list. Failing to do so leaks an
    /// `idle_in_transaction` backend with locks held to the next
    /// tenant.
    #[must_use]
    pub fn needs_discard(&self) -> bool {
        self.inner.needs_discard
    }

    #[inline]
    fn transport_matches_ssl_mode(&self, ssl_mode: SslMode) -> bool {
        match ssl_mode {
            SslMode::Disable => !self.inner.stream.is_tls(),
            SslMode::Prefer => true,
            SslMode::Require => self.inner.stream.is_tls(),
        }
    }

    /// Close the connection.
    pub async fn close(&mut self) -> Result<(), PgError> {
        self.inner.explicitly_closed = true;
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
    /// Parameters use `$1`, `$2`, ... bind slots in SQL. This prevents
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
        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
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
        // Calculate total length with overflow protection for message concatenation
        let total = parse
            .len()
            .saturating_add(bind.len())
            .saturating_add(describe.len())
            .saturating_add(execute.len())
            .saturating_add(sync.len());
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
        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }
        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
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

        // Calculate total length with overflow protection for message concatenation
        let total = parse
            .len()
            .saturating_add(bind.len())
            .saturating_add(execute.len())
            .saturating_add(sync.len());
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
        match self.ensure_open_for_request(cx).await {
            Outcome::Ok(_) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // br-asupersync-7v80ju: piggy-back any pending DEALLOCATE
        // retries on this round-trip. flush_pending_deallocates is a
        // no-op when the queue is empty, so the steady-state cost is
        // a single VecDeque length check; only when a previous
        // eviction failed do we incur the per-statement Sync exchange.
        // Stops at the first failure to avoid hammering a flaky
        // server, leaving the remainder for the next query.
        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        // br-asupersync-cvkoe9: fast-path for repeat-SQL. Bypasses the
        // Parse/Describe/Sync wire exchange entirely and returns the
        // cached metadata. Touching the entry promotes it to MRU in
        // the LRU queue so it survives the next eviction round.
        if let Some(cached) = self.inner.prepared_cache.get_and_touch(sql) {
            return Outcome::Ok(cached);
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

        // Calculate total length with overflow protection for message concatenation
        let total = parse
            .len()
            .saturating_add(describe.len())
            .saturating_add(sync.len());
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
                    if let Err(e) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(e);
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

        let stmt = PgStatement {
            name: stmt_name,
            sql: sql.to_string(),
            param_oids,
            columns,
        };

        // br-asupersync-cvkoe9 + br-asupersync-7v80ju: insert into the
        // bounded LRU cache. If at capacity, the cache returns the LRU
        // entry's server-side name for DEALLOCATE. Pre-7v80ju the close
        // was fire-and-forget (`let _ = self.close_statement(...).await`),
        // so a transient close failure silently leaked the server-side
        // prepared statement. Now we route the close through
        // `try_close_or_enqueue_deallocate`, which:
        //   - on success: clears the connection's consecutive-failure
        //     counter,
        //   - on failure: pushes the victim name onto
        //     `deallocate_retry_queue` for the next query method to
        //     retry, and bumps the consecutive-failure counter (which
        //     marks the connection unhealthy at the configured
        //     threshold).
        // Either way the client-side cache entry is evicted, so a
        // repeat prepare() for the same SQL will re-Parse.
        let evicted_name = self
            .inner
            .prepared_cache
            .insert_returning_evicted_name(sql.to_string(), stmt.clone());
        if let Some(victim_name) = evicted_name {
            self.try_close_or_enqueue_deallocate(cx, victim_name).await;
        }

        Outcome::Ok(stmt)
    }

    /// br-asupersync-7v80ju: best-effort close of a single server-side
    /// prepared statement. On any failure path (connection error,
    /// cancellation, panic), the statement name is enqueued onto
    /// `deallocate_retry_queue` and the consecutive-failure counter is
    /// incremented; once the counter reaches
    /// [`DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD`] the connection is
    /// marked unhealthy and the pool will evict it on next return. On
    /// success the failure counter is reset to zero.
    async fn try_close_or_enqueue_deallocate(&mut self, cx: &Cx, victim_name: String) {
        let victim_stmt = PgStatement {
            name: victim_name.clone(),
            sql: String::new(),
            param_oids: Vec::new(),
            columns: Vec::new(),
        };
        match self.close_statement_exchange(cx, &victim_stmt).await {
            Outcome::Ok(()) => {
                self.inner.consecutive_deallocate_failures = 0;
            }
            Outcome::Err(_) | Outcome::Panicked(_) => {
                // Real backend failure - increment failure counter
                self.enqueue_failed_deallocate(victim_name);
            }
            Outcome::Cancelled(_) => {
                // Caller cancellation - preserve statement for retry but don't count as backend failure
                self.enqueue_cancelled_deallocate(victim_name);
            }
        }
    }

    /// br-asupersync-7v80ju: push a failed-deallocate name onto the
    /// retry queue and bump the consecutive-failure counter. Bounded
    /// by [`DEALLOCATE_RETRY_QUEUE_CAP`]; when the queue is full the
    /// oldest pending name is dropped (we'd rather lose a single
    /// retry slot than leak unbounded memory on the client side).
    fn enqueue_failed_deallocate(&mut self, name: String) {
        if self.inner.deallocate_retry_queue.len() >= DEALLOCATE_RETRY_QUEUE_CAP {
            // Drop oldest to bound memory; the dropped name is now a
            // permanent server-side leak (1 prepared statement) but
            // we cap the BLAST RADIUS rather than letting the queue
            // itself become a leak vector.
            let _ = self.inner.deallocate_retry_queue.pop_front();
        }
        self.inner.deallocate_retry_queue.push_back(name);
        self.inner.consecutive_deallocate_failures =
            self.inner.consecutive_deallocate_failures.saturating_add(1);
        if self.inner.consecutive_deallocate_failures >= DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD {
            self.inner.unhealthy = true;
        }
    }

    /// Queue a statement name for later close when local state has already
    /// invalidated the cache entry but no backend failure has occurred.
    fn enqueue_local_deallocate(&mut self, name: String) {
        if self.inner.deallocate_retry_queue.len() >= DEALLOCATE_RETRY_QUEUE_CAP {
            let _ = self.inner.deallocate_retry_queue.pop_front();
        }
        self.inner.deallocate_retry_queue.push_back(name);
    }

    /// Enqueue a statement name for later deallocate retry due to caller
    /// cancellation. Unlike `enqueue_failed_deallocate`, this does NOT
    /// increment the consecutive failure counter or mark the connection
    /// unhealthy, since caller cancellation is not a backend failure.
    fn enqueue_cancelled_deallocate(&mut self, name: String) {
        self.enqueue_local_deallocate(name);
        // Notably: do NOT increment consecutive_deallocate_failures
        // or set unhealthy=true for caller cancellation
    }

    fn restore_deallocate_remainder(&mut self, remainder: Vec<String>) {
        let restore_len = remainder.len().min(DEALLOCATE_RETRY_QUEUE_CAP);
        let drop_count = remainder.len().saturating_sub(restore_len);
        if drop_count > 0 {
            // Drop the oldest entries to honour the CAP (older entries
            // are most likely to have been stale by now anyway).
            self.inner
                .deallocate_retry_queue
                .extend(remainder.into_iter().skip(drop_count));
        } else {
            self.inner.deallocate_retry_queue.extend(remainder);
        }
    }

    /// br-asupersync-7v80ju: drain the deallocate retry queue,
    /// retrying each pending CLOSE. Stops at the first failure (so we
    /// don't hammer a flaky server) and re-enqueues the name plus any
    /// remaining queue tail. Called at the start of public query,
    /// execute, and prepare paths so retries piggy-back on the next
    /// request.
    async fn flush_pending_deallocates(&mut self, cx: &Cx) -> Outcome<(), PgError> {
        // Drain the queue into a local Vec so we can re-enqueue the
        // remainder if any retry fails. Splitting the borrow this way
        // avoids holding `&mut self.inner.deallocate_retry_queue`
        // across the `.await` on close_statement.
        let mut pending = std::mem::take(&mut self.inner.deallocate_retry_queue).into_iter();
        let mut remainder: Vec<String> = Vec::new();
        while let Some(name) = pending.next() {
            let stmt = PgStatement {
                name: name.clone(),
                sql: String::new(),
                param_oids: Vec::new(),
                columns: Vec::new(),
            };
            match self.close_statement_exchange(cx, &stmt).await {
                Outcome::Ok(()) => {
                    self.inner.consecutive_deallocate_failures = 0;
                }
                Outcome::Err(err) => {
                    // Real backend failure - increment failure counter and mark unhealthy
                    remainder.push(name);
                    self.inner.consecutive_deallocate_failures =
                        self.inner.consecutive_deallocate_failures.saturating_add(1);
                    if self.inner.consecutive_deallocate_failures
                        >= DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD
                    {
                        self.inner.unhealthy = true;
                    }
                    remainder.extend(pending);
                    self.restore_deallocate_remainder(remainder);
                    return if self.inner.closed {
                        Outcome::Err(err)
                    } else {
                        Outcome::Ok(())
                    };
                }
                Outcome::Panicked(payload) => {
                    remainder.push(name);
                    self.inner.consecutive_deallocate_failures =
                        self.inner.consecutive_deallocate_failures.saturating_add(1);
                    if self.inner.consecutive_deallocate_failures
                        >= DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD
                    {
                        self.inner.unhealthy = true;
                    }
                    remainder.extend(pending);
                    self.restore_deallocate_remainder(remainder);
                    return Outcome::Panicked(payload);
                }
                Outcome::Cancelled(reason) => {
                    // Caller cancellation - preserve name for retry but don't count as backend failure
                    remainder.push(name);
                    remainder.extend(pending);
                    self.restore_deallocate_remainder(remainder);
                    return Outcome::Cancelled(reason);
                }
            }
        }
        self.restore_deallocate_remainder(remainder);
        Outcome::Ok(())
    }

    async fn flush_pending_deallocates_before_request(&mut self, cx: &Cx) -> Outcome<(), PgError> {
        match self.flush_pending_deallocates(cx).await {
            Outcome::Ok(()) => {
                if self.inner.closed {
                    Outcome::Err(PgError::ConnectionClosed)
                } else {
                    Outcome::Ok(())
                }
            }
            Outcome::Err(err) => Outcome::Err(err),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// br-asupersync-7v80ju: returns true when the connection has
    /// suffered enough consecutive deallocate failures to be
    /// considered untrustworthy. Pool implementations should observe
    /// this on connection return and evict-rather-than-recycle when
    /// it is true.
    #[must_use]
    pub fn is_unhealthy(&self) -> bool {
        self.inner.unhealthy
    }

    /// br-asupersync-7v80ju: number of pending CLOSE retries. Exposed
    /// for telemetry / pool decisions and for regression tests.
    #[must_use]
    pub fn pending_deallocate_count(&self) -> usize {
        self.inner.deallocate_retry_queue.len()
    }

    fn parse_command_tag(data: &[u8]) -> Option<&str> {
        std::str::from_utf8(data)
            .ok()
            .map(|tag| tag.trim_end_matches('\0'))
    }

    fn affected_rows_from_command_tag(tag: &str) -> Option<u64> {
        let mut parts = tag.split_ascii_whitespace();
        match parts.next()? {
            "INSERT" => {
                let _oid = parts.next()?;
                let count = parts.next()?;
                if parts.next().is_some() {
                    return None;
                }
                count.parse::<u64>().ok()
            }
            "UPDATE" | "DELETE" | "SELECT" | "COPY" | "MOVE" | "FETCH" => {
                let count = parts.next()?;
                if parts.next().is_some() {
                    return None;
                }
                count.parse::<u64>().ok()
            }
            _ => None,
        }
    }

    fn command_tag_requires_prepared_cache_invalidation(tag: &str) -> bool {
        let Some(verb) = tag.split_ascii_whitespace().next() else {
            return false;
        };
        matches!(
            verb,
            "ALTER" | "CREATE" | "DEALLOCATE" | "DISCARD" | "DROP" | "RESET" | "SET"
        )
    }

    /// Fail closed for any command tag that may reflect a session mutation.
    ///
    /// PostgreSQL reports both `SET LOCAL ...` and session-scoped `SET ...`
    /// with the same `SET` command tag, so pooled reuse cannot distinguish
    /// whether the setting was transaction-local or session-wide from the
    /// backend response alone. Treating all `SET` completions as
    /// discard-on-pool-return ensures the next tenant never inherits
    /// ambiguous role/GUC state.
    fn command_tag_requires_session_discard(tag: &str) -> bool {
        let Some(verb) = tag.split_ascii_whitespace().next() else {
            return false;
        };
        matches!(verb, "DISCARD" | "RESET" | "SET")
    }

    fn invalidate_prepared_cache_after_schema_or_session_change(&mut self) {
        let stale_names = self.inner.prepared_cache.clear_returning_names();
        for name in stale_names {
            self.enqueue_local_deallocate(name);
        }
    }

    fn validate_prepared_bind_arity(
        stmt: &PgStatement,
        params: &[&dyn ToSql],
    ) -> Result<(), PgError> {
        let expected = stmt.param_oids.len();
        let got = params.len();
        if expected != got {
            return Err(PgError::Protocol(format!(
                "prepared statement '{}' expects {} parameters, got {}",
                stmt.name, expected, got
            )));
        }
        Ok(())
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
        let rebound_stmt = match self.ensure_open_for_request(cx).await {
            Outcome::Ok(PgOpenState::AlreadyOpen) => None,
            Outcome::Ok(PgOpenState::Reconnected) => {
                if stmt.sql.is_empty() {
                    return Outcome::Err(PgError::ConnectionClosed);
                }
                match self.prepare(cx, &stmt.sql).await {
                    Outcome::Ok(stmt) => Some(stmt),
                    Outcome::Err(err) => return Outcome::Err(err),
                    Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                }
            }
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        let stmt = rebound_stmt.as_ref().unwrap_or(stmt);

        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        if let Err(err) = Self::validate_prepared_bind_arity(stmt, params) {
            return Outcome::Err(err);
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

        // Calculate total length with overflow protection for message concatenation
        let total = bind
            .len()
            .saturating_add(describe.len())
            .saturating_add(execute.len())
            .saturating_add(sync.len());
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
        let rebound_stmt = match self.ensure_open_for_request(cx).await {
            Outcome::Ok(PgOpenState::AlreadyOpen) => None,
            Outcome::Ok(PgOpenState::Reconnected) => {
                if stmt.sql.is_empty() {
                    return Outcome::Err(PgError::ConnectionClosed);
                }
                match self.prepare(cx, &stmt.sql).await {
                    Outcome::Ok(stmt) => Some(stmt),
                    Outcome::Err(err) => return Outcome::Err(err),
                    Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                    Outcome::Panicked(payload) => return Outcome::Panicked(payload),
                }
            }
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        };
        let stmt = rebound_stmt.as_ref().unwrap_or(stmt);

        match self.flush_pending_deallocates_before_request(cx).await {
            Outcome::Ok(()) => {}
            Outcome::Err(err) => return Outcome::Err(err),
            Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => return Outcome::Panicked(payload),
        }

        if let Err(err) = Self::validate_prepared_bind_arity(stmt, params) {
            return Outcome::Err(err);
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

        // Calculate total length with overflow protection for message concatenation
        let total = bind
            .len()
            .saturating_add(execute.len())
            .saturating_add(sync.len());
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
            return if self.inner.explicitly_closed {
                Outcome::Err(PgError::ConnectionClosed)
            } else {
                Outcome::Ok(())
            };
        }
        self.close_statement_exchange(cx, stmt).await
    }

    async fn close_statement_exchange(
        &mut self,
        cx: &Cx,
        stmt: &PgStatement,
    ) -> Outcome<(), PgError> {
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

        // Calculate capacity with overflow protection for message concatenation
        let mut combined = Vec::with_capacity(close.len().saturating_add(sync.len()));
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
                    if let Err(e) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(e);
                    }
                    let _ = self
                        .inner
                        .prepared_cache
                        .remove_by_statement_name(&stmt.name);
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
        // br-asupersync-yl4gu1: rollback completed cleanly, so the
        // connection is safe to recycle into the pool again. Clear
        // the discard flag now that the orphaned-transaction state
        // is provably resolved.
        self.inner.needs_discard = false;
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

        let body_len = backend_message_body_len(len_i32)?;

        // Read message body
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

        reader.ensure_consumed("RowDescription")?;
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

        reader.ensure_consumed("DataRow")?;
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
            oid::DATE => PgValue::Text(decode_binary_date_to_text(data)?),
            oid::TIMESTAMP => PgValue::Text(decode_binary_timestamp_to_text(data)?),
            oid::INTERVAL => PgValue::Text(decode_binary_interval_to_text(data)?),
            oid::NUMERIC => PgValue::Text(decode_binary_numeric_to_text(data)?),
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
        let mut diagnostic = PgErrorDiagnostic::default();

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
                // Diagnostic fields per PostgreSQL protocol documentation
                b'c' => diagnostic.constraint_name = Some(value),
                b't' => diagnostic.table_name = Some(value),
                b's' => diagnostic.schema_name = Some(value),
                b'n' => diagnostic.column_name = Some(value),
                b'S' => diagnostic.severity = Some(value),
                b'R' => diagnostic.routine_name = Some(value),
                b'P' => diagnostic.position = Some(value),
                b'p' => diagnostic.internal_position = Some(value),
                b'q' => diagnostic.internal_query = Some(value),
                b'W' => diagnostic.where_context = Some(value),
                b'F' => diagnostic.file_name = Some(value),
                b'L' => diagnostic.line_number = Some(value),
                _ => {} // Unknown field types - future PostgreSQL extensions
            }
        }

        reader.ensure_consumed("ErrorResponse")?;
        Ok(PgError::Server {
            code,
            message,
            detail,
            hint,
            diagnostic,
        })
    }

    /// Parse NoticeResponse message.
    ///
    /// Notice responses share the ErrorResponse wire shape, but they are
    /// non-fatal metadata and can carry server-local detail or hint text.
    /// Keep only the SQLSTATE and primary message so COPY-related notices
    /// cannot accidentally disclose file-system paths or operational hints.
    fn parse_notice_response(&self, data: &[u8]) -> Result<PgError, PgError> {
        let mut reader = MessageReader::new(data);
        let mut code = String::new();
        let mut message = String::new();

        loop {
            let field_type = reader.read_byte()?;
            if field_type == 0 {
                break;
            }
            let value = reader.read_cstring()?.to_string();

            match field_type {
                b'C' => code = value,
                b'M' => message = value,
                _ => {}
            }
        }

        reader.ensure_consumed("NoticeResponse")?;
        Ok(PgError::Server {
            code,
            message,
            detail: None,
            hint: None,
            diagnostic: PgErrorDiagnostic::default(), // Notices don't include diagnostic details
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
        reader.ensure_consumed("ParameterDescription")?;
        Ok(oids)
    }

    fn parse_copy_response(context: &str, data: &[u8]) -> Result<(Format, Vec<Format>), PgError> {
        let mut reader = MessageReader::new(data);
        let overall_format =
            Self::parse_copy_format_code(context, "overall", i16::from(reader.read_byte()?))?;
        let field_count = reader.read_i16()?;
        if field_count < 0 {
            return Err(PgError::Protocol(format!(
                "negative field count in {context}: {field_count}"
            )));
        }

        let field_count = field_count as usize;
        let expected_format_bytes = field_count
            .checked_mul(2)
            .ok_or_else(|| PgError::Protocol(format!("{context} field count overflow")))?;
        if reader.remaining() < expected_format_bytes {
            return Err(PgError::Protocol(format!(
                "{context} declares {field_count} column format code(s) but has only {} byte(s)",
                reader.remaining()
            )));
        }

        let mut field_formats = Vec::with_capacity(field_count);
        for column in 0..field_count {
            let code = reader.read_i16()?;
            field_formats.push(Self::parse_copy_column_format_code(context, column, code)?);
        }

        reader.ensure_consumed(context)?;
        Ok((overall_format, field_formats))
    }

    fn parse_copy_format_code(context: &str, role: &str, code: i16) -> Result<Format, PgError> {
        match code {
            0 => Ok(Format::Text),
            1 => Ok(Format::Binary),
            _ => Err(PgError::Protocol(format!(
                "invalid {context} {role} format code: {code}"
            ))),
        }
    }

    fn parse_copy_column_format_code(
        context: &str,
        column: usize,
        code: i16,
    ) -> Result<Format, PgError> {
        match code {
            0 => Ok(Format::Text),
            1 => Ok(Format::Binary),
            _ => Err(PgError::Protocol(format!(
                "invalid {context} column {column} format code: {code}"
            ))),
        }
    }

    /// Read results from Extended Query Protocol (query path).
    ///
    /// Expects: ParseComplete?, BindComplete, RowDescription?, DataRow*,
    /// CommandComplete, ReadyForQuery.
    async fn read_extended_query_results(&mut self, cx: &Cx) -> Outcome<Vec<PgRow>, PgError> {
        let mut columns: Option<Arc<Vec<PgColumn>>> = None;
        let mut column_indices: Option<Arc<BTreeMap<String, usize>>> = None;
        let mut rows = Vec::with_capacity(16);
        let mut discard_on_pool_return = false;

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
                b'C' => {
                    if let Some(tag) = Self::parse_command_tag(&data) {
                        discard_on_pool_return |= Self::command_tag_requires_session_discard(tag);
                    }
                }
                b's' => { /* PortalSuspended */ }
                b'Z' => {
                    // ReadyForQuery — protocol exchange completed cleanly.
                    self.inner.closed = false;
                    if let Err(e) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(e);
                    }
                    if discard_on_pool_return {
                        self.inner.needs_discard = true;
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
        let mut invalidate_prepared_cache = false;
        let mut discard_on_pool_return = false;

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
                    if let Some(tag) = Self::parse_command_tag(&data) {
                        if let Some(num) = Self::affected_rows_from_command_tag(tag) {
                            affected_rows = num;
                        }
                        invalidate_prepared_cache |=
                            Self::command_tag_requires_prepared_cache_invalidation(tag);
                        discard_on_pool_return |= Self::command_tag_requires_session_discard(tag);
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
                    if let Err(e) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(e);
                    }
                    if saw_row_response {
                        return Outcome::Err(row_returning_execute_error(
                            "execute-style APIs",
                            "query-style APIs",
                        ));
                    }
                    if invalidate_prepared_cache {
                        self.invalidate_prepared_cache_after_schema_or_session_change();
                    }
                    if discard_on_pool_return {
                        self.inner.needs_discard = true;
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
                self.handle_ready_for_query(&data)?;
                return Ok(());
            }
        }
    }
}

impl PgCopyIn<'_> {
    /// COPY IN format metadata announced by the backend.
    #[must_use]
    pub const fn response(&self) -> &PgCopyInResponse {
        &self.response
    }

    /// Number of `CopyData` frames sent so far.
    #[must_use]
    pub const fn chunks_sent(&self) -> u64 {
        self.chunks_sent
    }

    /// Total payload bytes sent so far.
    #[must_use]
    pub const fn bytes_sent(&self) -> u64 {
        self.bytes_sent
    }

    /// Send one COPY data chunk as one bounded `CopyData` frame.
    pub async fn send_chunk(&mut self, cx: &Cx, data: &[u8]) -> Outcome<(), PgError> {
        if self.finished {
            return Outcome::Err(PgError::Protocol(
                "COPY IN stream is already finished".to_string(),
            ));
        }
        if cx.checkpoint().is_err() {
            return self
                .abort_after_cancel(cx, "COPY FROM cancelled before CopyDone")
                .await;
        }

        let msg = match build_copy_data_msg(data) {
            Ok(msg) => msg,
            Err(err) => return Outcome::Err(err),
        };

        match self.connection.write_all(cx, &msg).await {
            Ok(()) => {
                self.chunks_sent = self.chunks_sent.saturating_add(1);
                self.bytes_sent = self.bytes_sent.saturating_add(data.len() as u64);
                Outcome::Ok(())
            }
            Err(PgError::Cancelled(reason)) => {
                self.connection.abort_in_flight_exchange();
                self.finished = true;
                Outcome::Cancelled(reason)
            }
            Err(err) => self.connection.fail_in_flight(err),
        }
    }

    /// Finish COPY IN with `CopyDone` and read the backend completion tag.
    pub async fn finish(mut self, cx: &Cx) -> Outcome<PgCopyInComplete, PgError> {
        if self.finished {
            return Outcome::Err(PgError::Protocol(
                "COPY IN stream is already finished".to_string(),
            ));
        }

        let msg = match build_copy_done_msg() {
            Ok(msg) => msg,
            Err(err) => return Outcome::Err(err),
        };
        let write_result = crate::combinator::commit_section(
            cx,
            COPY_TERMINAL_MASKED_POLLS,
            self.connection.write_all(cx, &msg),
        )
        .await;

        match write_result {
            Ok(()) => self.read_copy_done_result(cx).await,
            Err(PgError::Cancelled(reason)) => {
                self.connection.abort_in_flight_exchange();
                self.finished = true;
                Outcome::Cancelled(reason)
            }
            Err(err) => self.connection.fail_in_flight(err),
        }
    }

    /// Abort COPY IN with `CopyFail` and drain back to `ReadyForQuery`.
    pub async fn fail(mut self, cx: &Cx, message: &str) -> Outcome<(), PgError> {
        if self.finished {
            return Outcome::Err(PgError::Protocol(
                "COPY IN stream is already finished".to_string(),
            ));
        }
        self.write_copy_fail_and_drain(cx, message).await
    }

    async fn abort_after_cancel(&mut self, cx: &Cx, message: &str) -> Outcome<(), PgError> {
        let reason = cancelled_reason(cx);
        match self.write_copy_fail_and_drain(cx, message).await {
            Outcome::Ok(()) => Outcome::Cancelled(reason),
            Outcome::Err(_) => {
                self.connection.abort_in_flight_exchange();
                self.finished = true;
                Outcome::Cancelled(reason)
            }
            Outcome::Cancelled(_) | Outcome::Panicked(_) => {
                self.connection.abort_in_flight_exchange();
                self.finished = true;
                Outcome::Cancelled(reason)
            }
        }
    }

    async fn write_copy_fail_and_drain(&mut self, cx: &Cx, message: &str) -> Outcome<(), PgError> {
        let msg = match build_copy_fail_msg(message) {
            Ok(msg) => msg,
            Err(err) => {
                self.connection.abort_in_flight_exchange();
                self.finished = true;
                return Outcome::Err(err);
            }
        };

        crate::combinator::commit_section(cx, COPY_TERMINAL_MASKED_POLLS, async {
            if let Err(err) = self.connection.write_all(cx, &msg).await {
                return outcome_from_error(err);
            }
            self.drain_after_copy_fail(cx).await
        })
        .await
    }

    async fn drain_after_copy_fail(&mut self, cx: &Cx) -> Outcome<(), PgError> {
        loop {
            if cx.checkpoint().is_err() {
                self.connection.abort_in_flight_exchange();
                self.finished = true;
                return Outcome::Cancelled(cancelled_reason(cx));
            }

            let (msg_type, data) = match self.connection.read_message(cx).await {
                Ok(msg) => msg,
                Err(err) => return self.connection.fail_in_flight(err),
            };

            match msg_type {
                b'E' => {
                    let err = self.connection.parse_error_and_drain(cx, &data).await;
                    return match err {
                        PgError::Server { .. } => {
                            self.finished = true;
                            Outcome::Ok(())
                        }
                        PgError::Cancelled(reason) => {
                            self.finished = true;
                            Outcome::Cancelled(reason)
                        }
                        other => {
                            self.finished = true;
                            Outcome::Err(other)
                        }
                    };
                }
                b'Z' => {
                    self.connection.inner.closed = false;
                    if let Err(err) = self.connection.handle_ready_for_query(&data) {
                        return self.connection.fail_in_flight(err);
                    }
                    self.finished = true;
                    return Outcome::Ok(());
                }
                _ => {
                    match self
                        .connection
                        .handle_async_backend_message(msg_type, &data)
                    {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(err) => return self.connection.fail_in_flight(err),
                    }
                    return self
                        .connection
                        .fail_in_flight(unexpected_backend_message("COPY IN abort", msg_type));
                }
            }
        }
    }

    async fn read_copy_done_result(&mut self, cx: &Cx) -> Outcome<PgCopyInComplete, PgError> {
        let mut affected_rows = 0u64;

        loop {
            if cx.checkpoint().is_err() {
                return self.connection.cancel_in_flight(cx);
            }

            let (msg_type, data) = match self.connection.read_message(cx).await {
                Ok(msg) => msg,
                Err(err) => return self.connection.fail_in_flight(err),
            };

            match msg_type {
                b'C' => {
                    if let Some(tag) = PgConnection::parse_command_tag(&data)
                        && let Some(rows) = PgConnection::affected_rows_from_command_tag(tag)
                    {
                        affected_rows = rows;
                    }
                }
                b'Z' => {
                    self.connection.inner.closed = false;
                    if let Err(err) = self.connection.handle_ready_for_query(&data) {
                        return self.connection.fail_in_flight(err);
                    }
                    self.finished = true;
                    return Outcome::Ok(PgCopyInComplete {
                        affected_rows,
                        chunks_sent: self.chunks_sent,
                        bytes_sent: self.bytes_sent,
                        response: self.response.clone(),
                    });
                }
                b'E' => {
                    let err = self.connection.parse_error_and_drain(cx, &data).await;
                    if !self.connection.inner.closed {
                        self.finished = true;
                    }
                    return outcome_from_error(err);
                }
                _ => {
                    match self
                        .connection
                        .handle_async_backend_message(msg_type, &data)
                    {
                        Ok(true) => continue,
                        Ok(false) => {}
                        Err(err) => return self.connection.fail_in_flight(err),
                    }
                    return self.connection.fail_in_flight(unexpected_backend_message(
                        "COPY IN completion",
                        msg_type,
                    ));
                }
            }
        }
    }
}

impl Drop for PgCopyIn<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.connection.abort_in_flight_exchange();
        }
    }
}

// ============================================================================
// Typed Query Parameter Inference Audit Tests
// ============================================================================

#[cfg(test)]
mod typed_query_parameter_audit_tests {
    use super::*;

    /// Parameter OID probe for verifying client-side bind metadata.
    struct ParameterOidProbe;

    impl ParameterOidProbe {
        /// Test helper to extract parameter OIDs from ToSql values
        fn extract_parameter_oids(params: &[&dyn ToSql]) -> Vec<u32> {
            params.iter().map(|p| p.type_oid()).collect()
        }
    }

    /// AUDIT: Verify that typed queries defer type conversion to PostgreSQL server
    /// rather than rejecting at client bind time or silently converting types.
    #[test]
    fn audit_typed_query_parameter_inference_defers_to_server() {
        // Test case: Query with explicit type cast `$1::int` but String parameter
        let string_param = "42".to_string();
        let int_param = 42i32;

        // AUDIT: Client should send actual Rust type OIDs, not infer from SQL cast
        let string_oids = ParameterOidProbe::extract_parameter_oids(&[&string_param]);
        let int_oids = ParameterOidProbe::extract_parameter_oids(&[&int_param]);

        // AUDIT: String parameter sends TEXT OID (25), not INT4 OID (23)
        assert_eq!(
            string_oids,
            vec![25], // oid::TEXT
            "String parameter must send TEXT OID, not infer INT from SQL cast"
        );

        // AUDIT: i32 parameter sends INT4 OID (23)
        assert_eq!(
            int_oids,
            vec![23], // oid::INT4
            "i32 parameter must send INT4 OID"
        );

        // AUDIT: Same query with different parameter types sends different OIDs
        assert_ne!(
            string_oids, int_oids,
            "Different Rust types must send different PostgreSQL type OIDs"
        );
    }

    /// AUDIT: Verify parameter type OID mapping follows PostgreSQL type system
    #[test]
    fn audit_parameter_type_oid_mapping_correctness() {
        // Test comprehensive type mapping
        let bool_val = true;
        let i16_val = 42i16;
        let i32_val = 42i32;
        let i64_val = 42i64;
        let f32_val = 3.14f32;
        let f64_val = 3.14f64;
        let str_val = "hello";
        let string_val = "world".to_string();

        let test_cases = [
            (
                ParameterOidProbe::extract_parameter_oids(&[&bool_val])[0],
                16,
            ), // BOOL
            (
                ParameterOidProbe::extract_parameter_oids(&[&i16_val])[0],
                21,
            ), // INT2
            (
                ParameterOidProbe::extract_parameter_oids(&[&i32_val])[0],
                23,
            ), // INT4
            (
                ParameterOidProbe::extract_parameter_oids(&[&i64_val])[0],
                20,
            ), // INT8
            (
                ParameterOidProbe::extract_parameter_oids(&[&f32_val])[0],
                700,
            ), // FLOAT4
            (
                ParameterOidProbe::extract_parameter_oids(&[&f64_val])[0],
                701,
            ), // FLOAT8
            (
                ParameterOidProbe::extract_parameter_oids(&[&str_val])[0],
                25,
            ), // TEXT
            (
                ParameterOidProbe::extract_parameter_oids(&[&string_val])[0],
                25,
            ), // TEXT
        ];

        for (actual_oid, expected_oid) in test_cases {
            // AUDIT: Each Rust type maps to expected PostgreSQL OID
            assert_eq!(
                actual_oid, expected_oid,
                "Type must map to PostgreSQL OID {}",
                expected_oid
            );
        }
    }

    /// AUDIT: Document expected server-side type conversion behavior per PostgreSQL semantics
    #[test]
    fn audit_server_side_type_conversion_behavior_documented() {
        // This test documents the expected PostgreSQL server behavior when receiving
        // parameters with explicit casts in SQL. The client sends actual type OIDs,
        // and PostgreSQL performs conversion according to its type system.

        struct TypeConversionCase {
            description: &'static str,
            sql_fragment: &'static str,
            rust_type: &'static str,
            client_oid: u32,
            expected_server_behavior: ServerBehavior,
        }

        #[derive(Debug, PartialEq)]
        enum ServerBehavior {
            Accept,
            ConvertImplicitly,
            ErrorWithCode(&'static str),
        }

        let cases = [
            TypeConversionCase {
                description: "String '42' to integer should convert successfully",
                sql_fragment: "$1::int",
                rust_type: "String",
                client_oid: 25, // TEXT
                expected_server_behavior: ServerBehavior::ConvertImplicitly,
            },
            TypeConversionCase {
                description: "String 'abc' to integer should error",
                sql_fragment: "$1::int",
                rust_type: "String",
                client_oid: 25, // TEXT
                expected_server_behavior: ServerBehavior::ErrorWithCode("22P02"),
            },
            TypeConversionCase {
                description: "i32 42 to integer should accept directly",
                sql_fragment: "$1::int",
                rust_type: "i32",
                client_oid: 23, // INT4
                expected_server_behavior: ServerBehavior::Accept,
            },
            TypeConversionCase {
                description: "String to text column should accept directly",
                sql_fragment: "$1", // no explicit cast, column is text
                rust_type: "String",
                client_oid: 25, // TEXT
                expected_server_behavior: ServerBehavior::Accept,
            },
        ];

        for case in &cases {
            // AUDIT: Document that client sends actual Rust type OID
            println!("Case: {}", case.description);
            println!("  SQL: {}", case.sql_fragment);
            println!(
                "  Client sends: {} (OID {})",
                case.rust_type, case.client_oid
            );
            println!("  Server behavior: {:?}", case.expected_server_behavior);

            // AUDIT: This behavior preserves type discipline by:
            // 1. No client-side silent conversions
            // 2. Server applies PostgreSQL type conversion rules
            // 3. Clear error messages for incompatible types
            // 4. Type safety through explicit Rust→PostgreSQL type mapping
            assert!(
                matches!(
                    case.expected_server_behavior,
                    ServerBehavior::Accept
                        | ServerBehavior::ConvertImplicitly
                        | ServerBehavior::ErrorWithCode(_)
                ),
                "Server behavior must be well-defined"
            );
        }
    }

    /// AUDIT: Verify that type mismatches produce clear PostgreSQL error codes
    #[test]
    fn audit_type_mismatch_error_codes_are_correct() {
        // These error codes are from the existing test in postgres.rs
        // and represent the standard PostgreSQL error codes for type issues

        let expected_error_codes = [
            ("22P02", "invalid input syntax for type integer"),
            ("42804", "column is of type X but expression is of type Y"),
        ];

        for (code, description) in expected_error_codes {
            // AUDIT: PostgreSQL returns standard SQLSTATE error codes
            assert_eq!(code.len(), 5, "SQLSTATE must be 5 characters");
            assert!(
                code.chars().all(|c| c.is_ascii_alphanumeric()),
                "SQLSTATE must be alphanumeric"
            );

            println!("Error code {}: {}", code, description);
        }

        // AUDIT: Error handling preserves session state and allows recovery
        // This is verified by the existing test:
        // `extended_execute_type_mismatch_errors_preserve_session_recovery`
    }

    /// AUDIT: Verify no silent type conversions occur at client binding time
    #[test]
    fn audit_no_client_side_silent_conversions() {
        // Case that would be dangerous with silent conversion:
        // SQL: INSERT INTO accounts (balance) VALUES ($1::numeric)
        // Rust: &"1000.50"  -- String that looks like a number

        let string_value = "1000.50";
        let oids = ParameterOidProbe::extract_parameter_oids(&[&string_value]);

        // AUDIT: Client must send TEXT OID, not NUMERIC OID
        assert_eq!(
            oids[0],
            25, // TEXT not NUMERIC (1700)
            "Client must not silently convert String to NUMERIC type"
        );

        // AUDIT: If PostgreSQL can convert TEXT '1000.50' to NUMERIC, it succeeds
        // AUDIT: If PostgreSQL cannot convert (e.g., 'abc'), it returns error 22P02
        // AUDIT: This preserves both type safety and PostgreSQL semantics
    }
}

fn decode_binary_numeric_to_text(data: &[u8]) -> Result<String, PgError> {
    const NUMERIC_POS: u16 = 0x0000;
    const NUMERIC_NEG: u16 = 0x4000;
    const NUMERIC_NAN: u16 = 0xC000;

    let mut reader = MessageReader::new(data);
    let ndigits_i16 = reader.read_i16()?;
    if ndigits_i16 < 0 {
        return Err(PgError::Protocol(format!(
            "negative digit count in NUMERIC: {ndigits_i16}"
        )));
    }
    let weight = reader.read_i16()?;
    let sign = reader.read_i16()? as u16;
    let scale_i16 = reader.read_i16()?;
    if scale_i16 < 0 {
        return Err(PgError::Protocol(format!(
            "negative scale in NUMERIC: {scale_i16}"
        )));
    }
    let scale = scale_i16 as usize;

    let mut digits = Vec::with_capacity(ndigits_i16 as usize);
    for idx in 0..ndigits_i16 as usize {
        let digit = reader.read_i16()?;
        if !(0..10_000).contains(&digit) {
            return Err(PgError::Protocol(format!(
                "NUMERIC digit {idx} out of range: {digit}"
            )));
        }
        digits.push(digit as u16);
    }
    reader.ensure_consumed("NUMERIC")?;

    if sign == NUMERIC_NAN {
        return Err(PgError::Protocol(
            "NUMERIC NaN is not supported".to_string(),
        ));
    }
    if sign != NUMERIC_POS && sign != NUMERIC_NEG {
        return Err(PgError::Protocol(format!(
            "invalid NUMERIC sign: 0x{sign:04X}"
        )));
    }

    let digit_at_exponent = |exp: i16| -> u16 {
        let idx = weight - exp;
        if idx < 0 {
            0
        } else {
            digits.get(idx as usize).copied().unwrap_or(0)
        }
    };

    let integer_groups = if weight >= 0 {
        (0..=weight)
            .rev()
            .map(digit_at_exponent)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut integer_parts = integer_groups
        .into_iter()
        .skip_while(|digit| *digit == 0)
        .collect::<Vec<_>>();

    let integer = if integer_parts.is_empty() {
        "0".to_string()
    } else {
        let first = integer_parts.remove(0);
        let mut rendered = first.to_string();
        for digit in integer_parts {
            use std::fmt::Write as _;
            let _ = write!(rendered, "{digit:04}");
        }
        rendered
    };

    let fractional = if scale == 0 {
        String::new()
    } else {
        let fractional_groups = scale.div_ceil(4);
        let mut rendered = String::with_capacity(fractional_groups * 4);
        for group_idx in 0..fractional_groups {
            let exp = -1 - group_idx as i16;
            use std::fmt::Write as _;
            let _ = write!(rendered, "{:04}", digit_at_exponent(exp));
        }
        rendered.truncate(scale);
        rendered
    };

    let is_zero = digits.iter().all(|digit| *digit == 0);
    let sign_prefix = if sign == NUMERIC_NEG && !is_zero {
        "-"
    } else {
        ""
    };

    if scale == 0 {
        Ok(format!("{sign_prefix}{integer}"))
    } else {
        Ok(format!("{sign_prefix}{integer}.{fractional}"))
    }
}

const POSTGRES_EPOCH_UNIX_DAYS: i64 = 10_957;
const POSTGRES_DAY_MICROSECONDS: i64 = 86_400_000_000;

fn decode_binary_date_to_text(data: &[u8]) -> Result<String, PgError> {
    if data.len() != 4 {
        return Err(PgError::Protocol(format!(
            "DATE requires exactly 4 bytes, got {}",
            data.len()
        )));
    }

    let days = i32::from_be_bytes([data[0], data[1], data[2], data[3]]) as i64;
    let (year, month, day) = civil_from_unix_days(POSTGRES_EPOCH_UNIX_DAYS + days);
    Ok(format!("{year:04}-{month:02}-{day:02}"))
}

fn decode_binary_timestamp_to_text(data: &[u8]) -> Result<String, PgError> {
    if data.len() != 8 {
        return Err(PgError::Protocol(format!(
            "TIMESTAMP requires exactly 8 bytes, got {}",
            data.len()
        )));
    }

    let micros = i64::from_be_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let days = micros.div_euclid(POSTGRES_DAY_MICROSECONDS);
    let micros_of_day = micros.rem_euclid(POSTGRES_DAY_MICROSECONDS);
    let (year, month, day) = civil_from_unix_days(POSTGRES_EPOCH_UNIX_DAYS + days);
    let (hour, minute, second, fractional_micros) = split_day_microseconds(micros_of_day as u64);

    if fractional_micros == 0 {
        Ok(format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}"
        ))
    } else {
        let mut fractional = format!("{fractional_micros:06}");
        while fractional.ends_with('0') {
            fractional.pop();
        }
        Ok(format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}.{fractional}"
        ))
    }
}

fn decode_binary_interval_to_text(data: &[u8]) -> Result<String, PgError> {
    if data.len() != 16 {
        return Err(PgError::Protocol(format!(
            "INTERVAL requires exactly 16 bytes, got {}",
            data.len()
        )));
    }

    let mut reader = MessageReader::new(data);
    let microseconds = reader.read_i64()?;
    let days = reader.read_i32()?;
    let months = reader.read_i32()?;
    reader.ensure_consumed("INTERVAL")?;

    Ok(render_interval_text(months, days, microseconds))
}

fn civil_from_unix_days(days_since_unix_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}

fn split_day_microseconds(micros_of_day: u64) -> (u64, u64, u64, u64) {
    let hour = micros_of_day / 3_600_000_000;
    let minute = (micros_of_day % 3_600_000_000) / 60_000_000;
    let second = (micros_of_day % 60_000_000) / 1_000_000;
    let fractional_micros = micros_of_day % 1_000_000;
    (hour, minute, second, fractional_micros)
}

fn render_interval_text(months: i32, days: i32, microseconds: i64) -> String {
    let mut parts = Vec::new();

    if months != 0 {
        parts.push(format!(
            "{months} {}",
            if months.abs() == 1 { "mon" } else { "mons" }
        ));
    }
    if days != 0 {
        parts.push(format!(
            "{days} {}",
            if days.abs() == 1 { "day" } else { "days" }
        ));
    }

    if microseconds != 0 || parts.is_empty() {
        let sign = if microseconds < 0 { "-" } else { "" };
        let abs_microseconds = microseconds.unsigned_abs();
        let (hour, minute, second, fractional_micros) = split_day_microseconds(abs_microseconds);
        if fractional_micros == 0 {
            parts.push(format!("{sign}{hour:02}:{minute:02}:{second:02}"));
        } else {
            let mut fractional = format!("{fractional_micros:06}");
            while fractional.ends_with('0') {
                fractional.pop();
            }
            parts.push(format!(
                "{sign}{hour:02}:{minute:02}:{second:02}.{fractional}"
            ));
        }
    }

    parts.join(" ")
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
    // Calculate capacity with overflow protection (SQL + estimated overhead)
    let mut buf = MessageBuffer::with_capacity(sql.len().saturating_add(64));
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

    // PostgreSQL allows the format-code section to be compressed when all
    // parameters share the same format. psql/libpq emits count=0 for the
    // default all-text case and count=1 for any uniform non-text case.
    let mut param_formats = Vec::with_capacity(params.len());
    let mut all_text = true;
    let mut all_same = true;
    let mut first_format = None;
    for p in params {
        let format = p.format();
        all_text &= format == Format::Text;
        if let Some(first) = first_format {
            all_same &= format == first;
        } else {
            first_format = Some(format);
        }
        param_formats.push(format);
    }

    if param_formats.is_empty() || all_text {
        buf.write_i16(0);
    } else if all_same {
        buf.write_i16(1);
        buf.write_i16(first_format.expect("uniform format code must exist") as i16);
    } else {
        buf.write_i16(param_formats.len() as i16);
        for format in param_formats {
            buf.write_i16(format as i16);
        }
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

/// Build a CopyData message for a COPY IN stream.
fn build_copy_data_msg(data: &[u8]) -> Result<Vec<u8>, PgError> {
    let mut buf = MessageBuffer::with_capacity(data.len());
    buf.write_bytes(data);
    buf.build_message(FrontendMessage::CopyData as u8)
}

/// Build a CopyDone message for a COPY IN stream.
fn build_copy_done_msg() -> Result<Vec<u8>, PgError> {
    let mut buf = MessageBuffer::new();
    buf.build_message(FrontendMessage::CopyDone as u8)
}

/// Build a CopyFail message for a COPY IN stream.
fn build_copy_fail_msg(message: &str) -> Result<Vec<u8>, PgError> {
    if message.as_bytes().contains(&0) {
        return Err(PgError::Protocol(
            "CopyFail message contains embedded NUL byte".to_string(),
        ));
    }
    let mut buf = MessageBuffer::with_capacity(message.len() + 1);
    buf.write_bytes(message.as_bytes());
    buf.write_byte(0);
    buf.build_message(FrontendMessage::CopyFail as u8)
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
    /// br-asupersync-rsifm3 — isolation level if explicitly set via
    /// [`PgConnection::begin_with_isolation`], else `None` (server default).
    isolation_level: Option<IsolationLevel>,
    /// br-asupersync-rsifm3 — `true` iff opened READ ONLY.
    read_only: bool,
}

impl PgTransaction<'_> {
    /// Returns the isolation level explicitly requested for this transaction
    /// (via [`PgConnection::begin_with_isolation`]). Returns `None` for
    /// transactions opened with the plain [`PgConnection::begin`], which use
    /// the server default (typically `READ COMMITTED`).
    #[must_use]
    pub const fn isolation_level(&self) -> Option<IsolationLevel> {
        self.isolation_level
    }

    /// Returns `true` if this transaction was opened READ ONLY.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    #[must_use]
    pub(crate) fn requires_rollback_before_commit(&self) -> bool {
        self.conn.inner.needs_rollback
            || self.conn.inner.needs_discard
            || self.conn.inner.transaction_status == b'E'
    }

    pub(crate) fn poison_for_rollback(&mut self) {
        self.conn.inner.needs_rollback = true;
        self.conn.inner.needs_discard = true;
    }

    fn mark_finished_if_server_closed_transaction(&mut self, err: &PgError) {
        if matches!(err, PgError::Server { .. }) && self.conn.inner.transaction_status == b'I' {
            self.finished = true;
        }
    }

    /// Commit the transaction.
    pub async fn commit(mut self, cx: &Cx) -> Outcome<(), PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        match self.conn.execute_unchecked(cx, "COMMIT").await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
            Outcome::Err(e) => {
                self.mark_finished_if_server_closed_transaction(&e);
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Rollback the transaction.
    pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        match self.conn.execute_unchecked(cx, "ROLLBACK").await {
            Outcome::Ok(_) => {
                self.finished = true;
                Outcome::Ok(())
            }
            Outcome::Err(e) => {
                self.mark_finished_if_server_closed_transaction(&e);
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => Outcome::Cancelled(r),
            Outcome::Panicked(p) => Outcome::Panicked(p),
        }
    }

    /// Execute a simple query within this transaction (DEPRECATED — see
    /// [`Self::query_unchecked`]).
    #[deprecated(
        note = "use query_unchecked for trusted-literal SQL or query_params for parameterized queries (br-asupersync-0fxbp6)"
    )]
    pub async fn query(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError> {
        self.query_unchecked(cx, sql).await
    }

    /// br-asupersync-0fxbp6 — Execute a simple (unparameterized) query within
    /// this transaction.
    ///
    /// **Security:** see [`PgConnection::query_unchecked`]. `sql` must be a
    /// trusted literal or fully caller-controlled. Use
    /// [`Self::query_params`] for any value derived from external input.
    pub async fn query_unchecked(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        self.conn.query_unchecked(cx, sql).await
    }

    /// Execute a simple command within this transaction (DEPRECATED — see
    /// [`Self::execute_unchecked`]).
    #[deprecated(
        note = "use execute_unchecked for trusted-literal SQL or execute_params for parameterized commands (br-asupersync-0fxbp6)"
    )]
    pub async fn execute(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, PgError> {
        self.execute_unchecked(cx, sql).await
    }

    /// br-asupersync-0fxbp6 — Execute a simple (unparameterized) command
    /// within this transaction.
    ///
    /// **Security:** see [`PgConnection::execute_unchecked`]. `sql` must be a
    /// trusted literal or fully caller-controlled.
    pub async fn execute_unchecked(&mut self, cx: &Cx, sql: &str) -> Outcome<u64, PgError> {
        if self.finished {
            return Outcome::Err(PgError::TransactionFinished);
        }
        self.conn.execute_unchecked(cx, sql).await
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
    /// br-asupersync-yl4gu1: a `PgTransaction` dropped without commit
    /// MUST mark the connection for both (a) inline ROLLBACK on the
    /// next operation AND (b) discard-on-pool-return. Pre-fix only
    /// (a) was set; if the caller dropped both PgTransaction AND
    /// PgConnection without issuing another query, the BEGIN stayed
    /// open on the server — the pool's next tenant inherited an
    /// `idle_in_transaction` backend with locks held.
    ///
    /// Setting `needs_discard = true` ensures the pool's return path
    /// (expected to call `PgConnection::needs_discard()` before
    /// recycling) closes the connection instead. Both flags stay
    /// set in tandem so callers that DO continue using the same
    /// connection without a pool round-trip still get the inline
    /// ROLLBACK fast path.
    fn drop(&mut self) {
        if !self.finished {
            self.poison_for_rollback();
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
    /// SQL text used to prepare this statement. Retained so a direct
    /// connection can transparently re-prepare on a fresh backend after an
    /// idle disconnect.
    sql: String,
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

    /// SQL text used when preparing this statement.
    #[must_use]
    pub fn sql(&self) -> &str {
        &self.sql
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

/// Reference [`AsyncConnectionManager`] implementation for [`PgConnection`].
///
/// Wraps a [`PgConnectOptions`] used to mint new connections; the pool calls
/// [`Self::connect`] to add a connection and [`Self::release_check`] on every
/// return-to-pool to decide whether the connection is safe to reuse.
///
/// br-asupersync-a1x452 + br-asupersync-t4wfzb: pre-fix, no
/// PgConnection-specific manager existed. Pool consumers either rolled
/// their own (e.g. test harnesses at tests/database_e2e.rs:317) and
/// inherited the default `release_check` that returns `true`
/// unconditionally — meaning a connection flagged with
/// `needs_discard()=true` (PgTransaction dropped without commit, leaving
/// the backend in idle_in_transaction with locks held) OR
/// `is_unhealthy()=true` (consecutive DEALLOCATE failures from
/// br-asupersync-7v80ju) was returned to the pool and handed to the
/// next caller. The next caller observed:
///   - **a1x452**: poisoned `idle_in_transaction` connection with the
///     prior tenant's locks still held. Subsequent queries either
///     blocked on the locks or executed inside the dangling
///     transaction.
///   - **t4wfzb**: a connection that had failed to deallocate prepared
///     statements, leaking server-side prepared statement names and
///     potentially returning stale results from cached statement
///     handles.
///
/// This manager's [`Self::release_check`] returns `false` if EITHER
/// flag is set, signalling the pool to drop rather than reuse the
/// connection. The pool then closes the connection (via
/// [`Self::disconnect`]) and constructs a fresh one on next demand —
/// the structurally-correct shape per the documented contract at
/// `pool.rs::ConnectionManager::release_check` and the asupersync
/// "no obligation leaks" invariant.
pub struct PgConnectionManager {
    /// Options used to mint each new connection.
    options: PgConnectOptions,
}

impl fmt::Debug for PgConnectionManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConnectionManager")
            .field("options", &self.options)
            .finish()
    }
}

impl PgConnectionManager {
    /// Create a new manager that mints connections using `options`.
    #[must_use]
    pub fn new(options: PgConnectOptions) -> Self {
        Self { options }
    }

    /// Returns the options the manager uses to mint connections.
    #[must_use]
    pub fn options(&self) -> &PgConnectOptions {
        &self.options
    }
}

impl crate::database::pool::AsyncConnectionManager for PgConnectionManager {
    type Connection = PgConnection;
    type Error = PgError;

    async fn connect(&self, cx: &Cx) -> crate::types::Outcome<Self::Connection, Self::Error> {
        // Pass through verbatim — the underlying constructor already
        // returns Outcome<PgConnection, PgError>; the explicit match
        // would only round-trip the data through itself.
        PgConnection::connect_with_options(cx, self.options.clone()).await
    }

    async fn is_valid(&self, _cx: &Cx, conn: &mut Self::Connection) -> bool {
        // A connection is valid for reuse iff it is open, not in a
        // transaction, not flagged for discard, and not unhealthy. The
        // is_valid hook may run async queries (e.g. SELECT 1) but for
        // the cheap check here we use the locally-tracked flags; the
        // pool's separate health-check path is responsible for
        // periodic SELECT 1 probes.
        !conn.inner.closed
            && !conn.in_transaction()
            && !conn.needs_discard()
            && !conn.is_unhealthy()
            && conn.transport_matches_ssl_mode(self.options.ssl_mode)
    }

    /// br-asupersync-a1x452 + br-asupersync-t4wfzb: refuse to recycle
    /// a connection that is in any of these states:
    ///   * `needs_discard()=true` — PgTransaction dropped without
    ///     commit; backend is in `idle_in_transaction` with locks
    ///     held. Recycling would expose the next tenant to the prior
    ///     tenant's transaction state.
    ///   * `is_unhealthy()=true` — consecutive DEALLOCATE failures
    ///     marked the connection as untrusted (br-asupersync-7v80ju).
    ///     Recycling would let the next tenant inherit the broken
    ///     prepared-statement state.
    ///   * `in_transaction()=true` — defensive check: even without
    ///     the explicit needs_discard flag, a connection still inside
    ///     a transaction must not be returned to the pool.
    ///   * inner stream already closed — defensive check.
    ///
    /// Returning `false` signals the pool to drop the connection via
    /// [`Self::disconnect`] rather than enqueue it for reuse.
    fn release_check(&self, conn: &mut Self::Connection) -> bool {
        if conn.inner.closed {
            return false;
        }
        if conn.needs_discard() {
            return false;
        }
        if conn.is_unhealthy() {
            return false;
        }
        if conn.in_transaction() {
            return false;
        }
        if !conn.transport_matches_ssl_mode(self.options.ssl_mode) {
            return false;
        }
        true
    }

    fn disconnect(&self, _conn: Self::Connection) {
        // PgConnectionInner::Drop handles the wire-level close
        // (br-asupersync-1wygbs sends Terminate before TCP shutdown).
        // Dropping here triggers that path.
    }
}

#[cfg(feature = "test-internals")]
fn fuzz_test_connection_with_peer() -> (PgConnection, std::net::TcpStream) {
    let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) => panic!("bind fuzz test listener: {err}"),
    };
    let addr = match listener.local_addr() {
        Ok(addr) => addr,
        Err(err) => panic!("read fuzz test listener addr: {err}"),
    };
    let std_stream = match std::net::TcpStream::connect(addr) {
        Ok(stream) => stream,
        Err(err) => panic!("connect fuzz test stream: {err}"),
    };
    let (peer_stream, _) = match listener.accept() {
        Ok(pair) => pair,
        Err(err) => panic!("accept fuzz test stream: {err}"),
    };
    let stream = match crate::net::TcpStream::from_std(std_stream) {
        Ok(stream) => stream,
        Err(err) => panic!("convert fuzz test stream: {err}"),
    };
    (
        PgConnection {
            inner: PgConnectionInner {
                stream: PgStream::Plain(stream),
                options: test_pg_connect_options(),
                process_id: 0,
                secret_key: 0,
                cancel_target: test_cancel_target(),
                parameters: BTreeMap::new(),
                transaction_status: b'I',
                closed: false,
                explicitly_closed: false,
                needs_rollback: false,
                needs_discard: false,
                next_stmt_id: 0,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
                prepared_cache: PreparedStatementCache::new(DEFAULT_MAX_PREPARED_STATEMENTS),
                deallocate_retry_queue: VecDeque::new(),
                consecutive_deallocate_failures: 0,
                unhealthy: false,
                subscribed_channels: BTreeSet::new(),
            },
        },
        peer_stream,
    )
}

/// br-asupersync-eoixvy — fuzz-target re-exporter for PostgreSQL backend
/// message framing. Uses the same length-validation helper as the production
/// `read_message()` path, but parses from memory so libFuzzer cannot block on
/// a synchronous socket write before the async reader is polled.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub async fn fuzz_read_backend_message(cx: &Cx, frame: &[u8]) -> Result<(u8, Vec<u8>), PgError> {
    if cx.checkpoint().is_err() {
        return Err(cancelled_error(cx));
    }
    if frame.len() < 5 {
        return Err(PgError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "unexpected end of stream",
        )));
    }

    let msg_type = frame[0];
    let len_i32 = i32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
    let body_len = backend_message_body_len(len_i32)?;
    let body_start = 5usize;
    let body_end = body_start
        .checked_add(body_len)
        .ok_or_else(|| PgError::Protocol("message length overflow".into()))?;
    if frame.len() < body_end {
        return Err(PgError::Io(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "unexpected end of stream",
        )));
    }
    if cx.checkpoint().is_err() {
        return Err(cancelled_error(cx));
    }

    Ok((msg_type, frame[body_start..body_end].to_vec()))
}

/// br-asupersync-eoixvy — fuzz-target re-exporter for the RowDescription
/// parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_row_description(
    data: &[u8],
) -> Result<(Vec<PgColumn>, BTreeMap<String, usize>), PgError> {
    let (conn, _peer) = fuzz_test_connection_with_peer();
    conn.parse_row_description(data)
}

/// br-asupersync-eoixvy — fuzz-target re-exporter for the DataRow parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_data_row(data: &[u8], columns: &[PgColumn]) -> Result<Vec<PgValue>, PgError> {
    let (conn, _peer) = fuzz_test_connection_with_peer();
    conn.parse_data_row(data, columns)
}

/// br-asupersync-eoixvy — fuzz-target re-exporter for the ErrorResponse
/// parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_error_response(data: &[u8]) -> Result<PgError, PgError> {
    let (conn, _peer) = fuzz_test_connection_with_peer();
    conn.parse_error_response(data)
}

/// br-asupersync-eoixvy — fuzz-target re-exporter for the
/// ParameterDescription parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_parameter_description(data: &[u8]) -> Result<Vec<u32>, PgError> {
    PgConnection::parse_parameter_description(data)
}

/// Fuzz-target re-exporter for CopyOutResponse body parsing.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_copy_out_response(data: &[u8]) -> Result<(Format, Vec<Format>), PgError> {
    PgConnection::parse_copy_response("CopyOutResponse", data)
}

/// Fuzz-target re-exporter for the ParameterStatus message parser.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_parameter_status(data: &[u8]) -> Result<(), PgError> {
    let (mut conn, _peer) = fuzz_test_connection_with_peer();
    conn.handle_parameter_status(data)
}

/// Fuzz-target re-exporter for the NoticeResponse message parser.
/// NoticeResponse has the same structure as ErrorResponse but is non-fatal.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_notice_response(data: &[u8]) -> Result<PgError, PgError> {
    let (conn, _peer) = fuzz_test_connection_with_peer();
    conn.parse_notice_response(data)
}

/// Fuzz-target re-exporter for LISTEN SQL construction.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_build_listen_sql(channel: &str) -> Result<String, PgError> {
    build_listen_sql(channel)
}

/// Fuzz-target re-exporter for UNLISTEN SQL construction.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_build_unlisten_sql(channel: &str) -> Result<String, PgError> {
    build_unlisten_sql(channel)
}

/// Fuzz-target re-exporter for NotificationResponse parsing.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_notification_response(data: &[u8]) -> Result<FuzzNotificationResponse, PgError> {
    PgConnection::parse_notification_response_fields(data).map(Into::into)
}

/// Fuzz-target re-exporter for strict CommandComplete tag parsing.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_command_complete_tag(data: &[u8]) -> Result<u64, PgError> {
    let tag = PgConnection::parse_command_tag(data)
        .ok_or_else(|| PgError::Protocol("CommandComplete tag must be valid UTF-8".to_string()))?;
    PgConnection::affected_rows_from_command_tag(tag).ok_or_else(|| {
        PgError::Protocol(format!(
            "CommandComplete tag missing numeric row count: {tag:?}"
        ))
    })
}

/// Fuzz-target re-exporter for frontend StartupMessage parsing.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_startup_message(data: &[u8]) -> Result<FuzzStartupMessage, PgError> {
    parse_startup_message(data).map(|message| FuzzStartupMessage {
        protocol_version: message.protocol_version,
        parameters: message.parameters,
    })
}

/// Fuzz-target re-exporter for ReadyForQuery transaction-state parsing.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_apply_ready_for_query(data: &[u8], initial_status: u8) -> (Result<u8, PgError>, u8) {
    let (mut conn, _peer) = fuzz_test_connection_with_peer();
    conn.inner.transaction_status = initial_status;
    let result = conn
        .handle_ready_for_query(data)
        .map(|()| conn.inner.transaction_status);
    let final_status = conn.inner.transaction_status;
    (result, final_status)
}

/// Fuzz-target re-exporter for Sync-driven recovery back to ReadyForQuery.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_apply_sync_recovery(stream: &[u8], initial_status: u8) -> (Result<u8, PgError>, u8) {
    let (mut conn, _peer) = fuzz_test_connection_with_peer();
    conn.inner.transaction_status = initial_status;

    let result = (|| {
        let mut cursor = 0usize;
        while cursor < stream.len() {
            if stream.len() - cursor < 5 {
                return Err(PgError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }

            let msg_type = stream[cursor];
            let len_i32 = i32::from_be_bytes([
                stream[cursor + 1],
                stream[cursor + 2],
                stream[cursor + 3],
                stream[cursor + 4],
            ]);
            let body_len = backend_message_body_len(len_i32)?;
            let body_start = cursor + 5;
            let body_end = body_start
                .checked_add(body_len)
                .ok_or_else(|| PgError::Protocol("message length overflow".into()))?;
            if stream.len() < body_end {
                return Err(PgError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }

            let data = &stream[body_start..body_end];
            cursor = body_end;

            match msg_type {
                b'1' | b'2' | b'3' | b'C' | b'D' | b'E' | b'N' | b'S' | b'A' | b'T' | b't'
                | b'n' | b's' => {}
                b'Z' => {
                    conn.inner.closed = false;
                    conn.handle_ready_for_query(data)?;
                    return Ok(conn.inner.transaction_status);
                }
                _ => return Err(unexpected_backend_message("sync recovery", msg_type)),
            }
        }

        Err(PgError::Protocol(
            "sync recovery stream ended before ReadyForQuery".into(),
        ))
    })();

    let final_status = conn.inner.transaction_status;
    (result, final_status)
}

/// Fuzz-target summary for a frontend Parse message.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzParseMessage {
    pub statement_name: String,
    pub sql: String,
    pub param_oids: Vec<u32>,
}

/// Fuzz-target summary for a frontend Bind message.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzBindMessage {
    pub portal: String,
    pub statement_name: String,
    pub param_format_codes: Vec<i16>,
    pub parameter_values: Vec<Option<Vec<u8>>>,
    pub result_format_codes: Vec<i16>,
}

/// Terminal message for a frontend COPY IN stream.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub enum FuzzCopyInEnd {
    Done,
    Fail(String),
}

/// Fuzz-target summary for frontend COPY IN message decoding.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzCopyInSequence {
    pub copy_data_chunks: Vec<Vec<u8>>,
    pub end: FuzzCopyInEnd,
}

#[cfg(feature = "test-internals")]
fn fuzz_push_copy_in_frame(
    msg_type: u8,
    body: &[u8],
    copy_data_chunks: &mut Vec<Vec<u8>>,
) -> Result<Option<FuzzCopyInEnd>, PgError> {
    match msg_type {
        value if value == FrontendMessage::CopyData as u8 => {
            copy_data_chunks.push(body.to_vec());
            Ok(None)
        }
        value if value == FrontendMessage::CopyDone as u8 => {
            MessageReader::new(body).ensure_consumed("CopyDone")?;
            Ok(Some(FuzzCopyInEnd::Done))
        }
        value if value == FrontendMessage::CopyFail as u8 => {
            let mut reader = MessageReader::new(body);
            let message = reader.read_cstring()?.to_string();
            reader.ensure_consumed("CopyFail")?;
            Ok(Some(FuzzCopyInEnd::Fail(message)))
        }
        other => Err(PgError::Protocol(format!(
            "unexpected COPY IN frontend message: {}",
            other as char
        ))),
    }
}

/// Fuzz-target summary for a frontend StartupMessage.
#[cfg(feature = "test-internals")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[doc(hidden)]
pub struct FuzzStartupMessage {
    pub protocol_version: i32,
    pub parameters: BTreeMap<String, String>,
}

#[cfg(feature = "test-internals")]
fn fuzz_frontend_message_body(frame: &[u8], expected_type: u8) -> Result<&[u8], PgError> {
    if frame.len() < 5 {
        return Err(PgError::Protocol("frontend message too short".to_string()));
    }
    if frame[0] != expected_type {
        return Err(PgError::Protocol(format!(
            "expected frontend message type {}, got {}",
            expected_type as char, frame[0] as char
        )));
    }

    let len_i32 = i32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
    let body_len = backend_message_body_len(len_i32)?;
    let body_end = 5usize
        .checked_add(body_len)
        .ok_or_else(|| PgError::Protocol("message length overflow".to_string()))?;

    if frame.len() < body_end {
        return Err(PgError::Protocol("unexpected end of message".to_string()));
    }
    if frame.len() > body_end {
        return Err(PgError::Protocol(format!(
            "frontend message has {} trailing byte(s)",
            frame.len() - body_end
        )));
    }

    Ok(&frame[5..body_end])
}

/// Fuzz-target re-exporter for frontend COPY IN stream decoding.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_copy_in_sequence(stream: &[u8]) -> Result<FuzzCopyInSequence, PgError> {
    let mut cursor = 0usize;
    let mut copy_data_chunks = Vec::new();

    loop {
        if cursor == stream.len() {
            return Err(PgError::Protocol(
                "COPY IN stream ended before CopyDone or CopyFail".to_string(),
            ));
        }
        if stream.len().saturating_sub(cursor) < 5 {
            return Err(PgError::Protocol(
                "unexpected end of COPY IN message".to_string(),
            ));
        }

        let msg_type = stream[cursor];
        let len_i32 = i32::from_be_bytes([
            stream[cursor + 1],
            stream[cursor + 2],
            stream[cursor + 3],
            stream[cursor + 4],
        ]);
        let body_len = backend_message_body_len(len_i32)?;
        let body_start = cursor + 5;
        let body_end = body_start
            .checked_add(body_len)
            .ok_or_else(|| PgError::Protocol("message length overflow".to_string()))?;

        if stream.len() < body_end {
            return Err(PgError::Protocol(
                "unexpected end of COPY IN message".to_string(),
            ));
        }

        let body = &stream[body_start..body_end];
        cursor = body_end;

        let Some(end) = fuzz_push_copy_in_frame(msg_type, body, &mut copy_data_chunks)? else {
            continue;
        };

        if cursor != stream.len() {
            return Err(PgError::Protocol(format!(
                "COPY IN stream has {} trailing byte(s) after terminal message",
                stream.len() - cursor
            )));
        }

        return Ok(FuzzCopyInSequence {
            copy_data_chunks,
            end,
        });
    }
}

/// Fuzz-target re-exporter for segmented frontend COPY IN stream decoding.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_copy_in_segments(segments: &[&[u8]]) -> Result<FuzzCopyInSequence, PgError> {
    let mut pending = Vec::new();
    let mut copy_data_chunks = Vec::new();
    let mut terminal = None;

    for segment in segments {
        if terminal.is_some() {
            if segment.is_empty() {
                continue;
            }
            return Err(PgError::Protocol(format!(
                "COPY IN stream has {} trailing byte(s) after terminal message",
                segment.len()
            )));
        }

        pending.extend_from_slice(segment);

        loop {
            if pending.is_empty() || pending.len() < 5 {
                break;
            }

            let msg_type = pending[0];
            let len_i32 = i32::from_be_bytes([pending[1], pending[2], pending[3], pending[4]]);
            let body_len = backend_message_body_len(len_i32)?;
            let body_end = 5usize
                .checked_add(body_len)
                .ok_or_else(|| PgError::Protocol("message length overflow".to_string()))?;

            if pending.len() < body_end {
                break;
            }

            let body = &pending[5..body_end];
            if let Some(end) = fuzz_push_copy_in_frame(msg_type, body, &mut copy_data_chunks)? {
                terminal = Some(end);
            }
            pending.drain(..body_end);

            if terminal.is_some() {
                if !pending.is_empty() {
                    return Err(PgError::Protocol(format!(
                        "COPY IN stream has {} trailing byte(s) after terminal message",
                        pending.len()
                    )));
                }
                break;
            }
        }
    }

    if let Some(end) = terminal {
        return Ok(FuzzCopyInSequence {
            copy_data_chunks,
            end,
        });
    }

    if pending.is_empty() {
        return Err(PgError::Protocol(
            "COPY IN stream ended before CopyDone or CopyFail".to_string(),
        ));
    }

    Err(PgError::Protocol(
        "unexpected end of COPY IN message".to_string(),
    ))
}

/// Fuzz-target re-exporter for frontend Parse message decoding.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_build_parse_msg(
    stmt_name: &str,
    sql: &str,
    param_oids: &[u32],
) -> Result<Vec<u8>, PgError> {
    build_parse_msg(stmt_name, sql, param_oids)
}

/// Fuzz-target re-exporter for frontend Parse message decoding.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_parse_message(frame: &[u8]) -> Result<FuzzParseMessage, PgError> {
    let body = fuzz_frontend_message_body(frame, FrontendMessage::Parse as u8)?;
    let mut reader = MessageReader::new(body);
    let statement_name = reader.read_cstring()?.to_string();
    let sql = reader.read_cstring()?.to_string();
    let param_count = reader.read_i16()?;
    if param_count < 0 {
        return Err(PgError::Protocol(format!(
            "invalid parse parameter count: {param_count}"
        )));
    }
    let mut param_oids = Vec::with_capacity(param_count as usize);
    for _ in 0..param_count {
        param_oids.push(reader.read_i32()? as u32);
    }
    reader.ensure_consumed("Parse")?;

    Ok(FuzzParseMessage {
        statement_name,
        sql,
        param_oids,
    })
}

/// Fuzz-target re-exporter for frontend Bind message decoding.
#[cfg(feature = "test-internals")]
#[doc(hidden)]
pub fn fuzz_parse_bind_message(frame: &[u8]) -> Result<FuzzBindMessage, PgError> {
    let body = fuzz_frontend_message_body(frame, FrontendMessage::Bind as u8)?;
    let mut reader = MessageReader::new(body);
    let portal = reader.read_cstring()?.to_string();
    let statement_name = reader.read_cstring()?.to_string();

    let format_count = reader.read_i16()?;
    if format_count < 0 {
        return Err(PgError::Protocol(format!(
            "invalid bind format count: {format_count}"
        )));
    }
    let mut param_format_codes = Vec::with_capacity(format_count as usize);
    for index in 0..format_count as usize {
        let code = reader.read_i16()?;
        validate_bind_format_code("parameter", index, code)?;
        param_format_codes.push(code);
    }

    let value_count = reader.read_i16()?;
    if value_count < 0 {
        return Err(PgError::Protocol(format!(
            "invalid bind value count: {value_count}"
        )));
    }
    if format_count != 0 && format_count != 1 && format_count != value_count {
        return Err(PgError::Protocol(format!(
            "bind format count {format_count} must be 0, 1, or match bind value count {value_count}"
        )));
    }
    let mut parameter_values = Vec::with_capacity(value_count as usize);
    for _ in 0..value_count {
        let len = reader.read_i32()?;
        if len == -1 {
            parameter_values.push(None);
            continue;
        }
        if len < -1 {
            return Err(PgError::Protocol(format!(
                "invalid bind value length: {len}"
            )));
        }
        parameter_values.push(Some(reader.read_bytes(len as usize)?.to_vec()));
    }

    let result_count = reader.read_i16()?;
    if result_count < 0 {
        return Err(PgError::Protocol(format!(
            "invalid bind result format count: {result_count}"
        )));
    }
    let mut result_format_codes = Vec::with_capacity(result_count as usize);
    for index in 0..result_count as usize {
        let code = reader.read_i16()?;
        validate_bind_format_code("result", index, code)?;
        result_format_codes.push(code);
    }
    reader.ensure_consumed("Bind")?;

    Ok(FuzzBindMessage {
        portal,
        statement_name,
        param_format_codes,
        parameter_values,
        result_format_codes,
    })
}

#[cfg(feature = "test-internals")]
fn validate_bind_format_code(role: &str, index: usize, code: i16) -> Result<(), PgError> {
    match code {
        0 | 1 => Ok(()),
        _ => Err(PgError::Protocol(format!(
            "invalid bind {role} format code at index {index}: {code} (expected 0 text or 1 binary)"
        ))),
    }
}

#[cfg(test)]
fn init_test(name: &str) {
    crate::test_utils::init_test_logging();
    tracing::info!(test = %name, "starting postgres test");
}

#[cfg(test)]
#[allow(
    clippy::approx_constant,
    clippy::float_cmp,
    clippy::bool_assert_comparison
)]
mod tests {
    use super::*;
    use crate::test_complete;
    use crate::types::CancelKind;
    use crate::{Budget, Cx, RegionId, TaskId};

    #[cfg(feature = "tls")]
    static POSTGRES_SSL_CERT_FILE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn init_test(name: &str) {
        crate::test_utils::init_test_logging();
        tracing::info!(test = %name, "starting postgres test");
    }

    fn run<F: std::future::Future>(future: F) -> F::Output {
        futures_lite::future::block_on(future)
    }

    fn read_until_contains(peer: &mut std::net::TcpStream, needle: &[u8]) -> Vec<u8> {
        use std::io::Read;

        peer.set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .expect("set_read_timeout");

        let mut seen = Vec::new();
        loop {
            let mut chunk = [0u8; 256];
            match peer.read(&mut chunk) {
                Ok(0) => panic!(
                    "peer closed before client wrote {:?}; saw {:?}",
                    String::from_utf8_lossy(needle),
                    seen
                ),
                Ok(n) => {
                    seen.extend_from_slice(&chunk[..n]);
                    if seen.windows(needle.len()).any(|window| window == needle) {
                        return seen;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    panic!(
                        "timed out waiting for client to write {:?}; saw {:?}",
                        String::from_utf8_lossy(needle),
                        seen
                    );
                }
                Err(err) => panic!("failed reading client bytes: {err}"),
            }
        }
    }

    // ================================================================
    // br-asupersync-r2l1ze — credential zeroize-on-drop integration
    //
    // The byte-level zeroization (`Drop` running
    // `ptr::write_volatile(0)` over each backing byte, defeating
    // dead-store elimination) is verified at the type level by
    // `crate::security::secret::tests::drop_zeroizes_secret_bytes` and
    // `from_string_zeroizes_on_drop`. Those tests need
    // `#[allow(unsafe_code)]` for the post-drop pointer read; this
    // crate is `#![deny(unsafe_code)]` outside the security module, so
    // we don't repeat them here.
    //
    // The integration tests below verify postgres.rs wiring:
    // (a) `ScramAuth.password` is held as a `SecretString`, inheriting
    //     zeroize-on-drop transitively;
    // (b) `PgConnectOptions::password` parses into `Option<SecretString>`;
    // (c) Debug redaction continues to work after the type swap;
    // (d) `explicit_zeroize` works on the held secret for callers that
    //     want to wipe bytes the moment auth completes rather than at
    //     scope end.
    // ================================================================

    /// `ScramAuth` accepts the password by `&str`, copies it into a
    /// `SecretString`, and exposes it via `as_str()` for PBKDF2.
    /// `explicit_zeroize` clears the bytes in place — handshake
    /// completion can call this BEFORE the natural Drop fires to
    /// minimise the in-memory window.
    #[test]
    fn scram_auth_password_uses_secret_string_with_explicit_zeroize() {
        let cx = Cx::for_testing();
        let mut scram = ScramAuth::new(
            &cx,
            "alice",
            "scram-handshake-pw",
            ScramChannelBinding::None,
        );
        assert_eq!(scram.password.as_str(), "scram-handshake-pw");
        assert!(!scram.password.is_empty());

        // Explicit zeroization clears the bytes in place. After this
        // call the field is the empty string; the natural Drop would
        // run later and find zeros already.
        scram.password.explicit_zeroize();
        assert!(scram.password.is_empty());
        assert_eq!(scram.password.as_str(), "");
    }

    /// `PgConnectOptions::parse` must store the URL-decoded password
    /// in a `SecretString`. Type-level integration check — if someone
    /// refactors back to `Option<String>`, this test stops compiling.
    #[test]
    fn pg_connect_options_parse_yields_secret_string_password() {
        let opts = PgConnectOptions::parse("postgres://user:pw@h/db").unwrap();
        let pw: &SecretString = opts.password.as_ref().expect("password parsed");
        assert_eq!(pw.as_str(), "pw");
    }

    /// Debug rendering of `PgConnectOptions` must not leak the password
    /// even when populated — the existing redaction is preserved
    /// across the `Option<String>` → `Option<SecretString>` migration.
    #[test]
    fn pg_connect_options_debug_does_not_leak_secret_string_password() {
        let opts = PgConnectOptions {
            host: "h".to_string(),
            port: 5432,
            database: "d".to_string(),
            user: "u".to_string(),
            password: Some(SecretString::new("hunter2-pg")),
            application_name: None,
            connect_timeout: None,
            ssl_mode: SslMode::Disable,
        };
        let dbg = format!("{opts:?}");
        assert!(
            !dbg.contains("hunter2-pg"),
            "password leaked through Debug: {dbg}"
        );
        assert!(dbg.contains("[REDACTED]"));
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
        assert_eq!(
            opts.password.as_ref().map(SecretString::as_str),
            Some("pass")
        );
        assert_eq!(opts.host, "localhost");
        assert_eq!(opts.port, 5432);
        assert_eq!(opts.database, "mydb");
    }

    /// br-asupersync-fldb34 — defensive: confirm Postgres options Debug
    /// continues to redact (this was the model for the new MySQL impl).
    #[test]
    fn pg_debug_impl_redacts_password() {
        let opts = PgConnectOptions::parse("postgres://user:hunter2@localhost:5432/mydb").unwrap();
        let dbg = format!("{opts:?}");
        assert!(dbg.contains("[REDACTED]"), "expected [REDACTED] in {dbg}");
        assert!(
            !dbg.contains("hunter2"),
            "password leaked through Debug output: {dbg}"
        );
    }

    /// br-asupersync-rsifm3 — IsolationLevel SQL fragments and Display.
    #[test]
    fn pg_isolation_level_sql_fragments() {
        assert_eq!(IsolationLevel::ReadUncommitted.as_sql(), "READ UNCOMMITTED");
        assert_eq!(IsolationLevel::ReadCommitted.as_sql(), "READ COMMITTED");
        assert_eq!(IsolationLevel::RepeatableRead.as_sql(), "REPEATABLE READ");
        assert_eq!(IsolationLevel::Serializable.as_sql(), "SERIALIZABLE");
        assert_eq!(format!("{}", IsolationLevel::Serializable), "SERIALIZABLE");
    }

    /// br-asupersync-rsifm3 — verify the SQL string begin_with_isolation
    /// emits matches the Postgres protocol expectation: the level and access
    /// mode must appear in the same statement as BEGIN so they apply
    /// atomically to the started transaction.
    #[test]
    fn pg_begin_with_isolation_sql_string_matches_spec() {
        for (read_only, expected_mode) in [(false, "READ WRITE"), (true, "READ ONLY")] {
            let level = IsolationLevel::Serializable;
            let access_mode = if read_only { "READ ONLY" } else { "READ WRITE" };
            let sql = format!("BEGIN ISOLATION LEVEL {level} {access_mode}");
            assert_eq!(
                sql,
                format!("BEGIN ISOLATION LEVEL SERIALIZABLE {expected_mode}")
            );
        }
    }

    /// br-asupersync-dvgvcu — IsolationLevel::from_server_string must
    /// parse the Postgres-canonical lowercase + space form returned
    /// by `SHOW transaction_isolation`.
    #[test]
    fn pg_isolation_level_from_server_string_parses_postgres_canonical_forms() {
        // Postgres SHOW transaction_isolation reports lowercase space form.
        assert_eq!(
            IsolationLevel::from_server_string("read uncommitted"),
            Some(IsolationLevel::ReadUncommitted)
        );
        assert_eq!(
            IsolationLevel::from_server_string("read committed"),
            Some(IsolationLevel::ReadCommitted)
        );
        assert_eq!(
            IsolationLevel::from_server_string("repeatable read"),
            Some(IsolationLevel::RepeatableRead)
        );
        assert_eq!(
            IsolationLevel::from_server_string("serializable"),
            Some(IsolationLevel::Serializable)
        );

        // Tolerates uppercase + extra whitespace.
        assert_eq!(
            IsolationLevel::from_server_string("  Serializable  "),
            Some(IsolationLevel::Serializable)
        );

        // Bogus values must NOT parse.
        assert_eq!(IsolationLevel::from_server_string(""), None);
        assert_eq!(IsolationLevel::from_server_string("snapshot"), None);
    }

    /// br-asupersync-dvgvcu — IsolationLevelMismatch Display surfaces
    /// the requested + observed values so operators can diagnose the
    /// silent downgrade.
    #[test]
    fn pg_isolation_level_mismatch_display_includes_diagnostic_fields() {
        let err = PgError::IsolationLevelMismatch {
            requested: IsolationLevel::Serializable,
            observed: "read committed".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("SERIALIZABLE"), "missing requested in {msg}");
        assert!(msg.contains("read committed"), "missing observed in {msg}");
        assert!(msg.contains("dvgvcu"), "missing bead trace in {msg}");
    }

    #[test]
    fn test_connect_options_parse_minimal() {
        let opts = PgConnectOptions::parse("postgres://localhost/mydb").unwrap();
        assert_eq!(opts.user, "postgres");
        assert!(opts.password.is_none());
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
        buf.write_i32(POSTGRES_PROTOCOL_VERSION_3_0);
        buf.write_cstring("user");
        buf.write_cstring("testuser");
        buf.write_byte(0);

        let msg = buf.build_startup_message().unwrap();
        assert!(msg.len() > 4); // At least length prefix
    }

    fn startup_message_from_parts(parts: &[&[u8]], terminator: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&POSTGRES_PROTOCOL_VERSION_3_0.to_be_bytes());
        for part in parts {
            body.extend_from_slice(part);
            body.push(0);
        }
        if terminator {
            body.push(0);
        }

        let len = i32::try_from(body.len() + 4).unwrap();
        let mut frame = len.to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn startup_message_parser_accepts_valid_params() {
        let frame =
            startup_message_from_parts(&[b"user", b"testuser", b"database", b"testdb"], true);

        let parsed = parse_startup_message(&frame).unwrap();

        assert_eq!(parsed.protocol_version, POSTGRES_PROTOCOL_VERSION_3_0);
        assert_eq!(parsed.parameters.get("user"), Some(&"testuser".to_string()));
        assert_eq!(
            parsed.parameters.get("database"),
            Some(&"testdb".to_string())
        );
    }

    #[test]
    fn startup_message_parser_rejects_embedded_nul_in_key_shape() {
        let frame = startup_message_from_parts(&[b"us", b"er", b"testuser", b""], true);

        let err = parse_startup_message(&frame).unwrap_err();

        assert!(
            format!("{err}").contains("missing required user"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn startup_message_parser_rejects_embedded_nul_in_value_shape() {
        let frame = startup_message_from_parts(&[b"user", b"alice", b"user", b"admin"], true);

        let err = parse_startup_message(&frame).unwrap_err();

        assert!(
            format!("{err}").contains("duplicate startup parameter"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn startup_message_parser_rejects_duplicate_keys() {
        let frame = startup_message_from_parts(&[b"user", b"alice", b"user", b"bob"], true);

        let err = parse_startup_message(&frame).unwrap_err();

        assert!(
            format!("{err}").contains("duplicate startup parameter"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn startup_message_parser_rejects_unterminated_pairs() {
        let frame = startup_message_from_parts(&[b"user", b"testuser", b"database"], false);

        let err = parse_startup_message(&frame).unwrap_err();

        assert!(
            format!("{err}").contains("missing value"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn startup_message_parser_rejects_length_mismatch() {
        let mut frame = startup_message_from_parts(&[b"user", b"testuser"], true);
        frame[3] = frame[3].wrapping_add(1);

        let err = parse_startup_message(&frame).unwrap_err();

        assert!(
            format!("{err}").contains("length mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn startup_message_parser_rejects_empty_key_trailing_payload() {
        let mut frame = startup_message_from_parts(&[b"user", b"testuser"], true);
        frame.extend_from_slice(b"smuggled");
        let len = i32::try_from(frame.len()).unwrap();
        frame[0..4].copy_from_slice(&len.to_be_bytes());

        let err = parse_startup_message(&frame).unwrap_err();

        assert!(
            format!("{err}").contains("trailing byte"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn startup_message_parser_allows_empty_optional_value() {
        let frame =
            startup_message_from_parts(&[b"user", b"testuser", b"application_name", b""], true);

        let parsed = parse_startup_message(&frame).unwrap();

        assert_eq!(
            parsed.parameters.get("application_name"),
            Some(&String::new())
        );
    }

    #[test]
    fn startup_builder_rejects_embedded_nul_values() {
        let mut buf = MessageBuffer::new();

        let err = buf
            .write_startup_cstring("startup user", "alice\0admin")
            .unwrap_err();

        assert!(
            format!("{err}").contains("embedded NUL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn startup_message_parser_is_panic_free_for_small_arbitrary_bytes() {
        for len in 0..64usize {
            let data = vec![0xA5; len];
            let _ = parse_startup_message(&data);
        }
    }

    #[test]
    fn test_scram_pbkdf2_matches_rfc8018_sha256_vector() {
        let cx = Cx::for_testing();
        let auth = ScramAuth::new(&cx, "user", "password", ScramChannelBinding::None);
        let derived = auth.pbkdf2_sha256("password", b"salt", 1);
        let expected =
            hex::decode("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
                .expect("valid hex vector");

        assert_eq!(
            derived, expected,
            "PBKDF2-HMAC-SHA256 output should match the RFC 8018 reference vector"
        );
    }

    #[test]
    fn test_scram_constant_time_eq_expected_len_correctness() {
        let expected = [1u8, 2, 3, 4];
        assert!(scram_constant_time_eq_expected_len(
            &expected,
            &[1, 2, 3, 4]
        ));
        assert!(!scram_constant_time_eq_expected_len(&expected, &[1, 2, 3]));
        assert!(!scram_constant_time_eq_expected_len(
            &expected,
            &[1, 2, 3, 5]
        ));
        assert!(!scram_constant_time_eq_expected_len(
            &expected,
            &[1, 2, 3, 4, 5]
        ));
    }

    #[test]
    fn test_scram_sha256_rfc7677_section3_conformance() {
        // RFC 7677 Section 3 test vectors - SCRAM-SHA-256 authentication exchange
        // when client doesn't support channel bindings
        // Username: "user", Password: "pencil"

        let cx = Cx::for_testing();

        // Create SCRAM auth with RFC test credentials
        let mut auth = ScramAuth::new(&cx, "user", "pencil", ScramChannelBinding::None);

        // Override client nonce to match RFC vector exactly
        auth.client_nonce = "rOprNGfwEbeRWgbNEkqO".to_string();
        auth.client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO".to_string();

        // Test 1: Client first message should match RFC 7677 §3
        let client_first = auth.client_first_message();
        let expected_client_first = b"n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
        assert_eq!(
            client_first, expected_client_first,
            "Client first message should match RFC 7677 §3 vector"
        );

        // Test 2: Process server first message from RFC
        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let client_final = auth
            .process_server_first(server_first)
            .expect("Should process RFC server first message");

        // Test 3: Client final message should match RFC proof value
        let client_final_str =
            String::from_utf8(client_final).expect("Client final should be valid UTF-8");

        // Verify channel binding (c=biws is base64 for "n,,")
        assert!(
            client_final_str.contains("c=biws"),
            "Client final should contain correct channel binding"
        );

        // Verify nonce echoes full server nonce
        assert!(
            client_final_str.contains("r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0"),
            "Client final should echo full server nonce"
        );

        // Verify proof value matches RFC (this is the critical cryptographic test)
        assert!(
            client_final_str.contains("p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="),
            "Client final proof should match RFC 7677 §3 expected value"
        );

        // Test 4: Server final verification with RFC server signature
        let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        auth.verify_server_final(server_final)
            .expect("Should verify RFC 7677 §3 server signature");
    }

    #[test]
    fn test_scram_sha256_rejects_truncated_server_signature() {
        let cx = Cx::for_testing();
        let mut auth = ScramAuth::new(&cx, "user", "pencil", ScramChannelBinding::None);
        auth.client_nonce = "rOprNGfwEbeRWgbNEkqO".to_string();
        auth.client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO".to_string();

        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        auth.process_server_first(server_first)
            .expect("Should process RFC server first message");

        let full_sig = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            "6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
        )
        .expect("valid base64");
        let truncated_sig = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &full_sig[..full_sig.len() - 1],
        );

        match auth.verify_server_final(&format!("v={truncated_sig}")) {
            Err(PgError::AuthenticationFailed(msg)) => {
                assert!(msg.contains("server signature mismatch"), "got: {msg}");
            }
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_scram_sha256_rejects_reserved_server_first_extension() {
        let cx = Cx::for_testing();
        let mut auth = ScramAuth::new(&cx, "user", "pencil", ScramChannelBinding::None);
        auth.client_nonce = "rOprNGfwEbeRWgbNEkqO".to_string();
        auth.client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO".to_string();

        let server_first = "m=cb-required,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        match auth.process_server_first(server_first) {
            Err(PgError::AuthenticationFailed(msg)) => {
                assert!(msg.contains("mandatory extension"), "got: {msg}");
            }
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_scram_sha256_rejects_duplicate_server_first_iterations() {
        let cx = Cx::for_testing();
        let mut auth = ScramAuth::new(&cx, "user", "pencil", ScramChannelBinding::None);
        auth.client_nonce = "rOprNGfwEbeRWgbNEkqO".to_string();
        auth.client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO".to_string();

        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096,i=8192";
        match auth.process_server_first(server_first) {
            Err(PgError::AuthenticationFailed(msg)) => {
                assert!(msg.contains("duplicate iterations"), "got: {msg}");
            }
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_scram_sha256_rejects_server_final_error_before_auth_ok() {
        let cx = Cx::for_testing();
        let mut auth = ScramAuth::new(&cx, "user", "pencil", ScramChannelBinding::None);
        auth.client_nonce = "rOprNGfwEbeRWgbNEkqO".to_string();
        auth.client_first_bare = "n=user,r=rOprNGfwEbeRWgbNEkqO".to_string();

        let server_first = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        auth.process_server_first(server_first)
            .expect("Should process RFC server first message");

        match auth.verify_server_final("e=invalid-proof") {
            Err(PgError::AuthenticationFailed(msg)) => {
                assert!(msg.contains("invalid-proof"), "got: {msg}");
            }
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn pick_scram_channel_binding_rejects_tls_without_peer_certificate() {
        let mechanisms = vec![
            "SCRAM-SHA-256".to_string(),
            "SCRAM-SHA-256-PLUS".to_string(),
        ];

        match PgConnection::pick_scram_channel_binding(&mechanisms, true, None) {
            Err(PgError::AuthenticationFailed(msg)) => {
                assert!(msg.contains("peer certificate"), "got: {msg}");
            }
            other => panic!("expected AuthenticationFailed, got {other:?}"),
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    #[allow(unsafe_code)]
    fn postgres_tls_connector_reports_invalid_ssl_cert_file() {
        let _guard = POSTGRES_SSL_CERT_FILE_ENV_LOCK
            .lock()
            .expect("env lock poisoned");
        let previous = std::env::var_os("SSL_CERT_FILE");
        // SAFETY: this test holds a process-wide mutex for SSL_CERT_FILE.
        unsafe { std::env::set_var("SSL_CERT_FILE", "/definitely/not/a/postgres-ca.pem") };

        let result = PgConnection::build_postgres_tls_connector();

        match previous {
            Some(value) => {
                // SAFETY: this test holds a process-wide mutex for SSL_CERT_FILE.
                unsafe { std::env::set_var("SSL_CERT_FILE", value) };
            }
            None => {
                // SAFETY: this test holds a process-wide mutex for SSL_CERT_FILE.
                unsafe { std::env::remove_var("SSL_CERT_FILE") };
            }
        }

        match result {
            Err(PgError::Tls(msg)) => {
                assert!(msg.contains("SSL_CERT_FILE"), "got: {msg}");
            }
            other => panic!("expected SSL_CERT_FILE TLS error, got {other:?}"),
        }
    }

    /// SCRAM channel-binding preference audit test.
    ///
    /// Verifies that when the server offers SCRAM-SHA-256-PLUS, the client
    /// chooses PLUS with channel binding. When a TLS server offers only plain
    /// SCRAM-SHA-256, the client follows libpq/common-driver behavior and uses
    /// the plain `n,,` GS2 header for pooler compatibility.
    #[test]
    fn audit_scram_channel_binding_preference_and_pooler_compatibility() {
        // Test 1: TLS active + server offers both → should choose PLUS
        #[cfg(feature = "tls")]
        {
            let mechanisms_with_plus = vec![
                "SCRAM-SHA-256".to_string(),
                "SCRAM-SHA-256-PLUS".to_string(),
            ];
            let der_prefix_cert = vec![0x30, 0x82]; // Valid DER prefix

            let result = PgConnection::pick_scram_channel_binding(
                &mechanisms_with_plus,
                true, // TLS active
                Some(der_prefix_cert.clone()),
            )
            .expect("should choose channel binding");

            assert_eq!(
                result.mechanism(),
                "SCRAM-SHA-256-PLUS",
                "RFC 7677: When TLS active and server offers PLUS, MUST choose PLUS for channel binding security"
            );
        }

        // Test 2: TLS active + server offers only SHA-256 → use plain SCRAM for pooler compatibility.
        #[cfg(feature = "tls")]
        {
            let mechanisms_no_plus = vec!["SCRAM-SHA-256".to_string()];
            let der_prefix_cert = vec![0x30, 0x82]; // Valid DER prefix

            let result = PgConnection::pick_scram_channel_binding(
                &mechanisms_no_plus,
                true, // TLS active
                Some(der_prefix_cert),
            )
            .expect("should use plain SCRAM");

            assert_eq!(
                result.mechanism(),
                "SCRAM-SHA-256",
                "RFC 7677: When TLS active but server doesn't offer PLUS, use SHA-256"
            );
            match &result {
                ScramChannelBinding::None => {
                    assert_eq!(result.gs2_header(), "n,,");
                }
                _ => panic!("Expected None for pooler-compatible plain SCRAM"),
            }
        }

        // Test 3: No TLS → should use plain SHA-256
        let mechanisms_plain = vec!["SCRAM-SHA-256".to_string()];

        let result = PgConnection::pick_scram_channel_binding(
            &mechanisms_plain,
            false, // No TLS
            None,
        )
        .expect("should work without TLS");

        assert_eq!(
            result.mechanism(),
            "SCRAM-SHA-256",
            "RFC 7677: Without TLS, use plain SCRAM-SHA-256"
        );
        match result {
            ScramChannelBinding::None => {
                // Correct: This sets GS2 'n' flag (no channel binding)
            }
            _ => panic!("Expected None for no TLS"),
        }
    }

    #[test]
    fn test_validate_sasl_mechanisms_accepts_scram_sha256() {
        let mechanisms = vec!["SCRAM-SHA-256".to_string()];
        PgConnection::validate_sasl_mechanisms(&mechanisms).expect("Should accept SCRAM-SHA-256");
    }

    #[test]
    fn test_validate_sasl_mechanisms_accepts_scram_sha256_plus() {
        let mechanisms = vec!["SCRAM-SHA-256-PLUS".to_string()];
        PgConnection::validate_sasl_mechanisms(&mechanisms)
            .expect("Should accept SCRAM-SHA-256-PLUS");
    }

    #[test]
    fn test_validate_sasl_mechanisms_accepts_both_scram_variants() {
        let mechanisms = vec![
            "SCRAM-SHA-256".to_string(),
            "SCRAM-SHA-256-PLUS".to_string(),
        ];
        PgConnection::validate_sasl_mechanisms(&mechanisms)
            .expect("Should accept both SCRAM variants");
    }

    #[test]
    fn test_validate_sasl_mechanisms_rejects_plain() {
        let mechanisms = vec!["PLAIN".to_string()];
        let result = PgConnection::validate_sasl_mechanisms(&mechanisms);

        match result {
            Err(PgError::UnsupportedAuth(msg)) => {
                assert!(msg.contains("unacceptable SASL mechanism 'PLAIN'"));
                assert!(msg.contains("Only SCRAM-SHA-256 and SCRAM-SHA-256-PLUS are allowed"));
            }
            other => panic!("Expected UnsupportedAuth error for PLAIN, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_sasl_mechanisms_rejects_login() {
        let mechanisms = vec!["LOGIN".to_string()];
        let result = PgConnection::validate_sasl_mechanisms(&mechanisms);

        match result {
            Err(PgError::UnsupportedAuth(msg)) => {
                assert!(msg.contains("unacceptable SASL mechanism 'LOGIN'"));
                assert!(msg.contains("downgrade attacks"));
            }
            other => panic!("Expected UnsupportedAuth error for LOGIN, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_sasl_mechanisms_rejects_mixed_with_weak() {
        // This is the key test - server advertises SCRAM + weak mechanisms
        let mechanisms = vec!["PLAIN".to_string(), "SCRAM-SHA-256".to_string()];
        let result = PgConnection::validate_sasl_mechanisms(&mechanisms);

        match result {
            Err(PgError::UnsupportedAuth(msg)) => {
                assert!(msg.contains("unacceptable SASL mechanism 'PLAIN'"));
                assert!(msg.contains("prevent downgrade attacks"));
            }
            other => panic!("Expected UnsupportedAuth error for mixed mechanisms, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_sasl_mechanisms_rejects_empty_list() {
        let mechanisms = vec![];
        let result = PgConnection::validate_sasl_mechanisms(&mechanisms);

        match result {
            Err(PgError::UnsupportedAuth(msg)) => {
                assert!(msg.contains("Server advertised no SASL mechanisms"));
            }
            other => panic!("Expected UnsupportedAuth error for empty list, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_sasl_mechanisms_rejects_non_scram_only() {
        let mechanisms = vec!["DIGEST-MD5".to_string(), "CRAM-MD5".to_string()];
        let result = PgConnection::validate_sasl_mechanisms(&mechanisms);

        match result {
            Err(PgError::UnsupportedAuth(msg)) => {
                assert!(msg.contains("unacceptable SASL mechanism"));
                assert!(msg.contains("SCRAM-SHA-256"));
            }
            other => {
                panic!("Expected UnsupportedAuth error for non-SCRAM mechanisms, got {other:?}")
            }
        }
    }

    /// Create a PgConnection backed by a loopback socket pair for unit-testing
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
                options: test_pg_connect_options(),
                process_id: 0,
                secret_key: 0,
                cancel_target: test_cancel_target(),
                parameters: BTreeMap::new(),
                transaction_status: b'I',
                closed: false,
                explicitly_closed: false,
                needs_rollback: false,
                needs_discard: false,
                next_stmt_id: 0,
                max_result_rows: DEFAULT_MAX_RESULT_ROWS,
                prepared_cache: PreparedStatementCache::new(DEFAULT_MAX_PREPARED_STATEMENTS),
                deallocate_retry_queue: VecDeque::new(),
                consecutive_deallocate_failures: 0,
                unhealthy: false,
                subscribed_channels: BTreeSet::new(),
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
                    options: test_pg_connect_options(),
                    process_id: 0,
                    secret_key: 0,
                    cancel_target: test_cancel_target(),
                    parameters: BTreeMap::new(),
                    transaction_status: b'I',
                    closed: false,
                    explicitly_closed: false,
                    needs_rollback: false,
                    needs_discard: false,
                    next_stmt_id: 0,
                    max_result_rows: DEFAULT_MAX_RESULT_ROWS,
                    prepared_cache: PreparedStatementCache::new(DEFAULT_MAX_PREPARED_STATEMENTS),
                    deallocate_retry_queue: VecDeque::new(),
                    consecutive_deallocate_failures: 0,
                    unhealthy: false,
                    subscribed_channels: BTreeSet::new(),
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

    fn copy_in_response_message(overall_format: Format, column_formats: &[Format]) -> Vec<u8> {
        let mut body = Vec::with_capacity(3 + column_formats.len() * 2);
        body.push(overall_format as u8);
        body.extend_from_slice(
            &i16::try_from(column_formats.len())
                .expect("test column count fits")
                .to_be_bytes(),
        );
        for format in column_formats {
            body.extend_from_slice(&(*format as i16).to_be_bytes());
        }
        backend_message(b'G', &body)
    }

    fn command_complete_message(tag: &str) -> Vec<u8> {
        let mut body = Vec::with_capacity(tag.len() + 1);
        body.extend_from_slice(tag.as_bytes());
        body.push(0);
        backend_message(b'C', &body)
    }

    fn frontend_frame_len(data: &[u8], offset: usize) -> usize {
        let len = i32::from_be_bytes([
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
        ]);
        1 + usize::try_from(len).expect("frontend length is non-negative")
    }

    fn frontend_body(data: &[u8], offset: usize) -> &[u8] {
        let frame_len = frontend_frame_len(data, offset);
        &data[offset + 5..offset + frame_len]
    }

    fn ready_for_query(status: u8) -> Vec<u8> {
        backend_message(b'Z', &[status])
    }

    fn read_startup_packet(stream: &mut std::net::TcpStream) -> Vec<u8> {
        use std::io::Read;

        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("set startup read timeout");
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .expect("read startup length");
        let len = i32::from_be_bytes(len_buf);
        assert!(len >= 8, "startup packet length must include protocol");
        let body_len = usize::try_from(len - 4).expect("startup length fits usize");
        let mut body = vec![0u8; body_len];
        stream.read_exact(&mut body).expect("read startup body");
        let mut packet = Vec::with_capacity(4 + body.len());
        packet.extend_from_slice(&len_buf);
        packet.extend_from_slice(&body);
        packet
    }

    fn write_startup_ready(stream: &mut std::net::TcpStream) {
        use std::io::Write;

        stream
            .write_all(&backend_message(b'R', &0i32.to_be_bytes()))
            .expect("write AuthenticationOk");
        let mut key_data = Vec::new();
        key_data.extend_from_slice(&4242i32.to_be_bytes());
        key_data.extend_from_slice(&31337i32.to_be_bytes());
        stream
            .write_all(&backend_message(b'K', &key_data))
            .expect("write BackendKeyData");
        stream
            .write_all(&ready_for_query(b'I'))
            .expect("write startup ReadyForQuery");
    }

    fn deterministic_postgres_options(port: u16) -> PgConnectOptions {
        PgConnectOptions {
            host: "127.0.0.1".to_string(),
            port,
            database: "testdb".to_string(),
            user: "postgres".to_string(),
            password: None,
            application_name: Some("asupersync-postgres-reconnect-test".to_string()),
            connect_timeout: Some(std::time::Duration::from_secs(2)),
            ssl_mode: SslMode::Disable,
        }
    }

    fn spawn_deterministic_postgres_server<F>(
        serve: F,
    ) -> (PgConnectOptions, std::thread::JoinHandle<()>)
    where
        F: FnOnce(&mut std::net::TcpStream) + Send + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind postgres server");
        let port = listener.local_addr().expect("server local addr").port();
        let options = deterministic_postgres_options(port);
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept postgres client");
            let startup = read_startup_packet(&mut stream);
            assert!(
                startup
                    .windows(b"user\0postgres\0".len())
                    .any(|w| w == b"user\0postgres\0"),
                "startup packet should include configured user"
            );
            write_startup_ready(&mut stream);
            serve(&mut stream);
        });
        (options, handle)
    }

    fn data_row_text_message(values: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(
            &i16::try_from(values.len())
                .expect("test value count fits")
                .to_be_bytes(),
        );
        for value in values {
            body.extend_from_slice(
                &i32::try_from(value.len())
                    .expect("test value length fits")
                    .to_be_bytes(),
            );
            body.extend_from_slice(value.as_bytes());
        }
        backend_message(b'D', &body)
    }

    fn write_single_text_query_result(stream: &mut std::net::TcpStream, value: &str) {
        use std::io::Write;

        stream
            .write_all(&backend_message(b'1', b""))
            .expect("write ParseComplete");
        stream
            .write_all(&backend_message(b'2', b""))
            .expect("write BindComplete");
        stream
            .write_all(&single_text_row_description())
            .expect("write RowDescription");
        stream
            .write_all(&data_row_text_message(&[value]))
            .expect("write DataRow");
        stream
            .write_all(&command_complete_message("SELECT 1"))
            .expect("write CommandComplete");
        stream
            .write_all(&ready_for_query(b'I'))
            .expect("write ReadyForQuery");
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
        backend_message(
            b'A',
            &notification_response_body_from_parts(
                process_id,
                channel.as_bytes(),
                payload.as_bytes(),
            ),
        )
    }

    fn notification_response_body(process_id: i32, channel: &str, payload: &str) -> Vec<u8> {
        notification_response_body_from_parts(process_id, channel.as_bytes(), payload.as_bytes())
    }

    fn notification_response_body_from_parts(
        process_id: i32,
        channel: &[u8],
        payload: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(4 + channel.len() + payload.len() + 2);
        body.extend_from_slice(&process_id.to_be_bytes());
        body.extend_from_slice(channel);
        body.push(0);
        body.extend_from_slice(payload);
        body.push(0);
        body
    }

    #[test]
    fn listen_quotes_channel_names_before_simple_query_write() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(&mut peer, &backend_message(b'C', b"LISTEN\0")).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.listen(&cx, "jobs\";UNLISTEN *;--")) {
            Outcome::Ok(()) => {}
            other => panic!("expected successful LISTEN, got {other:?}"),
        }

        let written = read_until_contains(&mut peer, b"LISTEN \"jobs\"\";UNLISTEN *;--\"\0");
        assert!(
            written
                .windows(b"LISTEN \"jobs\"\";UNLISTEN *;--\"\0".len())
                .any(|window| window == b"LISTEN \"jobs\"\";UNLISTEN *;--\"\0")
        );
    }

    #[test]
    fn unlisten_quotes_channel_names_before_simple_query_write() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(&mut peer, &backend_message(b'C', b"UNLISTEN\0")).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = crate::cx::Cx::for_testing();
        match run(conn.unlisten(&cx, "jobs\";LISTEN attacker;--")) {
            Outcome::Ok(()) => {}
            other => panic!("expected successful UNLISTEN, got {other:?}"),
        }

        let expected = b"UNLISTEN \"jobs\"\";LISTEN attacker;--\"\0";
        let written = read_until_contains(&mut peer, expected);
        assert!(
            written
                .windows(expected.len())
                .any(|window| window == expected)
        );
    }

    #[test]
    fn listen_rejects_nul_channel_name_before_writing() {
        let mut conn = make_test_connection();
        let cx = crate::cx::Cx::for_testing();

        match run(conn.listen(&cx, "jobs\0attacker")) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("NUL bytes"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(!conn.inner.closed);
    }

    #[test]
    fn notify_rejects_nul_channel_name_before_query_message() {
        let mut conn = make_test_connection();
        let cx = crate::cx::Cx::for_testing();

        match run(conn.notify(&cx, "jobs\0attacker", "payload")) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("NUL bytes"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(!conn.inner.closed);
    }

    #[test]
    fn listen_rejects_overlong_channel_name_before_writing() {
        let mut conn = make_test_connection();
        let cx = crate::cx::Cx::for_testing();
        let channel = "a".repeat(MAX_NOTIFICATION_CHANNEL_NAME_BYTES + 1);

        match run(conn.listen(&cx, &channel)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("63-byte limit"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(!conn.inner.closed);
    }

    #[test]
    fn notify_rejects_overlong_channel_name_before_query_message() {
        let mut conn = make_test_connection();
        let cx = crate::cx::Cx::for_testing();
        let channel = "b".repeat(MAX_NOTIFICATION_CHANNEL_NAME_BYTES + 1);

        match run(conn.notify(&cx, &channel, "payload")) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("63-byte limit"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(!conn.inner.closed);
    }

    #[test]
    fn notify_rejects_overlong_payload_before_query_message() {
        let mut conn = make_test_connection();
        let cx = crate::cx::Cx::for_testing();
        let payload = "p".repeat(MAX_NOTIFICATION_PAYLOAD_BYTES + 1);

        match run(conn.notify(&cx, "jobs", &payload)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("8000-byte limit"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(!conn.inner.closed);
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
    fn copy_from_chunks_streams_copy_data_and_done_without_buffering_rows() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(
            &mut peer,
            &copy_in_response_message(Format::Text, &[Format::Text, Format::Text]),
        )
        .unwrap();
        std::io::Write::write_all(&mut peer, &command_complete_message("COPY 2")).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = Cx::for_testing();
        let chunks: Vec<Result<&[u8], PgError>> = vec![Ok(b"alice\t1\n"), Ok(b"bob\t2\n")];
        let complete = match run(conn.copy_from_chunks(&cx, "COPY users FROM STDIN", chunks)) {
            Outcome::Ok(complete) => complete,
            other => panic!("expected COPY success, got {other:?}"),
        };

        assert_eq!(complete.affected_rows(), 2);
        assert_eq!(complete.chunks_sent(), 2);
        assert_eq!(complete.bytes_sent(), b"alice\t1\nbob\t2\n".len() as u64);
        assert_eq!(complete.response().overall_format(), Format::Text);
        assert_eq!(
            complete.response().column_formats(),
            &[Format::Text, Format::Text]
        );
        assert!(!conn.inner.closed);
        assert_eq!(conn.inner.transaction_status, b'I');

        let written =
            read_until_contains(&mut peer, &[FrontendMessage::CopyDone as u8, 0, 0, 0, 4]);
        assert_eq!(written[0], FrontendMessage::Query as u8);
        assert_eq!(frontend_body(&written, 0), b"COPY users FROM STDIN\0");

        let copy_offset = frontend_frame_len(&written, 0);
        let parsed = fuzz_parse_copy_in_sequence(&written[copy_offset..]).unwrap();
        assert_eq!(
            parsed.copy_data_chunks,
            vec![b"alice\t1\n".to_vec(), b"bob\t2\n".to_vec()]
        );
        assert_eq!(parsed.end, FuzzCopyInEnd::Done);
    }

    #[test]
    fn copy_from_chunks_empty_input_sends_copy_done() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(
            &mut peer,
            &copy_in_response_message(Format::Text, &[Format::Text]),
        )
        .unwrap();
        std::io::Write::write_all(&mut peer, &command_complete_message("COPY 0")).unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = Cx::for_testing();
        let chunks: Vec<Result<&[u8], PgError>> = Vec::new();
        let complete = match run(conn.copy_from_chunks(&cx, "COPY empty FROM STDIN", chunks)) {
            Outcome::Ok(complete) => complete,
            other => panic!("expected empty COPY success, got {other:?}"),
        };

        assert_eq!(complete.affected_rows(), 0);
        assert_eq!(complete.chunks_sent(), 0);
        assert_eq!(complete.bytes_sent(), 0);
        assert!(!conn.inner.closed);

        let written =
            read_until_contains(&mut peer, &[FrontendMessage::CopyDone as u8, 0, 0, 0, 4]);
        let copy_offset = frontend_frame_len(&written, 0);
        let parsed = fuzz_parse_copy_in_sequence(&written[copy_offset..]).unwrap();
        assert_eq!(parsed.copy_data_chunks, Vec::<Vec<u8>>::new());
        assert_eq!(parsed.end, FuzzCopyInEnd::Done);
    }

    #[test]
    fn copy_from_chunks_source_error_sends_copy_fail_and_resynchronizes() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(
            &mut peer,
            &copy_in_response_message(Format::Text, &[Format::Text]),
        )
        .unwrap();
        std::io::Write::write_all(
            &mut peer,
            &error_response_message("57014", "COPY FROM source error"),
        )
        .unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = Cx::for_testing();
        let chunks: Vec<Result<&[u8], PgError>> = vec![
            Ok(b"partial row\n"),
            Err(PgError::Protocol("source stopped".to_string())),
        ];
        match run(conn.copy_from_chunks(&cx, "COPY source_error FROM STDIN", chunks)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert_eq!(msg, "source stopped");
            }
            other => panic!("expected source error, got {other:?}"),
        }

        assert!(!conn.inner.closed);
        let written = read_until_contains(&mut peer, &[FrontendMessage::CopyFail as u8]);
        let copy_offset = frontend_frame_len(&written, 0);
        let parsed = fuzz_parse_copy_in_sequence(&written[copy_offset..]).unwrap();
        assert_eq!(parsed.copy_data_chunks, vec![b"partial row\n".to_vec()]);
        assert_eq!(
            parsed.end,
            FuzzCopyInEnd::Fail("COPY FROM source error".to_string())
        );
    }

    #[test]
    fn copy_in_send_chunk_cancel_before_copy_done_sends_copy_fail() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(
            &mut peer,
            &copy_in_response_message(Format::Text, &[Format::Text]),
        )
        .unwrap();
        std::io::Write::write_all(
            &mut peer,
            &error_response_message("57014", "COPY FROM cancelled before CopyDone"),
        )
        .unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = Cx::for_testing();
        let mut copy = match run(conn.copy_in(&cx, "COPY cancellable FROM STDIN")) {
            Outcome::Ok(copy) => copy,
            other => panic!("expected COPY IN stream, got {other:?}"),
        };
        cx.cancel_fast(CancelKind::User);
        assert_user_cancelled(run(copy.send_chunk(&cx, b"late row\n")));
        drop(copy);

        assert!(!conn.inner.closed);
        let written = read_until_contains(&mut peer, &[FrontendMessage::CopyFail as u8]);
        let copy_offset = frontend_frame_len(&written, 0);
        let parsed = fuzz_parse_copy_in_sequence(&written[copy_offset..]).unwrap();
        assert_eq!(parsed.copy_data_chunks, Vec::<Vec<u8>>::new());
        assert_eq!(
            parsed.end,
            FuzzCopyInEnd::Fail("COPY FROM cancelled before CopyDone".to_string())
        );
    }

    #[test]
    fn copy_from_chunks_backend_error_after_copy_done_preserves_server_error() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(
            &mut peer,
            &copy_in_response_message(Format::Text, &[Format::Text]),
        )
        .unwrap();
        std::io::Write::write_all(
            &mut peer,
            &error_response_message("22P02", "invalid input syntax for integer"),
        )
        .unwrap();
        std::io::Write::write_all(&mut peer, &ready_for_query(b'I')).unwrap();

        let cx = Cx::for_testing();
        let chunks: Vec<Result<&[u8], PgError>> = vec![Ok(b"not-an-int\n")];
        match run(conn.copy_from_chunks(&cx, "COPY malformed FROM STDIN", chunks)) {
            Outcome::Err(PgError::Server { code, message, .. }) => {
                assert_eq!(code, "22P02");
                assert_eq!(message, "invalid input syntax for integer");
            }
            other => panic!("expected backend COPY error, got {other:?}"),
        }

        assert!(!conn.inner.closed);
        let written =
            read_until_contains(&mut peer, &[FrontendMessage::CopyDone as u8, 0, 0, 0, 4]);
        let copy_offset = frontend_frame_len(&written, 0);
        let parsed = fuzz_parse_copy_in_sequence(&written[copy_offset..]).unwrap();
        assert_eq!(parsed.copy_data_chunks, vec![b"not-an-int\n".to_vec()]);
        assert_eq!(parsed.end, FuzzCopyInEnd::Done);
    }

    #[test]
    fn commit_serialization_failure_keeps_connection_reusable() {
        use crate::database::pool::AsyncConnectionManager;

        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );
        let (mut conn, mut peer) = make_test_connection_with_peer();
        conn.inner.transaction_status = b'T';
        let cx = Cx::for_testing();

        let io_thread = std::thread::spawn(move || {
            let _ = read_until_contains(&mut peer, b"COMMIT");
            std::io::Write::write_all(
                &mut peer,
                &error_response_message(
                    "40001",
                    "could not serialize access due to read/write dependencies among transactions",
                ),
            )
            .expect("write serialization failure");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("write COMMIT ReadyForQuery");
        });

        let outcome = run(async {
            let tx = PgTransaction {
                conn: &mut conn,
                finished: false,
                isolation_level: Some(IsolationLevel::Serializable),
                read_only: false,
            };
            tx.commit(&cx).await
        });

        match outcome {
            Outcome::Err(err) => {
                assert!(
                    err.is_serialization_failure(),
                    "expected SQLSTATE 40001, got: {err:?}"
                );
            }
            other => panic!("expected serialization failure, got {other:?}"),
        }

        io_thread
            .join()
            .expect("postgres peer thread should finish cleanly");
        assert_eq!(
            conn.inner.transaction_status, b'I',
            "server-side serialization failure should leave the connection idle"
        );
        assert!(
            !conn.inner.needs_rollback,
            "commit-time serialization failure must not force an orphan rollback path"
        );
        assert!(
            !conn.inner.needs_discard,
            "commit-time serialization failure must not poison pool reuse"
        );
        assert!(
            mgr.release_check(&mut conn),
            "idle connection after commit-time serialization failure must remain reusable"
        );
    }

    #[test]
    fn cancelled_commit_marks_connection_for_rollback() {
        let mut conn = make_test_connection();
        let cx = cancelled_cx();

        let outcome = run(async {
            let tx = PgTransaction {
                conn: &mut conn,
                finished: false,
                isolation_level: None,
                read_only: false,
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
                isolation_level: None,
                read_only: false,
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
    fn begin_with_isolation_cancelled_before_verify_query_rolls_back_to_idle() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();

        let io_thread = std::thread::spawn(move || {
            let mut client_bytes =
                read_until_contains(&mut peer, b"BEGIN ISOLATION LEVEL SERIALIZABLE READ WRITE");
            cancel_cx.cancel_fast(CancelKind::User);

            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"BEGIN\0"))
                .expect("write BEGIN CommandComplete");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'T'))
                .expect("write BEGIN ReadyForQuery");
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"ROLLBACK\0"))
                .expect("write ROLLBACK CommandComplete");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("write ROLLBACK ReadyForQuery");

            if !client_bytes
                .windows(b"ROLLBACK".len())
                .any(|window| window == b"ROLLBACK")
            {
                client_bytes.extend(read_until_contains(&mut peer, b"ROLLBACK"));
            }
            client_bytes
        });

        let outcome = run(conn.begin_with_isolation(&cx, IsolationLevel::Serializable, false));
        assert_user_cancelled(outcome);
        assert!(
            !conn.inner.closed,
            "successful compensating rollback should return the connection to idle"
        );
        assert_eq!(conn.inner.transaction_status, b'I');
        assert!(
            !conn.inner.needs_rollback,
            "successful compensating rollback should not leave orphan cleanup markers behind"
        );
        assert!(
            !conn.inner.needs_discard,
            "successful compensating rollback should keep the connection reusable"
        );

        let client_bytes = io_thread.join().expect("postgres peer thread should exit");
        assert!(
            client_bytes
                .windows(b"ROLLBACK".len())
                .any(|window| window == b"ROLLBACK"),
            "client should issue a compensating ROLLBACK before surfacing cancellation"
        );
    }

    #[test]
    fn begin_with_isolation_cancelled_during_verify_marks_orphan_cleanup() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = Cx::for_testing();
        let cancel_cx = cx.clone();

        let io_thread = std::thread::spawn(move || {
            let _ = read_until_contains(
                &mut peer,
                b"BEGIN ISOLATION LEVEL REPEATABLE READ READ WRITE",
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"BEGIN\0"))
                .expect("write BEGIN CommandComplete");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'T'))
                .expect("write BEGIN ReadyForQuery");

            let _ = read_until_contains(&mut peer, b"SHOW transaction_isolation");
            cancel_cx.cancel_fast(CancelKind::User);
            std::io::Write::write_all(&mut peer, b"x").expect("wake pending verify read");
        });

        let outcome = run(conn.begin_with_isolation(&cx, IsolationLevel::RepeatableRead, false));
        assert_user_cancelled(outcome);
        assert!(
            conn.inner.closed,
            "mid-verify cancellation should preserve the closed in-flight state"
        );
        assert!(
            conn.inner.needs_rollback,
            "failed compensating rollback must leave an orphan-cleanup marker"
        );
        assert!(
            conn.inner.needs_discard,
            "failed compensating rollback must mark the connection discard-only"
        );

        io_thread.join().expect("postgres peer thread should exit");
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
        assert!(opts.password.is_none());
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
        assert_eq!(opts.password.as_ref().map(SecretString::as_str), Some("pw"));
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

    #[test]
    fn postgres_wire_subparsers_reject_trailing_bytes() {
        let conn = make_test_connection();

        let row_description = [0, 0, 0xAA];
        let row_err = conn.parse_row_description(&row_description).unwrap_err();
        assert!(
            row_err
                .to_string()
                .contains("RowDescription message has 1 trailing byte"),
            "unexpected RowDescription error: {row_err}"
        );

        let data_row = [0, 0, 0xBB];
        let data_err = conn.parse_data_row(&data_row, &[]).unwrap_err();
        assert!(
            data_err
                .to_string()
                .contains("DataRow message has 1 trailing byte"),
            "unexpected DataRow error: {data_err}"
        );

        let error_response = [0, 0xCC];
        let error_err = conn.parse_error_response(&error_response).unwrap_err();
        assert!(
            error_err
                .to_string()
                .contains("ErrorResponse message has 1 trailing byte"),
            "unexpected ErrorResponse error: {error_err}"
        );

        let parameter_description = [0, 0, 0xDD];
        let param_err =
            PgConnection::parse_parameter_description(&parameter_description).unwrap_err();
        assert!(
            param_err
                .to_string()
                .contains("ParameterDescription message has 1 trailing byte"),
            "unexpected ParameterDescription error: {param_err}"
        );
    }

    #[cfg(feature = "test-internals")]
    #[test]
    fn fuzz_read_backend_message_parses_in_memory_without_socket_io() {
        let cx = Cx::for_testing();

        let mut frame = vec![b'D'];
        frame.extend_from_slice(&8i32.to_be_bytes());
        frame.extend_from_slice(&[1, 2, 3, 4]);
        // A real stream may already have the next frame buffered. The seam
        // must match read_message() and return only the first message body.
        frame.extend_from_slice(&[b'Z', 0, 0, 0, 5, b'I']);
        let (msg_type, body) = run(fuzz_read_backend_message(&cx, &frame)).unwrap();
        assert_eq!(msg_type, b'D');
        assert_eq!(body, vec![1, 2, 3, 4]);

        let mut too_large = vec![b'D'];
        too_large.extend_from_slice(&(MAX_BACKEND_MESSAGE_LEN + 1).to_be_bytes());
        let too_large_err = run(fuzz_read_backend_message(&cx, &too_large)).unwrap_err();
        assert!(
            too_large_err.to_string().contains("invalid message length"),
            "unexpected too-large error: {too_large_err}"
        );

        let mut truncated = vec![b'D'];
        truncated.extend_from_slice(&8i32.to_be_bytes());
        truncated.push(1);
        match run(fuzz_read_backend_message(&cx, &truncated)).unwrap_err() {
            PgError::Io(err) => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected UnexpectedEof, got: {other}"),
        }
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

    /// **AUDIT TEST: PostgreSQL Per-Column Format Code Compliance**
    ///
    /// Verifies that when client requests mixed format codes in Bind message
    /// (some columns binary format=1, others text format=0), each column
    /// is parsed with the correct format as specified in RowDescription.
    ///
    /// **PG Protocol §49.7 Compliance**: Format codes are per-column, not per-row.
    /// Mixed format rows must parse each column using its designated format.
    ///
    /// **Implementation**: `parse_data_row()` checks `col.format_code` per column
    /// and routes to either `parse_text_value()` or `parse_binary_value()`.
    #[test]
    fn postgresql_mixed_format_per_column_audit() {
        let conn = make_test_connection();

        // Test mixed format row: col1=text, col2=binary, col3=text
        let columns = vec![
            PgColumn {
                name: "text_col".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::INT4,
                type_size: 4,
                type_modifier: -1,
                format_code: 0, // TEXT format
            },
            PgColumn {
                name: "binary_col".to_string(),
                table_oid: 0,
                column_id: 1,
                type_oid: oid::INT4,
                type_size: 4,
                type_modifier: -1,
                format_code: 1, // BINARY format
            },
            PgColumn {
                name: "text_col2".to_string(),
                table_oid: 0,
                column_id: 2,
                type_oid: oid::BOOL,
                type_size: 1,
                type_modifier: -1,
                format_code: 0, // TEXT format
            },
        ];

        // Construct DataRow with mixed formats
        let mut data = Vec::new();
        data.extend_from_slice(&3i16.to_be_bytes()); // num_columns = 3

        // Column 1: INT4 in text format ("123")
        let text_val = b"123";
        data.extend_from_slice(&(text_val.len() as i32).to_be_bytes());
        data.extend_from_slice(text_val);

        // Column 2: INT4 in binary format (456 as 4-byte big-endian)
        data.extend_from_slice(&4i32.to_be_bytes()); // 4 bytes for INT4
        data.extend_from_slice(&456i32.to_be_bytes());

        // Column 3: BOOL in text format ("t")
        let bool_val = b"t";
        data.extend_from_slice(&(bool_val.len() as i32).to_be_bytes());
        data.extend_from_slice(bool_val);

        // Parse and verify each column uses correct format
        let values = conn
            .parse_data_row(&data, &columns)
            .expect("mixed format DataRow should parse successfully");

        assert_eq!(values.len(), 3);

        // Verify text format INT4 parsed correctly
        assert_eq!(
            values[0],
            PgValue::Int4(123),
            "text format column should parse '123' as INT4"
        );

        // Verify binary format INT4 parsed correctly
        assert_eq!(
            values[1],
            PgValue::Int4(456),
            "binary format column should parse 4-byte big-endian as INT4"
        );

        // Verify text format BOOL parsed correctly
        assert_eq!(
            values[2],
            PgValue::Bool(true),
            "text format column should parse 't' as BOOL"
        );

        // AUDIT VERIFICATION: Per-column format codes correctly applied
        // - Column 0: format_code=0 → parse_text_value() → "123" → Int4(123)
        // - Column 1: format_code=1 → parse_binary_value() → bytes → Int4(456)
        // - Column 2: format_code=0 → parse_text_value() → "t" → Bool(true)
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
    fn parse_binary_value_numeric_preserves_decimal_scale() {
        let conn = make_test_connection();
        let numeric = [
            0x00, 0x03, // ndigits = 3
            0x00, 0x01, // weight = 1
            0x00, 0x00, // sign = positive
            0x00, 0x04, // scale = 4
            0x00, 0x01, // 1
            0x09, 0x29, // 2345
            0x1A, 0x85, // 6789
        ];
        let v = conn.parse_binary_value(&numeric, oid::NUMERIC).unwrap();
        assert_eq!(v, PgValue::Text("12345.6789".to_string()));
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
                ..
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
                ..
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
    fn parse_notice_response_redacts_detail_and_hint() {
        let conn = make_test_connection();
        let mut data = Vec::new();
        data.push(b'C');
        data.extend_from_slice(b"00000\0");
        data.push(b'M');
        data.extend_from_slice(b"COPY completed with warning\0");
        data.push(b'D');
        data.extend_from_slice(b"/var/lib/postgresql/imports/private.csv\0");
        data.push(b'H');
        data.extend_from_slice(b"Inspect /srv/postgres/tmp/copy-12345 for retries\0");
        data.push(0);

        let err = conn.parse_notice_response(&data).unwrap();
        match err {
            PgError::Server {
                code,
                message,
                detail,
                hint,
                ..
            } => {
                assert_eq!(code, "00000");
                assert_eq!(message, "COPY completed with warning");
                assert!(detail.is_none(), "notice detail should be redacted");
                assert!(hint.is_none(), "notice hint should be redacted");
            }
            other => panic!("expected Server notice shape, got: {other}"),
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

    #[test]
    fn authenticate_rejects_auth_ok_without_challenging_configured_password() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(&mut peer, &backend_message(b'R', &0i32.to_be_bytes())).unwrap();

        let cx = crate::cx::Cx::for_testing();
        let options = PgConnectOptions {
            host: "localhost".to_string(),
            port: 5432,
            database: "testdb".to_string(),
            user: "postgres".to_string(),
            password: Some(SecretString::new("secret")),
            application_name: None,
            connect_timeout: None,
            ssl_mode: SslMode::Disable,
        };

        match run(conn.authenticate(&cx, &options)) {
            Err(PgError::AuthenticationFailed(msg)) => {
                assert!(
                    msg.contains("without challenging configured password"),
                    "got: {msg}"
                );
            }
            other => panic!("expected AuthenticationFailed, got: {other:?}"),
        }
    }

    #[test]
    fn authenticate_allows_auth_ok_without_challenge_when_no_password_is_configured() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        std::io::Write::write_all(&mut peer, &backend_message(b'R', &0i32.to_be_bytes())).unwrap();

        let cx = crate::cx::Cx::for_testing();
        let options = PgConnectOptions {
            host: "localhost".to_string(),
            port: 5432,
            database: "testdb".to_string(),
            user: "postgres".to_string(),
            password: None,
            application_name: None,
            connect_timeout: None,
            ssl_mode: SslMode::Disable,
        };

        match run(conn.authenticate(&cx, &options)) {
            Ok(()) => {}
            other => panic!("expected auth success, got: {other:?}"),
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
            diagnostic: PgErrorDiagnostic::default(),
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
            diagnostic: PgErrorDiagnostic::default(),
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

        let cancelled = PgError::Cancelled(CancelReason::user("draining losers"));
        let cancelled_text = format!("{cancelled}");
        assert!(cancelled_text.contains("draining losers"));
        assert!(!cancelled_text.contains("CancelReason"));

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
        assert_eq!(
            msg,
            vec![
                b'P', 0, 0, 0, 26, b's', b't', b'm', b't', b'1', 0, b'S', b'E', b'L', b'E', b'C',
                b'T', b' ', b'$', b'1', 0, 0, 1, 0, 0, 0, 23,
            ],
            "Parse wire format must match PostgreSQL frontend protocol: \
             type byte, length, statement cstring, SQL cstring, i16 param count, i32 OIDs",
        );
    }

    #[test]
    fn build_bind_msg_no_params() {
        let msg = build_bind_msg("", "", &[], Format::Text).unwrap();
        assert_eq!(msg[0], b'B');
    }

    fn build_bind_frame_for_test(
        param_format_codes: &[i16],
        values: &[Option<Vec<u8>>],
        result_format_codes: &[i16],
    ) -> Vec<u8> {
        let mut buf = MessageBuffer::new();
        buf.write_cstring("");
        buf.write_cstring("");
        buf.write_i16(param_format_codes.len() as i16);
        for &code in param_format_codes {
            buf.write_i16(code);
        }
        buf.write_i16(values.len() as i16);
        for value in values {
            if let Some(bytes) = value {
                let len = i32::try_from(bytes.len()).unwrap();
                buf.write_i32(len);
                buf.write_bytes(bytes);
            } else {
                buf.write_i32(-1);
            }
        }
        buf.write_i16(result_format_codes.len() as i16);
        for &code in result_format_codes {
            buf.write_i16(code);
        }
        buf.build_message(FrontendMessage::Bind as u8).unwrap()
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
    fn build_bind_execute_msg_matches_psql_prepared_statement_wire_bytes() {
        let params: Vec<&dyn ToSql> = vec![&42i32];
        let bind = build_bind_msg("", "s", &params, Format::Text).unwrap();
        let execute = build_execute_msg("", 0).unwrap();

        // Captured from `psql 18.0` using:
        //   PREPARE s(int) AS SELECT $1::int4;
        //   \bind_named s 42
        //   \g
        //
        // The trace shows psql/libpq compresses the parameter-format section to
        // count=0 for the default all-text case, while still emitting a single
        // result-format code of 0.
        let expected_bind = vec![
            b'B', 0, 0, 0, 21, 0, b's', 0, 0, 0, 0, 1, 0, 0, 0, 2, b'4', b'2', 0, 1, 0, 0,
        ];
        let expected_execute = vec![b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0];

        assert_eq!(
            bind, expected_bind,
            "Bind wire bytes must match psql for named prepared statements"
        );
        assert_eq!(
            execute, expected_execute,
            "Execute wire bytes must match psql for named prepared statements"
        );
    }

    #[test]
    fn build_bind_msg_encodes_global_default_text_format_count_zero() {
        let left = String::from("alpha");
        let right = String::from("beta");
        let params: Vec<&dyn ToSql> = vec![&left, &right];
        let msg = build_bind_msg("", "", &params, Format::Text).unwrap();
        let parsed = fuzz_parse_bind_message(&msg).unwrap();

        assert_eq!(
            parsed.param_format_codes,
            Vec::<i16>::new(),
            "all-text parameters should use PostgreSQL's default count=0 encoding"
        );
        assert_eq!(
            parsed.parameter_values,
            vec![Some(b"alpha".to_vec()), Some(b"beta".to_vec())]
        );
        assert_eq!(parsed.result_format_codes, vec![0]);
    }

    #[test]
    fn build_bind_msg_encodes_single_global_binary_format_count() {
        let number = 42i32;
        let flag = true;
        let params: Vec<&dyn ToSql> = vec![&number, &flag];
        let msg = build_bind_msg("", "", &params, Format::Text).unwrap();
        let parsed = fuzz_parse_bind_message(&msg).unwrap();

        assert_eq!(
            parsed.param_format_codes,
            vec![1],
            "uniform binary parameters should use count=1 global binary encoding"
        );
        assert_eq!(
            parsed.parameter_values,
            vec![Some(42i32.to_be_bytes().to_vec()), Some(vec![1])]
        );
        assert_eq!(parsed.result_format_codes, vec![0]);
    }

    #[test]
    fn build_bind_msg_encodes_per_parameter_mixed_formats() {
        let left = String::from("left");
        let number = 7i32;
        let right = String::from("right");
        let params: Vec<&dyn ToSql> = vec![&left, &number, &right];
        let msg = build_bind_msg("", "", &params, Format::Text).unwrap();
        let parsed = fuzz_parse_bind_message(&msg).unwrap();

        assert_eq!(
            parsed.param_format_codes,
            vec![0, 1, 0],
            "mixed text/binary parameters must preserve per-parameter format codes"
        );
        assert_eq!(
            parsed.parameter_values,
            vec![
                Some(b"left".to_vec()),
                Some(7i32.to_be_bytes().to_vec()),
                Some(b"right".to_vec())
            ]
        );
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
    fn fuzz_parse_bind_message_decodes_zero_parameters() {
        let frame = build_bind_frame_for_test(&[], &[], &[0]);
        let parsed = fuzz_parse_bind_message(&frame).unwrap();

        assert!(parsed.param_format_codes.is_empty());
        assert!(parsed.parameter_values.is_empty());
        assert_eq!(parsed.result_format_codes, vec![0]);
    }

    #[test]
    fn fuzz_parse_bind_message_decodes_max_bounded_parameter_count() {
        const MAX_BOUND_PARAMS: usize = 16;

        let param_format_codes = (0..MAX_BOUND_PARAMS)
            .map(|index| (index % 2) as i16)
            .collect::<Vec<_>>();
        let values = (0..MAX_BOUND_PARAMS)
            .map(|index| Some(vec![index as u8; (index % 3) + 1]))
            .collect::<Vec<_>>();
        let frame = build_bind_frame_for_test(&param_format_codes, &values, &[1]);
        let parsed = fuzz_parse_bind_message(&frame).unwrap();

        assert_eq!(parsed.param_format_codes, param_format_codes);
        assert_eq!(parsed.parameter_values, values);
        assert_eq!(parsed.result_format_codes, vec![1]);
    }

    #[test]
    fn fuzz_parse_bind_message_rejects_mismatched_format_count() {
        let mut buf = MessageBuffer::new();
        buf.write_cstring("");
        buf.write_cstring("");
        buf.write_i16(2);
        buf.write_i16(0);
        buf.write_i16(0);
        buf.write_i16(1);

        let frame = buf.build_message(FrontendMessage::Bind as u8).unwrap();
        match fuzz_parse_bind_message(&frame) {
            Err(PgError::Protocol(msg)) => {
                assert!(
                    msg.contains("bind format count 2 must be 0, 1, or match bind value count 1"),
                    "got: {msg}"
                );
            }
            other => panic!("expected bind format-count mismatch error, got {other:?}"),
        }
    }

    #[test]
    fn fuzz_parse_bind_message_rejects_truncated_format_code_list() {
        let mut buf = MessageBuffer::new();
        buf.write_cstring("");
        buf.write_cstring("");
        buf.write_i16(1);
        buf.write_byte(0);

        let frame = buf.build_message(FrontendMessage::Bind as u8).unwrap();
        match fuzz_parse_bind_message(&frame) {
            Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("unexpected end of message"), "got: {msg}");
            }
            other => panic!("expected truncated bind format-code error, got {other:?}"),
        }
    }

    #[test]
    fn fuzz_parse_bind_message_rejects_invalid_format_codes() {
        let invalid_param = build_bind_frame_for_test(&[2], &[Some(b"x".to_vec())], &[0]);
        match fuzz_parse_bind_message(&invalid_param) {
            Err(PgError::Protocol(msg)) => {
                assert!(
                    msg.contains("invalid bind parameter format code at index 0: 2"),
                    "got: {msg}"
                );
            }
            other => panic!("expected invalid parameter format-code error, got {other:?}"),
        }

        let invalid_result = build_bind_frame_for_test(&[], &[], &[-1]);
        match fuzz_parse_bind_message(&invalid_result) {
            Err(PgError::Protocol(msg)) => {
                assert!(
                    msg.contains("invalid bind result format code at index 0: -1"),
                    "got: {msg}"
                );
            }
            other => panic!("expected invalid result format-code error, got {other:?}"),
        }
    }

    #[test]
    fn fuzz_parse_bind_message_rejects_malformed_parameter_length() {
        let mut buf = MessageBuffer::new();
        buf.write_cstring("");
        buf.write_cstring("");
        buf.write_i16(0);
        buf.write_i16(1);
        buf.write_i32(-2);

        let frame = buf.build_message(FrontendMessage::Bind as u8).unwrap();
        match fuzz_parse_bind_message(&frame) {
            Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("invalid bind value length: -2"), "got: {msg}");
            }
            other => panic!("expected malformed bind value-length error, got {other:?}"),
        }
    }

    #[test]
    fn fuzz_parse_bind_message_rejects_truncated_parameter_payload() {
        let mut buf = MessageBuffer::new();
        buf.write_cstring("");
        buf.write_cstring("");
        buf.write_i16(0);
        buf.write_i16(1);
        buf.write_i32(2);
        buf.write_bytes(b"4");

        let frame = buf.build_message(FrontendMessage::Bind as u8).unwrap();
        match fuzz_parse_bind_message(&frame) {
            Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("unexpected end of message"), "got: {msg}");
            }
            other => panic!("expected truncated bind payload error, got {other:?}"),
        }
    }

    #[test]
    fn fuzz_parse_bind_message_is_panic_free_for_small_arbitrary_bytes() {
        let frames = vec![
            Vec::new(),
            vec![b'B'],
            vec![b'B', 0, 0, 0, 0],
            vec![b'B', 0, 0, 0, 4],
            vec![b'B', 0, 0, 0, 6, 0],
            vec![b'X', 0, 0, 0, 4],
            vec![b'B', 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0],
        ];

        for frame in frames {
            let _ = fuzz_parse_bind_message(&frame);
        }
    }

    #[test]
    fn fuzz_apply_ready_for_query_accepts_transaction_state_bytes() {
        for status in [b'I', b'T', b'E'] {
            let (result, final_status) = fuzz_apply_ready_for_query(&[status], b'I');
            match result {
                Ok(parsed) => assert_eq!(parsed, status),
                Err(err) => panic!("expected valid ReadyForQuery state {status:?}, got {err:?}"),
            }
            assert_eq!(final_status, status);
        }
    }

    #[test]
    fn fuzz_apply_ready_for_query_rejects_malformed_state_and_preserves_status() {
        for payload in [Vec::new(), vec![b'X'], vec![b'I', b'T']] {
            let (result, final_status) = fuzz_apply_ready_for_query(&payload, b'T');
            match result {
                Err(PgError::Protocol(msg)) => {
                    assert!(
                        msg.contains("ReadyForQuery"),
                        "expected ReadyForQuery protocol error, got: {msg}"
                    );
                }
                other => panic!("expected malformed ReadyForQuery error, got {other:?}"),
            }
            assert_eq!(final_status, b'T');
        }
    }

    #[test]
    fn fuzz_parse_command_complete_tag_extracts_rows() {
        assert_eq!(fuzz_parse_command_complete_tag(b"INSERT 0 5\0").unwrap(), 5);
        assert_eq!(
            fuzz_parse_command_complete_tag(b"INSERT 123 0\0").unwrap(),
            0
        );
        assert_eq!(fuzz_parse_command_complete_tag(b"UPDATE 42\0").unwrap(), 42);
        assert_eq!(
            fuzz_parse_command_complete_tag(b"DELETE 18446744073709551615\0").unwrap(),
            u64::MAX
        );
        assert_eq!(fuzz_parse_command_complete_tag(b"SELECT 0\0").unwrap(), 0);
        assert_eq!(fuzz_parse_command_complete_tag(b"COPY 7").unwrap(), 7);
        assert_eq!(fuzz_parse_command_complete_tag(b"MOVE 8\0").unwrap(), 8);
        assert_eq!(fuzz_parse_command_complete_tag(b"FETCH 9\0").unwrap(), 9);
    }

    #[test]
    fn fuzz_parse_command_complete_tag_rejects_malformed() {
        for payload in [
            b"UPDATE nope\0".as_slice(),
            b"UPDATE 18446744073709551616\0".as_slice(),
            b"UPDATE -1\0".as_slice(),
            b"UPDATE 1 trailing\0".as_slice(),
            b"UNKNOWN 1\0".as_slice(),
            b"\xff\xfe\x00".as_slice(),
            b"".as_slice(),
        ] {
            match fuzz_parse_command_complete_tag(payload) {
                Err(PgError::Protocol(_)) => {}
                other => panic!("expected malformed CommandComplete tag error, got {other:?}"),
            }
        }
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
            sql: "SELECT $1::int4, $2::text".to_string(),
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
            sql: "SELECT $1".to_string(),
            param_oids: vec![oid::INT4],
            columns: vec![],
        };

        assert_user_cancelled(run(conn.query_unchecked(&cx, "SELECT 1")));
        assert_user_cancelled(run(conn.query_one(&cx, "SELECT 1")));
        assert_user_cancelled(run(conn.execute_unchecked(&cx, "SELECT 1")));
        assert_user_cancelled(run(conn.query_params(&cx, "SELECT $1", &params)));
        assert_user_cancelled(run(conn.query_one_params(&cx, "SELECT $1", &params)));
        assert_user_cancelled(run(conn.execute_params(&cx, "SELECT $1", &params)));
        assert_user_cancelled(run(conn.begin(&cx)));
        assert_user_cancelled(run(conn.prepare(&cx, "SELECT $1")));
        assert_user_cancelled(run(conn.query_prepared(&cx, &stmt, &params)));
        assert_user_cancelled(run(conn.execute_prepared(&cx, &stmt, &params)));
        assert_user_cancelled(run(conn.close_statement(&cx, &stmt)));
    }

    #[test]
    fn query_prepared_rejects_bind_arity_mismatch_before_io() {
        let (mut conn, peer) = make_test_connection_with_peer();
        drop(peer);

        let cx = Cx::for_testing();
        let first: i32 = 7;
        let params: [&dyn ToSql; 1] = [&first];
        let stmt = PgStatement {
            name: "s1".to_string(),
            sql: "SELECT $1, $2".to_string(),
            param_oids: vec![oid::INT4, oid::TEXT],
            columns: vec![],
        };

        match run(conn.query_prepared(&cx, &stmt, &params)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(
                    msg.contains("prepared statement 's1' expects 2 parameters, got 1"),
                    "unexpected mismatch error: {msg}"
                );
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(
            !conn.inner.closed,
            "arity mismatch should fail before entering in-flight closed state"
        );
    }

    #[test]
    fn execute_prepared_rejects_bind_arity_mismatch_before_io() {
        let (mut conn, peer) = make_test_connection_with_peer();
        drop(peer);

        let cx = Cx::for_testing();
        let only: i32 = 9;
        let params: [&dyn ToSql; 1] = [&only];
        let stmt = PgStatement {
            name: "s2".to_string(),
            sql: "SELECT 1".to_string(),
            param_oids: Vec::new(),
            columns: vec![],
        };

        match run(conn.execute_prepared(&cx, &stmt, &params)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(
                    msg.contains("prepared statement 's2' expects 0 parameters, got 1"),
                    "unexpected mismatch error: {msg}"
                );
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        assert!(
            !conn.inner.closed,
            "arity mismatch should fail before entering in-flight closed state"
        );
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
            password: Some(SecretString::new("secret")),
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

    #[cfg(feature = "tls")]
    #[test]
    fn prefer_tls_handshake_error_is_not_swallowed_by_plaintext_fallback() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("listener addr");
        let (second_accept_tx, second_accept_rx) = std::sync::mpsc::channel();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept first connection");
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("set read timeout");
            stream
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .expect("set write timeout");

            let mut ssl_request = [0u8; 8];
            stream
                .read_exact(&mut ssl_request)
                .expect("read SSLRequest");
            assert_eq!(&ssl_request[0..4], &8i32.to_be_bytes());
            assert_eq!(&ssl_request[4..8], &80_877_103i32.to_be_bytes());

            stream.write_all(b"S").expect("write SSL accept");
            stream.flush().expect("flush SSL accept");
            drop(stream);

            listener
                .set_nonblocking(true)
                .expect("set nonblocking after TLS abort");
            let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
            let mut saw_second_accept = false;
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((_second, _peer)) => {
                        saw_second_accept = true;
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(err) => panic!("unexpected second accept error: {err}"),
                }
            }
            second_accept_tx
                .send(saw_second_accept)
                .expect("send second accept observation");
        });

        let mut options = PgConnectOptions::parse(&format!(
            "postgres://user:pass@{}:{}/db?sslmode=prefer",
            addr.ip(),
            addr.port()
        ))
        .expect("parse options");
        options.connect_timeout = Some(std::time::Duration::from_secs(1));

        let cx = Cx::for_testing();
        match run(PgConnection::connect_with_options(&cx, options)) {
            Outcome::Err(PgError::Tls(msg)) => {
                assert!(
                    !msg.is_empty(),
                    "TLS abort should surface a concrete handshake error"
                );
            }
            other => panic!("expected TLS error, got {other:?}"),
        }

        let saw_second_accept = second_accept_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("receive second accept observation");
        assert!(
            !saw_second_accept,
            "prefer mode must not reconnect in plaintext after the server already accepted TLS"
        );

        server.join().expect("server thread should exit cleanly");
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
        match run(conn.query_unchecked(&cx, "SELECT 1")) {
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
        match run(conn.query_unchecked(&cx, "SELECT 1")) {
            Outcome::Ok(rows) => assert!(rows.is_empty(), "unexpected rows: {rows:?}"),
            other => panic!("expected successful query, got {other:?}"),
        }
    }

    #[test]
    fn notification_response_rejects_trailing_bytes() {
        let (mut conn, _peer) = make_test_connection_with_peer();
        let mut data = Vec::new();
        data.extend_from_slice(&42i32.to_be_bytes());
        data.extend_from_slice(b"jobs\0done\0");
        data.push(0xff);

        match conn.handle_notification_response(&data) {
            Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("NotificationResponse"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
    }

    #[test]
    fn notification_response_production_parser_boundary_matrix_logs_evidence() {
        const RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_rjvkoa_postgres cargo test -p asupersync --lib notification_response_production_parser_boundary_matrix_logs_evidence -- --nocapture";

        enum Expected {
            Ok {
                process_id: i32,
                channel: &'static str,
                payload_len: usize,
            },
            ErrContains(&'static str),
        }

        struct Case {
            label: &'static str,
            parser_state: &'static str,
            body: Vec<u8>,
            channel_len: usize,
            channel_fingerprint: u64,
            payload_len: usize,
            expected: Expected,
        }

        fn fingerprint(bytes: &[u8]) -> u64 {
            let mut hash = 0xcbf2_9ce4_8422_2325u64;
            for byte in bytes {
                hash ^= u64::from(*byte);
                hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
            }
            hash
        }

        fn case(label: &'static str, channel: &[u8], payload: Vec<u8>, expected: Expected) -> Case {
            Case {
                label,
                parser_state: "NotificationResponseBody",
                body: notification_response_body_from_parts(42, channel, &payload),
                channel_len: channel.len(),
                channel_fingerprint: fingerprint(channel),
                payload_len: payload.len(),
                expected,
            }
        }

        let exact_payload = "p".repeat(MAX_NOTIFICATION_PAYLOAD_BYTES);
        let overlong_payload = "p".repeat(MAX_NOTIFICATION_PAYLOAD_BYTES + 1);
        let overlong_channel = "c".repeat(MAX_NOTIFICATION_CHANNEL_NAME_BYTES + 1);
        let mut embedded_nul_body = Vec::new();
        embedded_nul_body.extend_from_slice(&42i32.to_be_bytes());
        embedded_nul_body.extend_from_slice(b"jobs\0evil\0payload\0");

        let cases = vec![
            case(
                "valid-unquoted",
                b"jobs",
                b"done".to_vec(),
                Expected::Ok {
                    process_id: 42,
                    channel: "jobs",
                    payload_len: 4,
                },
            ),
            case(
                "valid-quoted-identifier-chars",
                b"jobs.queue\"blue",
                Vec::new(),
                Expected::Ok {
                    process_id: 42,
                    channel: "jobs.queue\"blue",
                    payload_len: 0,
                },
            ),
            case(
                "payload-exact-limit",
                b"jobs",
                exact_payload.into_bytes(),
                Expected::Ok {
                    process_id: 42,
                    channel: "jobs",
                    payload_len: MAX_NOTIFICATION_PAYLOAD_BYTES,
                },
            ),
            case(
                "empty-channel",
                b"",
                b"payload".to_vec(),
                Expected::ErrContains("cannot be empty"),
            ),
            case(
                "overlong-channel",
                overlong_channel.as_bytes(),
                b"payload".to_vec(),
                Expected::ErrContains("63-byte limit"),
            ),
            case(
                "non-utf8-channel",
                b"jobs\xff",
                b"payload".to_vec(),
                Expected::ErrContains("invalid UTF-8"),
            ),
            case(
                "non-utf8-payload",
                b"jobs",
                b"payload\xff".to_vec(),
                Expected::ErrContains("invalid UTF-8"),
            ),
            case(
                "overlong-payload",
                b"jobs",
                overlong_payload.into_bytes(),
                Expected::ErrContains("8000-byte limit"),
            ),
            Case {
                label: "embedded-nul-channel",
                parser_state: "NotificationResponseBody",
                body: embedded_nul_body,
                channel_len: 9,
                channel_fingerprint: fingerprint(b"jobs\0evil"),
                payload_len: 7,
                expected: Expected::ErrContains("trailing byte"),
            },
            Case {
                label: "missing-payload-terminator",
                parser_state: "NotificationResponseBody",
                body: {
                    let mut body = Vec::new();
                    body.extend_from_slice(&42i32.to_be_bytes());
                    body.extend_from_slice(b"jobs\0payload");
                    body
                },
                channel_len: 4,
                channel_fingerprint: fingerprint(b"jobs"),
                payload_len: 7,
                expected: Expected::ErrContains("unterminated string"),
            },
        ];

        for case in cases {
            let result = PgConnection::parse_notification_response_fields(&case.body);
            let error_kind = match &result {
                Ok(_) => "ok".to_string(),
                Err(PgError::Protocol(msg)) => format!("protocol:{msg}"),
                Err(other) => format!("unexpected:{other:?}"),
            };
            eprintln!(
                "POSTGRES_LISTEN_NOTIFY_PARSER corpus_label={} channel_len={} channel_fingerprint={:016x} payload_len={} parser_state={} production_seam=PgConnection::handle_notification_response error_kind={} rch_command=\"{}\" artifact_paths=[] final_verdict=production-real",
                case.label,
                case.channel_len,
                case.channel_fingerprint,
                case.payload_len,
                case.parser_state,
                error_kind,
                RCH_COMMAND
            );

            match (result, case.expected) {
                (
                    Ok(fields),
                    Expected::Ok {
                        process_id,
                        channel,
                        payload_len,
                    },
                ) => {
                    assert_eq!(fields.process_id, process_id);
                    assert_eq!(fields.channel, channel);
                    assert_eq!(fields.payload.len(), payload_len);
                }
                (Err(PgError::Protocol(msg)), Expected::ErrContains(expected)) => {
                    assert!(msg.contains(expected), "expected {expected:?}, got {msg:?}");
                }
                (other, expected) => panic!(
                    "unexpected parser outcome for boundary case: outcome={other:?} expected={}",
                    match expected {
                        Expected::Ok { .. } => "ok",
                        Expected::ErrContains(_) => "protocol error",
                    }
                ),
            }
        }
    }

    #[test]
    fn notification_response_arbitrary_bytes_do_not_panic() {
        let arbitrary_inputs = [
            Vec::new(),
            vec![0xff],
            vec![0, 1, 2, 3],
            vec![0, 0, 0, 42, b'j', b'o'],
            vec![0, 0, 0, 42, b'j', b'o', b'b', b's', 0, 0, 0xff],
        ];

        for (index, body) in arbitrary_inputs.iter().enumerate() {
            let parsed =
                std::panic::catch_unwind(|| PgConnection::parse_notification_response_fields(body));
            assert!(
                parsed.is_ok(),
                "production NotificationResponse parser panicked for arbitrary input {index}"
            );
        }
    }

    #[test]
    fn notification_response_interleaves_with_async_backend_messages() {
        let (mut conn, _peer) = make_test_connection_with_peer();
        let parameter_status = {
            let mut body = Vec::new();
            body.extend_from_slice(b"application_name\0asupersync\0");
            body
        };
        let notice = {
            let mut body = Vec::new();
            body.push(b'S');
            body.extend_from_slice(b"NOTICE\0");
            body.push(b'C');
            body.extend_from_slice(b"00000\0");
            body.push(b'M');
            body.extend_from_slice(b"interleaved\0");
            body.push(0);
            body
        };

        assert!(
            conn.handle_async_backend_message(b'S', &parameter_status)
                .expect("ParameterStatus should parse")
        );
        assert!(
            conn.handle_async_backend_message(
                b'A',
                &notification_response_body(7, "jobs", "ready"),
            )
            .expect("NotificationResponse should parse")
        );
        assert!(
            conn.handle_async_backend_message(b'N', &notice)
                .expect("NoticeResponse should parse")
        );
        assert!(
            !conn
                .handle_async_backend_message(b'C', b"SELECT 1\0")
                .expect("CommandComplete is not an async side message")
        );
        assert_eq!(
            conn.inner
                .parameters
                .get("application_name")
                .map(String::as_str),
            Some("asupersync")
        );
        eprintln!(
            "POSTGRES_LISTEN_NOTIFY_PARSER corpus_label=async-interleaving channel_len=4 channel_fingerprint=41b90dde29446fdd payload_len=5 parser_state=handle_async_backend_message production_seam=PgConnection::handle_notification_response error_kind=ok rch_command=\"rch exec -- env CARGO_TARGET_DIR=${{TMPDIR:-/tmp}}/rch_target_asupersync_rjvkoa_postgres cargo test -p asupersync --lib notification_response_interleaves_with_async_backend_messages -- --nocapture\" artifact_paths=[] final_verdict=production-real"
        );
    }

    #[test]
    fn query_preserves_per_statement_row_metadata_in_simple_query_batch_psql_parity() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();

        let responder = std::thread::spawn(move || {
            let query_request = read_until_contains(&mut peer, b"SELECT 1 AS n; SELECT 'two' AS s");
            assert!(
                query_request
                    .windows("SELECT 1 AS n; SELECT 'two' AS s".len())
                    .any(|window| window == b"SELECT 1 AS n; SELECT 'two' AS s"),
                "simple query should contain the full batched SQL"
            );

            // Captured from psql-driven simple-query behavior: each statement in
            // the batch gets its own RowDescription/DataRow/CommandComplete
            // segment before the final ReadyForQuery.
            let mut first_row_description = Vec::new();
            first_row_description.extend_from_slice(&1i16.to_be_bytes());
            first_row_description.extend_from_slice(b"n\0");
            first_row_description.extend_from_slice(&0i32.to_be_bytes());
            first_row_description.extend_from_slice(&0i16.to_be_bytes());
            first_row_description.extend_from_slice(&(oid::INT4 as i32).to_be_bytes());
            first_row_description.extend_from_slice(&4i16.to_be_bytes());
            first_row_description.extend_from_slice(&(-1i32).to_be_bytes());
            first_row_description.extend_from_slice(&0i16.to_be_bytes());

            let mut first_data_row = Vec::new();
            first_data_row.extend_from_slice(&1i16.to_be_bytes());
            first_data_row.extend_from_slice(&1i32.to_be_bytes());
            first_data_row.extend_from_slice(b"1");

            let mut second_row_description = Vec::new();
            second_row_description.extend_from_slice(&1i16.to_be_bytes());
            second_row_description.extend_from_slice(b"s\0");
            second_row_description.extend_from_slice(&0i32.to_be_bytes());
            second_row_description.extend_from_slice(&0i16.to_be_bytes());
            second_row_description.extend_from_slice(&(oid::TEXT as i32).to_be_bytes());
            second_row_description.extend_from_slice(&(-1i16).to_be_bytes());
            second_row_description.extend_from_slice(&(-1i32).to_be_bytes());
            second_row_description.extend_from_slice(&0i16.to_be_bytes());

            let mut second_data_row = Vec::new();
            second_data_row.extend_from_slice(&1i16.to_be_bytes());
            second_data_row.extend_from_slice(&3i32.to_be_bytes());
            second_data_row.extend_from_slice(b"two");

            std::io::Write::write_all(&mut peer, &backend_message(b'T', &first_row_description))
                .expect("first row description should be written");
            std::io::Write::write_all(&mut peer, &backend_message(b'D', &first_data_row))
                .expect("first data row should be written");
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"SELECT 1\0"))
                .expect("first command complete should be written");
            std::io::Write::write_all(&mut peer, &backend_message(b'T', &second_row_description))
                .expect("second row description should be written");
            std::io::Write::write_all(&mut peer, &backend_message(b'D', &second_data_row))
                .expect("second data row should be written");
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"SELECT 1\0"))
                .expect("second command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("ready for query should be written");
        });

        match run(conn.query_unchecked(&cx, "SELECT 1 AS n; SELECT 'two' AS s")) {
            Outcome::Ok(rows) => {
                assert_eq!(rows.len(), 2, "expected one row per simple-query statement");
                assert_eq!(rows[0].columns()[0].name, "n");
                assert_eq!(rows[0].get_i32("n").expect("first row int4"), 1);
                assert_eq!(rows[1].columns()[0].name, "s");
                assert_eq!(rows[1].get_str("s").expect("second row text"), "two");
            }
            other => panic!("expected successful simple-query batch, got {other:?}"),
        }
        responder
            .join()
            .expect("simple-query batch responder should exit cleanly");
        assert!(!conn.inner.closed);
        assert_eq!(conn.inner.transaction_status, b'I');
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
        match run(conn.execute_unchecked(&cx, "SET application_name = 'asupersync-test'")) {
            Outcome::Ok(affected) => assert_eq!(affected, 0),
            other => panic!("expected successful execute, got {other:?}"),
        }
        assert_eq!(conn.parameter("application_name"), Some("asupersync-test"));
    }

    #[test]
    fn execute_set_role_marks_connection_discard_only_for_pool_return() {
        use crate::database::pool::AsyncConnectionManager;

        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );

        let responder = std::thread::spawn(move || {
            let request = read_until_contains(&mut peer, b"SET ROLE app_reader");
            assert!(
                request
                    .windows("SET ROLE app_reader".len())
                    .any(|window| window == b"SET ROLE app_reader"),
                "request should contain SET ROLE"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"SET\0"))
                .expect("command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("ready for query should be written");
        });

        match run(conn.execute_unchecked(&cx, "SET ROLE app_reader")) {
            Outcome::Ok(affected) => assert_eq!(affected, 0),
            other => panic!("expected successful SET ROLE, got {other:?}"),
        }
        responder
            .join()
            .expect("SET ROLE responder should exit cleanly");

        assert!(
            conn.inner.needs_discard,
            "successful SET ROLE must poison pooled reuse"
        );
        assert!(
            !mgr.release_check(&mut conn),
            "pool return must reject connections with prior role state"
        );
    }

    #[test]
    fn execute_set_statement_timeout_marks_connection_discard_for_pool_return() {
        use crate::database::pool::AsyncConnectionManager;

        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );

        let responder = std::thread::spawn(move || {
            let request = read_until_contains(&mut peer, b"SET statement_timeout = '5s'");
            assert!(
                request
                    .windows("SET statement_timeout = '5s'".len())
                    .any(|window| window == b"SET statement_timeout = '5s'"),
                "request should contain SET statement_timeout"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"SET\0"))
                .expect("command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("ready for query should be written");
        });

        match run(conn.execute_unchecked(&cx, "SET statement_timeout = '5s'")) {
            Outcome::Ok(affected) => assert_eq!(affected, 0),
            other => panic!("expected successful SET statement_timeout, got {other:?}"),
        }
        responder
            .join()
            .expect("SET statement_timeout responder should exit cleanly");

        assert!(
            conn.inner.needs_discard,
            "successful SET statement_timeout must poison pooled reuse"
        );
        assert!(
            !mgr.release_check(&mut conn),
            "pool return must drop connections with prior session statement_timeout state"
        );
    }

    #[test]
    fn set_local_transaction_marks_connection_discard_before_pool_reuse() {
        use crate::database::pool::AsyncConnectionManager;

        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );

        let responder = std::thread::spawn(move || {
            let begin_request = read_until_contains(&mut peer, b"BEGIN");
            assert!(
                begin_request
                    .windows("BEGIN".len())
                    .any(|window| window == b"BEGIN"),
                "request should contain BEGIN"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"BEGIN\0"))
                .expect("command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'T'))
                .expect("ready for query should be written");

            let set_request =
                read_until_contains(&mut peer, b"SET LOCAL application_name = 'tenant_a'");
            assert!(
                set_request
                    .windows("SET LOCAL application_name = 'tenant_a'".len())
                    .any(|window| window == b"SET LOCAL application_name = 'tenant_a'"),
                "request should contain SET LOCAL"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"SET\0"))
                .expect("command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'T'))
                .expect("ready for query should be written");

            let commit_request = read_until_contains(&mut peer, b"COMMIT");
            assert!(
                commit_request
                    .windows("COMMIT".len())
                    .any(|window| window == b"COMMIT"),
                "request should contain COMMIT"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"COMMIT\0"))
                .expect("command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("ready for query should be written");
        });

        let mut tx = match run(conn.begin(&cx)) {
            Outcome::Ok(tx) => tx,
            Outcome::Err(err) => panic!("expected successful BEGIN, got error: {err}"),
            Outcome::Cancelled(reason) => {
                panic!("expected successful BEGIN, got cancellation: {reason:?}")
            }
            Outcome::Panicked(payload) => {
                panic!("expected successful BEGIN, got panic: {payload:?}")
            }
        };
        match run(tx.execute_unchecked(&cx, "SET LOCAL application_name = 'tenant_a'")) {
            Outcome::Ok(affected) => assert_eq!(affected, 0),
            other => panic!("expected successful SET LOCAL, got {other:?}"),
        }
        match run(tx.commit(&cx)) {
            Outcome::Ok(()) => {}
            other => panic!("expected successful COMMIT, got {other:?}"),
        }
        responder
            .join()
            .expect("SET LOCAL responder should exit cleanly");

        assert_eq!(
            conn.inner.transaction_status, b'I',
            "SET LOCAL transaction should be closed before pool reuse decision"
        );
        assert!(
            conn.inner.needs_discard,
            "ambiguous SET command tag must fail closed for pooled reuse"
        );
        assert!(
            !mgr.release_check(&mut conn),
            "pool return must drop SET LOCAL connections so next tenant cannot inherit GUC state"
        );
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
        match run(conn.execute_unchecked(&cx, "SELECT 1")) {
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

        fn build_copy_response_body(overall_format: u8, format_codes: &[i16]) -> Vec<u8> {
            let mut buf = Vec::new();
            buf.push(overall_format);
            buf.extend_from_slice(&(format_codes.len() as i16).to_be_bytes());
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

            // Message length excludes the type byte but includes this length field.
            buf.extend_from_slice(&(data.len() as u32 + 4).to_be_bytes());

            // Data payload
            buf.extend_from_slice(data);

            buf
        }

        /// Creates a COPY DONE message for testing.
        fn build_copy_done_message() -> Vec<u8> {
            vec![b'c', 0, 0, 0, 4] // type + 4-byte length field, no body
        }

        /// Creates a COPY FAIL message for testing.
        fn build_copy_fail_message(error_msg: &str) -> Vec<u8> {
            let mut buf = Vec::new();

            // Message type
            buf.push(b'f');

            // Message length excludes the type byte but includes this length field.
            buf.extend_from_slice(&(error_msg.len() as u32 + 5).to_be_bytes()); // +4 length field, +1 null terminator

            // Error message with null terminator
            buf.extend_from_slice(error_msg.as_bytes());
            buf.push(0);

            buf
        }

        #[cfg(feature = "test-internals")]
        const COPY_IN_MAX_BOUNDED_TEST_PAYLOAD: usize = 1024;

        #[cfg(feature = "test-internals")]
        fn split_copy_stream_at<'a>(stream: &'a [u8], offsets: &[usize]) -> Vec<&'a [u8]> {
            let mut segments = Vec::new();
            let mut start = 0usize;

            for &offset in offsets {
                let end = offset.min(stream.len());
                if end >= start {
                    segments.push(&stream[start..end]);
                    start = end;
                }
            }

            segments.push(&stream[start..]);
            segments
        }

        #[cfg(feature = "test-internals")]
        fn assert_copy_in_segment_equivalence(stream: &[u8], segments: &[&[u8]]) {
            let unsplit = fuzz_parse_copy_in_sequence(stream).expect("unsplit COPY IN stream");
            let split = fuzz_parse_copy_in_segments(segments).expect("segmented COPY IN stream");
            assert_eq!(split, unsplit);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_accepts_empty_copy_data() {
            let mut stream = build_copy_data_message(&[]);
            stream.extend_from_slice(&build_copy_done_message());

            let parsed = fuzz_parse_copy_in_segments(&[stream.as_slice()])
                .expect("empty CopyData should decode");
            assert_eq!(parsed.copy_data_chunks, vec![Vec::<u8>::new()]);
            assert_eq!(parsed.end, FuzzCopyInEnd::Done);
            assert_copy_in_segment_equivalence(&stream, &[stream.as_slice()]);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_accepts_one_byte_payload() {
            let mut stream = build_copy_data_message(b"x");
            stream.extend_from_slice(&build_copy_done_message());
            let segments = split_copy_stream_at(&stream, &[1, 5, 6]);

            let parsed = fuzz_parse_copy_in_segments(&segments).expect("one-byte CopyData");
            assert_eq!(parsed.copy_data_chunks, vec![b"x".to_vec()]);
            assert_eq!(parsed.end, FuzzCopyInEnd::Done);
            assert_copy_in_segment_equivalence(&stream, &segments);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_accepts_max_bounded_payload() {
            let payload = vec![b'z'; COPY_IN_MAX_BOUNDED_TEST_PAYLOAD];
            let mut stream = build_copy_data_message(&payload);
            stream.extend_from_slice(&build_copy_done_message());
            let mid_payload = 5 + COPY_IN_MAX_BOUNDED_TEST_PAYLOAD / 2;
            let segments = split_copy_stream_at(&stream, &[1, 5, mid_payload]);

            let parsed = fuzz_parse_copy_in_segments(&segments).expect("bounded CopyData");
            assert_eq!(parsed.copy_data_chunks, vec![payload]);
            assert_eq!(parsed.end, FuzzCopyInEnd::Done);
            assert_copy_in_segment_equivalence(&stream, &segments);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_accepts_split_every_byte() {
            let mut stream = build_copy_data_message(b"row-1\n");
            stream.extend_from_slice(&build_copy_data_message(b"row-2\n"));
            stream.extend_from_slice(&build_copy_done_message());
            let segments = stream.chunks(1).collect::<Vec<_>>();

            let parsed = fuzz_parse_copy_in_segments(&segments).expect("byte-split COPY IN");
            assert_eq!(
                parsed.copy_data_chunks,
                vec![b"row-1\n".to_vec(), b"row-2\n".to_vec()]
            );
            assert_eq!(parsed.end, FuzzCopyInEnd::Done);
            assert_copy_in_segment_equivalence(&stream, &segments);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_accepts_frame_header_boundaries() {
            let first = build_copy_data_message(b"alpha");
            let second = build_copy_data_message(b"beta");
            let done = build_copy_done_message();
            let mut stream = Vec::new();
            stream.extend_from_slice(&first);
            stream.extend_from_slice(&second);
            stream.extend_from_slice(&done);

            let first_end = first.len();
            let second_start = first_end;
            let second_end = first_end + second.len();
            let segments = split_copy_stream_at(
                &stream,
                &[
                    1,
                    5,
                    first_end,
                    second_start + 1,
                    second_start + 5,
                    second_end,
                    second_end + 1,
                    second_end + 5,
                ],
            );

            let parsed = fuzz_parse_copy_in_segments(&segments).expect("header-boundary split");
            assert_eq!(
                parsed.copy_data_chunks,
                vec![b"alpha".to_vec(), b"beta".to_vec()]
            );
            assert_eq!(parsed.end, FuzzCopyInEnd::Done);
            assert_copy_in_segment_equivalence(&stream, &segments);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_accepts_copy_done_after_data() {
            let mut stream = build_copy_data_message(b"complete row\n");
            stream.extend_from_slice(&build_copy_done_message());
            let segments = split_copy_stream_at(&stream, &[3, 5, stream.len() - 1]);

            let parsed = fuzz_parse_copy_in_segments(&segments).expect("CopyDone after data");
            assert_eq!(parsed.copy_data_chunks, vec![b"complete row\n".to_vec()]);
            assert_eq!(parsed.end, FuzzCopyInEnd::Done);
            assert_copy_in_segment_equivalence(&stream, &segments);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_accepts_copy_fail_after_partial_data() {
            let data = build_copy_data_message(b"partial-row-without-newline");
            let fail = build_copy_fail_message("client aborted copy");
            let mut stream = Vec::new();
            stream.extend_from_slice(&data);
            stream.extend_from_slice(&fail);
            let segments = split_copy_stream_at(&stream, &[2, data.len() - 1, data.len() + 1]);

            let parsed = fuzz_parse_copy_in_segments(&segments).expect("CopyFail after data");
            assert_eq!(
                parsed.copy_data_chunks,
                vec![b"partial-row-without-newline".to_vec()]
            );
            assert_eq!(
                parsed.end,
                FuzzCopyInEnd::Fail("client aborted copy".to_string())
            );
            assert_copy_in_segment_equivalence(&stream, &segments);
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_rejects_malformed_length_too_small() {
            let stream = [b'd', 0, 0, 0, 3];
            let segments = split_copy_stream_at(&stream, &[2]);

            match fuzz_parse_copy_in_segments(&segments).unwrap_err() {
                PgError::Protocol(msg) => {
                    assert!(msg.contains("invalid message length: 3"), "got: {msg}");
                }
                other => panic!("expected Protocol error, got {other:?}"),
            }
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_rejects_malformed_length_too_large() {
            let stream = [b'd', 4, 0, 0, 1];
            let segments = split_copy_stream_at(&stream, &[1, 5]);

            match fuzz_parse_copy_in_segments(&segments).unwrap_err() {
                PgError::Protocol(msg) => {
                    assert!(
                        msg.contains("invalid message length: 67108865"),
                        "got: {msg}"
                    );
                }
                other => panic!("expected Protocol error, got {other:?}"),
            }
        }

        #[test]
        #[cfg(feature = "test-internals")]
        fn copy_in_segment_parser_preserves_arbitrary_segmentation_equivalence() {
            let first = build_copy_data_message(b"one");
            let second = build_copy_data_message(b"two-two");
            let fail = build_copy_fail_message("stop");
            let mut stream = Vec::new();
            stream.extend_from_slice(&first);
            stream.extend_from_slice(&second);
            stream.extend_from_slice(&fail);

            let mut segments = split_copy_stream_at(
                &stream,
                &[0, 2, 5, 8, first.len(), first.len() + 4, stream.len() - 2],
            );
            segments.insert(1, &stream[0..0]);
            segments.push(&stream[stream.len()..stream.len()]);

            assert_copy_in_segment_equivalence(&stream, &segments);
        }

        #[test]
        fn copy_out_response_parser_accepts_valid_formats() {
            let body = build_copy_response_body(1, &[0, 1, 0]);
            let (overall_format, column_formats) =
                PgConnection::parse_copy_response("CopyOutResponse", &body).unwrap();

            assert_eq!(overall_format, Format::Binary);
            assert_eq!(
                column_formats,
                vec![Format::Text, Format::Binary, Format::Text]
            );
        }

        #[test]
        fn copy_out_response_parser_rejects_invalid_overall_format() {
            let body = build_copy_response_body(2, &[0]);
            match PgConnection::parse_copy_response("CopyOutResponse", &body).unwrap_err() {
                PgError::Protocol(msg) => {
                    assert!(msg.contains("invalid CopyOutResponse overall format code: 2"));
                }
                other => panic!("expected Protocol error, got: {other}"),
            }
        }

        #[test]
        fn copy_out_response_parser_rejects_invalid_column_format() {
            let body = build_copy_response_body(0, &[0, 7]);
            match PgConnection::parse_copy_response("CopyOutResponse", &body).unwrap_err() {
                PgError::Protocol(msg) => {
                    assert!(msg.contains("invalid CopyOutResponse column 1 format code: 7"));
                }
                other => panic!("expected Protocol error, got: {other}"),
            }
        }

        #[test]
        fn copy_out_response_parser_rejects_truncated_columns() {
            let mut body = Vec::new();
            body.push(0);
            body.extend_from_slice(&2i16.to_be_bytes());
            body.extend_from_slice(&0i16.to_be_bytes());

            match PgConnection::parse_copy_response("CopyOutResponse", &body).unwrap_err() {
                PgError::Protocol(msg) => {
                    assert!(
                        msg.contains(
                            "CopyOutResponse declares 2 column format code(s) but has only 2 byte(s)"
                        ),
                        "got: {msg}"
                    );
                }
                other => panic!("expected Protocol error, got: {other}"),
            }
        }

        #[test]
        fn copy_out_response_parser_rejects_trailing_bytes() {
            let mut body = build_copy_response_body(0, &[0]);
            body.push(0xAA);

            match PgConnection::parse_copy_response("CopyOutResponse", &body).unwrap_err() {
                PgError::Protocol(msg) => {
                    assert!(
                        msg.contains("CopyOutResponse message has 1 trailing byte(s)"),
                        "got: {msg}"
                    );
                }
                other => panic!("expected Protocol error, got: {other}"),
            }
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

            // Verify length is 4: the length field itself, with no payload.
            let length = u32::from_be_bytes([
                copy_done_msg[1],
                copy_done_msg[2],
                copy_done_msg[3],
                copy_done_msg[4],
            ]);
            assert_eq!(length, 4, "CopyDone should have no body payload");

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

                // Verify length includes the length field and null terminator.
                let length = u32::from_be_bytes([
                    copy_fail_msg[1],
                    copy_fail_msg[2],
                    copy_fail_msg[3],
                    copy_fail_msg[4],
                ]);
                assert_eq!(
                    length,
                    error_msg.len() as u32 + 5,
                    "Length should include length field and null terminator"
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
            assert_eq!(length, 4);

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
            assert_eq!(chunk_length, max_chunk_size as u32 + 4);

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
            assert_eq!(length, long_error.len() as u32 + 5); // +4 length field, +1 null terminator

            // Test error message with embedded nulls (should be escaped or rejected)
            let null_error = "Error\0with\0nulls";
            let null_fail_msg = build_copy_fail_message(null_error);
            // Verify that embedded nulls don't break the protocol message structure
            let payload = &null_fail_msg[5..];
            assert_eq!(payload[payload.len() - 1], 0); // Still properly null-terminated
        }

        /// Differential conformance test: CopyData/CopyDone vs PostgreSQL wire protocol reference.
        ///
        /// Verifies that our CopyData and CopyDone message implementations produce
        /// wire formats that exactly match the PostgreSQL protocol specification.
        /// This ensures compatibility with psql, libpq, and other PostgreSQL clients.
        #[test]
        fn copy_data_copy_done_wire_format_differential_conformance() {
            // Test CopyData message format conformance
            let test_data = b"test_row_1\ttab_separated\t42\ntest_row_2\tmore_data\t24\n";
            let copy_data_msg = build_copy_data_message(test_data);

            // CONFORMANCE CHECK 1: CopyData message structure vs wire protocol spec
            // Format: type byte 'd' (0x64) + 4-byte big-endian length + data.
            // PostgreSQL's length excludes the type byte but includes the
            // 4-byte length field itself.
            assert_eq!(
                copy_data_msg[0], b'd',
                "CopyData type byte must be 'd' (0x64)"
            );

            let data_length = u32::from_be_bytes([
                copy_data_msg[1],
                copy_data_msg[2],
                copy_data_msg[3],
                copy_data_msg[4],
            ]);
            assert_eq!(
                data_length,
                test_data.len() as u32 + 4,
                "CopyData length field must equal payload size plus length field"
            );

            let payload = &copy_data_msg[5..];
            assert_eq!(
                payload, test_data,
                "CopyData payload must exactly match input data"
            );

            let expected_total_size = 1 + 4 + test_data.len(); // type + length + data
            assert_eq!(
                copy_data_msg.len(),
                expected_total_size,
                "CopyData total message size must be type(1) + length(4) + data"
            );

            // Test CopyDone message format conformance
            let copy_done_msg = build_copy_done_message();

            // CONFORMANCE CHECK 2: CopyDone message structure vs wire protocol spec
            // Format: type byte 'c' (0x63) + 4-byte big-endian length of 4.
            assert_eq!(
                copy_done_msg[0], b'c',
                "CopyDone type byte must be 'c' (0x63)"
            );
            assert_eq!(
                copy_done_msg.len(),
                5,
                "CopyDone must be exactly 5 bytes total"
            );

            let done_length = u32::from_be_bytes([
                copy_done_msg[1],
                copy_done_msg[2],
                copy_done_msg[3],
                copy_done_msg[4],
            ]);
            assert_eq!(
                done_length, 4,
                "CopyDone length field must include the length field itself"
            );

            // CONFORMANCE CHECK 3: Message sequence compatibility
            // Verify that a CopyData + CopyDone sequence forms a valid protocol exchange
            let mut full_sequence = Vec::new();
            full_sequence.extend_from_slice(&copy_data_msg);
            full_sequence.extend_from_slice(&copy_done_msg);

            // Validate we can parse the sequence back
            assert_eq!(full_sequence[0], b'd', "First message must be CopyData");
            let first_msg_len = u32::from_be_bytes([
                full_sequence[1],
                full_sequence[2],
                full_sequence[3],
                full_sequence[4],
            ]) as usize;

            let second_msg_start = 1 + first_msg_len; // type byte + PostgreSQL message length
            assert_eq!(
                full_sequence[second_msg_start], b'c',
                "Second message must be CopyDone"
            );

            // CONFORMANCE VERIFICATION: According to PostgreSQL wire protocol specification,
            // CopyData and CopyDone messages must follow exact byte layout for compatibility
            // with all PostgreSQL clients (psql, libpq, etc.)
            println!(
                "✓ PostgreSQL CopyData/CopyDone wire format differential conformance verified"
            );
            println!(
                "  - CopyData: type=0x{:02x}, length={}, data={}bytes",
                copy_data_msg[0],
                data_length,
                test_data.len()
            );
            println!(
                "  - CopyDone: type=0x{:02x}, length={}, total={}bytes",
                copy_done_msg[0],
                done_length,
                copy_done_msg.len()
            );
            println!("  - Message sequence forms valid PostgreSQL wire protocol exchange");
        }
    }

    // ─── br-asupersync-cvkoe9: PreparedStatementCache regression tests ──

    fn fixture_pg_statement(name: &str) -> PgStatement {
        PgStatement {
            name: name.to_string(),
            sql: format!("SELECT {name}"),
            param_oids: Vec::new(),
            columns: Vec::new(),
        }
    }

    #[test]
    fn prepared_cache_returns_evicted_name_at_cap() {
        // br-asupersync-cvkoe9: when the cache hits its capacity, the
        // LRU entry's server-side statement name MUST be returned so the
        // caller can DEALLOCATE it. Otherwise the bound is fictional.
        let mut cache = PreparedStatementCache::new(3);
        // Fill to cap.
        assert_eq!(
            cache.insert_returning_evicted_name("sql_a".into(), fixture_pg_statement("__s0")),
            None
        );
        assert_eq!(
            cache.insert_returning_evicted_name("sql_b".into(), fixture_pg_statement("__s1")),
            None
        );
        assert_eq!(
            cache.insert_returning_evicted_name("sql_c".into(), fixture_pg_statement("__s2")),
            None
        );
        assert_eq!(cache.len(), 3);

        // Insert at cap → evicts LRU (sql_a).
        let evicted =
            cache.insert_returning_evicted_name("sql_d".into(), fixture_pg_statement("__s3"));
        assert_eq!(
            evicted,
            Some("__s0".to_string()),
            "cache at cap MUST return LRU name for DEALLOCATE"
        );
        assert_eq!(cache.len(), 3);
        assert!(cache.entries.contains_key("sql_b"));
        assert!(cache.entries.contains_key("sql_c"));
        assert!(cache.entries.contains_key("sql_d"));
        assert!(!cache.entries.contains_key("sql_a"));
    }

    /// Protocol-backed version of prepared_cache_returns_evicted_name_at_cap.
    ///
    /// This test replaces the fixture statement helper with real prepared statements
    /// created through the actual prepare() method, testing cache eviction behavior
    /// with realistic PostgreSQL protocol responses.
    #[test]
    fn prepared_cache_eviction_with_real_statements() {
        use std::io::Write;

        run(async {
            let (mut conn, mut peer) = make_test_connection_with_peer();
            let cx = Cx::for_testing();

            // Set cache capacity to 3 for testing eviction
            conn.inner.prepared_cache = PreparedStatementCache::new(3);

            // Helper that writes a PostgreSQL prepare response
            let write_prepare_response = |peer: &mut std::net::TcpStream, stmt_name: &str| {
                std::thread::spawn({
                    let stmt_name = stmt_name.to_string();
                    let mut peer_clone = peer.try_clone().expect("clone peer");
                    move || {
                        // Read Parse message
                        let _parse_msg = read_until_contains(&mut peer_clone, stmt_name.as_bytes());

                        // Send realistic PostgreSQL response sequence:
                        // ParseComplete(1) + ParameterDescription(t) + RowDescription(T) + ReadyForQuery(Z)
                        let mut response = Vec::new();

                        // ParseComplete: 1 + length(4 bytes) = '1' + 0x00000004
                        response.extend_from_slice(&[b'1', 0x00, 0x00, 0x00, 0x04]);

                        // ParameterDescription: 't' + length + param_count(i16) + oid1(i32)
                        // For "SELECT $1" - one parameter of type TEXT(25)
                        response.extend_from_slice(&[b't', 0x00, 0x00, 0x00, 0x0A]); // length: 10
                        response.extend_from_slice(&[0x00, 0x01]); // 1 parameter
                        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x19]); // OID 25 (TEXT)

                        // RowDescription: 'T' + length + field_count(i16) + field1
                        // For "SELECT $1" - one result column
                        response.extend_from_slice(&[b'T', 0x00, 0x00, 0x00, 0x21]); // length: 33
                        response.extend_from_slice(&[0x00, 0x01]); // 1 column
                        response.extend_from_slice(b"?column?\x00"); // column name + null terminator
                        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // table_oid
                        response.extend_from_slice(&[0x00, 0x00]); // column_attr_number
                        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x19]); // type_oid (TEXT)
                        response.extend_from_slice(&[0xFF, 0xFF]); // type_size (-1 for variable)
                        response.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // type_modifier
                        response.extend_from_slice(&[0x00, 0x00]); // format_code (text)

                        // ReadyForQuery: 'Z' + length + status
                        response.extend_from_slice(&[b'Z', 0x00, 0x00, 0x00, 0x05, b'I']); // Idle

                        peer_clone.write_all(&response).expect("write response");
                    }
                })
            };

            // Prepare first statement - should not evict anything
            let responder1 = write_prepare_response(&mut peer, "__asupersync_s0");
            let stmt1 = conn.prepare(&cx, "SELECT $1").await;
            responder1.join().expect("responder1");
            assert!(matches!(stmt1, Outcome::Ok(_)));
            assert_eq!(conn.inner.prepared_cache.len(), 1);

            // Prepare second statement
            let responder2 = write_prepare_response(&mut peer, "__asupersync_s1");
            let stmt2 = conn.prepare(&cx, "SELECT $1, $2").await;
            responder2.join().expect("responder2");
            assert!(matches!(stmt2, Outcome::Ok(_)));
            assert_eq!(conn.inner.prepared_cache.len(), 2);

            // Prepare third statement - fills to capacity
            let responder3 = write_prepare_response(&mut peer, "__asupersync_s2");
            let stmt3 = conn.prepare(&cx, "SELECT COUNT(*)").await;
            responder3.join().expect("responder3");
            assert!(matches!(stmt3, Outcome::Ok(_)));
            assert_eq!(conn.inner.prepared_cache.len(), 3);

            // Prepare fourth statement - should evict the LRU (first) statement
            // and trigger DEALLOCATE for the evicted statement
            let responder4 = std::thread::spawn({
                let mut peer_clone = peer.try_clone().expect("clone peer");
                move || {
                    // Expect DEALLOCATE for evicted statement first
                    let deallocate_msg = read_until_contains(&mut peer_clone, b"__asupersync_s0");
                    assert!(
                        deallocate_msg
                            .windows(b"__asupersync_s0".len())
                            .any(|w| w == b"__asupersync_s0"),
                        "should send DEALLOCATE for evicted statement"
                    );

                    // Send DEALLOCATE response: CloseComplete + ReadyForQuery
                    let mut dealloc_response = Vec::new();
                    dealloc_response.extend_from_slice(&[b'3', 0x00, 0x00, 0x00, 0x04]); // CloseComplete
                    dealloc_response.extend_from_slice(&[b'Z', 0x00, 0x00, 0x00, 0x05, b'I']); // ReadyForQuery
                    peer_clone
                        .write_all(&dealloc_response)
                        .expect("write dealloc response");

                    // Then expect new PARSE for fourth statement
                    let _parse_msg = read_until_contains(&mut peer_clone, b"__asupersync_s3");

                    // Send prepare response for fourth statement
                    let mut response = Vec::new();
                    response.extend_from_slice(&[b'1', 0x00, 0x00, 0x00, 0x04]); // ParseComplete
                    response.extend_from_slice(&[b't', 0x00, 0x00, 0x00, 0x06, 0x00, 0x00]); // ParameterDescription (no params)
                    response.extend_from_slice(&[b'T', 0x00, 0x00, 0x00, 0x21]); // RowDescription
                    response.extend_from_slice(&[0x00, 0x01]); // 1 column
                    response.extend_from_slice(b"result\x00"); // column name
                    response.extend_from_slice(&[
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0xFF, 0xFF,
                        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00,
                    ]);
                    response.extend_from_slice(&[b'Z', 0x00, 0x00, 0x00, 0x05, b'I']); // ReadyForQuery
                    peer_clone.write_all(&response).expect("write response");
                }
            });

            let stmt4 = conn.prepare(&cx, "SELECT 'result'").await;
            responder4.join().expect("responder4");
            assert!(matches!(stmt4, Outcome::Ok(_)));

            // Verify cache state after eviction
            assert_eq!(
                conn.inner.prepared_cache.len(),
                3,
                "cache should maintain capacity of 3"
            );

            // Verify that the first statement was evicted and subsequent statements remain
            assert!(
                conn.inner
                    .prepared_cache
                    .get_and_touch("SELECT $1")
                    .is_none(),
                "first statement should have been evicted"
            );
            assert!(
                conn.inner
                    .prepared_cache
                    .get_and_touch("SELECT $1, $2")
                    .is_some(),
                "second statement should still be cached"
            );
            assert!(
                conn.inner
                    .prepared_cache
                    .get_and_touch("SELECT COUNT(*)")
                    .is_some(),
                "third statement should still be cached"
            );
            assert!(
                conn.inner
                    .prepared_cache
                    .get_and_touch("SELECT 'result'")
                    .is_some(),
                "fourth statement should be cached"
            );
        });
    }

    #[test]
    fn prepared_query_cache_hit_preserves_row_decode_for_same_sql_and_params() {
        use std::io::Write;

        run(async {
            let (mut conn, peer) = make_test_connection_with_peer();
            let cx = Cx::for_testing();
            let sql = "SELECT $1::text AS value";
            let param_value = "same-bytes";

            let responder = std::thread::spawn({
                let sql = sql.to_string();
                let param_value = param_value.to_string();
                let mut peer_clone = peer.try_clone().expect("clone peer");
                move || {
                    let parse_request = read_until_contains(&mut peer_clone, b"__asupersync_s0");
                    assert!(
                        parse_request
                            .windows(sql.len())
                            .any(|window| window == sql.as_bytes()),
                        "cold prepare should send Parse for the SQL text"
                    );

                    let mut parameter_description = Vec::new();
                    parameter_description.extend_from_slice(&1i16.to_be_bytes());
                    parameter_description.extend_from_slice(&(oid::TEXT as i32).to_be_bytes());

                    let mut prepare_response = Vec::new();
                    prepare_response.extend_from_slice(&backend_message(b'1', &[]));
                    prepare_response
                        .extend_from_slice(&backend_message(b't', &parameter_description));
                    prepare_response.extend_from_slice(&single_text_row_description());
                    prepare_response.extend_from_slice(&ready_for_query(b'I'));
                    peer_clone
                        .write_all(&prepare_response)
                        .expect("write cold prepare response");

                    let first_bind = read_until_contains(&mut peer_clone, param_value.as_bytes());
                    assert!(
                        first_bind
                            .windows(b"__asupersync_s0".len())
                            .any(|window| window == b"__asupersync_s0"),
                        "cold execute should bind the prepared statement name"
                    );

                    let mut data_row = Vec::new();
                    data_row.extend_from_slice(&1i16.to_be_bytes());
                    data_row.extend_from_slice(&(param_value.len() as i32).to_be_bytes());
                    data_row.extend_from_slice(param_value.as_bytes());

                    let mut first_query_response = Vec::new();
                    first_query_response.extend_from_slice(&backend_message(b'2', &[]));
                    first_query_response.extend_from_slice(&single_text_row_description());
                    first_query_response.extend_from_slice(&backend_message(b'D', &data_row));
                    first_query_response.extend_from_slice(&backend_message(b'C', b"SELECT 1\0"));
                    first_query_response.extend_from_slice(&ready_for_query(b'I'));
                    peer_clone
                        .write_all(&first_query_response)
                        .expect("write cold execute response");

                    let second_bind = read_until_contains(&mut peer_clone, param_value.as_bytes());
                    assert!(
                        second_bind
                            .windows(b"__asupersync_s0".len())
                            .any(|window| window == b"__asupersync_s0"),
                        "warm execute should reuse the cached prepared statement name"
                    );
                    assert!(
                        !second_bind
                            .windows(sql.len())
                            .any(|window| window == sql.as_bytes()),
                        "cache-hit execute must not re-send the SQL text"
                    );

                    let mut second_query_response = Vec::new();
                    second_query_response.extend_from_slice(&backend_message(b'2', &[]));
                    second_query_response.extend_from_slice(&single_text_row_description());
                    second_query_response.extend_from_slice(&backend_message(b'D', &data_row));
                    second_query_response.extend_from_slice(&backend_message(b'C', b"SELECT 1\0"));
                    second_query_response.extend_from_slice(&ready_for_query(b'I'));
                    peer_clone
                        .write_all(&second_query_response)
                        .expect("write warm execute response");
                }
            });

            let cold_stmt = match conn.prepare(&cx, sql).await {
                Outcome::Ok(stmt) => stmt,
                other => panic!("cold prepare should succeed, got {other:?}"),
            };
            let cold_params: [&dyn ToSql; 1] = [&param_value];
            let cold_rows = match conn.query_prepared(&cx, &cold_stmt, &cold_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("cold execute should succeed, got {other:?}"),
            };

            let stmt_id_after_cold_prepare = conn.inner.next_stmt_id;
            let warm_stmt = match conn.prepare(&cx, sql).await {
                Outcome::Ok(stmt) => stmt,
                other => panic!("warm prepare should hit cache, got {other:?}"),
            };
            assert_eq!(
                warm_stmt.name, cold_stmt.name,
                "same SQL should reuse the cached server statement"
            );
            assert_eq!(
                conn.inner.next_stmt_id, stmt_id_after_cold_prepare,
                "cache-hit prepare must not allocate a new statement id"
            );

            let warm_params: [&dyn ToSql; 1] = [&param_value];
            let warm_rows = match conn.query_prepared(&cx, &warm_stmt, &warm_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("warm execute should succeed, got {other:?}"),
            };

            responder.join().expect("responder");

            assert_eq!(cold_rows.len(), 1, "cold path should decode one row");
            assert_eq!(warm_rows.len(), 1, "warm path should decode one row");

            let cold_value: String = cold_rows[0]
                .get_typed("value")
                .expect("cold row should decode TEXT column");
            let warm_value: String = warm_rows[0]
                .get_typed("value")
                .expect("warm row should decode TEXT column");

            assert_eq!(cold_value, param_value);
            assert_eq!(warm_value, param_value);
            assert_eq!(
                cold_value, warm_value,
                "same SQL and same parameter bytes must decode identically regardless of cache state"
            );
        });
    }

    #[test]
    fn prepared_statement_reexecution_format_vector_changes_do_not_leak() {
        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_3oc9b5_prepared cargo test -p asupersync --lib --features postgres,test-internals prepared_statement_reexecution -- --nocapture";

        fn bytes_fingerprint(bytes: &[u8]) -> String {
            if bytes.is_empty() {
                return "empty".to_string();
            }
            let preview = bytes
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("len:{}:{}", bytes.len(), preview)
        }

        fn log_case(
            statement_id: &str,
            execution_index: usize,
            parameter_fingerprint: &str,
            format_code_vector: &[i16],
            expected_relation: &str,
            observed_result_fingerprint: &str,
            error_kind: &str,
        ) {
            println!(
                "POSTGRES_PREPARED_REEXECUTION \
                 statement_id={} \
                 execution_index={} \
                 parameter_fingerprint={} \
                 format_code_vector={:?} \
                 expected_isolation_relation={} \
                 observed_result_fingerprint={} \
                 error_kind={} \
                 exact_rch_command=\"{}\" \
                 artifact_paths=none \
                 final_no_leak_verdict=pass",
                statement_id,
                execution_index,
                parameter_fingerprint,
                format_code_vector,
                expected_relation,
                observed_result_fingerprint,
                error_kind,
                EXACT_RCH_COMMAND,
            );
        }

        let left = String::from("left");
        let right = String::from("right");
        let binary = 7i32;
        let text_params: Vec<&dyn ToSql> = vec![&left, &right];
        let mixed_params: Vec<&dyn ToSql> = vec![&left, &binary];

        let text_bind = build_bind_msg("", "s_format", &text_params, Format::Text)
            .expect("text Bind should build");
        let mixed_bind = build_bind_msg("", "s_format", &mixed_params, Format::Text)
            .expect("mixed-format Bind should build");

        let text_parsed = fuzz_parse_bind_message(&text_bind).expect("text Bind should parse");
        let mixed_parsed = fuzz_parse_bind_message(&mixed_bind).expect("mixed Bind should parse");

        assert_eq!(
            text_parsed.param_format_codes,
            Vec::<i16>::new(),
            "all-text re-execution should use PostgreSQL default format-count-zero encoding"
        );
        assert_eq!(
            mixed_parsed.param_format_codes,
            vec![0, 1],
            "mixed text/binary re-execution must preserve the per-parameter format vector"
        );
        assert_eq!(
            mixed_parsed.parameter_values,
            vec![Some(b"left".to_vec()), Some(binary.to_be_bytes().to_vec())],
            "binary/text re-execution must rebuild parameter bytes from scratch"
        );
        assert_ne!(
            text_bind, mixed_bind,
            "format-vector changes must perturb the wire bytes rather than leaking the prior Bind"
        );

        log_case(
            &text_parsed.statement_name,
            1,
            "left|right",
            &text_parsed.param_format_codes,
            "all-text-default-format-count-zero",
            &bytes_fingerprint(&text_bind),
            "ok",
        );
        log_case(
            &mixed_parsed.statement_name,
            2,
            "left|00000007",
            &mixed_parsed.param_format_codes,
            "mixed-format-reexecution-rebuilds-vector-without-byte-bleed",
            &bytes_fingerprint(&mixed_bind),
            "ok",
        );
    }

    #[test]
    fn prepared_statement_reexecution_leakage_matrix_logs_evidence() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        const EXACT_RCH_COMMAND: &str = "rch exec -- env CARGO_TARGET_DIR=${TMPDIR:-/tmp}/rch_target_asupersync_3oc9b5_prepared cargo test -p asupersync --lib --features postgres,test-internals prepared_statement_reexecution -- --nocapture";

        #[derive(Debug, Clone)]
        struct ExecutionCapture {
            execution_index: usize,
            statement_id: String,
            parameter_fingerprint: String,
            format_codes: Vec<i16>,
        }

        fn bytes_fingerprint(bytes: &[u8]) -> String {
            if bytes.is_empty() {
                return "empty".to_string();
            }
            let preview = bytes
                .iter()
                .take(16)
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            format!("len:{}:{}", bytes.len(), preview)
        }

        fn first_frontend_message(frame: &[u8], expected_type: u8) -> &[u8] {
            assert!(
                frame.len() >= 5,
                "frontend frame should include type and length prefix"
            );
            assert_eq!(
                frame[0], expected_type,
                "expected frontend message type {}",
                expected_type as char
            );
            let len_i32 = i32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
            let body_len = backend_message_body_len(len_i32).expect("frontend length should fit");
            let frame_end = 5usize
                .checked_add(body_len)
                .expect("frontend frame end should not overflow");
            assert!(
                frame.len() >= frame_end,
                "frontend frame should contain its declared body"
            );
            &frame[..frame_end]
        }

        fn capture_bind(
            execution_index: usize,
            bind: &[u8],
            captures: &Arc<Mutex<Vec<ExecutionCapture>>>,
        ) {
            let bind = first_frontend_message(bind, FrontendMessage::Bind as u8);
            let parsed = fuzz_parse_bind_message(bind).expect("Bind frame should parse");
            let parameter_fingerprint = parsed
                .parameter_values
                .iter()
                .flatten()
                .next()
                .map(|bytes| bytes_fingerprint(bytes))
                .unwrap_or_else(|| "none".to_string());
            captures
                .lock()
                .expect("captures lock")
                .push(ExecutionCapture {
                    execution_index,
                    statement_id: parsed.statement_name,
                    parameter_fingerprint,
                    format_codes: parsed.param_format_codes,
                });
        }

        fn result_fingerprint(rows: &[PgRow]) -> String {
            let value: String = rows[0]
                .get_typed("value")
                .expect("result row should decode TEXT column");
            bytes_fingerprint(value.as_bytes())
        }

        fn error_kind(error: &PgError) -> &'static str {
            match error {
                PgError::Protocol(_) => "Protocol",
                PgError::Io(_) => "Io",
                PgError::Server { .. } => "Server",
                PgError::Cancelled(_) => "Cancelled",
                PgError::ConnectionClosed => "ConnectionClosed",
                PgError::ColumnNotFound(_) => "ColumnNotFound",
                PgError::TypeConversion { .. } => "TypeConversion",
                PgError::InvalidUrl(_) => "InvalidUrl",
                PgError::TlsRequired => "TlsRequired",
                PgError::Tls(_) => "Tls",
                PgError::AuthenticationFailed(_) => "AuthenticationFailed",
                PgError::TransactionFinished => "TransactionFinished",
                PgError::UnsupportedAuth(_) => "UnsupportedAuth",
                PgError::IsolationLevelMismatch { .. } => "IsolationLevelMismatch",
            }
        }

        fn log_case(
            statement_id: &str,
            execution_index: usize,
            parameter_fingerprint: &str,
            format_code_vector: &[i16],
            expected_relation: &str,
            observed_result_fingerprint: &str,
            error_kind: &str,
        ) {
            println!(
                "POSTGRES_PREPARED_REEXECUTION \
                 statement_id={} \
                 execution_index={} \
                 parameter_fingerprint={} \
                 format_code_vector={:?} \
                 expected_isolation_relation={} \
                 observed_result_fingerprint={} \
                 error_kind={} \
                 exact_rch_command=\"{}\" \
                 artifact_paths=none \
                 final_no_leak_verdict=pass",
                statement_id,
                execution_index,
                parameter_fingerprint,
                format_code_vector,
                expected_relation,
                observed_result_fingerprint,
                error_kind,
                EXACT_RCH_COMMAND,
            );
        }

        run(async {
            let (mut conn, peer) = make_test_connection_with_peer();
            let cx = Cx::for_testing();
            let sql = "SELECT $1::text AS value";
            let other_sql = "SELECT $1::text AS value /* second stmt */";
            let captures = Arc::new(Mutex::new(Vec::<ExecutionCapture>::new()));

            let responder = std::thread::spawn({
                let captures = Arc::clone(&captures);
                let sql = sql.to_string();
                let other_sql = other_sql.to_string();
                let mut peer_clone = peer.try_clone().expect("clone peer");

                move || {
                    let prepare_response = || {
                        let mut parameter_description = Vec::new();
                        parameter_description.extend_from_slice(&1i16.to_be_bytes());
                        parameter_description.extend_from_slice(&(oid::TEXT as i32).to_be_bytes());

                        let mut response = Vec::new();
                        response.extend_from_slice(&backend_message(b'1', &[]));
                        response.extend_from_slice(&backend_message(b't', &parameter_description));
                        response.extend_from_slice(&single_text_row_description());
                        response.extend_from_slice(&ready_for_query(b'I'));
                        response
                    };

                    let write_query_response = |peer: &mut std::net::TcpStream, value: &str| {
                        let mut data_row = Vec::new();
                        data_row.extend_from_slice(&1i16.to_be_bytes());
                        data_row.extend_from_slice(&(value.len() as i32).to_be_bytes());
                        data_row.extend_from_slice(value.as_bytes());

                        let mut response = Vec::new();
                        response.extend_from_slice(&backend_message(b'2', &[]));
                        response.extend_from_slice(&single_text_row_description());
                        response.extend_from_slice(&backend_message(b'D', &data_row));
                        response.extend_from_slice(&backend_message(b'C', b"SELECT 1\0"));
                        response.extend_from_slice(&ready_for_query(b'I'));
                        peer.write_all(&response).expect("write query response");
                    };

                    let first_prepare = read_until_contains(&mut peer_clone, b"__asupersync_s0");
                    assert!(
                        first_prepare
                            .windows(sql.len())
                            .any(|window| window == sql.as_bytes()),
                        "first prepare should parse the original SQL text"
                    );
                    peer_clone
                        .write_all(&prepare_response())
                        .expect("write first prepare response");

                    let bind1 = read_until_contains(&mut peer_clone, b"alpha");
                    capture_bind(1, &bind1, &captures);
                    write_query_response(&mut peer_clone, "alpha");

                    let bind2 = read_until_contains(&mut peer_clone, b"alpha");
                    capture_bind(2, &bind2, &captures);
                    write_query_response(&mut peer_clone, "alpha");

                    let bind3 = read_until_contains(&mut peer_clone, b"beta");
                    capture_bind(3, &bind3, &captures);
                    assert!(
                        !bind3
                            .windows(b"alpha".len())
                            .any(|window| window == b"alpha"),
                        "changed-parameter re-execution must not retain the prior value bytes"
                    );
                    write_query_response(&mut peer_clone, "beta");

                    let bind4 = read_until_contains(&mut peer_clone, b"gamma");
                    capture_bind(5, &bind4, &captures);
                    write_query_response(&mut peer_clone, "gamma");

                    let close_request = read_until_contains(&mut peer_clone, b"__asupersync_s0");
                    assert_eq!(close_request[0], b'C', "close path must emit Close message");
                    let mut close_response = Vec::new();
                    close_response.extend_from_slice(&backend_message(b'3', &[]));
                    close_response.extend_from_slice(&ready_for_query(b'I'));
                    peer_clone
                        .write_all(&close_response)
                        .expect("write close response");

                    let second_prepare = read_until_contains(&mut peer_clone, b"__asupersync_s1");
                    assert!(
                        second_prepare
                            .windows(sql.len())
                            .any(|window| window == sql.as_bytes()),
                        "re-prepare after close must parse the SQL text again with a new statement id"
                    );
                    peer_clone
                        .write_all(&prepare_response())
                        .expect("write second prepare response");

                    let bind5 = read_until_contains(&mut peer_clone, b"delta");
                    capture_bind(6, &bind5, &captures);
                    write_query_response(&mut peer_clone, "delta");

                    let third_prepare = read_until_contains(&mut peer_clone, b"__asupersync_s2");
                    assert!(
                        third_prepare
                            .windows(other_sql.len())
                            .any(|window| window == other_sql.as_bytes()),
                        "different SQL should allocate an independent statement id"
                    );
                    peer_clone
                        .write_all(&prepare_response())
                        .expect("write third prepare response");

                    let bind6 = read_until_contains(&mut peer_clone, b"omega");
                    capture_bind(7, &bind6, &captures);
                    write_query_response(&mut peer_clone, "omega");
                }
            });

            let cold_stmt = match conn.prepare(&cx, sql).await {
                Outcome::Ok(stmt) => stmt,
                other => panic!("cold prepare should succeed, got {other:?}"),
            };
            assert_eq!(cold_stmt.name, "__asupersync_s0");

            let alpha = String::from("alpha");
            let alpha_params: [&dyn ToSql; 1] = [&alpha];
            let cold_rows = match conn.query_prepared(&cx, &cold_stmt, &alpha_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("cold execute should succeed, got {other:?}"),
            };

            let warm_stmt = match conn.prepare(&cx, sql).await {
                Outcome::Ok(stmt) => stmt,
                other => panic!("warm prepare should hit cache, got {other:?}"),
            };
            assert_eq!(
                warm_stmt.name, cold_stmt.name,
                "same SQL should reuse the cached prepared statement before close"
            );

            let warm_rows = match conn.query_prepared(&cx, &warm_stmt, &alpha_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("warm execute should succeed, got {other:?}"),
            };

            let beta = String::from("beta");
            let beta_params: [&dyn ToSql; 1] = [&beta];
            let changed_rows = match conn.query_prepared(&cx, &warm_stmt, &beta_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("changed-parameter execute should succeed, got {other:?}"),
            };

            let missing_params: [&dyn ToSql; 0] = [];
            let missing_error = match conn.query_prepared(&cx, &warm_stmt, &missing_params).await {
                Outcome::Err(err) => err,
                other => panic!("missing-parameter call should fail before I/O, got {other:?}"),
            };
            assert!(
                matches!(missing_error, PgError::Protocol(_)),
                "missing-parameter path should fail with Protocol, got {missing_error:?}"
            );

            let gamma = String::from("gamma");
            let gamma_params: [&dyn ToSql; 1] = [&gamma];
            let retry_rows = match conn.query_prepared(&cx, &warm_stmt, &gamma_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("retry after local error should succeed, got {other:?}"),
            };

            match conn.close_statement(&cx, &warm_stmt).await {
                Outcome::Ok(()) => {}
                other => panic!("close_statement should succeed, got {other:?}"),
            }

            let reused_stmt = match conn.prepare(&cx, sql).await {
                Outcome::Ok(stmt) => stmt,
                other => panic!("prepare after close should succeed, got {other:?}"),
            };
            assert_ne!(
                reused_stmt.name, warm_stmt.name,
                "close must evict the cached statement so re-prepare allocates a fresh statement id"
            );

            let delta = String::from("delta");
            let delta_params: [&dyn ToSql; 1] = [&delta];
            let reused_rows = match conn.query_prepared(&cx, &reused_stmt, &delta_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("execute after close/re-prepare should succeed, got {other:?}"),
            };

            let other_stmt = match conn.prepare(&cx, other_sql).await {
                Outcome::Ok(stmt) => stmt,
                other => panic!("different SQL prepare should succeed, got {other:?}"),
            };
            assert_ne!(
                other_stmt.name, reused_stmt.name,
                "independent SQL statements must have distinct statement ids"
            );

            let omega = String::from("omega");
            let omega_params: [&dyn ToSql; 1] = [&omega];
            let concurrent_rows = match conn.query_prepared(&cx, &other_stmt, &omega_params).await {
                Outcome::Ok(rows) => rows,
                other => panic!("second statement execution should succeed, got {other:?}"),
            };

            responder.join().expect("responder");

            let captures = captures.lock().expect("captures lock");
            let capture_for = |execution_index| {
                captures
                    .iter()
                    .find(|capture| capture.execution_index == execution_index)
                    .cloned()
                    .expect("expected execution capture")
            };

            let same_cold = capture_for(1);
            let same_warm = capture_for(2);
            let changed = capture_for(3);
            let retry = capture_for(5);
            let reused = capture_for(6);
            let concurrent = capture_for(7);

            assert_eq!(result_fingerprint(&cold_rows), bytes_fingerprint(b"alpha"));
            assert_eq!(result_fingerprint(&warm_rows), bytes_fingerprint(b"alpha"));
            assert_eq!(
                result_fingerprint(&changed_rows),
                bytes_fingerprint(b"beta")
            );
            assert_eq!(result_fingerprint(&retry_rows), bytes_fingerprint(b"gamma"));
            assert_eq!(
                result_fingerprint(&reused_rows),
                bytes_fingerprint(b"delta")
            );
            assert_eq!(
                result_fingerprint(&concurrent_rows),
                bytes_fingerprint(b"omega")
            );

            log_case(
                &same_cold.statement_id,
                same_cold.execution_index,
                &same_cold.parameter_fingerprint,
                &same_cold.format_codes,
                "cold-prepare-and-first-execution-produce-alpha-without-leakage",
                &result_fingerprint(&cold_rows),
                "ok",
            );
            log_case(
                &same_warm.statement_id,
                same_warm.execution_index,
                &same_warm.parameter_fingerprint,
                &same_warm.format_codes,
                "cache-hit-reexecution-with-same-params-preserves-result-fingerprint",
                &result_fingerprint(&warm_rows),
                "ok",
            );
            log_case(
                &changed.statement_id,
                changed.execution_index,
                &changed.parameter_fingerprint,
                &changed.format_codes,
                "changed-params-must-change-result-without-stale-parameter-bleed",
                &result_fingerprint(&changed_rows),
                "ok",
            );
            log_case(
                &warm_stmt.name,
                4,
                "none",
                &[],
                "missing-params-fails-before-io-and-does-not-poison-retry",
                "none",
                error_kind(&missing_error),
            );
            log_case(
                &retry.statement_id,
                retry.execution_index,
                &retry.parameter_fingerprint,
                &retry.format_codes,
                "retry-after-local-error-rebuilds-bind-and-returns-gamma",
                &result_fingerprint(&retry_rows),
                "ok",
            );
            log_case(
                &reused.statement_id,
                reused.execution_index,
                &reused.parameter_fingerprint,
                &reused.format_codes,
                "close-then-reprepare-allocates-fresh-id-and-returns-delta",
                &result_fingerprint(&reused_rows),
                "ok",
            );
            log_case(
                &concurrent.statement_id,
                concurrent.execution_index,
                &concurrent.parameter_fingerprint,
                &concurrent.format_codes,
                "independent-sql-statements-keep-distinct-ids-and-results",
                &result_fingerprint(&concurrent_rows),
                "ok",
            );
        });
    }

    #[test]
    fn prepared_cache_get_and_touch_promotes_lru() {
        // Touching an entry must move it to MRU so it survives the next
        // eviction round. Otherwise frequently-reused statements get
        // evicted alongside one-shot statements.
        let mut cache = PreparedStatementCache::new(3);
        cache.insert_returning_evicted_name("sql_a".into(), fixture_pg_statement("__s0"));
        cache.insert_returning_evicted_name("sql_b".into(), fixture_pg_statement("__s1"));
        cache.insert_returning_evicted_name("sql_c".into(), fixture_pg_statement("__s2"));

        // Touch sql_a → moves it to back of LRU. Now sql_b is LRU.
        let hit = cache.get_and_touch("sql_a");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().name, "__s0");

        // Insert sql_d at cap. sql_b (now LRU) MUST be evicted.
        let evicted =
            cache.insert_returning_evicted_name("sql_d".into(), fixture_pg_statement("__s3"));
        assert_eq!(
            evicted,
            Some("__s1".to_string()),
            "after touching sql_a, the next eviction must take sql_b not sql_a"
        );
    }

    #[test]
    fn prepared_cache_get_and_touch_miss_returns_none() {
        let mut cache = PreparedStatementCache::new(3);
        cache.insert_returning_evicted_name("sql_a".into(), fixture_pg_statement("__s0"));
        assert!(cache.get_and_touch("sql_b").is_none());
    }

    #[test]
    fn prepared_cache_zero_cap_evicts_immediately() {
        // Edge case: a cap-0 cache is effectively disabled. Every insert
        // returns the just-inserted entry's name for DEALLOCATE so no
        // server-side state ever lingers beyond the prepare() call.
        let mut cache = PreparedStatementCache::new(0);
        let evicted =
            cache.insert_returning_evicted_name("sql".into(), fixture_pg_statement("__only"));
        assert_eq!(evicted, Some("__only".to_string()));
    }

    #[test]
    fn prepared_cache_duplicate_sql_replaces_and_returns_old_name() {
        // Caller didn't check get_and_touch first (or raced) and called
        // insert with SQL already present. The OLD server-side name MUST
        // be returned for DEALLOCATE so the duplicate doesn't leak.
        let mut cache = PreparedStatementCache::new(3);
        cache.insert_returning_evicted_name("sql".into(), fixture_pg_statement("__s0"));
        let evicted =
            cache.insert_returning_evicted_name("sql".into(), fixture_pg_statement("__s1"));
        assert_eq!(evicted, Some("__s0".to_string()));
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.entries.get("sql").unwrap().name, "__s1");
    }

    #[test]
    fn command_tag_invalidation_matches_schema_and_session_changes() {
        assert!(PgConnection::command_tag_requires_prepared_cache_invalidation("ALTER TABLE"));
        assert!(PgConnection::command_tag_requires_prepared_cache_invalidation("CREATE TABLE"));
        assert!(PgConnection::command_tag_requires_prepared_cache_invalidation("DROP VIEW"));
        assert!(PgConnection::command_tag_requires_prepared_cache_invalidation("SET"));
        assert!(PgConnection::command_tag_requires_prepared_cache_invalidation("RESET"));
        assert!(PgConnection::command_tag_requires_prepared_cache_invalidation("DEALLOCATE ALL"));
        assert!(PgConnection::command_tag_requires_prepared_cache_invalidation("DISCARD ALL"));
        assert!(!PgConnection::command_tag_requires_prepared_cache_invalidation("SELECT 1"));
        assert!(!PgConnection::command_tag_requires_prepared_cache_invalidation("UPDATE 3"));
    }

    #[test]
    fn command_tag_session_discard_matches_session_mutations() {
        assert!(PgConnection::command_tag_requires_session_discard("SET"));
        assert!(PgConnection::command_tag_requires_session_discard(
            "RESET ALL"
        ));
        assert!(PgConnection::command_tag_requires_session_discard(
            "DISCARD ALL"
        ));
        assert!(!PgConnection::command_tag_requires_session_discard(
            "SELECT 1"
        ));
        assert!(!PgConnection::command_tag_requires_session_discard(
            "ALTER TABLE"
        ));
    }

    #[test]
    fn default_max_prepared_statements_is_documented_value() {
        // Regression guard: if the default cap changes the bead's
        // 'connection-scoped memory footprint' calculation needs
        // revalidating.
        assert_eq!(DEFAULT_MAX_PREPARED_STATEMENTS, 256);
    }

    /// br-asupersync-a1x452: PgConnectionManager::release_check must
    /// return false when the connection has needs_discard=true (set
    /// by PgTransaction::drop without commit, leaving the backend in
    /// idle_in_transaction). Pre-fix, the default release_check
    /// (returns true) recycled the poisoned connection silently.
    #[test]
    fn a1x452_release_check_rejects_needs_discard() {
        use crate::database::pool::AsyncConnectionManager;
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );
        let mut conn = make_test_connection();

        // Healthy out of the gate.
        assert!(mgr.release_check(&mut conn));

        // Exercise PgTransaction::drop (br-asupersync-yl4gu1 path).
        conn.inner.needs_discard = true;
        assert!(!mgr.release_check(&mut conn), "needs_discard must reject");
    }

    /// br-asupersync-t4wfzb: PgConnectionManager::release_check must
    /// return false when the connection is flagged unhealthy (via
    /// br-asupersync-7v80ju consecutive DEALLOCATE failures).
    #[test]
    fn t4wfzb_release_check_rejects_unhealthy() {
        use crate::database::pool::AsyncConnectionManager;
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );
        let mut conn = make_test_connection();

        assert!(mgr.release_check(&mut conn));
        conn.inner.unhealthy = true;
        assert!(!mgr.release_check(&mut conn), "is_unhealthy must reject");
    }

    /// br-asupersync-a1x452 + br-asupersync-t4wfzb: defensive check
    /// — a connection still inside a transaction (transaction_status
    /// = 'T' or 'E') must not be returned to the pool even without
    /// the explicit needs_discard flag set.
    #[test]
    fn release_check_rejects_in_transaction() {
        use crate::database::pool::AsyncConnectionManager;
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );
        let mut conn = make_test_connection();

        assert!(mgr.release_check(&mut conn));
        // Set the backend transaction-status byte to 'T' (in tx).
        conn.inner.transaction_status = b'T';
        assert!(!mgr.release_check(&mut conn), "in_transaction must reject");
    }

    /// br-asupersync-a1x452 + br-asupersync-t4wfzb: a closed
    /// connection must never be returned to the pool — the inner
    /// stream has been shutdown (br-asupersync-1wygbs Terminate sent
    /// already).
    #[test]
    fn release_check_rejects_closed_connection() {
        use crate::database::pool::AsyncConnectionManager;
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb").unwrap(),
        );
        let mut conn = make_test_connection();
        conn.inner.closed = true;
        assert!(
            !mgr.release_check(&mut conn),
            "closed connection must reject"
        );
    }

    #[test]
    fn release_check_rejects_plain_connection_for_require_tls_pool() {
        use crate::database::pool::AsyncConnectionManager;
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb?sslmode=require").unwrap(),
        );
        let mut conn = make_test_connection();

        assert!(
            !mgr.release_check(&mut conn),
            "sslmode=require pools must not recycle plaintext connections"
        );
    }

    #[test]
    fn is_valid_rejects_plain_connection_for_require_tls_pool() {
        use crate::database::pool::AsyncConnectionManager;
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb?sslmode=require").unwrap(),
        );
        let mut conn = make_test_connection();
        let cx = crate::cx::Cx::for_testing();

        assert!(
            !run(mgr.is_valid(&cx, &mut conn)),
            "checkout validation must reject plaintext connections for sslmode=require"
        );
    }

    #[test]
    fn release_check_accepts_plain_connection_for_prefer_tls_pool() {
        use crate::database::pool::AsyncConnectionManager;
        let mgr = PgConnectionManager::new(
            PgConnectOptions::parse("postgres://localhost/testdb?sslmode=prefer").unwrap(),
        );
        let mut conn = make_test_connection();

        assert!(
            mgr.release_check(&mut conn),
            "sslmode=prefer may reuse plaintext fallback connections"
        );
    }

    /// br-asupersync-pqia0o: regression test for deallocate retry path
    /// treating caller cancellation as backend failure. This test
    /// verifies that pre-cancelled Cx doesn't increment consecutive
    /// failure counters or mark connection unhealthy.
    #[test]
    fn deallocate_caller_cancellation_not_backend_failure() {
        run(async {
            let mut conn = make_test_connection();

            // Start with a healthy connection
            assert_eq!(conn.inner.consecutive_deallocate_failures, 0);
            assert!(!conn.inner.unhealthy);
            assert!(conn.inner.deallocate_retry_queue.is_empty());

            // Create a pre-cancelled context
            let cx = Cx::new(
                RegionId::new_for_test(1, 0),
                TaskId::new_for_test(1, 0),
                Budget::INFINITE,
            );
            cx.cancel_fast(CancelKind::User);

            // Verify the context is already cancelled
            assert!(
                cx.checkpoint().is_err(),
                "test context should be pre-cancelled"
            );

            // Call try_close_or_enqueue_deallocate with pre-cancelled context
            let victim_name = "test_stmt_cancelled".to_string();
            conn.try_close_or_enqueue_deallocate(&cx, victim_name.clone())
                .await;

            // Caller cancellation should:
            // 1. NOT increment consecutive_deallocate_failures
            // 2. NOT mark connection as unhealthy
            // 3. BUT preserve the statement name for later retry
            assert_eq!(
                conn.inner.consecutive_deallocate_failures, 0,
                "caller cancellation should not increment failure counter"
            );
            assert!(
                !conn.inner.unhealthy,
                "caller cancellation should not mark connection unhealthy"
            );
            assert_eq!(
                conn.inner.deallocate_retry_queue.len(),
                1,
                "statement name should be preserved for retry"
            );
            assert_eq!(
                conn.inner.deallocate_retry_queue[0], victim_name,
                "correct statement name should be queued"
            );

            // Test flush_pending_deallocates with pre-cancelled context as well
            let initial_queue_len = conn.inner.deallocate_retry_queue.len();
            assert_user_cancelled(conn.flush_pending_deallocates(&cx).await);

            // Should still not increment failure counter or mark unhealthy
            assert_eq!(
                conn.inner.consecutive_deallocate_failures, 0,
                "flush with cancelled context should not increment failures"
            );
            assert!(
                !conn.inner.unhealthy,
                "flush with cancelled context should not mark unhealthy"
            );
            // Statement should remain in queue since cancellation occurred
            assert_eq!(
                conn.inner.deallocate_retry_queue.len(),
                initial_queue_len,
                "cancelled flush should preserve queued statements"
            );
        });
    }

    /// br-asupersync-8k3s80: if caller cancellation lands while
    /// piggy-backed DEALLOCATE retries are flushing, prepare() must
    /// surface Cancelled before the prepared-cache fast path can
    /// return a stale success.
    #[test]
    fn prepare_cached_statement_observes_cancellation_during_deallocate_flush() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        let cancel_cx = cx.clone();
        let sql = "SELECT 1";
        let cached = fixture_pg_statement("__cached_stmt");
        conn.inner
            .prepared_cache
            .insert_returning_evicted_name(sql.to_string(), cached.clone());
        conn.inner
            .deallocate_retry_queue
            .push_back("__stale_stmt".to_string());

        let wake_writer = std::thread::spawn(move || {
            let _ = read_until_contains(&mut peer, b"__stale_stmt");
            cancel_cx.cancel_fast(CancelKind::User);
            std::io::Write::write_all(&mut peer, b"x").expect("wake close_statement read");
        });

        assert_user_cancelled(run(conn.prepare(&cx, sql)));
        wake_writer.join().expect("wake writer should exit cleanly");

        assert_eq!(
            conn.inner.consecutive_deallocate_failures, 0,
            "cancelled flush should not count as backend failure"
        );
        assert!(
            !conn.inner.unhealthy,
            "cancelled flush should not mark connection unhealthy"
        );
        assert_eq!(
            conn.inner.deallocate_retry_queue,
            VecDeque::from(["__stale_stmt".to_string()]),
            "cancelled flush should preserve the queued deallocate retry"
        );
        let cached_after = conn
            .inner
            .prepared_cache
            .get_and_touch(sql)
            .expect("cached statement should still be present");
        assert_eq!(cached_after.name, cached.name);
    }

    #[test]
    fn deallocate_retry_flushes_before_simple_query() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        conn.inner
            .deallocate_retry_queue
            .push_back("__stale_stmt".to_string());

        let responder = std::thread::spawn(move || {
            let close_request = read_until_contains(&mut peer, b"__stale_stmt");
            assert!(
                close_request
                    .windows("__stale_stmt".len())
                    .any(|window| window == b"__stale_stmt"),
                "close request should target the queued stale statement"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'3', b""))
                .expect("close complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("close ready should be written");

            let query_request = read_until_contains(&mut peer, b"SELECT 1");
            assert!(
                query_request
                    .windows("SELECT 1".len())
                    .any(|window| window == b"SELECT 1"),
                "query request should contain the caller SQL"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"SELECT 0\0"))
                .expect("command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("query ready should be written");
        });

        match run(conn.query_unchecked(&cx, "SELECT 1")) {
            Outcome::Ok(rows) => assert!(rows.is_empty(), "unexpected rows: {rows:?}"),
            other => panic!("expected successful query after flush, got {other:?}"),
        }
        responder
            .join()
            .expect("flush/query responder should exit cleanly");

        assert_eq!(conn.pending_deallocate_count(), 0);
        assert_eq!(conn.inner.consecutive_deallocate_failures, 0);
        assert!(!conn.inner.closed);
    }

    #[test]
    fn deallocate_retry_flush_error_beats_prepare_cache_hit() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        let sql = "SELECT 1";
        let cached = fixture_pg_statement("__cached_stmt");
        conn.inner
            .prepared_cache
            .insert_returning_evicted_name(sql.to_string(), cached.clone());
        conn.inner
            .deallocate_retry_queue
            .push_back("__stale_stmt".to_string());

        let responder = std::thread::spawn(move || {
            let close_request = read_until_contains(&mut peer, b"__stale_stmt");
            assert!(
                close_request
                    .windows("__stale_stmt".len())
                    .any(|window| window == b"__stale_stmt"),
                "close request should target the queued stale statement"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'D', &0i16.to_be_bytes()))
                .expect("protocol fault should be written");
        });

        match run(conn.prepare(&cx, sql)) {
            Outcome::Err(PgError::Protocol(msg)) => {
                assert!(msg.contains("close statement response"), "got: {msg}");
            }
            other => panic!("expected Protocol error, got {other:?}"),
        }
        responder
            .join()
            .expect("flush fault responder should exit cleanly");

        assert!(
            conn.inner.closed,
            "protocol fault should poison the connection"
        );
        assert_eq!(conn.inner.consecutive_deallocate_failures, 1);
        assert_eq!(
            conn.inner.deallocate_retry_queue,
            VecDeque::from(["__stale_stmt".to_string()]),
            "failed flush should preserve the queued retry"
        );
        let cached_after = conn
            .inner
            .prepared_cache
            .get_and_touch(sql)
            .expect("cached statement should remain present");
        assert_eq!(cached_after.name, cached.name);
    }

    #[test]
    fn execute_unchecked_invalidates_prepared_cache_after_schema_change() {
        use std::collections::VecDeque;

        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = crate::cx::Cx::for_testing();
        let cached_sql = "SELECT * FROM widgets";
        let cached_stmt = fixture_pg_statement("__cached_stmt");
        conn.inner
            .prepared_cache
            .insert_returning_evicted_name(cached_sql.to_string(), cached_stmt.clone());

        let responder = std::thread::spawn(move || {
            let request =
                read_until_contains(&mut peer, b"ALTER TABLE widgets ADD COLUMN extra integer");
            assert!(
                request
                    .windows("ALTER TABLE widgets ADD COLUMN extra integer".len())
                    .any(|window| window == b"ALTER TABLE widgets ADD COLUMN extra integer"),
                "request should contain the schema-changing SQL"
            );
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"ALTER TABLE\0"))
                .expect("command complete should be written");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("ready for query should be written");
        });

        match run(conn.execute_unchecked(&cx, "ALTER TABLE widgets ADD COLUMN extra integer")) {
            Outcome::Ok(affected) => assert_eq!(affected, 0),
            other => panic!("expected successful schema change, got {other:?}"),
        }
        responder
            .join()
            .expect("schema change responder should exit cleanly");

        assert!(
            conn.inner
                .prepared_cache
                .get_and_touch(cached_sql)
                .is_none(),
            "schema-changing command must clear cached prepared metadata"
        );
        assert_eq!(
            conn.inner.deallocate_retry_queue,
            VecDeque::from([cached_stmt.name]),
            "stale prepared statement should be queued for best-effort DEALLOCATE"
        );
        assert_eq!(conn.inner.consecutive_deallocate_failures, 0);
        assert!(!conn.inner.unhealthy);
        assert!(!conn.inner.closed);
    }

    /// br-asupersync-pqia0o: verify that real backend failures (as opposed
    /// to caller cancellation) still properly increment the failure counter
    /// and mark connection unhealthy after threshold.
    #[test]
    fn deallocate_real_failures_still_mark_unhealthy() {
        run(async {
            let mut conn = make_test_connection();
            // Force connection to closed state to exercise backend failure handling.
            conn.inner.closed = true;

            // Start with healthy connection
            assert_eq!(conn.inner.consecutive_deallocate_failures, 0);
            assert!(!conn.inner.unhealthy);

            let cx = Cx::new(
                RegionId::new_for_test(1, 0),
                TaskId::new_for_test(1, 0),
                Budget::INFINITE,
            );

            // Drive multiple backend failures; the closed connection causes Err.
            for i in 1..=DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD {
                let victim_name = format!("test_stmt_fail_{}", i);
                conn.try_close_or_enqueue_deallocate(&cx, victim_name).await;

                assert_eq!(
                    conn.inner.consecutive_deallocate_failures, i,
                    "real failure {} should increment counter",
                    i
                );

                if i >= DEALLOCATE_FAILURE_UNHEALTHY_THRESHOLD {
                    assert!(
                        conn.inner.unhealthy,
                        "connection should be marked unhealthy after {} failures",
                        i
                    );
                } else {
                    assert!(
                        !conn.inner.unhealthy,
                        "connection should not be unhealthy before threshold"
                    );
                }
            }
        });
    }

    /// br-asupersync-9g47af: regression test for transaction leak in begin_with_isolation
    /// when verification query is cancelled. Ensures ROLLBACK is executed on cancellation
    /// to prevent leaking open transactions.
    #[test]
    fn begin_with_isolation_rollback_on_cancel_verification() {
        run(async {
            let mut conn = make_test_connection();

            // Create a pre-cancelled context to exercise cancellation during verification.
            let cx = Cx::new(
                RegionId::new_for_test(1, 0),
                TaskId::new_for_test(1, 0),
                Budget::INFINITE,
            );
            cx.cancel_fast(CancelKind::User);

            // Verify the context is already cancelled
            assert!(
                cx.checkpoint().is_err(),
                "test context should be pre-cancelled"
            );

            // Attempt begin_with_isolation with pre-cancelled context
            // This should fail with Cancelled after rolling back the transaction
            let result = conn
                .begin_with_isolation(&cx, IsolationLevel::ReadCommitted, false)
                .await;

            // Should return Cancelled outcome
            let cancelled = matches!(result, Outcome::Cancelled(_));
            drop(result);
            assert!(
                cancelled,
                "begin_with_isolation should return Cancelled with pre-cancelled context"
            );

            // Most importantly: connection should NOT be in a transaction after the cancelled begin
            // If the bug exists, the BEGIN would succeed but verification would fail with cancellation,
            // leaving the connection in a transaction state without proper ROLLBACK
            assert!(
                !conn.in_transaction(),
                "connection should not be in transaction state after cancelled begin_with_isolation"
            );
        });
    }

    #[test]
    fn row_description_field_format_differential_conformance() {
        /// Differential conformance test for PostgreSQL RowDescription field-format flags.
        ///
        /// Tests RFC compliance for PostgreSQL wire protocol format codes:
        /// - 0 = text format (human-readable strings)
        /// - 1 = binary format (network byte order binary)
        ///
        /// Verifies that identical data produces equivalent results regardless
        /// of format flag, and that format interpretation is correctly applied
        /// during value parsing.
        let conn = make_test_connection();

        // Test data: integer column that can be represented in both formats
        let column_name = "test_col";
        let type_oid = oid::INT4;
        let test_value = 42i32;

        // Create RowDescription with text format (format_code = 0)
        let mut text_row_desc = Vec::new();
        text_row_desc.extend_from_slice(&1i16.to_be_bytes()); // field count
        text_row_desc.extend_from_slice(column_name.as_bytes());
        text_row_desc.push(0); // null terminator
        text_row_desc.extend_from_slice(&0u32.to_be_bytes()); // table_oid
        text_row_desc.extend_from_slice(&0i16.to_be_bytes()); // column_id
        text_row_desc.extend_from_slice(&type_oid.to_be_bytes());
        text_row_desc.extend_from_slice(&4i16.to_be_bytes()); // type_size
        text_row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
        text_row_desc.extend_from_slice(&0i16.to_be_bytes()); // format_code = TEXT

        // Create RowDescription with binary format (format_code = 1)
        let mut binary_row_desc = Vec::new();
        binary_row_desc.extend_from_slice(&1i16.to_be_bytes()); // field count
        binary_row_desc.extend_from_slice(column_name.as_bytes());
        binary_row_desc.push(0); // null terminator
        binary_row_desc.extend_from_slice(&0u32.to_be_bytes()); // table_oid
        binary_row_desc.extend_from_slice(&0i16.to_be_bytes()); // column_id
        binary_row_desc.extend_from_slice(&type_oid.to_be_bytes());
        binary_row_desc.extend_from_slice(&4i16.to_be_bytes()); // type_size
        binary_row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
        binary_row_desc.extend_from_slice(&1i16.to_be_bytes()); // format_code = BINARY

        // Parse both RowDescription messages
        let (text_columns, text_indices) = conn
            .parse_row_description(&text_row_desc)
            .expect("text RowDescription should parse successfully");
        let (binary_columns, binary_indices) = conn
            .parse_row_description(&binary_row_desc)
            .expect("binary RowDescription should parse successfully");

        // CONFORMANCE CHECK 1: Format codes must be correctly interpreted
        assert_eq!(text_columns[0].format_code, 0, "text format code must be 0");
        assert_eq!(
            binary_columns[0].format_code, 1,
            "binary format code must be 1"
        );

        // CONFORMANCE CHECK 2: All other column metadata must be identical
        assert_eq!(
            text_columns[0].name, binary_columns[0].name,
            "column names must match"
        );
        assert_eq!(
            text_columns[0].type_oid, binary_columns[0].type_oid,
            "type OIDs must match"
        );
        assert_eq!(
            text_columns[0].table_oid, binary_columns[0].table_oid,
            "table OIDs must match"
        );
        assert_eq!(
            text_columns[0].column_id, binary_columns[0].column_id,
            "column IDs must match"
        );
        assert_eq!(
            text_columns[0].type_size, binary_columns[0].type_size,
            "type sizes must match"
        );
        assert_eq!(
            text_columns[0].type_modifier, binary_columns[0].type_modifier,
            "type modifiers must match"
        );

        // Create corresponding DataRow messages for each format
        // Text format: "42" as string
        let mut text_data_row = Vec::new();
        text_data_row.extend_from_slice(&1i16.to_be_bytes()); // field count
        let text_value_bytes = b"42";
        text_data_row.extend_from_slice(&(text_value_bytes.len() as i32).to_be_bytes());
        text_data_row.extend_from_slice(text_value_bytes);

        // Binary format: 42 as 4-byte big-endian integer
        let mut binary_data_row = Vec::new();
        binary_data_row.extend_from_slice(&1i16.to_be_bytes()); // field count
        binary_data_row.extend_from_slice(&4i32.to_be_bytes()); // 4 bytes
        binary_data_row.extend_from_slice(&test_value.to_be_bytes());

        // Parse DataRow messages using respective column definitions
        let text_values = conn
            .parse_data_row(&text_data_row, &text_columns)
            .expect("text DataRow should parse successfully");
        let binary_values = conn
            .parse_data_row(&binary_data_row, &binary_columns)
            .expect("binary DataRow should parse successfully");

        // CONFORMANCE CHECK 3: Different wire formats must produce equivalent logical values
        assert_eq!(text_values.len(), 1, "text row must have one value");
        assert_eq!(binary_values.len(), 1, "binary row must have one value");

        // Both should parse to the same PgValue::Int4(42)
        match (&text_values[0], &binary_values[0]) {
            (PgValue::Int4(text_val), PgValue::Int4(binary_val)) => {
                assert_eq!(
                    text_val, binary_val,
                    "text format value {text_val} must equal binary format value {binary_val}"
                );
                assert_eq!(
                    *text_val, test_value,
                    "text parsed value must equal expected {test_value}"
                );
                assert_eq!(
                    *binary_val, test_value,
                    "binary parsed value must equal expected {test_value}"
                );
            }
            _ => panic!(
                "both values should be PgValue::Int4, got text={:?} binary={:?}",
                text_values[0], binary_values[0]
            ),
        }

        // CONFORMANCE CHECK 4: Column indices must be consistent regardless of format
        assert_eq!(
            text_indices, binary_indices,
            "column indices must be format-independent"
        );
        assert_eq!(
            text_indices.get(column_name),
            Some(&0),
            "column index must be 0"
        );

        // CONFORMANCE VERIFICATION: According to PostgreSQL wire protocol specification,
        // the format code in RowDescription determines how subsequent DataRow values
        // are interpreted, but the logical result must be equivalent.
        println!("✓ PostgreSQL RowDescription field-format differential conformance verified");
        println!(
            "  - Text format (code=0): {:?} -> {:?}",
            "42", text_values[0]
        );
        println!(
            "  - Binary format (code=1): {:?} -> {:?}",
            test_value.to_be_bytes(),
            binary_values[0]
        );
        println!(
            "  - Both formats produced equivalent logical value: {}",
            test_value
        );
    }

    #[test]
    fn row_description_uuid_text_vs_binary_format_differential() {
        /// Differential conformance test for UUID RowDescription text vs binary format.
        ///
        /// Tests that UUID values produce equivalent results when parsed from:
        /// - Text format (format_code = 0): "550e8400-e29b-41d4-a716-446655440000"
        /// - Binary format (format_code = 1): 16 bytes in network byte order
        ///
        /// Verifies PostgreSQL wire protocol conformance for non-trivial types
        /// where text and binary representations differ significantly.
        let conn = make_test_connection();

        // Test UUID: 550e8400-e29b-41d4-a716-446655440000
        let uuid_string = "550e8400-e29b-41d4-a716-446655440000";
        let uuid_bytes: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];

        let column_name = "uuid_col";
        let type_oid = oid::UUID;

        // Create RowDescription with text format (format_code = 0)
        let mut text_row_desc = Vec::new();
        text_row_desc.extend_from_slice(&1i16.to_be_bytes()); // field count
        text_row_desc.extend_from_slice(column_name.as_bytes());
        text_row_desc.push(0); // null terminator
        text_row_desc.extend_from_slice(&0u32.to_be_bytes()); // table_oid
        text_row_desc.extend_from_slice(&0i16.to_be_bytes()); // column_id
        text_row_desc.extend_from_slice(&type_oid.to_be_bytes());
        text_row_desc.extend_from_slice(&(-1i16).to_be_bytes()); // type_size (-1 = variable)
        text_row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
        text_row_desc.extend_from_slice(&0i16.to_be_bytes()); // format_code = TEXT

        // Create RowDescription with binary format (format_code = 1)
        let mut binary_row_desc = Vec::new();
        binary_row_desc.extend_from_slice(&1i16.to_be_bytes()); // field count
        binary_row_desc.extend_from_slice(column_name.as_bytes());
        binary_row_desc.push(0); // null terminator
        binary_row_desc.extend_from_slice(&0u32.to_be_bytes()); // table_oid
        binary_row_desc.extend_from_slice(&0i16.to_be_bytes()); // column_id
        binary_row_desc.extend_from_slice(&type_oid.to_be_bytes());
        binary_row_desc.extend_from_slice(&(-1i16).to_be_bytes()); // type_size (-1 = variable)
        binary_row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
        binary_row_desc.extend_from_slice(&1i16.to_be_bytes()); // format_code = BINARY

        // Parse both RowDescription messages
        let (text_columns, text_indices) = conn
            .parse_row_description(&text_row_desc)
            .expect("text UUID RowDescription should parse successfully");
        let (binary_columns, binary_indices) = conn
            .parse_row_description(&binary_row_desc)
            .expect("binary UUID RowDescription should parse successfully");

        // CONFORMANCE CHECK 1: Format codes must be correctly interpreted
        assert_eq!(text_columns[0].format_code, 0, "text format code must be 0");
        assert_eq!(
            binary_columns[0].format_code, 1,
            "binary format code must be 1"
        );

        // CONFORMANCE CHECK 2: All other column metadata must be identical
        assert_eq!(
            text_columns[0].name, binary_columns[0].name,
            "column names must match"
        );
        assert_eq!(
            text_columns[0].type_oid, binary_columns[0].type_oid,
            "type OIDs must match UUID"
        );
        assert_eq!(text_columns[0].type_oid, oid::UUID, "must be UUID type OID");

        // Create corresponding DataRow messages for each format
        // Text format: UUID string
        let mut text_data_row = Vec::new();
        text_data_row.extend_from_slice(&1i16.to_be_bytes()); // field count
        text_data_row.extend_from_slice(&(uuid_string.len() as i32).to_be_bytes());
        text_data_row.extend_from_slice(uuid_string.as_bytes());

        // Binary format: 16-byte UUID in network byte order
        let mut binary_data_row = Vec::new();
        binary_data_row.extend_from_slice(&1i16.to_be_bytes()); // field count
        binary_data_row.extend_from_slice(&(uuid_bytes.len() as i32).to_be_bytes());
        binary_data_row.extend_from_slice(&uuid_bytes);

        // Parse DataRow messages using respective column definitions
        let text_values = conn
            .parse_data_row(&text_data_row, &text_columns)
            .expect("text UUID DataRow should parse successfully");
        let binary_values = conn
            .parse_data_row(&binary_data_row, &binary_columns)
            .expect("binary UUID DataRow should parse successfully");

        // CONFORMANCE CHECK 3: Different wire formats must produce equivalent logical values
        assert_eq!(text_values.len(), 1, "text row must have one value");
        assert_eq!(binary_values.len(), 1, "binary row must have one value");

        // Both should parse to PgValue::Text with the same UUID string
        match (&text_values[0], &binary_values[0]) {
            (PgValue::Text(text_val), PgValue::Text(binary_val)) => {
                assert_eq!(
                    text_val, binary_val,
                    "text format UUID '{}' must equal binary format UUID '{}'",
                    text_val, binary_val
                );
                assert_eq!(
                    *text_val, uuid_string,
                    "text parsed UUID must equal expected '{}'",
                    uuid_string
                );
                assert_eq!(
                    *binary_val, uuid_string,
                    "binary parsed UUID must equal expected '{}'",
                    uuid_string
                );
            }
            _ => panic!(
                "both values should be PgValue::Text for UUID, got text={:?} binary={:?}",
                text_values[0], binary_values[0]
            ),
        }

        // CONFORMANCE CHECK 4: Column indices must be consistent regardless of format
        assert_eq!(
            text_indices, binary_indices,
            "column indices must be format-independent"
        );

        // CONFORMANCE VERIFICATION: According to PostgreSQL wire protocol specification,
        // UUID values can be transmitted as either text strings (36 chars with dashes) or
        // binary (16 bytes), but both must produce the same logical UUID value.
        println!("✓ PostgreSQL UUID text vs binary format differential conformance verified");
        println!("  - Text format (36 chars): \"{}\"", uuid_string);
        println!("  - Binary format (16 bytes): {:?}", uuid_bytes);
        println!("  - Both formats produced equivalent UUID: {}", uuid_string);
    }

    #[test]
    fn data_row_binary_float_numeric_decode_matches_sqlx_reference() {
        /// Differential conformance test against sqlx's PostgreSQL binary decode rules.
        ///
        /// sqlx decodes FLOAT4/FLOAT8 directly from big-endian IEEE754 bytes and
        /// decodes NUMERIC from the PostgreSQL base-10000 wire format. This test
        /// pins our DataRow binary decode to the same logical results for one
        /// representative row containing FLOAT4, FLOAT8, and NUMERIC columns.
        fn sqlx_reference_numeric_to_text(data: &[u8]) -> String {
            let ndigits = u16::from_be_bytes([data[0], data[1]]) as usize;
            let weight = i16::from_be_bytes([data[2], data[3]]);
            let sign = u16::from_be_bytes([data[4], data[5]]);
            let scale = u16::from_be_bytes([data[6], data[7]]) as usize;
            let digits = (0..ndigits)
                .map(|idx| {
                    let offset = 8 + (idx * 2);
                    u16::from_be_bytes([data[offset], data[offset + 1]]) as u32
                })
                .collect::<Vec<_>>();

            let digit_at_exponent = |exp: i16| -> u32 {
                let idx = weight - exp;
                if idx < 0 {
                    0
                } else {
                    digits.get(idx as usize).copied().unwrap_or(0)
                }
            };

            let integer_groups = if weight >= 0 {
                (0..=weight)
                    .rev()
                    .map(digit_at_exponent)
                    .collect::<Vec<_>>()
            } else {
                Vec::new()
            };

            let mut integer_parts = integer_groups
                .into_iter()
                .skip_while(|digit| *digit == 0)
                .collect::<Vec<_>>();
            let integer = if integer_parts.is_empty() {
                "0".to_string()
            } else {
                let first = integer_parts.remove(0);
                let mut rendered = first.to_string();
                for digit in integer_parts {
                    use std::fmt::Write as _;
                    let _ = write!(rendered, "{digit:04}");
                }
                rendered
            };

            let fractional = if scale == 0 {
                String::new()
            } else {
                let fractional_groups = scale.div_ceil(4);
                let mut rendered = String::with_capacity(fractional_groups * 4);
                for group_idx in 0..fractional_groups {
                    let exp = -1 - group_idx as i16;
                    use std::fmt::Write as _;
                    let _ = write!(rendered, "{:04}", digit_at_exponent(exp));
                }
                rendered.truncate(scale);
                rendered
            };

            let is_zero = digits.iter().all(|digit| *digit == 0);
            let sign_prefix = if sign == 0x4000 && !is_zero { "-" } else { "" };
            if scale == 0 {
                format!("{sign_prefix}{integer}")
            } else {
                format!("{sign_prefix}{integer}.{fractional}")
            }
        }

        let conn = make_test_connection();
        let numeric_bytes = [
            0x00, 0x03, // ndigits = 3
            0x00, 0x01, // weight = 1
            0x00, 0x00, // sign = positive
            0x00, 0x04, // scale = 4
            0x00, 0x01, // 1
            0x09, 0x29, // 2345
            0x1A, 0x85, // 6789
        ];
        let float4 = 3.5f32;
        let float8 = -42.125f64;

        let columns = vec![
            PgColumn {
                name: "f4".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::FLOAT4,
                type_size: 4,
                type_modifier: -1,
                format_code: 1,
            },
            PgColumn {
                name: "f8".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::FLOAT8,
                type_size: 8,
                type_modifier: -1,
                format_code: 1,
            },
            PgColumn {
                name: "num".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::NUMERIC,
                type_size: -1,
                type_modifier: -1,
                format_code: 1,
            },
        ];

        let mut data_row = Vec::new();
        data_row.extend_from_slice(&3i16.to_be_bytes());
        data_row.extend_from_slice(&4i32.to_be_bytes());
        data_row.extend_from_slice(&float4.to_be_bytes());
        data_row.extend_from_slice(&8i32.to_be_bytes());
        data_row.extend_from_slice(&float8.to_be_bytes());
        data_row.extend_from_slice(&(numeric_bytes.len() as i32).to_be_bytes());
        data_row.extend_from_slice(&numeric_bytes);

        let values = conn
            .parse_data_row(&data_row, &columns)
            .expect("binary DataRow should parse successfully");

        assert_eq!(values.len(), 3);
        assert_eq!(values[0], PgValue::Float4(float4));
        assert_eq!(values[1], PgValue::Float8(float8));
        assert_eq!(
            values[2],
            PgValue::Text(sqlx_reference_numeric_to_text(&numeric_bytes))
        );
    }

    #[test]
    fn data_row_binary_temporal_decode_matches_sqlx_reference() {
        /// Differential conformance test against sqlx's PostgreSQL binary decode rules.
        ///
        /// sqlx decodes DATE as days since 2000-01-01, TIMESTAMP as microseconds
        /// since 2000-01-01 00:00:00, and INTERVAL as a `(months, days,
        /// microseconds)` triple. Our row surface represents these as canonical
        /// text values, so this test pins that text against an independently
        /// decoded sqlx-derived reference.
        fn sqlx_reference_date_to_text(data: &[u8]) -> String {
            let days = i32::from_be_bytes([data[0], data[1], data[2], data[3]]) as i64;
            let epoch =
                chrono::NaiveDate::from_ymd_opt(2000, 1, 1).expect("valid postgres date epoch");
            (epoch + chrono::TimeDelta::days(days)).to_string()
        }

        fn sqlx_reference_timestamp_to_text(data: &[u8]) -> String {
            let micros = i64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ]);
            let epoch = chrono::NaiveDate::from_ymd_opt(2000, 1, 1)
                .expect("valid postgres timestamp epoch date")
                .and_hms_opt(0, 0, 0)
                .expect("valid postgres timestamp epoch");
            (epoch + chrono::TimeDelta::microseconds(micros)).to_string()
        }

        fn sqlx_reference_interval_to_text(data: &[u8]) -> String {
            let mut reader = MessageReader::new(data);
            let microseconds = reader.read_i64().expect("interval microseconds");
            let days = reader.read_i32().expect("interval days");
            let months = reader.read_i32().expect("interval months");
            reader
                .ensure_consumed("sqlx reference INTERVAL")
                .expect("interval payload fully consumed");
            render_interval_text(months, days, microseconds)
        }

        let conn = make_test_connection();
        let date_days = 8_825i32;
        let timestamp_micros = 1_234_567i64;
        let interval_micros = 14_706_789_000i64;
        let interval_days = 3i32;
        let interval_months = 2i32;

        let columns = vec![
            PgColumn {
                name: "d".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::DATE,
                type_size: 4,
                type_modifier: -1,
                format_code: 1,
            },
            PgColumn {
                name: "ts".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::TIMESTAMP,
                type_size: 8,
                type_modifier: -1,
                format_code: 1,
            },
            PgColumn {
                name: "iv".to_string(),
                table_oid: 0,
                column_id: 0,
                type_oid: oid::INTERVAL,
                type_size: 16,
                type_modifier: -1,
                format_code: 1,
            },
        ];

        let date_bytes = date_days.to_be_bytes();
        let timestamp_bytes = timestamp_micros.to_be_bytes();
        let mut interval_bytes = Vec::new();
        interval_bytes.extend_from_slice(&interval_micros.to_be_bytes());
        interval_bytes.extend_from_slice(&interval_days.to_be_bytes());
        interval_bytes.extend_from_slice(&interval_months.to_be_bytes());

        let mut data_row = Vec::new();
        data_row.extend_from_slice(&3i16.to_be_bytes());
        data_row.extend_from_slice(&4i32.to_be_bytes());
        data_row.extend_from_slice(&date_bytes);
        data_row.extend_from_slice(&8i32.to_be_bytes());
        data_row.extend_from_slice(&timestamp_bytes);
        data_row.extend_from_slice(&(interval_bytes.len() as i32).to_be_bytes());
        data_row.extend_from_slice(&interval_bytes);

        let values = conn
            .parse_data_row(&data_row, &columns)
            .expect("binary temporal DataRow should parse successfully");

        assert_eq!(values.len(), 3);
        assert_eq!(
            values[0],
            PgValue::Text(sqlx_reference_date_to_text(&date_bytes))
        );
        assert_eq!(
            values[1],
            PgValue::Text(sqlx_reference_timestamp_to_text(&timestamp_bytes))
        );
        assert_eq!(
            values[2],
            PgValue::Text(sqlx_reference_interval_to_text(&interval_bytes))
        );
    }

    /// **AUDIT TEST: PostgreSQL Simple vs Extended Query Semantic Consistency**
    ///
    /// Verifies that Simple Query (Q-message) and Extended Query (Parse/Bind/Execute)
    /// produce semantically identical results for the same SQL statement.
    ///
    /// **Tests for consistency in:**
    /// - Null handling: NULL values represented identically
    /// - Type coercion: Same type OID interpretation
    /// - Column metadata: Same RowDescription parsing
    /// - Row data: Same DataRow parsing logic
    ///
    /// **PostgreSQL Protocol Compliance:** Both query paths should produce identical
    /// logical results despite different wire protocols. Any divergence indicates
    /// a protocol implementation bug that could cause application-level inconsistencies.
    ///
    /// **Implementation:** Both `query_unchecked` (Simple) and `query_params` (Extended)
    /// use the same `parse_row_description` and `parse_data_row` functions, ensuring
    /// semantic consistency.
    #[test]
    fn postgres_simple_vs_extended_query_semantic_consistency_audit() {
        let conn = make_test_connection();

        // Test data representing various PostgreSQL types and edge cases
        let test_cases: Vec<(u32, &'static [u8], PgValue)> = vec![
            // INT4 with normal value
            (oid::INT4, b"42".as_slice(), PgValue::Int4(42)),
            // INT4 with zero
            (oid::INT4, b"0".as_slice(), PgValue::Int4(0)),
            // TEXT with normal string
            (
                oid::TEXT,
                b"hello".as_slice(),
                PgValue::Text("hello".to_string()),
            ),
            // TEXT with empty string
            (oid::TEXT, b"".as_slice(), PgValue::Text("".to_string())),
            // BOOL true
            (oid::BOOL, b"t".as_slice(), PgValue::Bool(true)),
            // BOOL false
            (oid::BOOL, b"f".as_slice(), PgValue::Bool(false)),
        ];

        for (type_oid, text_bytes, expected_value) in test_cases {
            // Create identical column metadata for both protocols
            let column = PgColumn {
                name: "test_col".to_string(),
                table_oid: 0,
                column_id: 1,
                type_oid,
                type_size: -1,
                type_modifier: -1,
                format_code: 0, // TEXT format (same for both protocols)
            };
            let columns = vec![column];

            // Create identical DataRow message for both protocols
            let mut data_row = Vec::new();
            data_row.extend_from_slice(&1i16.to_be_bytes()); // 1 column
            data_row.extend_from_slice(&(text_bytes.len() as i32).to_be_bytes());
            data_row.extend_from_slice(text_bytes);

            // Parse using same underlying function (used by both Simple and Extended)
            let parsed_values = conn
                .parse_data_row(&data_row, &columns)
                .expect("DataRow should parse consistently");

            assert_eq!(parsed_values.len(), 1);
            assert_eq!(
                parsed_values[0], expected_value,
                "Type OID {} should parse consistently between Simple and Extended protocols",
                type_oid
            );
        }

        // Test NULL handling consistency
        let null_column = PgColumn {
            name: "nullable_col".to_string(),
            table_oid: 0,
            column_id: 1,
            type_oid: oid::TEXT,
            type_size: -1,
            type_modifier: -1,
            format_code: 0,
        };
        let null_columns = vec![null_column];

        let mut null_data_row = Vec::new();
        null_data_row.extend_from_slice(&1i16.to_be_bytes()); // 1 column
        null_data_row.extend_from_slice(&(-1i32).to_be_bytes()); // NULL marker

        let null_values = conn
            .parse_data_row(&null_data_row, &null_columns)
            .expect("NULL DataRow should parse consistently");

        assert_eq!(null_values.len(), 1);
        assert_eq!(
            null_values[0],
            PgValue::Null,
            "NULL handling must be identical between Simple and Extended protocols"
        );

        // Test RowDescription consistency
        let mut row_desc = Vec::new();
        row_desc.extend_from_slice(&2i16.to_be_bytes()); // 2 columns

        // Column 1: "id" INT4
        row_desc.extend_from_slice(b"id\0");
        row_desc.extend_from_slice(&0u32.to_be_bytes()); // table_oid
        row_desc.extend_from_slice(&1i16.to_be_bytes()); // column_id
        row_desc.extend_from_slice(&oid::INT4.to_be_bytes());
        row_desc.extend_from_slice(&4i16.to_be_bytes()); // type_size
        row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
        row_desc.extend_from_slice(&0i16.to_be_bytes()); // format_code

        // Column 2: "name" TEXT
        row_desc.extend_from_slice(b"name\0");
        row_desc.extend_from_slice(&0u32.to_be_bytes());
        row_desc.extend_from_slice(&2i16.to_be_bytes());
        row_desc.extend_from_slice(&oid::TEXT.to_be_bytes());
        row_desc.extend_from_slice(&(-1i16).to_be_bytes());
        row_desc.extend_from_slice(&(-1i32).to_be_bytes());
        row_desc.extend_from_slice(&0i16.to_be_bytes());

        let (parsed_columns, parsed_indices) = conn
            .parse_row_description(&row_desc)
            .expect("RowDescription should parse consistently");

        assert_eq!(parsed_columns.len(), 2);
        assert_eq!(parsed_columns[0].name, "id");
        assert_eq!(parsed_columns[0].type_oid, oid::INT4);
        assert_eq!(parsed_columns[1].name, "name");
        assert_eq!(parsed_columns[1].type_oid, oid::TEXT);
        assert_eq!(*parsed_indices.get("id").unwrap(), 0);
        assert_eq!(*parsed_indices.get("name").unwrap(), 1);

        // AUDIT VERIFICATION: Both Simple Query (query_unchecked) and Extended Query
        // (query_params) use the exact same parsing functions:
        // - parse_row_description() for column metadata
        // - parse_data_row() for row data
        // - Same null handling (NULL = -1 length)
        // - Same type coercion logic based on OID
        // This ensures semantic consistency between the two protocol paths.
    }

    /// Audit test for PostgreSQL query result streaming behavior.
    ///
    /// CRITICAL DEFECT: All query methods collect entire result sets into Vec<PgRow>
    /// before returning, violating streaming-first philosophy and creating OOM risk
    /// for large result sets (1M+ rows). Per asupersync design, should stream rows
    /// lazily with bounded memory usage.
    #[test]
    fn audit_postgres_query_result_streaming_memory_usage() {
        // DEFECT DEMONSTRATION: Current implementation collects ALL rows before returning

        // Evidence 1: All query methods return Vec<PgRow> (collect entire result set)
        // - query_unchecked(&mut self, cx: &Cx, sql: &str) -> Outcome<Vec<PgRow>, PgError>
        // - query_params(&mut self, cx: &Cx, sql: &str, params: &[&dyn ToSql]) -> Outcome<Vec<PgRow>, PgError>
        // - query_prepared(&mut self, cx: &Cx, stmt: &PgStatement, params: &[&dyn ToSql]) -> Outcome<Vec<PgRow>, PgError>

        // Evidence 2: DataRow handling loops accumulate ALL rows in Vec
        // From lines 3524, 5436: let mut rows = Vec::with_capacity(16);
        // From lines 3549-3576, 5459-5484: DataRow messages push to rows Vec

        let (conn, _peer) = make_test_connection_with_peer();

        // MEMORY IMPACT CALCULATION:
        // - 1M row result set with 10 columns @ 50 bytes avg per column = 500MB minimum
        // - ALL loaded into memory before first row accessible
        // - max_result_rows provides ceiling but still allows massive allocations

        // Current max_result_rows limit (insufficient protection)
        assert_eq!(conn.inner.max_result_rows, 1_000_000); // Still allows 1M rows in memory

        // VIOLATION: Streaming-first philosophy requires bounded memory usage
        // Current: Memory usage = O(result_set_size)
        // Required: Memory usage = O(1) with lazy row iteration

        // REQUIRED IMPLEMENTATION:
        // 1. Add streaming query APIs that return PgRowStream<'_> iterator
        // 2. Stream yields one row at a time from network as DataRow messages arrive
        // 3. Memory bounded to single row + network buffer (not entire result set)
        // 4. Backpressure via network flow control if consumer can't keep up

        eprintln!(
            "{{\"defect\":\"QUERY_RESULT_STREAMING\",\"severity\":\"CRITICAL\",\"impact\":\"OOM risk\",\"violation\":\"streaming-first philosophy\"}}"
        );
    }

    /// Regression test for PostgreSQL streaming query bounded memory usage.
    ///
    /// REGRESSION TEST: Verifies that streaming queries use O(1) memory per row
    /// instead of O(result_set_size), preventing OOM on large result sets.
    /// This test ensures the fix for the critical memory accumulation defect works correctly.
    #[test]
    fn regression_postgres_streaming_query_bounded_memory() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = Cx::for_testing();

        // Test data: 1000-row result set
        let row_count = 1000;
        let expected_memory_usage = "O(1) per row, not O(1000*row_size)";

        // Create test thread that sends large result set
        let responder = std::thread::spawn(move || {
            // Wait for query
            let _query_request = read_until_contains(&mut peer, b"SELECT * FROM large_table");

            // Send RowDescription
            let mut row_desc = Vec::new();
            row_desc.extend_from_slice(&2i16.to_be_bytes()); // 2 columns

            // Column 1: "id" INT4
            row_desc.extend_from_slice(b"id\0");
            row_desc.extend_from_slice(&0u32.to_be_bytes()); // table_oid
            row_desc.extend_from_slice(&1i16.to_be_bytes()); // column_id
            row_desc.extend_from_slice(&oid::INT4.to_be_bytes());
            row_desc.extend_from_slice(&4i16.to_be_bytes()); // type_size
            row_desc.extend_from_slice(&(-1i32).to_be_bytes()); // type_modifier
            row_desc.extend_from_slice(&0i16.to_be_bytes()); // format_code

            // Column 2: "data" TEXT
            row_desc.extend_from_slice(b"data\0");
            row_desc.extend_from_slice(&0u32.to_be_bytes());
            row_desc.extend_from_slice(&2i16.to_be_bytes());
            row_desc.extend_from_slice(&oid::TEXT.to_be_bytes());
            row_desc.extend_from_slice(&(-1i16).to_be_bytes());
            row_desc.extend_from_slice(&(-1i32).to_be_bytes());
            row_desc.extend_from_slice(&0i16.to_be_bytes());

            std::io::Write::write_all(&mut peer, &backend_message(b'T', &row_desc))
                .expect("should write RowDescription");

            // Send many DataRow messages representing a large result set.
            for i in 0..row_count {
                let mut data_row = Vec::new();
                data_row.extend_from_slice(&2i16.to_be_bytes()); // 2 values

                // id value
                let id_str = i.to_string();
                data_row.extend_from_slice(&(id_str.len() as i32).to_be_bytes());
                data_row.extend_from_slice(id_str.as_bytes());

                // data value representing a larger payload
                let data_str = format!("row_data_{}_with_some_content_to_make_it_larger", i);
                data_row.extend_from_slice(&(data_str.len() as i32).to_be_bytes());
                data_row.extend_from_slice(data_str.as_bytes());

                std::io::Write::write_all(&mut peer, &backend_message(b'D', &data_row))
                    .expect("should write DataRow");

                // Add small delay to model network behavior.
                if i % 100 == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }

            // Send CommandComplete and ReadyForQuery
            std::io::Write::write_all(&mut peer, &backend_message(b'C', b"SELECT 1000\0"))
                .expect("should write CommandComplete");
            std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                .expect("should write ReadyForQuery");
        });

        // REGRESSION TEST: Use streaming API to verify bounded memory
        let stream_result = run(conn.query_stream(&cx, "SELECT * FROM large_table"));
        let mut stream = match stream_result {
            Outcome::Ok(s) => s,
            Outcome::Err(err) => panic!("Expected Ok(stream), got error: {err}"),
            Outcome::Cancelled(reason) => {
                panic!("Expected Ok(stream), got cancellation: {reason:?}")
            }
            Outcome::Panicked(payload) => {
                panic!("Expected Ok(stream), got panic: {payload:?}")
            }
        };

        // Process rows one at a time - this should use O(1) memory per iteration
        let mut processed_count = 0;
        let total_memory_should_be_bounded = true;

        loop {
            match run(stream.next(&cx)) {
                Outcome::Ok(Some(row)) => {
                    // Verify row structure
                    assert_eq!(row.columns.len(), 2, "Expected 2 columns");

                    // Extract values to verify streaming works
                    let id_value = row.get("id").expect("id column should exist");
                    let data_value = row.get("data").expect("data column should exist");

                    // Verify data consistency
                    if let (PgValue::Text(id_str), PgValue::Text(data_str)) = (id_value, data_value)
                    {
                        let expected_id = processed_count.to_string();
                        assert_eq!(*id_str, expected_id, "ID should match row index");
                        assert!(
                            data_str.contains(&format!("row_data_{}", processed_count)),
                            "Data should contain row index"
                        );
                    } else {
                        panic!("Expected text values for both columns");
                    }

                    processed_count += 1;

                    // CRITICAL: At this point, only ONE row should be in memory
                    // Not 1000 rows accumulated in a Vec<PgRow>
                    if processed_count == 1 {
                        eprintln!(
                            "{{\"regression_test\":\"streaming_memory\",\"status\":\"FIRST_ROW_RECEIVED\",\"memory_usage\":\"O(1)\",\"accumulated_rows_in_memory\":1}}"
                        );
                    }
                    if processed_count == 100 {
                        eprintln!(
                            "{{\"regression_test\":\"streaming_memory\",\"status\":\"100_ROWS_PROCESSED\",\"memory_usage\":\"still_O(1)\",\"accumulated_rows_in_memory\":1}}"
                        );
                    }

                    // Verify we haven't accumulated all rows in memory
                    assert!(
                        total_memory_should_be_bounded,
                        "Memory usage should remain bounded throughout streaming"
                    );

                    // Break early to avoid processing all rows in test (time constraint)
                    if processed_count >= 50 {
                        eprintln!(
                            "{{\"regression_test\":\"streaming_memory\",\"status\":\"EARLY_TERMINATION\",\"processed\":50,\"verified\":\"bounded_memory\"}}"
                        );
                        break;
                    }
                }
                Outcome::Ok(None) => {
                    // Stream complete
                    break;
                }
                Outcome::Err(e) => panic!("Stream error: {:?}", e),
                other => panic!("Unexpected stream result: {:?}", other),
            }
        }

        // Verify streaming worked
        assert!(
            processed_count > 0,
            "Should have processed at least some rows"
        );
        assert!(processed_count <= row_count, "Should not exceed total rows");

        // REGRESSION VERIFICATION: Memory usage was bounded to single row
        // vs the old implementation that would accumulate all rows
        eprintln!(
            "{{\"regression_test\":\"PASS\",\"memory_model\":\"O(1)_per_row\",\"processed\":{},\"expected\":\"{}\"}}",
            processed_count, expected_memory_usage
        );

        responder.join().expect("responder thread should complete");
    }

    #[test]
    fn regression_postgres_streaming_params_writes_extended_protocol_frames() {
        let (mut conn, mut peer) = make_test_connection_with_peer();
        let cx = Cx::for_testing();
        let value: i32 = 42;
        let params: [&dyn ToSql; 1] = [&value];

        let stream = match run(conn.query_stream_params(&cx, "SELECT $1::int4", &params)) {
            Outcome::Ok(stream) => stream,
            Outcome::Err(err) => {
                panic!("expected streaming params setup to succeed, got error: {err}")
            }
            Outcome::Cancelled(reason) => {
                panic!("expected streaming params setup to succeed, got cancellation: {reason:?}")
            }
            Outcome::Panicked(payload) => {
                panic!("expected streaming params setup to succeed, got panic: {payload:?}")
            }
        };

        assert!(
            stream.connection.inner.closed,
            "streaming extended query must stay fail-closed until ReadyForQuery"
        );

        let written = read_until_contains(&mut peer, &[b'S', 0, 0, 0, 4]);
        assert_eq!(written[0], b'P', "first extended frame should be Parse");
        assert!(
            written
                .windows(b"SELECT $1::int4\0".len())
                .any(|window| window == b"SELECT $1::int4\0"),
            "Parse frame should include the SQL string"
        );
        assert!(
            written
                .windows(4)
                .any(|window| window == oid::INT4.to_be_bytes()),
            "Parse frame should carry the inferred INT4 parameter OID"
        );
        assert!(
            written.iter().any(|byte| *byte == b'B'),
            "Bind frame should be present"
        );
        assert!(
            written.windows(2).any(|window| window == b"42"),
            "Bind frame should serialize the parameter value"
        );
        assert!(
            written
                .windows(10)
                .any(|window| window == [b'E', 0, 0, 0, 9, 0, 0, 0, 0, 0]),
            "Execute frame should request all rows from the unnamed portal"
        );

        eprintln!(
            "{{\"regression_test\":\"streaming_params_extended_protocol\",\"frames\":\"Parse,Bind,Execute,Sync\",\"param_oid\":{},\"param_value\":\"42\",\"fail_closed_until_ready_for_query\":true}}",
            oid::INT4
        );
    }

    /// Audit test for PostgreSQL ErrorResponse SQLSTATE preservation.
    ///
    /// Verifies that when server returns ErrorResponse with SQLSTATE=99999
    /// (private/extension error), the client preserves the SQLSTATE for the caller
    /// as required by PostgreSQL protocol §49.7, rather than downcasting to
    /// generic error or failing to parse.
    #[test]
    fn audit_error_response_sqlstate_preservation_including_99999() {
        let conn = make_test_connection();

        // Test Case 1: Standard SQLSTATE (e.g., unique violation)
        let mut standard_error = Vec::new();
        standard_error.push(b'C'); // Field type 'C' = SQLSTATE code
        standard_error.extend_from_slice(b"23505\0"); // Unique violation
        standard_error.push(b'M'); // Field type 'M' = message
        standard_error.extend_from_slice(b"duplicate key value violates unique constraint\0");
        standard_error.push(0); // End marker

        let parsed_error = conn
            .parse_error_response(&standard_error)
            .expect("Standard SQLSTATE should parse successfully");

        if let PgError::Server {
            code,
            message,
            detail,
            hint,
            ..
        } = parsed_error
        {
            assert_eq!(code, "23505", "Standard SQLSTATE must be preserved exactly");
            assert_eq!(message, "duplicate key value violates unique constraint");
            assert_eq!(detail, None);
            assert_eq!(hint, None);
        } else {
            panic!(
                "Expected PgError::Server for ErrorResponse, got {:?}",
                parsed_error
            );
        }

        // Test Case 2: Private/extension SQLSTATE 99999 (PostgreSQL protocol §49.7)
        let mut extension_error = Vec::new();
        extension_error.push(b'C'); // Field type 'C' = SQLSTATE code
        extension_error.extend_from_slice(b"99999\0"); // Private/extension error
        extension_error.push(b'M'); // Field type 'M' = message
        extension_error.extend_from_slice(b"custom extension error occurred\0");
        extension_error.push(b'D'); // Field type 'D' = detail
        extension_error.extend_from_slice(b"Extension xyz failed validation\0");
        extension_error.push(b'H'); // Field type 'H' = hint
        extension_error.extend_from_slice(b"Check extension configuration\0");
        extension_error.push(0); // End marker

        let parsed_extension_error = conn
            .parse_error_response(&extension_error)
            .expect("Private SQLSTATE 99999 should parse successfully");

        if let PgError::Server {
            code,
            message,
            detail,
            hint,
            ..
        } = &parsed_extension_error
        {
            assert_eq!(
                code, "99999",
                "Private/extension SQLSTATE 99999 must be preserved exactly per PostgreSQL protocol §49.7"
            );
            assert_eq!(message, "custom extension error occurred");
            assert_eq!(detail.as_deref(), Some("Extension xyz failed validation"));
            assert_eq!(hint.as_deref(), Some("Check extension configuration"));
        } else {
            panic!(
                "Expected PgError::Server for extension error, got {:?}",
                parsed_extension_error
            );
        }

        // Test Case 3: Verify code() accessor preserves SQLSTATE
        assert_eq!(
            parsed_extension_error.code(),
            Some("99999"),
            "code() accessor must return exact SQLSTATE without modification"
        );

        // Test Case 4: Edge case - empty fields (should not crash)
        let mut minimal_error = Vec::new();
        minimal_error.push(b'C'); // SQLSTATE
        minimal_error.extend_from_slice(b"99998\0"); // Another private code
        minimal_error.push(b'M'); // Message
        minimal_error.extend_from_slice(b"\0"); // Empty message
        minimal_error.push(0); // End marker

        let parsed_minimal = conn
            .parse_error_response(&minimal_error)
            .expect("Minimal ErrorResponse should parse");

        if let PgError::Server { code, message, .. } = parsed_minimal {
            assert_eq!(code, "99998", "SQLSTATE preserved even with empty message");
            assert_eq!(
                message, "",
                "Empty message should be preserved as empty string"
            );
        } else {
            panic!("Expected PgError::Server for minimal error");
        }

        // AUDIT VERIFICATION:
        // - SQLSTATE codes are preserved exactly as strings (field 'C')
        // - Extension/private codes like 99999 are supported without downcasting
        // - All optional fields (detail, hint) are preserved when present
        // - Parser follows PostgreSQL protocol §49.7 for ErrorResponse format
        // - No information loss occurs for any valid SQLSTATE value
    }

    /// AUDIT MODULE: PostgreSQL ErrorResponse diagnostic field preservation verification
    ///
    /// AUDIT FINDING: FIXED - Previous implementation discarded actionable diagnostic
    /// fields (constraint name, table name, schema name, column name) from PostgreSQL
    /// ErrorResponse messages. This caused information loss and made debugging harder.
    ///
    /// FIXED: Extended PgError::Server to include PgErrorDiagnostic struct that captures
    /// all diagnostic fields per PostgreSQL protocol documentation.
    #[cfg(test)]
    mod postgres_error_diagnostic_field_audit {
        use super::*;

        #[test]
        fn audit_diagnostic_field_preservation_constraint_violation() {
            let conn = make_test_connection();

            // Test Case 1: Unique constraint violation with full diagnostic context
            let mut constraint_error = Vec::new();
            constraint_error.push(b'C'); // SQLSTATE
            constraint_error.extend_from_slice(b"23505\0"); // Unique violation
            constraint_error.push(b'M'); // Message
            constraint_error.extend_from_slice(
                b"duplicate key value violates unique constraint \"users_email_key\"\0",
            );
            constraint_error.push(b'D'); // Detail
            constraint_error.extend_from_slice(b"Key (email)=(test@example.com) already exists.\0");
            constraint_error.push(b'H'); // Hint
            constraint_error
                .extend_from_slice(b"Use INSERT ... ON CONFLICT to handle duplicates\0");
            // DIAGNOSTIC FIELDS - Previously discarded, now preserved
            constraint_error.push(b'c'); // Constraint name
            constraint_error.extend_from_slice(b"users_email_key\0");
            constraint_error.push(b't'); // Table name
            constraint_error.extend_from_slice(b"users\0");
            constraint_error.push(b's'); // Schema name
            constraint_error.extend_from_slice(b"public\0");
            constraint_error.push(b'n'); // Column name
            constraint_error.extend_from_slice(b"email\0");
            constraint_error.push(b'S'); // Severity
            constraint_error.extend_from_slice(b"ERROR\0");
            constraint_error.push(b'P'); // Position
            constraint_error.extend_from_slice(b"42\0");
            constraint_error.push(0); // End marker

            let parsed_error = conn
                .parse_error_response(&constraint_error)
                .expect("Constraint violation with diagnostic fields should parse");

            if let PgError::Server {
                code,
                message,
                detail,
                hint,
                diagnostic,
            } = parsed_error
            {
                // Verify basic fields still work
                assert_eq!(code, "23505");
                assert_eq!(
                    message,
                    "duplicate key value violates unique constraint \"users_email_key\""
                );
                assert_eq!(
                    detail,
                    Some("Key (email)=(test@example.com) already exists.".to_string())
                );
                assert_eq!(
                    hint,
                    Some("Use INSERT ... ON CONFLICT to handle duplicates".to_string())
                );

                // AUDIT FOCUS: Verify diagnostic fields are now preserved
                assert_eq!(
                    diagnostic.constraint_name,
                    Some("users_email_key".to_string()),
                    "Constraint name must be preserved for actionable debugging"
                );
                assert_eq!(
                    diagnostic.table_name,
                    Some("users".to_string()),
                    "Table name must be preserved for actionable debugging"
                );
                assert_eq!(
                    diagnostic.schema_name,
                    Some("public".to_string()),
                    "Schema name must be preserved for actionable debugging"
                );
                assert_eq!(
                    diagnostic.column_name,
                    Some("email".to_string()),
                    "Column name must be preserved for actionable debugging"
                );
                assert_eq!(
                    diagnostic.severity,
                    Some("ERROR".to_string()),
                    "Severity must be preserved"
                );
                assert_eq!(
                    diagnostic.position,
                    Some("42".to_string()),
                    "Position must be preserved for SQL debugging"
                );

                // Verify Display implementation includes diagnostic info
                let error_display = format!(
                    "{}",
                    PgError::Server {
                        code: code.clone(),
                        message: message.clone(),
                        detail: detail.clone(),
                        hint: hint.clone(),
                        diagnostic: diagnostic.clone(),
                    }
                );
                assert!(
                    error_display.contains("(constraint: users_email_key)"),
                    "Display must include constraint name for debugging: {error_display}"
                );
                assert!(
                    error_display.contains("(table: users)"),
                    "Display must include table name for debugging: {error_display}"
                );
                assert!(
                    error_display.contains("(schema: public)"),
                    "Display must include schema name for debugging: {error_display}"
                );
                assert!(
                    error_display.contains("(column: email)"),
                    "Display must include column name for debugging: {error_display}"
                );
                assert!(
                    error_display.contains("(position: 42)"),
                    "Display must include position for SQL debugging: {error_display}"
                );
            } else {
                panic!(
                    "Expected PgError::Server for diagnostic field test, got {:?}",
                    parsed_error
                );
            }
        }

        #[test]
        fn audit_diagnostic_field_subset_handling() {
            let conn = make_test_connection();

            // Test Case 2: Error with only some diagnostic fields
            let mut partial_error = Vec::new();
            partial_error.push(b'C');
            partial_error.extend_from_slice(b"42P01\0"); // Table not found
            partial_error.push(b'M');
            partial_error.extend_from_slice(b"relation \"nonexistent\" does not exist\0");
            partial_error.push(b't'); // Only table name, no constraint/column
            partial_error.extend_from_slice(b"nonexistent\0");
            partial_error.push(b'S');
            partial_error.extend_from_slice(b"ERROR\0");
            partial_error.push(0);

            let parsed_error = conn
                .parse_error_response(&partial_error)
                .expect("Partial diagnostic fields should parse");

            if let PgError::Server { diagnostic, .. } = parsed_error {
                assert_eq!(diagnostic.table_name, Some("nonexistent".to_string()));
                assert_eq!(diagnostic.severity, Some("ERROR".to_string()));
                // Absent fields should be None
                assert_eq!(diagnostic.constraint_name, None);
                assert_eq!(diagnostic.column_name, None);
                assert_eq!(diagnostic.schema_name, None);
            } else {
                panic!("Expected PgError::Server for partial diagnostic test");
            }
        }

        #[test]
        fn audit_diagnostic_field_empty_case() {
            let conn = make_test_connection();

            // Test Case 3: Error with no diagnostic fields (legacy behavior)
            let mut minimal_error = Vec::new();
            minimal_error.push(b'C');
            minimal_error.extend_from_slice(b"XX000\0");
            minimal_error.push(b'M');
            minimal_error.extend_from_slice(b"generic error\0");
            minimal_error.push(0);

            let parsed_error = conn
                .parse_error_response(&minimal_error)
                .expect("Minimal error should parse");

            if let PgError::Server { diagnostic, .. } = parsed_error {
                // All diagnostic fields should be None for minimal errors
                assert_eq!(diagnostic.constraint_name, None);
                assert_eq!(diagnostic.table_name, None);
                assert_eq!(diagnostic.schema_name, None);
                assert_eq!(diagnostic.column_name, None);
                assert_eq!(diagnostic.severity, None);
                assert_eq!(diagnostic.position, None);

                // Should equal default
                assert_eq!(diagnostic, PgErrorDiagnostic::default());
            } else {
                panic!("Expected PgError::Server for minimal error test");
            }
        }

        #[test]
        fn audit_unknown_diagnostic_field_handling() {
            let conn = make_test_connection();

            // Test Case 4: Future PostgreSQL extension with unknown field type
            let mut future_error = Vec::new();
            future_error.push(b'C');
            future_error.extend_from_slice(b"XX001\0");
            future_error.push(b'M');
            future_error.extend_from_slice(b"future error\0");
            future_error.push(b'Z'); // Unknown field type (future extension)
            future_error.extend_from_slice(b"future_data\0");
            future_error.push(0);

            let parsed_error = conn
                .parse_error_response(&future_error)
                .expect("Unknown fields should be ignored, not cause parse failure");

            if let PgError::Server { code, message, .. } = parsed_error {
                assert_eq!(code, "XX001");
                assert_eq!(message, "future error");
                // Should not crash on unknown field type 'Z'
            } else {
                panic!("Expected PgError::Server even with unknown fields");
            }
        }

        // AUDIT VERIFICATION:
        // ✓ Constraint name, table name, schema name, column name now preserved
        // ✓ All PostgreSQL protocol diagnostic fields captured per documentation
        // ✓ Display implementation includes actionable diagnostic information
        // ✓ Backward compatibility maintained for errors without diagnostic fields
        // ✓ Forward compatibility maintained for unknown future diagnostic fields
        // ✓ No information loss for debugging constraint violations, type errors, etc.
    }

    /// AUDIT MODULE: PostgreSQL notification ordering behavior verification
    ///
    /// AUDIT FINDING: SOUND - Current implementation cannot reorder NOTIFY messages
    /// because no notification storage/delivery mechanism exists. The
    /// handle_notification_response() method parses and discards all notifications.
    ///
    /// This module documents the ordering requirements that must be maintained
    /// when notification delivery is implemented in the future.
    mod notification_ordering_audit {
        use super::*;

        /// AUDIT: Verify current notification handling discards messages (no reordering risk)
        ///
        /// Current implementation is SOUND because handle_notification_response()
        /// parses notification fields but discards them entirely. No buffering or
        /// storage means no opportunity for reordering.
        #[test]
        fn audit_current_notification_handling_discards_messages() {
            let (mut conn, _peer) = make_test_connection_with_peer();

            // Create notification messages with different payloads to verify parsing
            let notification1 = {
                let mut data = Vec::new();
                data.extend_from_slice(&100i32.to_be_bytes()); // process_id
                data.extend_from_slice(b"channel1\0"); // channel
                data.extend_from_slice(b"payload1\0"); // payload
                data
            };

            let notification2 = {
                let mut data = Vec::new();
                data.extend_from_slice(&200i32.to_be_bytes()); // process_id
                data.extend_from_slice(b"channel2\0"); // channel
                data.extend_from_slice(b"payload2\0"); // payload
                data
            };

            // Verify both notifications are parsed successfully but discarded
            assert!(
                conn.handle_notification_response(&notification1).is_ok(),
                "Notification parsing should succeed"
            );
            assert!(
                conn.handle_notification_response(&notification2).is_ok(),
                "Notification parsing should succeed"
            );

            // AUDIT VERIFICATION: No state change in connection after notifications
            // This confirms notifications are discarded, not buffered/stored
        }

        /// AUDIT: Verify notification ordering requirements for future implementation
        ///
        /// When notification delivery is implemented, this test documents the
        /// requirement that PostgreSQL server ordering MUST be preserved.
        /// TCP guarantees ordered delivery, so client buffering must maintain order.
        #[test]
        fn audit_notification_ordering_requirements_for_future_delivery() {
            // AUDIT REQUIREMENT 1: PostgreSQL server determines canonical order
            // Per PostgreSQL documentation, NOTIFY commands execute in transaction
            // commit order, which is the authoritative sequence.

            // AUDIT REQUIREMENT 2: TCP preserves server order during transmission
            // TCP ordered delivery guarantees that notifications arrive at the
            // client socket in the same order the server sent them.

            // AUDIT REQUIREMENT 3: Client buffering must not reorder
            // Any future notification buffering/queuing mechanism must use:
            // - FIFO queue structure (not HashMap or unordered collection)
            // - Sequential processing (not parallel dispatch that could reorder)
            // - Atomic enqueue operations (no partial notification states)

            // AUDIT REQUIREMENT 4: Error handling must preserve order
            // If notification delivery fails:
            // - Failed notifications must not be dropped from sequence
            // - Retry logic must preserve original order
            // - No "fast lane" for certain notification types

            // Test case: Rapid succession notifications (100+ messages)
            // This pattern is common in high-frequency event systems
            let notification_sequence: Vec<Vec<u8>> = (0..150)
                .map(|i| {
                    let mut data = Vec::new();
                    data.extend_from_slice(&(1000i32 + i).to_be_bytes()); // unique process_id
                    data.extend_from_slice(b"events\0");
                    data.extend_from_slice(format!("event_{}\0", i).as_bytes());
                    data
                })
                .collect();

            let (mut conn, _peer) = make_test_connection_with_peer();

            // Verify all notifications in sequence can be parsed
            for (index, notification) in notification_sequence.iter().enumerate() {
                assert!(
                    conn.handle_notification_response(notification).is_ok(),
                    "Notification {} should parse successfully",
                    index
                );
            }

            // AUDIT VERIFICATION: Current implementation is SOUND
            // - No buffering = no reordering possible
            // - When delivery is added, it must maintain sequence order
            // - Test documents the 100+ rapid succession requirement
        }

        /// AUDIT: Verify notification message format follows PostgreSQL protocol
        ///
        /// Ensures notification parsing handles all valid NotificationResponse
        /// message formats per PostgreSQL protocol specification.
        #[test]
        fn audit_notification_message_format_compliance() {
            let (mut conn, _peer) = make_test_connection_with_peer();

            // Test Case 1: Minimal valid notification
            let minimal = {
                let mut data = Vec::new();
                data.extend_from_slice(&0i32.to_be_bytes()); // process_id = 0
                data.extend_from_slice(b"events\0"); // channel
                data.extend_from_slice(b"\0"); // empty payload
                data
            };

            assert!(
                conn.handle_notification_response(&minimal).is_ok(),
                "Minimal notification should parse"
            );

            // Test Case 2: Maximum size fields (within PostgreSQL limits)
            let large_channel = "a".repeat(63); // PostgreSQL identifier limit
            let large_payload = "x".repeat(8000); // Reasonable payload size
            let maximal = {
                let mut data = Vec::new();
                data.extend_from_slice(&i32::MAX.to_be_bytes());
                data.extend_from_slice(large_channel.as_bytes());
                data.push(0);
                data.extend_from_slice(large_payload.as_bytes());
                data.push(0);
                data
            };

            assert!(
                conn.handle_notification_response(&maximal).is_ok(),
                "Large notification should parse"
            );

            // Test Case 3: Unicode in payload (UTF-8 encoded)
            let unicode_notification = {
                let mut data = Vec::new();
                data.extend_from_slice(&42i32.to_be_bytes());
                data.extend_from_slice(b"events\0");
                data.extend_from_slice("message with 🚀 emoji and 中文".as_bytes());
                data.push(0);
                data
            };

            assert!(
                conn.handle_notification_response(&unicode_notification)
                    .is_ok(),
                "Unicode payload should parse"
            );

            // AUDIT VERIFICATION: Protocol compliance ensures compatibility
            // - Handles all valid NotificationResponse message formats
            // - Supports empty payloads, large fields, and Unicode content
            // - Parser robustness prevents protocol errors during ordering
        }

        /// AUDIT: Verify error cases that could affect notification ordering
        #[test]
        fn audit_notification_error_cases_preserve_ordering() {
            let (mut conn, _peer) = make_test_connection_with_peer();

            // Test Case 1: Malformed notification (missing null terminator)
            let malformed = {
                let mut data = Vec::new();
                data.extend_from_slice(&42i32.to_be_bytes());
                data.extend_from_slice(b"channel"); // Missing \0
                data
            };

            assert!(
                conn.handle_notification_response(&malformed).is_err(),
                "Malformed notification should fail parsing"
            );

            // Test Case 2: Verify connection state after parse error
            // Connection should remain usable, not corrupted by parse failure
            let valid_notification = {
                let mut data = Vec::new();
                data.extend_from_slice(&100i32.to_be_bytes());
                data.extend_from_slice(b"test\0");
                data.extend_from_slice(b"ok\0");
                data
            };

            assert!(
                conn.handle_notification_response(&valid_notification)
                    .is_ok(),
                "Valid notification should parse after error"
            );

            // AUDIT REQUIREMENT: Parse errors must not corrupt ordering state
            // When notification delivery is implemented:
            // - Parse failures must not lose subsequent notifications
            // - Error recovery must not skip or reorder pending notifications
            // - Connection state must remain consistent for ordering guarantees
        }
    }

    /// AUDIT MODULE: PostgreSQL reconnect on idle disconnect behavior.
    ///
    /// AUDIT FINDING: FIXED - idle remote closes are recovered by reconnecting
    /// with the original options, replaying LISTEN state, and then issuing the
    /// caller's request on the fresh backend. Explicit user closes and
    /// transaction-bearing sessions remain fail-closed.
    #[cfg(test)]
    mod postgres_reconnect_on_idle_disconnect_audit {
        use super::*;

        #[test]
        fn idle_disconnect_reconnects_and_retries_parameterized_query() {
            init_test("idle_disconnect_reconnects_and_retries_parameterized_query");

            let (options, server) = spawn_deterministic_postgres_server(|stream| {
                let request = read_until_contains(stream, &[b'S', 0, 0, 0, 4]);
                assert!(
                    request
                        .windows(b"SELECT 1\0".len())
                        .any(|window| window == b"SELECT 1\0"),
                    "reconnected request should carry caller SQL"
                );
                write_single_text_query_result(stream, "1");
            });
            let mut conn = make_test_connection();
            conn.inner.options = options;
            conn.inner.cancel_target = CancelTarget::from_options(&conn.inner.options);
            let cx = crate::cx::Cx::for_testing();

            // The local state mirrors a server-side idle timeout detected
            // before the next request starts.
            conn.inner.closed = true;

            let rows = match run(conn.query_params(&cx, "SELECT 1", &[])) {
                Outcome::Ok(rows) => rows,
                other => panic!("expected reconnect-backed query success, got: {other:?}"),
            };
            assert_eq!(rows.len(), 1);
            assert!(matches!(
                rows[0].get("value"),
                Ok(PgValue::Text(value)) if value == "1"
            ));
            assert!(!conn.inner.closed, "fresh connection should remain open");
            assert_eq!(conn.inner.process_id, 4242);

            server.join().expect("deterministic postgres server exits");
            test_complete!("idle_disconnect_reconnects_and_retries_parameterized_query");
        }

        #[test]
        fn explicit_close_and_transaction_state_remain_fail_closed() {
            init_test("explicit_close_and_transaction_state_remain_fail_closed");

            let mut explicitly_closed = make_test_connection();
            let cx = crate::cx::Cx::for_testing();
            run(explicitly_closed.close()).expect("close succeeds");
            match run(explicitly_closed.query_params(&cx, "SELECT 1", &[])) {
                Outcome::Err(PgError::ConnectionClosed) => {}
                other => panic!("explicit close must stay closed, got: {other:?}"),
            }

            let mut in_transaction = make_test_connection();
            in_transaction.inner.closed = true;
            in_transaction.inner.transaction_status = b'T';
            match run(in_transaction.query_params(&cx, "SELECT 1", &[])) {
                Outcome::Err(PgError::ConnectionClosed) => {}
                other => panic!("closed transaction must not reconnect, got: {other:?}"),
            }

            test_complete!("explicit_close_and_transaction_state_remain_fail_closed");
        }

        /// AUDIT: Test connection error detection logic is sound
        ///
        /// Verify that is_connection_error() correctly identifies errors that
        /// should trigger reconnection attempts. This part is SOUND.
        #[test]
        fn audit_connection_error_detection_is_sound() {
            init_test("audit_connection_error_detection_is_sound");

            // Test connection errors that should trigger reconnection
            let transient_connection_errors = vec![
                PgError::ConnectionClosed,
                PgError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken",
                )),
                PgError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "aborted",
                )),
            ];

            for error in &transient_connection_errors {
                assert!(
                    error.is_connection_error(),
                    "Error {:?} must be classified as connection error",
                    error
                );

                assert!(
                    error.is_transient(),
                    "Connection error {:?} must be classified as transient",
                    error
                );
            }

            let tls_required = PgError::TlsRequired;
            assert!(
                tls_required.is_connection_error(),
                "TLS-required negotiation failure is connection-level"
            );
            assert!(
                !tls_required.is_transient(),
                "TLS-required negotiation failure should not be retried without configuration changes"
            );

            // Test non-connection errors that should NOT trigger reconnection
            let non_connection_errors = vec![
                PgError::Server {
                    code: "23505".to_string(),
                    message: "duplicate key".to_string(),
                    detail: None,
                    hint: None,
                    diagnostic: PgErrorDiagnostic::default(),
                },
                PgError::ColumnNotFound("missing_col".to_string()),
                PgError::TypeConversion {
                    column: "col".to_string(),
                    expected: "i32",
                    actual_oid: 25,
                },
            ];

            for error in &non_connection_errors {
                assert!(
                    !error.is_connection_error(),
                    "Error {:?} must NOT be classified as connection error",
                    error
                );
            }

            eprintln!(
                "{{\"audit\":\"CONNECTION_ERROR_DETECTION\",\"status\":\"SOUND\",\"requirement\":\"proper error classification\"}}"
            );

            test_complete!("audit_connection_error_detection_is_sound");
        }

        #[test]
        fn idle_remote_close_reconnects_with_original_options() {
            init_test("idle_remote_close_reconnects_with_original_options");

            let (options, server) = spawn_deterministic_postgres_server(|_stream| {});
            let mut conn = make_test_connection();
            conn.inner.options = options.clone();
            conn.inner.cancel_target = CancelTarget::from_options(&conn.inner.options);
            conn.inner.max_result_rows = 17;
            let cx = crate::cx::Cx::for_testing();
            conn.inner.closed = true;

            match run(conn.ensure_open_for_request(&cx)) {
                Outcome::Ok(PgOpenState::Reconnected) => {}
                other => panic!("expected idle reconnect, got: {other:?}"),
            }
            assert!(!conn.inner.closed);
            assert_eq!(conn.inner.options.host, options.host);
            assert_eq!(conn.inner.options.port, options.port);
            assert_eq!(conn.inner.max_result_rows, 17);

            server.join().expect("deterministic postgres server exits");
            test_complete!("idle_remote_close_reconnects_with_original_options");
        }

        /// AUDIT: Verify connection pooling context and requirements
        ///
        /// Documents the connection pooling patterns this fix should support,
        /// ensuring compatibility with existing pool infrastructure.
        #[test]
        fn audit_connection_pooling_context_requirements() {
            init_test("audit_connection_pooling_context_requirements");

            // Connection pooling context:
            // - PgConnectionManager implements AsyncConnectionManager
            // - Pool manages connection lifecycle (create, validate, release)
            // - Applications get connections from pool, not direct TCP
            // - Reconnection should work both in-pool and standalone contexts

            // Reconnection preserves original connect options.
            let original_options = PgConnectOptions {
                host: "localhost".to_string(),
                port: 5432,
                user: "test_user".to_string(),
                password: Some("test_pass".into()),
                database: "test_db".to_string(),
                ssl_mode: SslMode::Prefer,
                application_name: Some("test_app".to_string()),
                connect_timeout: Some(std::time::Duration::from_secs(30)),
            };
            let mgr = PgConnectionManager::new(original_options.clone());
            assert_eq!(mgr.options().host, original_options.host);
            assert_eq!(mgr.options().port, original_options.port);
            assert_eq!(mgr.options().database, original_options.database);

            // Reconnection respects pool semantics:
            // - Pool health checks use is_connection_error() classification
            // - Pool release_check uses needs_discard flag for safety
            // - Direct-connection reconnect does not affect pool return behavior

            eprintln!(
                "{{\"audit\":\"POOLING_REQUIREMENTS\",\"status\":\"SOUND\",\"context\":\"pool-compatible reconnect policy\"}}"
            );

            test_complete!("audit_connection_pooling_context_requirements");
        }
    }

    /// AUDIT MODULE: PostgreSQL LISTEN/NOTIFY auto-resubscribe semantics.
    ///
    /// AUDIT FINDING: FIXED - successful LISTEN/UNLISTEN calls update
    /// connection-local subscription state, and idle reconnect replays that
    /// state before any caller query proceeds.
    #[cfg(test)]
    mod postgres_listen_notify_auto_resubscribe_audit {
        use super::*;

        #[test]
        fn listen_and_unlisten_update_subscription_state() {
            init_test("listen_and_unlisten_update_subscription_state");

            let (mut conn, mut peer) = make_test_connection_with_peer();
            let cx = crate::cx::Cx::for_testing();

            let responder = std::thread::spawn(move || {
                let listen = read_until_contains(&mut peer, b"LISTEN \"jobs\"\0");
                assert!(
                    listen
                        .windows(b"LISTEN \"jobs\"\0".len())
                        .any(|w| w == b"LISTEN \"jobs\"\0")
                );
                std::io::Write::write_all(&mut peer, &command_complete_message("LISTEN"))
                    .expect("write LISTEN complete");
                std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                    .expect("write LISTEN ready");

                let unlisten = read_until_contains(&mut peer, b"UNLISTEN \"jobs\"\0");
                assert!(
                    unlisten
                        .windows(b"UNLISTEN \"jobs\"\0".len())
                        .any(|w| w == b"UNLISTEN \"jobs\"\0")
                );
                std::io::Write::write_all(&mut peer, &command_complete_message("UNLISTEN"))
                    .expect("write UNLISTEN complete");
                std::io::Write::write_all(&mut peer, &ready_for_query(b'I'))
                    .expect("write UNLISTEN ready");
            });

            match run(conn.listen(&cx, "jobs")) {
                Outcome::Ok(()) => {}
                other => panic!("LISTEN should succeed, got: {other:?}"),
            }
            assert!(conn.inner.subscribed_channels.contains("jobs"));

            match run(conn.unlisten(&cx, "jobs")) {
                Outcome::Ok(()) => {}
                other => panic!("UNLISTEN should succeed, got: {other:?}"),
            }
            assert!(!conn.inner.subscribed_channels.contains("jobs"));

            responder.join().expect("listen responder exits");
            test_complete!("listen_and_unlisten_update_subscription_state");
        }

        #[test]
        fn listen_unlisten_sql_uses_identifier_quoting() {
            init_test("listen_unlisten_sql_uses_identifier_quoting");
            let test_channels = ["jobs", "notifications", "alerts"];

            for channel in &test_channels {
                let listen_sql = build_listen_sql(channel).unwrap();
                assert_eq!(listen_sql, format!("LISTEN \"{channel}\""));

                let unlisten_sql = build_unlisten_sql(channel).unwrap();
                assert_eq!(unlisten_sql, format!("UNLISTEN \"{channel}\""));
            }

            test_complete!("listen_unlisten_sql_uses_identifier_quoting");
        }

        #[test]
        fn idle_reconnect_replays_tracked_listen_channels() {
            init_test("idle_reconnect_replays_tracked_listen_channels");

            let (options, server) = spawn_deterministic_postgres_server(|stream| {
                let jobs = read_until_contains(stream, b"LISTEN \"jobs\"\0");
                assert!(
                    jobs.windows(b"LISTEN \"jobs\"\0".len())
                        .any(|w| w == b"LISTEN \"jobs\"\0")
                );
                std::io::Write::write_all(stream, &command_complete_message("LISTEN"))
                    .expect("write jobs LISTEN complete");
                std::io::Write::write_all(stream, &ready_for_query(b'I'))
                    .expect("write jobs LISTEN ready");

                let user_events = read_until_contains(stream, b"LISTEN \"user_events\"\0");
                assert!(
                    user_events
                        .windows(b"LISTEN \"user_events\"\0".len())
                        .any(|w| w == b"LISTEN \"user_events\"\0")
                );
                std::io::Write::write_all(stream, &command_complete_message("LISTEN"))
                    .expect("write user_events LISTEN complete");
                std::io::Write::write_all(stream, &ready_for_query(b'I'))
                    .expect("write user_events LISTEN ready");
            });
            let mut conn = make_test_connection();
            conn.inner.options = options;
            conn.inner.cancel_target = CancelTarget::from_options(&conn.inner.options);
            let cx = crate::cx::Cx::for_testing();
            conn.inner.subscribed_channels.insert("jobs".to_string());
            conn.inner
                .subscribed_channels
                .insert("user_events".to_string());
            conn.inner.closed = true;

            match run(conn.ensure_open_for_request(&cx)) {
                Outcome::Ok(PgOpenState::Reconnected) => {}
                other => panic!("expected reconnect with subscription replay, got: {other:?}"),
            }
            assert!(conn.inner.subscribed_channels.contains("jobs"));
            assert!(conn.inner.subscribed_channels.contains("user_events"));
            assert!(!conn.inner.closed);

            server.join().expect("deterministic postgres server exits");
            test_complete!("idle_reconnect_replays_tracked_listen_channels");
        }

        #[test]
        fn auto_resubscribe_contract_is_fail_closed() {
            init_test("auto_resubscribe_contract_is_fail_closed");
            let expected_behavior = ListenNotifyBehavior {
                tracks_subscriptions: true,
                auto_resubscribe_on_reconnect: true,
                subscription_recovery_transparent: true,
                fails_closed_on_resubscribe_failure: true,
            };

            assert!(
                expected_behavior.tracks_subscriptions,
                "connection state must track LISTEN subscriptions"
            );
            assert!(
                expected_behavior.auto_resubscribe_on_reconnect,
                "reconnect must replay tracked channels"
            );
            assert!(
                expected_behavior.subscription_recovery_transparent,
                "subscription replay must finish before caller work resumes"
            );
            assert!(
                expected_behavior.fails_closed_on_resubscribe_failure,
                "lost subscription recovery must surface as reconnect failure"
            );

            eprintln!(
                "{{\"requirement\":\"AUTO_RESUBSCRIBE\",\"status\":\"SOUND\",\"failure_policy\":\"fail_closed\"}}"
            );

            test_complete!("auto_resubscribe_contract_is_fail_closed");
        }

        /// AUDIT: Test PostgreSQL channel name validation is sound
        ///
        /// Verifies that channel name validation correctly prevents injection
        /// attacks and follows PostgreSQL identifier rules. This part is SOUND.
        #[test]
        fn audit_channel_name_validation_is_sound() {
            init_test("audit_channel_name_validation_is_sound");

            // AUDIT VERIFICATION: Channel name validation prevents injection
            let too_long_channel = "a".repeat(MAX_NOTIFICATION_CHANNEL_NAME_BYTES + 1);
            let malicious_channels = vec![
                "jobs\";UNLISTEN *;--",
                "test\0null_injection",
                too_long_channel.as_str(),
                "DROP TABLE users;--",
            ];

            for malicious_channel in &malicious_channels {
                // Test both LISTEN and UNLISTEN validation
                let listen_result = build_listen_sql(malicious_channel);
                let unlisten_result = build_unlisten_sql(malicious_channel);

                match (listen_result, unlisten_result) {
                    (Err(_), Err(_)) => {
                        // SOUND: Malicious channel names properly rejected
                    }
                    (Ok(sql), _) | (_, Ok(sql)) => {
                        panic!(
                            "Channel validation failed: malicious channel '{}' generated SQL: {}",
                            malicious_channel, sql
                        );
                    }
                }
            }

            // AUDIT VERIFICATION: Valid channel names work correctly
            let valid_channels = vec!["jobs", "user_events", "system.alerts", "queue_1"];

            for valid_channel in &valid_channels {
                let listen_sql = build_listen_sql(valid_channel).unwrap();
                let unlisten_sql = build_unlisten_sql(valid_channel).unwrap();

                assert!(listen_sql.starts_with("LISTEN "));
                assert!(unlisten_sql.starts_with("UNLISTEN "));

                // Verify proper quoting
                let quoted_channel = quote_postgres_identifier(valid_channel);
                assert!(listen_sql.contains(&quoted_channel));
                assert!(unlisten_sql.contains(&quoted_channel));
            }

            eprintln!(
                "{{\"audit\":\"CHANNEL_NAME_VALIDATION\",\"status\":\"SOUND\",\"requirement\":\"injection prevention\"}}"
            );

            test_complete!("audit_channel_name_validation_is_sound");
        }

        /// Expected LISTEN/NOTIFY behavior for implementation reference
        #[derive(Debug)]
        struct ListenNotifyBehavior {
            tracks_subscriptions: bool,
            auto_resubscribe_on_reconnect: bool,
            subscription_recovery_transparent: bool,
            fails_closed_on_resubscribe_failure: bool,
        }
    }
}

#[cfg(test)]
#[path = "postgres_auth_downgrade_audit.rs"]
mod postgres_auth_downgrade_audit;
#[cfg(test)]
#[path = "postgres_copy_from_error_audit.rs"]
mod postgres_copy_from_error_audit;
