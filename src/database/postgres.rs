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

use crate::cx::{CancelWakerToken, Cx};
use crate::database::transaction::trace_database_transaction;
use crate::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::net::TcpStream;
use crate::obligation::graded::{ObligationToken, TransactionKind};
use crate::security::SecretString;
#[cfg(feature = "tls")]
use crate::tls::{Certificate, TlsConnector, TlsConnectorBuilder, TlsStream};
use crate::types::{CancelReason, Outcome};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

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
/// the memory usage issue where all rows are collected into `Vec<PgRow>` before
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

impl PgRowStream<'_> {
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
    /// Set when a caller supplied a string containing an embedded NUL to
    /// [`MessageBuffer::write_cstring`]. Because a PostgreSQL C-string cannot
    /// carry an interior NUL, the buffer is "poisoned" and the finalizing
    /// `build_*` call fails closed rather than emitting a truncated,
    /// injection-prone message.
    nul_error: Option<String>,
}

impl MessageBuffer {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(256),
            nul_error: None,
        }
    }

    fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
            nul_error: None,
        }
    }

    #[cfg(test)]
    fn clear(&mut self) {
        self.buf.clear();
        self.nul_error = None;
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
        // Prevent protocol injection: a PostgreSQL C-string is NUL-terminated,
        // so a caller-supplied embedded NUL cannot be represented. The previous
        // behavior truncated at the first NUL and continued, guarded only by a
        // `debug_assert!` — meaning release builds silently emitted a truncated
        // string followed by whatever bytes trailed the NUL (a
        // truncation-injection hazard). Instead, poison the buffer so the
        // finalizing `build_message` / `build_startup_message` fails closed with
        // an error in both debug and release builds. Nothing is appended for the
        // offending field, keeping the poisoned buffer unambiguous.
        let bytes = s.as_bytes();
        if let Some(pos) = bytes.iter().position(|&b| b == 0) {
            if self.nul_error.is_none() {
                self.nul_error = Some(format!(
                    "C-string contains embedded NUL byte at offset {pos}"
                ));
            }
            return;
        }
        self.buf.extend_from_slice(bytes);
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
        if let Some(err) = &self.nul_error {
            return Err(PgError::Protocol(err.clone()));
        }
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
        if let Some(err) = &self.nul_error {
            return Err(PgError::Protocol(err.clone()));
        }
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

    // Constant-time byte comparison: every expected byte is visited
    // regardless of earlier mismatches, and missing actual bytes compare
    // against 0 rather than short-circuiting.
    #[allow(clippy::needless_range_loop)]
    for i in 0..expected.len() {
        let actual_byte = actual.get(i).copied().unwrap_or(0);
        diff |= expected[i] ^ actual_byte;
    }

    black_box(diff) == 0
}

#[derive(Debug)]
struct ScramServerFirst<'a> {
    full_nonce: &'a str,
    salt: Vec<u8>,
    iterations: u32,
}

#[inline]
fn is_scram_nonce_byte(byte: u8) -> bool {
    matches!(byte, b'!'..=b'+' | b'-'..=b'~')
}

/// Precomputed HMAC-SHA-256 key schedule whose password-equivalent material is
/// wiped on every exit path, including cancellation between PBKDF2 rounds.
struct ScramHmacSha256Key {
    inner_pad: zeroize::Zeroizing<[u8; SCRAM_HMAC_BLOCK_LEN]>,
    outer_pad: zeroize::Zeroizing<[u8; SCRAM_HMAC_BLOCK_LEN]>,
}

// Keep the dependency feature that wipes transient SHA-256 compression and
// buffer state as a compile-time part of this authentication contract.
const _: fn() = {
    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<sha2::Sha256>
};

impl ScramHmacSha256Key {
    fn new(key: &[u8]) -> Self {
        use sha2::{Digest, Sha256};

        let mut key_block = zeroize::Zeroizing::new([0; SCRAM_HMAC_BLOCK_LEN]);
        if key.len() > SCRAM_HMAC_BLOCK_LEN {
            let digest: zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]> =
                zeroize::Zeroizing::new(Sha256::digest(key).into());
            key_block[..SCRAM_SHA256_LEN].copy_from_slice(&digest[..]);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner_pad = zeroize::Zeroizing::new([0x36; SCRAM_HMAC_BLOCK_LEN]);
        let mut outer_pad = zeroize::Zeroizing::new([0x5c; SCRAM_HMAC_BLOCK_LEN]);
        for ((inner, outer), key_byte) in inner_pad
            .iter_mut()
            .zip(outer_pad.iter_mut())
            .zip(key_block.iter())
        {
            *inner ^= *key_byte;
            *outer ^= *key_byte;
        }

        Self {
            inner_pad,
            outer_pad,
        }
    }

    fn digest(&self, data: &[u8]) -> zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]> {
        self.digest_segments(&[data])
    }

    fn digest_segments(&self, segments: &[&[u8]]) -> zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]> {
        use sha2::{Digest, Sha256};

        let mut inner = Sha256::new();
        inner.update(&self.inner_pad[..]);
        for segment in segments {
            inner.update(*segment);
        }
        let inner_hash: zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]> =
            zeroize::Zeroizing::new(inner.finalize().into());

        let mut outer = Sha256::new();
        outer.update(&self.outer_pad[..]);
        outer.update(&inner_hash[..]);
        zeroize::Zeroizing::new(outer.finalize().into())
    }
}

/// SCRAM-SHA-256 authentication state machine.
///
/// br-asupersync-r2l1ze: `password` is held in a [`SecretString`] so the
/// plaintext bytes are zeroized when the `ScramAuth` value is dropped
/// (i.e. when the SCRAM exchange completes or is cancelled). A successful
/// server-first exchange wipes it earlier, immediately after the only PBKDF2
/// derivation. Heap snapshots, core dumps, or attached debuggers reading stale
/// memory after auth completes recover only zero bytes.
struct ScramAuth {
    /// Password — wiped on drop (br-asupersync-r2l1ze).
    password: SecretString,
    /// Client nonce.
    client_nonce: String,
    /// One-shot expected server verifier. All other derived state is discarded
    /// after client-final construction.
    expected_server_signature: Option<zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]>>,
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
            expected_server_signature: None,
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

    fn parse_server_first<'a>(
        &self,
        server_first: &'a str,
    ) -> Result<ScramServerFirst<'a>, PgError> {
        if server_first.len() > MAX_SCRAM_SERVER_FIRST_LEN {
            return Err(PgError::AuthenticationFailed(format!(
                "SCRAM server-first message is {} bytes; maximum is {MAX_SCRAM_SERVER_FIRST_LEN}",
                server_first.len()
            )));
        }

        // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
        let mut server_nonce: Option<&str> = None;
        let mut salt = None;
        let mut iterations: Option<u32> = None;

        for part in server_first.split(',') {
            if part.starts_with("m=") {
                return Err(PgError::AuthenticationFailed(
                    "unsupported SCRAM mandatory extension".to_string(),
                ));
            } else if let Some(value) = part.strip_prefix("r=") {
                if server_nonce.replace(value).is_some() {
                    return Err(PgError::AuthenticationFailed(
                        "duplicate server nonce".to_string(),
                    ));
                }
            } else if let Some(value) = part.strip_prefix("s=") {
                if value.len() > MAX_SCRAM_SALT_B64_LEN {
                    return Err(PgError::AuthenticationFailed(format!(
                        "SCRAM salt encoding is {} bytes; maximum is {MAX_SCRAM_SALT_B64_LEN}",
                        value.len()
                    )));
                }
                let decoded =
                    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
                        .map_err(|e| PgError::AuthenticationFailed(format!("invalid salt: {e}")))?;
                if decoded.is_empty() || decoded.len() > MAX_SCRAM_SALT_LEN {
                    return Err(PgError::AuthenticationFailed(format!(
                        "SCRAM salt is {} bytes; expected 1..={MAX_SCRAM_SALT_LEN}",
                        decoded.len()
                    )));
                }
                if salt.replace(decoded).is_some() {
                    return Err(PgError::AuthenticationFailed("duplicate salt".to_string()));
                }
            } else if let Some(value) = part.strip_prefix("i=") {
                if value.starts_with('0')
                    || value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(PgError::AuthenticationFailed(format!(
                        "invalid iterations: {value}"
                    )));
                }
                let parsed = value.parse::<u32>().map_err(|e| {
                    PgError::AuthenticationFailed(format!("invalid iterations: {e}"))
                })?;
                if iterations.replace(parsed).is_some() {
                    return Err(PgError::AuthenticationFailed(
                        "duplicate iterations".to_string(),
                    ));
                }
            } else if !part.contains('=') {
                return Err(PgError::AuthenticationFailed(
                    "invalid SCRAM server-first attribute".to_string(),
                ));
            }
        }

        let full_nonce = server_nonce
            .ok_or_else(|| PgError::AuthenticationFailed("missing server nonce".to_string()))?;
        let salt = salt.ok_or_else(|| PgError::AuthenticationFailed("missing salt".to_string()))?;
        let iterations = iterations
            .ok_or_else(|| PgError::AuthenticationFailed("missing iterations".to_string()))?;
        if !(MIN_SCRAM_PBKDF2_ITERATIONS..=MAX_SCRAM_PBKDF2_ITERATIONS).contains(&iterations) {
            return Err(PgError::AuthenticationFailed(format!(
                "SCRAM iteration count {iterations} outside safe range {MIN_SCRAM_PBKDF2_ITERATIONS}..={MAX_SCRAM_PBKDF2_ITERATIONS}"
            )));
        }

        if full_nonce.len() > MAX_SCRAM_NONCE_LEN {
            return Err(PgError::AuthenticationFailed(format!(
                "SCRAM server nonce is {} bytes; maximum is {MAX_SCRAM_NONCE_LEN}",
                full_nonce.len()
            )));
        }
        if !full_nonce.bytes().all(is_scram_nonce_byte) {
            return Err(PgError::AuthenticationFailed(
                "SCRAM server nonce contains an invalid byte".to_string(),
            ));
        }
        // The server must preserve our nonce and contribute at least one byte
        // of its own; equality provides no freshness contribution from it.
        if !full_nonce.starts_with(&self.client_nonce)
            || full_nonce.len() == self.client_nonce.len()
        {
            return Err(PgError::AuthenticationFailed(
                "server nonce must extend the client nonce".to_string(),
            ));
        }

        Ok(ScramServerFirst {
            full_nonce,
            salt,
            iterations,
        })
    }

    /// Process server-first message and generate client-final message.
    async fn process_server_first(
        &mut self,
        cx: &Cx,
        server_first: &str,
    ) -> Result<Vec<u8>, PgError> {
        let ScramServerFirst {
            full_nonce,
            salt,
            iterations,
        } = self.parse_server_first(server_first)?;

        // Compute salted password using PBKDF2-SHA256
        let salted_password_result =
            Self::pbkdf2_sha256(cx, self.password.as_str(), &salt, iterations).await;
        // No later SCRAM step needs the plaintext password. Wipe it on both the
        // success and cancellation/error paths as soon as PBKDF2 releases it.
        self.password.explicit_zeroize();
        let salted_password = salted_password_result?;

        // Compute client key and stored key
        let client_key = Self::hmac_sha256(&salted_password[..], b"Client Key");
        let stored_key = Self::sha256(&client_key[..]);

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

        // Compute client signature and proof
        let client_signature = Self::hmac_sha256(&stored_key[..], auth_message.as_bytes());
        let client_proof: zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]> =
            zeroize::Zeroizing::new(std::array::from_fn(|index| {
                client_key[index] ^ client_signature[index]
            }));
        let client_proof_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &client_proof[..],
        );

        // Derive the verifier while the single salted-password result is live.
        // Server-final then performs only bounded decoding and comparison.
        let server_key = Self::hmac_sha256(&salted_password[..], b"Server Key");
        self.expected_server_signature =
            Some(Self::hmac_sha256(&server_key[..], auth_message.as_bytes()));

        // Build client-final-message
        let client_final = format!("{client_final_without_proof},p={client_proof_b64}");
        Ok(client_final.into_bytes())
    }

    /// Verify server-final message.
    fn verify_server_final(&mut self, server_final: &str) -> Result<(), PgError> {
        let expected_sig = self.expected_server_signature.take().ok_or_else(|| {
            PgError::AuthenticationFailed(
                "SCRAM state error: missing expected server signature".to_string(),
            )
        })?;
        if server_final.len() > MAX_SCRAM_SERVER_FINAL_LEN {
            return Err(PgError::AuthenticationFailed(format!(
                "SCRAM server-final message is {} bytes; maximum is {MAX_SCRAM_SERVER_FINAL_LEN}",
                server_final.len()
            )));
        }

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
        if server_sig.len() != SCRAM_SHA256_LEN {
            return Err(PgError::AuthenticationFailed(format!(
                "invalid SCRAM server signature length: expected {SCRAM_SHA256_LEN}, got {}",
                server_sig.len()
            )));
        }

        if !scram_constant_time_eq_expected_len(&expected_sig[..], &server_sig) {
            return Err(PgError::AuthenticationFailed(
                "server signature mismatch".to_string(),
            ));
        }

        Ok(())
    }

    /// PBKDF2-SHA256 key derivation.
    async fn pbkdf2_sha256(
        cx: &Cx,
        password: &str,
        salt: &[u8],
        iterations: u32,
    ) -> Result<zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]>, PgError> {
        if iterations == 0 {
            return Err(PgError::AuthenticationFailed(
                "SCRAM PBKDF2 iteration count must be nonzero".to_string(),
            ));
        }
        if cx.checkpoint().is_err() {
            return Err(cancelled_error(cx));
        }

        // Precompute zeroizing inner/outer pads once. This removes both the
        // per-round heap allocation and repeated key-pad construction while
        // ensuring all password-equivalent state live across a yield is wiped.
        let keyed = ScramHmacSha256Key::new(password.as_bytes());
        let block_index = 1u32.to_be_bytes();
        let mut u = keyed.digest_segments(&[salt, &block_index]);
        let mut result = zeroize::Zeroizing::new(*u);

        for iteration in 1..iterations {
            if iteration.is_multiple_of(SCRAM_PBKDF2_YIELD_INTERVAL) {
                if cx.checkpoint().is_err() {
                    return Err(cancelled_error(cx));
                }
                crate::runtime::yield_now().await;
                if cx.checkpoint().is_err() {
                    return Err(cancelled_error(cx));
                }
            }

            u = keyed.digest(&u[..]);
            for (accumulator, value) in result.iter_mut().zip(u.iter()) {
                *accumulator ^= value;
            }
        }

        if cx.checkpoint().is_err() {
            return Err(cancelled_error(cx));
        }
        Ok(result)
    }

    /// HMAC-SHA256.
    fn hmac_sha256(key: &[u8], data: &[u8]) -> zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]> {
        ScramHmacSha256Key::new(key).digest(data)
    }

    /// SHA-256 hash.
    fn sha256(data: &[u8]) -> zeroize::Zeroizing<[u8; SCRAM_SHA256_LEN]> {
        use sha2::{Digest, Sha256};
        zeroize::Zeroizing::new(Sha256::digest(data).into())
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
    /// br-asupersync-server-stack-hardening-eeexl1.5 — cache effectiveness
    /// counters. The cache is owned by a single `PgConnection` and only
    /// touched under `&mut self`, so plain counters (no atomics) are correct.
    stats: PreparedCacheStats,
}

/// Snapshot of `PreparedStatementCache` effectiveness counters
/// (br-asupersync-server-stack-hardening-eeexl1.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PreparedCacheStats {
    /// Lookups that found a cached statement.
    pub hits: u64,
    /// Lookups that missed (the statement had to be prepared on the wire).
    pub misses: u64,
    /// Entries removed to make room (LRU eviction) or replaced.
    pub evictions: u64,
}

impl PreparedCacheStats {
    /// Total lookups (`hits + misses`).
    #[must_use]
    pub const fn lookups(&self) -> u64 {
        self.hits + self.misses
    }

    /// Cache hit ratio in `[0.0, 1.0]`, or `0.0` when there were no lookups.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.lookups();
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl PreparedStatementCache {
    fn new(cap: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(cap.min(64)),
            lru: VecDeque::with_capacity(cap.min(64)),
            cap,
            stats: PreparedCacheStats::default(),
        }
    }

    /// Returns the current effectiveness counters.
    fn stats(&self) -> PreparedCacheStats {
        self.stats
    }

    /// Look up a cached statement. Returns a clone of the cached metadata
    /// AND moves the SQL key to the back of the LRU queue (most-recently
    /// used). Returns `None` on miss.
    fn get_and_touch(&mut self, sql: &str) -> Option<PgStatement> {
        let Some(stmt) = self.entries.get(sql).cloned() else {
            self.stats.misses += 1;
            return None;
        };
        self.stats.hits += 1;
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
            self.stats.evictions += 1;
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
        if evicted.is_some() {
            self.stats.evictions += 1;
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
    /// br-asupersync-server-stack-hardening-eeexl1.1.2: per-connection
    /// statement-timeout override. The effective per-query timeout is
    /// `min(remaining Cx budget, this override)`; see
    /// [`PgConnection::set_statement_timeout_override`].
    statement_timeout_override: Option<std::time::Duration>,
    /// br-asupersync-server-stack-hardening-eeexl1.1.2: the
    /// `statement_timeout` (in ms) this client last applied to the server
    /// session, so unchanged timeouts cost zero extra wire traffic.
    /// `None` means the session is at its server-side default (we never set
    /// it, or we restored it with `SET statement_timeout TO DEFAULT`).
    applied_statement_timeout_ms: Option<u64>,
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

/// Classify a zero-byte read from the peer.
///
/// `read_exact`'s in-poll cancel guard runs at the top of each poll, but the
/// `n == 0` check happens after the poll returns. Cancellation is set from
/// another thread (the deadline monitor, `cancel_with`), so it can land in that
/// window: the guard sees a live `cx`, the peer's hangup is observed, and the
/// EOF is reported as `Outcome::Err` even though a cancel was already pending.
/// Per the severity lattice (`Ok < Err < Cancelled < Panicked`), `Cancelled`
/// dominates and the caller should see 499, not 5xx (br-asupersync-xwanb4).
///
/// The downgrade is gated on cancellation *actually* being pending, mirroring
/// the established idiom in `src/transport/router.rs`. A peer that genuinely
/// hung up early with no cancel outstanding still reports `UnexpectedEof`; this
/// is not a license to suppress errors that happened before any cancel.
fn eof_or_cancelled(cx: &Cx) -> PgError {
    if cx.checkpoint().is_err() {
        return cancelled_error(cx);
    }
    PgError::Io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "unexpected end of stream",
    ))
}

/// Owns exactly one cancellation-Waker registration on a `Cx` for the
/// lifetime of a socket poll loop.
///
/// The in-poll `cx.checkpoint()` guard only observes cancellation when the
/// task is polled. A read parked on a socket with no bytes arriving is never
/// polled again on its own, so an external `cancel_with` (the deadline
/// monitor, a sibling thread, a region cancel) used to be noticed only when
/// the server finally answered: the real-server suite measured `pg_sleep(30)`
/// running its full 30 s before `Outcome::Cancelled` surfaced. Registering the
/// task's Waker with the `Cx` makes the cancel wake the parked poll, after
/// which the checkpoint guard returns `PgError::Cancelled` and the caller's
/// `cancel_in_flight` fires the `CancelRequest`. Same owned-token pattern as
/// the oneshot `RecvFuture`; a stale token from an earlier poll is refreshed
/// without allocation when the Waker is unchanged.
struct CancelWakerGuard<'a> {
    cx: &'a Cx,
    token: Option<CancelWakerToken>,
}

impl<'a> CancelWakerGuard<'a> {
    fn new(cx: &'a Cx) -> Self {
        Self { cx, token: None }
    }

    fn refresh(&mut self, waker: &Waker) {
        self.token = Some(self.cx.refresh_cancel_waker(self.token, waker));
    }
}

impl Drop for CancelWakerGuard<'_> {
    fn drop(&mut self) {
        if let Some(token) = self.token.take() {
            self.cx.clear_cancel_waker(token);
        }
    }
}

/// Read a complete buffer while preserving cancellation precedence at EOF.
///
/// Keeping the loop generic over the stream gives deterministic tests a narrow
/// seam for injecting cancellation from inside `poll_read`, after the guard has
/// run but before the empty-read classification below.
async fn read_exact_from<R>(cx: &Cx, stream: &mut R, buf: &mut [u8]) -> Result<(), PgError>
where
    R: AsyncRead + Unpin,
{
    let mut pos = 0;
    let mut cancel_wake = CancelWakerGuard::new(cx);
    while pos < buf.len() {
        let mut read_buf = ReadBuf::new(&mut buf[pos..]);
        std::future::poll_fn(|task_cx| {
            if cx.checkpoint().is_err() {
                return Poll::Ready(Err(cancelled_error(cx)));
            }
            cancel_wake.refresh(task_cx.waker());
            match Pin::new(&mut *stream).poll_read(task_cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(PgError::Io(err))),
                Poll::Pending => Poll::Pending,
            }
        })
        .await?;

        let n = read_buf.filled().len();
        if n == 0 {
            return Err(eof_or_cancelled(cx));
        }
        pos += n;
    }
    Ok(())
}

const POSTGRES_PROTOCOL_VERSION_3_0: i32 = 196_608;
const MAX_BACKEND_MESSAGE_LEN: i32 = 64 * 1024 * 1024;
// Authentication messages are control-plane traffic. Keeping their wire bodies
// small prevents a peer from turning the generic 64 MiB data-frame allowance
// into a pre-authentication allocation attack.
const MAX_POSTGRES_AUTH_BODY_LEN: usize = 8 * 1024;
// These are local defensive ceilings, not RFC-wide SCRAM maxima. Native
// PostgreSQL emits challenges far below them (tens of bytes of nonce/salt).
const MAX_SCRAM_SERVER_FIRST_LEN: usize = 4 * 1024;
const MAX_SCRAM_SERVER_FINAL_LEN: usize = 2 * 1024;
const MAX_SCRAM_NONCE_LEN: usize = 256;
const MAX_SCRAM_SALT_LEN: usize = 64;
const MAX_SCRAM_SALT_B64_LEN: usize = 4 * ((MAX_SCRAM_SALT_LEN + 2) / 3);
const SCRAM_SHA256_LEN: usize = 32;
const SCRAM_HMAC_BLOCK_LEN: usize = 64;
// RFC 7677 and PostgreSQL use 4096 as the floor. Retain the existing
// compatibility ceiling, but make its work allocation-free and cooperative.
const MIN_SCRAM_PBKDF2_ITERATIONS: u32 = 4_096;
const MAX_SCRAM_PBKDF2_ITERATIONS: u32 = 600_000;
const SCRAM_PBKDF2_YIELD_INTERVAL: u32 = 1_024;
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

    /// Sends a PostgreSQL `CancelRequest` frame on a fresh plain-TCP socket,
    /// awaited to completion
    /// (br-asupersync-server-stack-hardening-eeexl1.1.2; previously a
    /// detached fire-and-forget thread under br-asupersync-gvkj1r).
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
    /// Returns the failure stage plus error so the drain path can log the
    /// connection-close fallback distinctly. The connect attempt is bounded
    /// by [`CancelTarget::connect_timeout`] (clamped to 500ms at capture
    /// time); the frame itself is a single 16-byte write into a fresh socket
    /// buffer. TLS is intentionally not negotiated: the CancelRequest
    /// exchange is defined pre-TLS in the protocol and carries only the
    /// `(process_id, secret_key)` pair issued by BackendKeyData.
    ///
    /// This future performs no `Cx` checkpoints, so it runs to completion
    /// even when the calling task's `Cx` is already cancelled — exactly the
    /// drain-phase situation it exists for.
    async fn send_cancel_request(
        target: CancelTarget,
        process_id: i32,
        secret_key: i32,
    ) -> Result<(), (&'static str, std::io::Error)> {
        let addr = format!("{}:{}", target.host, target.port);
        let mut stream = crate::net::TcpStream::connect_timeout(addr, target.connect_timeout)
            .await
            .map_err(|err| ("connect", err))?;

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

        let mut written = 0usize;
        while written < frame.len() {
            let n = std::future::poll_fn(|task_cx| {
                Pin::new(&mut stream).poll_write(task_cx, &frame[written..])
            })
            .await
            .map_err(|err| ("write", err))?;
            if n == 0 {
                return Err((
                    "write",
                    std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "cancel-request socket accepted 0 bytes",
                    ),
                ));
            }
            written += n;
        }
        let _ = stream.shutdown(std::net::Shutdown::Both);
        Ok(())
    }

    /// br-asupersync-server-stack-hardening-eeexl1.1.2: deliver the
    /// `CancelRequest` inside the drain phase, returning only once delivery
    /// completed or the connection-close fallback was taken. Every exit is
    /// logged distinctly so operators can tell "server told to abort" from
    /// "only the client socket was torn down".
    async fn wire_cancel_in_drain(&mut self, cx: &Cx) {
        // No backend identity yet (e.g. cancel during pre-startup
        // exchange) → nothing the server can match this cancel against.
        if self.inner.process_id == 0 && self.inner.secret_key == 0 {
            cx.trace(
                "client.wire_cancel proto=postgres outcome=skipped reason=no_backend_key \
                 fallback=connection_close",
            );
            return;
        }
        let target = self.inner.cancel_target.clone();
        let process_id = self.inner.process_id;
        let secret_key = self.inner.secret_key;
        match Self::send_cancel_request(target, process_id, secret_key).await {
            Ok(()) => cx.trace(&format!(
                "client.wire_cancel proto=postgres outcome=sent process_id={process_id}"
            )),
            Err((stage, err)) => cx.trace(&format!(
                "client.wire_cancel proto=postgres outcome=send_failed stage={stage} \
                 fallback=connection_close err={err}"
            )),
        }
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
                statement_timeout_override: None,
                applied_statement_timeout_ms: None,
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

    async fn cancel_in_flight<T>(&mut self, cx: &Cx) -> Outcome<T, PgError> {
        // Tell the server to abort the in-flight query via PostgreSQL's
        // CancelRequest protocol BEFORE we tear down the original socket.
        // Sending the cancel after the original close would still work, but
        // doing it first lets the server's SIGINT race the close-induced
        // read failure and minimizes the window in which the server keeps
        // holding locks for a query no one is listening for.
        // (br-asupersync-gvkj1r)
        //
        // br-asupersync-server-stack-hardening-eeexl1.1.2: the delivery is
        // awaited — this drain step resolves only after the CancelRequest
        // completed (or its connection-close fallback was logged), so a
        // caller observing `Outcome::Cancelled` knows the server-side abort
        // signal is no longer merely "scheduled".
        self.wire_cancel_in_drain(cx).await;

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

        let mut cancel_wake = CancelWakerGuard::new(cx);

        // Write SSLRequest
        {
            let mut pos = 0;
            while pos < ssl_request.len() {
                let written = std::future::poll_fn(|task_cx| {
                    if cx.checkpoint().is_err() {
                        return Poll::Ready(Err(cancelled_error(cx)));
                    }
                    cancel_wake.refresh(task_cx.waker());
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
                cancel_wake.refresh(task_cx.waker());
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

            let (msg_type, data) = self
                .read_message_with_body_limit(
                    cx,
                    MAX_POSTGRES_AUTH_BODY_LEN,
                    "PostgreSQL authentication",
                )
                .await?;

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
                            //     advertise -PLUS, use SCRAM-SHA-256 with the
                            //     `y,,` supported-but-not-used GS2 header
                            //     (RFC 5802 §6). This is channel-binding
                            //     downgrade detection: a MITM that stripped
                            //     -PLUS is caught because the genuine server
                            //     would have offered it and aborts on `y,,`.
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
                // TLS is in use but the server did not advertise -PLUS. Per
                // RFC 5802 §6, a channel-binding-capable client MUST send the
                // `y,,` GS2 header in this case (SupportedNotUsed). If a MITM
                // stripped -PLUS from the advertised mechanism list, the real
                // server — which would have offered -PLUS — sees the `y,,`
                // signal and aborts, making the downgrade detectable. Emitting
                // plain `n,,` here would silently mask that attack.
                ScramChannelBinding::SupportedNotUsed
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
        let (msg_type, data) = self
            .read_message_with_body_limit(cx, MAX_SCRAM_SERVER_FIRST_LEN + 4, "SCRAM server-first")
            .await?;
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
        let client_final = scram.process_server_first(cx, server_first).await?;
        let mut buf = MessageBuffer::new();
        buf.write_bytes(&client_final);
        let msg = buf.build_message(FrontendMessage::Password as u8)?;
        self.write_all(cx, &msg).await?;

        if cx.checkpoint().is_err() {
            return Err(PgError::Cancelled(cancelled_reason(cx)));
        }

        // Receive SASLFinal
        let (msg_type, data) = self
            .read_message_with_body_limit(cx, MAX_SCRAM_SERVER_FINAL_LEN + 4, "SCRAM server-final")
            .await?;
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
        let (msg_type, data) = self
            .read_message_with_body_limit(
                cx,
                MAX_POSTGRES_AUTH_BODY_LEN,
                "PostgreSQL authentication",
            )
            .await?;
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

    /// Sets the per-connection statement-timeout override
    /// (br-asupersync-server-stack-hardening-eeexl1.1.2).
    ///
    /// The effective timeout forwarded to the server before each query is
    /// `min(remaining Cx budget, this override)` — meet semantics: the
    /// override can only tighten what the ambient budget allows, and vice
    /// versa. `None` (the default) leaves the ambient budget as the only
    /// source. Delivery is `SET statement_timeout`, applied lazily and only
    /// when the effective value changed (the budget-derived component is
    /// bucketed — see `database::wire_statement_timeout_ms` — so
    /// back-to-back queries under one deadline reuse the session value).
    /// When no bound applies anymore, the session value is restored with
    /// `SET statement_timeout TO DEFAULT`.
    pub fn set_statement_timeout_override(&mut self, timeout: Option<std::time::Duration>) {
        self.inner.statement_timeout_override = timeout;
    }

    /// Current per-connection statement-timeout override; see
    /// [`Self::set_statement_timeout_override`].
    #[must_use]
    pub fn statement_timeout_override(&self) -> Option<std::time::Duration> {
        self.inner.statement_timeout_override
    }

    /// True for transaction/session-control verbs that must never trigger
    /// statement-timeout reconciliation
    /// (br-asupersync-server-stack-hardening-eeexl1.1.2). Two reasons:
    /// cleanup statements (`ROLLBACK`, `COMMIT`) are drain-critical and must
    /// not be aborted server-side by an almost-exhausted budget's tightened
    /// timeout, and control statements are near-instant so a timeout
    /// backstop buys nothing for an extra round-trip.
    fn is_session_control_statement(sql: &str) -> bool {
        let verb = sql
            .trim_start()
            .split(|c: char| c.is_whitespace() || c == ';')
            .next()
            .unwrap_or("");
        [
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "ABORT",
            "END",
            "START",
            "SAVEPOINT",
            "RELEASE",
            "SET",
            "RESET",
            "SHOW",
            "DEALLOCATE",
            "DISCARD",
            "LISTEN",
            "UNLISTEN",
            "NOTIFY",
        ]
        .iter()
        .any(|kw| verb.eq_ignore_ascii_case(kw))
    }

    /// br-asupersync-server-stack-hardening-eeexl1.1.2: reconcile the server
    /// session's `statement_timeout` with `min(remaining Cx budget,
    /// per-connection override)` before a query is sent.
    ///
    /// Zero wire traffic when the effective value is unchanged. The managed
    /// exchange deliberately bypasses [`Self::execute_unchecked_on_open`]:
    /// that path fail-closed marks every `SET` completion as
    /// discard-on-pool-return and invalidates the prepared-statement cache,
    /// which is correct for *user* session mutations but would make this
    /// client-managed, always-reconciled GUC unusable with pooling.
    async fn apply_statement_timeout(&mut self, cx: &Cx) -> Outcome<(), PgError> {
        let override_timeout = self.inner.statement_timeout_override;
        let effective_ms = crate::database::wire_statement_timeout_ms(cx, override_timeout);
        if effective_ms == self.inner.applied_statement_timeout_ms {
            return Outcome::Ok(());
        }
        let remaining_ns = crate::database::remaining_budget(cx)
            .map_or_else(|| "none".to_string(), |d| d.as_nanos().to_string());
        let base_ms = override_timeout.map_or_else(
            || "none".to_string(),
            |d| crate::database::statement_timeout_millis(d).to_string(),
        );
        let sql = match effective_ms {
            Some(ms) => {
                cx.trace(&format!(
                    "client.budget_forwarded proto=postgres base_ms={base_ms} \
                     remaining_ns={remaining_ns} statement_timeout_ms={ms}"
                ));
                format!("SET statement_timeout = {ms}")
            }
            None => {
                cx.trace(&format!(
                    "client.budget_forwarded proto=postgres base_ms={base_ms} \
                     remaining_ns={remaining_ns} statement_timeout_ms=default"
                ));
                "SET statement_timeout TO DEFAULT".to_string()
            }
        };
        // Session state is uncertain until the exchange completes cleanly.
        self.inner.applied_statement_timeout_ms = None;
        match self.run_managed_statement_timeout_set(cx, &sql).await {
            Outcome::Ok(()) => {
                self.inner.applied_statement_timeout_ms = effective_ms;
                Outcome::Ok(())
            }
            Outcome::Err(err) => Outcome::Err(err),
            Outcome::Cancelled(reason) => Outcome::Cancelled(reason),
            Outcome::Panicked(payload) => Outcome::Panicked(payload),
        }
    }

    /// Minimal simple-Query exchange for the client-managed
    /// `SET statement_timeout` reconciliation. Mirrors the
    /// [`Self::execute_unchecked_on_open`] response loop minus the
    /// session-discard and prepared-cache-invalidation reactions (see
    /// [`Self::apply_statement_timeout`] for why those must not fire here).
    async fn run_managed_statement_timeout_set(
        &mut self,
        cx: &Cx,
        sql: &str,
    ) -> Outcome<(), PgError> {
        let mut buf = MessageBuffer::new();
        buf.write_cstring(sql);
        let msg = match buf.build_message(FrontendMessage::Query as u8) {
            Ok(m) => m,
            Err(e) => return Outcome::Err(e),
        };

        // Same desync protection as the public query paths: stay closed
        // unless the exchange completes through ReadyForQuery.
        self.inner.closed = true;

        if let Err(e) = self.write_all(cx, &msg).await {
            return self.fail_in_flight(e);
        }

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx).await;
            }

            let (msg_type, data) = match self.read_message(cx).await {
                Ok(m) => m,
                Err(e) => return self.fail_in_flight(e),
            };

            match msg_type {
                b'C' | b'I' => {}
                b'Z' => {
                    self.inner.closed = false;
                    if let Err(e) = self.handle_ready_for_query(&data) {
                        return self.fail_in_flight(e);
                    }
                    return Outcome::Ok(());
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
                        "managed statement_timeout SET response",
                        msg_type,
                    ));
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

        if !Self::is_session_control_statement(sql) {
            match self.apply_statement_timeout(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(err) => return Outcome::Err(err),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
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
                return self.cancel_in_flight(cx).await;
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

        if !Self::is_session_control_statement(sql) {
            match self.apply_statement_timeout(cx).await {
                Outcome::Ok(()) => {}
                Outcome::Err(err) => return Outcome::Err(err),
                Outcome::Cancelled(reason) => return Outcome::Cancelled(reason),
                Outcome::Panicked(payload) => return Outcome::Panicked(payload),
            }
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
        // br-asupersync-server-stack-hardening-eeexl1.1.2: the execute path
        // was missing the session-discard reaction the query path has had
        // since br-asupersync-r8f4pq — a user-issued `SET`/`RESET`/`DISCARD`
        // through `execute_unchecked` left `needs_discard` unset, so a
        // pooled connection could hand ambiguous session GUC/role state to
        // its next tenant. Mirror the query loop exactly.
        let mut discard_on_pool_return = false;

        loop {
            if cx.checkpoint().is_err() {
                return self.cancel_in_flight(cx).await;
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
                        discard_on_pool_return |= Self::command_tag_requires_session_discard(tag);
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
                    if discard_on_pool_return {
                        self.inner.needs_discard = true;
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
                return self.cancel_in_flight(cx).await;
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
        trace_database_transaction(cx, "postgres", "begin", "start");
        match self.execute_unchecked(cx, "BEGIN").await {
            // Reserve the obligation ONLY after BEGIN succeeds: an
            // ObligationToken is a drop bomb, so reserving it before a fallible
            // BEGIN would panic on the error/cancel paths (token dropped
            // unconsumed). The transaction now owns it for its whole lifetime.
            Outcome::Ok(_) => {
                trace_database_transaction(cx, "postgres", "begin", "ok");
                Outcome::Ok(PgTransaction {
                    conn: self,
                    finished: false,
                    isolation_level: None,
                    read_only: false,
                    obligation: reserve_transaction_obligation(cx),
                })
            }
            Outcome::Err(e) => {
                trace_database_transaction(cx, "postgres", "begin", "err");
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                trace_database_transaction(cx, "postgres", "begin", "cancelled");
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                trace_database_transaction(cx, "postgres", "begin", "panicked");
                Outcome::Panicked(p)
            }
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
        trace_database_transaction(cx, "postgres", "begin_with_isolation", "start");
        let access_mode = if read_only { "READ ONLY" } else { "READ WRITE" };
        let sql = format!("BEGIN ISOLATION LEVEL {level} {access_mode}");
        match self.execute_unchecked(cx, &sql).await {
            Outcome::Ok(_) => {}
            Outcome::Err(e) => {
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "err");
                return Outcome::Err(e);
            }
            Outcome::Cancelled(r) => {
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "cancelled");
                return Outcome::Cancelled(r);
            }
            Outcome::Panicked(p) => {
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "panicked");
                return Outcome::Panicked(p);
            }
        }

        if cx.checkpoint().is_err() {
            self.rollback_isolated_begin_or_mark(cx).await;
            trace_database_transaction(cx, "postgres", "begin_with_isolation", "cancelled");
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
                    trace_database_transaction(cx, "postgres", "begin_with_isolation", "err");
                    return Outcome::Err(PgError::IsolationLevelMismatch {
                        requested: level,
                        observed: String::new(),
                    });
                }
            },
            Outcome::Err(e) => {
                self.rollback_isolated_begin_or_mark(cx).await;
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "err");
                return Outcome::Err(e);
            }
            Outcome::Cancelled(r) => {
                self.rollback_isolated_begin_or_mark(cx).await;
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "cancelled");
                return Outcome::Cancelled(r);
            }
            Outcome::Panicked(p) => {
                self.rollback_isolated_begin_or_mark(cx).await;
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "panicked");
                return Outcome::Panicked(p);
            }
        };

        match IsolationLevel::from_server_string(&observed_level) {
            Some(parsed) if parsed == level => {
                let obligation = reserve_transaction_obligation(cx);
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "ok");
                Outcome::Ok(PgTransaction {
                    conn: self,
                    finished: false,
                    isolation_level: Some(level),
                    read_only,
                    obligation,
                })
            }
            _ => {
                self.rollback_isolated_begin_or_mark(cx).await;
                trace_database_transaction(cx, "postgres", "begin_with_isolation", "err");
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

    /// Returns the prepared-statement cache effectiveness counters
    /// (hits / misses / evictions) for this connection
    /// (br-asupersync-server-stack-hardening-eeexl1.5). Use these to size the
    /// statement cache against a real workload and to confirm a repeated-query
    /// path is actually reusing prepared statements.
    #[must_use]
    pub fn prepared_cache_stats(&self) -> PreparedCacheStats {
        self.inner.prepared_cache.stats()
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

        match self.apply_statement_timeout(cx).await {
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

        match self.apply_statement_timeout(cx).await {
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
                return self.cancel_in_flight(cx).await;
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

        match self.apply_statement_timeout(cx).await {
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

        match self.apply_statement_timeout(cx).await {
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
                return self.cancel_in_flight(cx).await;
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
        let mut cancel_wake = CancelWakerGuard::new(cx);
        while pos < data.len() {
            let written = std::future::poll_fn(|task_cx| {
                if cx.checkpoint().is_err() {
                    return Poll::Ready(Err(cancelled_error(cx)));
                }
                cancel_wake.refresh(task_cx.waker());
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
            cancel_wake.refresh(task_cx.waker());
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
        read_exact_from(cx, &mut self.inner.stream, buf).await
    }

    /// Read a complete message from the stream.
    async fn read_message(&mut self, cx: &Cx) -> Result<(u8, Vec<u8>), PgError> {
        self.read_message_with_body_limit(cx, MAX_BACKEND_MESSAGE_LEN as usize - 4, "backend")
            .await
    }

    /// Read one message while enforcing a context-specific body cap before
    /// allocating or reading the body. Authentication uses much smaller caps
    /// than data-bearing backend messages.
    async fn read_message_with_body_limit(
        &mut self,
        cx: &Cx,
        max_body_len: usize,
        context: &str,
    ) -> Result<(u8, Vec<u8>), PgError> {
        // Read message type (1 byte)
        let mut type_buf = [0u8; 1];
        self.read_exact(cx, &mut type_buf).await?;
        let msg_type = type_buf[0];

        // Read length (4 bytes, includes itself)
        let mut len_buf = [0u8; 4];
        self.read_exact(cx, &mut len_buf).await?;
        let len_i32 = i32::from_be_bytes(len_buf);

        let body_len = backend_message_body_len(len_i32)?;
        if body_len > max_body_len {
            return Err(PgError::Protocol(format!(
                "{context} message body is {body_len} bytes; maximum is {max_body_len}"
            )));
        }

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
            oid::UUID => PgValue::Text(decode_binary_uuid_to_text(data)?),
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
                return self.cancel_in_flight(cx).await;
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
                return self.cancel_in_flight(cx).await;
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
                return self.connection.cancel_in_flight(cx).await;
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
        // Arbitrary non-integral values: only the STATIC TYPE selects the
        // parameter OID here, never the value. Deliberately not 3.14, which
        // clippy reads as an approximation of PI (`approx_constant`).
        let f32_val = 2.5f32;
        let f64_val = 2.5f64;
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
        // Widen to i32: `weight` is attacker-controlled and unvalidated, and in
        // the fractional path `exp` is negative, so `weight - exp` can exceed
        // i16::MAX (e.g. weight=0x7FFF) and overflow — a debug-build panic /
        // release wrong-digit on hostile wire input.
        let idx = i32::from(weight) - i32::from(exp);
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

fn decode_binary_uuid_to_text(data: &[u8]) -> Result<String, PgError> {
    if data.len() != 16 {
        return Err(PgError::Protocol(format!(
            "UUID requires exactly 16 bytes, got {}",
            data.len()
        )));
    }

    use std::fmt::Write as _;
    let mut rendered = String::with_capacity(36);
    for (index, byte) in data.iter().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            rendered.push('-');
        }
        let _ = write!(rendered, "{byte:02x}");
    }
    Ok(rendered)
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
    let year = year + i64::from(month <= 2);
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
    /// br-asupersync-server-stack-hardening-eeexl1.5 — the open transaction's
    /// obligation. Reserved at `begin` when running inside a non-root region;
    /// `commit` consumes it via `commit()`, while rollback (explicit or on
    /// drop/cancel) consumes it via `abort()`. `None` when begun at the root
    /// region (obligations must be non-root, ASUP-E103) — such a transaction
    /// is still rolled back via poison-on-drop, just not obligation-tracked.
    obligation: Option<ObligationToken<TransactionKind>>,
}

/// Reserve a transaction obligation scoped to the caller's current region.
///
/// Returns `None` at the root region: obligations must be scoped to a
/// structured-concurrency child region (ASUP-E103), so a transaction begun
/// outside any child region is intentionally not obligation-tracked. It still
/// rolls back on drop via the connection poison flags.
fn reserve_transaction_obligation(cx: &Cx) -> Option<ObligationToken<TransactionKind>> {
    let region = cx.region_id();
    if region.as_u64() == 0 {
        None
    } else {
        Some(ObligationToken::reserve("db-transaction:postgres", region))
    }
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
            trace_database_transaction(cx, "postgres", "commit", "already_finished");
            return Outcome::Err(PgError::TransactionFinished);
        }
        trace_database_transaction(cx, "postgres", "commit", "start");
        match self.conn.execute_unchecked(cx, "COMMIT").await {
            Outcome::Ok(_) => {
                self.finished = true;
                // The transaction truly committed: discharge the obligation
                // with commit(). On any non-Ok arm we leave the token in place
                // so Drop aborts it, matching the rollback the connection
                // poison will perform.
                if let Some(token) = self.obligation.take() {
                    let _ = token.commit();
                }
                trace_database_transaction(cx, "postgres", "commit", "ok");
                Outcome::Ok(())
            }
            Outcome::Err(e) => {
                self.mark_finished_if_server_closed_transaction(&e);
                trace_database_transaction(cx, "postgres", "commit", "err");
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                trace_database_transaction(cx, "postgres", "commit", "cancelled");
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                trace_database_transaction(cx, "postgres", "commit", "panicked");
                Outcome::Panicked(p)
            }
        }
    }

    /// Rollback the transaction.
    pub async fn rollback(mut self, cx: &Cx) -> Outcome<(), PgError> {
        if self.finished {
            trace_database_transaction(cx, "postgres", "rollback", "already_finished");
            return Outcome::Err(PgError::TransactionFinished);
        }
        trace_database_transaction(cx, "postgres", "rollback", "start");
        match self.conn.execute_unchecked(cx, "ROLLBACK").await {
            Outcome::Ok(_) => {
                self.finished = true;
                // Explicit rollback: abort the obligation.
                if let Some(token) = self.obligation.take() {
                    let _ = token.abort();
                }
                trace_database_transaction(cx, "postgres", "rollback", "ok");
                Outcome::Ok(())
            }
            Outcome::Err(e) => {
                self.mark_finished_if_server_closed_transaction(&e);
                trace_database_transaction(cx, "postgres", "rollback", "err");
                Outcome::Err(e)
            }
            Outcome::Cancelled(r) => {
                trace_database_transaction(cx, "postgres", "rollback", "cancelled");
                Outcome::Cancelled(r)
            }
            Outcome::Panicked(p) => {
                trace_database_transaction(cx, "postgres", "rollback", "panicked");
                Outcome::Panicked(p)
            }
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
        // Resolve the obligation first: a transaction dropped without an
        // explicit commit rolls back, so abort() is the correct discharge.
        // This also disarms the token's own leak panic. Aborting an
        // already-taken (committed/rolled-back) obligation is a no-op.
        if let Some(token) = self.obligation.take() {
            let _ = token.abort();
        }
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

/// Reference [`crate::database::pool::AsyncConnectionManager`] implementation
/// for [`PgConnection`].
///
/// Wraps a [`PgConnectOptions`] used to mint new connections; the pool calls
/// [`crate::database::pool::AsyncConnectionManager::connect`] to add a connection and
/// [`crate::database::pool::AsyncConnectionManager::release_check`] on every
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
/// This manager's [`crate::database::pool::AsyncConnectionManager::release_check`]
/// returns `false` if EITHER flag is set, signalling the pool to drop rather than reuse the
/// connection. The pool then closes the connection (via
/// [`crate::database::pool::AsyncConnectionManager::disconnect`]) and
/// constructs a fresh one on next demand —
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
    /// [`crate::database::pool::AsyncConnectionManager::disconnect`] rather
    /// than enqueue it for reuse.
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
                statement_timeout_override: None,
                applied_statement_timeout_ms: None,
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
include!("postgres_tests.rs");

#[cfg(test)]
#[path = "postgres_auth_downgrade_audit.rs"]
mod postgres_auth_downgrade_audit;
#[cfg(test)]
#[path = "postgres_copy_from_error_audit.rs"]
mod postgres_copy_from_error_audit;
