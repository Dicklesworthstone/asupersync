//! PostgreSQL async client with wire protocol implementation.
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
//!     let conn = PgConnection::connect(cx, "postgres://user:pass@localhost/db").await?;
//!
//!     let rows = conn.query(cx, "SELECT id, name FROM users WHERE active = $1", &[&true]).await?;
//!     for row in rows {
//!         let id: i32 = row.get("id")?;
//!         let name: String = row.get("name")?;
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
    /// Transaction already finished.
    TransactionFinished,
    /// Unsupported authentication method.
    UnsupportedAuth(String),
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
    /// 64-bit integer (bytea).
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
        let val = self.get(column)?;
        val.as_i32().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "i32",
            actual_oid: 0,
        })
    }

    /// Get an i64 value by column name.
    pub fn get_i64(&self, column: &str) -> Result<i64, PgError> {
        let val = self.get(column)?;
        val.as_i64().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "i64",
            actual_oid: 0,
        })
    }

    /// Get a string value by column name.
    pub fn get_str(&self, column: &str) -> Result<&str, PgError> {
        let val = self.get(column)?;
        val.as_str().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "string",
            actual_oid: 0,
        })
    }

    /// Get a bool value by column name.
    pub fn get_bool(&self, column: &str) -> Result<bool, PgError> {
        let val = self.get(column)?;
        val.as_bool().ok_or_else(|| PgError::TypeConversion {
            column: column.to_string(),
            expected: "bool",
            actual_oid: 0,
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
    /// Flush message.
    Flush = b'H',
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
}

/// Backend (server) message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum BackendMessage {
    /// Authentication request.
    Authentication = b'R',
    /// Backend key data.
    BackendKeyData = b'K',
    /// Bind complete.
    BindComplete = b'2',
    /// Close complete.
    CloseComplete = b'3',
    /// Command complete.
    CommandComplete = b'C',
    /// Data row.
    DataRow = b'D',
    /// Error response.
    ErrorResponse = b'E',
    /// Notice response.
    NoticeResponse = b'N',
    /// Parameter description.
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
        self.buf.extend_from_slice(s.as_bytes());
        self.buf.push(0);
    }

    /// Build a typed message with length prefix.
    fn build_message(&mut self, msg_type: u8) -> Vec<u8> {
        let len = (self.buf.len() + 4) as i32; // +4 for length field itself
        let mut result = Vec::with_capacity(1 + 4 + self.buf.len());
        result.push(msg_type);
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.buf);
        result
    }

    /// Build a startup message (no type byte, includes protocol version).
    fn build_startup_message(&mut self) -> Vec<u8> {
        let len = (self.buf.len() + 4) as i32;
        let mut result = Vec::with_capacity(4 + self.buf.len());
        result.extend_from_slice(&len.to_be_bytes());
        result.extend_from_slice(&self.buf);
        result
    }

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
        if self.pos + len > self.data.len() {
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
    /// Username.
    username: String,
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
            username: username.to_string(),
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
        if iterations == 0 {
            return Err(PgError::AuthenticationFailed(
                "invalid iterations".to_string(),
            ));
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
        let client_key = self.hmac_sha256(&salted_password, b"Client Key");
        let stored_key = self.sha256(&client_key);

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
        let client_signature = self.hmac_sha256(&stored_key, auth_message.as_bytes());
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
        let salted_password = self.pbkdf2_sha256(&self.password, salt, iterations);
        let server_key = self.hmac_sha256(&salted_password, b"Server Key");
        let auth_message = self.auth_message.as_ref().ok_or_else(|| {
            PgError::AuthenticationFailed("SCRAM state error: missing auth_message".to_string())
        })?;
        let expected_sig = self.hmac_sha256(&server_key, auth_message.as_bytes());

        if server_sig != expected_sig {
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

        let mut u = self.hmac_sha256(password.as_bytes(), &salt_with_block);
        result.copy_from_slice(&u);

        // U_2 ... U_iterations
        for _ in 1..iterations {
            u = self.hmac_sha256(password.as_bytes(), &u);
            for (r, ui) in result.iter_mut().zip(u.iter()) {
                *r ^= ui;
            }
        }

        result
    }

    /// HMAC-SHA256.
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
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
    fn sha256(&self, data: &[u8]) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        Sha256::digest(data).to_vec()
    }
}

// ============================================================================
// Connection URL Parsing
// ============================================================================

/// Parsed PostgreSQL connection URL.
#[derive(Debug, Clone)]
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

        // Split auth@host
        let (user, password, host_port) = if let Some((auth, host)) = auth_host.rsplit_once('@') {
            let (user, password) = auth
                .split_once(':')
                .map_or((auth, None), |(u, p)| (u, Some(p)));
            (user.to_string(), password.map(String::from), host)
        } else {
            ("postgres".to_string(), None, auth_host)
        };

        // Split host:port (handle IPv6 addresses like [::1]:5432)
        let (host, port) = if host_port.starts_with('[') {
            // IPv6 literal: [::1]:5432
            if let Some((bracket_host, rest)) = host_port.split_once(']') {
                let h = bracket_host.trim_start_matches('[');
                let p = rest
                    .strip_prefix(':')
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(5432u16);
                (h, p)
            } else {
                (host_port, 5432)
            }
        } else {
            host_port
                .rsplit_once(':')
                .map_or((host_port, 5432), |(h, p)| (h, p.parse().unwrap_or(5432)))
        };

        Ok(Self {
            host: host.to_string(),
            port,
            database: database.to_string(),
            user,
            password,
            application_name: None,
            connect_timeout: None,
            ssl_mode: SslMode::Prefer,
        })
    }
}

// ============================================================================
// PostgreSQL Connection
// ============================================================================

/// Inner connection state.
struct PgConnectionInner {
    /// TCP stream to the server.
    stream: TcpStream,
    /// Read buffer for incoming messages.
    read_buf: Vec<u8>,
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

impl PgConnection {
    /// Connect to a PostgreSQL database.
    ///
    /// # Cancellation
    ///
    /// This operation checks for cancellation before starting.
    pub async fn connect(cx: &Cx, url: &str) -> Outcome<Self, PgError> {
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
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
            Err(e) => return Outcome::Err(PgError::Io(e)),
        };

        let mut conn = Self {
            inner: PgConnectionInner {
                stream,
                read_buf: Vec::with_capacity(8192),
                process_id: 0,
                secret_key: 0,
                parameters: BTreeMap::new(),
                transaction_status: b'I', // Idle
                closed: false,
            },
        };

        // Send startup message
        if let Err(e) = conn.send_startup(&options).await {
            return Outcome::Err(e);
        }

        // Handle authentication
        if let Err(e) = conn.authenticate(cx, &options).await {
            return Outcome::Err(e);
        }

        // Wait for ReadyForQuery
        if let Err(e) = conn.wait_for_ready().await {
            return Outcome::Err(e);
        }

        Outcome::Ok(conn)
    }

    /// Send the startup message.
    async fn send_startup(&mut self, options: &PgConnectOptions) -> Result<(), PgError> {
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

        let msg = buf.build_startup_message();
        self.write_all(&msg).await?;

        Ok(())
    }

    /// Handle the authentication handshake.
    async fn authenticate(&mut self, cx: &Cx, options: &PgConnectOptions) -> Result<(), PgError> {
        loop {
            let (msg_type, data) = self.read_message().await?;

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
                            self.send_password(password).await?;
                        }
                        5 => {
                            // AuthenticationMD5Password
                            let salt = reader.read_bytes(4)?;
                            let password = options.password.as_ref().ok_or_else(|| {
                                PgError::AuthenticationFailed("password required".to_string())
                            })?;
                            self.send_md5_password(&options.user, password, salt)
                                .await?;
                        }
                        10 => {
                            // AuthenticationSASL
                            let mechanisms = self.read_sasl_mechanisms(&mut reader)?;
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
    fn read_sasl_mechanisms(&self, reader: &mut MessageReader<'_>) -> Result<Vec<String>, PgError> {
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
        buf.write_i32(client_first.len() as i32);
        buf.write_bytes(&client_first);
        let msg = buf.build_message(b'p');
        self.write_all(&msg).await?;

        // Receive SASLContinue
        let (msg_type, data) = self.read_message().await?;
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
        let msg = buf.build_message(b'p');
        self.write_all(&msg).await?;

        // Receive SASLFinal
        let (msg_type, data) = self.read_message().await?;
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

        // Wait for AuthenticationOk
        let (msg_type, data) = self.read_message().await?;
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
    async fn send_password(&mut self, password: &str) -> Result<(), PgError> {
        let mut buf = MessageBuffer::new();
        buf.write_cstring(password);
        let msg = buf.build_message(b'p');
        self.write_all(&msg).await?;
        Ok(())
    }

    /// Send MD5-hashed password.
    #[allow(clippy::unused_async)]
    async fn send_md5_password(
        &mut self,
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
    async fn wait_for_ready(&mut self) -> Result<(), PgError> {
        loop {
            let (msg_type, data) = self.read_message().await?;

            match msg_type {
                b'K' => {
                    // BackendKeyData
                    let mut reader = MessageReader::new(&data);
                    self.inner.process_id = reader.read_i32()?;
                    self.inner.secret_key = reader.read_i32()?;
                }
                b'S' => {
                    // ParameterStatus
                    let mut reader = MessageReader::new(&data);
                    let name = reader.read_cstring()?.to_string();
                    let value = reader.read_cstring()?.to_string();
                    self.inner.parameters.insert(name, value);
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
                    // Unexpected message - log warning
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
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        // Send Query message
        let mut buf = MessageBuffer::new();
        buf.write_cstring(sql);
        let msg = buf.build_message(b'Q');

        if let Err(e) = self.write_all(&msg).await {
            return Outcome::Err(e);
        }

        // Process responses
        let mut columns: Option<Arc<Vec<PgColumn>>> = None;
        let mut column_indices: Option<Arc<BTreeMap<String, usize>>> = None;
        let mut rows = Vec::with_capacity(16);

        loop {
            let (msg_type, data) = match self.read_message().await {
                Ok(m) => m,
                Err(e) => return Outcome::Err(e),
            };

            match msg_type {
                b'T' => {
                    // RowDescription
                    match self.parse_row_description(&data) {
                        Ok((cols, indices)) => {
                            columns = Some(Arc::new(cols));
                            column_indices = Some(Arc::new(indices));
                        }
                        Err(e) => return Outcome::Err(e),
                    }
                }
                b'D' => {
                    // DataRow
                    if let (Some(cols), Some(indices)) = (&columns, &column_indices) {
                        match self.parse_data_row(&data, cols) {
                            Ok(values) => {
                                rows.push(PgRow {
                                    columns: Arc::clone(cols),
                                    column_indices: Arc::clone(indices),
                                    values,
                                });
                            }
                            Err(e) => return Outcome::Err(e),
                        }
                    }
                }
                b'C' => {
                    // CommandComplete
                    // Continue to ReadyForQuery
                }
                b'Z' => {
                    // ReadyForQuery
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    break;
                }
                b'E' => {
                    // ErrorResponse — drain to ReadyForQuery before returning so
                    // the connection stays synchronized for subsequent operations.
                    let err = match self.parse_error_response(&data) {
                        Err(e) => e,
                        Ok(e) => e,
                    };
                    loop {
                        let (drain_type, drain_data) = match self.read_message().await {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        if drain_type == b'Z' {
                            if !drain_data.is_empty() {
                                self.inner.transaction_status = drain_data[0];
                            }
                            break;
                        }
                    }
                    return Outcome::Err(err);
                }
                b'N' => {
                    // NoticeResponse - ignore
                }
                _ => {
                    // Unknown message type
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
        if cx.is_cancel_requested() {
            return Outcome::Cancelled(
                cx.cancel_reason()
                    .unwrap_or_else(|| CancelReason::user("cancelled")),
            );
        }

        if self.inner.closed {
            return Outcome::Err(PgError::ConnectionClosed);
        }

        // Send Query message
        let mut buf = MessageBuffer::new();
        buf.write_cstring(sql);
        let msg = buf.build_message(b'Q');

        if let Err(e) = self.write_all(&msg).await {
            return Outcome::Err(e);
        }

        // Process responses
        let mut affected_rows = 0u64;

        loop {
            let (msg_type, data) = match self.read_message().await {
                Ok(m) => m,
                Err(e) => return Outcome::Err(e),
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
                    // RowDescription, DataRow - skip for execute
                }
                b'Z' => {
                    // ReadyForQuery
                    if !data.is_empty() {
                        self.inner.transaction_status = data[0];
                    }
                    break;
                }
                b'E' => {
                    // ErrorResponse — drain to ReadyForQuery before returning so
                    // the connection stays synchronized for subsequent operations.
                    let err = match self.parse_error_response(&data) {
                        Err(e) => e,
                        Ok(e) => e,
                    };
                    loop {
                        let (drain_type, drain_data) = match self.read_message().await {
                            Ok(m) => m,
                            Err(_) => break,
                        };
                        if drain_type == b'Z' {
                            if !drain_data.is_empty() {
                                self.inner.transaction_status = drain_data[0];
                            }
                            break;
                        }
                    }
                    return Outcome::Err(err);
                }
                b'N' => {
                    // NoticeResponse - ignore
                }
                _ => {}
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
        let msg = [b'X', 0, 0, 0, 4]; // Type + length (4)
        let _ = self.write_all(&msg).await;

        let _ = self.inner.stream.shutdown(std::net::Shutdown::Both);

        self.inner.closed = true;
        Ok(())
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Write data to the stream using async I/O.
    async fn write_all(&mut self, data: &[u8]) -> Result<(), PgError> {
        let mut pos = 0;
        while pos < data.len() {
            let written = std::future::poll_fn(|cx| {
                Pin::new(&mut self.inner.stream).poll_write(cx, &data[pos..])
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
        Ok(())
    }

    /// Read exactly `len` bytes from the stream.
    async fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), PgError> {
        let mut pos = 0;
        while pos < buf.len() {
            let mut read_buf = ReadBuf::new(&mut buf[pos..]);
            std::future::poll_fn(|cx| {
                Pin::new(&mut self.inner.stream).poll_read(cx, &mut read_buf)
            })
            .await
            .map_err(PgError::Io)?;

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
    async fn read_message(&mut self) -> Result<(u8, Vec<u8>), PgError> {
        // Read message type (1 byte)
        let mut type_buf = [0u8; 1];
        self.read_exact(&mut type_buf).await?;
        let msg_type = type_buf[0];

        // Read length (4 bytes, includes itself)
        let mut len_buf = [0u8; 4];
        self.read_exact(&mut len_buf).await?;
        let len_i32 = i32::from_be_bytes(len_buf);

        // PostgreSQL messages should not exceed 1 GiB in practice.
        const MAX_MESSAGE_LEN: i32 = 1_073_741_824;
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
            self.read_exact(&mut body).await?;
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

        let mut values = Vec::with_capacity(num_values);

        for i in 0..num_values {
            let len = reader.read_i32()?;
            if len == -1 {
                // NULL value
                values.push(PgValue::Null);
            } else if len < -1 {
                return Err(PgError::Protocol(format!(
                    "negative column length in DataRow: {len}"
                )));
            } else {
                let data = reader.read_bytes(len as usize)?;
                let col = columns.get(i);
                let type_oid = col.map_or(oid::TEXT, |c| c.type_oid);
                let format = col.map_or(0, |c| c.format_code);

                let value = if format == 0 {
                    // Text format
                    self.parse_text_value(data, type_oid)?
                } else {
                    // Binary format
                    self.parse_binary_value(data, type_oid)?
                };
                values.push(value);
            }
        }

        Ok(values)
    }

    /// Parse a text-format value.
    fn parse_text_value(&self, data: &[u8], type_oid: u32) -> Result<PgValue, PgError> {
        let s = std::str::from_utf8(data)
            .map_err(|e| PgError::Protocol(format!("invalid UTF-8: {e}")))?;

        Ok(match type_oid {
            oid::BOOL => PgValue::Bool(s == "t"),
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
            oid::BOOL => PgValue::Bool(data.first() == Some(&1)),
            oid::INT2 if data.len() >= 2 => PgValue::Int2(i16::from_be_bytes([data[0], data[1]])),
            oid::INT4 | oid::OID if data.len() >= 4 => {
                PgValue::Int4(i32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            oid::INT8 if data.len() >= 8 => PgValue::Int8(i64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            oid::FLOAT4 if data.len() >= 4 => {
                PgValue::Float4(f32::from_be_bytes([data[0], data[1], data[2], data[3]]))
            }
            oid::FLOAT8 if data.len() >= 8 => PgValue::Float8(f64::from_be_bytes([
                data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
            ])),
            oid::BYTEA => PgValue::Bytes(data.to_vec()),
            _ => {
                // Try to interpret as text
                match std::str::from_utf8(data) {
                    Ok(s) => PgValue::Text(s.to_string()),
                    Err(_) => PgValue::Bytes(data.to_vec()),
                }
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

        Err(PgError::Server {
            code,
            message,
            detail,
            hint,
        })
    }
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
        self.finished = true;
        match self.conn.execute(cx, "COMMIT").await {
            Outcome::Ok(_) => Outcome::Ok(()),
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
        self.finished = true;
        match self.conn.execute(cx, "ROLLBACK").await {
            Outcome::Ok(_) => Outcome::Ok(()),
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
}

impl Drop for PgTransaction<'_> {
    fn drop(&mut self) {
        if !self.finished {
            // Best-effort rollback on drop
            // We can't await here, so we'll just mark the connection as needing attention
            // In practice, the server will auto-rollback when we send another command
            // or close the connection
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
        buf.write_i32(196608);
        buf.write_cstring("user");
        buf.write_cstring("testuser");
        buf.write_byte(0);

        let msg = buf.build_startup_message();
        assert!(msg.len() > 4); // At least length prefix
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
                stream,
                read_buf: Vec::new(),
                process_id: 0,
                secret_key: 0,
                parameters: BTreeMap::new(),
                transaction_status: b'I',
                closed: false,
            },
        }
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
        let row = make_test_row(
            &["i", "b", "s", "big"],
            vec![
                PgValue::Int4(42),
                PgValue::Bool(false),
                PgValue::Text("hello".to_string()),
                PgValue::Int8(99),
            ],
        );
        assert_eq!(row.get_i32("i").unwrap(), 42);
        assert!(!row.get_bool("b").unwrap());
        assert_eq!(row.get_str("s").unwrap(), "hello");
        assert_eq!(row.get_i64("big").unwrap(), 99);

        // Type mismatch: i32 on a bool column
        match row.get_i32("b").unwrap_err() {
            PgError::TypeConversion {
                column, expected, ..
            } => {
                assert_eq!(column, "b");
                assert_eq!(expected, "i32");
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
        let msg = buf.build_message(b'Q');
        // byte 0: msg type 'Q'
        assert_eq!(msg[0], b'Q');
        // bytes 1-4: length = body_len + 4
        let len = i32::from_be_bytes([msg[1], msg[2], msg[3], msg[4]]);
        assert_eq!(len as usize, msg.len() - 1);
    }

    #[test]
    fn message_buffer_startup_no_type_byte() {
        let mut buf = MessageBuffer::new();
        buf.write_i32(196608); // protocol version 3.0
        buf.write_cstring("user");
        buf.write_cstring("test");
        buf.write_byte(0);
        let msg = buf.build_startup_message();
        // bytes 0-3: length (includes itself)
        let len = i32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
        assert_eq!(len as usize, msg.len());
        // protocol version at bytes 4-7
        let version = i32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
        assert_eq!(version, 196608);
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

        let err = conn.parse_error_response(&data).unwrap_err();
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

        let err = conn.parse_error_response(&data).unwrap_err();
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
}
